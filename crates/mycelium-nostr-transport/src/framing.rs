//! Framing fiável sobre eventos Nostr (seq/ACK cumulativo, janela, RTO adaptativo).
//!
//! Cada evento 39406 leva **um segmento**: até [`MAX_PAYLOAD`] bytes de dados
//! (ou só FIN, ou nada = ACK puro) e sempre o ACK cumulativo do sentido
//! contrário. O `ack` é o **próximo seq esperado** (0 = nada recebido), por
//! isso um segmento enviado antes de receber qualquer coisa não confirma nada.
//!
//! Para poupar eventos (relays públicos aplicam rate-limit), quem usa o estado
//! agrupa escritas pequenas num segmento, atrasa ACKs puros para irem de
//! carona nos dados e, em timeout, retransmite só o segmento mais antigo com
//! RTO em backoff exponencial (RFC 6298, amostragem de Karn).

use std::collections::BTreeMap;
use std::time::Duration;
use tokio::time::Instant;

/// Segmentos em voo por sentido.
pub const WINDOW_SIZE: u64 = 16;
/// Dados por segmento. Codificado (base64 → NIP-44 → base64) o evento fica
/// perto de 33 KiB, abaixo dos 64 KiB que relays comuns aceitam.
pub const MAX_PAYLOAD: usize = 16 * 1024;
/// RTO mínimo e máximo.
pub const RTO_MIN: Duration = Duration::from_millis(1000);
pub const RTO_MAX: Duration = Duration::from_secs(60);
/// Retransmissões do mesmo segmento antes de declarar a conexão morta.
pub const MAX_RETRIES: u32 = 8;

const FLAG_FIN: u8 = 1;
const HEADER: usize = 8 + 8 + 8 + 1 + 4;

/// Segmento: dados, FIN ou ACK puro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub stream_id: [u8; 8],
    pub seq: u64,
    /// Próximo seq esperado do peer (ACK cumulativo).
    pub ack: u64,
    pub fin: bool,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Ocupa um número de sequência (tem de ser confirmado).
    pub fn is_sequenced(&self) -> bool {
        self.fin || !self.payload.is_empty()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + self.payload.len());
        out.extend_from_slice(&self.stream_id);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.ack.to_be_bytes());
        out.push(if self.fin { FLAG_FIN } else { 0 });
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER {
            return None;
        }
        let mut stream_id = [0u8; 8];
        stream_id.copy_from_slice(&bytes[0..8]);
        let seq = u64::from_be_bytes(bytes[8..16].try_into().ok()?);
        let ack = u64::from_be_bytes(bytes[16..24].try_into().ok()?);
        let fin = bytes[24] & FLAG_FIN != 0;
        let len = u32::from_be_bytes(bytes[25..29].try_into().ok()?) as usize;
        if bytes.len() != HEADER + len || len > MAX_PAYLOAD {
            return None;
        }
        Some(Self {
            stream_id,
            seq,
            ack,
            fin,
            payload: bytes[HEADER..].to_vec(),
        })
    }
}

/// O peer não confirmou um segmento após [`MAX_RETRIES`] retransmissões.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerUnresponsive;

#[derive(Debug)]
struct Inflight {
    payload: Vec<u8>,
    fin: bool,
    sent_at: Instant,
    retries: u32,
}

/// Resultado de processar um segmento recebido.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Received {
    /// Bytes entregues em ordem.
    pub data: Vec<u8>,
    /// O peer fechou o seu sentido (FIN entregue em ordem).
    pub fin: bool,
    /// O segmento era duplicado ou fora de ordem: confirmar já, sem esperar.
    pub ack_now: bool,
}

/// Estado de fiabilidade de um sentido de envio + um de receção (sem I/O).
#[derive(Debug)]
pub struct ReliableState {
    pub stream_id: [u8; 8],
    next_send_seq: u64,
    next_recv_seq: u64,
    /// Último ACK que o peer já recebeu de nós (em qualquer segmento).
    ack_sent: u64,
    inflight: BTreeMap<u64, Inflight>,
    reorder: BTreeMap<u64, (Vec<u8>, bool)>,
    fin_received: bool,
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
    /// Prazo do temporizador de retransmissão (só com dados em voo).
    rto_deadline: Option<Instant>,
}

impl ReliableState {
    pub fn new(stream_id: [u8; 8], initial_rto: Duration) -> Self {
        Self {
            stream_id,
            next_send_seq: 0,
            next_recv_seq: 0,
            ack_sent: 0,
            inflight: BTreeMap::new(),
            reorder: BTreeMap::new(),
            fin_received: false,
            srtt: None,
            rttvar: Duration::ZERO,
            rto: initial_rto.clamp(RTO_MIN, RTO_MAX),
            rto_deadline: None,
        }
    }

    pub fn window_full(&self) -> bool {
        (self.inflight.len() as u64) >= WINDOW_SIZE
    }

    pub fn has_inflight(&self) -> bool {
        !self.inflight.is_empty()
    }

    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// Há dados recebidos ainda não confirmados ao peer.
    pub fn ack_pending(&self) -> bool {
        self.next_recv_seq != self.ack_sent
    }

    pub fn fin_received(&self) -> bool {
        self.fin_received
    }

    /// Novo segmento de dados (e/ou FIN). O chamador respeita a janela e
    /// [`MAX_PAYLOAD`]. Leva de carona o ACK cumulativo atual.
    pub fn push_segment(&mut self, payload: Vec<u8>, fin: bool) -> Frame {
        debug_assert!(payload.len() <= MAX_PAYLOAD);
        let seq = self.next_send_seq;
        self.next_send_seq += 1;
        let now = Instant::now();
        self.inflight.insert(
            seq,
            Inflight {
                payload: payload.clone(),
                fin,
                sent_at: now,
                retries: 0,
            },
        );
        self.rto_deadline.get_or_insert(now + self.rto);
        self.ack_sent = self.next_recv_seq;
        Frame {
            stream_id: self.stream_id,
            seq,
            ack: self.next_recv_seq,
            fin,
            payload,
        }
    }

    /// ACK puro (não ocupa seq).
    pub fn ack_frame(&mut self) -> Frame {
        self.ack_sent = self.next_recv_seq;
        Frame {
            stream_id: self.stream_id,
            seq: self.next_send_seq,
            ack: self.next_recv_seq,
            fin: false,
            payload: Vec::new(),
        }
    }

    /// Processa um segmento do peer.
    pub fn on_recv(&mut self, frame: Frame) -> Received {
        let mut out = Received::default();
        if frame.stream_id != self.stream_id {
            return out;
        }
        self.apply_ack(frame.ack);

        if !frame.is_sequenced() {
            return out;
        }
        if frame.seq < self.next_recv_seq || self.fin_received {
            // Duplicado: o nosso ACK perdeu-se ou atrasou.
            out.ack_now = true;
            return out;
        }
        if frame.seq > self.next_recv_seq {
            if frame.seq < self.next_recv_seq + WINDOW_SIZE * 2 {
                self.reorder.insert(frame.seq, (frame.payload, frame.fin));
            }
            out.ack_now = true;
            return out;
        }
        let mut seg = Some((frame.payload, frame.fin));
        while let Some((payload, fin)) = seg {
            out.data.extend_from_slice(&payload);
            self.next_recv_seq += 1;
            if fin {
                self.fin_received = true;
                out.fin = true;
                self.reorder.clear();
                break;
            }
            seg = self.reorder.remove(&self.next_recv_seq);
        }
        out
    }

    fn apply_ack(&mut self, ack: u64) {
        let now = Instant::now();
        let mut progressed = false;
        while let Some((&seq, inf)) = self.inflight.first_key_value() {
            if seq >= ack {
                break;
            }
            // Karn: só amostra RTT de segmentos nunca retransmitidos.
            if inf.retries == 0 {
                self.sample_rtt(now.duration_since(inf.sent_at));
            }
            self.inflight.pop_first();
            progressed = true;
        }
        if progressed {
            self.rto = self.base_rto();
            self.rto_deadline = (!self.inflight.is_empty()).then(|| now + self.rto);
        }
    }

    fn sample_rtt(&mut self, r: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(srtt) => {
                let diff = srtt.abs_diff(r);
                self.rttvar = (self.rttvar * 3 + diff) / 4;
                self.srtt = Some((srtt * 7 + r) / 8);
            }
        }
    }

    fn base_rto(&self) -> Duration {
        match self.srtt {
            Some(srtt) => (srtt + (self.rttvar * 4).max(Duration::from_millis(100)))
                .clamp(RTO_MIN, RTO_MAX),
            None => self.rto,
        }
    }

    /// Prazo do próximo timeout de retransmissão.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.rto_deadline
    }

    /// Em timeout, retransmite só o segmento mais antigo e dobra o RTO.
    /// `Err` = esgotou [`MAX_RETRIES`]: a conexão está morta.
    pub fn on_timeout(&mut self, now: Instant) -> Result<Option<Frame>, PeerUnresponsive> {
        match self.rto_deadline {
            Some(d) if d <= now => {}
            _ => return Ok(None),
        }
        let next_recv = self.next_recv_seq;
        let Some((&seq, inf)) = self.inflight.iter_mut().next() else {
            self.rto_deadline = None;
            return Ok(None);
        };
        if inf.retries >= MAX_RETRIES {
            return Err(PeerUnresponsive);
        }
        inf.retries += 1;
        inf.sent_at = now;
        let frame = Frame {
            stream_id: self.stream_id,
            seq,
            ack: next_recv,
            fin: inf.fin,
            payload: inf.payload.clone(),
        };
        self.ack_sent = next_recv;
        self.rto = (self.rto * 2).min(RTO_MAX);
        self.rto_deadline = Some(now + self.rto);
        Ok(Some(frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: [u8; 8] = [9u8; 8];

    fn pair() -> (ReliableState, ReliableState) {
        (
            ReliableState::new(SID, Duration::from_secs(1)),
            ReliableState::new(SID, Duration::from_secs(1)),
        )
    }

    #[test]
    fn frame_roundtrip() {
        let f = Frame {
            stream_id: [1; 8],
            seq: 7,
            ack: 3,
            fin: true,
            payload: b"hello".to_vec(),
        };
        assert_eq!(Frame::decode(&f.encode()), Some(f));
        assert_eq!(Frame::decode(&[0u8; 10]), None);
    }

    #[test]
    fn data_then_cumulative_ack() {
        let (mut a, mut b) = pair();
        let f = a.push_segment(b"abcdef".to_vec(), false);
        assert_eq!(f.ack, 0, "nada recebido ainda: não confirma nada");
        let r = b.on_recv(f);
        assert_eq!(r.data, b"abcdef");
        assert!(b.ack_pending());
        let ack = b.ack_frame();
        assert_eq!(ack.ack, 1);
        assert!(!b.ack_pending());
        a.on_recv(ack);
        assert!(!a.has_inflight());
        assert_eq!(a.next_deadline(), None);
    }

    #[test]
    fn first_segment_does_not_falsely_ack_peer_seq0() {
        let (mut a, mut b) = pair();
        let _lost = a.push_segment(b"lost".to_vec(), false);
        // B fala antes de receber nada: o ACK 0 não pode apagar o seq 0 de A.
        let fb = b.push_segment(b"hi".to_vec(), false);
        a.on_recv(fb);
        assert!(a.has_inflight());
    }

    #[test]
    fn gap_then_fill_and_duplicate_asks_for_ack() {
        let (mut a, mut b) = pair();
        let f0 = a.push_segment(b"A".to_vec(), false);
        let f1 = a.push_segment(b"B".to_vec(), false);
        let r1 = b.on_recv(f1);
        assert!(r1.data.is_empty() && r1.ack_now);
        let r0 = b.on_recv(f0.clone());
        assert_eq!(r0.data, b"AB");
        assert!(b.on_recv(f0).ack_now);
    }

    #[test]
    fn fin_is_reliable_and_ends_stream() {
        let (mut a, mut b) = pair();
        let d = a.push_segment(b"x".to_vec(), false);
        let fin = a.push_segment(Vec::new(), true);
        let r = b.on_recv(fin);
        assert!(!r.fin, "FIN fora de ordem espera os dados");
        let r = b.on_recv(d);
        assert_eq!(r.data, b"x");
        assert!(r.fin && b.fin_received());
        a.on_recv(b.ack_frame());
        assert!(!a.has_inflight());
    }

    #[test]
    fn timeout_retransmits_oldest_with_backoff_then_gives_up() {
        let (mut a, _) = pair();
        a.push_segment(b"1".to_vec(), false);
        a.push_segment(b"2".to_vec(), false);
        let mut now = Instant::now();
        assert_eq!(a.on_timeout(now), Ok(None), "ainda não venceu");
        let mut last_rto = a.rto();
        for _ in 0..MAX_RETRIES {
            now = a.next_deadline().unwrap();
            let f = a.on_timeout(now).unwrap().expect("retransmite");
            assert_eq!(f.seq, 0, "só o mais antigo");
            assert!(a.rto() >= last_rto);
            last_rto = a.rto();
        }
        now = a.next_deadline().unwrap();
        assert!(a.on_timeout(now).is_err());
    }

    #[test]
    fn rtt_sample_sets_rto_from_measurement() {
        let (_, mut b) = pair();
        let mut r = ReliableState::new(SID, Duration::from_secs(30));
        let f = r.push_segment(b"x".to_vec(), false);
        b.on_recv(f);
        r.on_recv(b.ack_frame());
        assert!(r.rto() < Duration::from_secs(30), "RTO cai para o medido");
        assert_eq!(r.rto(), RTO_MIN, "RTT local ≈ 0 → RTO mínimo");
    }
}
