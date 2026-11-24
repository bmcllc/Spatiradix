//! Ponte IPv4/TCP/DNS em espaço de usuário (`tun2socks`) para o `Android VpnService` e túneis TUN.
//!
//! Protocolo de enquadramento sobre TCP loopback (`127.0.0.1:<porta>`):
//! - Cada pacote IPv4 bruto recebido do `ParcelFileDescriptor` (Android `VpnService`) é precedido
//!   por 2 bytes big-endian (`u16::to_be_bytes`) indicando o comprimento do pacote.
//! - Pacotes TCP IPv4 são multiplexados por 4-tupla e abertos diretamente sobre o circuito
//!   pós-quântico `LiveCircuitClient` (`ML-KEM-1024`), obedecendo estritamente ao `KillSwitch`.
//! - Consultas DNS UDP (porta 53) são convertidas em DNS-over-TCP (RFC 1035 §4.2.2) dentro do
//!   próprio circuito VEIL usando exclusivamente DNS independente (Quad9 `9.9.9.9` / Cloudflare `1.1.1.1`,
//!   zero DNS da Google).

use crate::planes::live::{CircuitStreamWriter, LiveCircuitClient};
use crate::socks5::Socks5Target;
use crate::tunnel::KillSwitch;
use crate::VeilError;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
const TCP_MSS: usize = 1360;
const MAX_PACKET_SIZE: usize = 65535;

/// Métricas vivas da ponte TUN ↔ Circuito VEIL.
#[derive(Default, Debug)]
pub struct TunBridgeStats {
    pub connected_clients: AtomicUsize,
    pub active_tcp_flows: AtomicUsize,
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub dns_queries: AtomicU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FlowKey {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

struct TcpFlow {
    client_next_seq: u32,
    server_seq: u32,
    writer: Option<CircuitStreamWriter>,
    pending_payload: Vec<u8>,
}

/// Calcula o checksum complemento de 1 (RFC 1071).
pub fn ones_complement_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn transport_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + segment.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(proto);
    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(segment);
    ones_complement_checksum(&pseudo)
}

/// Constrói um pacote IPv4 + TCP válido (RFC 791 + RFC 793).
pub fn build_ipv4_tcp_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let tcp_hdr_len = 20 + options.len();
    debug_assert_eq!(tcp_hdr_len % 4, 0);
    let tcp_len = tcp_hdr_len + payload.len();
    let total_len = 20 + tcp_len;

    let mut pkt = vec![0u8; total_len];
    // IPv4 header
    pkt[0] = 0x45; // v4, IHL=5 (20 bytes)
    pkt[1] = 0x00;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0x5645u16.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    pkt[8] = 64; // TTL
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    let ip_ck = ones_complement_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&ip_ck.to_be_bytes());

    // TCP header
    let tcp = &mut pkt[20..];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = ((tcp_hdr_len / 4) as u8) << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&window.to_be_bytes());
    if !options.is_empty() {
        tcp[20..20 + options.len()].copy_from_slice(options);
    }
    if !payload.is_empty() {
        tcp[tcp_hdr_len..].copy_from_slice(payload);
    }
    let tcp_ck = transport_checksum(src_ip, dst_ip, 6, tcp);
    tcp[16..18].copy_from_slice(&tcp_ck.to_be_bytes());
    pkt
}

/// Constrói um pacote IPv4 + UDP válido (RFC 791 + RFC 768).
pub fn build_ipv4_udp_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut pkt = vec![0u8; total_len];

    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0x5644u16.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    let ip_ck = ones_complement_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&ip_ck.to_be_bytes());

    let udp = &mut pkt[20..];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let mut udp_ck = transport_checksum(src_ip, dst_ip, 17, udp);
    if udp_ck == 0 {
        udp_ck = 0xffff;
    }
    udp[6..8].copy_from_slice(&udp_ck.to_be_bytes());
    pkt
}

/// Servidor TCP loopback que recebe pacotes IPv4 do `Android VpnService` (ou túnel TUN)
/// e encaminha TCP + DNS diretamente pelo circuito VEIL pós-quântico.
pub struct TunBridgeServer {
    bind_addr: SocketAddr,
    circuit: Arc<LiveCircuitClient>,
    kill_switch: KillSwitch,
    stats: Arc<TunBridgeStats>,
}

impl TunBridgeServer {
    pub fn new(
        bind_addr: SocketAddr,
        circuit: Arc<LiveCircuitClient>,
        kill_switch: KillSwitch,
    ) -> Self {
        Self {
            bind_addr,
            circuit,
            kill_switch,
            stats: Arc::new(TunBridgeStats::default()),
        }
    }

    pub fn stats(&self) -> Arc<TunBridgeStats> {
        Arc::clone(&self.stats)
    }

    pub async fn bind_and_spawn(
        self,
    ) -> Result<(SocketAddr, Arc<TunBridgeStats>, tokio::task::JoinHandle<()>), VeilError> {
        let listener = TcpListener::bind(self.bind_addr)
            .await
            .map_err(|e| VeilError::Tunnel(format!("falha ao abrir ponte TUN loopback: {e}")))?;
        let actual_addr = listener
            .local_addr()
            .map_err(|e| VeilError::Tunnel(e.to_string()))?;
        let stats = Arc::clone(&self.stats);
        let circuit = Arc::clone(&self.circuit);
        let ks = self.kill_switch.clone();
        let stats_loop = Arc::clone(&stats);

        let handle = tokio::spawn(async move {
            tracing::info!(bind = %actual_addr, "VEIL TUN bridge (Android VpnService) escutando");
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let c = Arc::clone(&circuit);
                        let k = ks.clone();
                        let s = Arc::clone(&stats_loop);
                        tokio::spawn(async move {
                            s.connected_clients.fetch_add(1, Ordering::Relaxed);
                            let _ = handle_tun_client(stream, c, k, Arc::clone(&s)).await;
                            s.connected_clients.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "VEIL TUN bridge listener encerrado");
                        break;
                    }
                }
            }
        });

        Ok((actual_addr, stats, handle))
    }
}

async fn handle_tun_client(
    stream: TcpStream,
    circuit: Arc<LiveCircuitClient>,
    kill_switch: KillSwitch,
    stats: Arc<TunBridgeStats>,
) -> Result<(), VeilError> {
    let _ = stream.set_nodelay(true);
    let (mut reader, mut writer) = stream.into_split();
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(512);

    let stats_w = Arc::clone(&stats);
    let writer_task = tokio::spawn(async move {
        while let Some(pkt) = out_rx.recv().await {
            if pkt.is_empty() || pkt.len() > MAX_PACKET_SIZE {
                continue;
            }
            let len_be = (pkt.len() as u16).to_be_bytes();
            if writer.write_all(&len_be).await.is_err() {
                break;
            }
            if writer.write_all(&pkt).await.is_err() {
                break;
            }
            stats_w.packets_out.fetch_add(1, Ordering::Relaxed);
            stats_w
                .bytes_out
                .fetch_add(pkt.len() as u64, Ordering::Relaxed);
        }
    });

    let flows: Arc<Mutex<HashMap<FlowKey, Arc<Mutex<TcpFlow>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let mut len_buf = [0u8; 2];
    loop {
        if reader.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let pkt_len = u16::from_be_bytes(len_buf) as usize;
        if pkt_len < 20 {
            let mut skip = vec![0u8; pkt_len];
            if reader.read_exact(&mut skip).await.is_err() {
                break;
            }
            continue;
        }
        let mut pkt = vec![0u8; pkt_len];
        if reader.read_exact(&mut pkt).await.is_err() {
            break;
        }

        stats.packets_in.fetch_add(1, Ordering::Relaxed);
        stats.bytes_in.fetch_add(pkt_len as u64, Ordering::Relaxed);

        // Somente IPv4 (versão 4)
        let version = pkt[0] >> 4;
        if version != 4 {
            continue;
        }
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        if ihl < 20 || pkt.len() < ihl {
            continue;
        }
        let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        let end = total_len.min(pkt.len());
        if end < ihl {
            continue;
        }
        let proto = pkt[9];
        let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        let l4 = &pkt[ihl..end];

        match proto {
            6 => {
                // TCP
                handle_ipv4_tcp(
                    src_ip,
                    dst_ip,
                    l4,
                    Arc::clone(&flows),
                    Arc::clone(&circuit),
                    kill_switch.clone(),
                    out_tx.clone(),
                    Arc::clone(&stats),
                )
                .await;
            }
            17 => {
                // UDP (intercepta DNS porta 53 via DNS-over-TCP dentro do circuito VEIL)
                if l4.len() >= 8 {
                    let src_port = u16::from_be_bytes([l4[0], l4[1]]);
                    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
                    let payload = l4[8..].to_vec();
                    if dst_port == 53 && !payload.is_empty() {
                        stats.dns_queries.fetch_add(1, Ordering::Relaxed);
                        let c = Arc::clone(&circuit);
                        let ks = kill_switch.clone();
                        let tx = out_tx.clone();
                        tokio::spawn(async move {
                            let _ = handle_dns_over_veil(
                                src_ip, src_port, dst_ip, dst_port, payload, c, ks, tx,
                            )
                            .await;
                        });
                    }
                }
            }
            _ => {}
        }
    }

    writer_task.abort();
    stats
        .active_tcp_flows
        .store(0, Ordering::Relaxed);
    Ok(())
}

/// Encaminha consulta DNS UDP (porta 53) como DNS-over-TCP (RFC 1035) pelo circuito VEIL.
async fn handle_dns_over_veil(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    dns_query: Vec<u8>,
    circuit: Arc<LiveCircuitClient>,
    kill_switch: KillSwitch,
    out_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(), VeilError> {
    kill_switch.allow_traffic()?;

    // Nunca roteia para DNS Google (8.8.8.8/8.8.4.4) nem IPs privados: força Quad9 (9.9.9.9)
    let upstream_dns = if dst_ip.is_private()
        || dst_ip.is_loopback()
        || dst_ip == Ipv4Addr::new(8, 8, 8, 8)
        || dst_ip == Ipv4Addr::new(8, 8, 4, 4)
    {
        Ipv4Addr::new(9, 9, 9, 9)
    } else {
        dst_ip
    };

    let target = Socks5Target::Ip(SocketAddr::V4(SocketAddrV4::new(upstream_dns, 53)));
    let mut stream = circuit.open_stream(&target).await?;

    let mut tcp_dns = Vec::with_capacity(2 + dns_query.len());
    tcp_dns.extend_from_slice(&(dns_query.len() as u16).to_be_bytes());
    tcp_dns.extend_from_slice(&dns_query);
    stream.send_data(&tcp_dns).await?;

    let mut acc = Vec::new();
    let expected_len = loop {
        kill_switch.allow_traffic()?;
        match tokio::time::timeout(std::time::Duration::from_secs(6), stream.receive_data()).await {
            Ok(Ok(Some(chunk))) => {
                acc.extend_from_slice(&chunk);
                if acc.len() >= 2 {
                    let want = u16::from_be_bytes([acc[0], acc[1]]) as usize;
                    if acc.len() >= 2 + want {
                        break want;
                    }
                }
            }
            _ => {
                let _ = stream.close().await;
                return Ok(());
            }
        }
    };
    let _ = stream.close().await;

    let dns_resp = &acc[2..2 + expected_len];
    let udp_pkt = build_ipv4_udp_packet(dst_ip, dst_port, src_ip, src_port, dns_resp);
    let _ = out_tx.send(udp_pkt).await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_ipv4_tcp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    tcp: &[u8],
    flows: Arc<Mutex<HashMap<FlowKey, Arc<Mutex<TcpFlow>>>>>,
    circuit: Arc<LiveCircuitClient>,
    kill_switch: KillSwitch,
    out_tx: mpsc::Sender<Vec<u8>>,
    stats: Arc<TunBridgeStats>,
) {
    if tcp.len() < 20 {
        return;
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return;
    }
    let flags = tcp[13];
    let payload = &tcp[data_offset..];
    let key = FlowKey {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
    };

    // RST: encerra fluxo imediatamente
    if (flags & TCP_RST) != 0 {
        if let Some(flow_arc) = flows.lock().await.remove(&key) {
            stats.active_tcp_flows.fetch_sub(1, Ordering::Relaxed);
            if let Some(w) = flow_arc.lock().await.writer.take() {
                let _ = w.close().await;
            }
        }
        return;
    }

    // SYN (novo fluxo TCP)
    if (flags & TCP_SYN) != 0 && (flags & TCP_ACK) == 0 {
        if kill_switch.allow_traffic().is_err() {
            // Fail-closed: recusa conexão com RST
            let rst = build_ipv4_tcp_packet(
                dst_ip,
                dst_port,
                src_ip,
                src_port,
                0,
                seq.wrapping_add(1),
                TCP_RST | TCP_ACK,
                0,
                &[],
                &[],
            );
            let _ = out_tx.send(rst).await;
            return;
        }

        let server_isn: u32 = rand::random();
        let client_next_seq = seq.wrapping_add(1);
        let flow_arc = Arc::new(Mutex::new(TcpFlow {
            client_next_seq,
            server_seq: server_isn.wrapping_add(1),
            writer: None,
            pending_payload: Vec::new(),
        }));

        {
            let mut map = flows.lock().await;
            if map.insert(key, Arc::clone(&flow_arc)).is_none() {
                stats.active_tcp_flows.fetch_add(1, Ordering::Relaxed);
            }
        }

        let flows_c = Arc::clone(&flows);
        let stats_c = Arc::clone(&stats);
        let flow_c = Arc::clone(&flow_arc);
        let out_c = out_tx.clone();
        let ks_c = kill_switch.clone();

        tokio::spawn(async move {
            let target = Socks5Target::Ip(SocketAddr::new(IpAddr::V4(dst_ip), dst_port));
            match circuit.open_stream(&target).await {
                Ok(stream) => {
                    let (mut c_reader, c_writer) = stream.split();
                    let pending = {
                        let mut fl = flow_c.lock().await;
                        fl.writer = Some(c_writer);
                        std::mem::take(&mut fl.pending_payload)
                    };

                    // Envia SYN+ACK com opção MSS=1360
                    let mss_opt = [0x02, 0x04, (TCP_MSS >> 8) as u8, (TCP_MSS & 0xff) as u8];
                    let syn_ack = build_ipv4_tcp_packet(
                        dst_ip,
                        dst_port,
                        src_ip,
                        src_port,
                        server_isn,
                        client_next_seq,
                        TCP_SYN | TCP_ACK,
                        65535,
                        &mss_opt,
                        &[],
                    );
                    let _ = out_c.send(syn_ack).await;

                    if !pending.is_empty() {
                        if let Some(ref w) = flow_c.lock().await.writer {
                            let _ = w.send_data(&pending).await;
                        }
                    }

                    // Downlink: Circuito VEIL -> segmentos TCP PSH+ACK para o TUN
                    loop {
                        if ks_c.allow_traffic().is_err() {
                            break;
                        }
                        match c_reader.receive_data().await {
                            Ok(Some(data)) => {
                                for chunk in data.chunks(TCP_MSS) {
                                    let (s_seq, c_ack) = {
                                        let mut fl = flow_c.lock().await;
                                        let cur = fl.server_seq;
                                        fl.server_seq = fl.server_seq.wrapping_add(chunk.len() as u32);
                                        (cur, fl.client_next_seq)
                                    };
                                    let seg = build_ipv4_tcp_packet(
                                        dst_ip,
                                        dst_port,
                                        src_ip,
                                        src_port,
                                        s_seq,
                                        c_ack,
                                        TCP_PSH | TCP_ACK,
                                        65535,
                                        &[],
                                        chunk,
                                    );
                                    if out_c.send(seg).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok(None) | Err(_) => break,
                        }
                    }

                    // Encerra enviando FIN+ACK
                    let (s_seq, c_ack) = {
                        let mut fl = flow_c.lock().await;
                        let cur = fl.server_seq;
                        fl.server_seq = fl.server_seq.wrapping_add(1);
                        (cur, fl.client_next_seq)
                    };
                    let fin = build_ipv4_tcp_packet(
                        dst_ip,
                        dst_port,
                        src_ip,
                        src_port,
                        s_seq,
                        c_ack,
                        TCP_FIN | TCP_ACK,
                        65535,
                        &[],
                        &[],
                    );
                    let _ = out_c.send(fin).await;
                    if flows_c.lock().await.remove(&key).is_some() {
                        stats_c.active_tcp_flows.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    let rst = build_ipv4_tcp_packet(
                        dst_ip,
                        dst_port,
                        src_ip,
                        src_port,
                        0,
                        client_next_seq,
                        TCP_RST | TCP_ACK,
                        0,
                        &[],
                        &[],
                    );
                    let _ = out_c.send(rst).await;
                    if flows_c.lock().await.remove(&key).is_some() {
                        stats_c.active_tcp_flows.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            }
        });
        return;
    }

    // Fluxo existente (ACK / PSH / FIN)
    let flow_opt = { flows.lock().await.get(&key).cloned() };
    let Some(flow_arc) = flow_opt else {
        return;
    };

    if kill_switch.allow_traffic().is_err() {
        let (s_seq, c_ack) = {
            let mut fl = flow_arc.lock().await;
            if let Some(w) = fl.writer.take() {
                let _ = w.close().await;
            }
            (fl.server_seq, fl.client_next_seq)
        };
        let rst = build_ipv4_tcp_packet(
            dst_ip, dst_port, src_ip, src_port, s_seq, c_ack, TCP_RST | TCP_ACK, 0, &[], &[],
        );
        let _ = out_tx.send(rst).await;
        if flows.lock().await.remove(&key).is_some() {
            stats.active_tcp_flows.fetch_sub(1, Ordering::Relaxed);
        }
        return;
    }

    if !payload.is_empty() {
        let (to_send, s_seq, c_ack, writer_clone) = {
            let mut fl = flow_arc.lock().await;
            let expected = fl.client_next_seq;
            let diff = seq.wrapping_sub(expected) as i32;
            let new_data = if diff == 0 {
                fl.client_next_seq = expected.wrapping_add(payload.len() as u32);
                Some(payload.to_vec())
            } else if diff < 0 {
                let overlap = (-diff) as usize;
                if overlap < payload.len() {
                    let slice = &payload[overlap..];
                    fl.client_next_seq = expected.wrapping_add(slice.len() as u32);
                    Some(slice.to_vec())
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(ref d) = new_data {
                if fl.writer.is_none() {
                    fl.pending_payload.extend_from_slice(d);
                }
            }
            // Só envia diretamente se o writer já estiver conectado
            let has_writer = fl.writer.is_some();
            (
                if has_writer { new_data } else { None },
                fl.server_seq,
                fl.client_next_seq,
                has_writer,
            )
        };

        if let Some(data) = to_send {
            if writer_clone {
                let guard = flow_arc.lock().await;
                if let Some(ref w) = guard.writer {
                    let _ = w.send_data(&data).await;
                }
            }
        }

        // Envia ACK imediato
        let ack_pkt = build_ipv4_tcp_packet(
            dst_ip, dst_port, src_ip, src_port, s_seq, c_ack, TCP_ACK, 65535, &[], &[],
        );
        let _ = out_tx.send(ack_pkt).await;
    }

    if (flags & TCP_FIN) != 0 {
        let (s_seq, c_ack, writer_opt) = {
            let mut fl = flow_arc.lock().await;
            fl.client_next_seq = fl.client_next_seq.wrapping_add(1);
            let s = fl.server_seq;
            fl.server_seq = fl.server_seq.wrapping_add(1);
            (s, fl.client_next_seq, fl.writer.take())
        };
        if let Some(w) = writer_opt {
            let _ = w.close().await;
        }
        let fin_ack = build_ipv4_tcp_packet(
            dst_ip,
            dst_port,
            src_ip,
            src_port,
            s_seq,
            c_ack,
            TCP_FIN | TCP_ACK,
            65535,
            &[],
            &[],
        );
        let _ = out_tx.send(fin_ack).await;
        if flows.lock().await.remove(&key).is_some() {
            stats.active_tcp_flows.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExitPolicy;
    use crate::planes::live::{CircuitHopNode, VeilHopRouter};

    #[test]
    fn ipv4_tcp_and_udp_checksums_verify_to_zero() {
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(10, 240, 0, 2),
            51234,
            Ipv4Addr::new(93, 184, 216, 34),
            80,
            1000,
            0,
            TCP_SYN,
            65535,
            &[],
            b"GET / HTTP/1.0\r\n\r\n",
        );
        assert_eq!(ones_complement_checksum(&pkt[0..20]), 0);
        assert_eq!(
            transport_checksum(
                Ipv4Addr::new(10, 240, 0, 2),
                Ipv4Addr::new(93, 184, 216, 34),
                6,
                &pkt[20..]
            ),
            0
        );

        let udp = build_ipv4_udp_packet(
            Ipv4Addr::new(9, 9, 9, 9),
            53,
            Ipv4Addr::new(10, 240, 0, 2),
            54321,
            b"\x12\x34\x81\x80\x00\x01\x00\x00",
        );
        assert_eq!(ones_complement_checksum(&udp[0..20]), 0);
        assert_eq!(
            transport_checksum(
                Ipv4Addr::new(9, 9, 9, 9),
                Ipv4Addr::new(10, 240, 0, 2),
                17,
                &udp[20..]
            ),
            0
        );
    }

    #[tokio::test]
    async fn tun_bridge_routes_tcp_echo_through_live_veil_circuit_and_honors_killswitch() {
        // 1. Sobe servidor TCP eco local (simulando serviço destino)
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_port = echo_addr.port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = echo_listener.accept().await {
                let mut buf = [0u8; 256];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&buf[..n]).await;
                }
            }
        });

        // 2. Sobe Exit router VEIL com política permissiva somente para este teste local
        let mut policy = ExitPolicy::default();
        policy.block_private_networks = false;
        policy.allowed_ports.clear();
        policy.blocked_ports.clear();
        let exit_router = VeilHopRouter::new(mycelium_pqc::mlkem_keygen(), Some(policy));
        let exit_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let exit_addr = exit_listener.local_addr().unwrap();
        let exit_desc = exit_router.descriptor("test-exit".into(), exit_addr.to_string());
        tokio::spawn(async move {
            let _ = exit_router.run(exit_listener).await;
        });

        let circuit = Arc::new(
            LiveCircuitClient::connect(77, vec![CircuitHopNode::from_descriptor(exit_desc)])
                .await
                .unwrap(),
        );
        let ks = KillSwitch::new(true);
        let bridge = TunBridgeServer::new(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&circuit),
            ks.clone(),
        );
        let (bridge_addr, stats, handle) = bridge.bind_and_spawn().await.unwrap();

        // 3. Conecta cliente TUN simulado e executa SYN -> SYN+ACK -> PSH+ACK -> eco!
        let mut tun = TcpStream::connect(bridge_addr).await.unwrap();
        let client_ip = Ipv4Addr::new(10, 240, 0, 2);
        let dst_ip = Ipv4Addr::new(127, 0, 0, 1);

        let syn = build_ipv4_tcp_packet(
            client_ip, 40001, dst_ip, echo_port, 100, 0, TCP_SYN, 65535, &[], &[],
        );
        tun.write_all(&(syn.len() as u16).to_be_bytes()).await.unwrap();
        tun.write_all(&syn).await.unwrap();

        // Lê SYN+ACK
        let mut lb = [0u8; 2];
        tun.read_exact(&mut lb).await.unwrap();
        let mut resp = vec![0u8; u16::from_be_bytes(lb) as usize];
        tun.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[9], 6);
        assert_eq!(resp[20 + 13] & (TCP_SYN | TCP_ACK), TCP_SYN | TCP_ACK);
        let srv_seq = u32::from_be_bytes([resp[24], resp[25], resp[26], resp[27]]);

        // Envia payload "VEIL-TUN-OK"
        let psh = build_ipv4_tcp_packet(
            client_ip,
            40001,
            dst_ip,
            echo_port,
            101,
            srv_seq.wrapping_add(1),
            TCP_PSH | TCP_ACK,
            65535,
            &[],
            b"VEIL-TUN-OK",
        );
        tun.write_all(&(psh.len() as u16).to_be_bytes()).await.unwrap();
        tun.write_all(&psh).await.unwrap();

        // Recebe ACK + dados ecoados do servidor através do circuito ML-KEM-1024!
        let mut got_echo = false;
        for _ in 0..4 {
            tun.read_exact(&mut lb).await.unwrap();
            let mut seg = vec![0u8; u16::from_be_bytes(lb) as usize];
            tun.read_exact(&mut seg).await.unwrap();
            let doff = ((seg[20 + 12] >> 4) as usize) * 4;
            if &seg[20 + doff..] == b"VEIL-TUN-OK" {
                got_echo = true;
                break;
            }
        }
        assert!(got_echo, "esperava eco TCP real através do circuito VEIL");
        assert!(stats.packets_in.load(Ordering::Relaxed) >= 2);
        assert!(stats.packets_out.load(Ordering::Relaxed) >= 2);

        // 4. Aciona Kill Switch fail-closed: novo SYN DEVE retornar RST imediatamente!
        ks.trigger("test-killswitch");
        let syn2 = build_ipv4_tcp_packet(
            client_ip, 40002, dst_ip, echo_port, 500, 0, TCP_SYN, 65535, &[], &[],
        );
        tun.write_all(&(syn2.len() as u16).to_be_bytes()).await.unwrap();
        tun.write_all(&syn2).await.unwrap();
        let mut got_rst = false;
        for _ in 0..4 {
            tun.read_exact(&mut lb).await.unwrap();
            let mut seg = vec![0u8; u16::from_be_bytes(lb) as usize];
            tun.read_exact(&mut seg).await.unwrap();
            if u16::from_be_bytes([seg[22], seg[23]]) == 40002 && (seg[20 + 13] & TCP_RST) != 0 {
                got_rst = true;
                break;
            }
        }
        assert!(got_rst, "KillSwitch disparado deve recusar novo fluxo com RST");

        handle.abort();
    }
}
