//! # mycelium-veil — Protocolo VEIL Ω
//!
//! Infraestrutura P2P pós-quântica de privacidade, comunicação e anonimato
//! sobre o Mycelium Network, fundindo:
//! - Criptografia em Camadas ML-KEM-1024 + AEAD ChaCha20-Poly1305.
//! - Plano LIVE (circuitos onion interativos em 1 ou 3 saltos).
//! - Plano MIX (mixnet estocástica com atrasos de Poisson e tráfego de cobertura).
//! - As 7 Camadas Herdadas e Corrigidas do ET-COSMIC-OLD (GhostVPN):
//!   0. Identidade (GhostID efêmero + MAC local administrado)
//!   1. Fragmentação Segura (QEL sem vazar sessionKey)
//!   2. Transporte Fantasma (DistanceBridge multi-canal)
//!   3. Consenso Causal e Anti-Replay (HashChronicle + Cone de Luz)
//!   4. Execução Invisível (ANIMUS/COSMIC Sandbox)
//!   5. Ofuscação Temporal (QRC + Padding Estocástico)
//!   6. Zero-Trace em RAM & Auditabilidade ZKP (Pedersen H Independente)
//! - Proxy SOCKS5 Local (RFC 1928) com Prevenção Total de Vazamento DNS.
//! - Nó de Saída (Exit Node) com Proteção Anti-SSRF.
//! - Kill Switch Fail-Closed e Abstração de Túnel de Sistema.

pub mod bridge;
pub mod config;
pub mod crypto;
pub mod exit;
pub mod identity;
pub mod layers;
pub mod planes;
pub mod socks5;
pub mod transport;
pub mod tunnel;

pub use config::{ExitPolicy, VeilConfig, VeilMode};
pub use bridge::{BridgeEntry, BridgeHandle, BridgeRelay, DirectEntry, EntryConnection, EntryPool, EntryTransport};
pub use crypto::cell::{CellCommand, VeilCell, CELL_SIZE};
pub use crypto::{HopKeys, CryptoError};
pub use identity::{VeilNodeIdentity, VEIL_NODE_IDENTITY_TTL};
pub use exit::{ExitForwarder, ExitPolicyValidator};
pub use layers::{LayerPipeline, VeilLayer};
pub use planes::live::{
    CircuitHopNode, CircuitStreamReader, CircuitStreamWriter, FrameType, InnerMessage,
    LiveCircuit, LiveCircuitClient, LiveCircuitManager, LiveCircuitStream, NodeDescriptor,
    RelayExtendChunk, RelayExtendPayload, VeilHopRouter,
};
pub use planes::mix::{MixMessage, MixPlane};
pub use socks5::{proxy_socks5_connection, Socks5Server, Socks5Target};
pub use transport::{link_handshake_client, link_handshake_server, VeilSecureStream};
pub use tunnel::{KillSwitch, KillSwitchState, PlatformTunnelType, SystemTunnel};
pub use mycelium_pqc;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Erros centrais do Mycelium VEIL Ω.
#[derive(Debug, thiserror::Error)]
pub enum VeilError {
    #[error("erro criptográfico: {0}")]
    Crypto(String),
    #[error("erro em camada do pipeline: {0}")]
    Layer(String),
    #[error("erro de circuito: {0}")]
    Circuit(String),
    #[error("erro SOCKS5: {0}")]
    Socks5(String),
    #[error("erro no nó Exit: {0}")]
    Exit(String),
    #[error("erro no túnel de sistema: {0}")]
    Tunnel(String),
    #[error("nenhuma sessão ativa")]
    NoActiveSession,
    /// Um `std::sync::Mutex` foi envenenado por um pânico anterior e o estado
    /// sob ele não pode ser considerado válido.
    ///
    /// Usado pelos caminhos que **propagam** (`start_session`, `route`) para
    /// falhar fechado em vez de recuperar uma sessão possivelmente meio-atualizada.
    /// Os caminhos que não propagam (`stop_session`, `is_active`,
    /// `current_session`) armam o latch `session_poisoned` e devolvem o valor
    /// seguro em vez deste erro.
    #[error("estado interno envenenado: {0}")]
    Poisoned(&'static str),
}

/// Sessão ativa do Veil com isolamento e descarte seguro em memória.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VeilSession {
    #[zeroize(skip)]
    pub session_id: String,
    #[zeroize(skip)]
    pub mode: VeilMode,
    #[zeroize(skip)]
    pub started_at: u64,
    pub bytes_routed: u64,
    /// Camadas de privacidade **realmente aplicadas ao tráfego desta sessão**.
    ///
    /// Não é o total de camadas implementadas em [`crate::layers`] — é o que sai de
    /// [`VeilEngine::wired_layer_count`].
    #[zeroize(skip)]
    pub active_layers: usize,
    pub mac_address: [u8; 6],
    #[zeroize(skip)]
    pub exit_node: String,
}

/// Motor principal do Mycelium VEIL Ω.
pub struct VeilEngine {
    config: VeilConfig,
    pipeline: LayerPipeline,
    /// `true` **somente** se `pipeline` estiver de fato no caminho de dados.
    ///
    /// Hoje é `false`: nenhum ponto de entrada de produção chama `route`/`decode`
    /// (ver o aviso em [`crate::layers`]). Enquanto for `false`, a telemetria
    /// reporta 0 camadas em operação em vez de 7.
    pipeline_on_data_path: bool,
    live_manager: LiveCircuitManager,
    mix_plane: MixPlane,
    tunnel: SystemTunnel,
    /// Guarda da sessão ativa.
    ///
    /// IMPORTANTE — esta guarda **não** protege material criptográfico.
    /// [`VeilSession`] contém apenas `session_id`, `mode`, `started_at`,
    /// `bytes_routed`, `active_layers`, `mac_address` e `exit_node`; todo o
    /// material de chaves vive em [`planes::live`] (campos próprios de
    /// `LiveCircuitClient`/`LiveCircuitStream`, protegidos por
    /// `tokio::sync::Mutex`, que não envenena). Portanto, envenenar esta guarda
    /// é um problema de **contabilidade e anonimato** (contadores e um MAC
    /// reportados com valores não verificados), **não** de gestão de chaves.
    ///
    /// Consequência prática: a guarda nunca pode ser mantida atravessando
    /// [`LayerPipeline::process`], que é a seção crítica com maior probabilidade
    /// de pânico do crate (aloca em todas as 7 camadas) e não toca em `session`.
    /// Ver [`VeilEngine::route`].
    session: Arc<Mutex<Option<VeilSession>>>,
    /// Latch fail-closed: armado quando `session` foi observada envenenada.
    ///
    /// Enquanto armado, [`VeilEngine::start_session`] e [`VeilEngine::route`]
    /// recusam com [`VeilError::Poisoned`] — um motor envenenado não pode ser
    /// reutilizado em silêncio. Só um `start_session` bem-sucedido rearma.
    session_poisoned: AtomicBool,
}

impl VeilEngine {
    pub fn new(config: VeilConfig) -> Self {
        let mut pipeline = LayerPipeline::new();
        pipeline.activate_all();

        // O pipeline de 7 camadas é compilado e ativado, mas NÃO está no caminho de
        // dados de produção: o tráfego real passa por `planes::live` + `bridge`.
        // Registrado aqui para que o operador não seja informado de 7 camadas ativas.
        tracing::warn!(
            "VEIL Ω: as 7 camadas de `layers::LayerPipeline` estão projetadas mas NÃO \
             ligadas ao caminho de dados de produção (status: projetado, não ligado); \
             o tráfego real usa planes::live + bridge. `active_layers` reportará 0. \
             Ver mycelium_veil::layers."
        );

        let live_manager = LiveCircuitManager::new();
        let mix_plane = MixPlane::new(1, config.mix_cover_rate_hz);
        let tunnel = SystemTunnel::new("veil0".into(), PlatformTunnelType::UserspaceProxy);

        Self {
            config,
            pipeline,
            pipeline_on_data_path: false,
            live_manager,
            mix_plane,
            tunnel,
            session: Arc::new(Mutex::new(None)),
            session_poisoned: AtomicBool::new(false),
        }
    }

    /// Quantas camadas de privacidade estão **de fato** operando no caminho de dados.
    ///
    /// Retorna `0` enquanto o [`LayerPipeline`] não estiver ligado à produção. Hoje
    /// os únicos consumidores de `pipeline` são [`VeilEngine::route`] e
    /// [`VeilEngine::decode`], e nenhum ponto de entrada de produção os chama — o
    /// tráfego real é roteado por [`LiveCircuitClient`]/[`VeilHopRouter`]
    /// (`planes::live`) e [`EntryPool`]/[`BridgeRelay`] (`bridge`). Ver o aviso em
    /// [`crate::layers`].
    ///
    /// É este número — e não a contagem de camadas implementadas — que alimenta a
    /// telemetria `VeilStatusResult::active_layers` no nó.
    pub fn wired_layer_count(&self) -> usize {
        if !self.pipeline_on_data_path {
            return 0;
        }
        self.pipeline.layers.iter().filter(|l| l.is_active()).count()
    }

    /// Inicia uma nova sessão Veil com identidade efêmera e MAC administrado localmente.
    ///
    /// Recusa com [`VeilError::Poisoned`] se a guarda de sessão já foi observada
    /// envenenada: o motor não pode ser reutilizado em silêncio. O rearme
    /// acontece **aqui e somente aqui**, depois de a nova sessão ser gravada.
    pub fn start_session(&self, mode: VeilMode) -> Result<VeilSession, VeilError> {
        if self.session_poisoned.load(Ordering::SeqCst) {
            tracing::error!(
                campo = "VeilEngine::session",
                "start_session recusado: motor envenenado anteriormente; é necessário um start_session \
                 bem-sucedido para rearme"
            );
            return Err(VeilError::Poisoned("VeilEngine::session (start_session)"));
        }

        let session_id = format!("veil_{}_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(), hex::encode(&rand::random::<[u8; 4]>()));

        // Obtém MAC da camada 0
        let mac_address = if let Some(l0) = self.pipeline.layers.first() {
            let mut buf = [0u8; 6];
            let out = l0.process(b"")?;
            if out.len() >= 38 {
                buf.copy_from_slice(&out[32..38]);
            }
            buf
        } else {
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]
        };

        let exit_hash = blake3::hash(&rand::random::<[u8; 32]>());
        let exit_node = hex::encode(&exit_hash.as_bytes()[..8]);

        let session = VeilSession {
            session_id: session_id.clone(),
            mode,
            started_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            bytes_routed: 0,
            active_layers: self.wired_layer_count(),
            mac_address,
            exit_node,
        };

        // Propaga: uma sessão possivelmente meio-atualizada por um pânico
        // anterior não pode ser silenciosamente substituída nem reutilizada.
        match self.session.lock() {
            Ok(mut lock) => *lock = Some(session.clone()),
            Err(poisoned) => {
                self.session_poisoned.store(true, Ordering::SeqCst);
                tracing::error!(
                    campo = "VeilEngine::session",
                    "guarda de sessão envenenada em start_session(); sessão nova descartada"
                );
                drop(poisoned);
                return Err(VeilError::Poisoned("VeilEngine::session (start_session)"));
            }
        }

        // Rearme explícito: só uma sessão realmente gravada devolve o motor ao
        // estado operacional.
        self.session_poisoned.store(false, Ordering::SeqCst);
        tracing::info!(session_id = %session_id, mode = ?mode, "Sessão VEIL Ω iniciada com sucesso");

        Ok(session)
    }

    /// Roteia dados através das 7 camadas ativas (encapsulamento de saída).
    ///
    /// ATENÇÃO: nenhum caminho de produção chama este método — ver o banner em
    /// [`crate::layers`]. Ele existe para exercitar o pipeline.
    ///
    /// O pipeline roda **fora** da guarda de sessão, deliberadamente.
    /// `LayerPipeline::process(&self, ..)` recebe apenas a si mesmo e as
    /// camadas (`&self`), sem qualquer acesso a `VeilEngine::session` — logo
    /// movê-lo para fora do guard não altera nenhum resultado. Mantido dentro,
    /// ele era a seção crítica de maior probabilidade de pânico do crate
    /// (alocação em cada uma das 7 camadas) segurando o lock, e um pânico ali
    /// envenenava a guarda com `bytes_routed` pela metade — justamente o valor
    /// de telemetria e anonimato que não pode ser reportado sem verificação.
    /// A guarda agora cobre apenas a atualização contábil, que não aloca nem
    /// faz I/O.
    pub fn route(&self, data: &[u8]) -> Result<Vec<u8>, VeilError> {
        // Verifica Kill Switch
        self.tunnel.kill_switch.allow_traffic()?;

        if self.session_poisoned.load(Ordering::SeqCst) {
            tracing::error!(
                campo = "VeilEngine::session",
                "route recusado: motor envenenado anteriormente; é necessário um start_session \
                 bem-sucedido para rearme"
            );
            return Err(VeilError::Poisoned("VeilEngine::session (route)"));
        }

        // Seção crítica movida para fora do guard: o pipeline roda sem nenhuma
        // guarda de sessão retida.
        let processed = self.pipeline.process(data)?;

        // A partir daqui só há aritmética sem alocação sob o guard.
        let mut lock = match self.session.lock() {
            Ok(lock) => lock,
            Err(poisoned) => {
                self.session_poisoned.store(true, Ordering::SeqCst);
                tracing::error!(
                    campo = "VeilEngine::session",
                    "guarda de sessão envenenada em route(); bytes_routed NÃO contabilizado — \
                     falha fechada em vez de recuperar contagem não verificada"
                );
                drop(poisoned);
                return Err(VeilError::Poisoned("VeilEngine::session (route)"));
            }
        };
        let session = lock.as_mut().ok_or(VeilError::NoActiveSession)?;
        session.bytes_routed += processed.len() as u64;

        Ok(processed)
    }

    /// Decodifica dados recebidos na ordem reversa das camadas (desencapsulamento de entrada).
    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, VeilError> {
        self.tunnel.kill_switch.allow_traffic()?;
        self.pipeline.recover(data)
    }

    /// Encerra a sessão ativa e destrói o material criptográfico volátil em memória.
    ///
    /// Não propaga. Mesmo envenenada, a guarda é usada para **limpar** a sessão:
    /// descartá-la é o que libera a memória, então essa parte nunca pode ser
    /// pulada. Só o latch e o log são acréscimos.
    pub fn stop_session(&self) {
        let session = match self.session.lock() {
            Ok(mut lock) => lock.take(),
            Err(poisoned) => {
                // Fail-closed: descartar a sessão é obrigatório mesmo com a guarda
                // envenenada — o drop é o que libera a memória. O latch impede
                // que o motor seja reutilizado em silêncio.
                let mut lock = poisoned.into_inner();
                let session = lock.take();
                self.session_poisoned.store(true, Ordering::SeqCst);
                tracing::error!(
                    campo = "VeilEngine::session",
                    "guarda de sessão envenenada em stop_session(); sessão descartada, latch armado"
                );
                session
            }
        };
        if let Some(session) = session {
            tracing::info!(session_id = %session.session_id, bytes = session.bytes_routed, "Sessão VEIL Ω encerrada e memória limpa");
        }
    }

    /// Configuração do motor.
    pub fn config(&self) -> &VeilConfig {
        &self.config
    }

    /// Retorna as estatísticas da sessão atual.
    ///
    /// Não propaga. Reporta `false` — a direção segura — quando a guarda está
    /// envenenada ou quando o latch está armado: um `true` recuperado seria um
    /// sinal fail-open de "circuito vivo" para um motor em estado desconhecido.
    pub fn is_active(&self) -> bool {
        if self.session_poisoned.load(Ordering::SeqCst) {
            return false;
        }
        match self.session.lock() {
            Ok(lock) => lock.is_some(),
            Err(poisoned) => {
                drop(poisoned);
                self.session_poisoned.store(true, Ordering::SeqCst);
                tracing::error!(
                    campo = "VeilEngine::session",
                    "guarda de sessão envenenada em is_active(); reportando inativo, latch armado"
                );
                false
            }
        }
    }

    /// Retorna uma cópia da sessão ativa (se houver).
    ///
    /// Não propaga. Reporta `None` — a sessão como **ausente** — quando a guarda
    /// está envenenada ou quando o latch está armado, para que o daemon não
    /// publique `bytes_routed`/`active_layers`/`mac_address` sem verificação.
    pub fn current_session(&self) -> Option<VeilSession> {
        if self.session_poisoned.load(Ordering::SeqCst) {
            return None;
        }
        match self.session.lock() {
            Ok(lock) => lock.clone(),
            Err(poisoned) => {
                drop(poisoned);
                self.session_poisoned.store(true, Ordering::SeqCst);
                tracing::error!(
                    campo = "VeilEngine::session",
                    "guarda de sessão envenenada em current_session(); sessão reportada como \
                     ausente, latch armado"
                );
                None
            }
        }
    }

    /// Acesso ao Kill Switch.
    pub fn kill_switch(&self) -> &KillSwitch {
        &self.tunnel.kill_switch
    }

    /// Acesso ao gerenciador de circuitos LIVE.
    pub fn live_circuits(&self) -> &LiveCircuitManager {
        &self.live_manager
    }

    /// Acesso ao plano MIX.
    pub fn mix_plane(&self) -> &MixPlane {
        &self.mix_plane
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_7_layer_pipeline_roundtrip() {
        let config = VeilConfig::default();
        let engine = VeilEngine::new(config);

        let session = engine.start_session(VeilMode::Veil).expect("start session");
        // As 7 camadas existem e estão *ativadas* no pipeline, mas o pipeline não
        // está no caminho de dados de produção (ver `crate::layers`): o número
        // honesto de camadas em operação é 0, não 7. O roundtrip abaixo segue
        // válido porque `route`/`decode` dirigem o pipeline explicitamente.
        assert_eq!(session.active_layers, 0);
        assert_eq!(engine.wired_layer_count(), 0);

        let original_data = b"requisicao secreta navegando atraves das 7 camadas do Mycelium VEIL";

        // Encapsula nas 7 camadas (0 -> 6)
        let routed = engine.route(original_data).expect("route through 7 layers");
        assert_ne!(routed, original_data);

        // Desencapsula na ordem reversa (6 -> 0)
        let recovered = engine.decode(&routed).expect("decode through 7 layers");
        assert_eq!(recovered, original_data);

        engine.stop_session();
        assert!(!engine.is_active());
    }

    #[test]
    fn kill_switch_blocks_route_when_triggered() {
        let config = VeilConfig::default();
        let engine = VeilEngine::new(config);
        engine.start_session(VeilMode::Geo).expect("start session");

        // Circuito saudavel: transita normalmente
        assert!(engine.route(b"ping").is_ok());

        // Simula queda de circuito
        engine.kill_switch().trigger("Circuito interrompido");

        // Deve falhar imediatamente (fail-closed)
        assert!(engine.route(b"ping").is_err());
    }
}
