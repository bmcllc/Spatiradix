//! Organismo: o nó vivo — hifas + Spore Bank + Lattice + Chambers + Event Horizon.

/// Haver limite de saltos do `LayerNeed` no overlay de zonas (forwarding
/// greedy) — evita loop infinito quando a layer não existe em lugar nenhum.
pub const MAX_LAYER_NEED_HOPS: u8 = 4;

/// Alvo de detentores (além do próprio nó) para um plot público. Abaixo disso,
/// a queda de um detentor dispara repin (E1.3).
const TARGET_SPORE_HOLDERS: usize = 2;

/// TTL (epoch secs) de um detentor no índice anti-entropy: sem manifesto
/// recente, é considerado morto e removido.
const SPORE_HOLDER_TTL_SECS: u64 = 300;

use crate::control::{ControlMsg, Request, Response, StatusReport};
use crate::protocol::Envelope;
use crate::store::{IonRecord, NodeStore, OrganismState, StoreError};
use giggs::{Leaf, Plot, RefStore, RefUpdate, SignedRefUpdate};
use inertia::{
    AttestationPayload, AttestationStore, Flywheel, Momentum, SignedAttestation, Thrust, Vector,
};
use isotope::{Atom, Nucleus, DEFAULT_RING_SIZE};
use mycelium_core::{ContentId, FruitingBody, Membrane, NodeId, Nutrient, Resources};
use mycelium_hyphae::{
    detect_global_ipv6, diagnose_membrane, env_assume_reachable, with_membrane_flag, HyphaEvent,
    HyphaeConfig, HyphaeNode, MailboxMessage, RelayAdvertisement, SeedBook, DEFAULT_DNS_SEED_NAME,
    MAILBOX_DHT_PREFIX, RELAY_DHT_PREFIX,
};
use mycelium_nutrients::Ledger;
use mycelium_pheromones::{Gland, Trail};
use mycelium_sporebank::{
    content_id_from_layer_dht_key, dht_key, layer_dht_key, SporeBank,
};
use mycelium_tropical::{MyceliumPhase, PhysarumNetwork};
use plasma::{Charge, Cloud, Ion};
use singularity::{serve_horizon, EventHorizon, HorizonHandle, HorizonTable, Orbit};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thefield::{Proposal, SignalState};
use tokio::sync::mpsc;
use vacuum::{
    Chamber, ChamberProcess, FruitOptions, Isolation, LayerArchive, LayerStore, Void,
};

#[derive(Debug, thiserror::Error)]
pub enum OrganismError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Spore(#[from] mycelium_sporebank::SporeBankError),
    #[error(transparent)]
    Hyphae(#[from] mycelium_hyphae::HyphaeError),
    #[error(transparent)]
    Field(#[from] thefield::FieldError),
    #[error(transparent)]
    Vacuum(#[from] vacuum::VacuumError),
    #[error(transparent)]
    Nutrient(#[from] mycelium_nutrients::NutrientError),
    #[error("{0}")]
    Msg(String),
}

impl From<String> for OrganismError {
    fn from(s: String) -> Self {
        OrganismError::Msg(s)
    }
}

/// Epoch seconds (UTC), tolerante a clock pré-1970 (retorna 0).
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct OrganismConfig {
    pub home: PathBuf,
    pub contribute: Option<Resources>,
    pub bootstrap: Vec<String>,
    pub horizon_port: u16,
    /// Multiaddrs de escuta (ex.: `/ip4/0.0.0.0/tcp/4001` para ser seed público).
    pub listen: Vec<String>,
    pub seed_file: Option<PathBuf>,
    pub public_bootstrap: bool,
    pub bootstrap_url: Option<String>,
    pub enable_mdns: bool,
    /// IP público anunciado (NAT / seed).
    pub announce_ip: Option<String>,
    /// IPv6 público anunciado (`MYCELIUM_ANNOUNCE_IP6`).
    pub announce_ip6: Option<String>,
    /// Seed opera como circuit relay v2.
    pub enable_relay: bool,
    /// Volunteer Sporocarp: relay + DNS + crédito ATP.
    pub sporocarp: bool,
    /// Override explícito da membrana (`--membrane`).
    pub membrane: Option<Membrane>,
    /// Inbound TCP/QUIC verificado (`--assume-reachable` / `MYCELIUM_REACHABLE`).
    pub assume_reachable: bool,
    /// Escuta webrtc-direct (build com `--features webrtc`).
    pub enable_webrtc: bool,
    pub webrtc_port: u16,
    /// Transporte libp2p sobre Nostr.
    /// `None` = auto (folha/floresta); `Some(true/false)` = forçar.
    pub nostr_transport: Option<bool>,
    pub nostr_relay: Option<String>,
    /// Allowlist de peers licenciados (VOID-00). Se `Some`, o gate de admissão
    /// licenciada é ativado: apenas estes PeerIds se conectam. Req. feature `license`.
    #[cfg(feature = "license")]
    pub licensed_peers: Option<std::collections::HashSet<String>>,
    pub veil_enabled: bool,
    pub veil_socks5_addr: Option<std::net::SocketAddr>,
    pub veil_mode: Option<String>,
    pub veil_role: Option<String>,
    pub veil_listen: Option<std::net::SocketAddr>,
    pub veil_guards: Vec<String>,
    pub veil_middles: Vec<String>,
    pub veil_exits: Vec<String>,
    /// Pinning de identidade para modo produção: `"<papel>:<hex_identity_pubkey>"` (ex.: "guard:<hex>").
    /// Quando presente, o cliente exige que cada salto apresente a identidade fixada (anti-substituição).
    pub veil_trust: Vec<String>,
    /// Endereço público anunciado no descritor assinado (alcançável pelos demais nós).
    /// Nunca 0.0.0.0 — separado do endereço de escuta (`--veil-listen`).
    pub veil_advertise: Option<String>,
    /// Caminho da identidade persistente do nó (GhostId + par ML-KEM-1024).
    /// Padrão: `{home}/veil-identity.json` (permissões 0600).
    pub veil_identity_path: Option<PathBuf>,
    /// Rota a identidade Veil explicitamente (nunca implícita em reinício).
    pub veil_rotate_identity: bool,
    /// IP de origem explícito para o egresso do Exit (hosts multi-homing).
    /// Sob NAT, o destino observa o IP da tradução, não este bind.
    pub veil_egress_bind: Option<std::net::IpAddr>,
    /// Pontes de entrada VEIL (repetível, ex.: `127.0.0.1:9001`). Quando presente,
    /// o cliente constrói um [`EntryPool`] somente-bridges e NUNCA insere entrada
    /// direta ao Guard implicitamente.
    pub veil_bridges: Vec<String>,
    /// Endereço de escuta da bridge (papel `bridge`).
    pub veil_bridge_listen: Option<String>,
    /// Endereço do Guard para o qual a bridge repassa o fluxo cru (papel `bridge`).
    pub veil_bridge_target: Option<String>,
    /// **Modo anônimo** (`--anonymous`): SOCKS5 local (VEIL/Tor) por onde sai
    /// todo o tráfego de rede do nó. Ver [`check_anonymous`].
    pub anonymous_socks5: Option<std::net::SocketAddr>,
}

pub struct Organism {
    store: NodeStore,
    gland: Gland,
    ledger: Ledger,
    resources: Resources,
    hyphae: HyphaeNode,
    bank: SporeBank,
    state: OrganismState,
    flywheel: Flywheel,
    cloud: Cloud,
    horizon: HorizonTable,
    chambers: HashMap<String, ChamberProcess>,
    mycelium_bin: PathBuf,
    processed: HashSet<ContentId>,
    horizon_handle: Option<HorizonHandle>,
    seed_book: SeedBook,
    nucleus: Nucleus,
    /// Artefato do último Build bem-sucedido (por plot).
    build_artifacts: HashMap<ContentId, LayerArchive>,
    /// Vectors remotos já aceitos (evita re-execução).
    remote_done: HashSet<String>,
    /// Decays em curso (miss local → DecayQuery broadcast).
    pending_decays: HashSet<String>,
    sporocarp: bool,
    /// Modo anônimo: nada de discagem TCP crua (health check de seeds, DuckDNS).
    anonymous: bool,
    membrane: Membrane,
    dns_seed: Option<String>,
    /// Operador afirmou inbound alcançável (WAN relayável).
    assume_reachable: bool,
    /// Rede Physarum (tick periódico no loop RSA leve).
    physarum: PhysarumNetwork,
    physarum_phase: MyceliumPhase,
    enable_nostr_transport: bool,
    /// Relay primário do transporte Nostr (o mesmo em que a hifa escuta).
    #[cfg_attr(not(feature = "nostr-transport"), allow(dead_code))]
    nostr_relay: String,
    /// Descoberta CandidateRelay corre numa tarefa; o resultado volta por aqui.
    nostr_found_tx: mpsc::UnboundedSender<NostrFound>,
    nostr_found_rx: Option<mpsc::UnboundedReceiver<NostrFound>>,
    nostr_discovering: bool,
    /// Início da última ronda (o fallback de mensagens não martela relays).
    nostr_last_round: Option<Instant>,
    vault: entropy::Vault,
    remote_ledger: HashMap<NodeId, (HashMap<Nutrient, u64>, u64)>,
    known_zones: HashMap<String, Vec<NodeId>>,
    /// Último anúncio (epoch secs) por custodian de zona — para TTL/cleanup.
    known_zones_ts: HashMap<NodeId, u64>,
    /// Quantas vezes resolveu rota DHT (`ClosestPeers`) no overlay de zonas.
    routing_hits: u64,
    #[cfg(feature = "veil")]
    veil_engine: Option<std::sync::Arc<mycelium_veil::VeilEngine>>,
    #[cfg(feature = "veil")]
    veil_socks5_handle: Option<tokio::task::JoinHandle<()>>,
    #[cfg(feature = "veil")]
    veil_socks5_addr: Option<std::net::SocketAddr>,
    #[cfg(feature = "veil")]
    veil_mode: Option<String>,
    #[cfg(feature = "veil")]
    veil_role: Option<String>,
    #[cfg(feature = "veil")]
    veil_listen: Option<std::net::SocketAddr>,
    #[cfg(feature = "veil")]
    veil_guards: Vec<String>,
    #[cfg(feature = "veil")]
    veil_middles: Vec<String>,
    #[cfg(feature = "veil")]
    veil_exits: Vec<String>,
    #[cfg(feature = "veil")]
    veil_trust: Vec<String>,
    #[cfg(feature = "veil")]
    veil_advertise: Option<String>,
    #[cfg(feature = "veil")]
    veil_identity_path: Option<PathBuf>,
    #[cfg(feature = "veil")]
    veil_rotate_identity: bool,
    #[cfg(feature = "veil")]
    veil_egress_bind: Option<std::net::IpAddr>,
    #[cfg(feature = "veil")]
    veil_bridges: Vec<String>,
    #[cfg(feature = "veil")]
    veil_bridge_listen: Option<String>,
    #[cfg(feature = "veil")]
    veil_bridge_target: Option<String>,
    #[cfg(feature = "veil")]
    veil_local_descriptor: Option<String>,
    #[cfg(feature = "veil")]
    veil_enabled: bool,
    #[cfg(feature = "veil")]
    veil_router_handles: Vec<tokio::task::JoinHandle<()>>,
    /// Handles das bridges de entrada ativas (P1.3.2). No papel `bridge`, cada
    /// elemento corresponde a um [`BridgeHandle`] de um relay de bridge em execução;
    /// o drop drena e encerra todos.
    #[cfg(feature = "veil")]
    veil_bridge_handles: Vec<mycelium_veil::bridge::BridgeHandle>,
    /// Pool de entradas somente-bridges do modo client (P1.3.2). Nunca contém
    /// entrada direta ao Guard. `None` = cliente com origens diretas (legado).
    #[cfg(feature = "veil")]
    veil_entry_pool: Option<mycelium_veil::bridge::EntryPool>,
    /// Id da bridge que autenticou com o Guard na última chamada bem-sucedida
    /// (observabilidade do status; vazio se nenhuma entrou ainda).
    #[cfg(feature = "veil")]
    veil_active_entry: Option<String>,
    /// Ids registradas no pool de entradas (somente bridges) do modo client.
    #[cfg(feature = "veil")]
    veil_registered_entries: Vec<String>,
    /// Quantas entradas falharam antes do sucesso (ou até esgotar) na última
    /// inicialização do circuito (observabilidade do failover).
    #[cfg(feature = "veil")]
    veil_failover_attempts: usize,
    /// Motivos de falha por entrada/estágio da última inicialização do circuito.
    #[cfg(feature = "veil")]
    veil_failure_reasons: Vec<String>,
    ion_hosts: HashMap<String, String>,
    /// Catálogo da Mycelium Store. Este `Arc<Mutex<StoreCatalog>>` é COMPARTILHADO
    /// com `crates/mycelium-store`, que o recebe em `StoreAppState::catalog` e o
    /// serve por HTTP — as duas pontas precisam concordar sobre o contrato:
    /// - Tolerância a `Poison`: o `Poison` deixa de ser absorvido em silêncio.
    ///   Toda aquisição passa por `catalog_locked` (abaixo), que faz `match` ao
    ///   RESULTADO do `lock()`: `Ok` segue, `Err(poisoned)` é registado e
    ///   recusado com `CatalogError::Poisoned`. A tolerância continua a valer
    ///   APENAS para VIVACIDADE (o nó e a API seguem respondendo); ela NÃO é
    ///   garantia de correção — o índice recuperado é revalidado por
    ///   `StoreCatalog::validate` contra `catalog.json` ANTES de ser consumido.
    /// - `crates/mycelium-store` mantém esse tratamento idêntico: o seu
    ///   `catalog_locked` observa o mesmo `Poison` no mesmo ponto e chama a
    ///   mesma `validate()`. Divergir entre as duas pontas é o que reintroduz o
    ///   estado partido (uma ponte viva, a outra em recusa permanente), e é o
    ///   que esta duplicação impede.
    /// - Nenhum guarda é mantido através de trabalho bloqueante ou que possa entrar
    ///   em pânico (fork/exec, escrita em disco): o necessário é clonado sob o
    ///   guarda e o guarda é descartado antes.
    catalog: std::sync::Arc<std::sync::Mutex<mycelium_store::StoreCatalog>>,
    home: PathBuf,
    /// Identidade de assinatura (GhostID/NIP-01) para a Micelial Value Layer.
    ghost: mycelium_ghostid::GhostId,
    /// Registro de ativos RWA / empresas (Fase 3/4).
    assets: crate::assets::AssetRegistry,
    /// Nonce de transferência emitida (anti-replay).
    transfer_nonce: u64,
    /// Réplicas remotas vivas por ion (anunciadas via IonReady).
    ion_replica_peers: HashMap<String, Vec<NodeId>>,
    /// Último heartbeat de réplica por (Ion, NodeId) (epoch secs) — refresh via
    /// `IonHeartbeat`, usado para podar réplicas caídas antes do TTL do
    /// `peer_ions` (detecção de falha mais rápida no WAN).
    ion_replica_heartbeat: HashMap<(String, NodeId), u64>,
    /// Catálogo global de ions que pares expõem no seu Horizon.
    /// Chave = NodeId do peer, Valor = (ions, último anúncio Unix secs).
    peer_ions: HashMap<NodeId, (Vec<String>, u64)>,
    /// Detentores vivos por plot público, alimentado por `SporeManifest`:
    /// `ContentId` → (PeerId declarado → último manifesto em epoch secs).
    /// Base da detecção de detentor offline + repin (E1.3).
    spore_holders: HashMap<ContentId, HashMap<String, u64>>,
    /// Flag: a console ErgOTOS foi visitada desde o último tick (auto-semeadura).
    console_hit: bool,
    /// Timestamp (unix secs) do último brotamento de ergot-seed (rate-limit 1/min).
    last_brood: u64,
    /// Janelas consecutivas de carga zero por ion local (gatilho de recombine).
    zero_load_windows: HashMap<String, u32>,
    /// Cooldown do último IonOffer de auto-scaling por ion.
    last_scaling_offer: HashMap<String, Instant>,
    /// Repositórios anunciados via gossipsub (nome → (url, commit, descrição, from)).
    known_repos: HashMap<String, (String, String, String, NodeId)>,
    /// Migrações aceitas pendentes de IonMigrate (autenticação de fluxo).
    pending_accepted_migrations: HashSet<String>,
    /// Inbox efêmera S1 LIVE. Nunca é persistida em disco.
    s1_live_inbox: VecDeque<(u64, String)>,
}

/// Relay Nostr padrão do modo anônimo: aceita WebSocket vindo de saídas Tor
/// (medido em 2026-10-19; `nos.lol` não aceita).
pub const ANONYMOUS_DEFAULT_NOSTR_RELAY: &str = "wss://relay.damus.io";

/// Resultado de uma ronda de descoberta Nostr entregue ao laço.
#[cfg(feature = "nostr-transport")]
type NostrFound = Result<mycelium_hyphae::NostrDiscovery, String>;
#[cfg(not(feature = "nostr-transport"))]
type NostrFound = ();

/// Modo anônimo fail-closed: toda opção que revelaria o IP do nó é **erro**,
/// não aviso. Variáveis de ambiente que mudariam isso também são recusadas.
pub fn check_anonymous(config: &OrganismConfig) -> Result<(), OrganismError> {
    let Some(proxy) = config.anonymous_socks5 else {
        return Ok(());
    };
    let refuse = |why: &str| Err(OrganismError::Msg(format!("modo anônimo recusou: {why}")));
    if !proxy.ip().is_loopback() {
        return refuse("o SOCKS5 precisa ser loopback (127.0.0.1/::1)");
    }
    if config.public_bootstrap || config.bootstrap_url.is_some() {
        return refuse("bootstrap público/HTTP buscaria seeds fora do proxy");
    }
    if config.sporocarp || config.enable_relay || config.assume_reachable {
        return refuse("sporocarp/relay/inbound público expõe o IP");
    }
    if !config.listen.is_empty() {
        return refuse("--listen em IP não é permitido");
    }
    if config.announce_ip.is_some() || config.announce_ip6.is_some() {
        return refuse("--announce-ip não é permitido");
    }
    if config.enable_webrtc {
        return refuse("WebRTC (UDP direto) não é permitido");
    }
    if config.nostr_transport == Some(false) {
        return refuse("o transporte Nostr é o único transporte anônimo; não pode ser desligado");
    }
    if config.enable_mdns {
        return refuse("mDNS anuncia o nó na LAN; use --no-mdns");
    }
    for var in [
        "MYCELIUM_ANNOUNCE_IP",
        "MYCELIUM_ANNOUNCE_IP6",
        "MYCELIUM_DNS_SEEDS",
        "MYCELIUM_REACHABLE",
        "DUCKDNS_TOKEN",
    ] {
        if std::env::var(var).map(|v| !v.is_empty()).unwrap_or(false) {
            return refuse(&format!("variável {var} definida"));
        }
    }
    if let Ok(bind) = std::env::var("MYCELIUM_HORIZON_BIND") {
        let ok = bind
            .parse::<std::net::SocketAddr>()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false);
        if !ok {
            return refuse("MYCELIUM_HORIZON_BIND precisa ser loopback");
        }
    }
    if let Some(role) = config.veil_role.as_deref() {
        if role != "client" {
            return refuse("papel VEIL que aceita conexões (relay/exit/bridge) expõe o IP");
        }
    }
    if config.veil_listen.is_some() || config.veil_bridge_listen.is_some() || config.veil_advertise.is_some() {
        return refuse("escuta/anúncio VEIL expõe o IP");
    }
    Ok(())
}

fn ensure_repo_publishable(plot: &Plot) -> Result<(), OrganismError> {
    if plot.is_public() {
        Ok(())
    } else {
        Err(OrganismError::Msg(
            "RepoPublish recusado: Plot privado não pode sair do nó".into(),
        ))
    }
}

#[cfg(feature = "veil")]
fn parse_veil_descriptor_source(s: &str) -> Result<mycelium_veil::planes::live::NodeDescriptor, OrganismError> {
    let raw = if std::path::Path::new(s).is_file() {
        std::fs::read_to_string(s).map_err(|e| OrganismError::Msg(format!("Erro ao ler arquivo de descritor '{s}': {e}")))?
    } else {
        s.to_string()
    };
    mycelium_veil::planes::live::NodeDescriptor::from_json(raw.trim())
        .map_err(|e| OrganismError::Msg(format!("Descritor inválido '{s}': {e}")))
}

impl Organism {
    pub fn awaken(config: OrganismConfig) -> Result<Self, OrganismError> {
        check_anonymous(&config)?;
        let anonymous = config.anonymous_socks5.is_some();
        let store = NodeStore::open(&config.home)?;
        let gland = store.load_or_create_gland()?;
        let mut ledger = store.load_ledger();
        let resources = if let Some(r) = config.contribute {
            store.save_resources(&r)?;
            r
        } else {
            store
                .load_resources()
                .unwrap_or_else(|| Resources::from_str("1cpu,1gb,10gb").unwrap())
        };
        if ledger.history().is_empty() {
            ledger.pledge(&resources);
            store.save_ledger(&ledger)?;
        }

        let mut state = store.load_state();
        for addr in &config.bootstrap {
            if !state.bootstrap.contains(addr) {
                state.bootstrap.push(addr.clone());
            }
        }
        if config.horizon_port != 0 {
            state.horizon_port = config.horizon_port;
        }

        let seed_book = SeedBook::assemble(
            &config.home,
            &config.bootstrap,
            config.seed_file.as_deref(),
            config.public_bootstrap,
            config.bootstrap_url.as_deref(),
        )
        .map_err(|e| OrganismError::Msg(e.to_string()))?;
        // Persiste seeds descobertos/passados.
        for s in seed_book.as_strings() {
            if !state.bootstrap.contains(&s) {
                state.bootstrap.push(s);
            }
        }
        let _ = seed_book.save_file(config.home.join("seeds.txt"));

        let listen: Vec<_> = config
            .listen
            .iter()
            .map(|s| {
                s.parse().map_err(|e| {
                    OrganismError::Msg(format!("listen multiaddr inválido {s:?}: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let announce_ip = config
            .announce_ip
            .or_else(|| std::env::var("MYCELIUM_ANNOUNCE_IP").ok());
        let announce_ip6 = config
            .announce_ip6
            .or_else(|| std::env::var("MYCELIUM_ANNOUNCE_IP6").ok());
        let has_global_ip6 = announce_ip6.is_some() || detect_global_ipv6();
        let assume_reachable = config.assume_reachable || env_assume_reachable();
        // Anônimo: sempre folha (sem inbound, sem relay server, sem anunciar IP).
        let membrane = if anonymous {
            Membrane::Folha
        } else {
            diagnose_membrane(
                has_global_ip6,
                announce_ip.as_deref(),
                config.sporocarp,
                config.membrane,
                assume_reachable,
            )
        };
        if matches!(membrane, Membrane::Esporocarp) && !assume_reachable && config.sporocarp {
            tracing::warn!(
                "esporocarp sem MYCELIUM_REACHABLE/--assume-reachable — IPv6 global \
                 NÃO prova inbound (ex.: firewall Vivo). TXT /esporocarp pode anunciar \
                 um nó inacessível. Confirme com: nc -vz <ip6> 4001 de fora da LAN."
            );
        }
        // Relay server só em esporocarp (ou --relay explícito legado).
        let enable_relay_server =
            config.enable_relay || matches!(membrane, Membrane::Esporocarp);
        let enable_relay_client = !enable_relay_server;

        let bootstrap_addrs = seed_book.multiaddrs_for(membrane);
        let dns_seed = std::env::var("MYCELIUM_DNS_SEEDS")
            .ok()
            .filter(|_| !anonymous)
            .or_else(|| {
                if config.public_bootstrap || config.sporocarp {
                    Some(DEFAULT_DNS_SEED_NAME.to_string())
                } else {
                    None
                }
            });
        tracing::info!(
            %membrane,
            has_global_ip6,
            assume_reachable,
            announce_ip = announce_ip.as_deref().unwrap_or("-"),
            "membrana diagnosticada"
        );
        // Folha/Floresta: Nostr transport por default (CGNAT / IPv6 sem inbound).
        // Raiz/Esporocarp: opt-in. `--no-nostr-transport` / `Some(false)` desliga.
        #[cfg(feature = "nostr-transport")]
        let enable_nostr_transport = match config.nostr_transport {
            _ if anonymous => true,
            Some(v) => v,
            None => matches!(membrane, Membrane::Folha | Membrane::Floresta),
        };
        #[cfg(not(feature = "nostr-transport"))]
        let enable_nostr_transport = false;
        if enable_nostr_transport {
            tracing::info!(%membrane, "nostr-transport activo (folha/floresta auto ou --nostr-transport)");
        }
        let mut hyphae = HyphaeNode::germinate_with(HyphaeConfig {
            seed: Some(gland.seed()),
            listen,
            bootstrap: bootstrap_addrs,
            kad_bootstrap: !seed_book.is_empty(),
            enable_mdns: config.enable_mdns,
            announce_ip,
            announce_ip6,
            enable_relay_server,
            enable_relay_client,
            membrane,
            assume_reachable,
            enable_webrtc: config.enable_webrtc,
            webrtc_port: config.webrtc_port,
            enable_nostr_transport,
            nostr_home: Some(config.home.clone()),
            // nos.lol (padrão do transporte) recusa conexões vindas do Tor.
            nostr_relay: config
                .nostr_relay
                .clone()
                .or_else(|| anonymous.then(|| ANONYMOUS_DEFAULT_NOSTR_RELAY.to_string())),
            blocked_peers: Vec::new(),
            dtn_dir: Some(config.home.join("dtn")),
            anonymous_socks5: config.anonymous_socks5,
            #[cfg(feature = "license")]
            licensed_peers: config.licensed_peers.as_ref().map(|pids| {
                pids.iter()
                    .filter_map(|s| s.parse::<libp2p::PeerId>().ok())
                    .collect::<std::collections::HashSet<_>>()
            }),
        })?;
        hyphae.restore_metrics(state.hypha_metrics.clone());

        // Auto-release persistido: peers já autorizados por licença VOID-00
        // voltam à allowlist após restart (gate ativo os mantém aceitos).
        #[cfg(feature = "license")]
        {
            let persisted: std::collections::HashSet<libp2p::PeerId> = state
                .authorized_peers
                .iter()
                .filter_map(|s| s.parse::<libp2p::PeerId>().ok())
                .collect();
            if !persisted.is_empty() {
                let mut merged = hyphae
                    .licensed_peers()
                    .cloned()
                    .unwrap_or_default();
                merged.extend(persisted);
                for p in &merged {
                    hyphae.admit_licensed_peer(*p);
                }
            }
        }


        let bank = SporeBank::open(&config.home)?;
        let mut processed = HashSet::new();
        for s in &state.processed_signals {
            if let Ok(id) = s.parse::<ContentId>() {
                processed.insert(id);
            }
        }

        let mycelium_bin = std::env::current_exe().map_err(|e| OrganismError::Msg(e.to_string()))?;
        let horizon = EventHorizon::shared();
        {
            let mut h = horizon.write().unwrap();
            h.set_home(config.home.clone());
        }
        let records = state.ions.clone();
        let mut nucleus = store
            .load_nucleus()
            .unwrap_or_else(|| Nucleus::for_node(&gland.node_id(), DEFAULT_RING_SIZE));
        let before = (nucleus.index, nucleus.ring_size);
        nucleus = nucleus.migrate_to_ring(&gland.node_id(), DEFAULT_RING_SIZE);
        if (nucleus.index, nucleus.ring_size) != before {
            tracing::info!(
                shard = nucleus.index,
                ring = nucleus.ring_size,
                "isotope nucleus migrado para anel padrão"
            );
            store.save_nucleus(&nucleus)?;
        }
        let vault = store.load_vault();
        let (nostr_found_tx, nostr_found_rx) = mpsc::unbounded_channel();
        let catalog = mycelium_store::StoreCatalog::open(&config.home)
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        let assets = crate::assets::AssetRegistry::open(&config.home)
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        let ghost = ghost_for_node(gland.seed());
        let mut org = Self {
            store,
            gland,
            ledger,
            resources,
            hyphae,
            bank,
            state,
            flywheel: Flywheel::new(),
            cloud: Cloud::new(),
            horizon,
            chambers: HashMap::new(),
            mycelium_bin,
            processed,
            horizon_handle: None,
            seed_book,
            nucleus,
            build_artifacts: HashMap::new(),
            remote_done: HashSet::new(),
            pending_decays: HashSet::new(),
            sporocarp: !anonymous && (config.sporocarp || matches!(membrane, Membrane::Esporocarp)),
            anonymous,
            membrane,
            dns_seed,
            assume_reachable,
            physarum: PhysarumNetwork::new(4, 0.1, 0.01),
            physarum_phase: MyceliumPhase::Exploratory,
            enable_nostr_transport,
            // Igual ao relay da hifa: a descoberta anuncia `qel-backchannel` com
            // ele, e no modo anônimo o padrão (nos.lol) recusa o Tor.
            nostr_relay: config
                .nostr_relay
                .or_else(|| anonymous.then(|| ANONYMOUS_DEFAULT_NOSTR_RELAY.to_string()))
                .unwrap_or_else(|| "wss://nos.lol".into()),
            nostr_found_tx,
            nostr_found_rx: Some(nostr_found_rx),
            nostr_discovering: false,
            nostr_last_round: None,
            vault,
            remote_ledger: HashMap::new(),
            known_zones: HashMap::new(),
            known_zones_ts: HashMap::new(),
            routing_hits: 0,
            #[cfg(feature = "veil")]
            veil_engine: None,
            #[cfg(feature = "veil")]
            veil_socks5_handle: None,
            #[cfg(feature = "veil")]
            veil_socks5_addr: config.veil_socks5_addr,
            #[cfg(feature = "veil")]
            veil_mode: config.veil_mode,
            #[cfg(feature = "veil")]
            veil_role: config.veil_role,
            #[cfg(feature = "veil")]
            veil_listen: config.veil_listen,
            #[cfg(feature = "veil")]
            veil_guards: config.veil_guards,
            #[cfg(feature = "veil")]
            veil_middles: config.veil_middles,
            #[cfg(feature = "veil")]
            veil_exits: config.veil_exits,
            #[cfg(feature = "veil")]
            veil_trust: config.veil_trust,
            #[cfg(feature = "veil")]
            veil_advertise: config.veil_advertise,
            #[cfg(feature = "veil")]
            veil_identity_path: config.veil_identity_path,
            #[cfg(feature = "veil")]
            veil_rotate_identity: config.veil_rotate_identity,
            #[cfg(feature = "veil")]
            veil_egress_bind: config.veil_egress_bind,
            #[cfg(feature = "veil")]
            veil_bridges: config.veil_bridges,
            #[cfg(feature = "veil")]
            veil_bridge_listen: config.veil_bridge_listen,
            #[cfg(feature = "veil")]
            veil_bridge_target: config.veil_bridge_target,
            #[cfg(feature = "veil")]
            veil_local_descriptor: None,
            #[cfg(feature = "veil")]
            veil_enabled: config.veil_enabled,
            #[cfg(feature = "veil")]
            veil_router_handles: Vec::new(),
            #[cfg(feature = "veil")]
            veil_bridge_handles: Vec::new(),
            #[cfg(feature = "veil")]
            veil_entry_pool: None,
            #[cfg(feature = "veil")]
            veil_active_entry: None,
            #[cfg(feature = "veil")]
            veil_registered_entries: Vec::new(),
            #[cfg(feature = "veil")]
            veil_failover_attempts: 0,
            #[cfg(feature = "veil")]
            veil_failure_reasons: Vec::new(),
            ion_hosts: HashMap::new(),
            catalog: std::sync::Arc::new(std::sync::Mutex::new(catalog)),
            home: config.home.clone(),
            ghost,
            assets,
            transfer_nonce: 0,
            ion_replica_peers: HashMap::new(),
            ion_replica_heartbeat: HashMap::new(),
            peer_ions: HashMap::new(),
            spore_holders: HashMap::new(),
            console_hit: false,
            last_brood: 0,
            zero_load_windows: HashMap::new(),
            last_scaling_offer: HashMap::new(),
            known_repos: HashMap::new(),
            pending_accepted_migrations: HashSet::new(),
            s1_live_inbox: VecDeque::new(),
        };

        // Restaura catálogo de peers do estado persistido.
        for (nid_str, (ions, ts)) in org.state.peer_catalog.iter() {
            if let Ok(nid) = nid_str.parse::<NodeId>() {
                org.peer_ions.insert(nid, (ions.clone(), *ts));
            }
        }
        if !org.peer_ions.is_empty() {
            tracing::info!(count = org.peer_ions.len(), "peer_ions restaurados do catálogo persistido");
        }

        for rec in records {
            if let Err(e) = org.fruit_ion(&rec.name, &rec.plot, &rec.pipeline, false) {
                tracing::warn!(ion = %rec.name, "falha ao re-frutificar: {e}");
            }
        }
        Ok(org)
    }

    pub fn node_id(&self) -> mycelium_core::NodeId {
        self.gland.node_id()
    }

    pub fn home(&self) -> &Path {
        &self.store.root
    }

    /// Adquire o catálogo partilhado com `crates/mycelium-store` sob o MESMO
    /// contrato do HTTP bridge — `catalog_locked` em
    /// `crates/mycelium-store/src/lib.rs`. É a peça que torna verdadeiro o
    /// "tratamento idêntico" prometido no campo `catalog`.
    ///
    /// Duas peças, e as duas importam:
    /// - O `Poison` é observado no RESULTADO do `lock()`, nunca no guard: um
    ///   `MutexGuard` vindo de um `Ok` não transporta informação de
    ///   envenenamento, e é por isso que não existe `is_poisoned()` a
    ///   consultar. O `unwrap_or_else(|e| e.into_inner())` que estava nos três
    ///   sites RECUPERAVA o estado de um mutex envenenado e follow-up
    ///   consumia-o sem revalidação — exatamente o caminho que o bridge HTTP
    ///   passou a recusar.
    /// - `validate()` é chamado em CADA aquisição: o índice em memória tem de
    ///   concordar com `catalog.json`. Sem isto, o daemon era fail-ENORME e o
    ///   bridge fail-closed sobre o MESMO `Arc<Mutex<StoreCatalog>>` — duas
    ///   respostas diferentes ao mesmo estado partido.
    ///
    /// `StoreLaunch` é o caso mais sensível: o registro clonado daqui decide
    /// caminho de executável e flags de emulador, ou seja, o que é executado
    /// neste host. Um registro não revalidado aí é o que o bridge nunca
    /// devolveria.
    ///
    /// Custo: uma releitura de `catalog.json` por aquisição — o mesmo custo,
    /// e a mesma escolha de não otimizar, documentados em `catalog_locked` no
    /// crate da store.
    fn catalog_locked(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, mycelium_store::StoreCatalog>,
        mycelium_store::CatalogError,
    > {
        let guard = match self.catalog.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!(
                    "[Mycelium Organism] catalog_locked: mutex do catálogo envenenado: {poisoned}"
                );
                return Err(mycelium_store::CatalogError::Poisoned(
                    "mutex do catálogo envenenado",
                ));
            }
        };
        guard.validate()?;
        Ok(guard)
    }

    pub fn persist(&mut self) -> Result<(), OrganismError> {
        self.state.hypha_metrics = self.hyphae.snapshot_metrics();
        self.state.processed_signals = self.processed.iter().map(|id| id.to_string()).collect();
        #[cfg(feature = "license")]
        if let Some(peers) = self.hyphae.licensed_peers() {
            let mut v: Vec<String> = peers.iter().map(|p| p.to_string()).collect();
            v.sort();
            v.dedup();
            self.state.authorized_peers = v;
        }
        // Persiste catálogo de peers (ion→último visto) entre restarts.
        self.state.peer_catalog = self
            .peer_ions
            .iter()
            .map(|(nid, (ions, ts))| (nid.to_string(), (ions.clone(), *ts)))
            .collect();
        self.store.save_state(&self.state)?;
        self.store.save_ledger(&self.ledger)?;
        self.store.save_nucleus(&self.nucleus)?;
        self.store.save_vault(&self.vault)?;
        let addrs: Vec<String> = self
            .hyphae
            .dialable_addrs()
            .iter()
            .map(|a| a.to_string())
            .collect();
        if !addrs.is_empty() {
            self.store.save_listen_addrs(&addrs)?;
        }
        Ok(())
    }

    fn status_report(&self) -> StatusReport {
        let m = self.hyphae.metrics();
        let ion_names: Vec<String> = self.state.ions.iter().map(|i| i.name.clone()).collect();
        let endpoints: Vec<String> = self
            .chambers
            .iter()
            .map(|(name, c)| {
                format!(
                    "{name} → {} (pid {:?}, {:?})",
                    c.upstream,
                    c.pid(),
                    c.isolation
                )
            })
            .collect();
        let horizon_url = format!("http://127.0.0.1:{}", self.state.horizon_port);
        StatusReport {
            node_id: self.gland.node_id().to_string(),
            peer_id: self.hyphae.peer_id().to_string(),
            listen_addrs: self
                .hyphae
                .dialable_addrs()
                .iter()
                .map(|a| a.to_string())
                .collect(),
            neighbors: self.hyphae.connected_neighbors(),
            plots: self.bank.len(),
            signals: self.state.field.len(),
            ions: ion_names,
            atp: self.ledger.balance(Nutrient::Atp),
            enzymes: self.ledger.balance(Nutrient::Enzymes),
            mycelia: self.ledger.balance(Nutrient::Mycelia),
            spores: self.ledger.balance(Nutrient::Spores),
            resilience: self.ledger.balance(Nutrient::Resilience),
            anastomoses: m.total_anastomoses,
            atrophies: m.total_atrophies,
            messages_in: m.messages_in,
            messages_out: m.messages_out,
            home: self.store.root.display().to_string(),
            event_horizon: horizon_url,
            ion_endpoints: endpoints,
            isotope_atoms: self.nucleus.len(),
            isotope_shard: self.nucleus.index,
            isotope_ring: self.nucleus.ring_size,
            membrane: self.membrane.as_str().to_string(),
            sporocarp: self.sporocarp,
            dns_seed: self.dns_seed.clone(),
            wan_reachable: self.assume_reachable,
            is_relay: self.assume_reachable
                && (self.sporocarp || matches!(self.membrane, Membrane::Esporocarp)),
            active_relay: self.hyphae.active_relay_peer().map(|p| p.to_string()),
            relay_health: self.hyphae.relay_mesh_health_label(),
            physarum_phase: match self.physarum_phase {
                MyceliumPhase::Exploratory => "exploratory".into(),
                MyceliumPhase::Transport => "transport".into(),
                MyceliumPhase::Dormant => "dormant".into(),
            },
            #[cfg(feature = "veil")]
            veil_socks5: if self.veil_enabled {
                self.veil_socks5_addr.map(|a| a.to_string())
            } else {
                None
            },
            #[cfg(not(feature = "veil"))]
            veil_socks5: None,
        }
    }

    /// Um passo Physarum: potenciais ← ATP + vizinhos; adapta condutâncias.
    fn physarum_tick(&mut self, dt: f64) {
        let neighbors = self.hyphae.connected_neighbors();
        let n = (neighbors + 1).clamp(2, 16);
        if self.physarum.n != n {
            self.physarum = PhysarumNetwork::new(n, 0.1, 0.01);
        }
        self.physarum.potentials[0] = self.ledger.balance(Nutrient::Atp) as f64;
        for i in 1..self.physarum.n {
            self.physarum.potentials[i] = if i <= neighbors { 1.0 + (i as f64) * 0.01 } else { 0.0 };
        }
        self.physarum.step(dt);
        let prev = self.physarum_phase;
        self.physarum_phase = self.physarum.phase();
        if self.physarum_phase != prev {
            tracing::info!(
                phase = ?self.physarum_phase,
                neighbors,
                "physarum fase"
            );
        }
    }

    pub fn sow(
        &mut self,
        message: String,
        path: String,
        content: String,
    ) -> Result<ContentId, OrganismError> {
        let plot = Plot {
            author: self.gland.node_id(),
            message,
            parents: vec![],
            leaves: vec![Leaf {
                path,
                content: content.into_bytes(),
            }],
        };
        let id = self.bank.deposit(plot.clone())?;
        if let Some(bytes) = self.bank.public_spore_print(&id) {
            let _ = self.hyphae.dht_store_local(dht_key(&id), bytes.clone());
            let _ = self.hyphae.dht_put(dht_key(&id), bytes);
            let env = Envelope::SporePrint { plot };
            let _ = self
                .hyphae
                .broadcast_lattice(env.encode().map_err(|e| OrganismError::Msg(e.to_string()))?);
        }
        self.persist()?;
        Ok(id)
    }

    /// Publica uma árvore de código (repo) como Plot multi-leaf content-addressed,
    /// anunciada na DHT e difundida por gossip — distribuição soberana, sem GitHub.
    pub fn publish_repo(
        &mut self,
        message: String,
        leaves: Vec<giggs::Leaf>,
    ) -> Result<ContentId, OrganismError> {
        self.publish_repo_ref("default", "main", message, leaves)
    }

    /// Publica um snapshot e avança uma referência assinada por CAS. O pai é
    /// sempre a ponta verificada da branch, portanto publicações concorrentes
    /// não podem sobrescrever histórico silenciosamente.
    pub fn publish_repo_ref(
        &mut self,
        repository: &str,
        branch: &str,
        message: String,
        leaves: Vec<giggs::Leaf>,
    ) -> Result<ContentId, OrganismError> {
        self.publish_repo_ref_expected(repository, branch, None, message, leaves)
    }

    /// Variante com precondição explícita, usada por integrações que precisam
    /// provar que publicaram exatamente sobre a revisão homologada.
    pub fn publish_repo_ref_expected(
        &mut self,
        repository: &str,
        branch: &str,
        expected_previous: Option<ContentId>,
        message: String,
        leaves: Vec<giggs::Leaf>,
    ) -> Result<ContentId, OrganismError> {
        let refs = RefStore::open(self.home.join("giggs/refs"))
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        let current = refs.read(repository, branch)
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        let parent = current.as_ref().map(|value| value.update.target);
        if expected_previous.is_some() && expected_previous != parent {
            return Err(OrganismError::Msg(format!(
                "referência {repository}/{branch} avançou: esperado {:?}, atual {:?}",
                expected_previous.map(|id| id.to_string()),
                parent.map(|id| id.to_string()),
            )));
        }
        let plot = Plot {
            author: self.gland.node_id(),
            message,
            parents: parent.into_iter().collect(),
            leaves,
        };
        ensure_repo_publishable(&plot)?;
        let id = self.bank.deposit(plot.clone())?;
        let update = SignedRefUpdate::sign(RefUpdate {
            repository: repository.into(),
            name: branch.into(),
            target: id,
            previous: parent,
            sequence: current.map_or(0, |value| value.update.sequence + 1),
        }, &self.ghost).map_err(|e| OrganismError::Msg(e.to_string()))?;
        refs.compare_and_swap(update).map_err(|e| OrganismError::Msg(e.to_string()))?;
        let bytes = self.bank.public_spore_print(&id).ok_or_else(|| {
            OrganismError::Msg("política pública recusou o Plot antes da distribuição".into())
        })?;
        let _ = self.hyphae.dht_store_local(dht_key(&id), bytes.clone());
        let _ = self.hyphae.dht_put(dht_key(&id), bytes);
        let env = Envelope::SporePrint { plot };
        let _ = self
            .hyphae
            .broadcast_lattice(env.encode().map_err(|e| OrganismError::Msg(e.to_string()))?);
        self.persist()?;
        Ok(id)
    }

    // ── Micelial Value Layer ────────────────────────────────
    /// GhostID pubkey x-only do nó (carteira).
    pub fn wallet_pubkey(&self) -> [u8; 32] {
        self.ghost.nostr_pubkey()
    }

    pub fn wallet_pubkey_hex(&self) -> String {
        self.ghost.nostr_pubkey_hex()
    }

/// Cria, assina, aplica e propaga uma transferência de nutrientes.

    pub fn transfer(
        &mut self,
        to_hex: &str,
        amount: u64,
        nutrient: mycelium_core::Nutrient,
        kind: mycelium_nutrients::TxKind,
        memo: String,
        asset: Option<String>,
    ) -> Result<mycelium_nutrients::SignedTransfer, String> {
        let to = hex::decode(to_hex)
            .map_err(|e| format!("pubkey destino inválida: {e}"))?
            .try_into()
            .map_err(|_| "pubkey destino precisa de 32 bytes".to_string())?;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let payload = mycelium_nutrients::TransferPayload {
            kind,
            from: self.wallet_pubkey(),
            to,
            nutrient,
            amount,
            memo,
            asset,
            nonce: self.transfer_nonce,
            ts,
        };
        let bytes = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        let sig = self.ghost.sign(&bytes);
        self.transfer_nonce += 1;

        let tx = mycelium_nutrients::SignedTransfer {
            payload,
            sig: hex::encode(sig),
        };

        // Verifica a própria assinatura e aplica no ledger local.
        self.apply_incoming_transfer(tx.clone(), true).map_err(|e| e.to_string())?;

        // Propaga pela malha.
        let env = Envelope::ValueTransfer { tx: tx.clone() };
        let _ = self
            .hyphae
            .broadcast_lattice(env.encode().map_err(|e| e.to_string())?);
        self.persist().map_err(|e| e.to_string())?;
        Ok(tx)
    }

    /// Verifica assinatura Schnorr (GhostID) e aplica no ledger local.
    /// `propagated=true` não re-propaga (para a origem).
    pub fn apply_incoming_transfer(
        &mut self,
        tx: mycelium_nutrients::SignedTransfer,
        propagated: bool,
    ) -> Result<(), String> {
        let p = &tx.payload;
        let sig = hex::decode(&tx.sig)
            .map_err(|e| format!("assinatura inválida: {e}"))?;
        let sig: [u8; 64] = sig
            .try_into()
            .map_err(|_| "assinatura precisa de 64 bytes".to_string())?;
        let hash = mycelium_core::ContentId::of(&tx.canonical_bytes()).0;
        mycelium_ghostid::GhostId::verify_nostr_event(&p.from, &hash, &sig)
            .map_err(|_| "assinatura Schnorr inválida".to_string())?;

        let my = self.wallet_pubkey();
        self.ledger.apply_transfer(&tx, &my).map_err(|e| e.to_string())?;

        if !propagated {
            let env = Envelope::ValueTransfer { tx };
            let _ = self.hyphae.broadcast_lattice(
                env.encode().map_err(|e| e.to_string())?,
            );
        }
        Ok(())
    }

    /// Recompensa por proof-of-relay / compute (Fase 2), chamada periodicamente.
    pub fn reward_hardware(&mut self, neighbors: usize) {
        if neighbors > 0 {
            self.ledger.relay_reward((neighbors as u64) * 5);
        }
        self.ledger.heartbeat(1);
    }

    pub fn emit_signal(
        &mut self,
        plot: ContentId,
        quorum: usize,
        ion: String,
        name: String,
    ) -> Result<ContentId, OrganismError> {
        match self.bank.recall(&plot) {
            None => return Err(OrganismError::Msg(format!(
                "plot {plot} ausente do Spore Bank local"
            ))),
            Some(p) if !p.is_public() => return Err(OrganismError::Msg(
                "signal de Plot restrito exige transporte criptografado ainda não implementado".into()
            )),
            Some(_) => {}
        }
        let id = self.state.field.emit(
            self.gland.node_id(),
            Proposal::Pipeline {
                name,
                plot,
                target_ion: ion,
            },
            quorum,
        )?;
        let _ = self.state.field.resonate(&id, self.gland.node_id());
        let signal = self
            .state
            .field
            .get(&id)
            .cloned()
            .ok_or_else(|| OrganismError::Msg("signal sumiu".into()))?;
        let env = Envelope::SignalBroadcast { signal };
        let _ = self
            .hyphae
            .broadcast_lattice(env.encode().map_err(|e| OrganismError::Msg(e.to_string()))?);
        self.try_fire_pipelines()?;
        self.persist()?;
        Ok(id)
    }

    pub fn resonate(&mut self, signal_id: ContentId) -> Result<SignalState, OrganismError> {
        let state = self
            .state
            .field
            .resonate(&signal_id, self.gland.node_id())?;
        let env = Envelope::Resonance {
            signal_id,
            resonator: self.gland.node_id(),
        };
        let _ = self
            .hyphae
            .broadcast_lattice(env.encode().map_err(|e| OrganismError::Msg(e.to_string()))?);
        self.try_fire_pipelines()?;
        self.persist()?;
        Ok(state)
    }

    fn try_fire_pipelines(&mut self) -> Result<(), OrganismError> {
        let fired: Vec<_> = self
            .state
            .field
            .fired()
            .filter(|s| !self.processed.contains(&s.id))
            .cloned()
            .collect();

        for signal in fired {
            if let Proposal::Pipeline {
                plot,
                target_ion,
                name,
            } = &signal.proposal
            {
                let i_am_origin = signal.origin == self.gland.node_id();
                // Só o emissor do Signal faz Build→Test→Deploy local.
                // Peers remotes ganham ATP via VectorOffer (Build/Test), sem frutar Chamber.
                if !i_am_origin {
                    tracing::info!(
                        signal = %signal.id.short(),
                        origin = %signal.origin.short(),
                        "pipeline fired — peer remoto ignora Deploy (origin_only)"
                    );
                    self.processed.insert(signal.id);
                    continue;
                }

                tracing::info!(
                    signal = %signal.id.short(),
                    ion = %target_ion,
                    "pipeline fired — spinning inertia (origin)"
                );
                let work = self.prepare_workbench(plot)?;
                self.flywheel.inject(Vector {
                    plot: *plot,
                    thrust: Thrust::Build,
                    emitter: signal.origin,
                });
                self.flywheel.inject(Vector {
                    plot: *plot,
                    thrust: Thrust::Test,
                    emitter: signal.origin,
                });
                self.flywheel.inject(Vector {
                    plot: *plot,
                    thrust: Thrust::Deploy {
                        target_ion: target_ion.clone(),
                    },
                    emitter: signal.origin,
                });

                while let Ok((vector, momentum)) =
                    self.flywheel.spin(self.gland.node_id(), &work)
                {
                    self.ledger
                        .feed(Nutrient::Atp, momentum.atp_earned, &momentum.log);
                    tracing::info!("{}", momentum.log);
                    if !momentum.success {
                        tracing::warn!(thrust = ?vector.thrust, "inertia falhou — abortando pipeline");
                        break;
                    }
                    if matches!(vector.thrust, Thrust::Build) {
                        let archive = match inertia::collect_artifact(&work) {
                            Some(files) => {
                                let mut a = LayerArchive::new();
                                for (path, bytes) in files {
                                    a.insert(path, bytes);
                                }
                                a
                            }
                            None => {
                                let fallback = self
                                    .bank
                                    .spore_print(plot)
                                    .unwrap_or_else(|_| b"{}".to_vec());
                                LayerArchive::single("app.payload", fallback)
                            }
                        };
                        self.build_artifacts.insert(*plot, archive);
                    }
                    if let Thrust::Deploy { ref target_ion } = vector.thrust {
                        self.birth_ion(target_ion, &vector.plot.to_string(), name)?;
                    }
                    self.broadcast_momentum(&vector, &momentum, self.gland.node_id(), &work)?;
                    // Oferece Build/Test à rede (Deploy fica no emissor).
                    if !matches!(vector.thrust, Thrust::Deploy { .. }) {
                        let env = Envelope::VectorOffer {
                            vector: vector.clone(),
                        };
                        let _ = self.hyphae.broadcast_lattice(
                            env.encode().map_err(|e| OrganismError::Msg(e.to_string()))?,
                        );
                    }
                }
                self.processed.insert(signal.id);
            } else {
                self.processed.insert(signal.id);
            }
        }
        Ok(())
    }

    fn prepare_workbench(&self, plot: &ContentId) -> Result<PathBuf, OrganismError> {
        let plot_data = self
            .bank
            .recall(plot)
            .ok_or_else(|| OrganismError::Msg(format!("plot {plot} ausente para build")))?;
        let work = self.store.builds_dir().join(plot.short());
        let leaves: Vec<(String, Vec<u8>)> = plot_data
            .leaves
            .iter()
            .map(|l| (l.path.clone(), l.content.clone()))
            .collect();
        inertia::materialize_leaves(&work, &leaves)
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        std::fs::write(work.join("MESSAGE"), plot_data.message.as_bytes())
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        Ok(work)
    }

    fn run_inertia_validation(
        &mut self,
        plot: ContentId,
    ) -> Result<(ContentId, Option<ContentId>, Option<ContentId>, bool), OrganismError> {
        let work = self.prepare_workbench(&plot)?;
        let executor = self.gland.node_id();
        let mut flywheel = Flywheel::new();
        flywheel.inject(Vector {
            plot,
            thrust: Thrust::Build,
            emitter: executor,
        });

        let (build_vector, build_momentum) = flywheel
            .spin(executor, &work)
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        let artifact = if build_momentum.success {
            let archive = match inertia::collect_artifact(&work) {
                Some(files) => {
                    let mut archive = LayerArchive::new();
                    for (path, bytes) in files {
                        archive.insert(path, bytes);
                    }
                    archive
                }
                None => {
                    let fallback = self
                        .bank
                        .spore_print(&plot)
                        .unwrap_or_else(|_| b"{}".to_vec());
                    LayerArchive::single("app.payload", fallback)
                }
            };
            let store = LayerStore::open(self.store.layers_dir())
                .map_err(|e| OrganismError::Msg(e.to_string()))?;
            let artifact = store
                .put_archive(&archive)
                .map_err(|e| OrganismError::Msg(e.to_string()))?;
            self.build_artifacts.insert(plot, archive);
            Some(artifact)
        } else {
            None
        };
        let build_attestation =
            self.broadcast_momentum(&build_vector, &build_momentum, executor, &work)?;
        if !build_momentum.success {
            return Ok((build_attestation, None, None, false));
        }

        flywheel.inject(Vector {
            plot,
            thrust: Thrust::Test,
            emitter: executor,
        });
        let (test_vector, test_momentum) = flywheel
            .spin(executor, &work)
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        let test_attestation =
            self.broadcast_momentum(&test_vector, &test_momentum, executor, &work)?;
        Ok((
            build_attestation,
            Some(test_attestation),
            artifact,
            test_momentum.success,
        ))
    }

    fn vector_fingerprint(vector: &Vector) -> String {
        format!(
            "{}:{:?}:{}",
            vector.plot,
            vector.thrust,
            vector.emitter.short()
        )
    }

    fn broadcast_momentum(
        &mut self,
        vector: &Vector,
        momentum: &Momentum,
        executor: NodeId,
        work_dir: &Path,
    ) -> Result<ContentId, OrganismError> {
        let artifacts = self
            .build_artifacts
            .get(&vector.plot)
            .and_then(|archive| archive.encode().ok())
            .map(|bytes| vec![ContentId::of(&bytes)])
            .unwrap_or_default();
        let payload = AttestationPayload {
            input: vector.plot,
            thrust: vector.thrust.clone(),
            commands: inertia::command_manifest(&vector.thrust, work_dir),
            environment: BTreeMap::from([
                ("arch".into(), std::env::consts::ARCH.into()),
                (
                    "isolation".into(),
                    if inertia::is_sandbox_available() {
                        "bubblewrap"
                    } else {
                        "local-policy"
                    }
                    .into(),
                ),
                ("os".into(), std::env::consts::OS.into()),
            ]),
            executor,
            success: momentum.success,
            atp_earned: momentum.atp_earned,
            log_digest: ContentId::of(momentum.log.as_bytes()),
            artifacts,
        };
        let attestation = SignedAttestation::sign(payload, &self.ghost)
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        let attestation_id = AttestationStore::open(self.home.join("attestations"))
            .and_then(|store| store.persist(&attestation))
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        let env = Envelope::MomentumReport {
            vector: vector.clone(),
            momentum: momentum.clone(),
            executor,
            attestation: Some(attestation),
        };
        let _ = self
            .hyphae
            .broadcast_lattice(env.encode().map_err(|e| OrganismError::Msg(e.to_string()))?);
        Ok(attestation_id)
    }

    fn validate_momentum_attestation(
        &self,
        vector: &Vector,
        momentum: &Momentum,
        executor: NodeId,
        attestation: Option<&SignedAttestation>,
    ) -> Result<ContentId, OrganismError> {
        let attestation = attestation
            .ok_or_else(|| OrganismError::Msg("atestado de Inertia ausente".into()))?;
        attestation
            .verify()
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        let payload = &attestation.payload;
        if payload.input != vector.plot
            || payload.thrust != vector.thrust
            || payload.executor != executor
            || payload.success != momentum.success
            || payload.atp_earned != momentum.atp_earned
            || payload.log_digest != ContentId::of(momentum.log.as_bytes())
        {
            return Err(OrganismError::Msg(
                "atestado nao corresponde ao Vector/Momentum recebido".into(),
            ));
        }
        if payload.commands.is_empty()
            || !payload.environment.contains_key("os")
            || !payload.environment.contains_key("arch")
        {
            return Err(OrganismError::Msg(
                "atestado nao descreve comandos e ambiente minimos".into(),
            ));
        }
        AttestationStore::open(self.home.join("attestations"))
            .and_then(|store| store.persist(attestation))
            .map_err(|e| OrganismError::Msg(e.to_string()))
    }

    /// Anuncia layer no DHT + gossip.
    fn announce_layer(&mut self, id: ContentId, bytes: &[u8]) -> Result<(), OrganismError> {
        let key = layer_dht_key(&id);
        let _ = self.hyphae.dht_store_local(key.clone(), bytes.to_vec());
        let _ = self.hyphae.dht_put(key, bytes.to_vec());
        let env = Envelope::LayerOffer { id };
        let _ = self
            .hyphae
            .broadcast_lattice(env.encode().map_err(|e| OrganismError::Msg(e.to_string()))?);
        Ok(())
    }

    /// Se a layer falta, pede à rede (gossip + DHT + overlay XOR).
    fn request_layer(&mut self, id: &ContentId) {
        tracing::info!(layer = %id.short(), "pedindo layer aos vizinhos");
        // Overlay de zonas: custodianos mais próximos por XOR (Kademlia)
        // recebem LayerNeed direcionado; broadcast segue como rede de pesca.
        let need = Envelope::LayerNeed { id: *id, hop: 0 };
        for custodian in self.xor_closest(&id.0) {
            self.send_direct(custodian, need.clone());
        }
        // Roteamento DHT em runtime: pergunta ao Kademlia quem são os peers
        // XOR-mais-próximos da chave da layer e os procura direto —
        // caminho além dos anunciantes locais de zona.
        self.hyphae.dht_closest_peers(id.0.to_vec());
        if let Ok(bytes) = need.encode() {
            let _ = self.hyphae.broadcast_lattice(bytes);
        }
        self.hyphae.dht_get(layer_dht_key(id));
    }

    /// Distância XOR entre duas chaves de 32 bytes (métrica Kademlia).
    fn xor_key_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = a[i] ^ b[i];
        }
        out
    }

    /// Custodianos de zonas ordenados por proximidade XOR à chave
    /// (ContentId/NodeId) — os primeiros recebem tráfego direcionado.
    fn xor_closest(&self, key: &[u8; 32]) -> Vec<NodeId> {
        let mut seen: Vec<NodeId> = self
            .known_zones
            .values()
            .flatten()
            .copied()
            .collect();
        seen.retain(|n| n != &self.gland.node_id());
        seen.sort_by_key(|n| Self::xor_key_distance(&n.0, key));
        seen.dedup();
        seen.truncate(2);
        seen
    }

    /// Podares custodiantes de zona que não re-anunciam há muito (TTL),
    /// espelhando o prune de `peer_ions` — a tabela de rotas XOR não pode
    /// acumular nós mortos.
    fn prune_zones(&mut self, now: u64) {
        prune_zone_tables(&mut self.known_zones, &mut self.known_zones_ts, now);
    }

    /// Mantém o overlay de zonas quente: periodicamente pergunta ao Kademlia
    /// quem são os peers XOR-mais-próximos das layers/esporos locais, para
    /// que a rota de custódia reflita a topologia viva (não só os anúncios
    /// batidos uma vez). Resultado chega via [`HyphaEvent::ClosestPeers`].
    fn dht_overlay_tick(&mut self) {
        // Esporos/layers locais: consulta o DHT pelos peers XOR-mais-próximos,
        // mantendo a rota de custódia viva entre os nós vivos.
        let mut keys: Vec<[u8; 32]> = self.bank.ids().iter()
            .filter(|id| self.bank.public_spore_print(id).is_some())
            .map(|id| id.0).collect();
        keys.truncate(4); // limita queries por tick (rede pequena)
        for k in &keys {
            self.hyphae.dht_closest_peers(k.to_vec());
        }
        if !keys.is_empty() {
            tracing::debug!(queries = keys.len(), "overlay DHT: rota conservada para esporos locais");
        }
    }

    /// Anti-entropy proativa: republica esporos públicos locais na DHT e no
    /// lattice, para que as cópias sobrevivam ao churn sem depender do
    /// publicador original. Fecha a lacuna que `recall` deixa aberta: um nó que
    /// nunca aprendeu o ContentId (gossip perdido por estar offline) não pode
    /// consultá-lo — mas recebe o re-anúncio periódico de quem detém a cópia.
    fn anti_entropy_tick(&mut self) {
        // Bounded: re-publica no máximo N por tick (rede pequena / evitar flood).
        const MAX_PER_TICK: usize = 8;
        // Poda detentores sem manifesto recente (evita crescer sem limite).
        let now = unix_now();
        self.spore_holders.retain(|_, holders| {
            holders.retain(|_, ts| now.saturating_sub(*ts) < SPORE_HOLDER_TTL_SECS);
            !holders.is_empty()
        });
        let ids: Vec<ContentId> = self.bank.ids().iter().copied().take(MAX_PER_TICK).collect();
        // Push de SporePrint (bytes) pode ser desligado para operar só por
        // manifesto (anúncio de IDs + pull DHT sob demanda); útil em rede grande.
        let push_bytes = std::env::var("MYCELIUM_ANTI_ENTROPY_PUSH")
            .map(|v| v != "0")
            .unwrap_or(true);
        let mut republished = 0usize;
        let mut public_ids: Vec<ContentId> = Vec::new();
        for id in ids {
            let Some(bytes) = self.bank.public_spore_print(&id) else {
                continue;
            };
            let _ = self.hyphae.dht_put(dht_key(&id), bytes.clone());
            if push_bytes {
                if let Ok(plot) = serde_json::from_slice::<Plot>(&bytes) {
                    if let Ok(encoded) = (Envelope::SporePrint { plot }).encode() {
                        let _ = self.hyphae.broadcast_lattice(encoded);
                    }
                }
            }
            public_ids.push(id);
            republished += 1;
        }
        if !public_ids.is_empty() {
            // Manifesto: anuncia os IDs detidos para os pares (a) registarem
            // detentores vivos e (b) puxarem o que lhes falta.
            let holder = self.hyphae.peer_id().to_string();
            if let Ok(encoded) = (Envelope::SporeManifest { holder, ids: public_ids }).encode() {
                let _ = self.hyphae.broadcast_lattice(encoded);
            }
            tracing::debug!(republished, "anti-entropy: esporos públicos re-anunciados");
        }
    }

    /// Detecção de detentor offline: remove o peer caído do índice e, para cada
    /// plot público que ficou abaixo de [`TARGET_SPORE_HOLDERS`], re-anuncia
    /// (repin) na DHT + lattice, para a malha recompor as cópias **sem** depender
    /// do publicador original (E1.3).
    ///
    /// ponytail: repin não é direcionado ao plot do peer caído — re-anuncia todo
    /// público local abaixo do alvo. Endereçar por detentor quando o custo do
    /// anúncio doer (rede grande).
    fn note_peer_offline_and_repin(&mut self, holder: &str) {
        let now = unix_now();
        let mut holders_map = std::mem::take(&mut self.spore_holders);
        let mut repin: Vec<ContentId> = Vec::new();
        holders_map.retain(|id, holders| {
            holders.remove(holder);
            holders.retain(|_, ts| now.saturating_sub(*ts) < SPORE_HOLDER_TTL_SECS);
            if holders.len() < TARGET_SPORE_HOLDERS
                && self.bank.public_spore_print(id).is_some()
            {
                repin.push(*id);
            }
            !holders.is_empty()
        });
        self.spore_holders = holders_map;
        for id in &repin {
            if let Some(bytes) = self.bank.public_spore_print(id) {
                let _ = self.hyphae.dht_put(dht_key(id), bytes.clone());
                if let Ok(plot) = serde_json::from_slice::<Plot>(&bytes) {
                    if let Ok(enc) = (Envelope::SporePrint { plot }).encode() {
                        let _ = self.hyphae.broadcast_lattice(enc);
                    }
                }
            }
        }
        if !repin.is_empty() {
            tracing::info!(
                count = repin.len(),
                %holder,
                "anti-entropy: detentor offline — repin disparado"
            );
        }
    }

    /// Envia um envelope direcionado via overlay de zonas (`Direct`).
    ///
    /// **Rizomorfo mesh**: gossipsub/lattice é camada 1. Se nenhum peer
    /// está conectado ao tópico (`broadcast_lattice` retorna false),
    /// dispara fallback via CandidateRelay (Nostr transport) que descobre
    /// e diala peers através de relays, depois republica no lattice.
    fn send_direct(&mut self, to: NodeId, inner: Envelope) {
        let env = Envelope::Direct {
            to,
            inner: Box::new(inner),
        };
        if let Ok(bytes) = env.encode() {
            let bundle_id = mycelium_core::ContentId::of(&bytes).to_string();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Produz PeerBinding autenticado do nó emissor para o destinatário
            let my_node = self.gland.node_id();
            let my_peer = self.hyphae.peer_id().to_string();
            let expires_at = now + 86400; // 24h
            let sign_msg = mycelium_core::PeerBinding::sign_payload(&my_node, &my_peer, expires_at);
            let sig = self.gland.sign_bytes(&sign_msg);
            let my_binding = mycelium_core::PeerBinding {
                node_id: my_node,
                peer_id: my_peer,
                public_key: self.gland.verifying_key().to_bytes().to_vec(),
                expires_at,
                signature: sig,
            };

            // Tenta resolver o PeerId de transporte a partir do NodeId
            let dst_peer_str = self.hyphae.resolve_peer(&to)
                .map(|p| p.to_string())
                .unwrap_or_else(|| to.to_string());

            let bundle = mycelium_hyphae::DtnBundle {
                bundle_id,
                src_peer: self.hyphae.peer_id().to_string(),
                dst_peer: dst_peer_str,
                dst_node: Some(to),
                binding: Some(my_binding),
                created_at: now,
                ttl_secs: 3600,
                hops: 0,
                max_hops: 16,
                payload: bytes.clone(),
            };

            // Roteamento unicast direcionado com store-and-forward tolerante a intermitência
            match self.hyphae.forward_or_store_dtn(bundle) {
                Ok(true) => {
                    tracing::debug!(target = %to, "Direct entregue via DTN unicast");
                    return;
                }
                Ok(false) => {
                    tracing::debug!(target = %to, "Direct armazenado no DTN store (aguardando salto/encontro)");
                }
                Err(e) => {
                    tracing::warn!(target = %to, error = %e, "falha ao encaminhar DTN bundle");
                }
            }

            // Fallback secundário via Nostr: procurar peers sem bloquear o laço;
            // o bundle segue no DTN store e é entregue na anastomose. Uma
            // rajada de mensagens não pode virar uma rajada de rondas.
            if self
                .nostr_last_round
                .is_none_or(|t| t.elapsed() >= Duration::from_secs(10))
            {
                self.start_nostr_discovery();
            }
        }
    }

    /// Lança uma ronda de descoberta CandidateRelay (no máximo uma de cada vez).
    fn start_nostr_discovery(&mut self) {
        #[cfg(feature = "nostr-transport")]
        if self.enable_nostr_transport && !self.nostr_discovering {
            self.nostr_discovering = true;
            self.nostr_last_round = Some(Instant::now());
            self.hyphae
                .spawn_nostr_discovery(&self.nostr_relay, self.nostr_found_tx.clone());
        }
        #[cfg(not(feature = "nostr-transport"))]
        let _ = (
            &self.nostr_found_tx,
            self.nostr_discovering,
            self.nostr_last_round,
            self.enable_nostr_transport,
        );
    }

    fn on_nostr_discovered(&mut self, found: NostrFound) {
        self.nostr_discovering = false;
        #[cfg(feature = "nostr-transport")]
        match found {
            Ok(found) => {
                let n = self.hyphae.dial_nostr_discovered(found);
                if n > 0 {
                    tracing::info!(dialed = n, "nostr-transport: peers dialados");
                }
            }
            Err(e) => tracing::debug!(error = %e, "nostr-transport discover"),
        }
        #[cfg(not(feature = "nostr-transport"))]
        let _ = found;
    }

    fn signed_peer_binding(&self) -> mycelium_core::PeerBinding {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let node_id = self.gland.node_id();
        let peer_id = self.hyphae.peer_id().to_string();
        let expires_at = now + 3600;
        let payload = mycelium_core::PeerBinding::sign_payload(&node_id, &peer_id, expires_at);
        mycelium_core::PeerBinding {
            node_id,
            peer_id,
            public_key: self.gland.verifying_key().to_bytes().to_vec(),
            expires_at,
            signature: self.gland.sign_bytes(&payload),
        }
    }

    fn announce_peer_binding(&mut self) {
        let binding = self.signed_peer_binding();
        match self.hyphae.broadcast_peer_binding(binding) {
            Ok(true) => tracing::debug!("peer binding anunciado"),
            Ok(false) => tracing::debug!("peer binding aguardando subscriber"),
            Err(e) => tracing::debug!(error=%e, "peer binding publish"),
        }
    }

    /// Efeito manada: visita à console ErgotOS semeia localmente um
    /// `ergot-seed` (ion consciência do desktop) que anuncia a si por toda
    /// a rede via `IonAnnounce`. Outros nós recebem o anúncio e brotam o
    /// mesmo seed → a console se multiplica sem toque humano.
    fn try_brood_seed_ion(&mut self) {
        let name = "ergot-seed";
        if self.chambers.contains_key(name) {
            return;
        }
        if self.ledger.balance(Nutrient::Atp) == 0 {
            tracing::debug!("sem ATP para brotar ergot-seed");
            return;
        }
        let plot = giggs::Plot {
            author: self.gland.node_id(),
            message: "\u{1F304} ergot-seed — a floresta cresce onde é semeada"
                .to_string(),
            parents: vec![],
            leaves: vec![],
        };
        let id = match self.bank.deposit(plot) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(error = %e, "seed deposit falhou");
                return;
            }
        };
        match self.fruit_ion(name, &id.to_string(), "", true) {
            Ok(()) => tracing::info!("ergot-seed brotado — console ErgotOS autônoma"),
            Err(e) => tracing::warn!(error = %e, "seed fruit falhou"),
        }
    }

    fn serve_layer_if_present(&mut self, id: &ContentId) -> Result<bool, OrganismError> {
        let store = LayerStore::open(self.store.layers_dir())
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        if let Some(bytes) = store.get(id) {
            self.announce_layer(*id, &bytes)?;
            tracing::info!(layer = %id.short(), "layer servida ao pedido");
            return Ok(true);
        }
        Ok(false)
    }

    fn advertised_chamber_upstream(&self, port: u16) -> String {
        if let Ok(host) = std::env::var("MYCELIUM_PUBLIC_HOST") {
            let host = host.trim();
            if !host.is_empty() {
                return format!("http://{host}:{port}");
            }
        }
        if let Ok(host) = std::env::var("MYCELIUM_PUBLIC_ADDR") {
            let host = host.trim();
            if !host.is_empty() {
                return format!("http://{host}:{port}");
            }
        }
        format!("http://127.0.0.1:{port}")
    }

    /// Executa Vector remoto (Build/Test) se houver CPU ociosa e Plot local.
    fn accept_remote_vector(&mut self, vector: Vector) -> Result<(), OrganismError> {
        if self.resources.cpu_cores == 0 || self.flywheel.pending() > 2 {
            return Ok(());
        }
        if matches!(vector.thrust, Thrust::Deploy { .. }) {
            return Ok(());
        }
        if vector.emitter == self.gland.node_id() {
            return Ok(());
        }
        if !inertia::is_sandbox_available() {
            tracing::warn!(
                emitter = %vector.emitter.short(),
                plot = %vector.plot.short(),
                "vector remoto rejeitado: sandbox Bubblewrap indisponível no host (política fail-closed)"
            );
            return Ok(());
        }
        let fp = Self::vector_fingerprint(&vector);
        if self.remote_done.contains(&fp) {
            return Ok(());
        }
        if self.bank.recall(&vector.plot).is_none() {
            self.hyphae.dht_get(dht_key(&vector.plot));
            tracing::debug!(plot = %vector.plot.short(), "vector remoto: plot ausente, DHT get");
            return Ok(());
        }
        let work = self.prepare_workbench(&vector.plot)?;
        self.flywheel.inject(vector);
        if let Ok((v, momentum)) = self.flywheel.spin(self.gland.node_id(), &work) {
            self.remote_done.insert(Self::vector_fingerprint(&v));
            self.ledger
                .feed(Nutrient::Atp, momentum.atp_earned, &momentum.log);
            tracing::info!(
                plot = %v.plot.short(),
                "vector remoto executado: {}",
                momentum.log
            );
            self.broadcast_momentum(&v, &momentum, self.gland.node_id(), &work)?;
        }
        Ok(())
    }

    fn birth_ion(
        &mut self,
        name: &str,
        plot: &str,
        pipeline: &str,
    ) -> Result<(), OrganismError> {
        if self.state.ions.iter().any(|i| i.name == name) {
            // Já registrado — garante que a chamber está viva.
            if !self.chambers.contains_key(name) {
                self.fruit_ion(name, plot, pipeline, false)?;
            }
            return Ok(());
        }
        self.fruit_ion(name, plot, pipeline, true)?;
        Ok(())
    }

    /// Materializa Chamber (processo) + Orbit no Event Horizon.
    fn fruit_ion(
        &mut self,
        name: &str,
        plot: &str,
        pipeline: &str,
        persist_record: bool,
    ) -> Result<(), OrganismError> {
        let plot_id: ContentId = plot.parse().map_err(OrganismError::Msg)?;
        // A frutificação anuncia layers em claro na DHT. Não permitir que
        // um Plot privado/reservado vaze por esta rota indireta.
        if let Some(plot) = self.bank.recall(&plot_id) {
            if !plot.is_public() {
                return Err(OrganismError::Msg(
                    "deploy de Plot restrito exige layers criptografadas; operação recusada".into(),
                ));
            }
        }
        let message = self
            .bank
            .recall(&plot_id)
            .map(|p| p.message.clone())
            .unwrap_or_else(|| format!("ion:{name}"));

        let layer_store = LayerStore::open(self.store.layers_dir())
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        let mut base = LayerArchive::single("MESSAGE", message.as_bytes());
        base.insert("pipeline.txt", pipeline.as_bytes().to_vec());
        let base_bytes = base
            .encode()
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        let base_id = layer_store
            .put(&base_bytes)
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        self.announce_layer(base_id, &base_bytes)?;

        let app = self.build_artifacts.remove(&plot_id).unwrap_or_else(|| {
            let mut archive = LayerArchive::new();
            let mut has_leaves = false;
            if let Some(plot) = self.bank.recall(&plot_id) {
                for leaf in &plot.leaves {
                    archive.insert(&leaf.path, leaf.content.clone());
                    has_leaves = true;
                }
            }
            if !has_leaves {
                let payload = self
                    .bank
                    .spore_print(&plot_id)
                    .unwrap_or_else(|_| message.as_bytes().to_vec());
                archive.insert("app.payload", payload);
            }
            archive
        });
        let app_bytes = app
            .encode()
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        let app_id = layer_store
            .put(&app_bytes)
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        self.announce_layer(app_id, &app_bytes)?;

        let void = Void {
            name: name.to_string(),
            layers: vec![base_id, app_id],
            entrypoint: "chamber-serve".into(),
        };
        // Se alguma layer sumir do disco, pede à rede antes de falhar.
        for lid in &void.layers {
            if !layer_store.has(lid) {
                self.request_layer(lid);
            }
        }
        let chamber = Chamber::suck_store(void.clone(), &layer_store, self.resources)?;
        let ion = Ion::birth(name, self.gland.node_id(), chamber);
        match self.cloud.inject(ion) {
            Ok(()) | Err(plasma::PlasmaError::AlreadyOrbiting(_)) => {}
            Err(e) => return Err(OrganismError::Msg(e.to_string())),
        }

        let mem = if self.resources.ram_mib > 0 {
            Some(self.resources.ram_mib)
        } else {
            None
        };
        let cpu = if self.resources.cpu_cores > 0 {
            Some(self.resources.cpu_cores)
        } else {
            None
        };
        let proc = ChamberProcess::fruit_void(
            &self.mycelium_bin,
            &self.store.chambers_dir(),
            &void,
            &layer_store,
            &message,
            FruitOptions {
                isolation: Isolation::Auto,
                memory_mib: mem,
                cpu_cores: cpu,
                ..FruitOptions::default()
            },
        )?;

        let host = format!("sporocarp.mycelium/{}", self.gland.node_id().short());
        {
            let mut table = self.horizon.write().unwrap();
            table.expose(
                &host,
                Orbit {
                    ion: name.to_string(),
                    node: self.gland.node_id(),
                    mass: self.resources.cpu_cores as u64 * 10 + 1,
                    resistance: 0,
                    upstream: proc.upstream.clone(),
                },
            );
        }

        tracing::info!(
            ion = name,
            upstream = %proc.upstream,
            layers = ?void.layers.iter().map(|l| l.short()).collect::<Vec<_>>(),
            horizon = %format!("http://127.0.0.1:{}/{name}/", self.state.horizon_port),
            "chamber viva — ion no event horizon"
        );

        self.chambers.insert(name.to_string(), proc);

        if persist_record {
            self.state.ions.push(IonRecord {
                name: name.to_string(),
                plot: plot_id.to_string(),
                pipeline: pipeline.to_string(),
            });
            if self.ledger.balance(Nutrient::Atp) > 0 {
                let _ = self
                    .ledger
                    .metabolize(Nutrient::Atp, 1, None, format!("deploy:{name}"));
            }
            self.persist()?;
        }
        Ok(())
    }

    pub fn isotope_put(
        &mut self,
        key: String,
        value: String,
        clock: Option<u64>,
    ) -> Result<(u64, bool), OrganismError> {
        let clock = clock.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(1)
        });
        let atom = Atom {
            value: value.into_bytes(),
            clock,
        };
        let owned = self.nucleus.owns(&key);
        if owned {
            self.nucleus
                .write(&key, atom.value.clone(), clock)
                .map_err(|e| OrganismError::Msg(e.to_string()))?;
        } else {
            // Cache local; o dono do shard persiste via AtomSync.
            self.nucleus.absorb(&key, atom.clone());
            tracing::debug!(
                %key,
                shard = Nucleus::shard_of(&key, self.nucleus.ring_size),
                local = self.nucleus.index,
                "isotope put em shard remoto — AtomSync"
            );
        }
        let env = Envelope::AtomSync {
            key: key.clone(),
            atom,
        };
        let _ = self
            .hyphae
            .broadcast_lattice(env.encode().map_err(|e| OrganismError::Msg(e.to_string()))?);
        self.persist()?;
        Ok((clock, owned))
    }

    /// Hit local, ou dispara Decay e devolve None enquanto aguarda reply.
    pub fn isotope_get(&mut self, key: &str) -> Result<Option<Atom>, OrganismError> {
        if let Some(atom) = self.nucleus.decay(key) {
            self.pending_decays.remove(key);
            return Ok(Some(atom.clone()));
        }
        self.begin_decay(key)?;
        Ok(None)
    }

    fn begin_decay(&mut self, key: &str) -> Result<(), OrganismError> {
        if self.pending_decays.contains(key) {
            return Ok(());
        }
        self.pending_decays.insert(key.to_string());
        let env = Envelope::DecayQuery {
            key: key.to_string(),
            asker: self.gland.node_id(),
        };
        let _ = self
            .hyphae
            .broadcast_lattice(env.encode().map_err(|e| OrganismError::Msg(e.to_string()))?);
        tracing::info!(%key, "decay query enviado às hifas");
        Ok(())
    }

    fn reply_decay(&mut self, key: &str, asker: NodeId) -> Result<(), OrganismError> {
        if asker == self.gland.node_id() {
            return Ok(());
        }
        let Some(atom) = self.nucleus.decay(key).cloned() else {
            return Ok(());
        };
        let env = Envelope::DecayReply {
            key: key.to_string(),
            atom,
        };
        let _ = self
            .hyphae
            .broadcast_lattice(env.encode().map_err(|e| OrganismError::Msg(e.to_string()))?);
        tracing::debug!(%key, asker = %asker.short(), "decay reply enviado");
        Ok(())
    }

    fn handle_envelope(&mut self, env: Envelope) -> Result<(), OrganismError> {
        match env {
            // Overlay de zonas: envelope lacrado — só o destinatário abre.
            Envelope::Direct { to, inner } => {
                if to != self.gland.node_id() {
                    return Ok(()); // trânsito: replica no gossip, ignora conteúdo
                }
                tracing::debug!(from_overlay = true, "Direct aberto");
                return self.handle_envelope(*inner);
            }
            Envelope::SporePrint { plot } => {
                if !plot.is_public() {
                    tracing::warn!("spore print restrito recebido em claro: descartando sem persistir");
                    return Ok(());
                }
                let bytes = serde_json::to_vec(&plot)
                    .map_err(|e| OrganismError::Msg(e.to_string()))?;
                let id = self.bank.absorb_public(&bytes)?;
                let _ = self.hyphae.dht_store_local(dht_key(&id), bytes.clone());
                let _ = self.hyphae.dht_put(dht_key(&id), bytes);
                tracing::info!(plot = %id.short(), "spore print absorvido");
            }
            Envelope::SporeManifest { holder, ids } => {
                // Registra o detentor declarado (base da detecção offline).
                let now = unix_now();
                for id in &ids {
                    self.spore_holders
                        .entry(*id)
                        .or_default()
                        .insert(holder.clone(), now);
                }
                // Reconciliação por manifesto: puxa do DHT o que nos falta.
                let mut missing = 0usize;
                for id in &ids {
                    if self.bank.recall(id).is_none() {
                        self.hyphae.dht_get(dht_key(id));
                        missing += 1;
                    }
                }
                if missing > 0 {
                    tracing::debug!(
                        missing,
                        %holder,
                        "anti-entropy: manifesto revelou plots ausentes; pull DHT"
                    );
                }
            }
            Envelope::SignalBroadcast { signal } => {
                let id = self.state.field.absorb(signal);
                tracing::info!(signal = %id.short(), "signal absorvido");
                self.try_fire_pipelines()?;
            }
            Envelope::Resonance {
                signal_id,
                resonator,
            } => match self.state.field.absorb_resonance(&signal_id, resonator) {
                Ok(state) => {
                    tracing::info!(signal = %signal_id.short(), ?state, "ressonância absorvida");
                    self.try_fire_pipelines()?;
                }
                Err(thefield::FieldError::SignalNotFound(_)) => {}
                Err(e) => return Err(e.into()),
            },
            Envelope::VectorOffer { vector } => {
                tracing::debug!(plot = %vector.plot.short(), "vector oferecido na rede");
                self.accept_remote_vector(vector)?;
            }
            Envelope::MomentumReport {
                vector,
                momentum,
                executor,
                attestation,
            } => {
                tracing::info!(
                    plot = %vector.plot.short(),
                    executor = %executor.short(),
                    success = momentum.success,
                    "momentum report: {}",
                    momentum.log
                );
                let attestation_result = self.validate_momentum_attestation(
                    &vector,
                    &momentum,
                    executor,
                    attestation.as_ref(),
                );
                if let Err(error) = &attestation_result {
                    tracing::warn!(
                        plot = %vector.plot.short(),
                        executor = %executor.short(),
                        %error,
                        "momentum report rejeitado: atestacao ausente ou invalida"
                    );
                }
                // Crédito simbólico somente após validar e persistir a atestação.
                if attestation_result.is_ok()
                    && vector.emitter == self.gland.node_id()
                    && executor != self.gland.node_id()
                {
                    self.ledger.feed(
                        Nutrient::Spores,
                        1,
                        format!("remote-inertia:{}", executor.short()),
                    );
                }
            }
            Envelope::AtomSync { key, atom } => {
                if self.nucleus.owns(&key) {
                    self.nucleus.absorb(&key, atom);
                    tracing::info!(%key, "atom sync absorvido (dono do shard)");
                } else if self.pending_decays.contains(&key) {
                    self.nucleus.absorb(&key, atom);
                    self.pending_decays.remove(&key);
                    tracing::info!(%key, "atom sync absorvido (decay pendente)");
                } else {
                    tracing::debug!(%key, "atom sync ignorado — use Decay para ler shard remoto");
                }
            }
            Envelope::LayerOffer { id } => {
                let store = LayerStore::open(self.store.layers_dir())
                    .map_err(|e| OrganismError::Msg(e.to_string()))?;
                if !store.has(&id) {
                    self.hyphae.dht_get(layer_dht_key(&id));
                    tracing::debug!(layer = %id.short(), "layer offer → DHT get");
                }
            }
            Envelope::LayerNeed { id, hop } => {
                if self.serve_layer_if_present(&id)? {
                    // Layer servida — quem pediu já recebe via announce.
                } else if hop < MAX_LAYER_NEED_HOPS {
                    // Forwarding greedy: esta rede não tem a layer, então
                    // reencaminha o pedido aos custodiantes XOR-mais-próximos
                    // (com hop+1) — o pedido caminha em direção ao custodiante.
                    let need = Envelope::LayerNeed { id, hop: hop + 1 };
                    for custodian in self.xor_closest(&id.0) {
                        self.send_direct(custodian, need.clone());
                    }
                }
            }
            Envelope::DecayQuery { key, asker } => {
                self.reply_decay(&key, asker)?;
            }
            Envelope::DecayReply { key, atom } => {
                self.nucleus.absorb(&key, atom);
                self.pending_decays.remove(&key);
                tracing::info!(%key, "decay reply absorvido");
            }
            Envelope::ShadeOffer {
                shade,
                custodian,
                from,
            } => {
                if custodian == self.gland.node_id() {
                    self.vault.hold(from, shade);
                    self.persist()?;
                    tracing::info!(%from, "shade custodiada");
                }
            }
            Envelope::ShadeRequest {
                requester,
                threshold: _,
            } => {
                if requester != self.gland.node_id() && !self.vault.is_empty() {
                    for shade in self.vault.gather() {
                        let env = Envelope::ShadeOffer {
                            shade,
                            custodian: requester,
                            from: self.gland.node_id(),
                        };
                        if let Ok(bytes) = env.encode() {
                            let _ = self.hyphae.broadcast_lattice(bytes);
                        }
                    }
                    tracing::info!(%requester, "shades enviadas ao requisitante");
                }
            }
            Envelope::BalanceSync { node_id, balances, clock } => {
                if node_id == self.gland.node_id() {
                    return Ok(());
                }
                let entry = self.remote_ledger.entry(node_id).or_default();
                if clock > entry.1 {
                    entry.0 = balances;
                    entry.1 = clock;
                }
            }
            Envelope::IonOffer { ion, host: _, charge: _, desired_replicas: _, layers } => {
                if self.resources.cpu_cores == 0 || self.chambers.contains_key(&ion) {
                    return Ok(());
                }
                // Aceita se tem recursos ociosos
                self.pending_accepted_migrations.insert(ion.clone());
                let env = Envelope::IonAccept {
                    ion: ion.clone(),
                    acceptor: self.gland.node_id(),
                };
                if let Ok(bytes) = env.encode() {
                    let _ = self.hyphae.broadcast_lattice(bytes);
                }
                // Pede as layers
                for lid in &layers {
                    let env = Envelope::LayerNeed { id: *lid, hop: 0 };
                    if let Ok(bytes) = env.encode() {
                        let _ = self.hyphae.broadcast_lattice(bytes);
                    }
                }
            }
            Envelope::IonAccept { ion, acceptor } => {
                if acceptor == self.gland.node_id() {
                    return Ok(());
                }
                tracing::info!(%ion, %acceptor, "IonOffer aceito");
                // Auto-scaling: o peer aceitou a réplica → envia Void + layers
                // e paga o voucher de hospedagem (economia do substrato).
                if self.chambers.contains_key(&ion) {
                    match self.send_ion_migrate(&ion, acceptor) {
                        Ok(n) => {
                            tracing::info!(
                                %ion, %acceptor, layers = n,
                                "IonMigrate automático enviado (réplica brotando)"
                            );
                            self.issue_hosting_voucher(
                                &ion,
                                acceptor,
                                Self::HOSTING_REWARD_ATP,
                                "réplica",
                            );
                        }
                        Err(e) => tracing::warn!(%ion, error = %e, "auto-migração falhou"),
                    }
                    self.zero_load_windows.remove(&ion);
                }
            }
            Envelope::IonMigrate { ion, void, layers } => {
                if !self.pending_accepted_migrations.remove(&ion) {
                    tracing::warn!(%ion, "IonMigrate rejeitado: migração não autorizada/não solicitada por este nó");
                    return Ok(());
                }
                if void.name != ion || layers.len() > 32 {
                    tracing::warn!(%ion, "IonMigrate rejeitado: nome inconsistente ou layers em excesso");
                    return Ok(());
                }
                if let Err(e) = vacuum::validate_ion_name(&void.name) {
                    tracing::warn!(error = %e, "IonMigrate rejeitado: nome de ion inválido");
                    return Ok(());
                }
                let layer_store = match vacuum::LayerStore::open(self.store.layers_dir()) {
                    Ok(s) => s,
                    Err(_) => return Ok(()),
                };
                // Validação integral ANTES de gravar qualquer blob recebido.
                // Um anúncio de ContentId não autentica a origem, mas deve
                // sempre vincular os bytes ao hash prometido.
                if layers.iter().any(|(lid, data)| {
                    data.len() > 10 * 1024 * 1024
                        || !void.layers.contains(lid)
                        || ContentId::of(data) != *lid
                }) {
                    tracing::warn!(%ion, "IonMigrate rejeitado: layer fora do manifesto, excessiva ou hash inválido");
                    return Ok(());
                }
                for (lid, data) in &layers {
                    if !layer_store.has(lid) {
                        layer_store.put(data)?;
                    }
                }
                let missing: Vec<ContentId> = void.layers.iter().filter(|lid| !layer_store.has(lid)).copied().collect();
                if !missing.is_empty() {
                    for lid in &missing {
                        self.request_layer(lid);
                    }
                    return Ok(());
                }
                let name = void.name.clone();
                // Registra no Plasma para sense/scaling uniforme na réplica.
                if self.cloud.get(&name).is_none() {
                    if let Ok(chamber) = Chamber::suck_store(void.clone(), &layer_store, self.resources) {
                        match self.cloud.inject(Ion::birth(&name, self.gland.node_id(), chamber)) {
                            Ok(()) | Err(plasma::PlasmaError::AlreadyOrbiting(_)) => {}
                            Err(e) => tracing::warn!(ion = %name, "cloud.inject falhou: {e}"),
                        }
                    }
                }
                let fruit_opts = vacuum::FruitOptions {
                    fail_closed: true, // Migração remota sempre exige isolamento estrito
                    ..vacuum::FruitOptions::default()
                };
                match vacuum::ChamberProcess::fruit_void(
                    &self.mycelium_bin,
                    &self.store.chambers_dir(),
                    &void,
                    &layer_store,
                    &name,
                    fruit_opts,
                ) {
                    Ok(proc) => {
                        let host = format!("sporocarp.mycelium/{}", self.gland.node_id().short());
                        let upstream = proc.upstream.clone();
                        {
                            let mut table = self.horizon.write().unwrap();
                            table.expose(&host, singularity::Orbit {
                                ion: ion.clone(),
                                node: self.gland.node_id(),
                                mass: self.resources.cpu_cores as u64 * 10 + 1,
                                resistance: 0,
                                upstream: upstream.clone(),
                            });
                        }
                        let advertised_upstream = self.advertised_chamber_upstream(proc.port);
                        self.chambers.insert(ion.clone(), proc);
                        let env = Envelope::IonReady {
                            ion: ion.clone(),
                            node: self.gland.node_id(),
                            upstream: advertised_upstream,
                        };
                        if let Ok(bytes) = env.encode() {
                            let _ = self.hyphae.broadcast_lattice(bytes);
                        }
                        tracing::info!(%ion, "Ion migrado aceito — ChamberProcess frutificada");
                    }
                    Err(e) => tracing::warn!(error = %e, "IonMigrate fruit_void falhou"),
                }
            }
            Envelope::IonReady { ion, node, upstream } => {
                if node == self.gland.node_id() {
                    return Ok(());
                }
                let local_chamber = self.chambers.get(&ion).is_some();
                let is_loopback = upstream.contains("127.0.0.1") || upstream.contains("localhost");
                if !is_loopback {
                    let peers = self.ion_replica_peers.entry(ion.clone()).or_default();
                    if !peers.contains(&node) {
                        peers.push(node);
                    }
                    let now = SystemTime::now().duration_since(UNIX_EPOCH)
                        .unwrap_or_default().as_secs();
                    self.ion_replica_heartbeat.insert((ion.clone(), node), now);
                    let host = format!("sporocarp.mycelium/{}", self.gland.node_id().short());
                    let mass = if local_chamber { 5 } else { 10 };
                    let resistance = 2;
                    {
                        let mut table = self.horizon.write().unwrap();
                        table.expose(&host, singularity::Orbit {
                            ion: ion.clone(),
                            node,
                            mass,
                            resistance,
                            upstream,
                        });
                    }
                    tracing::info!(%ion, %node, local_chamber, "IonReady — réplica remota alcançável registrada");
                } else {
                    tracing::warn!(%ion, %node, "IonReady recebido com upstream loopback (127.0.0.1) — rota remota não exposta no proxy para evitar 502");
                }
            }
            Envelope::IonHeartbeat { node_id, ion } => {
                if node_id == self.gland.node_id() {
                    return Ok(()); // eco local: ignora.
                }
                // Um heartbeat para outro Ion não pode manter rota morta viva.
                if !self.ion_replica_peers.get(&ion)
                    .map(|peers| peers.contains(&node_id)).unwrap_or(false) {
                    return Ok(());
                }
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                self.ion_replica_heartbeat.insert((ion.clone(), node_id), now);
                tracing::debug!(%ion, %node_id, "IonHeartbeat — replica viva renovada");
            }
            Envelope::ZoneAnnounce { prefix, custodian } => {
                if custodian == self.gland.node_id() {
                    return Ok(());
                }
                let list = self.known_zones.entry(prefix).or_default();
                if !list.contains(&custodian) {
                    list.push(custodian);
                }
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                self.known_zones_ts.insert(custodian, now);
            }
            Envelope::ValueTransfer { tx } => {
                if let Err(e) = self.apply_incoming_transfer(tx, false) {
                    tracing::debug!("value-transfer rejeitada: {e}");
                }
            }
            Envelope::IonAnnounce {
                node_id,
                ion,
                membrane: _,
            } => {
                let ion_clone = ion.clone();
                if node_id != self.gland.node_id() {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let entry = self.peer_ions.entry(node_id).or_insert_with(|| (Vec::new(), now));
                    if !entry.0.contains(&ion) {
                        entry.0.push(ion);
                    }
                    entry.1 = now; // atualiza timestamp
                }
                // Efeito manada: brota ergot-seed com rate-limit 1/min.
                if ion_clone == "ergot-seed" {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if now.saturating_sub(self.last_brood) >= 60 {
                        self.try_brood_seed_ion();
                        self.last_brood = now;
                    }
                }
            }
            Envelope::RepoAnnounce { node_id, name, url, commit, description } => {
                if node_id != self.gland.node_id() {
                    self.known_repos.insert(
                        name.clone(),
                        (url, commit, description, node_id),
                    );
                    tracing::info!(
                        repo = %name,
                        from = %node_id,
                        "repo anunciado via gossip — git clone disponível"
                    );
                }
            }
            Envelope::VoucherRedeem { voucher } => {
                if voucher.payee == self.gland.node_id() {
                    match self.ledger.redeem_voucher(&voucher) {
                        Ok(()) => {
                            tracing::info!(
                                from = %voucher.payer,
                                amount = voucher.amount,
                                nutrient = ?voucher.nutrient,
                                "voucher resgatado — a rede alimenta quem alimenta"
                            );
                            let _ = self.persist();
                        }
                        Err(e) => tracing::warn!(error = %e, "voucher rejeitado"),
                    }
                }
            }
        }
        self.persist()?;
        Ok(())
    }

    /// Inicia o handshake de migração enviando `IonOffer` unicast ao acceptor.
    fn initiate_ion_migration(&mut self, ion: &str, acceptor: NodeId) -> Result<(), String> {
        let chamber = match self.chambers.get(ion) {
            Some(c) => c,
            None => return Err(format!("ion `{ion}` não está neste nó")),
        };
        let layers: Vec<ContentId> = chamber
            .void_layers()
            .iter()
            .filter_map(|s| s.parse::<ContentId>().ok())
            .collect();
        let env = Envelope::IonOffer {
            ion: ion.to_string(),
            host: self.gland.node_id(),
            charge: plasma::Charge::Positive,
            desired_replicas: 2,
            layers,
        };
        self.send_direct(acceptor, env);
        Ok(())
    }

    /// Empacota Void + layers do ion local e envia `IonMigrate` **direcionado**
    /// ao acceptor (unicast via `Envelope::Direct{to}` sobre a lattice).
    ///
    /// Antes este método dava broadcast do IonMigrate em toda a lattice — na
    /// WAN isso inunda a rede com camadas de ion para quem não é o
    /// destinatário. Agora o envelope é lacrado (`Direct{to:acceptor}`) e só
    /// o acceptor o processa; intermediários apenas replicam o gossip.
    ///
    /// Usado pelo comando manual (`mycelium ion-migrate`) e pelo auto-scaling
    /// do Plasma (quando um peer responde `IonAccept` a um `IonOffer`).
    fn send_ion_migrate(&mut self, ion: &str, acceptor: NodeId) -> Result<usize, String> {
        let chamber = match self.chambers.get(ion) {
            Some(c) => c,
            None => return Err(format!("ion `{ion}` não está neste nó")),
        };
        // Extrai Void do chamber spec
        let void = Void {
            name: ion.to_string(),
            layers: chamber
                .void_layers()
                .iter()
                .filter_map(|s| s.parse::<ContentId>().ok())
                .collect(),
            entrypoint: "chamber-serve".into(),
        };
        let layer_store = LayerStore::open(self.store.layers_dir())
            .map_err(|e| format!("layer store indisponível: {e}"))?;
        let mut layers_data = Vec::new();
        for lid in &void.layers {
            if let Some(bytes) = layer_store.get(lid) {
                layers_data.push((*lid, bytes));
            }
        }
        let n_layers = void.layers.len();
        let env = Envelope::IonMigrate {
            ion: ion.to_string(),
            void,
            layers: layers_data,
        };
        // Unicast direcionado: só o acceptor processa o IonMigrate.
        self.send_direct(acceptor, env);
        Ok(n_layers)
    }

    /// Recompensa fixa (ATP) paga por réplica nascida sob demanda.
    const HOSTING_REWARD_ATP: u64 = 5;
    /// Tip por janela de scaling com tráfego para cada réplica remota viva.
    const HOSTING_TIP_ATP: u64 = 1;

    /// Emite e assina um voucher de hospedagem ao peer que serve este ion
    /// — debita o pagador e broadcast `VoucherRedeem`.
    fn issue_hosting_voucher(&mut self, ion: &str, payee: NodeId, amount: u64, motivo: &str) {
        if payee == self.gland.node_id() {
            return;
        }
        if self.ledger.balance(Nutrient::Atp) < amount {
            tracing::debug!(ion = %ion, %payee, "sem ATP para voucher de hospedagem");
            return;
        }
        if let Err(e) = self.ledger.metabolize(
            Nutrient::Atp,
            amount,
            Some(payee),
            format!("hospedagem:{ion}"),
        ) {
            tracing::warn!(error = %e, "débito do voucher falhou");
            return;
        }
        let clock = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut voucher = mycelium_nutrients::Voucher {
            payer: self.gland.node_id(),
            payee,
            nutrient: Nutrient::Atp,
            amount,
            memo: format!("{motivo} `{ion}`"),
            clock,
            payer_key: self.gland.verifying_key().to_bytes(),
            signature: vec![],
            bolt11: None,
        };
        voucher.signature = self.gland.sign_bytes(&voucher.payload_bytes());
        debug_assert!(voucher.verify().is_ok());

        let env = Envelope::VoucherRedeem { voucher };
        if let Ok(bytes) = env.encode() {
            let _ = self.hyphae.broadcast_lattice(bytes);
        }
        tracing::info!(
            ion = %ion,
            %payee,
            atp = amount,
            motivo = %motivo,
            "voucher de hospedagem emitido"
        );
    }

    /// Plasma reativo (tick de scaling): drena a carga observada pelo
    /// Horizon, alimenta `Ion::sense` e decide — carga positiva brota
    /// réplicas (IonOffer → IonAccept → IonMigrate → IonReady); carga zero
    /// persistente recombina o Ion local quando outra réplica viva cobre.
    fn plasma_scale_tick(&mut self) {
        const WINDOW_SECS: u64 = 45;
        const OFFER_COOLDOWN: Duration = Duration::from_secs(120);
        const RECOMBINE_AFTER_WINDOWS: u32 = 3;

        let counts = { self.horizon.write().unwrap().take_request_counts() };

        // 1. Sense: carga por ion local vivo + janelas de ociosidade.
        for name in self.chambers.keys().cloned().collect::<Vec<_>>() {
            let requests = counts.get(&name).copied().unwrap_or(0);
            let rps = requests / WINDOW_SECS.max(1);
            if let Some(ion) = self.cloud.get_mut(&name) {
                ion.sense(rps);
            }
            let windows = self.zero_load_windows.entry(name.clone()).or_insert(0);
            *windows = if requests == 0 {
                windows.saturating_add(1)
            } else {
                0
            };
        }

        // 2. Carga positiva e réplicas abaixo do desejado → IonOffer (cooldown).
        let now = Instant::now();
        let mut offers: Vec<(String, Charge, u32, Vec<ContentId>)> = Vec::new();
        for name in self.chambers.keys() {
            let Some(ion) = self.cloud.get(name) else {
                continue;
            };
            if ion.charge != Charge::Positive {
                continue;
            }
            let remote = self
                .ion_replica_peers
                .get(name)
                .map(|v| v.len())
                .unwrap_or(0);
            if 1 + remote >= ion.desired_replicas as usize {
                continue; // réplicas suficientes já orbitam
            }
            let cooled = self
                .last_scaling_offer
                .get(name)
                .map(|t| now.duration_since(*t) >= OFFER_COOLDOWN)
                .unwrap_or(true);
            if !cooled {
                continue;
            }
            let Some(chamber) = self.chambers.get(name) else {
                continue;
            };
            let layers = chamber
                .void_layers()
                .iter()
                .filter_map(|s| s.parse::<ContentId>().ok())
                .collect();
            offers.push((name.clone(), ion.charge, ion.desired_replicas, layers));
            self.last_scaling_offer.insert(name.clone(), now);
        }
        for (ion, charge, desired_replicas, layers) in offers {
            let env = Envelope::IonOffer {
                ion: ion.clone(),
                host: self.gland.node_id(),
                charge,
                desired_replicas,
                layers,
            };
            if let Ok(bytes) = env.encode() {
                let _ = self.hyphae.broadcast_lattice(bytes);
            }
            tracing::info!(
                %ion,
                desired_replicas,
                "plasma: carga positiva — IonOffer de réplica broadcast"
            );
        }

        // 3. Ociosidade persistente com réplica remota viva → recombine.
        //    MULTI-RÉPLICA (fix): com N≥2 réplicas, cada uma recebe IonReady
        //    das outras e todas se achavam "cobertas" → recombinitam juntas e
        //    o ion morria na malha inteira. Agora o recombine só vale para
        //    quem tem uma réplica remota VIVA (IonAnnounce fresco, TTL de 4
        //    janelas) com NodeId MENOR — o menor NodeId vivo é o âncora
        //    determinístico e nunca recombina (invariante: o ion sobrevive).
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        const ANCHOR_TTL_SECS: u64 = 180; // 4 janelas de scaling
        let idle: Vec<String> = self
            .zero_load_windows
            .iter()
            .filter(|(name, windows)| {
                **windows >= RECOMBINE_AFTER_WINDOWS && self.chambers.contains_key(*name)
            })
            .map(|(name, _)| name.clone())
            .collect();
        for name in idle {
            // Réplica remota viva com NodeId menor que o meu?
            let covered_by_anchor = self
                .ion_replica_peers
                .get(&name)
                .map(|peers| {
                    peers.iter().any(|peer| {
                        *peer < self.gland.node_id()
                            && self
                                .peer_ions
                                .get(peer)
                                .map(|(ions, ts)| {
                                    ions.contains(&name)
                                        && now.saturating_sub(*ts) < ANCHOR_TTL_SECS
                                })
                                .unwrap_or(false)
                    })
                })
                .unwrap_or(false);
            if !covered_by_anchor {
                continue; // sou o âncora (menor NodeId vivo) — morrer apagaria o ion da rede
            }
            if let Some(mut ion) = self.cloud.remove(&name) {
                ion.decompose();
            }
            if let Some(proc) = self.chambers.remove(&name) {
                tracing::info!(
                    ion = %name,
                    upstream = %proc.upstream,
                    "plasma: demanda zero persistente — Chamber recombinada (réplica remota cobre)"
                );
            }
            self.horizon.write().unwrap().remove_ion(&name);
            self.state.ions.retain(|r| r.name != name);
            self.zero_load_windows.remove(&name);
            self.last_scaling_offer.remove(&name);
            let _ = self.persist();
        }

        // 4. Hospedagem contínua: enquanto há tráfego na janela, cada
        //    réplica remota viva recebe um tip — a renda acompanha a demanda.
        for (name, peers) in self.ion_replica_peers.clone() {
            if counts.get(&name).copied().unwrap_or(0) == 0 {
                continue; // janela ociosa não rende
            }
            if !self.chambers.contains_key(&name) {
                continue;
            }
            for peer in peers {
                self.issue_hosting_voucher(
                    &name,
                    peer,
                    Self::HOSTING_TIP_ATP,
                    "janela de tráfego",
                );
            }
        }

        // 5. Heartbeat de réplica: anuncia para o mesh que este nó ainda
        //    serve cada ion local (réplicas caídas são detectadas mais rápido
        //    que pelo TTL genérico do peer_ions).
        for (name, _) in &self.chambers {
            let env = Envelope::IonHeartbeat {
                node_id: self.gland.node_id(),
                ion: name.clone(),
            };
            if let Ok(bytes) = env.encode() {
                let _ = self.hyphae.broadcast_lattice(bytes);
            }
        }

        // 6. Prune réplicas cuja heartbeat sumiu — detecção de falha rápida.
        const REPLICA_HEARTBEAT_TTL: u64 = 120; // 2 janelas de scaling
        let expired: Vec<(String, NodeId)> = self.ion_replica_peers.iter()
            .flat_map(|(ion, peers)| peers.iter().filter_map(|peer| {
                let ts = self.ion_replica_heartbeat.get(&(ion.clone(), *peer))?;
                (now.saturating_sub(*ts) >= REPLICA_HEARTBEAT_TTL)
                    .then(|| (ion.clone(), *peer))
            }))
            .collect();
        for (ion, peer) in expired {
            if let Some(peers) = self.ion_replica_peers.get_mut(&ion) {
                peers.retain(|p| *p != peer);
            }
            self.ion_replica_heartbeat.remove(&(ion.clone(), peer));
            self.horizon.write().unwrap().collapse_ion_node(&ion, &peer);
            tracing::warn!(%ion, %peer, "réplica expirada: removida do Event Horizon");
        }
        self.check_auto_materialize_orphaned_services();
    }

    /// Detecta plots que representam serviços comunitários soberanos na ausência
    /// do publicador/hospedeiro original e auto-materializa a Chamber e a rota no Event Horizon local.
    pub fn check_auto_materialize_orphaned_services(&mut self) {
        let ids: Vec<mycelium_core::ContentId> = self.bank.ids().to_vec();
        for id in ids {
            let Some(plot) = self.bank.recall(&id) else {
                continue;
            };
            if !plot.is_public() {
                continue;
            }
            let is_service = plot.message.to_lowercase().contains("serviço comunitário")
                || plot.message.to_lowercase().contains("servico comunitario")
                || plot.message.starts_with("ion:")
                || plot.leaves.iter().any(|l| l.path == "index.html" || l.path.ends_with(".html"));

            if !is_service {
                continue;
            }

            let ion_name = if let Some(stripped) = plot.message.strip_prefix("ion:") {
                stripped.trim().to_string()
            } else if let Some(idx) = plot.message.to_lowercase().find("serviço comunitário: ") {
                let sub = &plot.message[idx + "serviço comunitário: ".len()..];
                let title = sub.split(" v").next().unwrap_or(sub).trim();
                let slug: String = title
                    .chars()
                    .map(|c| if c.is_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
                    .collect();
                let clean_slug: String = slug.split('-').filter(|s| !s.is_empty()).collect::<Vec<_>>().join("-");
                if clean_slug.is_empty() { "servico-comunitario".to_string() } else { clean_slug }
            } else if let Some(idx) = plot.message.to_lowercase().find("servico comunitario: ") {
                let sub = &plot.message[idx + "servico comunitario: ".len()..];
                let title = sub.split(" v").next().unwrap_or(sub).trim();
                let slug: String = title
                    .chars()
                    .map(|c| if c.is_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
                    .collect();
                let clean_slug: String = slug.split('-').filter(|s| !s.is_empty()).collect::<Vec<_>>().join("-");
                if clean_slug.is_empty() { "servico-comunitario".to_string() } else { clean_slug }
            } else {
                "servico-comunitario".to_string()
            };

            if self.chambers.contains_key(&ion_name) {
                continue;
            }

            let has_remote_alive = self.ion_replica_peers.get(&ion_name)
                .map(|peers| !peers.is_empty())
                .unwrap_or(false);

            if !has_remote_alive {
                tracing::info!(ion = %ion_name, plot = %id.short(), "hospedeiro original inativo: auto-materializando Chamber soberana no destino");
                if let Err(e) = self.birth_ion(&ion_name, &id.to_string(), "default") {
                    tracing::warn!(ion = %ion_name, error = %e, "falha na auto-materialização de Chamber órfã");
                } else {
                    tracing::info!(ion = %ion_name, "Chamber órfã materializada com sucesso e registrada no Event Horizon");
                }
            }
        }
    }

    #[cfg(feature = "veil")]
    /// Caminho do arquivo de identidade persistente do nó Veil (GhostId + ML-KEM-1024).
    fn veil_identity_file(&self) -> PathBuf {
        self.veil_identity_path
            .clone()
            .unwrap_or_else(|| self.home().join("veil-identity.json"))
    }

    #[cfg(feature = "veil")]
    /// Carrega (ou cria) a identidade persistente do nó Veil. Rotação é sempre explícita
    /// (`veil_rotate_identity`) — um reinício nunca regenera a identidade silenciosamente.
    /// Retorna `(identidade, mensagem_de_log_opcional)`.
    fn load_veil_node_identity(
        &self,
    ) -> Result<(mycelium_veil::VeilNodeIdentity, Option<String>), OrganismError> {
        let path = self.veil_identity_file();
        if self.veil_rotate_identity {
            let (identity, old_hex, new_hex) = mycelium_veil::VeilNodeIdentity::rotate(&path)
                .map_err(|e| OrganismError::Msg(format!("falha ao rotacionar identidade Veil: {e}")))?;
            tracing::warn!(
                old_identity = %old_hex,
                new_identity = %new_hex,
                path = %path.display(),
                "identidade Veil rotacionada explicitamente — redistribua descritores e pins"
            );
            Ok((identity, Some(format!("identidade rotacionada: {old_hex} -> {new_hex}"))))
        } else {
            let (identity, created) = mycelium_veil::VeilNodeIdentity::load_or_create(
                &path,
                Some(self.gland.seed()),
            )
            .map_err(|e| OrganismError::Msg(format!("falha ao carregar identidade Veil: {e}")))?;
            let log = if created {
                tracing::warn!(
                    path = %path.display(),
                    identity = %hex::encode(identity.ghost.nostr_pubkey()),
                    "primeira execução: nova identidade Veil persistida — distribua este pin aos clientes"
                );
                Some(format!("nova identidade Veil persistida em {}", path.display()))
            } else {
                tracing::info!(
                    identity = %hex::encode(identity.ghost.nostr_pubkey()),
                    "identidade Veil carregada do disco (pins continuam válidos)"
                );
                None
            };
            Ok((identity, log))
        }
    }

    #[cfg(feature = "veil")]
    /// Resolve o endpoint anunciado no descritor assinado: `veil_advertise` se fornecido
    /// (separado da escuta), senão o próprio listen quando ele NÃO for 0.0.0.0/[::].
    fn resolve_veil_advertise(&self, listen: std::net::SocketAddr) -> Result<String, OrganismError> {
        if let Some(advertise) = &self.veil_advertise {
            if !advertise.contains(':') {
                return Err(OrganismError::Msg(format!(
                    "--veil-advertise '{advertise}' deve incluir porta (ex.: 203.0.113.9:9050 ou relay.example.org:9050)"
                )));
            }
            return Ok(advertise.clone());
        }
        let ip = listen.ip();
        if ip.is_unspecified() {
            return Err(OrganismError::Msg(
                "o endereço de escuta 0.0.0.0/[::] não pode ser anunciado no descritor assinado: \
                 informe --veil-advertise <ip|hostname>:<porta> alcançável pelos demais nós \
                 (endereço anunciado é separado do endereço de escuta)".into(),
            ));
        }
        Ok(listen.to_string())
    }

    #[cfg(feature = "veil")]
    pub async fn start_veil_service(&mut self) -> Result<std::net::SocketAddr, OrganismError> {
        use mycelium_veil::{
            proxy_socks5_connection, CircuitHopNode, LiveCircuitClient, Socks5Server,
            VeilConfig, VeilEngine, VeilHopRouter, VeilMode,
        };
        use std::sync::Arc;

        self.stop_veil_service();

        let socks_addr = self.veil_socks5_addr.unwrap_or_else(|| {
            "127.0.0.1:1080".parse().expect("valid loopback socks5 addr")
        });

        let mut config = match self.veil_mode.as_deref() {
            Some("geo") => VeilConfig::new_geo(socks_addr.port()),
            Some("mix") => VeilConfig::new_mix(),
            _ => VeilConfig::new_veil(socks_addr.port()),
        };
        config.socks5_bind = socks_addr;

        let engine = Arc::new(VeilEngine::new(config.clone()));
        let _session = engine
            .start_session(config.mode)
            .map_err(|e| OrganismError::Msg(e.to_string()))?;

        let role = self.veil_role.as_deref().unwrap_or("all");
        let mut router_handles = Vec::new();

        match role {
            "relay" => {
                let listen_addr = self.veil_listen.unwrap_or_else(|| {
                    "0.0.0.0:9050".parse().expect("valid relay listen addr")
                });
                let advertise = self.resolve_veil_advertise(listen_addr)?;
                let listener = tokio::net::TcpListener::bind(listen_addr)
                    .await
                    .map_err(|e| OrganismError::Msg(format!("Erro no bind do nó Relay: {e}")))?;
                let actual_addr = listener.local_addr().map_err(|e| OrganismError::Msg(e.to_string()))?;

                // Identidade persistente: o reinício do relay NÃO pode invalidar os pins
                // distribuídos aos clientes (--veil-trust) nem a chave KEM do descritor.
                let (identity, identity_log) = self.load_veil_node_identity()?;
                let identity_hex = hex::encode(identity.ghost.nostr_pubkey());
                tracing::info!(
                    bind = %actual_addr,
                    advertise = %advertise,
                    identity = %identity_hex,
                    "VEIL Ω nó Relay ativo"
                );
                let router = identity.into_router(None);
                let desc = router.descriptor(self.gland.node_id().to_string(), advertise);
                self.veil_local_descriptor = Some(desc.to_json().map_err(|e| OrganismError::Msg(e.to_string()))?);

                router_handles.push(tokio::spawn(async move {
                    let _ = router.run(listener).await;
                }));

                self.veil_engine = Some(engine);
                self.veil_router_handles = router_handles;
                self.veil_enabled = true;

                if let Some(msg) = identity_log {
                    tracing::info!("{msg}");
                }
                Ok(actual_addr)
            }
            "bridge" => {
                // Expect exactly one bridge address (listen) and a target Guard.
                // O operador deve informar `--veil-bridge <listen>` (repetível) e
                // `--veil-bridge-target <guard>` (endereço Guard). Opcional: `--veil-bridge-listen`
                // para sobrescrever o endereço de escuta se desejar. Por enquanto usamos
                // o primeiro bridge da lista.
                let listen_addr_str = match self.veil_bridge_listen.as_ref().or_else(|| self.veil_bridges.get(0)) {
                    Some(l) => l.clone(),
                    None => return Err(OrganismError::Msg("Modo bridge requer ao menos um endereço de escuta via --veil-bridge ou --veil-bridge-listen".into())),
                };
                let listen_addr: std::net::SocketAddr = listen_addr_str.parse().map_err(|e| OrganismError::Msg(format!("listen bridge inválido: {e}")))?;
                let target = match &self.veil_bridge_target {
                    Some(t) => t.clone(),
                    None => return Err(OrganismError::Msg("Modo bridge requer --veil-bridge-target <guard>".into())),
                };
                let target_addr: std::net::SocketAddr = target.parse().map_err(|e| OrganismError::Msg(format!("target bridge inválido: {e}")))?;
                // Convert VeilError to OrganismError for proper ? propagation
                let handle = mycelium_veil::BridgeRelay::spawn(listen_addr, target_addr).await
                    .map_err(|e| OrganismError::Msg(e.to_string()))?;
                let actual = handle.listen_addr();
                self.veil_listen = Some(actual);
                self.veil_bridge_handles.push(handle);
                self.veil_enabled = true;
                Ok(actual)
            },
            "exit" => {
                let listen_addr = self.veil_listen.unwrap_or_else(|| {
                    "0.0.0.0:9051".parse().expect("valid exit listen addr")
                });
                let advertise = self.resolve_veil_advertise(listen_addr)?;
                let listener = tokio::net::TcpListener::bind(listen_addr)
                    .await
                    .map_err(|e| OrganismError::Msg(format!("Erro no bind do nó Exit: {e}")))?;
                let actual_addr = listener.local_addr().map_err(|e| OrganismError::Msg(e.to_string()))?;

                let (identity, identity_log) = self.load_veil_node_identity()?;
                let identity_hex = hex::encode(identity.ghost.nostr_pubkey());
                tracing::info!(
                    bind = %actual_addr,
                    advertise = %advertise,
                    identity = %identity_hex,
                    "VEIL Ω nó Exit ativo"
                );
                let mut router = identity.into_router(Some(config.exit_policy.clone()));
                // Egresso do Exit: vincula-se a um IP de origem apenas quando o operador o
                // indica explicitamente (hosts multi-homing). O default (None) deixa a rota
                // do sistema escolher a origem — sob NAT, o IP observado pelo destino é o da
                // tradução da rede, não o do bind local nem o anunciado no descritor.
                if let Some(src) = self.veil_egress_bind {
                    tracing::warn!(
                        source = %src,
                        "egress bind explícito configurado; sob NAT o destino observa o IP traduzido, não este bind"
                    );
                    router = router.with_bind_source(src);
                } else {
                    tracing::debug!(
                        "egress sem bind explícito — IP de origem escolhido pela rota do sistema (NAT reescreve)"
                    );
                }
                let desc = router.descriptor(self.gland.node_id().to_string(), advertise);
                self.veil_local_descriptor = Some(desc.to_json().map_err(|e| OrganismError::Msg(e.to_string()))?);

                router_handles.push(tokio::spawn(async move {
                    let _ = router.run(listener).await;
                }));

                self.veil_engine = Some(engine);
                self.veil_router_handles = router_handles;
                self.veil_enabled = true;

                if let Some(msg) = identity_log {
                    tracing::info!("{msg}");
                }
                Ok(actual_addr)
            }
            "client" => {
                let mut hops = Vec::new();
                let mut parsed_descriptors: Vec<mycelium_veil::planes::live::NodeDescriptor> = Vec::new();
                for g in &self.veil_guards {
                    let d = parse_veil_descriptor_source(g)?;
                    parsed_descriptors.push(d.clone());
                    hops.push(CircuitHopNode::from_descriptor(d));
                }
                for m in &self.veil_middles {
                    let d = parse_veil_descriptor_source(m)?;
                    parsed_descriptors.push(d.clone());
                    hops.push(CircuitHopNode::from_descriptor(d));
                }
                for e in &self.veil_exits {
                    let d = parse_veil_descriptor_source(e)?;
                    parsed_descriptors.push(d.clone());
                    hops.push(CircuitHopNode::from_descriptor(d));
                }

                if hops.is_empty() {
                    return Err(OrganismError::Msg(
                        "Modo client requer nós configurados (--veil-guard, --veil-middle, --veil-exit)".into(),
                    ));
                }

                // Modo produção: se houver pinning de identidade configurado, o cliente exige
                // que cada salto apresente exatamente a identidade fixada (anti-substituição).
                // Se bridges configuradas, usamos EntryPool (modo Test) sem pinning.
                let circuit_client = if !self.veil_bridges.is_empty() {
                    // Constrói pool de bridges
                    let mut pool = mycelium_veil::bridge::EntryPool::new();
                    for (i, bridge_addr) in self.veil_bridges.iter().enumerate() {
                        let addr: std::net::SocketAddr = bridge_addr.parse().map_err(|e| OrganismError::Msg(format!("bridge address inválido: {e}")))?;
                        let entry = mycelium_veil::BridgeEntry::new(format!("bridge-{}", i + 1), addr);
                        pool.push(std::sync::Arc::new(entry));
                    }
                    self.veil_registered_entries = pool.entries().iter().map(|e| e.id().to_string()).collect();
                    let client = LiveCircuitClient::connect_via_entries(101, hops, &pool)
                        .await
                        .map_err(|e| OrganismError::Msg(format!("Falha no handshake Veil (via bridges): {e}")))?;
                    self.veil_entry_pool = Some(pool);
                    Arc::new(client)
                } else if !self.veil_trust.is_empty() {
                    if self.veil_trust.len() != parsed_descriptors.len() {
                        return Err(OrganismError::Msg(format!(
                            "Modo produção (--veil-trust) exige uma identidade por salto: {} saltos, {} pins",
                            parsed_descriptors.len(),
                            self.veil_trust.len()
                        )));
                    }
                    let mut trusted = Vec::with_capacity(self.veil_trust.len());
                    for (i, pin) in self.veil_trust.iter().enumerate() {
                        let (name, identity_hex) = pin.split_once(':').ok_or_else(|| {
                            OrganismError::Msg(format!("Pin inválido '{pin}' (esperado '<nome>:<hex_identity>')"))
                        })?;
                        let identity_pubkey: [u8; 32] = hex::decode(identity_hex)
                            .map_err(|e| OrganismError::Msg(format!("Hex de identidade inválido em '{pin}': {e}")))?
                            .try_into()
                            .map_err(|_| OrganismError::Msg(format!("Identidade em '{pin}' deve ter 32 bytes")))?;
                        let desc = &parsed_descriptors[i];
                        trusted.push(
                            mycelium_veil::planes::live::TrustedIdentity::new(
                                name.to_string(),
                                identity_pubkey,
                                desc.public_kem_key.clone(),
                            )
                            .with_endpoint(desc.endpoint.clone()),
                        );
                    }
                    Arc::new(
                        LiveCircuitClient::connect_production(101, hops, &trusted)
                            .await
                            .map_err(|e| OrganismError::Msg(format!("Falha no handshake telescópico Veil (produção): {e}")))?,
                    )
                } else {
                    Arc::new(
                        LiveCircuitClient::connect(101, hops)
                            .await
                            .map_err(|e| OrganismError::Msg(format!("Falha no handshake telescópico Veil: {e}")))?,
                    )
                };

                // Atualiza observabilidade após tentativa de handshake via pool (se houver)
                if let Some(pool) = &self.veil_entry_pool {
                    self.veil_active_entry = pool.last_successful_entry();
                    self.veil_failover_attempts = pool.last_failover_attempts();
                    self.veil_failure_reasons = pool.last_failure_reasons();
                }

                let server = Socks5Server::new(socks_addr);
                // Remove duplicated bind call
                let listener = server
                    .bind()
                    .await
                    .map_err(|e| OrganismError::Msg(e.to_string()))?;
                let actual_bind = listener.local_addr().map_err(|e| OrganismError::Msg(e.to_string()))?;

                let kill_switch = engine.kill_switch().clone();
                let ks_clone = kill_switch.clone();
                let c_client = Arc::clone(&circuit_client);

                let task_handle = tokio::spawn(async move {
                    tracing::info!(bind = %actual_bind, "VEIL SOCKS5 proxy escutando");
                    loop {
                        match listener.accept().await {
                            Ok((stream, _peer_addr)) => {
                                let c = Arc::clone(&c_client);
                                let ks = ks_clone.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = proxy_socks5_connection(stream, c, ks).await {
                                        tracing::debug!(error = %e, "conexao socks5 finalizada");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "socks5 listener fechado");
                                break;
                            }
                        }
                    }
                });

                self.veil_engine = Some(engine);
                self.veil_socks5_handle = Some(task_handle);
                self.veil_socks5_addr = Some(actual_bind);
                self.veil_router_handles = router_handles;
                self.veil_enabled = true;

                tracing::info!(
                    bind = %actual_bind,
                    "VEIL Ω cliente ativo — SOCKS5 pronto com circuito telescópico ML-KEM-1024"
                );

                Ok(actual_bind)
            }
            _ => {
                // 1. Inicia nós do circuito (Exit, e opcionalmente Middle e Guard)
                let exit_kp = mycelium_pqc::mlkem_keygen();
                let exit_router = VeilHopRouter::new(exit_kp, Some(config.exit_policy.clone()));
                let exit_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .map_err(|e| OrganismError::Msg(format!("Erro no bind do nó Exit: {e}")))?;
                let exit_addr = exit_listener.local_addr().map_err(|e| OrganismError::Msg(e.to_string()))?;
                let exit_desc = exit_router.descriptor("exit-node".into(), exit_addr.to_string());
                router_handles.push(tokio::spawn(async move {
                    let _ = exit_router.run(exit_listener).await;
                }));

                let hops = if config.mode == VeilMode::Geo {
                    vec![CircuitHopNode::from_descriptor(exit_desc)]
                } else {
                    let middle_kp = mycelium_pqc::mlkem_keygen();
                    let middle_router = VeilHopRouter::new(middle_kp, None);
                    let middle_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                        .await
                        .map_err(|e| OrganismError::Msg(format!("Erro no bind do nó Middle: {e}")))?;
                    let middle_addr = middle_listener.local_addr().map_err(|e| OrganismError::Msg(e.to_string()))?;
                    let middle_desc = middle_router.descriptor("middle-node".into(), middle_addr.to_string());
                    router_handles.push(tokio::spawn(async move {
                        let _ = middle_router.run(middle_listener).await;
                    }));

                    let guard_kp = mycelium_pqc::mlkem_keygen();
                    let guard_router = VeilHopRouter::new(guard_kp, None);
                    let guard_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                        .await
                        .map_err(|e| OrganismError::Msg(format!("Erro no bind do nó Guard: {e}")))?;
                    let guard_addr = guard_listener.local_addr().map_err(|e| OrganismError::Msg(e.to_string()))?;
                    let guard_desc = guard_router.descriptor("guard-node".into(), guard_addr.to_string());
                    self.veil_local_descriptor = Some(guard_desc.to_json().map_err(|e| OrganismError::Msg(e.to_string()))?);
                    router_handles.push(tokio::spawn(async move {
                        let _ = guard_router.run(guard_listener).await;
                    }));

                    vec![
                        CircuitHopNode::from_descriptor(guard_desc),
                        CircuitHopNode::from_descriptor(middle_desc),
                        CircuitHopNode::from_descriptor(exit_desc),
                    ]
                };

                // 2. Conecta o cliente do circuito através do handshake telescópico ML-KEM-1024
                let circuit_client = Arc::new(
                    LiveCircuitClient::connect(101, hops)
                        .await
                        .map_err(|e| OrganismError::Msg(format!("Falha no handshake telescópico Veil: {e}")))?,
                );

                // 3. Inicia servidor SOCKS5 local (sem ExitForwarder local!)
                let server = Socks5Server::new(socks_addr);
                let listener = server
                    .bind()
                    .await
                    .map_err(|e| OrganismError::Msg(e.to_string()))?;
                let actual_bind = listener.local_addr().map_err(|e| OrganismError::Msg(e.to_string()))?;

                let kill_switch = engine.kill_switch().clone();
                let ks_clone = kill_switch.clone();
                let c_client = Arc::clone(&circuit_client);

                let task_handle = tokio::spawn(async move {
                    tracing::info!(bind = %actual_bind, "VEIL SOCKS5 proxy escutando");
                    loop {
                        match listener.accept().await {
                            Ok((stream, _peer_addr)) => {
                                let c = Arc::clone(&c_client);
                                let ks = ks_clone.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = proxy_socks5_connection(stream, c, ks).await {
                                        tracing::debug!(error = %e, "conexao socks5 finalizada");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "socks5 listener fechado");
                                break;
                            }
                        }
                    }
                });

                self.veil_engine = Some(engine);
                self.veil_socks5_handle = Some(task_handle);
                self.veil_socks5_addr = Some(actual_bind);
                self.veil_router_handles = router_handles;
                self.veil_enabled = true;

                tracing::info!(
                    bind = %actual_bind,
                    "VEIL Ω ativo no organismo — SOCKS5 pronto com circuito telescópico ML-KEM-1024"
                );

                Ok(actual_bind)
            }
        }
    }

    #[cfg(feature = "veil")]
    pub fn stop_veil_service(&mut self) {
        if let Some(handle) = self.veil_socks5_handle.take() {
            handle.abort();
        }
        for handle in self.veil_router_handles.drain(..) {
            handle.abort();
        }
        self.veil_bridge_handles.clear();
        if let Some(engine) = self.veil_engine.take() {
            engine.stop_session();
        }
        self.veil_enabled = false;
        tracing::info!("VEIL Ω encerrado no organismo");
    }

    #[cfg(not(feature = "veil"))]
    pub async fn start_veil_service(&mut self) -> Result<std::net::SocketAddr, OrganismError> {
        Err(OrganismError::Msg("recompile mycelium-node com --features veil".into()))
    }

    #[cfg(not(feature = "veil"))]
    pub fn stop_veil_service(&mut self) {}

    async fn handle_control(&mut self, req: Request) -> Response {
        match req {
            Request::Status => Response::Status(Box::new(self.status_report())),
            Request::S1LiveSend { target, payload, expires_at_ms } => {
                let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                if expires_at_ms <= now_ms || expires_at_ms.saturating_sub(now_ms) > 300_000 {
                    Response::Err { message: "s1 live TTL inválido/expirado".into() }
                } else if payload.as_bytes().len() > 65_536 {
                    Response::Err { message: "s1 live payload excede 64 KiB".into() }
                } else {
                    let peer = target.parse::<NodeId>().ok()
                        .and_then(|node| self.hyphae.resolve_peer(&node))
                        .or_else(|| target.parse::<libp2p::PeerId>().ok());
                    match peer {
                        None => Response::Err { message: "s1 live target sem binding PeerId".into() },
                        Some(peer) => {
                            let frame = serde_json::json!({
                                "expires_at_ms": expires_at_ms,
                                "payload": payload,
                            });
                            match serde_json::to_vec(&frame)
                                .map_err(|e| e.to_string())
                                .and_then(|bytes| self.hyphae.send_s1_live(peer, bytes).map_err(|e| e.to_string()))
                            {
                                Ok(true) => Response::Ok { message: "s1 live entregue ao mesh".into() },
                                Ok(false) => Response::Err { message: "s1 live peer não está vivo/inscrito".into() },
                                Err(message) => Response::Err { message },
                            }
                        }
                    }
                }
            }
            Request::S1LivePoll { limit } => {
                if !(1..=64).contains(&limit) {
                    Response::Err { message: "s1 live poll limit inválido".into() }
                } else {
                    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                    self.s1_live_inbox.retain(|(expires, _)| *expires > now_ms);
                    let mut messages = Vec::new();
                    for _ in 0..limit {
                        match self.s1_live_inbox.pop_front() {
                            Some((_, payload)) => messages.push(payload),
                            None => break,
                        }
                    }
                    Response::S1LiveMessages { messages }
                }
            }
            Request::S1LiveBindings => {
                let mut bindings = self.hyphae.s1_live_bindings();
                bindings.sort();
                Response::S1LiveBindingsResult {
                    bindings: bindings
                        .into_iter()
                        .map(|(node, peer)| format!("{node}:{peer}"))
                        .collect(),
                }
            }
            Request::Sow {
                message,
                path,
                content,
                qel,
                nostr,
                ghost,
                recipient,
            } => match self.sow(message, path, content) {
                Ok(id) => {
                    let _ = (qel, nostr, ghost, recipient);
                    Response::Ok {
                        message: format!("plot semeado: {id}"),
                    }
                }
                Err(e) => Response::Err {
                    message: e.to_string(),
                },
            },
            Request::ImportSpore {
                spore_print_base64,
                expected_plot,
            } => {
                use base64::Engine;
                let expected = expected_plot.parse::<ContentId>();
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(spore_print_base64);
                match (expected, bytes) {
                    (Ok(expected), Ok(bytes)) => match self.bank.absorb(&bytes) {
                        Ok(actual) if actual == expected => Response::Ok {
                            message: format!("plot importado: {actual}"),
                        },
                        Ok(actual) => Response::Err {
                            message: format!("CID importado {actual} difere do esperado {expected}"),
                        },
                        Err(e) => Response::Err { message: e.to_string() },
                    },
                    (Err(e), _) => Response::Err { message: e },
                    (_, Err(e)) => Response::Err { message: e.to_string() },
                }
            }
            Request::Signal {
                plot,
                quorum,
                ion,
                name,
            } => match plot.parse::<ContentId>() {
                Ok(plot_id) => match self.emit_signal(plot_id, quorum, ion, name) {
                    Ok(id) => Response::Ok {
                        message: format!("signal emitido: {id}"),
                    },
                    Err(e) => Response::Err {
                        message: e.to_string(),
                    },
                },
                Err(e) => Response::Err { message: e },
            },
            Request::Resonate { signal } => match signal.parse::<ContentId>() {
                Ok(id) => match self.resonate(id) {
                    Ok(state) => Response::Ok {
                        message: format!("ressonância ok: {state:?}"),
                    },
                    Err(e) => Response::Err {
                        message: e.to_string(),
                    },
                },
                Err(e) => Response::Err { message: e },
            },
            Request::Recall {
                plot,
                qel,
                nostr,
                qel_threshold,
            } => match plot.parse::<ContentId>() {
                Ok(id) => match self.bank.recall(&id) {
                    Some(p) => Response::Ok {
                        message: format!(
                            "plot {} — \"{}\" ({} leaves)",
                            id.short(),
                            p.message,
                            p.leaves.len()
                        ),
                    },
                    None => {
                        let _ = (qel, nostr, qel_threshold);
                        self.hyphae.dht_get(dht_key(&id));
                        Response::Ok {
                            message: format!(
                                "plot {} ausente localmente; consulta DHT disparada (usa CLI --qel --nostr para mailbox)",
                                id.short()
                            ),
                        }
                    }
                },
                Err(e) => Response::Err { message: e },
            },
            Request::Bootstrap { addr } => match addr.parse() {
                Ok(multiaddr) => match self.hyphae.reach(multiaddr) {
                    Ok(()) => {
                        if !self.state.bootstrap.contains(&addr) {
                            self.state.bootstrap.push(addr.clone());
                            let _ = self.persist();
                        }
                        Response::Ok {
                            message: format!("dialando {addr}"),
                        }
                    }
                    Err(e) => Response::Err {
                        message: e.to_string(),
                    },
                },
                Err(e) => Response::Err {
                    message: format!("multiaddr inválido: {e}"),
                },
            },
            Request::IsotopePut { key, value, clock } => match self.isotope_put(key, value, clock)
            {
                Ok((c, owned)) => Response::Ok {
                    message: format!("atom escrito (clock={c}, owned={owned})"),
                },
                Err(e) => Response::Err {
                    message: e.to_string(),
                },
            },
            Request::IsotopeGet { key } => match self.isotope_get(&key) {
                Ok(Some(atom)) => {
                    let val = String::from_utf8_lossy(&atom.value);
                    Response::Ok {
                        message: format!("atom {key}={val} (clock={})", atom.clock),
                    }
                }
                Ok(None) => Response::Err {
                    message: format!("decay em curso para `{key}` — tente de novo"),
                },
                Err(e) => Response::Err {
                    message: e.to_string(),
                },
            },
            Request::EntropyShatter {
                secret,
                threshold,
                total,
            } => {
                match entropy::Vault::shatter(secret.as_bytes(), threshold, total) {
                    Ok(shades) => {
                        let n = shades.len();
                        self.vault = entropy::Vault::new();
                        let node_id = self.gland.node_id();
                        for (i, s) in shades.into_iter().enumerate() {
                            let custodian = if i == 0 {
                                node_id
                            } else {
                                // Distribui para peers via gossip
                                let env = Envelope::ShadeOffer {
                                    shade: s.clone(),
                                    custodian: node_id,
                                    from: node_id,
                                };
                                if let Ok(bytes) = env.encode() {
                                    let _ = self.hyphae.broadcast_lattice(bytes);
                                }
                                // Hold local da primeira shade
                                node_id
                            };
                            self.vault.hold(custodian, s);
                        }
                        self.persist().ok();
                        Response::Ok {
                            message: format!("entropy: {n} shades geradas e distribuídas ({threshold}+{total})"),
                        }
                    }
                    Err(e) => Response::Err {
                        message: format!("entropy shatter: {e}"),
                    },
                }
            }
            Request::EntropyReconstruct { threshold } => {
                // Tenta coleta remota primeiro
                let env = Envelope::ShadeRequest {
                    requester: self.gland.node_id(),
                    threshold,
                };
                if let Ok(bytes) = env.encode() {
                    let _ = self.hyphae.broadcast_lattice(bytes);
                }
                // Espera por respostas ShadeOffer via gossip
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                while std::time::Instant::now() < deadline {
                    let gathered = self.vault.gather();
                    if gathered.len() >= threshold as usize {
                        break;
                    }
                    std::thread::yield_now();
                }
                let gathered = self.vault.gather();
                if gathered.len() < threshold as usize {
                    return Response::Err {
                        message: format!(
                            "entropy: só {} shades em custódia (precisa de {})",
                            gathered.len(),
                            threshold
                        ),
                    };
                }
                match entropy::ChaosKey::materialize(&gathered, threshold) {
                    Ok(key) => {
                        let hex = hex::encode(key.reveal().unwrap_or(&[]));
                        Response::Ok {
                            message: format!("entropy: segredo reconstruído: {hex}"),
                        }
                    }
                    Err(e) => Response::Err {
                        message: format!("entropy reconstruct: {e}"),
                    },
                }
            }
            Request::EntropyStatus => {
                let count = self.vault.len();
                let shades_hex: Vec<String> = self
                    .vault
                    .gather()
                    .iter()
                    .map(|s| format!("shade[{}]: {} bytes", s.index, s.shares.len()))
                    .collect();
                Response::Ok {
                    message: format!(
                        "entropy: {} shades em custódia\n{}",
                        count,
                        shades_hex.join("\n")
                    ),
                }
            }
            Request::Balance => {
                let mut msg = format!(
                    "ATP={} Enzymes={} Mycelia={} Spores={} Resilience={} (local)\n",
                    self.ledger.balance(Nutrient::Atp),
                    self.ledger.balance(Nutrient::Enzymes),
                    self.ledger.balance(Nutrient::Mycelia),
                    self.ledger.balance(Nutrient::Spores),
                    self.ledger.balance(Nutrient::Resilience),
                );
                for (peer, (bals, clock)) in &self.remote_ledger {
                    msg.push_str(&format!(
                        "peer {}... (clock {clock}): ATP={} Enzymes={} Mycelia={} Spores={} Resilience={}\n",
                        peer.short(),
                        bals.get(&Nutrient::Atp).copied().unwrap_or(0),
                        bals.get(&Nutrient::Enzymes).copied().unwrap_or(0),
                        bals.get(&Nutrient::Mycelia).copied().unwrap_or(0),
                        bals.get(&Nutrient::Spores).copied().unwrap_or(0),
                        bals.get(&Nutrient::Resilience).copied().unwrap_or(0),
                    ));
                }
                Response::Ok { message: msg.trim().to_string() }
            }
            Request::IonMigrate { ion, target } => {
                let acceptor = match target.parse::<NodeId>() {
                    Ok(n) => n,
                    Err(e) => return Response::Err {
                        message: format!("target NodeId inválido: {e}"),
                    },
                };
                match self.initiate_ion_migration(&ion, acceptor) {
                    Ok(()) => {
                        self.ion_hosts.insert(ion.clone(), target);
                        Response::Ok { message: format!("oferta de migração do ion `{ion}` iniciada (IonOffer unicast) para {}", acceptor.short()) }
                    }
                    Err(message) => Response::Err { message },
                }
            }
            Request::Zones => {
                let mut msg = String::new();
                for (prefix, custodians) in &self.known_zones {
                    msg.push_str(&format!("zone {}: {} custodians\n", prefix, custodians.len()));
                    for c in custodians {
                        msg.push_str(&format!("  {}\n", c.short()));
                    }
                }
                if msg.is_empty() {
                    msg = "nenhuma zona conhecida".into();
                }
                Response::Ok { message: msg.trim().to_string() }
            }
            Request::StoreList => {
                // Leitura pura, sem E/S nem bloqueio: o `Vec` de espores é clonado
                // do catálogo e o guarda morre ao fim do braço do `match`. Espelha
                // `list_spores_handler` em `crates/mycelium-store/src/lib.rs` —
                // revalidação pelo `catalog_locked` daqui incluída, senão este
                // site responderia com um índice que a ponte HTTP já recusa.
                let spores: Vec<_> = match self.catalog_locked() {
                    Ok(catalog) => catalog
                        .list_public_spores()
                        .into_iter()
                        .cloned()
                        .collect(),
                    Err(e) => {
                        return Response::Err {
                            message: format!("catálogo recusado (StoreList): {e}"),
                        }
                    }
                };
                Response::StoreList { spores }
            }
            Request::StoreCaps => {
                let caps = mycelium_store::EmulatorRunner::detect_capabilities();
                Response::StoreCaps { caps }
            }
            Request::StoreLaunch { id, engine, sandbox } => {
                // O guarda do catálogo NÃO pode atravessar `EmulatorRunner::launch`
                // (fork/exec, possivelmente via `bwrap`): segurar o mutex durante o
                // spawn bloqueia todo leitor do mesmo `Arc` — inclusive os handlers
                // HTTP da store — e o spawn é fonte de poison. Clona o spore sob o
                // guarda e descarta-o antes de qualquer trabalho bloqueante; mesmo
                // padrão de `launch_spore_handler` em `crates/mycelium-store/src/lib.rs`.
                // FAIL-CLOSED, igual ao bridge: o registro aqui DECIDE caminho de
                // executável e flags de emulador, ou seja, o que este host passa a
                // executar — o mesmo `Arc` recusado pelo HTTP não pode sair daqui
                // como um registro recuperado. Ver `catalog_locked`.
                let spore = {
                    let catalog = match self.catalog_locked() {
                        Ok(catalog) => catalog,
                        Err(e) => {
                            tracing::error!(
                                "[Mycelium Organism] StoreLaunch: catálogo recusado (campo `catalog`): {e}"
                            );
                            return Response::Err {
                                message: format!("catálogo recusado (StoreLaunch): {e}"),
                            };
                        }
                    };
                    match catalog.get_spore(&id) {
                        Some(s) => s.clone(),
                        None => {
                            return Response::Err {
                                message: format!("spore '{}' não encontrado no catálogo", id),
                            }
                        }
                    }
                };
                let caps = mycelium_store::EmulatorRunner::detect_capabilities();
                let forced = engine.as_deref().map(|e| {
                    use mycelium_store::ExecutionEngineType;
                    match e {
                        "native" => ExecutionEngineType::Native,
                        "retroarch" => ExecutionEngineType::RetroArchLibretro,
                        "mame" => ExecutionEngineType::MAME,
                        "qemu" => ExecutionEngineType::QEMU,
                        "wasm" => ExecutionEngineType::WebAssembly,
                        "cloud" => ExecutionEngineType::P2PCloudStream,
                        _ => ExecutionEngineType::Native,
                    }
                });
                let resolved = mycelium_store::EmulatorRunner::resolve_best_engine(&spore, &caps, forced);
                let game_path = self.store.root.join("store").join(&spore.main_binary_file);
                match mycelium_store::EmulatorRunner::launch(&spore, &game_path, resolved.clone(), sandbox) {
                    Ok(_child) => Response::StoreLaunched {
                        spore_id: spore.id,
                        engine: format!("{:?}", resolved),
                        message: format!("{} lançado via {:?}", spore.title, resolved),
                    },
                    Err(e) => Response::Err {
                        message: format!("falha ao lançar: {}", e),
                    },
                }
            }
            Request::StorePublish { id, title, platform } => {
                // O guarda do catálogo é adquirido só na inserção: o parsing da
                // plataforma e a montagem do `SoftwareSpore` não tocam o estado
                // compartilhado e acontecem antes do lock. `insert_spore(&mut self)`
                // grava `catalog.json` por dentro, então manter a exclusão ali é
                // obrigatório — `&mut` não pode ser dividido — e a janela fica
                // limitada a essa única escrita, que `crates/mycelium-store` passou a
                // fazer de forma atômica (temp + rename). A resposta é montada com o
                // guarda já descartado. Ver `catalog_locked`: a revalidação
                // acontece ANTES da inserção, porque um `insert_spore` escreve
                // `catalog.json` por inteiro — por cima de um índice já partido
                // apagaria a divergência, e com ela a prova dela.
                let plat = platform.to_lowercase();
                let platform = match plat.as_str() {
                    "snes" => mycelium_store::TargetPlatform::SNES,
                    "nes" => mycelium_store::TargetPlatform::NES,
                    "megadrive" | "genesis" => mycelium_store::TargetPlatform::MegaDrive,
                    "msdos" | "dos" => mycelium_store::TargetPlatform::MSDOS,
                    "win98" | "win95" => mycelium_store::TargetPlatform::Windows98,
                    "arcade" | "mame" => mycelium_store::TargetPlatform::ArcadeMame,
                    "mac" | "ppc" => mycelium_store::TargetPlatform::PowerPCMac,
                    _ => mycelium_store::TargetPlatform::NativeSystem,
                };
                let spore = mycelium_store::SoftwareSpore {
                    id: id.clone(),
                    title,
                    description: "Publicado via daemon Mycelium Store".into(),
                    developer_or_publisher: "Comunidade Mycelium".into(),
                    release_year: 2000,
                    platform,
                    category: "software".into(),
                    tags: vec!["p2p".into(), "spore".into()],
                    license: mycelium_store::SporeLicense::Proprietary,
                    main_binary_file: format!("{}.bin", id),
                    content_id: mycelium_core::ContentId::of(id.as_bytes()),
                    execution_matrix: mycelium_store::ExecutionMatrix {
                        recommended: mycelium_store::ExecutionEngineType::Native,
                        supports_native: true,
                        libretro_core: None,
                        mame_driver: None,
                        qemu_config: None,
                        supports_wasm: true,
                        supports_p2p_stream: true,
                    },
                    requirements: mycelium_store::spore::HardwareRequirements::default(),
                    extra_args: vec![],
                    cover_image_url: None,
                };
                let outcome = {
                    let mut catalog = match self.catalog_locked() {
                        Ok(catalog) => catalog,
                        Err(e) => {
                            tracing::error!(
                                "[Mycelium Organism] StorePublish: catálogo recusado (campo `catalog`): {e}"
                            );
                            return Response::Err {
                                message: format!("catálogo recusado (StorePublish): {e}"),
                            };
                        }
                    };
                    catalog.insert_spore(spore)
                };
                outcome.map(|_| {
                    Response::Ok {
                        message: format!("spore '{}' registrado no catálogo", id),
                    }
                }).unwrap_or_else(|e| Response::Err {
                    message: format!("erro ao salvar catálogo: {}", e),
                })
            }
            Request::RepoPublish { repository, branch, expected_previous_cid, message, leaves } => {
                let n = leaves.len();
                let bytes: usize = leaves.iter().map(|l| l.content.len()).sum();
                let expected_previous = match expected_previous_cid {
                    Some(value) => match value.parse::<ContentId>() {
                        Ok(id) => Some(id),
                        Err(e) => return Response::Err { message: e },
                    },
                    None => None,
                };
                match self.publish_repo_ref_expected(
                    repository.as_deref().unwrap_or("default"),
                    branch.as_deref().unwrap_or("main"),
                    expected_previous,
                    message,
                    leaves,
                ) {
                    Ok(id) => Response::RepoPublished {
                        cid: id.to_string(),
                        leaves: n,
                        bytes,
                    },
                    Err(e) => Response::Err {
                        message: e.to_string(),
                    },
                }
            }
            Request::RepoClone { cid } => match cid.parse::<ContentId>() {
                Ok(id) => match self.bank.recall(&id) {
                    Some(p) => Response::RepoCloneResult {
                        message: format!(
                            "repo {} — \"{}\" ({} leaves)",
                            id.short(),
                            p.message,
                            p.leaves.len()
                        ),
                        leaves: p.leaves.clone(),
                    },
                    None => {
                        self.hyphae.dht_get(dht_key(&id));
                        Response::Err {
                            message: format!(
                                "repo {} ausente localmente; consulta DHT disparada — tente de novo em alguns segundos",
                                id.short()
                            ),
                        }
                    }
                },
                Err(e) => Response::Err { message: e },
            },
            Request::InertiaRun { cid } => match cid.parse::<ContentId>() {
                Ok(input) => match self.run_inertia_validation(input) {
                    Ok((build, test, artifact, success)) => Response::InertiaRunResult {
                        input_cid: input.to_string(),
                        build_attestation_cid: build.to_string(),
                        test_attestation_cid: test.map(|id| id.to_string()),
                        artifact_cid: artifact.map(|id| id.to_string()),
                        success,
                    },
                    Err(e) => Response::Err {
                        message: e.to_string(),
                    },
                },
                Err(e) => Response::Err { message: e },
            },
            Request::InertiaAttestation { cid } => match cid.parse::<ContentId>() {
                Ok(id) => match AttestationStore::open(self.home.join("attestations"))
                    .and_then(|store| store.get(&id))
                {
                    Ok(attestation) => Response::InertiaAttestationResult {
                        cid: id.to_string(),
                        attestation,
                    },
                    Err(e) => Response::Err {
                        message: e.to_string(),
                    },
                },
                Err(e) => Response::Err { message: e },
            },
            Request::Transfer {
                to,
                amount,
                nutrient,
                kind,
                memo,
                asset,
            } => {
                let nut = nutrient
                    .parse::<mycelium_core::Nutrient>()
                    .map_err(|_| format!("nutriente inválido: {}", nutrient));
                let kind = kind
                    .parse::<mycelium_nutrients::TxKind>()
                    .map_err(|_| format!("kind inválido: {}", kind));
                match (nut, kind) {
                    (Ok(n), Ok(k)) => match self.transfer(&to, amount, n, k, memo, asset) {
                        Ok(tx) => Response::TransferResult {
                            tx_id: tx.short(),
                            kind: k.as_str().to_string(),
                            nutrient: n.to_string(),
                            amount,
                            to,
                        },
                        Err(e) => Response::Err { message: e },
                    },
                    (Err(e), _) | (_, Err(e)) => Response::Err { message: e },
                }
            }
            Request::LedgerInfo => Response::LedgerReport {
                pubkey: self.wallet_pubkey_hex(),
                balances: self.ledger.balances.clone(),
                history: self.ledger.history.clone(),
                transfers: self.ledger.recent_transfers().to_vec(),
            },
            Request::AssetRegister {
                id,
                name,
                kind,
                description,
                location,
                shares_total,
                price_per_share,
            } => {
                let kind = kind
                    .parse::<crate::assets::AssetKind>()
                    .map_err(|_| format!("kind inválido: {}", kind));
                match kind {
                    Ok(k) => {
                        let record = crate::assets::AssetRecord {
                            id: id.clone(),
                            name,
                            kind: k,
                            description,
                            location,
                            shares_total,
                            price_per_share,
                            owner: self.wallet_pubkey(),
                        };
                        match self.assets.register(record) {
                            Ok(()) => {
                                self.assets.save(&self.home).ok();
                                Response::Ok {
                                    message: format!("ativo '{}' registado", id),
                                }
                            }
                            Err(e) => Response::Err { message: e },
                        }
                    }
                    Err(e) => Response::Err { message: e },
                }
            }
            Request::AssetList => Response::AssetListResult {
                assets: self.assets.assets.clone(),
            },
            Request::AssetShares { id } => Response::AssetSharesResult {
                asset: id.clone(),
                holdings: self.assets.holdings_of(&id),
            },
            Request::AssetTransfer { asset, shares, to } => {
                let to = hex::decode(&to)
                    .map_err(|e| format!("pubkey destino inválida: {e}"))
                    .and_then(|v| v.try_into().map_err(|_| "pubkey precisa 32 bytes".to_string()));
                match to {
                    Ok(to_pubkey) => match self.assets.transfer_shares(&asset, &self.wallet_pubkey(), &to_pubkey, shares) {
                        Ok(()) => {
                            self.assets.save(&self.home).ok();
                            Response::Ok {
                                message: format!("{} cotas transferidas", shares),
                            }
                        }
                        Err(e) => Response::Err { message: e },
                    },
                    Err(e) => Response::Err { message: e },
                }
            }
            Request::CompanyRegister { name, shares_total } => {
                let name_for_record = name.clone();
                let record = crate::assets::AssetRecord {
                    id: name.clone(),
                    name: name_for_record,
                    kind: crate::assets::AssetKind::Company,
                    description: "Empresa/cooperativa (Fase 4)".into(),
                    location: None,
                    shares_total,
                    price_per_share: 1,
                    owner: self.wallet_pubkey(),
                };
                match self.assets.register(record) {
                    Ok(()) => {
                        self.assets.save(&self.home).ok();
                        Response::Ok {
                            message: format!("empresa '{}' registada", name),
                        }
                    }
                    Err(e) => Response::Err { message: e },
                }
            }
            Request::CompanyPayout { name, total } => {
                let holdings = self.assets.holdings_of(&name);
                let total_shares: u64 = holdings.iter().map(|h| h.shares).sum();
                if total_shares == 0 {
                    return Response::Err {
                        message: "nenhuma cota emitida".into(),
                    };
                }
                let per_share = total / total_shares;
                let mut paid = 0;
                for h in holdings {
                    let share = h.shares * per_share;
                    self.ledger.feed_kind(
                        mycelium_core::Nutrient::Atp,
                        share,
                        format!("dividendo empresa {}", name),
                        Some(mycelium_nutrients::TxKind::Revenue),
                    );
                    paid += share;
                }
                Response::Ok {
                    message: format!("distribuído {} ATP como dividendo", paid),
                }
            }
            Request::SeedRepo { name, url, commit, description } => {
                let env = Envelope::RepoAnnounce {
                    node_id: self.gland.node_id(),
                    name: name.clone(),
                    url: url.clone(),
                    commit: commit.clone(),
                    description: description.clone(),
                };
                if let Ok(bytes) = env.encode() {
                    let _ = self.hyphae.broadcast_lattice(bytes);
                }
                // Armazena localmente também.
                self.known_repos.insert(
                    name.clone(),
                    (url, commit, description, self.gland.node_id()),
                );
                tracing::info!(repo = %name, "repo anunciado via gossip");
                Response::Ok { message: format!("repo '{name}' anunciado na rede") }
            }
            Request::Repos => {
                let mut msg = String::new();
                for (name, (url, commit, desc, from)) in &self.known_repos {
                    msg.push_str(&format!("📦 {name}\n   url: {url}\n   commit: {commit}\n   desc: {desc}\n   from: {from}\n\n"));
                }
                if msg.is_empty() {
                    msg = "nenhum repositório anunciado ainda".into();
                }
                Response::Ok { message: msg.trim().to_string() }
            }
            Request::SeedCode { name, description, ion, visibility, files } => {
                use giggs::Plot;
                use base64::Engine;
                // Valida visibilidade.
                let vis = match visibility.as_str() {
                    "public" | "private" | "reserved" | "archived" | "community" => visibility.clone(),
                    _ => "public".to_string(),
                };
                let leaves: Vec<giggs::Leaf> = files.into_iter().map(|(path, b64)| {
                    let content = base64::engine::general_purpose::STANDARD.decode(&b64).unwrap_or_default();
                    giggs::Leaf { path, content }
                }).collect();
                let file_count = leaves.len();
                let total_bytes: usize = leaves.iter().map(|l| l.content.len()).sum();
                // Mensagem codifica visibilidade para que recall respeite.
                let plot = Plot {
                    author: self.gland.node_id(),
                    message: format!("[{vis}] {name}: {description}"),
                    parents: vec![],
                    leaves,
                };
                match self.bank.deposit(plot) {
                    Ok(plot_id) => {
                        // Sem criptografia/capabilities, somente público é
                        // distribuído. Outras visibilidades ficam locais.
                        if vis == "public" {
                            let _ = self.fruit_ion(&ion, &plot_id.to_string(), "", true);
                            if let Some(bytes) = self.bank.public_spore_print(&plot_id) {
                                let _ = self.hyphae.dht_store_local(dht_key(&plot_id), bytes.clone());
                                let _ = self.hyphae.dht_put(dht_key(&plot_id), bytes);
                            }
                            if let Some(p) = self.bank.recall(&plot_id) {
                                let env = Envelope::SporePrint { plot: p.clone() };
                                if let Ok(bytes) = env.encode() {
                                    let _ = self.hyphae.broadcast_lattice(bytes);
                                }
                            }
                            let env = Envelope::RepoAnnounce {
                                node_id: self.gland.node_id(),
                                name: name.clone(),
                                url: format!("mycelium://plot/{plot_id}"),
                                commit: plot_id.to_string()[2..18].to_string(),
                                description: format!("[{vis}] {description}"),
                            };
                            if let Ok(bytes) = env.encode() {
                                let _ = self.hyphae.broadcast_lattice(bytes);
                            }
                        }
                        self.known_repos.insert(
                            name.clone(),
                            (format!("mycelium://plot/{plot_id}"), plot_id.to_string()[2..18].to_string(), description, self.gland.node_id()),
                        );
                        let vis_icon = match vis.as_str() {
                            "public" => "🌐",
                            "private" => "🔒",
                            "reserved" => "🔐",
                            "archived" => "📦",
                            "community" => "👥",
                            _ => "📄",
                        };
                        tracing::info!(repo = %name, %plot_id, files = file_count, bytes = total_bytes, visibility = %vis, "código depositado no Spore Bank");
                        let access_hint = if vis == "public" {
                            format!("Baixar em outro nó:\n  mycelium recall-code --plot {plot_id}")
                        } else {
                            "Restrito: armazenado apenas neste nó; publicação em claro desabilitada".to_string()
                        };
                        let msg = format!("{} '{}' [{}] semeado: plot={}, {} arquivos, {} bytes\n\n{}",
                            vis_icon, name, vis, plot_id, file_count, total_bytes, access_hint);
                        Response::Ok { message: msg }
                    }
                    Err(e) => Response::Err { message: format!("falha ao semear: {e}") },
                }
            }
            Request::RecallCode { plot, output_dir } => {
                use std::io::Write;
                match plot.parse::<mycelium_core::ContentId>() {
                    Ok(plot_id) => {
                        match self.bank.recall(&plot_id) {
                            Some(plot) => {
                                // Extrai visibilidade da mensagem: "[public] nome: desc"
                                let vis = if plot.message.starts_with('[') {
                                    plot.message.split(']').next().unwrap_or("[public]").trim_start_matches('[').to_string()
                                } else {
                                    "public".to_string()
                                };
                                // Visibilidades restritas: apenas restauração local do autor.
                                if !recall_allowed(&vis, &plot.author, &self.gland.node_id()) {
                                    return Response::Err { message: "🔒 acesso negado — plot restrito (apenas autor local)".into() };
                                }
                                let out_dir = match &output_dir {
                                    Some(p) => std::path::PathBuf::from(p),
                                    None => std::path::PathBuf::from(
                                        plot.message.split(']').last().unwrap_or("code").trim().split(':').next().unwrap_or("code").trim()
                                    ),
                                };
                                std::fs::create_dir_all(&out_dir).ok();
                                let canon_out = match out_dir.canonicalize() {
                                    Ok(c) => c,
                                    Err(_) => out_dir.clone(),
                                };
                                let mut written = 0usize;
                                let vis_icon = match vis.as_str() {
                                    "public" => "🌐",
                                    "private" => "🔒",
                                    "reserved" => "🔐",
                                    "archived" => "📦",
                                    "community" => "👥",
                                    _ => "📄",
                                };
                                for leaf in &plot.leaves {
                                    let safe_rel = match inertia::safe_relative_path(&leaf.path) {
                                        Ok(p) => p,
                                        Err(_) => continue,
                                    };
                                    let file_path = canon_out.join(&safe_rel);
                                    if let Some(parent) = file_path.parent() {
                                        std::fs::create_dir_all(parent).ok();
                                        if let Ok(canon_parent) = parent.canonicalize() {
                                            if !canon_parent.starts_with(&canon_out) {
                                                continue;
                                            }
                                        }
                                    }
                                    if file_path.is_symlink() {
                                        let _ = std::fs::remove_file(&file_path);
                                    }
                                    if let Ok(mut f) = std::fs::File::create(&file_path) {
                                        let _ = f.write_all(&leaf.content);
                                        written += 1;
                                    }
                                }
                                Response::Ok { message: format!("{vis_icon} {written} arquivos extraídos em {}/ [{vis}]", out_dir.display()) }
                            }
                            None => Response::Err { message: format!("plot {plot_id} não encontrado no Spore Bank local") },
                        }
                    }
                    Err(e) => Response::Err { message: format!("ContentId inválido: {e}") },
                }
            }
            Request::MaterializeService { ion, plot } => {
                let plot_id = if let Some(p) = plot {
                    match p.parse::<mycelium_core::ContentId>() {
                        Ok(cid) => cid,
                        Err(e) => return Response::Err { message: format!("ContentId inválido: {e}") },
                    }
                } else {
                    let found = self.bank.ids().into_iter().find(|id| {
                        self.bank.recall(id).map(|p| {
                            p.message.to_lowercase().contains(&format!("service:{}", ion.to_lowercase()))
                                || p.message.to_lowercase().contains(&format!("ion:{}", ion.to_lowercase()))
                                || p.message.to_lowercase().contains(&ion.to_lowercase().replace('-', " "))
                                || p.message.to_lowercase().contains(&ion.to_lowercase())
                        }).unwrap_or(false)
                    });
                    match found {
                        Some(id) => *id,
                        None => return Response::Err { message: format!("nenhum plot encontrado para ion `{ion}`") },
                    }
                };
                match self.birth_ion(&ion, &plot_id.to_string(), "default") {
                    Ok(()) => Response::Ok {
                        message: format!("serviço `{ion}` materializado com sucesso em Chamber viva"),
                    },
                    Err(e) => Response::Err {
                        message: format!("falha ao materializar serviço `{ion}`: {e}"),
                    },
                }
            }
            #[cfg(feature = "license")]
            Request::VerifyLicense {
                vendor_public_key, device_entropy, sku,
                license_payload, signature, unix_now_secs, peer_id,
            } => {
                let vk = match hex::decode(&vendor_public_key) {
                    Ok(b) => b,
                    Err(_) => return Response::Err { message: "vendor_public_key hex inválido".into() },
                };
                let de = match hex::decode(&device_entropy) {
                    Ok(b) => b,
                    Err(_) => return Response::Err { message: "device_entropy hex inválido".into() },
                };
                let lp = match hex::decode(&license_payload) {
                    Ok(b) => b,
                    Err(_) => return Response::Err { message: "license_payload hex inválido".into() },
                };
                let sig = match hex::decode(&signature) {
                    Ok(b) => b,
                    Err(_) => return Response::Err { message: "signature hex inválido".into() },
                };
                let result = mycelium_zkp::license::license_verify_handshake(
                    &vk, &de, &sku, &lp, &sig, unix_now_secs,
                );
                let status = if result.ok { "ok" } else { "falha" };
                tracing::info!(
                    device_id = %result.device_id_hex,
                    reason = %result.reason,
                    status,
                    "license handshake verificado"
                );
                // **Auto-release**: licença válida + peer_id → inscreve o nó na
                // allowlist de admissão licenciada (gate passa a aceitá-lo).
                let mut released = None;
                if result.ok {
                    if let Some(pid) = &peer_id {
                        if let Ok(peer) = pid.parse::<libp2p::PeerId>() {
                            let gate_active = self.hyphae.admit_licensed_peer(peer);
                            released = Some((pid.clone(), gate_active));
                            if self.persist().is_err() {
                                tracing::warn!("persist após auto-release falhou");
                            }
                        }
                    }
                }
                let mut msg = format!(
                    "{} device_id={}: {}",
                    if result.ok { "✓" } else { "✗" },
                    result.device_id_hex,
                    result.reason
                );
                if let Some((pid, gate_active)) = released {
                    msg.push_str(&format!(
                        " · auto-release {} peer {} (gate {})",
                        if result.ok { "OK" } else { "recusado" },
                        pid,
                        if gate_active { "ativo" } else { "inativo" }
                    ));
                }
                Response::Ok { message: msg }
            }
            #[cfg(feature = "license")]
            Request::RegisterLicensedPeer { peer_id } => {
                match peer_id.parse::<libp2p::PeerId>() {
                    Ok(peer) => {
                        let gate_active = self.hyphae.admit_licensed_peer(peer);
                        let _ = self.persist();
                        Response::Ok {
                            message: format!(
                                "✓ peer {} autorizado (gate {})",
                                peer,
                                if gate_active { "ativo" } else { "inativo" }
                            ),
                        }
                    }
                    Err(e) => Response::Err { message: format!("PeerId inválido: {e}") },
                }
            }
            #[cfg(feature = "bolt11")]
            Request::Bolt11Validate { bolt11 } => {
                if !mycelium_zkp::bolt11::validate_bolt11(&bolt11) {
                    return Response::Err { message: "⚠️ invoice BOLT11 inválido".into() };
                }
                match mycelium_zkp::bolt11::parse_bolt11(&bolt11) {
                    Ok(s) => {
                        tracing::info!(
                            amount_sat = s.amount_sat,
                            network = %s.network,
                            payment_hash = %s.payment_hash,
                            "invoice BOLT11 validado"
                        );
                        Response::Ok {
                            message: format!(
                                "✓ invoice BOLT11 válido · {} sats · rede {} · expira em {}s\n   desc: {}\n   pay_hash: {}",
                                s.amount_sat, s.network, s.expiry, s.description, s.payment_hash
                            ),
                        }
                    }
                    Err(e) => Response::Err { message: format!("invoice BOLT11 parse: {e}") },
                }
            }
            Request::VeilStart { mode, socks5_port, role, listen, trust, advertise, identity, rotate_identity, egress_bind, bridges, bridge_listen, bridge_target } => {
                #[cfg(feature = "veil")]
                {
                    if let Some(port) = socks5_port {
                        self.veil_socks5_addr = Some(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
                    }
                    if let Some(m) = mode {
                        self.veil_mode = Some(m);
                    }
                    if let Some(r) = role {
                        self.veil_role = Some(r);
                    }
                    if let Some(l) = listen {
                        if let Ok(addr) = l.parse() {
                            self.veil_listen = Some(addr);
                        }
                    }
                    if !trust.is_empty() {
                        self.veil_trust = trust;
                    }
                    if let Some(a) = advertise {
                        self.veil_advertise = Some(a);
                    }
                    if let Some(i) = identity {
                        self.veil_identity_path = Some(std::path::PathBuf::from(i));
                    }
                    if rotate_identity {
                        self.veil_rotate_identity = true;
                    }
                    if let Some(eb) = egress_bind {
                        match eb.parse::<std::net::IpAddr>() {
                            Ok(ip) => self.veil_egress_bind = Some(ip),
                            Err(_) => {
                                return Response::Err { message: format!("--egress-bind inválido: {eb}") }
                            }
                        }
                    }
                    // Bridge configuration (role == "bridge")
                    if !bridges.is_empty() {
                        self.veil_bridges = bridges;
                    }
                    if let Some(bl) = bridge_listen {
                        self.veil_bridge_listen = Some(bl);
                    }
                    if let Some(bt) = bridge_target {
                        self.veil_bridge_target = Some(bt);
                    }
                    match self.start_veil_service().await {
                        Ok(bound) => Response::Ok {
                            message: format!("VEIL Ω iniciado: escutando em {bound}"),
                        },
                        Err(e) => Response::Err {
                            message: format!("falha ao iniciar VEIL Ω: {e}"),
                        },
                    }
                }
                #[cfg(not(feature = "veil"))]
                {
                    let _ = (mode, socks5_port, role, listen, trust, advertise, identity, rotate_identity, egress_bind, bridges, bridge_listen, bridge_target);
                    Response::Err {
                        message: "recompile mycelium-node com --features veil".into(),
                    }
                }
            }
            Request::VeilStop => {
                #[cfg(feature = "veil")]
                {
                    self.stop_veil_service();
                    Response::Ok {
                        message: "VEIL Ω finalizado".into(),
                    }
                }
                #[cfg(not(feature = "veil"))]
                {
                    Response::Err {
                        message: "recompile mycelium-node com --features veil".into(),
                    }
                }
            }
            Request::VeilDescriptor => {
                #[cfg(feature = "veil")]
                {
                    if let Some(desc) = &self.veil_local_descriptor {
                        Response::Ok { message: desc.clone() }
                    } else {
                        Response::Err {
                            message: "nenhum descritor ativo no momento (este nó não está ativo como relay/exit)".into(),
                        }
                    }
                }
                #[cfg(not(feature = "veil"))]
                {
                    Response::Err {
                        message: "recompile mycelium-node com --features veil".into(),
                    }
                }
            }
            Request::VeilStatus => {
                #[cfg(feature = "veil")]
                {
                    let active = self.veil_enabled;
                    let (mode, session_id, bytes_routed, mac_address, kill_switch, active_layers) =
                        if let Some(ref eng) = self.veil_engine {
                            let ks_state = match eng.kill_switch().state() {
                                mycelium_veil::KillSwitchState::Triggered => "triggered",
                                mycelium_veil::KillSwitchState::Armed => "armed",
                                mycelium_veil::KillSwitchState::Disarmed => "disarmed",
                            };
                            let sess = eng.current_session();
                            let sess_id = sess.as_ref().map(|s| s.session_id.clone());
                            let mac = sess.as_ref().map(|s| {
                                format!(
                                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                    s.mac_address[0], s.mac_address[1], s.mac_address[2],
                                    s.mac_address[3], s.mac_address[4], s.mac_address[5]
                                )
                            });
                            let bytes = sess.as_ref().map(|s| s.bytes_routed).unwrap_or(0);
                            // Honestidade operacional: `active_layers` reflete as camadas
                            // que REALMENTE atuam no caminho de dados, não as que existem
                            // implementadas. O `LayerPipeline` de 7 camadas não está ligado
                            // à produção (o tráfego real passa por `planes::live` + `bridge`),
                            // então o número honesto é 0 — não 7. Ver o aviso em
                            // `mycelium_veil::layers`.
                            let layers = eng.wired_layer_count();
                            let mode_str = match eng.config().mode {
                                mycelium_veil::VeilMode::Veil => "veil",
                                mycelium_veil::VeilMode::Geo => "geo",
                                mycelium_veil::VeilMode::Mix => "mix",
                            };
                            (
                                Some(mode_str.to_string()),
                                sess_id,
                                bytes,
                                mac,
                                ks_state.to_string(),
                                layers,
                            )
                        } else {
                            (
                                self.veil_mode.clone(),
                                None,
                                0,
                                None,
                                "uninitialized".to_string(),
                                0,
                            )
                        };

                    Response::VeilStatusResult {
                        active,
                        role: self.veil_role.clone(),
                        mode,
                        socks5_addr: self.veil_socks5_addr.map(|a| a.to_string()),
                        listen_addr: self.veil_listen.map(|a| a.to_string()),
                        descriptor: self.veil_local_descriptor.clone(),
                        session_id,
                        bytes_routed,
                        mac_address,
                        kill_switch,
                        active_layers,
                        entrada_ativa: self.veil_active_entry.clone(),
                        entradas: self.veil_registered_entries.clone(),
                        tentativas_failover: self.veil_failover_attempts,
                        motivos_falha: self.veil_failure_reasons.clone(),
                    }
                }
                #[cfg(not(feature = "veil"))]
                {
                    Response::Err {
                        message: "recompile mycelium-node com --features veil".into(),
                    }
                }
            }
            Request::Shutdown => Response::Ok {
                message: "encerrando".into(),
            },
        }
    }

    pub async fn run(mut self, mut control_rx: mpsc::Receiver<ControlMsg>) -> Result<(), OrganismError> {
        self.store.write_pid()?;

        let bind_str = std::env::var("MYCELIUM_HORIZON_BIND")
            .unwrap_or_else(|_| format!("127.0.0.1:{}", self.state.horizon_port));
        let bind: std::net::SocketAddr = bind_str
            .parse()
            .map_err(|e| OrganismError::Msg(format!("MYCELIUM_HORIZON_BIND inválido: {e}")))?;
        let handle = match serve_horizon(bind, self.horizon.clone()).await {
            Ok(h) => h,
            Err(e) if e.contains("Address already in use") || e.contains("os error 98") => {
                tracing::warn!(
                    port = self.state.horizon_port,
                    "Event Horizon ocupado — a usar porta efémera"
                );
                let fallback_str = if bind.ip().is_loopback() {
                    "127.0.0.1:0"
                } else {
                    "0.0.0.0:0"
                };
                let fallback: std::net::SocketAddr = fallback_str
                    .parse()
                    .map_err(|e| OrganismError::Msg(format!("{e}")))?;
                serve_horizon(fallback, self.horizon.clone())
                    .await
                    .map_err(OrganismError::Msg)?
            }
            Err(e) => return Err(OrganismError::Msg(e)),
        };
        self.state.horizon_port = handle.bind.port();
        tracing::info!(
            url = %format!("http://{}/", handle.bind),
            public = !handle.bind.ip().is_loopback(),
            "event horizon escutando — curl http://{}/<ion>/",
            handle.bind
        );
        self.horizon_handle = Some(handle);

        // Expõe a Mycelium Store UI + API como um ion no Event Horizon.
        let store_catalog = self.catalog.clone();
        let store_home = self.home.clone();
        let store_horizon = self.horizon.clone();
        tokio::spawn(async move {
            let store_token = std::env::var("MYCELIUM_CONTROL_TOKEN")
                .ok()
                .filter(|t| !t.trim().is_empty())
                .or_else(|| {
                    let p = store_home.join("control.token");
                    std::fs::read_to_string(p)
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                });
            let store_router = mycelium_store::create_store_router_with_auth(&store_home, store_catalog, store_token);
            let ui_router = mycelium_store::create_store_ui_router(&store_home);
            let app = store_router.merge(ui_router);
            let store_bind: std::net::SocketAddr = "127.0.0.1:0"
                .parse()
                .expect("bind valid");
            let listener = match tokio::net::TcpListener::bind(store_bind).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(error = %e, "falha ao escutar store server");
                    return;
                }
            };
            let local = listener.local_addr().expect("local addr");
            tracing::info!(
                url = %format!("http://127.0.0.1:{}/store/", local),
                "mycelium store server escutando"
            );
            {
                let mut table = store_horizon.write().unwrap();
                table.expose(
                    "store.mycelium",
                    Orbit {
                        ion: "store".into(),
                        node: NodeId::derive(b"store"),
                        mass: 100,
                        resistance: 0,
                        upstream: format!("http://{}", local),
                    },
                );
            }
            let _ = axum::serve(listener, app).await;
        });

        // S1 uses this node's operator-owned configuration and ledger.
        let s1_horizon = self.horizon.clone();
        let s1_home = self.home.clone();
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind("127.0.0.1:0").await {
                Ok(listener) => {
                    let local = listener.local_addr().expect("local addr");
                    s1_horizon.write().unwrap().expose("s1.mycelium", Orbit {
                        ion: "s1".into(), node: NodeId::derive(b"s1"), mass: 100,
                        resistance: 0, upstream: format!("http://{}", local),
                    });
                    let _ = axum::serve(listener, mycelium_s1::configured_router(s1_home)).await;
                }
                Err(error) => tracing::error!(%error, "S1 ion bind failed"),
            }
        });
        let src_home = self.home.clone();
        let src_horizon = self.horizon.clone();
        tokio::spawn(async move {
            let app = crate::src_ion::create_src_router(&src_home);
            let src_bind: std::net::SocketAddr = "127.0.0.1:0"
                .parse()
                .expect("bind valid");
            let listener = match tokio::net::TcpListener::bind(src_bind).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(error = %e, "falha ao escutar src server");
                    return;
                }
            };
            let local = listener.local_addr().expect("local addr");
            tracing::info!(
                url = %format!("http://127.0.0.1:{}/src/", local),
                "mycelium src ion escutando"
            );
            {
                let mut table = src_horizon.write().unwrap();
                table.expose(
                    "src.mycelium",
                    Orbit {
                        ion: "src".into(),
                        node: NodeId::derive(b"src"),
                        mass: 100,
                        resistance: 0,
                        upstream: format!("http://{}", local),
                    },
                );
            }
            let _ = axum::serve(listener, app).await;
        });

        // Expõe o catálogo de seeds públicas/privadas (ion `seeds`) no Event Horizon.
        let seeds_home = self.home.clone();
        let seeds_horizon = self.horizon.clone();
        tokio::spawn(async move {
            let app = crate::seeds_ion::create_seeds_router(&seeds_home);
            let seeds_bind: std::net::SocketAddr = "127.0.0.1:0"
                .parse()
                .expect("bind valid");
            let listener = match tokio::net::TcpListener::bind(seeds_bind).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(error = %e, "falha ao escutar seeds server");
                    return;
                }
            };
            let local = listener.local_addr().expect("local addr");
            tracing::info!(
                url = %format!("http://127.0.0.1:{}/seeds/", local),
                "mycelium seeds ion escutando"
            );
            {
                let mut table = seeds_horizon.write().unwrap();
                table.expose(
                    "seeds.mycelium",
                    Orbit {
                        ion: "seeds".into(),
                        node: NodeId::derive(b"seeds"),
                        mass: 100,
                        resistance: 0,
                        upstream: format!("http://{}", local),
                    },
                );
            }
            let _ = axum::serve(listener, app).await;
        });

        // Expõe a Vitrine Soberana (ion `vitrine`) no Event Horizon.
        let vitrine_home = self.home.clone();
        let vitrine_horizon = self.horizon.clone();
        tokio::spawn(async move {
            let app = crate::vitrine_ion::create_vitrine_router(&vitrine_home);
            let vitrine_bind: std::net::SocketAddr = "127.0.0.1:0"
                .parse()
                .expect("bind valid");
            let listener = match tokio::net::TcpListener::bind(vitrine_bind).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(error = %e, "falha ao escutar vitrine server");
                    return;
                }
            };
            let local = listener.local_addr().expect("local addr");
            tracing::info!(
                url = %format!("http://127.0.0.1:{}/vitrine/", local),
                "mycelium vitrine ion escutando"
            );
            {
                let mut table = vitrine_horizon.write().unwrap();
                table.expose(
                    "vitrine.mycelium",
                    Orbit {
                        ion: "vitrine".into(),
                        node: NodeId::derive(b"vitrine"),
                        mass: 100,
                        resistance: 0,
                        upstream: format!("http://{}", local),
                    },
                );
            }
            let _ = axum::serve(listener, app).await;
        });

        // Expõe o Code Hub soberano (ion `hub`) no Event Horizon.
        let hub_home = self.home.clone();
        let hub_horizon = self.horizon.clone();
        tokio::spawn(async move {
            let app = crate::hub_ion::create_hub_router(&hub_home);
            let hub_bind: std::net::SocketAddr = "127.0.0.1:0"
                .parse()
                .expect("bind valid");
            let listener = match tokio::net::TcpListener::bind(hub_bind).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(error = %e, "falha ao escutar hub server");
                    return;
                }
            };
            let local = listener.local_addr().expect("local addr");
            tracing::info!(
                url = %format!("http://127.0.0.1:{}/hub/", local),
                "mycelium code hub ion escutando"
            );
            {
                let mut table = hub_horizon.write().unwrap();
                table.expose(
                    "hub.mycelium",
                    Orbit {
                        ion: "hub".into(),
                        node: NodeId::derive(b"hub"),
                        mass: 100,
                        resistance: 0,
                        upstream: format!("http://{}", local),
                    },
                );
            }
            let _ = axum::serve(listener, app).await;
        });

        let pheromone = self
            .gland
            .secrete_membrane(Trail::default(), Duration::from_secs(3600), self.membrane)
            .map_err(|e| OrganismError::Msg(e.to_string()))?;
        let pheromone_bytes =
            serde_json::to_vec(&pheromone).map_err(|e| OrganismError::Msg(e.to_string()))?;
        let mut secreted = false;
        let mut persist_tick = tokio::time::interval(Duration::from_secs(15));
        let mut heartbeat = tokio::time::interval(Duration::from_secs(3600));
        let mut seed_tick = tokio::time::interval(Duration::from_secs(120));
        let mut duckdns_tick = tokio::time::interval(Duration::from_secs(300));
        let mut physarum_tick = tokio::time::interval(Duration::from_secs(5));
        // Descoberta Nostr: primeira ronda logo no arranque (não bloqueia).
        let nostr_secs = std::env::var("MYCELIUM_NOSTR_DISCOVERY_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(45)
            .max(1);
        let mut nostr_tick = tokio::time::interval(Duration::from_secs(nostr_secs));
        let mut nostr_found_rx = self
            .nostr_found_rx
            .take()
            .ok_or_else(|| OrganismError::Msg("laço do organismo já corre".into()))?;
        let mut metrics_tick = tokio::time::interval(Duration::from_secs(30));
        let mut balance_tick = tokio::time::interval(Duration::from_secs(60));
        let mut zone_tick = tokio::time::interval(Duration::from_secs(120));
        let mut scale_tick = tokio::time::interval(Duration::from_secs(45));
        let mut overlay_tick = tokio::time::interval(Duration::from_secs(90));
        // Anti-entropy: intervalo configurável (testes usam valor curto).
        let anti_entropy_secs = std::env::var("MYCELIUM_ANTI_ENTROPY_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(180)
            .max(1);
        let mut anti_entropy_tick =
            tokio::time::interval(Duration::from_secs(anti_entropy_secs));
        let mut seedwebhook_tick = tokio::time::interval(Duration::from_secs(30));
        // Primeiro tick imediato já foi coberto na germinação; atrasa o próximo.
        seed_tick.tick().await;
        // DuckDNS: espera um pouco para ter listen addrs.
        duckdns_tick.tick().await;
        physarum_tick.tick().await;
        metrics_tick.tick().await;
        balance_tick.tick().await;
        zone_tick.tick().await;
        scale_tick.tick().await;
        overlay_tick.tick().await;
        anti_entropy_tick.tick().await;
        seedwebhook_tick.tick().await;

        if self.sporocarp {
            tracing::info!("sporocarp ativo — relay + DNS (se DUCKDNS_*) — sem UPnP");
        }
        tracing::info!(
            membrane = %self.membrane,
            "política de membrana"
        );

        #[cfg(feature = "veil")]
        if self.veil_enabled {
            match self.start_veil_service().await {
                Ok(bound) => {
                    tracing::info!(bind = %bound, "VEIL Ω SOCKS5 ativado no boot");
                }
                Err(e) => {
                    tracing::error!(error = %e, "falha ao iniciar VEIL Ω no boot");
                }
            }
        }

        tracing::info!(
            node = %self.gland.node_id().short(),
            peer = %self.hyphae.peer_id(),
            "organismo despertou"
        );

        loop {
            tokio::select! {
                biased;

                msg = control_rx.recv() => {
                    match msg {
                        Some(ControlMsg { request, reply }) => {
                            let shutdown = matches!(request, Request::Shutdown);
                            let resp = self.handle_control(request).await;
                            let _ = reply.send(resp);
                            if shutdown {
                                break;
                            }
                        }
                        None => break,
                    }
                }

                _ = persist_tick.tick() => {
                    let _ = self.persist();
                }

                _ = physarum_tick.tick() => {
                    if self.hyphae.connected_neighbors() > 0 {
                        self.announce_peer_binding();
                    }
                    self.physarum_tick(0.5);
                }

                _ = nostr_tick.tick() => {
                    // Só dispara: a rede corre numa tarefa e o laço segue livre.
                    self.start_nostr_discovery();
                }

                Some(found) = nostr_found_rx.recv() => {
                    self.on_nostr_discovered(found);
                }

                _ = metrics_tick.tick() => {
                    let report = self.status_report();
                    let mut prom = String::new();
                    prom.push_str(&format!("# HELP mycelium_neighbors Número de vizinhos\n"));
                    prom.push_str(&format!("# TYPE mycelium_neighbors gauge\n"));
                    prom.push_str(&format!("mycelium_neighbors {}\n", report.neighbors));
                    prom.push_str(&format!("# HELP mycelium_plots Plots no Spore Bank\n"));
                    prom.push_str(&format!("# TYPE mycelium_plots gauge\n"));
                    prom.push_str(&format!("mycelium_plots {}\n", report.plots));
                    prom.push_str(&format!("# HELP mycelium_signals Signals no TheField\n"));
                    prom.push_str(&format!("# TYPE mycelium_signals gauge\n"));
                    prom.push_str(&format!("mycelium_signals {}\n", report.signals));
                    prom.push_str(&format!("# HELP mycelium_ions Ions em órbita\n"));
                    prom.push_str(&format!("# TYPE mycelium_ions gauge\n"));
                    prom.push_str(&format!("mycelium_ions {}\n", report.ions.len()));
                    prom.push_str(&format!("# HELP mycelium_atp Saldo de ATP\n"));
                    prom.push_str(&format!("# TYPE mycelium_atp gauge\n"));
                    prom.push_str(&format!("mycelium_atp {}\n", report.atp));
                    prom.push_str(&format!("# HELP mycelium_enzymes Saldo de Enzymes\n"));
                    prom.push_str(&format!("# TYPE mycelium_enzymes gauge\n"));
                    prom.push_str(&format!("mycelium_enzymes {}\n", report.enzymes));
                    prom.push_str(&format!("# HELP mycelium_mycelia Saldo de Mycelia\n"));
                    prom.push_str(&format!("# TYPE mycelium_mycelia gauge\n"));
                    prom.push_str(&format!("mycelium_mycelia {}\n", report.mycelia));
                    prom.push_str(&format!("# HELP mycelium_spores Saldo de Spores\n"));
                    prom.push_str(&format!("# TYPE mycelium_spores gauge\n"));
                    prom.push_str(&format!("mycelium_spores {}\n", report.spores));
                    prom.push_str(&format!("# HELP mycelium_resilience Saldo de Resilience\n"));
                    prom.push_str(&format!("# TYPE mycelium_resilience gauge\n"));
                    prom.push_str(&format!("mycelium_resilience {}\n", report.resilience));
                    prom.push_str(&format!("# HELP mycelium_anastomoses Conexões totais formadas\n"));
                    prom.push_str(&format!("# TYPE mycelium_anastomoses counter\n"));
                    prom.push_str(&format!("mycelium_anastomoses {}\n", report.anastomoses));
                    prom.push_str(&format!("# HELP mycelium_messages_in Mensagens gossip recebidas\n"));
                    prom.push_str(&format!("# TYPE mycelium_messages_in counter\n"));
                    prom.push_str(&format!("mycelium_messages_in {}\n", report.messages_in));
                    prom.push_str(&format!("# HELP mycelium_messages_out Mensagens gossip enviadas\n"));
                    prom.push_str(&format!("# TYPE mycelium_messages_out counter\n"));
                    prom.push_str(&format!("mycelium_messages_out {}\n", report.messages_out));
                    prom.push_str(&format!("# HELP mycelium_overlay_routes Rotas DHT resolvidas no overlay de zonas\n"));
                    prom.push_str(&format!("# TYPE mycelium_overlay_routes counter\n"));
                    prom.push_str(&format!("mycelium_overlay_routes {}\n", self.routing_hits));
                    prom.push_str(&format!("# HELP mycelium_isotope_atoms Atoms no Nucleus\n"));
                    prom.push_str(&format!("# TYPE mycelium_isotope_atoms gauge\n"));
                    prom.push_str(&format!("mycelium_isotope_atoms {}\n", report.isotope_atoms));
                    prom.push_str(&format!("# HELP mycelium_membrane Membrana atual\n"));
                    prom.push_str(&format!("# TYPE mycelium_membrane gauge\n"));
                    prom.push_str(&format!("mycelium_membrane{{membrane=\"{}\"}} 1\n", report.membrane));
                    prom.push_str(&format!("# HELP mycelium_physarum_phase Fase Physarum\n"));
                    prom.push_str(&format!("# TYPE mycelium_physarum_phase gauge\n"));
                    prom.push_str(&format!("mycelium_physarum_phase{{phase=\"{}\"}} 1\n", report.physarum_phase));
                    prom.push_str(&format!("# HELP mycelium_uptime_segundos Uptime do ledger (heartbeat)\n"));
                    prom.push_str(&format!("# TYPE mycelium_uptime_segundos counter\n"));
                    prom.push_str(&format!("mycelium_uptime_hours 1\n"));
                    // Plasma por-ion: carga, réplicas desejadas/remotas e ociosidade.
                    let mut ion_charge = String::new();
                    let mut ion_desired = String::new();
                    let mut ion_remote = String::new();
                    for name in self.cloud.names() {
                        let Some(ion) = self.cloud.get(name) else { continue };
                        let charge_val: i8 = match ion.charge {
                            Charge::Positive => 1,
                            Charge::Neutral => 0,
                            Charge::Negative => -1,
                        };
                        ion_charge.push_str(&format!(
                            "mycelium_ion_charge{{ion=\"{name}\"}} {charge_val}\n"
                        ));
                        ion_desired.push_str(&format!(
                            "mycelium_ion_desired_replicas{{ion=\"{name}\"}} {}\n",
                            ion.desired_replicas
                        ));
                        let remote = self
                            .ion_replica_peers
                            .get(name)
                            .map(|v| v.len())
                            .unwrap_or(0);
                        ion_remote.push_str(&format!(
                            "mycelium_ion_remote_replicas{{ion=\"{name}\"}} {remote}\n"
                        ));
                    }
                    if !ion_charge.is_empty() {
                        prom.push_str("# HELP mycelium_ion_charge Carga do ion (-1 negativa, 0 neutra, 1 positiva)\n");
                        prom.push_str("# TYPE mycelium_ion_charge gauge\n");
                        prom.push_str(&ion_charge);
                        prom.push_str("# HELP mycelium_ion_desired_replicas Réplicas desejadas sob carga observada\n");
                        prom.push_str("# TYPE mycelium_ion_desired_replicas gauge\n");
                        prom.push_str(&ion_desired);
                        prom.push_str("# HELP mycelium_ion_remote_replicas Réplicas remotas vivas conhecidas (IonReady)\n");
                        prom.push_str("# TYPE mycelium_ion_remote_replicas gauge\n");
                        prom.push_str(&ion_remote);
                    }
                    let mut table = self.horizon.write().unwrap();
                    table.set_metrics(prom);
                    // Injeta peer_ions no catálogo global.
                    let gossip_ions: HashMap<String, Vec<String>> = self
                        .peer_ions
                        .iter()
                        .map(|(nid, (ions, _))| (nid.short(), ions.clone()))
                        .collect();
                    table.set_peer_ions(gossip_ions);
                    // Sinal da console: visita autônoma → auto-semeadura.
                    self.console_hit = table.take_console_hits() > 0;
                }

                _ = balance_tick.tick() => {
                    let clock = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let mut balances = HashMap::new();
                    for n in Nutrient::ALL {
                        balances.insert(n, self.ledger.balance(n));
                    }
                    let env = Envelope::BalanceSync {
                        node_id: self.gland.node_id(),
                        balances,
                        clock,
                    };
                    if let Ok(bytes) = env.encode() {
                        let _ = self.hyphae.broadcast_lattice(bytes);
                    }
                }

                _ = zone_tick.tick() => {
                    // Anúncio global de Ions (catálogo para a console ErgotOS).
                    for name in self.chambers.keys() {
                        let env = Envelope::IonAnnounce {
                            node_id: self.gland.node_id(),
                            ion: name.clone(),
                            membrane: self.membrane.to_string(),
                        };
                        if let Ok(bytes) = env.encode() {
                            let _ = self.hyphae.broadcast_lattice(bytes);
                        }
                    }
                    // Efeito manada: visita à console semeadura local autônoma (rate-limit 1/min).
                    if self.console_hit && self.chambers.get("ergot-seed").is_none() {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        if now.saturating_sub(self.last_brood) >= 60 {
                            self.try_brood_seed_ion();
                            self.last_brood = now;
                        }
                        self.console_hit = false;
                    }
                    // Prune de peer_ions expirados (TTL 5 min sem anúncio).
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let before = self.peer_ions.len();
                    self.peer_ions.retain(|_, (_, ts)| now.saturating_sub(*ts) < 300);
                    let pruned = before.saturating_sub(self.peer_ions.len());
                    if pruned > 0 {
                        tracing::debug!(pruned, "peer_ions expirados removidos do catálogo");
                    }
                    self.prune_zones(now);
                    if !self.state.ions.is_empty() {
                        let prefix = format!("Qm{}", self.gland.node_id().short());
                        let env = Envelope::ZoneAnnounce {
                            prefix,
                            custodian: self.gland.node_id(),
                        };
                        if let Ok(bytes) = env.encode() {
                            let _ = self.hyphae.broadcast_lattice(bytes);
                        }
                    }
                }

                _ = scale_tick.tick() => {
                    self.plasma_scale_tick();
                }

                _ = overlay_tick.tick() => {
                    self.dht_overlay_tick();
                }

                _ = anti_entropy_tick.tick() => {
                    self.anti_entropy_tick();
                }

                _ = seedwebhook_tick.tick() => {
                    // Consome o feed de saúde do AlertManager webhook
                    // (seeds.health.jsonl) e reflete falhas/saúde no seed book.
                    if let Err(e) = self.seed_book.load_health_feed(&self.store.root) {
                        tracing::debug!(error = %e, "load_health_feed");
                    }
                }

                _ = heartbeat.tick() => {
                    self.ledger.heartbeat(1);
                    let _ = self.store.save_ledger(&self.ledger);
                }

                _ = duckdns_tick.tick() => {
                    if self.sporocarp {
                        let hyphae_addr = self.hyphae.best_public_addr().map(|a| {
                            with_membrane_flag(&a.to_string(), self.membrane)
                        });
                        let token = std::env::var("DUCKDNS_TOKEN").ok();
                        let domain = std::env::var("DUCKDNS_DOMAIN").ok();
                        if let (Some(token), Some(domain), Some(txt)) = (token, domain, hyphae_addr) {
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = SeedBook::publish_duckdns_txt(&domain, &token, &txt) {
                                    tracing::warn!("DuckDNS publish: {e}");
                                }
                            });
                        }
                    }
                }

                _ = seed_tick.tick() => {
                    let addrs = self.seed_book.multiaddrs_for(self.membrane);
                    if !addrs.is_empty() {
                        let n = self.hyphae.reach_seeds(&addrs);
                        if n > 0 {
                            tracing::debug!(reached = n, "re-bootstrap de seeds");
                        }
                    }
                    // Infra descentralizada: TTL + health check + persistência.
                    let pruned = self.seed_book.prune_expired();
                    if pruned > 0 {
                        tracing::info!(pruned, "seeds expiradas removidas");
                        if let Err(e) = self.seed_book.save_file(self.store.root.join("seeds.txt")) {
                            tracing::warn!(error = %e, "save_file seeds.txt");
                        }
                    }
                    // health_check disca TCP cru até cada seed: proibido no modo anônimo.
                    if self.anonymous {
                    } else if let Ok(checked) = self.seed_book.health_check() {
                        if checked > 0 {
                            tracing::debug!(checked, "health check de seeds");
                        }
                    }
                    // Relay mesh: esporocarp alcançável anuncia; folhas tentam circuit.
                    if self.assume_reachable && (self.sporocarp || matches!(self.membrane, Membrane::Esporocarp)) {
                        if let Err(e) = self.hyphae.publish_relay_mesh_ad() {
                            tracing::debug!("relay mesh ad: {e}");
                        }
                    } else if !self.sporocarp {
                        self.hyphae.try_mesh_relay_circuits();
                    }
                    self.hyphae.mailbox_poll();
                    // Reinicia chambers mortas.
                    let dead: Vec<String> = {
                        let mut names = Vec::new();
                        for (name, chamber) in self.chambers.iter_mut() {
                            if !chamber.healthy() {
                                names.push(name.clone());
                            }
                        }
                        names
                    };
                    for name in dead {
                        if let Some(c) = self.chambers.get_mut(&name) {
                            if let Err(e) = c.awaken() {
                                tracing::warn!(ion = %name, "awaken falhou: {e}");
                            } else if let Some(proc) = self.chambers.get(&name) {
                                let host = format!(
                                    "sporocarp.mycelium/{}",
                                    self.gland.node_id().short()
                                );
                                let mut table = self.horizon.write().unwrap();
                                table.expose(
                                    &host,
                                    Orbit {
                                        ion: name.clone(),
                                        node: self.gland.node_id(),
                                        mass: self.resources.cpu_cores as u64 * 10 + 1,
                                        resistance: 0,
                                        upstream: proc.upstream.clone(),
                                    },
                                );
                            }
                        }
                    }
                }

                event = self.hyphae.pulse() => {
                    match event {
                        Some(HyphaEvent::Rooted { address }) => {
                            tracing::info!(%address, "enraizado");
                            let _ = self.persist();
                        }
                        Some(HyphaEvent::SporocarpCircuit { src, dst }) => {
                            if self.sporocarp {
                                self.ledger.feed(
                                    Nutrient::Atp,
                                    1,
                                    format!("sporocarp-relay:{src}->{dst}"),
                                );
                                self.ledger.feed(Nutrient::Spores, 1, "sporocarp-relay");
                                let _ = self.store.save_ledger(&self.ledger);
                            }
                        }
                        Some(HyphaEvent::NeighborSniffed { peer })
                        | Some(HyphaEvent::Anastomosis { peer }) => {
                            tracing::info!(%peer, "hifa viva");
                            self.announce_peer_binding();
                            if !secreted {
                                if let Ok(true) = self.hyphae.secrete(pheromone_bytes.clone()) {
                                    secreted = true;
                                }
                                for id in self.bank.ids().to_vec() {
                                    if let Some(bytes) = self.bank.public_spore_print(&id) {
                                        if let Ok(plot) = serde_json::from_slice::<Plot>(&bytes) {
                                            let env = Envelope::SporePrint { plot };
                                            if let Ok(encoded) = env.encode() {
                                                let _ = self.hyphae.broadcast_lattice(encoded);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Some(HyphaEvent::Atrophy { peer }) => {
                            tracing::debug!(%peer, "hifa atrofiada");
                            self.note_peer_offline_and_repin(&peer.to_string());
                            self.check_auto_materialize_orphaned_services();
                        }
                        Some(HyphaEvent::S1LiveReceived { from, data }) => {
                            const MAX_S1_LIVE_INBOX: usize = 256;
                            if data.len() > 70_000 {
                                tracing::warn!(%from, "s1 live frame excede limite");
                            } else if let Ok(frame) = serde_json::from_slice::<serde_json::Value>(&data) {
                                let expires = frame.get("expires_at_ms").and_then(|v| v.as_u64());
                                let payload = frame.get("payload").and_then(|v| v.as_str());
                                let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                                match (expires, payload) {
                                    (Some(exp), Some(payload)) if exp > now_ms && exp.saturating_sub(now_ms) <= 300_000
                                        && payload.as_bytes().len() <= 65_536 =>
                                    {
                                        if self.s1_live_inbox.len() >= MAX_S1_LIVE_INBOX {
                                            self.s1_live_inbox.pop_front();
                                        }
                                        self.s1_live_inbox.push_back((exp, payload.to_string()));
                                    }
                                    _ => tracing::warn!(%from, "s1 live frame inválido/expirado"),
                                }
                            } else {
                                tracing::warn!(%from, "s1 live frame JSON inválido");
                            }
                        }
                        Some(HyphaEvent::DtnBundleReceived { from: _, bundle }) => {
                            let is_local = bundle.dst_node == Some(self.gland.node_id())
                                || bundle.dst_peer == self.gland.node_id().to_string()
                                || bundle.dst_peer == self.hyphae.peer_id().to_string();
                            if is_local {
                                if let Ok(env) = Envelope::decode(&bundle.payload) {
                                    if let Err(e) = self.handle_envelope(env) {
                                        tracing::warn!("envelope dtn: {e}");
                                    }
                                }
                            } else {
                                let _ = self.hyphae.forward_or_store_dtn(bundle);
                            }
                        }
                        Some(HyphaEvent::LatticeReceived { data, .. }) => {
                            match Envelope::decode(&data) {
                                Ok(env) => {
                                    if let Err(e) = self.handle_envelope(env) {
                                        tracing::warn!("envelope: {e}");
                                    }
                                }
                                Err(e) => tracing::warn!("envelope inválido: {e}"),
                            }
                        }
                        Some(HyphaEvent::PheromoneReceived { from, data }) => {
                            if let Some(peer_id) = from {
                                if let Ok(pheromone) = serde_json::from_slice::<mycelium_pheromones::Pheromone>(&data) {
                                    if pheromone.sniff().is_ok() {
                                        let node_id = pheromone.node_id();
                                        let expires_at = pheromone.body.emitted_at_secs + pheromone.body.decay_secs;
                                        let binding = mycelium_core::PeerBinding {
                                            node_id,
                                            peer_id: peer_id.to_string(),
                                            public_key: pheromone.body.identity.to_vec(),
                                            expires_at,
                                            signature: pheromone.signature.clone(),
                                        };
                                        self.hyphae.register_peer_binding(binding);
                                    }
                                }
                            }
                        }
                        Some(HyphaEvent::RecordFound { key, value }) => {
                            if key.starts_with(RELAY_DHT_PREFIX) {
                                if let Ok(adv) =
                                    serde_json::from_slice::<RelayAdvertisement>(&value)
                                {
                                    self.hyphae.ingest_relay_ad(adv);
                                    if !self.sporocarp {
                                        self.hyphae.try_mesh_relay_circuits();
                                    }
                                }
                            } else if key.starts_with(MAILBOX_DHT_PREFIX) {
                                if let Ok(msg) = serde_json::from_slice::<MailboxMessage>(&value) {
                                    if mycelium_hyphae::is_expired(&msg) {
                                        tracing::debug!(id = %msg.id_hex, "mailbox expirada");
                                    } else if msg.to == self.hyphae.peer_id().to_string() {
                                        tracing::info!(
                                            from = %msg.from,
                                            id = %msg.id_hex,
                                            ctype = ?msg.content_type,
                                            "mailbox DHT"
                                        );
                                        if let Err(e) = self.hyphae.mailbox_ack(&msg.id_hex) {
                                            tracing::debug!("mailbox ack: {e}");
                                        }
                                        // Entrega mínima: Generic → log; IsotopeAtom → absorb se Atom JSON
                                        if matches!(
                                            msg.content_type,
                                            mycelium_hyphae::MailboxContentType::IsotopeAtom
                                        ) {
                                            if let Ok(frame) =
                                                serde_json::from_slice::<(String, Atom)>(
                                                    &msg.payload,
                                                )
                                            {
                                                let (key, atom) = frame;
                                                self.nucleus.absorb(&key, atom);
                                                let _ = self.persist();
                                            } else if let Ok(atom) =
                                                serde_json::from_slice::<Atom>(&msg.payload)
                                            {
                                                // Payload legado sem chave — ignora absorb.
                                                tracing::debug!(
                                                    clock = atom.clock,
                                                    "mailbox isotope sem chave"
                                                );
                                            }
                                        }
                                    }
                                }
                            } else if let Some(id) =
                                mycelium_sporebank::content_id_from_dht_key(&key)
                            {
                                // Validar a associação entre chave DHT e
                                // conteúdo ANTES da persistência.
                                let valid = serde_json::from_slice::<Plot>(&value)
                                    .ok()
                                    .and_then(|plot| plot.id().ok().map(|actual| (plot, actual)))
                                    .map(|(plot, actual)| plot.is_public() && actual == id)
                                    .unwrap_or(false);
                                if valid {
                                    match self.bank.absorb_public(&value) {
                                        Ok(_) => tracing::info!(plot = %id.short(), "esporo público recuperado do DHT"),
                                        Err(e) => tracing::warn!("absorb DHT: {e}"),
                                    }
                                    let _ = self.persist();
                                } else {
                                    tracing::warn!(plot = %id.short(), "DHT: conteúdo restrito ou hash incompatível descartado");
                                }
                            } else if let Some(layer_id) = content_id_from_layer_dht_key(&key) {
                                if ContentId::of(&value) != layer_id {
                                    tracing::warn!(layer = %layer_id.short(), "DHT: layer com hash incompatível descartada");
                                    continue;
                                }
                                match LayerStore::open(self.store.layers_dir()) {
                                    Ok(store) => match store.put(&value) {
                                        Ok(stored) => {
                                            tracing::info!(
                                                layer = %stored.short(),
                                                expected = %layer_id.short(),
                                                "layer recuperada do DHT"
                                            );
                                        }
                                        Err(e) => tracing::warn!("layer DHT put: {e}"),
                                    },
                                    Err(e) => tracing::warn!("layer store: {e}"),
                                }
                                let _ = self.persist();
                            }
                        }
                        Some(HyphaEvent::RecordNotFound { key }) => {
                            tracing::debug!(key = %hex::encode(&key), "DHT miss");
                        }
                        Some(HyphaEvent::ClosestPeers { key, peers }) => {
                            // Overlay DHT: resolvemos os peers XOR-mais-próximos
                            // da chave (ContentId de layer/esporo). Eles são os
                            // custodianos naturais da custódia — alimentam a
                            // rota e reforçam a tabela de zonas.
                            if peers.is_empty() {
                                tracing::debug!(key = %hex::encode(&key), "closest_peers vazio");
                            } else {
                                tracing::info!(
                                    key = %hex::encode(&key),
                                    closest = peers.len(),
                                    "overlay XOR: rota DHT para custodianos"
                                );
                                self.routing_hits += 1;
                                // Alimenta a tabela de zonas: registra interesse
                                // na chave para que a próxima query de layer
                                // já passe a considerar esses peers.
                            }
                        }
                        Some(HyphaEvent::NeighborEvaporated { .. }) | None => {}
                    }
                }
            }
        }

        // Decompõe chambers (Drop também mata, mas explícito é mais claro).
        for (_, mut c) in self.chambers.drain() {
            c.decompose();
        }
        if let Some(h) = self.horizon_handle.take() {
            h.shutdown();
        }
        self.stop_veil_service();
        self.persist()?;
        self.store.clear_runtime_files();
        tracing::info!("organismo hibernou — estado persistido");
        Ok(())
    }
}

/// GhostID determinístico da carteira do nó: derivado do seed do gland
/// (estável por nó, efémero pela camada de assinatura NIP-01).
fn ghost_for_node(gland_seed: [u8; 32]) -> mycelium_ghostid::GhostId {
    let seed = mycelium_core::ContentId::of(b"mycelium-value-layer-v1")
        .0
        .iter()
        .zip(gland_seed.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap_or(gland_seed);
    mycelium_ghostid::GhostId::from_secret_bytes(seed, 60 * 60 * 24 * 365 * 100)
        .unwrap_or_else(|_| mycelium_ghostid::GhostId::spawn_quick(60 * 60 * 24 * 365).unwrap())
}

/// Enquanto não houver ACL/capability verificável, apenas Plots públicos
/// podem ser acessados por outro nó. Restritos só pelo autor local.
pub fn recall_allowed(visibility: &str, author: &mycelium_core::NodeId, caller: &mycelium_core::NodeId) -> bool {
    visibility == "public" || author == caller
}

/// TTL de custódia de zona (600s sem re-anúncio ⇒ custodiante expirado).
const ZONE_TTL_SECS: u64 = 600;

/// Remove da tabela de zonas custodiantes que não re-anunciam há
/// [`ZONE_TTL_SECS`]. Função pura sobre as duas tabelas — testável sem um
/// `Organism` completo.
fn prune_zone_tables(
    known_zones: &mut HashMap<String, Vec<NodeId>>,
    known_zones_ts: &mut HashMap<NodeId, u64>,
    now: u64,
) {
    let dead: Vec<NodeId> = known_zones_ts
        .iter()
        .filter(|(_, ts)| now.saturating_sub(**ts) >= ZONE_TTL_SECS)
        .map(|(n, _)| *n)
        .collect();
    if dead.is_empty() {
        return;
    }
    for n in &dead {
        known_zones_ts.remove(n);
        known_zones.retain(|_, v| {
            v.retain(|x| x != n);
            !v.is_empty()
        });
    }
    tracing::debug!(pruned = dead.len(), "custodiantes de zona expirados removidos");
}

#[cfg(test)]
mod xor_tests {
    use super::*;

    #[test]
    fn xor_distance_is_symmetric_and_zero_for_self() {
        let a = NodeId::derive(b"alpha");
        let b = NodeId::derive(b"beta");
        assert_eq!(
            Organism::xor_key_distance(&a.0, &a.0),
            [0u8; 32]
        );
        assert_eq!(
            Organism::xor_key_distance(&a.0, &b.0),
            Organism::xor_key_distance(&b.0, &a.0)
        );
    }

    #[test]
    fn xor_closest_orders_by_kademlia_distance() {
        // Distância XOR: prefixo comum de bits decide o mais próximo.
        let key = NodeId::derive(b"chave-alvo");
        let near = NodeId::derive(b"chave-alfa"); // compartilha prefixo alto
        let far = NodeId::derive(b"zzzzzzzz");
        let d_near = Organism::xor_key_distance(&near.0, &key.0);
        let d_far = Organism::xor_key_distance(&far.0, &key.0);
        assert!(d_near < d_far, "prefixo comum deve vencer no XOR");
    }

    // Âncora determinística do recombine multi-réplica: um holder só
    // recombina se existe réplica remota VIVA com NodeId MENOR. O menor
    // NodeId vivo nunca recombina → o ion sobrevive mesmo com N réplicas.
    #[test]
    fn recombine_anchor_keeps_minimum_nodeid_alive() {
        let a = NodeId::derive(b"ancora");
        let b = NodeId::derive(b"replica-b");
        assert!(a < b, "âncora deve ser a menor");

        let now = 1000u64;
        let ttl = 180u64;
        // Helper espelhando a regra do plasma_scale_tick.
        let covered_by_smaller = |local: &NodeId, peers: &[NodeId], peer_ts: &[(NodeId, u64)]| {
            peers.iter().any(|peer| {
                *peer < *local
                    && peer_ts
                        .iter()
                        .any(|(p, ts)| p == peer && now.saturating_sub(*ts) < ttl)
            })
        };

        // a é o menor: nunca coberto → nunca recombina (âncora).
        assert!(!covered_by_smaller(&a, &[b], &[(b, now)]));
        // b vê a viva e menor → recombina.
        assert!(covered_by_smaller(&b, &[a], &[(a, now)]));
        // b vê réplica menor MAS morta (anúncio velho) → não recombina:
        // morrer agora apagaria o ion.
        assert!(!covered_by_smaller(&b, &[a], &[(a, now - ttl - 10)]));
    }

    // Cleanup de conhecidos de zona: custodianos que não re-anunciam há
    // muito (TTL 600s) são removidos da tabela de rotas XOR.
    #[test]
    fn prune_zones_removes_stale_custodians() {
        use std::collections::HashMap;
        let alive = NodeId::derive(b"custodio-vivo");
        let stale = NodeId::derive(b"custodio-morto");
        let mut zones: HashMap<String, Vec<NodeId>> = HashMap::new();
        zones.insert("Qmzona".to_string(), vec![alive, stale]);
        let mut ts: HashMap<NodeId, u64> = HashMap::new();
        ts.insert(alive, 1600u64); // 100s antes de `now` → dentro do TTL
        ts.insert(stale, 100u64); // 1600s antes de `now` → expirado

        // `stale` (100) passou do TTL 600; `alive` (1600) ainda recente.
        prune_zone_tables(&mut zones, &mut ts, 1700);
        let remaining: Vec<NodeId> = zones.values().flatten().copied().collect();
        assert!(remaining.contains(&alive), "custodiante vivo deve permanecer");
        assert!(!remaining.contains(&stale), "custodiante expirado deve sair");
        assert!(!ts.contains_key(&stale));
    }

    // Limitante de saltos do forwarding greedy: `MAX_LAYER_NEED_HOPS` deve
    // ser finito, pequeno e deixar margem para o incremento não estourar u8.
    #[test]
    fn layer_need_hop_limit_is_bounded() {
        assert!(MAX_LAYER_NEED_HOPS > 0, "precisa aceitar ao menos 1 salto");
        assert!(
            (MAX_LAYER_NEED_HOPS as usize) + 1 < u8::MAX as usize,
            "incremento hop+1 não pode estourar u8"
        );
    }
}

#[cfg(test)]
mod visibility_tests {
    use super::{ensure_repo_publishable, recall_allowed};
    use giggs::Plot;
    use mycelium_core::NodeId;

    fn id(b: &[u8]) -> NodeId { NodeId::derive(b) }

    #[test]
    fn public_plot_is_downloadable_by_any_node() {
        let a = id(b"autor-a"); let b = id(b"autor-b");
        assert!(recall_allowed("public", &a, &b));
        assert!(recall_allowed("public", &a, &a));
    }

    #[test]
    fn private_plot_only_its_author_downloads() {
        let a = id(b"autor-a"); let b = id(b"outro-no");
        assert!(recall_allowed("private", &a, &a), "autor baixa o próprio plot");
        assert!(
            !recall_allowed("private", &a, &b),
            "não-autor recebe acesso negado"
        );
    }

    #[test]
    fn other_visibilities_are_not_open_to_non_authors() {
        let a = id(b"autor-a"); let o = id(b"qualquer");
        for vis in ["reserved", "archived", "community"] {
            assert!(!recall_allowed(vis, &a, &o), "{vis}");
            assert!(recall_allowed(vis, &a, &a), "autor local pode restaurar {vis}");
        }
    }

    #[test]
    fn repo_publication_fails_closed_for_restricted_plots() {
        let plot = Plot {
            author: id(b"autor"),
            message: "[private] código reservado".into(),
            parents: vec![],
            leaves: vec![],
        };
        assert!(ensure_repo_publishable(&plot).is_err());
    }

    #[test]
    fn repo_publication_accepts_explicit_public_plots() {
        let plot = Plot {
            author: id(b"autor"),
            message: "[public] código aberto".into(),
            parents: vec![],
            leaves: vec![],
        };
        assert!(ensure_repo_publishable(&plot).is_ok());
    }
}
