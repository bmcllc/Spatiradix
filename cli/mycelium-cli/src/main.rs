//! # mycelium — CLI do substrato vivo

use axum::routing::get;
use axum::{Json, Router};
use clap::{Parser, Subcommand};
use mycelium_core::Resources;
use mycelium_hyphae::{SeedBook, DEFAULT_BOOTSTRAP_URL, DEFAULT_DNS_SEED_NAME};
use mycelium_node::{call, run_daemon, DaemonOptions, NodeStore, Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

#[derive(Parser)]
#[command(
    name = "mycelium",
    about = "Mycelium Network — o substrato vivo do The Lattice",
    version
)]
struct Cli {
    #[arg(long, global = true, env = "MYCELIUM_HOME")]
    home: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    Sprout {
        #[arg(long, default_value = "1cpu,1gb,10gb")]
        contribute: String,
    },
    Daemon {
        #[arg(long, default_value = "1cpu,1gb,10gb")]
        contribute: String,
        /// Seed/bootstrap multiaddr (repetível). Aceita `/dnsaddr/...`.
        #[arg(long = "bootstrap")]
        bootstrap: Vec<String>,
        /// Arquivo local de seeds (uma multiaddr por linha).
        #[arg(long = "seed-file")]
        seed_file: Option<PathBuf>,
        /// Baixa o catálogo público de seeds (além da LAN).
        #[arg(long = "public-bootstrap")]
        public_bootstrap: bool,
        /// URL do catálogo (default: github mycelium-network/seeds).
        #[arg(long = "bootstrap-url")]
        bootstrap_url: Option<String>,
        /// Multiaddr de escuta (repetível). Ex.: `/ip4/0.0.0.0/tcp/4001`
        #[arg(long = "listen")]
        listen: Vec<String>,
        /// Porta do Event Horizon HTTP (Singularity).
        #[arg(long, default_value_t = 7474)]
        horizon_port: u16,
        /// Desliga mDNS — discovery só via seed book / --bootstrap.
        #[arg(long = "no-mdns")]
        no_mdns: bool,
        /// IP público anunciado (quando listen é 0.0.0.0). Env: MYCELIUM_ANNOUNCE_IP.
        #[arg(long = "announce-ip", env = "MYCELIUM_ANNOUNCE_IP")]
        announce_ip: Option<String>,
        /// IPv6 público anunciado (quando listen é `::`). Env: MYCELIUM_ANNOUNCE_IP6.
        #[arg(long = "announce-ip6", env = "MYCELIUM_ANNOUNCE_IP6")]
        announce_ip6: Option<String>,
        /// Opera como circuit relay v2 (seed público). Gera control.token se sem env.
        #[arg(long = "relay")]
        relay: bool,
        /// Volunteer Sporocarp: relay + publish DNS TXT + crédito ATP.
        #[arg(long = "sporocarp")]
        sporocarp: bool,
        /// Override da membrana (floresta|raiz|folha|esporocarp).
        #[arg(long = "membrane", value_parser = parse_membrane)]
        membrane: Option<mycelium_core::Membrane>,
        /// Declara inbound TCP/QUIC alcançável (auto-esporocarp se IPv6/announce).
        /// Env: MYCELIUM_REACHABLE=1
        #[arg(long = "assume-reachable", env = "MYCELIUM_REACHABLE")]
        assume_reachable: bool,
        /// Escuta webrtc-direct (requer `cargo build --features webrtc`).
        #[arg(long = "webrtc")]
        webrtc: bool,
        /// Porta UDP webrtc-direct.
        #[arg(long = "webrtc-port", default_value_t = 4002)]
        webrtc_port: u16,
        /// Transporte libp2p sobre Nostr (força ON). Sem flag: auto em folha/floresta.
        #[arg(long = "nostr-transport", env = "MYCELIUM_NOSTR_TRANSPORT")]
        nostr_transport: bool,
        /// Desliga Nostr transport (mesmo em folha/floresta).
        #[arg(long = "no-nostr-transport", conflicts_with = "nostr_transport")]
        no_nostr_transport: bool,
        /// Relay Nostr WSS para o transporte (default nos.lol).
        #[arg(long = "nostr-relay", env = "MYCELIUM_NOSTR_RELAY")]
        nostr_relay: Option<String>,
        /// **Licença VOID-00**: only accept peers com estes PeerIds (virgula,
        /// repetível). Ativa o gate de admissão licenciada. Req. feature `license`.
        #[arg(long = "licensed-peers", value_delimiter = ',')]
        licensed_peers: Vec<String>,
        /// Depreciado: ignorado (Política de Membrana — sem UPnP).
        #[arg(long = "upnp")]
        upnp: bool,
        /// Ativa o serviço VEIL Ω (SOCKS5 proxy e privacidade pós-quântica).
        #[arg(long = "veil")]
        veil: bool,
        /// Endereço de escuta do SOCKS5 (default: 127.0.0.1:1080).
        #[arg(long = "veil-socks5")]
        veil_socks5: Option<std::net::SocketAddr>,
        /// Modo de operação VEIL: veil (3 saltos), geo (1 salto), mix (mixnet).
        #[arg(long = "veil-mode")]
        veil_mode: Option<String>,
        /// Papel do nó no VEIL Ω: client, relay, exit, all.
        #[arg(long = "veil-role")]
        veil_role: Option<String>,
        /// Endereço de escuta para roteador de salto VEIL (relay ou exit).
        #[arg(long = "veil-listen")]
        veil_listen: Option<std::net::SocketAddr>,
        /// Descritor de nó Guard (caminho para arquivo JSON ou string JSON). Repetível.
        #[arg(long = "veil-guard")]
        veil_guards: Vec<String>,
        /// Descritor de nó Middle (caminho para arquivo JSON ou string JSON). Repetível.
        #[arg(long = "veil-middle")]
        veil_middles: Vec<String>,
        /// Descritor de nó Exit (caminho para arquivo JSON ou string JSON). Repetível.
        #[arg(long = "veil-exit")]
        veil_exits: Vec<String>,
        /// Pinning de identidade de produção: "<nome>:<hex_identity_pubkey>" por salto (ex.: guard:<hex>).
        /// Ativa autenticação estrita anti-substituição no modo client.
        #[arg(long = "veil-trust")]
        veil_trust: Vec<String>,
        /// Endereço público anunciado no descritor assinado (ex.: 203.0.113.9:9050).
        /// Separado do --veil-listen; nunca use 0.0.0.0.
        #[arg(long = "veil-advertise")]
        veil_advertise: Option<String>,
        /// Caminho da identidade persistente do nó (GhostId + ML-KEM-1024).
        /// Padrão: {home}/veil-identity.json (permissões 0600).
        #[arg(long = "veil-identity")]
        veil_identity: Option<PathBuf>,
        /// Rota a identidade Veil explicitamente (nunca implícita em reinício).
        #[arg(long = "veil-rotate-identity")]
        veil_rotate_identity: bool,
        /// IP de origem explícito do egresso do Exit (multi-homing). Sob NAT o destino
        /// observa o IP da tradução, não este bind.
        #[arg(long = "veil-egress-bind")]
        veil_egress_bind: Option<std::net::IpAddr>,
        /// Pontes de entrada VEIL (repetível, ex.: 127.0.0.1:9001). Quando presente,
        /// o cliente usa somente bridges — NUNCA insere entrada direta ao Guard.
        #[arg(long = "veil-bridge")]
        veil_bridges: Vec<String>,
        /// Endereço de escuta da bridge (papel bridge).
        #[arg(long = "veil-bridge-listen")]
        veil_bridge_listen: Option<String>,
        /// Endereço do Guard para o qual a bridge repassa o fluxo cru (papel bridge).
        #[arg(long = "veil-bridge-target")]
        veil_bridge_target: Option<String>,
        /// Modo anônimo fail-closed: todo tráfego sai pelo SOCKS5 de `--anon-socks`;
        /// só transporte Nostr (wss), sem TCP/QUIC/mDNS/escuta em IP. Opções que
        /// revelariam o IP viram erro. O daemon não sobe sem o proxy respondendo.
        #[arg(long)]
        anonymous: bool,
        /// SOCKS5 local do modo anônimo (Tor: 127.0.0.1:9050 · VEIL: 127.0.0.1:1080).
        #[arg(long = "anon-socks", default_value = "127.0.0.1:9050")]
        anon_socks: std::net::SocketAddr,
        /// Ativa boot automático do motor de emissão mainnet (`mycelium-mint`, 1 MYC = 8 USDC).
        #[arg(long = "mint-mainnet")]
        mint_mainnet: bool,
        /// Chain ID da mainnet para o motor de emissão.
        #[arg(long = "mint-chain-id", default_value = "mycelium-mainnet")]
        mint_chain_id: String,
        /// Quórum mínimo de esporocarpos para liquidação de época.
        #[arg(long = "mint-quorum", default_value_t = 1)]
        mint_quorum: usize,
    },
    /// Habitat soberano: declara e gerencia políticas de serviços locais.
    Habitat {
        #[command(subcommand)]
        action: HabitatCmd,
    },
    Status,
    Sow {
        #[arg(long, default_value = "init")]
        message: String,
        #[arg(long, default_value = "main.rs")]
        path: String,
        #[arg(long, default_value = "fn main() {}")]
        content: String,
        /// Fragmenta com QEL (formato k,n — default 3,7). Requer --features nostr.
        #[arg(long, value_name = "K,N")]
        qel: Option<String>,
        /// Publica anúncio NIP-94 + shards via relays Nostr (wss:// outbound).
        #[arg(long)]
        nostr: bool,
        /// Usa GhostID efémero secp256k1 para assinar eventos Nostr.
        #[arg(long)]
        ghost: bool,
        /// Pubkey Nostr hex do destinatário (NIP-44); sem isto shards vão em plaintext assinado.
        #[arg(long = "to")]
        recipient: Option<String>,
        /// Hybrid Theory: QEL + Nostr + blockstore local (ipfs-blocks/).
        #[arg(long)]
        hybrid: bool,
    },
    /// Publica pela mailbox Nostr um plot que já existe no SporeBank.
    PublishExisting {
        #[arg(long)]
        plot: String,
        #[arg(long)]
        nostr: bool,
        #[arg(long, value_name = "K,N", default_value = "3,7")]
        qel: String,
        #[arg(long, default_value_t = 4)]
        max_attempts: u32,
        #[arg(long, default_value_t = 30)]
        timeout: u64,
        #[arg(long, default_value_t = 500, hide = true)]
        backoff_ms: u64,
    },
    Signal {
        #[arg(long)]
        plot: String,
        #[arg(long, default_value_t = 1)]
        quorum: usize,
        #[arg(long, default_value = "webapp")]
        ion: String,
        #[arg(long, default_value = "ci")]
        name: String,
    },
    Resonate {
        #[arg(long)]
        signal: String,
    },
    Recall {
        #[arg(long)]
        plot: String,
        /// Reconstrói via shards QEL (Nostr).
        #[arg(long)]
        qel: bool,
        /// Busca shards em relays Nostr.
        #[arg(long)]
        nostr: bool,
        /// Threshold QEL (default 3).
        #[arg(long, default_value_t = 3)]
        qel_threshold: u8,
        /// Hybrid: local → Nostr → blockstore ipfs local.
        #[arg(long)]
        hybrid: bool,
    },
    Bootstrap {
        #[arg(long)]
        addr: String,
    },
    /// Gerencia o seed book local (bootstrap público).
    Seeds {
        #[command(subcommand)]
        action: SeedsCmd,
    },
    /// Escreve estado no Isotope (propaga por hifas).
    IsotopePut {
        #[arg(long)]
        key: String,
        #[arg(long)]
        value: String,
        #[arg(long)]
        clock: Option<u64>,
    },
    /// Lê estado do Isotope (local ou Decay pelas hifas).
    IsotopeGet {
        #[arg(long)]
        key: String,
    },
    /// One-shot: sow → signal → espera ion no Horizon (fluxo do manifesto).
    Deploy {
        #[arg(long)]
        plot: Option<String>,
        #[arg(long, default_value = "init")]
        message: String,
        #[arg(long, default_value = "build.sh")]
        path: String,
        #[arg(long, default_value = "#!/bin/sh\nmkdir -p dist\necho ok > dist/index.html\n")]
        content: String,
        #[arg(long, default_value = "webapp")]
        ion: String,
        #[arg(long, default_value = "ci")]
        name: String,
        #[arg(long, default_value_t = 1)]
        quorum: usize,
        /// Segundos máximos à espera do ion.
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
    #[command(alias = "stop")]
    Shutdown,
    /// Mostra balance local + de peers.
    Balance,
    /// Migra um Ion para outro nó.
    IonMigrate {
        #[arg(long)]
        ion: String,
        #[arg(long)]
        target: String,
    },
    /// Mostra zonas de crescimento conhecidas.
    Zones,
    /// Publica código-fonte diretamente na rede (sem git, sem GitHub).
    SeedCode {
        /// Caminho do diretório.
        #[arg(long)]
        path: String,
        /// Nome do projeto.
        #[arg(long)]
        name: String,
        /// Descrição curta.
        #[arg(long)]
        description: String,
        /// Ion para sinalizar (default: "code").
        #[arg(long, default_value = "code")]
        ion: String,
        /// Visibilidade: public, private, reserved, archived, community.
        #[arg(long, default_value = "public")]
        visibility: String,
    },
    /// Anuncia um repositório Git via gossipsub (URL pública, sem dados sensíveis).
    SeedRepo {
        /// Nome do repositório (ex: "mycelium-network").
        #[arg(long)]
        name: String,
        /// URL pública de clone (ex: "https://github.com/bmcc-DEV/mycelium-network.git").
        #[arg(long)]
        url: String,
        /// Hash do commit atual (ex: "ad924b6").
        #[arg(long)]
        commit: String,
        /// Descrição curta do repositório.
        #[arg(long)]
        description: String,
    },
    /// Baixa código-fonte da rede via ContentId (sem git, sem GitHub).
    RecallCode {
        /// ContentId do plot (Qm...).
        #[arg(long)]
        plot: String,
        /// Diretório de destino (default: ./<nome-do-plot>).
        #[arg(long)]
        output: Option<String>,
    },
    /// Lista repositórios anunciados via gossipsub por peers da rede.
    Repos,
    /// Verifica uma licença VOID-00 (ML-DSA-87 + device binding).
    LicenseVerify {
        /// Chave pública do vendor (hex, 2592 bytes).
        #[arg(long)]
        vendor_key: String,
        /// Entropia do dispositivo (hex).
        #[arg(long)]
        device_entropy: String,
        /// SKU do produto.
        #[arg(long)]
        sku: String,
        /// Payload canónico da licença (hex, 121 bytes).
        #[arg(long)]
        payload: String,
        /// Assinatura ML-DSA-87 (hex, 4627 bytes).
        #[arg(long)]
        signature: String,
        /// Timestamp Unix em segundos (default: agora).
        #[arg(long)]
        now: Option<u64>,
        /// Auto-release: se a licença passar, inscreve este PeerId na allowlist
        /// de admissão licenciada (gate passa a aceitá-lo).
        #[arg(long = "peer-id")]
        peer_id: Option<String>,
    },
    /// Inscreve um PeerId na allowlist de admissão licenciada (runtime).
    RegisterPeer {
        /// PeerId do nó a autorizar.
        #[arg(long)]
        peer_id: String,
    },
    /// Valida um invoice BOLT11 (Lightning) e mostra resumo.
    Bolt11 {
        /// Invoice BOLT11 (string completa `lnbc...`).
        invoice: String,
    },
    /// Entropy: Shamir Secret Sharing com meia-vida.
    Entropy {
        #[command(subcommand)]
        action: EntropyCmd,
    },
    /// Mainnet Mint: consulta política monetária (1 MYC = 8 USDC) e submete provas de trabalho útil.
    Mint {
        #[command(subcommand)]
        action: MintCmd,
    },
    /// Supreme Meta-Gateway: pagamentos unificados (pix:, swift:, brics:, myc:) com paridade 1 MYC = 8 USDC.
    Gateway {
        #[command(subcommand)]
        action: GatewayCmd,
    },
    /// CandidateRelay (kind 39401/39406): descoberta + backchannel CGNAT↔CGNAT.
    Candidate {
        #[command(subcommand)]
        cmd: Option<CandidateCmd>,
        /// Repetir com jitter 30–300s (só em discover sem subcomando).
        #[arg(long)]
        r#loop: bool,
        /// Uma ronda e sai (default se sem --loop).
        #[arg(long)]
        once: bool,
        /// Relays wss:// (repetível). Default = pool público.
        #[arg(long = "relay")]
        relays: Vec<String>,
    },
    #[command(hide = true)]
    ChamberServe {
        #[arg(long)]
        port: u16,
        #[arg(long)]
        ion: String,
        #[arg(long)]
        root: PathBuf,
    },
    /// App Store / Steam P2P de jogos e software antigo/legado
    Store {
        #[command(subcommand)]
        action: StoreCmd,
    },
    /// Distribuição de código soberana via P2P (sem GitHub)
    Repo {
        #[command(subcommand)]
        action: RepoCmd,
    },
    /// TheField: forja soberana de repositórios Git P2P e campo de Signals/quórum.
    Field {
        /// Porta do Event Horizon onde o TheField está servido (default: 7474).
        #[arg(long, default_value_t = 7474)]
        port: u16,
    },
    /// Infraestrutura pós-quântica de privacidade VEIL Ω (SOCKS5, Onion Routing, Anti-SSRF).
    Veil {
        #[command(subcommand)]
        action: VeilCmd,
    },
    /// Mycelium Media: streaming, publicação e gestão de áudio e vídeo soberano (zero VPS).
    Media {
        #[command(subcommand)]
        action: MediaCmd,
    },
    /// Gerencia canais descentralizados assinados por GhostID.
    Channel {
        #[command(subcommand)]
        action: ChannelCmd,
    },
    /// Gerencia playlists descentralizadas.
    Playlist {
        #[command(subcommand)]
        action: PlaylistCmd,
    },
    /// Protocolo Sclerotium: nós dormentes, GhostLease e despertar seletivo (Ghost Carrier / WoL).
    Sclerotium {
        #[command(subcommand)]
        action: SclerotiumCmd,
    },
    /// Assinatura de conteúdo premium: plano, emissão e verificação de acesso.
    /// Site + serviço por assinatura sem hospedagem, sem domínio e sem VPS.
    Sub {
        #[command(subcommand)]
        action: SubCmd,
    },
    /// Descoberta anônima sem seed/DNS/VPS: registro Pkarr com chave cegada por
    /// época, conteúdo cifrado e publicação só via SOCKS5 local (VEIL/Tor).
    Pkarr {
        #[command(subcommand)]
        action: PkarrCmd,
    },
    /// Root: nuvem sem servidor e sem P2P — cofre K-de-N espalhado pelos seus
    /// pendrives/cartões/discos, sincronizado por contato, montável como pendrive.
    Root {
        #[command(subcommand)]
        action: RootCmd,
    },
    /// Mycelium Rhizome: Super-app social soberano (YouTube/Reels, Instagram/Stories,
    /// Facebook/Comunidades, X/Microblog e WhatsApp PQ E2EE) sobre toda a malha Mycelium.
    Rhizome {
        #[command(subcommand)]
        action: RhizomeCmd,
    },
}

#[derive(Subcommand)]
enum RhizomeCmd {
    /// Exibe URLs da interface web e endpoints abertos (RSS 2.0 / ActivityPub) do Rhizome.
    Ui {
        #[arg(long, default_value_t = 7474)]
        port: u16,
    },
    /// Mostra o cartão completo da identidade soberana (NodeId, PKARR myc1..., GhostID Nostr, ML-KEM-1024).
    Identity,
    /// Atualiza handle, nome de exibição e bio do perfil/canal soberano.
    Profile {
        #[arg(long)]
        handle: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        bio: Option<String>,
    },
    /// Publica um post (microblog X, artigo Facebook ou foto) assinado por Ed25519.
    Post {
        /// Texto da publicação (#hashtags e @menções são extraídas automaticamente).
        text: String,
        /// Tipo: microblog | article | photo_gallery
        #[arg(long, default_value = "microblog")]
        kind: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        community: Option<String>,
        #[arg(long)]
        reply_to: Option<String>,
        #[arg(long)]
        repost_of: Option<String>,
    },
    /// Publica um Story efêmero propagado via Isotope com TTL automático.
    Story {
        caption: String,
        /// Tempo de vida em horas (padrão: 24).
        #[arg(long, default_value_t = 24)]
        ttl_hours: u64,
    },
    /// Publica um vídeo (Longform, Short/Reel ou Doc) fatiado em chunks BLAKE3 via mycelium-media.
    Video {
        file: PathBuf,
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long)]
        short: bool,
        #[arg(long)]
        doc: bool,
        #[arg(long)]
        commons: Option<String>,
        #[arg(long)]
        thumbnail: Option<PathBuf>,
        #[arg(long, default_value_t = 3)]
        replicas: u32,
        #[arg(long, default_value = "CC-BY-4.0")]
        license: String,
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
    },
    /// Consulta o feed unificado usando uma Lente de Descoberta soberana.
    Feed {
        /// Lente: symbiosis | chronological | trust_web
        #[arg(long, default_value = "symbiosis")]
        lens: String,
        /// Filtro: all | video | short | tube | photo | article | microblog
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        query: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Envia mensagem E2EE pós-quântica (ML-KEM-1024 + XChaCha20-Poly1305) estilo WhatsApp.
    ChatSend {
        /// NodeId, @handle ou endereço myc1... do destinatário.
        #[arg(long)]
        to: String,
        /// Mensagem de texto.
        text: String,
        /// Chave pública ML-KEM-1024 hex opcional caso o perfil remoto ainda não tenha chegado.
        #[arg(long)]
        mlkem: Option<String>,
        /// Também gera envelope Nostr NIP-44 (fallback CGNAT).
        #[arg(long)]
        nostr_fallback: bool,
    },
    /// Lista conversas ou mensagens de uma conversa específica do Zap PQ.
    ChatInbox {
        #[arg(long)]
        conversation: Option<String>,
    },
    /// Importa tweets e reconstrói threads de um archive do X (`tweets.js` ou JSON).
    ImportX {
        file: PathBuf,
    },
    /// Importa histórico exportado (`.txt`) do WhatsApp para uma conversa local.
    ImportWhatsapp {
        file: PathBuf,
        #[arg(long, default_value = "WhatsApp Importado")]
        title: String,
    },
    /// Exporta o feed ou post em formato de bridge aberta: rss | activitypub | nostr:<post_id>.
    Bridge {
        /// Formato: rss | ap-actor | ap-outbox | nostr
        format: String,
        /// Post ID (obrigatório apenas para `nostr`).
        #[arg(long)]
        post_id: Option<String>,
    },
    /// Força sincronização do snapshot Rhizome com os peers conectados ao daemon.
    Sync,
    /// Cria e assina um projeto coletivo MCP (Mycelium Commons Protocol).
    CommonsCreate {
        #[arg(long)]
        slug: String,
        #[arg(long)]
        title: String,
        #[arg(long)]
        summary: String,
        #[arg(long, default_value_t = 1000.0)]
        goal: f64,
        #[arg(long, default_value_t = 0)]
        spores_pool: u64,
        #[arg(long, default_value = "")]
        release_date: String,
    },
    /// Lista projetos MCP locais e replicados na malha.
    CommonsList,
    /// Registra uma contribuição assinada a um projeto MCP.
    CommonsContribute {
        project: String,
        #[arg(long, default_value_t = 0.0)]
        amount: f64,
        #[arg(long, default_value_t = 0)]
        spores: u64,
        #[arg(long, default_value = "")]
        message: String,
    },
    /// Lista todas as Lentes de Descoberta (nativas + customizadas).
    LensList,
    /// Cria e assina uma nova Lente de Descoberta (MEP).
    LensCreate {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long, default_value_t = 0.4)]
        reciprocity: f64,
        #[arg(long, default_value_t = 0.3)]
        replication: f64,
        #[arg(long, default_value_t = 0.2)]
        freshness: f64,
        #[arg(long, default_value_t = 0.1)]
        commons: f64,
    },
    /// Consulta telemetria viva do enxame libp2p / Physarum via Horizon HTTP.
    Swarm {
        #[arg(long, default_value_t = 7474)]
        port: u16,
    },
    /// Consulta a carteira P2P viva (saldos e transferências Schnorr).
    Wallet {
        #[arg(long, default_value_t = 7474)]
        port: u16,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum VeilCmd {
    /// Consulta o estado da sessão e do proxy VEIL Ω.
    Status,
    /// Inicia o serviço VEIL Ω e SOCKS5 proxy no nó em execução.
    Start {
        /// Modo de operação: veil (3 saltos), geo (1 salto), mix (mixnet).
        #[arg(long, default_value = "veil")]
        mode: String,
        /// Porta local SOCKS5 (default: 1080).
        #[arg(long, default_value_t = 1080)]
        port: u16,
        /// Papel do nó: client, relay, exit, bridge, all.
        #[arg(long)]
        role: Option<String>,
        /// Endereço de escuta para relay/exit/bridge.
        #[arg(long)]
        listen: Option<String>,
        /// Pinning de identidade de produção: "<nome>:<hex_identity_pubkey>" por salto.
        #[arg(long, value_name = "NOME:HEX")]
        trust: Vec<String>,
        /// Endereço público anunciado no descritor (ex.: 203.0.113.9:9050). Separado do listen.
        #[arg(long, value_name = "HOST:PORTA")]
        advertise: Option<String>,
        /// Caminho da identidade persistente do nó (GhostId + ML-KEM-1024).
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Rota a identidade Veil explicitamente (nunca implícita em reinício).
        #[arg(long)]
        rotate_identity: bool,
        /// IP de origem explícito do egresso do Exit (multi-homing).
        #[arg(long)]
        egress_bind: Option<std::net::IpAddr>,
        /// Pontes de entrada VEIL (repetível, ex.: 127.0.0.1:9001).
        #[arg(long = "bridge")]
        bridges: Vec<String>,
        /// Endereço de escuta da bridge (papel bridge).
        #[arg(long = "bridge-listen")]
        bridge_listen: Option<String>,
        /// Endereço do Guard para o qual a bridge repassa o fluxo cru (papel bridge).
        #[arg(long = "bridge-target")]
        bridge_target: Option<String>,
    },
    /// Encerra o serviço VEIL Ω e desliga o SOCKS5 proxy.
    Stop,
    /// Exibe o descritor criptográfico assinado deste nó (para compartilhar com clientes).
    Descriptor,
}

#[derive(Subcommand)]
enum MediaCmd {
    /// Publica um arquivo de vídeo na rede, fatiando em chunks com ContentId BLAKE3.
    Publish {
        /// Caminho do arquivo de vídeo local.
        file: PathBuf,
        /// Título do vídeo.
        #[arg(long)]
        title: Option<String>,
        /// Canal associado.
        #[arg(long, default_value = "ch_soberano")]
        channel: String,
        /// Descrição do vídeo.
        #[arg(long, default_value = "")]
        description: String,
        /// Tipo de conteúdo: longform, short, doc.
        #[arg(long, default_value = "longform")]
        content_type: String,
        /// Licença (ex: CC-BY-SA-4.0, AGPL-3.0).
        #[arg(long, default_value = "CC-BY-SA-4.0")]
        license: String,
        /// Tags separadas por vírgula.
        #[arg(long, default_value = "p2p,media")]
        tags: String,
        /// Tamanho do chunk em MB (default 2).
        #[arg(long, default_value_t = 2)]
        chunk_mb: usize,
    },
    /// Inspeciona ou assiste a um vídeo publicado na rede via ContentId.
    Watch {
        /// ContentId do vídeo (Qm...).
        cid: String,
    },
    /// Fixa um vídeo/chunk localmente no SporeBank para garantir persistência.
    Pin {
        /// ContentId a fixar.
        cid: String,
    },
    /// Remove fixação local.
    Unpin {
        /// ContentId a desfixar.
        cid: String,
    },
    /// Lista conteúdos fixados (pinned) no SporeBank local.
    Pins,
}

#[derive(Subcommand)]
enum ChannelCmd {
    /// Cria um novo canal assinado com a identidade deste nó.
    Create {
        handle: String,
        display_name: String,
        #[arg(long, default_value = "")]
        bio: String,
    },
    /// Publica/atualiza o manifesto do canal no SporeBank.
    Publish {
        channel_id: String,
    },
    /// Inspeciona o canal pelo ID.
    Show {
        channel_id: String,
    },
}

#[derive(Subcommand)]
enum PlaylistCmd {
    /// Cria uma nova playlist soberana.
    Create {
        title: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    /// Adiciona um vídeo (ContentId) a uma playlist.
    Add {
        playlist_id: String,
        video_cid: String,
    },
}

#[derive(Subcommand)]
enum SclerotiumCmd {
    /// Exibe o status de escleródio, leases ativas e interfaces de rede físicas detectadas.
    Status,
    /// Inspeciona o hardware de rede local para capacidades de Wake-on-LAN (WoL/ethtool).
    Hardware,
    /// Cria e assina uma GhostLease criptográfica para delegação a proxies vizinhos.
    Lease {
        /// Tempo de validade da lease em minutos (default: 1440 min = 24 horas).
        #[arg(long, default_value_t = 1440)]
        ttl_minutes: u64,
        /// Proxies autorizados (NodeIds em hex separados por vírgula). Se omitido, aberto ao quórum.
        #[arg(long, value_delimiter = ',')]
        proxies: Vec<String>,
        /// Endereço MAC para despertar via Ethernet WoL (ex: 00:11:22:33:44:55). Auto-detectado se omitido.
        #[arg(long)]
        mac: Option<String>,
    },
    /// Envia um sinal de despertar (ImpulsePacket + Magic Packet WoL) para um nó dormente.
    Wake {
        /// NodeId de destino (64 caracteres hex).
        #[arg(long)]
        target: String,
        /// Endereço MAC de destino (ex: 00:11:22:33:44:55).
        #[arg(long)]
        mac: String,
        /// Razão do despertar (urgent_compute, exclusive_content, direct_session, operator_manual).
        #[arg(long, default_value = "urgent_compute")]
        reason: String,
    },
}

#[derive(clap::Args)]
struct RootSel {
    /// Usa as raízes encontradas em /media, /run/media e /mnt.
    #[arg(long)]
    auto: bool,
    /// Caminhos das raízes (pendrives, cartões, pastas).
    roots: Vec<PathBuf>,
}

#[derive(Subcommand)]
enum RootCmd {
    /// Cria um Root K-de-N: uma raiz em cada caminho.
    Init {
        #[arg(long)]
        k: u8,
        #[arg(long, default_value = "root")]
        label: String,
        #[arg(required = true)]
        roots: Vec<PathBuf>,
    },
    /// Lista os arquivos.
    Ls {
        #[command(flatten)]
        sel: RootSel,
    },
    /// Grava arquivos/pastas: `root put R1 R2 -- foto.jpg docs/`.
    Put {
        #[command(flatten)]
        sel: RootSel,
        #[arg(last = true, required = true)]
        files: Vec<PathBuf>,
    },
    /// Lê um arquivo: `root get R1 R2 -- docs/a.txt ./a.txt`.
    Get {
        #[command(flatten)]
        sel: RootSel,
        #[arg(last = true, num_args = 2, required = true)]
        args: Vec<String>,
    },
    /// Apaga um arquivo ou pasta (o histórico guarda): `root rm R1 R2 -- a.txt`.
    Rm {
        #[command(flatten)]
        sel: RootSel,
        #[arg(last = true, required = true)]
        paths: Vec<String>,
    },
    /// Monta como pasta (pendrive): `root mount R1 R2 -- ~/Root`. Ctrl-C desmonta.
    Mount {
        #[command(flatten)]
        sel: RootSel,
        /// Permite executar programas a partir do Root (jogos, Proton/Wine).
        #[arg(long)]
        exec: bool,
        #[arg(last = true, num_args = 1, required = true)]
        mountpoint: Vec<PathBuf>,
    },
    /// Sincroniza por contato as raízes plugadas (não precisa de K).
    Sync {
        #[command(flatten)]
        sel: RootSel,
    },
    /// Recria uma raiz perdida num meio novo.
    Heal {
        #[command(flatten)]
        sel: RootSel,
        #[arg(long)]
        replace: u8,
        #[arg(long)]
        into: PathBuf,
    },
    /// Procura raízes em mídias montadas.
    Scan,
}

#[derive(Subcommand)]
enum PkarrCmd {
    /// Cria a identidade mestra do serviço anônimo (separada do NodeId do nó).
    Init {
        /// Modo privado: o endereço passa a carregar um segredo de acesso;
        /// sem ele, nem quem conhece a chave lê os endpoints.
        #[arg(long)]
        private: bool,
    },
    /// Mostra o endereço `myc1…` para entregar a quem pode achar o serviço.
    Address,
    /// Cifra, assina com a chave da época e publica nos relays Pkarr via SOCKS5.
    Publish {
        /// Preenche o endpoint Nostr com o GhostID e o relay do daemon local.
        #[arg(long)]
        from_node: bool,
        /// Pubkey Nostr (64 hex) do rendezvous.
        #[arg(long)]
        nostr_pubkey: Option<String>,
        /// Relay Nostr do rendezvous (só wss:// com domínio). Repetível.
        #[arg(long = "nostr-relay")]
        nostr_relays: Vec<String>,
        /// Endereço onion v3 (`<56>.onion[:porta]`).
        #[arg(long)]
        onion: Option<String>,
        /// Descritor de entrada VEIL (hex).
        #[arg(long)]
        veil_descriptor: Option<String>,
        /// ContentId de Plot público (64 hex). Repetível.
        #[arg(long)]
        plot: Vec<String>,
        /// Relays Pkarr (https). Default: relays públicos padrão do Pkarr.
        #[arg(long = "relay")]
        relays: Vec<String>,
        /// SOCKS5 local (VEIL ou Tor).
        #[arg(long, default_value = mycelium_pkarr::VEIL_SOCKS5_DEFAULT)]
        socks: std::net::SocketAddr,
        /// Conecta direto aos relays, REVELANDO O IP. Só para teste.
        #[arg(long)]
        unsafe_direct: bool,
        /// Republica a cada N segundos (±20% de jitter, mínimo 300) até Ctrl-C.
        #[arg(long)]
        every: Option<u64>,
        /// Só monta e verifica o pacote, sem rede.
        #[arg(long)]
        dry_run: bool,
    },
    /// Resolve um endereço `myc1…` e manda o daemon local discar os endpoints
    /// Nostr encontrados ("recebi o endereço, conectei").
    Connect {
        address: String,
        #[arg(long = "relay")]
        relays: Vec<String>,
        #[arg(long, default_value = mycelium_pkarr::VEIL_SOCKS5_DEFAULT)]
        socks: std::net::SocketAddr,
        #[arg(long)]
        unsafe_direct: bool,
    },
    /// Resolve um endereço `myc1…` e mostra os endpoints decifrados.
    Resolve {
        address: String,
        #[arg(long = "relay")]
        relays: Vec<String>,
        #[arg(long, default_value = mycelium_pkarr::VEIL_SOCKS5_DEFAULT)]
        socks: std::net::SocketAddr,
        #[arg(long)]
        unsafe_direct: bool,
    },
}

#[derive(Subcommand)]
enum SubCmd {
    /// Publica o plano de assinatura (preço, período e endereço de recebimento) para o site exibir.
    Plan {
        /// Preço em USDC.
        #[arg(long)]
        usdc: f64,
        /// Duração de cada período de assinatura, em dias.
        #[arg(long)]
        days: u32,
        /// Endereço que recebe o pagamento (USDC na Base: 0x + 40 hex).
        #[arg(long)]
        recipient: String,
    },
    /// Emite a lease de assinatura de um assinante, atrelada a um pagamento (uma tx = uma lease).
    Issue {
        /// NodeId do assinante (64 hex) — obtido com `mycelium sclerotium status` no nó dele.
        #[arg(long)]
        subscriber: String,
        /// Hash da tx de pagamento (64 hex). Reutilizar o mesmo hash é recusado (anti double-spend).
        #[arg(long)]
        payment_tx: String,
        /// Duração em dias. Default: período do plano publicado.
        #[arg(long)]
        days: Option<u32>,
        /// Sobrepõe o período: validade alvo em timestamp Unix (aceita o passado — usado
        /// para provar expiração ao vivo e para concessões de janela explícita).
        #[arg(long)]
        valid_until: Option<u64>,
        /// Marca que a tx foi verificada on-chain (`mycelium-economy verify-base-usdc`).
        #[arg(long)]
        payment_verified: bool,
        /// Caminho da lease emitida. Default: {home}/premium/leases/<assinante>.json (JSON compacto).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verifica uma lease de assinatura (assinatura ed25519, validade e capacidade). Exit 0 = válida.
    Verify {
        /// Arquivo da lease (JSON compacto ou pretty).
        #[arg(long)]
        lease: PathBuf,
        /// NodeId esperado do portador — confere se a lease foi emitida para ele.
        #[arg(long)]
        subscriber: Option<String>,
    },
}

#[derive(Subcommand)]
enum StoreCmd {
    /// Lista jogos e softwares legados cadastrados no catálogo P2P
    List,
    /// Mostra as capacidades de emulação do sistema host (QEMU, MAME, RetroArch, bwrap)
    Caps,
    /// Executa um jogo ou software legado por ID
    Launch {
        #[arg(long)]
        id: String,
        /// Força o motor de execução (native, retroarch, mame, qemu, wasm, cloud)
        #[arg(long)]
        engine: Option<String>,
        /// Sandboxing estrito com bubblewrap
        #[arg(long, default_value_t = false)]
        sandbox: bool,
    },
    /// Publica uma nova ROM / software legado no SporeBank
    Publish {
        #[arg(long)]
        id: String,
        #[arg(long)]
        title: String,
        #[arg(long)]
        platform: String,
        #[arg(long)]
        binary: PathBuf,
        /// Licença de distribuição (shareware, freeware, open_source, public_domain, proprietary).
        /// Default: proprietary (só local / BYOR — não distribuído na rede)
        #[arg(long, default_value = "proprietary")]
        license: String,
    },
}

#[derive(Subcommand)]
enum RepoCmd {
    /// Publica uma árvore de código como Plot multi-leaf no SporeBank (DHT + gossip)
    Publish {
        /// Diretório raiz do repositório a publicar.
        #[arg(short, long)]
        dir: PathBuf,
        /// Nome persistente do repositório no Giggs.
        #[arg(long)]
        repository: Option<String>,
        /// Branch atualizada por compare-and-swap.
        #[arg(long, default_value = "main")]
        branch: String,
        /// Publica somente se a branch ainda apontar para este ContentId.
        #[arg(long)]
        expected_previous_cid: Option<String>,
        /// Mensagem/descrição do commit (ex.: "v0.1.0 — store P2P").
        #[arg(short, long, default_value = "mycelium-launcher-store")]
        message: String,
    },
    /// Reconstrói uma árvore de código a partir de um ContentId
    Clone {
        /// ContentId (Qm…) do repo publicado.
        #[arg(long)]
        cid: String,
        /// Diretório de destino da árvore reconstruída.
        #[arg(short, long)]
        dest: PathBuf,
    },
    /// Executa Build e Test sobre um ContentId, sem deploy.
    Validate {
        #[arg(long)]
        cid: String,
    },
    /// Recupera e verifica uma atestação persistida.
    Attestation {
        #[arg(long)]
        cid: String,
    },
    /// Lista os repos disponíveis no SporeBank local
    List,
}

#[derive(Subcommand)]
enum CandidateCmd {
    /// Escuta mensagens backchannel (NIP-44, kind 39406) e re-anuncia presença.
    Listen {
        #[arg(long)]
        r#loop: bool,
    },
    /// Envia texto cifrado a um ghost peer (`--to` = pubkey hex 64 chars).
    Send {
        #[arg(long)]
        to: String,
        #[arg(short = 'm', long)]
        message: String,
    },
    /// Mostra o GhostID da sessão local (para o outro lado usar em `--to`).
    Whoami,
    /// Apaga `candidate.session` (novo GhostID na próxima vez).
    Reset,
}

#[derive(Subcommand)]
enum EntropyCmd {
    /// Fragmenta um segredo em N Shades.
    Shatter {
        #[arg(short, long)]
        secret: String,
        #[arg(short = 'k', long, default_value_t = 3)]
        threshold: u8,
        #[arg(short = 'n', long, default_value_t = 5)]
        total: u8,
    },
    /// Reconstrói o segredo a partir das Shades em custódia.
    Reconstruct {
        #[arg(short = 'k', long, default_value_t = 3)]
        threshold: u8,
    },
    /// Mostra as Shades armazenadas.
    Status,
}

#[derive(Subcommand)]
enum MintCmd {
    /// Mostra época ativa, suprimento, orçamento e paridade 1 MYC = 8 USDC.
    Status,
    /// Constrói, assina e envia um WorkClaim com hashcash anti-Sybil ao daemon.
    Claim {
        /// Identificador do trabalho (ContentId hex ou prefixo Qm).
        #[arg(long)]
        work_id: String,
        /// Tipo de trabalho útil: seeding | compute | relay.
        #[arg(long, default_value = "compute")]
        kind: String,
        /// Quantidade de unidades de trabalho verificadas.
        #[arg(long, default_value_t = 1)]
        units: u64,
        /// Época alvo da mainnet.
        #[arg(long, default_value_t = 0)]
        epoch: u64,
        /// Chain ID da mainnet.
        #[arg(long, default_value = "mycelium-mainnet")]
        chain_id: String,
        /// Seed ed25519 (64 chars hex) da contraparte que co-assina a entrega.
        #[arg(long)]
        counterparty_seed: String,
        /// Dificuldade do hashcash em zero bits.
        #[arg(long, default_value_t = mycelium_mint::DEFAULT_MIN_HASHCASH_BITS)]
        hashcash_bits: u8,
    },
}

#[derive(Subcommand)]
enum GatewayCmd {
    /// Testa um SOCKS5 CONNECT via VEIL para o host:443, SEM enviar dados financeiros.
    VeilProbe {
        /// Nome DNS público (porta 443). Sem DNS local.
        #[arg(long)]
        host: String,
    },
    /// Roteia e executa um pagamento pelo Meta-Gateway (prefixos: pix:, swift:, brics:, myc:).
    Pay {
        /// Destinatário qualificado (ex.: pix:chave@email.com, swift:CHASUS33XXX, brics:node-09, myc:<node_id>).
        #[arg(long = "to")]
        to: String,
        /// Valor em micro-unidades (6 casas decimais; ex.: 10000000 = 10.000000).
        #[arg(long = "amount-micros")]
        amount_micros: u64,
        /// Moeda da intenção (MYC, USDC, BRL, USD).
        #[arg(long, default_value = "MYC")]
        currency: String,
        /// Flag de conformidade SWIFT CSP/CSCF (obrigatória para swift:).
        #[arg(long = "swift-csp-compliant")]
        swift_csp_compliant: bool,
        /// ID do log da Secure Zone (obrigatório para swift:).
        #[arg(long = "secure-zone-log")]
        secure_zone_log: Option<String>,
        /// Hora local (0..23) para checagem de limite noturno do Pix.
        #[arg(long = "local-hour")]
        local_hour: Option<u64>,
        /// Consentimento expresso para preparar payload de destino externo
        /// (Pix/SWIFT/BRICS; não significa pagamento efetivamente enviado).
        #[arg(long = "allow-external-disclosure")]
        allow_external_disclosure: bool,
        /// Mostra payload completo, inclusive dados sensíveis (oculto por padrão).
        #[arg(long = "show-native-payload")]
        show_native_payload: bool,
    },
}

#[derive(Subcommand)]
enum SeedsCmd {
    /// Lista seeds em `{home}/seeds.txt`.
    List,
    /// Adiciona uma multiaddr ao seed book.
    Add { addr: String },
    /// Baixa o catálogo público e mescla no seed book.
    Fetch {
        #[arg(long)]
        url: Option<String>,
        /// Nome DNS TXT do Spore Bank. Sem valor → default `_mycelium.seeds.duckdns.org`.
        #[arg(long, num_args = 0..=1, default_missing_value = DEFAULT_DNS_SEED_NAME)]
        dns: Option<String>,
    },
    /// Catálogo estruturado de seeds públicas e privadas (`{home}/seeds/catalog.json`).
    Catalog {
        #[command(subcommand)]
        action: SeedCatalogCmd,
    },
}

#[derive(Subcommand)]
enum SeedCatalogCmd {
    /// Lista seeds do catálogo.
    List {
        /// Filtro de visibilidade: public | private | all.
        #[arg(long, default_value = "all")]
        visibility: String,
    },
    /// Adiciona um seed ao catálogo.
    Add {
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        name: String,
        #[arg(long)]
        multiaddr: String,
        /// public | private
        #[arg(long, default_value = "public")]
        visibility: String,
        #[arg(long)]
        membrane: Option<String>,
        #[arg(long)]
        region: Option<String>,
        #[arg(long)]
        operator: Option<String>,
        /// Opera como circuit relay v2.
        #[arg(long, default_value_t = false)]
        relay: bool,
        /// Inbound verificado.
        #[arg(long, default_value_t = false)]
        verified: bool,
    },
    /// Remove um seed do catálogo por id.
    Remove {
        #[arg(long)]
        id: String,
    },
    /// Exporta as seeds públicas no formato `seeds/mainnet.txt`.
    Export {
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

/// Nenhum destes comandos implanta serviços ou replica conteúdo por conta própria.
#[derive(Subcommand)]
enum HabitatCmd {
    /// Mostra respostas 2xx efetivamente retornadas pelo proxy Event Horizon.
    Usage {
        /// Nome de serviço Habitat registrado no mesmo nó.
        name: String,
        /// Estimativa MANUAL de MYC micros por resposta (não cria cobrança).
        #[arg(long)]
        estimate_myc_micros_per_response: Option<u64>,
    },
    /// Cria manifesto assinado pelo nó; --visibility public NÃO publica nada.
    Register {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "data", value_parser = ["data", "compute", "site"])]
        kind: String,
        #[arg(long, default_value = "local", value_parser = ["local", "private", "public"])]
        visibility: String,
        /// Quantidade desejada; só há provisionamento local nesta fase.
        #[arg(long, default_value_t = 1)]
        replicas: u8,
        /// NodeId autorizado a visualizar metadados privados (repetível).
        #[arg(long = "peer")]
        peers: Vec<String>,
    },
    /// Lista manifestos do registro local validando assinaturas.
    List,
    /// Inspeciona o manifesto e a assinatura de um serviço.
    Inspect { name: String },
}

fn main() {
    let cli = Cli::parse();

    let filter = if matches!(cli.command, Commands::ChamberServe { .. }) {
        "warn"
    } else {
        "info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(false)
        .compact()
        .init();

    let home = resolve_home(cli.home);
    let rt = tokio::runtime::Runtime::new().expect("tokio");

    let result = match cli.command {
        Commands::Sprout { contribute } => rt.block_on(sprout(&home, &contribute)),
        Commands::Daemon {
            contribute,
            bootstrap,
            seed_file,
            public_bootstrap,
            bootstrap_url,
            listen,
            horizon_port,
            no_mdns,
            announce_ip,
            announce_ip6,
            relay,
            sporocarp,
            membrane,
            assume_reachable,
            webrtc,
            webrtc_port,
            nostr_transport,
            no_nostr_transport,
            nostr_relay,
            licensed_peers,
            upnp,
            veil,
            veil_socks5,
            veil_mode,
            veil_role,
            veil_listen,
            veil_guards,
            veil_middles,
            veil_exits,
            veil_trust,
            veil_advertise,
            veil_identity,
            veil_rotate_identity,
            veil_egress_bind,
            veil_bridges,
            veil_bridge_listen,
            veil_bridge_target,
            anonymous,
            anon_socks,
            mint_mainnet,
            mint_chain_id,
            mint_quorum,
        } => {
            #[cfg(not(feature = "license"))]
            let _ = licensed_peers;
            rt.block_on(daemon(
            &home,
            &contribute,
            DaemonOptions {
                contribute: None, // preenchido abaixo
                bootstrap,
                horizon_port,
                listen,
                seed_file,
                public_bootstrap,
                bootstrap_url,
                no_mdns,
                announce_ip,
                announce_ip6,
                enable_relay: relay || sporocarp,
                sporocarp,
                membrane,
                assume_reachable,
                enable_webrtc: webrtc,
                webrtc_port,
                nostr_transport: if no_nostr_transport {
                    Some(false)
                } else if nostr_transport {
                    Some(true)
                } else {
                    None
                },
                nostr_relay,
                #[cfg(feature = "license")]
                licensed_peers: if licensed_peers.is_empty() {
                    None
                } else {
                    Some(licensed_peers.into_iter().collect())
                },
                veil_enabled: veil,
                veil_socks5_addr: veil_socks5,
                veil_mode,
                veil_role,
                veil_listen,
                veil_guards,
                veil_middles,
                veil_exits,
                veil_trust,
                veil_advertise,
                veil_identity,
                veil_rotate_identity,
                veil_egress_bind,
                veil_bridges,
                veil_bridge_listen,
                veil_bridge_target,
                anonymous_socks5: anonymous.then_some(anon_socks),
                mint_mainnet,
                mint_chain_id,
                mint_quorum,
            },
            upnp,
            ))
        }
        Commands::Habitat { action } => rt.block_on(habitat_cmd(&home, action)),
        Commands::Status => rt.block_on(status(&home)),
        Commands::Sow {
            message,
            path,
            content,
            qel,
            nostr,
            ghost,
            recipient,
            hybrid,
        } => rt.block_on(sow_cmd(
            &home, message, path, content, qel, nostr, ghost, recipient, hybrid,
        )),
        Commands::PublishExisting {
            plot,
            nostr,
            qel,
            max_attempts,
            timeout,
            backoff_ms,
        } => rt.block_on(publish_existing_cmd(
            &home,
            plot,
            nostr,
            qel,
            max_attempts,
            timeout,
            backoff_ms,
        )),
        Commands::Signal {
            plot,
            quorum,
            ion,
            name,
        } => rt.block_on(rpc(
            &home,
            Request::Signal {
                plot,
                quorum,
                ion,
                name,
            },
        )),
        Commands::Resonate { signal } => {
            rt.block_on(rpc(&home, Request::Resonate { signal }))
        }
        Commands::Recall {
            plot,
            qel,
            nostr,
            qel_threshold,
            hybrid,
        } => rt.block_on(recall_cmd(&home, plot, qel, nostr, qel_threshold, hybrid)),
        Commands::Bootstrap { addr } => {
            rt.block_on(rpc(&home, Request::Bootstrap { addr }))
        }
        Commands::Seeds { action } => seeds_cmd(&home, action),
        Commands::IsotopePut { key, value, clock } => rt.block_on(rpc(
            &home,
            Request::IsotopePut { key, value, clock },
        )),
        Commands::IsotopeGet { key } => rt.block_on(isotope_get_poll(&home, key)),
        Commands::Deploy {
            plot,
            message,
            path,
            content,
            ion,
            name,
            quorum,
            timeout,
        } => rt.block_on(deploy(
            &home,
            DeployOpts {
                plot,
                message,
                path,
                content,
                ion,
                name,
                quorum,
                timeout,
            },
        )),
        Commands::Shutdown => rt.block_on(rpc(&home, Request::Shutdown)),
        Commands::Balance => rt.block_on(rpc(&home, Request::Balance)),
        Commands::IonMigrate { ion, target } => rt.block_on(rpc(&home, Request::IonMigrate { ion, target })),
        Commands::Zones => rt.block_on(rpc(&home, Request::Zones)),
        Commands::SeedRepo { name, url, commit, description } => {
            rt.block_on(rpc(&home, Request::SeedRepo { name, url, commit, description }))
        }
        Commands::SeedCode { path, name, description, ion, visibility } => {
            rt.block_on(seed_code_cmd(&home, path, name, description, ion, visibility))
        }
        Commands::RecallCode { plot, output } => {
            rt.block_on(recall_code_cmd(&home, plot, output))
        }
        Commands::Repos => rt.block_on(rpc(&home, Request::Repos)),
        Commands::LicenseVerify { vendor_key, device_entropy, sku, payload, signature, now, peer_id } => {
            #[cfg(feature = "license")]
            {
                let unix_now = now.unwrap_or_else(|| std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0));
                let req = Request::VerifyLicense {
                    vendor_public_key: vendor_key,
                    device_entropy,
                    sku,
                    license_payload: payload,
                    signature,
                    unix_now_secs: unix_now,
                    peer_id,
                };
                rt.block_on(rpc(&home, req))
            }
            #[cfg(not(feature = "license"))]
            {
                let _ = (vendor_key, device_entropy, sku, payload, signature, now, peer_id);
                eprintln!("licença exige feature `license`. Compile com --features license.");
                std::process::exit(1);
            }
        }
        Commands::RegisterPeer { peer_id } => {
            #[cfg(feature = "license")]
            {
                rt.block_on(rpc(&home, Request::RegisterLicensedPeer { peer_id }))
            }
            #[cfg(not(feature = "license"))]
            {
                let _ = peer_id;
                eprintln!("admissão licenciada exige feature `license`. Compile com --features license.");
                std::process::exit(1);
            }
        }
        Commands::Bolt11 { invoice } => {
            #[cfg(feature = "bolt11")]
            {
                rt.block_on(rpc(&home, Request::Bolt11Validate { bolt11: invoice }))
            }
            #[cfg(not(feature = "bolt11"))]
            {
                let _ = invoice;
                eprintln!("BOLT11 exige feature `bolt11`. Compile com --features bolt11.");
                std::process::exit(1);
            }
        }
        Commands::Entropy { action } => rt.block_on(entropy_cmd(&home, action)),
        Commands::Mint { action } => rt.block_on(mint_cmd(&home, action)),
        Commands::Gateway { action } => rt.block_on(gateway_cmd(&home, action)),
        Commands::Candidate {
            cmd,
            r#loop,
            once: _,
            relays,
        } => rt.block_on(candidate_cmd(&home, cmd, r#loop, relays)),
        Commands::ChamberServe { port, ion, root } => {
            rt.block_on(chamber_serve(port, ion, root))
        }
        Commands::Store { action } => store_cmd(&home, action),
        Commands::Repo { action } => rt.block_on(repo_cmd(&home, action)),
        Commands::Field { port } => {
            println!("[🌌 TheField] A Forja Soberana de Repositórios Git P2P & Signals está disponível em:");
            println!("    👉 Web UI      : http://127.0.0.1:{port}/field/");
            println!("    👉 API Repos   : http://127.0.0.1:{port}/field/api/repos");
            println!("    👉 API Signals : http://127.0.0.1:{port}/field/api/signals");
            println!();
            println!("Comandos rápidos para gerenciar repositórios no TheField:");
            println!("    mycelium repo publish --dir ./projeto --repository meu-repo --branch main");
            println!("    mycelium repo clone --cid Qm... --dest ./copia");
            println!("    mycelium repo validate --cid Qm...");
            Ok(())
        }
        Commands::Veil { action } => rt.block_on(veil_cmd(&home, action)),
        Commands::Media { action } => rt.block_on(media_cmd(&home, action)),
        Commands::Channel { action } => rt.block_on(channel_cmd(&home, action)),
        Commands::Playlist { action } => rt.block_on(playlist_cmd(&home, action)),
        Commands::Sclerotium { action } => rt.block_on(sclerotium_cmd(&home, action)),
        Commands::Sub { action } => sub_cmd(&home, action),
        Commands::Pkarr { action } => rt.block_on(pkarr_cmd(&home, action)),
        Commands::Root { action } => root_cmd(action),
        Commands::Rhizome { action } => rt.block_on(rhizome_cmd(&home, action)),
    };

    if let Err(e) = result {
        eprintln!("[🍄] {e}");
        std::process::exit(1);
    }
}

fn resolve_home(override_home: Option<PathBuf>) -> PathBuf {
    if let Some(p) = override_home {
        return p;
    }
    directories::ProjectDirs::from("network", "Mycelium", "mycelium")
        .map(|d| d.data_local_dir().to_path_buf())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".mycelium")))
        .unwrap_or_else(|| PathBuf::from(".mycelium"))
}

fn parse_membrane(s: &str) -> Result<mycelium_core::Membrane, String> {
    s.parse()
}

fn seeds_cmd(home: &PathBuf, action: SeedsCmd) -> Result<(), String> {
    let path = home.join("seeds.txt");
    match action {
        SeedsCmd::List => {
            let mut book = SeedBook::new();
            book.load_file(&path).map_err(|e| e.to_string())?;
            if book.is_empty() {
                println!("[🍄] seed book vazio ({})", path.display());
                println!("[🍄] dica: mycelium seeds fetch  ou  --public-bootstrap");
            } else {
                println!("[🍄] {} seeds em {}", book.len(), path.display());
                for s in book.as_strings() {
                    println!("  {s}");
                }
            }
            Ok(())
        }
        SeedsCmd::Add { addr } => {
            let mut book = SeedBook::new();
            book.load_file(&path).map_err(|e| e.to_string())?;
            book.add(&addr).map_err(|e| e.to_string())?;
            book.save_file(&path).map_err(|e| e.to_string())?;
            println!("[🍄] seed adicionada: {addr}");
            Ok(())
        }
        SeedsCmd::Fetch { url, dns } => {
            let mut book = SeedBook::new();
            book.load_file(&path).map_err(|e| e.to_string())?;
            let mut added = 0usize;
            if let Some(name) = dns {
                let name = if name.is_empty() {
                    DEFAULT_DNS_SEED_NAME.to_string()
                } else {
                    name
                };
                let n = book.fetch_dns_txt(&name).map_err(|e| e.to_string())?;
                added += n;
                println!("[🍄] +{n} seeds DNS TXT `{name}`");
            } else if url.is_none() {
                // Sem flags: HTTP legado (comportamento anterior).
                let u = DEFAULT_BOOTSTRAP_URL.to_string();
                let n = book.fetch_url(&u).map_err(|e| e.to_string())?;
                added += n;
                println!("[🍄] +{n} seeds de {u}");
            }
            if let Some(u) = url {
                let n = book.fetch_url(&u).map_err(|e| e.to_string())?;
                added += n;
                println!("[🍄] +{n} seeds de {u}");
            }
            book.save_file(&path).map_err(|e| e.to_string())?;
            println!("[🍄] total +{added} → {}", path.display());
            for s in book.as_strings() {
                println!("  {s}");
            }
            Ok(())
        }
        SeedsCmd::Catalog { action } => seed_catalog_cmd(home, action),
    }
}

fn seed_catalog_cmd(home: &PathBuf, action: SeedCatalogCmd) -> Result<(), String> {
    use mycelium_hyphae::{SeedCatalog, SeedEntry, SeedVisibility};
    match action {
        SeedCatalogCmd::List { visibility } => {
            let catalog = SeedCatalog::open(home)?;
            let filter = match visibility.as_str() {
                "all" => None,
                "public" => Some(SeedVisibility::Public),
                "private" => Some(SeedVisibility::Private),
                other => {
                    return Err(format!(
                        "visibilidade desconhecida: '{other}' (use public|private|all)"
                    ))
                }
            };
            let entries = catalog.list(filter);
            println!("\n[🍄] Catálogo de seeds ({}) — {}", entries.len(), SeedCatalog::catalog_path(home).display());
            for s in entries {
                let verified = if s.verified { "✓" } else { "✗" };
                println!("  • [{}] {} ({})", s.visibility.as_str(), s.id, s.name);
                println!("      multiaddr : {}", s.multiaddr);
                println!(
                    "      meta      : membrana={} região={} operador={} relay={} inbound={}",
                    s.membrane.as_deref().unwrap_or("-"),
                    s.region.as_deref().unwrap_or("-"),
                    s.operator.as_deref().unwrap_or("-"),
                    s.relay,
                    verified
                );
            }
            Ok(())
        }
        SeedCatalogCmd::Add {
            id,
            name,
            multiaddr,
            visibility,
            membrane,
            region,
            operator,
            relay,
            verified,
        } => {
            let visibility = match visibility.as_str() {
                "public" => SeedVisibility::Public,
                "private" => SeedVisibility::Private,
                other => return Err(format!("visibilidade inválida: '{other}' (use public|private)")),
            };
            let mut catalog = SeedCatalog::open(home)?;
            catalog.add(SeedEntry {
                id: id.unwrap_or_default(),
                name,
                multiaddr,
                visibility,
                membrane,
                region,
                operator,
                relay,
                verified,
                last_seen: None,
                notes: None,
            })?;
            catalog.save(home)?;
            println!("[🍄] Seed adicionada ao catálogo.");
            Ok(())
        }
        SeedCatalogCmd::Remove { id } => {
            let mut catalog = SeedCatalog::open(home)?;
            if catalog.remove(&id) {
                catalog.save(home)?;
                println!("[🍄] Seed '{id}' removida.");
            } else {
                println!("[🍄] Seed '{id}' não encontrada.");
            }
            Ok(())
        }
        SeedCatalogCmd::Export { out } => {
            let catalog = SeedCatalog::open(home)?;
            let lines = catalog.to_mainnet_lines();
            let n_seeds = lines.iter().filter(|l| !l.starts_with('#')).count();
            let dest = out.unwrap_or_else(|| home.join("seeds").join("mainnet.txt"));
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let mut body = String::from("# Mycelium Network — seeds públicas verificadas (do catálogo)\n# Só entradas com inbound verificado entram aqui.\n");
            for l in &lines {
                body.push_str(l);
                body.push('\n');
            }
            std::fs::write(&dest, body).map_err(|e| format!("gravar {}: {e}", dest.display()))?;
            println!("[🍄] Exportadas {} seeds públicas verificadas → {}", n_seeds, dest.display());
            Ok(())
        }
    }
}

async fn sprout(home: &PathBuf, contribute: &str) -> Result<(), String> {
    println!("[🍄] Semente germinando...");
    let store = NodeStore::open(home).map_err(|e| e.to_string())?;
    let gland = store.load_or_create_gland().map_err(|e| e.to_string())?;
    let resources = Resources::from_str(contribute).map_err(|e| e.to_string())?;
    store
        .save_resources(&resources)
        .map_err(|e| e.to_string())?;
    let mut ledger = store.load_ledger();
    if ledger.history().is_empty() {
        ledger.pledge(&resources);
        store.save_ledger(&ledger).map_err(|e| e.to_string())?;
    }
    println!(
        "[🍄] Identidade persistida: {} (NodeId {})",
        gland.node_id().short(),
        gland.node_id()
    );
    println!("[🍄] Home: {}", home.display());
    println!("[🍄] Pronto. Suba o organismo com: mycelium daemon");
    Ok(())
}

async fn daemon(
    home: &PathBuf,
    contribute: &str,
    mut opts: DaemonOptions,
    upnp_flag: bool,
) -> Result<(), String> {
    let resources = Resources::from_str(contribute).map_err(|e| e.to_string())?;
    opts.contribute = Some(resources);
    if let Some(proxy) = opts.anonymous_socks5 {
        // mDNS anuncia o nó na LAN: o modo anônimo o desliga sempre.
        opts.no_mdns = true;
        if upnp_flag {
            return Err("modo anônimo: --upnp abriria porta no roteador".into());
        }
        println!("[🍄] 🕶️  modo anônimo — todo tráfego via SOCKS5 {proxy} (fail-closed)");
    }
    println!("[🍄] Despertando organismo em {}…", home.display());
    println!("[🍄] Event Horizon em http://127.0.0.1:{}/", opts.horizon_port);
    if upnp_flag {
        println!("[🍄] --upnp ignorado — Política de Membrana (sem STUN/UPnP)");
    }
    if opts.public_bootstrap {
        println!(
            "[🍄] Bootstrap público: {}",
            opts.bootstrap_url
                .as_deref()
                .unwrap_or(DEFAULT_BOOTSTRAP_URL)
        );
    }
    if opts.no_mdns {
        println!("[🍄] mDNS desligado — só seed book / bootstrap");
    }
    if let Some(ip) = &opts.announce_ip {
        println!("[🍄] Announce IP (raiz IPv4 declarada): {ip}");
    }
    if let Some(ip6) = &opts.announce_ip6 {
        println!("[🍄] Announce IPv6: {ip6}");
    }
    if let Some(m) = opts.membrane {
        println!("[🍄] Membrana forçada: {m}");
    }
    if opts.sporocarp {
        println!("[🍄] Sporocarp (relay + DNS) ligado — membrana esporocarp");
    } else if opts.enable_relay {
        println!("[🍄] Relay server (circuit v2) ligado");
    }
    if !opts.listen.is_empty() {
        println!("[🍄] Listen: {:?}", opts.listen);
    } else {
        println!("[🍄] Listen: auto conforme membrana (folha=loopback IPv4)");
    }
    if std::env::var("MYCELIUM_CONTROL_TOKEN").ok().filter(|t| !t.is_empty()).is_some() {
        println!("[🍄] Control socket com auth (MYCELIUM_CONTROL_TOKEN)");
    }
    println!(
        "[🍄] Ctrl-C ou `mycelium --home {} shutdown` para hibernar",
        home.display()
    );

    let home_for_signal = home.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let sock = home_for_signal.join("mycelium.sock");
        let _ = call(&sock, Request::Shutdown).await;
    });

    run_daemon(home.clone(), opts)
        .await
        .map_err(|e| e.to_string())
}

async fn status(home: &PathBuf) -> Result<(), String> {
    let sock = home.join("mycelium.sock");
    // Android/shell: Unix socket pode falhar; `call` cai para `mycelium.tcp`.
    if sock.exists() || sock.with_extension("tcp").exists() {
        return print_response(call(&sock, Request::Status).await?);
    }
    let store = NodeStore::open(home).map_err(|e| e.to_string())?;
    let gland = store.load_or_create_gland().map_err(|e| e.to_string())?;
    let ledger = store.load_ledger();
    let state = store.load_state();
    let addrs = store.load_listen_addrs();
    let ion_names: Vec<_> = state.ions.iter().map(|i| i.name.clone()).collect();
    println!("[🍄] Estado offline (daemon não está rodando)");
    println!("    home     : {}", home.display());
    println!("    NodeId   : {}", gland.node_id());
    println!("    listen   : {addrs:?}");
    println!("    ions     : {ion_names:?}");
    println!("    signals  : {}", state.field.len());
    println!(
        "    ATP={} Enzymes={} Mycelia={} Spores={} Resilience={}",
        ledger.balance(mycelium_core::Nutrient::Atp),
        ledger.balance(mycelium_core::Nutrient::Enzymes),
        ledger.balance(mycelium_core::Nutrient::Mycelia),
        ledger.balance(mycelium_core::Nutrient::Spores),
        ledger.balance(mycelium_core::Nutrient::Resilience),
    );
    Ok(())
}

async fn candidate_cmd(
    home: &PathBuf,
    cmd: Option<CandidateCmd>,
    do_loop: bool,
    relays: Vec<String>,
) -> Result<(), String> {
    #[cfg(not(feature = "nostr"))]
    {
        let _ = (home, cmd, do_loop, relays);
        return Err(
            "`mycelium candidate` requer `cargo build -p mycelium-cli --features nostr`".into(),
        );
    }
    #[cfg(feature = "nostr")]
    {
        use mycelium_nostr::{
            candidate_sleep_secs, run_candidate_round, run_listen_round, send_backchannel,
            CandidateSession, RelayPool,
        };
        use std::collections::HashSet;

        let pool = if relays.is_empty() {
            RelayPool::default_public()
        } else {
            RelayPool::new(relays)
        };

        match cmd {
            None => {
                loop {
                    match run_candidate_round(&pool).await {
                        Ok(r) => {
                            println!(
                                "[🍄] candidate: published={} discovered={} peers={} ghost={}…",
                                r.published,
                                r.discovered,
                                r.peer_count,
                                &r.self_ghost[..r.self_ghost.len().min(12)]
                            );
                            for p in &r.peers {
                                println!("  peer {}", p);
                            }
                            if r.peer_count == 0 {
                                println!(
                                    "[🍄] candidate: ainda 0 peers (ponto fixo). Outra folha no mesmo relay?"
                                );
                            } else {
                                println!(
                                    "[🍄] candidate: peers vistos — use `listen`/`send` para backchannel"
                                );
                            }
                        }
                        Err(e) => eprintln!("[🍄] candidate round falhou: {e}"),
                    }
                    if !do_loop {
                        break;
                    }
                    let sleep = candidate_sleep_secs();
                    println!("[🍄] candidate: próxima ronda em {sleep}s (jitter)");
                    tokio::time::sleep(std::time::Duration::from_secs(sleep)).await;
                }
                Ok(())
            }
            Some(CandidateCmd::Whoami) => {
                let (sess, _) = CandidateSession::load_or_create(home).map_err(|e| e.to_string())?;
                println!("[🍄] candidate ghost: {}", sess.pk_hex);
                println!("    sessão: {}", CandidateSession::path(home).display());
                println!("    TTL restante ~{}s (desde criação)", {
                    let age = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                        .saturating_sub(sess.created_at);
                    sess.ttl_secs.saturating_sub(age)
                });
                Ok(())
            }
            Some(CandidateCmd::Reset) => {
                CandidateSession::clear(home).map_err(|e| e.to_string())?;
                println!("[🍄] candidate.session apagada");
                Ok(())
            }
            Some(CandidateCmd::Send { to, message }) => {
                let to = to.trim().to_lowercase();
                let (_, ghost) =
                    CandidateSession::load_or_create(home).map_err(|e| e.to_string())?;
                println!(
                    "[🍄] candidate send: from={}… → to={}…",
                    &ghost.nostr_pubkey_hex()[..12],
                    &to[..to.len().min(12)]
                );
                let id = send_backchannel(&pool, &ghost, &to, &message)
                    .await
                    .map_err(|e| e.to_string())?;
                println!("[🍄] enviado event {id}");
                println!(
                    "[🍄] o destinatário precisa de `mycelium candidate listen` com esse ghost"
                );
                Ok(())
            }
            Some(CandidateCmd::Listen { r#loop: listen_loop }) => {
                let (sess, ghost) =
                    CandidateSession::load_or_create(home).map_err(|e| e.to_string())?;
                println!("[🍄] candidate listen ghost: {}", sess.pk_hex);
                println!("[🍄] o outro lado: mycelium candidate send --to {} -m \"…\"", sess.pk_hex);
                let mut seen = HashSet::new();
                loop {
                    match run_listen_round(&pool, &ghost).await {
                        Ok((published, msgs)) => {
                            println!(
                                "[🍄] listen: announced={published} inbox={}",
                                msgs.len()
                            );
                            for m in msgs {
                                if seen.insert(m.event_id.clone()) {
                                    println!(
                                        "[🍄] ← {}… : {}",
                                        &m.from[..m.from.len().min(12)],
                                        m.text
                                    );
                                }
                            }
                        }
                        Err(e) => eprintln!("[🍄] listen round falhou: {e}"),
                    }
                    if !listen_loop {
                        break;
                    }
                    let sleep = 15u64;
                    tokio::time::sleep(std::time::Duration::from_secs(sleep)).await;
                }
                Ok(())
            }
        }
    }
}

async fn entropy_cmd(home: &PathBuf, action: EntropyCmd) -> Result<(), String> {
    let sock = home.join("mycelium.sock");
    match action {
        EntropyCmd::Shatter {
            secret,
            threshold,
            total,
        } => {
            let resp = call(
                &sock,
                Request::EntropyShatter {
                    secret,
                    threshold,
                    total,
                },
            )
            .await?;
            print_response(resp)
        }
        EntropyCmd::Reconstruct { threshold } => {
            // Poll com retry pra dar tempo das shades chegarem via gossip
            let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
            let mut last = String::new();
            while tokio::time::Instant::now() < deadline {
                match call(&sock, Request::EntropyReconstruct { threshold }).await? {
                    Response::Ok { message } => {
                        println!("[🍄] {message}");
                        return Ok(());
                    }
                    Response::Err { message } => {
                        last = message;
                        if last.contains("não") && last.contains("custódia")  {
                            // erro definitivo, não de timeout
                            return Err(last);
                        }
                    }
                    Response::Status(_) => return Err("resposta inesperada".into()),
                    _ => return Err("resposta inesperada".into()),
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
            Err(format!("entropy reconstruct timeout: {last}"))
        }
        EntropyCmd::Status => {
            let resp = call(&sock, Request::EntropyStatus).await?;
            print_response(resp)
        }
    }
}

async fn mint_cmd(home: &PathBuf, action: MintCmd) -> Result<(), String> {
    let sock = mycelium_node::NodeStore::open(home)
        .map_err(|e| e.to_string())?
        .socket_path();
    match action {
        MintCmd::Status => {
            let resp = call(&sock, Request::MintStatus).await?;
            print_response(resp)
        }
        MintCmd::Claim {
            work_id,
            kind,
            units,
            epoch,
            chain_id,
            counterparty_seed,
            hashcash_bits,
        } => {
            let store = mycelium_node::NodeStore::open(home).map_err(|e| e.to_string())?;
            let gland = store.load_or_create_gland().map_err(|e| e.to_string())?;
            let ledger = store.load_ledger();
            let work_cid: mycelium_core::ContentId = work_id.parse()?;
            let tx_kind: mycelium_nutrients::TxKind = kind.parse()?;

            let seed_bytes = hex::decode(counterparty_seed.trim())
                .map_err(|e| format!("counterparty_seed hex inválido: {e}"))?;
            let seed_arr: [u8; 32] = seed_bytes
                .try_into()
                .map_err(|_| "counterparty_seed precisa de exatamente 32 bytes (64 hex)".to_string())?;
            let counterparty_sk = ed25519_dalek::SigningKey::from_bytes(&seed_arr);

            let claim = mycelium_mint::WorkClaim::build_signed(
                &chain_id,
                epoch,
                gland.node_id(),
                &counterparty_sk,
                work_cid,
                tx_kind,
                units,
                ledger.balance(mycelium_core::Nutrient::Spores),
                ledger.balance(mycelium_core::Nutrient::Resilience),
                hashcash_bits,
            );
            let resp = call(&sock, Request::MintClaim { claim }).await?;
            print_response(resp)
        }
    }
}

async fn gateway_cmd(home: &PathBuf, action: GatewayCmd) -> Result<(), String> {
    let sock = mycelium_node::NodeStore::open(home)
        .map_err(|e| e.to_string())?
        .socket_path();
    match action {
        GatewayCmd::VeilProbe { host } => {
            rpc(home, Request::GatewayVeilProbe { hostname: host }).await
        }
        GatewayCmd::Pay {
            to,
            amount_micros,
            currency,
            swift_csp_compliant,
            secure_zone_log,
            local_hour,
            allow_external_disclosure,
            show_native_payload,
        } => {
            let mut meta = serde_json::Map::new();
            if allow_external_disclosure {
                meta.insert("external_disclosure_consent".into(), serde_json::Value::Bool(true));
            }
            if swift_csp_compliant {
                meta.insert("swift_csp_compliant".into(), serde_json::Value::Bool(true));
            }
            if let Some(log_id) = secure_zone_log {
                meta.insert("secure_zone_log_id".into(), serde_json::Value::String(log_id));
            }
            if let Some(h) = local_hour {
                meta.insert("local_hour".into(), serde_json::Value::Number(h.into()));
            }
            let compliance_json = Some(serde_json::Value::Object(meta).to_string());
            let mut resp = call(
                &sock,
                Request::GatewayPay {
                    receiver_id: to,
                    amount_micros,
                    currency,
                    compliance_json,
                },
            )
            .await?;
            if !show_native_payload {
                if let Response::GatewayPayResult { native_payload, .. } = &mut resp {
                    *native_payload = "[oculto: use --show-native-payload para exibir]".into();
                }
            }
            print_response(resp)
        }
    }
}

async fn sow_cmd(
    home: &PathBuf,
    message: String,
    path: String,
    content: String,
    qel: Option<String>,
    nostr: bool,
    ghost: bool,
    recipient: Option<String>,
    hybrid: bool,
) -> Result<(), String> {
    #[cfg(not(feature = "nostr"))]
    {
        if qel.is_some() || nostr || ghost || recipient.is_some() || hybrid {
            return Err(
                "sow --qel/--nostr/--ghost/--hybrid requer `cargo build -p mycelium-cli --features nostr`"
                    .into(),
            );
        }
    }
    let want_nostr = nostr || qel.is_some() || ghost || hybrid;
    let qel = if want_nostr && qel.is_none() {
        Some("3,7".into())
    } else {
        qel
    };
    let sock = home.join("mycelium.sock");
    let resp = call(
        &sock,
        Request::Sow {
            message,
            path,
            content,
            qel: qel.clone(),
            nostr: nostr || hybrid,
            ghost: ghost || nostr || hybrid,
            recipient: recipient.clone(),
        },
    )
    .await?;

    #[cfg(feature = "nostr")]
    if want_nostr {
        if let Response::Ok { message: ref msg } = resp {
            if let Some(id_str) = msg.strip_prefix("plot semeado: ") {
                let id_str = id_str.split(';').next().unwrap_or(id_str).trim();
                match publish_plot_nostr(
                    home,
                    id_str,
                    qel.as_deref(),
                    recipient.as_deref(),
                    hybrid,
                )
                .await
                {
                    Ok(result) => {
                        println!("[🍄] {msg}{}", result.summary);
                        return Ok(());
                    }
                    Err(e) => {
                        println!("[🍄] {msg}");
                        return Err(format!("plot local ok; nostr/qel falhou: {e}"));
                    }
                }
            }
        }
    }

    print_response(resp)
}

#[cfg(feature = "nostr")]
#[derive(Debug)]
struct NostrPublishResult {
    summary: String,
    relay_acks: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum DistributionPhase {
    Local,
    Distributing,
    Distributed,
    DistributionFailed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DistributionRecord {
    version: u8,
    plot: String,
    state: DistributionPhase,
    qel: String,
    attempts: u32,
    max_attempts: u32,
    relay_acks: usize,
    /// Relay ACK confirma aceitação de evento, não armazenamento por uma réplica.
    replicas_stored: usize,
    last_error: Option<String>,
    updated_at_unix: u64,
}

fn distribution_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn distribution_path(home: &std::path::Path, plot: &str) -> PathBuf {
    home.join("distributions").join(format!("{plot}.json"))
}

fn write_distribution(home: &std::path::Path, record: &DistributionRecord) -> Result<(), String> {
    use std::io::Write;
    let dir = home.join("distributions");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = distribution_path(home, &record.plot);
    let tmp = dir.join(format!(".{}.{}.tmp", record.plot, std::process::id()));
    let bytes = serde_json::to_vec_pretty(record).map_err(|e| e.to_string())?;
    let result = (|| -> Result<(), std::io::Error> {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &path)?;
        std::fs::File::open(&dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result.map_err(|e| e.to_string())
}

fn retry_backoff_ms(initial_ms: u64, attempt: u32) -> u64 {
    initial_ms.saturating_mul(1u64 << attempt.saturating_sub(1).min(16))
}

fn should_retry_distribution(error: &str, attempt: u32, max_attempts: u32) -> bool {
    attempt < max_attempts && !error.starts_with("deterministic: ")
}

fn acquire_distribution_lock(path: PathBuf) -> Result<Option<DistributionLock>, String> {
    use std::io::Write;
    let open = || std::fs::OpenOptions::new().write(true).create_new(true).open(&path);
    match open() {
        Ok(mut file) => {
            writeln!(file, "{}", std::process::id()).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            Ok(Some(DistributionLock { file: Some(file), path }))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let owner = std::fs::read_to_string(&path)
                .ok()
                .and_then(|value| value.trim().parse::<u32>().ok());
            let owner_alive = owner
                .map(|pid| std::path::Path::new("/proc").join(pid.to_string()).exists())
                .unwrap_or(false);
            if owner_alive {
                return Ok(None);
            }
            // O processo anterior caiu: remove somente o lock órfão e retoma
            // a partir do journal persistente, sem tocar no plot ou identidade.
            std::fs::remove_file(&path).map_err(|remove| remove.to_string())?;
            let mut file = open().map_err(|retry| retry.to_string())?;
            writeln!(file, "{}", std::process::id()).map_err(|write| write.to_string())?;
            file.sync_all().map_err(|sync| sync.to_string())?;
            Ok(Some(DistributionLock { file: Some(file), path }))
        }
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(feature = "nostr")]
async fn publish_existing_cmd(
    home: &PathBuf,
    plot: String,
    nostr: bool,
    qel: String,
    max_attempts: u32,
    timeout_secs: u64,
    backoff_ms: u64,
) -> Result<(), String> {
    use mycelium_core::ContentId;
    use mycelium_sporebank::SporeBank;
    if !nostr {
        return Err("publish-existing requer --nostr".into());
    }
    if max_attempts == 0 {
        return Err("--max-attempts deve ser maior que zero".into());
    }
    parse_qel_kn(Some(&qel))?;
    let id = ContentId::from_str(&plot).map_err(|e| e.to_string())?;
    let canonical = id.to_string();
    // O nome do journal faz parte do contrato com o chamador. ContentId::to_string()
    // pode acrescentar um prefixo (por exemplo, `Qm`) e criar um segundo registro
    // que o consumidor do CID original nunca lê.
    let journal_plot = plot.clone();
    // Leitura explícita do spore print: não há novo sow nem mutação do plot.
    SporeBank::open(home)
        .and_then(|bank| bank.spore_print(&id))
        .map_err(|e| format!("plot existente indisponível: {e}"))?;

    let path = distribution_path(home, &journal_plot);
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(existing) = serde_json::from_slice::<DistributionRecord>(&bytes) {
            if existing.state == DistributionPhase::Distributed && existing.qel == qel {
                println!("[🍄] plot {canonical} já distribuído (idempotente)");
                return Ok(());
            }
        }
    }

    std::fs::create_dir_all(home.join("distributions")).map_err(|e| e.to_string())?;
    let lock_path = home
        .join("distributions")
        .join(format!("{journal_plot}.lock"));
    let _lock = match acquire_distribution_lock(lock_path)? {
        Some(lock) => lock,
        None => {
            println!("[🍄] plot {canonical} já está em distribuição (idempotente)");
            return Ok(());
        }
    };

    let mut record = DistributionRecord {
        version: 1,
        plot: journal_plot,
        state: DistributionPhase::Local,
        qel: qel.clone(),
        attempts: 0,
        max_attempts,
        relay_acks: 0,
        replicas_stored: 0,
        last_error: None,
        updated_at_unix: distribution_now(),
    };
    write_distribution(home, &record)?;
    for attempt in 1..=max_attempts {
        record.state = DistributionPhase::Distributing;
        record.attempts = attempt;
        record.updated_at_unix = distribution_now();
        write_distribution(home, &record)?;
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs.max(1)),
            publish_plot_nostr(home, &canonical, Some(&qel), None, false),
        )
        .await;
        match outcome {
            Ok(Ok(result)) => {
                record.state = DistributionPhase::Distributed;
                record.relay_acks = result.relay_acks;
                record.last_error = None;
                record.updated_at_unix = distribution_now();
                write_distribution(home, &record)?;
                println!("[🍄] plot {canonical}{}; replicas_stored=0", result.summary);
                return Ok(());
            }
            Ok(Err(error)) => record.last_error = Some(error),
            Err(_) => record.last_error = Some(format!("timeout após {}s", timeout_secs.max(1))),
        }
        record.state = DistributionPhase::DistributionFailed;
        record.updated_at_unix = distribution_now();
        write_distribution(home, &record)?;
        if !record.last_error.as_deref().is_some_and(|error| should_retry_distribution(error, attempt, max_attempts)) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(retry_backoff_ms(backoff_ms, attempt))).await;
    }
    Err(format!(
        "distribuição Nostr falhou após {} tentativa(s): {}",
        record.attempts,
        record.last_error.unwrap_or_else(|| "erro desconhecido".into())
    ))
}

#[cfg(not(feature = "nostr"))]
async fn publish_existing_cmd(
    _home: &PathBuf, _plot: String, _nostr: bool, _qel: String,
    _max_attempts: u32, _timeout_secs: u64, _backoff_ms: u64,
) -> Result<(), String> {
    Err("publish-existing requer build com feature nostr".into())
}

struct DistributionLock {
    file: Option<std::fs::File>,
    path: PathBuf,
}

impl Drop for DistributionLock {
    fn drop(&mut self) {
        self.file.take();
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod distribution_tests {
    use super::*;

    fn temporary_home(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mycelium-{label}-{}-{}",
            std::process::id(),
            distribution_now()
        ))
    }

    #[test]
    fn distribution_journal_survives_reopen() {
        let home = temporary_home("distribution-journal");
        let record = DistributionRecord {
            version: 1,
            plot: "a".repeat(64),
            state: DistributionPhase::DistributionFailed,
            qel: "3,7".into(),
            attempts: 4,
            max_attempts: 4,
            relay_acks: 0,
            replicas_stored: 0,
            last_error: Some("relay indisponível".into()),
            updated_at_unix: distribution_now(),
        };
        write_distribution(&home, &record).unwrap();
        let reopened: DistributionRecord = serde_json::from_slice(
            &std::fs::read(distribution_path(&home, &record.plot)).unwrap(),
        )
        .unwrap();
        assert_eq!(reopened.state, DistributionPhase::DistributionFailed);
        assert_eq!(reopened.attempts, 4);
        assert_eq!(reopened.replicas_stored, 0);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn distribution_path_preserves_the_callers_plot_identifier() {
        let home = temporary_home("distribution-path");
        let original = "1ed9d092dd06298b8a8bb4ed02feac6116482114e435331853e0e5e0bb58d90d";
        assert_eq!(
            distribution_path(&home, original),
            home.join("distributions").join(format!("{original}.json"))
        );
    }

    #[test]
    fn retry_backoff_is_exponential_and_saturating() {
        assert_eq!(retry_backoff_ms(500, 1), 500);
        assert_eq!(retry_backoff_ms(500, 2), 1_000);
        assert_eq!(retry_backoff_ms(500, 3), 2_000);
        assert_eq!(retry_backoff_ms(u64::MAX, 17), u64::MAX);
    }

    #[test]
    fn deterministic_oversize_is_not_retried_even_with_four_attempts() {
        assert!(!should_retry_distribution(
            "deterministic: evento Nostr excede limite",
            1,
            4
        ));
        assert!(should_retry_distribution("relay timeout", 1, 4));
    }

    #[test]
    fn orphaned_distribution_lock_is_recovered() {
        let home = temporary_home("distribution-lock");
        std::fs::create_dir_all(&home).unwrap();
        let path = home.join("plot.lock");
        std::fs::write(&path, "4294967295\n").unwrap();
        let lock = acquire_distribution_lock(path.clone()).unwrap().unwrap();
        assert!(path.exists());
        drop(lock);
        assert!(!path.exists());
        std::fs::remove_dir_all(home).unwrap();
    }

    #[cfg(feature = "nostr")]
    #[test]
    fn reconstructed_content_id_mismatch_is_rejected() {
        let expected = mycelium_core::ContentId::of(b"expected plot");
        let error = verify_reconstructed_content_id(&expected, b"different plot").unwrap_err();
        assert!(error.contains("não confere"), "{error}");
    }
}

#[cfg(feature = "nostr")]
async fn publish_plot_nostr(
    home: &PathBuf,
    id_str: &str,
    qel_spec: Option<&str>,
    recipient: Option<&str>,
    hybrid: bool,
) -> Result<NostrPublishResult, String> {
    use mycelium_core::ContentId;
    use mycelium_sporebank::SporeBank;
    use std::str::FromStr;

    let id = ContentId::from_str(id_str).map_err(|e| e.to_string())?;
    let bank = SporeBank::open(home).map_err(|e| e.to_string())?;
    let bytes = bank.spore_print(&id).map_err(|e| e.to_string())?;

    let (threshold, total) = parse_qel_kn(qel_spec)?;
    let cfg = mycelium_qel::QelConfig {
        threshold,
        total,
        ttl_secs: 86_400,
    };
    let ghost = mycelium_ghostid::GhostId::spawn_quick(cfg.ttl_secs).map_err(|e| e.to_string())?;
    let mut shards = if hybrid {
        mycelium_qel::fragment_hybrid(&bytes, &id.to_string(), &cfg).map_err(|e| format!("deterministic: {e}"))?
    } else {
        mycelium_qel::fragment(&bytes, &id.to_string(), &cfg).map_err(|e| format!("deterministic: {e}"))?
    };

    let mut landscape_note = String::new();
    if hybrid {
        let ctx = mycelium_distancebridge::TransportContext {
            has_internet: true,
            ipfs_peers: 1,
            relay_available: false,
            ..Default::default()
        };
        let ranked = mycelium_distancebridge::select_transports(&ctx, 3);
        landscape_note = ranked
            .iter()
            .map(|(t, p)| format!("{t:?}:{p:.2}"))
            .collect::<Vec<_>>()
            .join(",");
        let hints =
            mycelium_distancebridge::hybrid_hints_from_landscape(&ctx, threshold, total);
        for (shard, hint) in shards.iter_mut().zip(hints) {
            shard.transport = hint;
        }
    }

    let blake3_hex = hex::encode(blake3::hash(&bytes).as_bytes());
    let pool = mycelium_nostr::RelayPool::default_public().with_min_relays(1);
    // Publicar shards de mailbox (Nostr / RelayMesh / Sms); store fica no blockstore.
    let to_publish: Vec<_> = if hybrid {
        shards
            .iter()
            .filter(|s| {
                matches!(
                    s.transport,
                    mycelium_qel::TransportHint::Nostr
                        | mycelium_qel::TransportHint::RelayMesh
                        | mycelium_qel::TransportHint::Sms
                )
            })
            .cloned()
            .collect()
    } else {
        shards.iter().take(threshold as usize).cloned().collect()
    };
    let published = mycelium_nostr::publish_shards(
        &pool,
        &ghost,
        &to_publish,
        &blake3_hex,
        bytes.len(),
        recipient,
    )
    .await
    .map_err(|e| if e.is_deterministic() { format!("deterministic: {e}") } else { e.to_string() })?;

    let mut extra = format!(
        "; qel={threshold},{total} nostr_publishes={published} ghost={}",
        ghost.nostr_pubkey_hex()
    );

    if hybrid {
        let store = mycelium_ipfs::BlockStore::open(home).map_err(|e| e.to_string())?;
        store.put_named(&id, &bytes).map_err(|e| e.to_string())?;
        let mut ipfs_shards = 0usize;
        for shard in shards.iter().filter(|s| {
            matches!(
                s.transport,
                mycelium_qel::TransportHint::Ipfs
                    | mycelium_qel::TransportHint::Dtn
                    | mycelium_qel::TransportHint::Visual
            )
        }) {
            let wire = serde_json::to_vec(shard).map_err(|e| e.to_string())?;
            let shard_key = format!("{}:shard:{}", id, shard.index);
            let shard_id = ContentId::of(shard_key.as_bytes());
            store
                .put_named(&shard_id, &wire)
                .map_err(|e| e.to_string())?;
            ipfs_shards += 1;
        }
        extra.push_str(&format!(
            " hybrid=1 ipfs_plot=1 ipfs_shards={ipfs_shards} landscape=[{landscape_note}]"
        ));
    }

    Ok(NostrPublishResult { summary: extra, relay_acks: published })
}

#[cfg(feature = "nostr")]
fn parse_qel_kn(spec: Option<&str>) -> Result<(u8, u8), String> {
    let s = spec.unwrap_or("3,7");
    let (k, n) = s
        .split_once(',')
        .ok_or_else(|| format!("qel inválido '{s}' — use k,n (ex. 3,7)"))?;
    Ok((
        k.trim()
            .parse()
            .map_err(|_| "qel threshold inválido".to_string())?,
        n.trim()
            .parse()
            .map_err(|_| "qel total inválido".to_string())?,
    ))
}

async fn recall_cmd(
    home: &PathBuf,
    plot: String,
    qel: bool,
    nostr: bool,
    qel_threshold: u8,
    hybrid: bool,
) -> Result<(), String> {
    #[cfg(not(feature = "nostr"))]
    {
        if qel || nostr || hybrid {
            return Err(
                "recall --qel/--nostr/--hybrid requer `cargo build -p mycelium-cli --features nostr`"
                    .into(),
            );
        }
    }

    #[cfg(feature = "nostr")]
    if qel || nostr || hybrid {
        // 1) SporeBank local
        if let Ok(bank) = mycelium_sporebank::SporeBank::open(home) {
            if let Ok(id) = plot.parse::<mycelium_core::ContentId>() {
                if let Some(p) = bank.recall(&id) {
                    println!(
                        "[🍄] plot {} — \"{}\" ({} leaves) [local]",
                        id.short(),
                        p.message,
                        p.leaves.len()
                    );
                    return Ok(());
                }
            }
        }

        // 2) Nostr QEL
        match recall_plot_nostr(home, &plot, qel_threshold).await {
            Ok(msg) => {
                println!("[🍄] {msg}");
                return Ok(());
            }
            Err(nostr_err) => {
                // 3) Hybrid: blockstore ipfs local
                if hybrid {
                    match recall_plot_ipfs(home, &plot).await {
                        Ok(msg) => {
                            println!("[🍄] {msg}");
                            return Ok(());
                        }
                        Err(ipfs_err) => {
                            let sock = home.join("mycelium.sock");
                            if sock.exists() || sock.with_extension("tcp").exists() {
                                let resp = call(
                                    &sock,
                                    Request::Recall {
                                        plot: plot.clone(),
                                        qel,
                                        nostr,
                                        qel_threshold: Some(qel_threshold),
                                    },
                                )
                                .await?;
                                print_response(resp)?;
                            }
                            return Err(format!(
                                "hybrid: nostr={nostr_err}; ipfs={ipfs_err}"
                            ));
                        }
                    }
                }

                let sock = home.join("mycelium.sock");
                if sock.exists() || sock.with_extension("tcp").exists() {
                    let resp = call(
                        &sock,
                        Request::Recall {
                            plot: plot.clone(),
                            qel,
                            nostr,
                            qel_threshold: Some(qel_threshold),
                        },
                    )
                    .await?;
                    print_response(resp)?;
                }
                return Err(format!("nostr/qel: {nostr_err}"));
            }
        }
    }

    let sock = home.join("mycelium.sock");
    print_response(
        call(
            &sock,
            Request::Recall {
                plot,
                qel,
                nostr,
                qel_threshold: None,
            },
        )
        .await?,
    )
}

#[cfg(feature = "nostr")]
async fn recall_plot_ipfs(home: &PathBuf, plot: &str) -> Result<String, String> {
    use mycelium_core::ContentId;
    use std::str::FromStr;

    let id = ContentId::from_str(plot).map_err(|e| e.to_string())?;
    let store = mycelium_ipfs::BlockStore::open(home).map_err(|e| e.to_string())?;
    let bytes = store.get(&id).map_err(|e| e.to_string())?;
    import_spore_via_daemon(home, &id, &bytes).await?;
    Ok(format!("plot {} reconstruído via ipfs-blocks", id.short()))
}

#[cfg(feature = "nostr")]
async fn recall_plot_nostr(home: &PathBuf, plot: &str, threshold: u8) -> Result<String, String> {
    use mycelium_core::ContentId;
    use std::str::FromStr;

    let id = ContentId::from_str(plot).map_err(|e| e.to_string())?;
    let pool = mycelium_nostr::RelayPool::default_public().with_min_relays(1);
    let shards = mycelium_nostr::fetch_shards(&pool, &id.to_string(), threshold, None)
        .await
        .map_err(|e| e.to_string())?;
    if shards.len() < threshold as usize {
        return Err(format!(
            "só {} shards Nostr (preciso {threshold})",
            shards.len()
        ));
    }
    let bytes = mycelium_qel::reconstruct(&shards).map_err(|e| e.to_string())?;
    verify_reconstructed_content_id(&id, &bytes)?;
    import_spore_via_daemon(home, &id, &bytes).await?;
    Ok(format!("plot {} reconstruído via Nostr/QEL", id.short()))
}

#[cfg(feature = "nostr")]
fn verify_reconstructed_content_id(
    expected: &mycelium_core::ContentId,
    bytes: &[u8],
) -> Result<(), String> {
    if mycelium_core::ContentId::of(bytes) != *expected {
        return Err("ContentId reconstruído não confere com o plot solicitado".into());
    }
    Ok(())
}

#[cfg(feature = "nostr")]
async fn import_spore_via_daemon(
    home: &PathBuf,
    expected: &mycelium_core::ContentId,
    bytes: &[u8],
) -> Result<(), String> {
    use base64::Engine;
    let response = call(
        &home.join("mycelium.sock"),
        Request::ImportSpore {
            spore_print_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
            expected_plot: expected.to_string(),
        },
    )
    .await?;
    match response {
        Response::Ok { .. } => Ok(()),
        Response::Err { message } => Err(message),
        _ => Err("resposta inesperada ao importar spore print".into()),
    }
}

/// Coleta arquivos recursivamente, ignorando metadados e artefatos de build
/// (`.git`, `target`, `node_modules`, entradas ocultas).
fn collect_code_files(
    dir: &std::path::Path,
    root: &std::path::Path,
    files: &mut Vec<(String, String)>,
    total_bytes: &mut usize,
) -> Result<(), String> {
    use base64::Engine;
    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let file_path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if file_path.is_dir() {
            if name == ".git" || name == "target" || name == "node_modules" || (name.starts_with('.') && name.len() > 1) {
                continue;
            }
            collect_code_files(&file_path, root, files, total_bytes)?;
        } else if file_path.is_file() {
            let relative = file_path.strip_prefix(root).unwrap_or(&file_path);
            let content = std::fs::read(&file_path).map_err(|e| e.to_string())?;
            *total_bytes += content.len();
            let b64 = base64::engine::general_purpose::STANDARD.encode(&content);
            files.push((relative.to_string_lossy().to_string(), b64));
        }
    }
    Ok(())
}

/// Lê recursivamente um diretório e envia os arquivos ao daemon via SeedCode.
async fn seed_code_cmd(
    home: &PathBuf,
    path: String,
    name: String,
    description: String,
    ion: String,
    visibility: String,
) -> Result<(), String> {
    let dir = std::path::PathBuf::from(&path);
    if !dir.is_dir() {
        return Err(format!("'{path}' não é um diretório"));
    }
    let mut files: Vec<(String, String)> = Vec::new();
    let mut total_bytes = 0usize;
    collect_code_files(&dir, &dir, &mut files, &mut total_bytes)?;
    if files.is_empty() {
        return Err(format!("'{path}' não contém arquivos (ou todos foram ignorados)"));
    }
    println!("[🍄] seed-code: {} arquivos ({} bytes) de '{}' [{}]", files.len(), total_bytes, path, visibility);
    rpc(home, Request::SeedCode { name, description, ion, visibility, files }).await
}

/// Baixa código-fonte da rede. `--output` resolve relativo ao CWD do CLI;
/// sem `--output`, descobre o nome do plot via `recall` e extrai em ./<nome>.
async fn recall_code_cmd(home: &PathBuf, plot: String, output: Option<String>) -> Result<(), String> {
    let dest: Option<std::path::PathBuf> = match output {
        Some(o) => {
            let p = std::path::PathBuf::from(&o);
            Some(if p.is_absolute() {
                p
            } else {
                std::env::current_dir().unwrap_or_default().join(p)
            })
        }
        None => {
            // O nome do plot vive no daemon; a extração deve cair no CWD do CLI.
            let sock = home.join("mycelium.sock");
            let resp = call(
                &sock,
                Request::Recall {
                    plot: plot.clone(),
                    qel: false,
                    nostr: false,
                    qel_threshold: None,
                },
            )
            .await?;
            let msg = match resp {
                mycelium_node::Response::Ok { message } => message,
                mycelium_node::Response::Err { message } => return Err(message),
                _ => return Err("resposta inesperada do daemon".into()),
            };
            // message: "plot Qm… — \"[vis] nome: desc\" (N leaves)"
            let name = msg
                .split('"')
                .nth(1)
                .map(|s| s.trim().split(':').next().unwrap_or("code").trim().to_string())
                .map(|n| {
                    // remove o prefixo de visibilidade "[vis] nome"
                    if n.starts_with('[') {
                        n.split(']').last().unwrap_or("code").trim().to_string()
                    } else {
                        n
                    }
                })
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "code".to_string());
            Some(std::env::current_dir().unwrap_or_default().join(name))
        }
    };
    rpc(
        home,
        Request::RecallCode {
            plot,
            output_dir: dest.map(|p| p.display().to_string()),
        },
    )
    .await
}

async fn habitat_cmd(home: &PathBuf, action: HabitatCmd) -> Result<(), String> {
    use mycelium_node::habitat::{Privacy, ServiceKind};
    match action {
        HabitatCmd::Usage { name, estimate_myc_micros_per_response } => {
            let sock = home.join("mycelium.sock");
            let resp = call(&sock, Request::HabitatUsage { name }).await?;
            if let Response::HabitatUsageReport { successful_responses, .. } = &resp {
                if let Some(rate) = estimate_myc_micros_per_response {
                    if rate == 0 {
                        return Err("estimativa MYC por resposta deve ser > 0".into());
                    }
                    let estimated_myc = (*successful_responses as u128)
                        .checked_mul(rate as u128)
                        .ok_or("estimativa MYC ultrapassa capacidade")?;
                    let estimated_usdc = estimated_myc
                        .checked_mul(mycelium_mint::DEFAULT_USDC_PER_MYC as u128)
                        .ok_or("estimativa USDC ultrapassa capacidade")?;
                    println!(
                        "[🍄] Estimativa fornecida pelo operador: {}.{:06} MYC ≈ {}.{:06} USDC",
                        estimated_myc / 1_000_000, estimated_myc % 1_000_000,
                        estimated_usdc / 1_000_000, estimated_usdc % 1_000_000,
                    );
                    println!("    referência interna: 1 MYC = 8 USDC; SEM cobrança, receita ou resgate");
                }
            }
            print_response(resp)
        }
        HabitatCmd::Register { name, kind, visibility, replicas, peers } => {
            let kind = match kind.as_str() {
                "data" => ServiceKind::Data,
                "compute" => ServiceKind::Compute,
                "site" => ServiceKind::Site,
                _ => return Err("tipo Habitat inválido".into()),
            };
            let privacy = match visibility.as_str() {
                "local" => Privacy::Local,
                "private" => Privacy::Private,
                "public" => Privacy::Public,
                _ => return Err("visibilidade Habitat inválida".into()),
            };
            let permitted_nodes = peers.into_iter()
                .map(|p| p.parse::<mycelium_core::NodeId>())
                .collect::<Result<Vec<_>, _>>()?;
            rpc(home, Request::HabitatRegister {
                name, kind, privacy, replicas, permitted_nodes,
            }).await
        }
        HabitatCmd::List => rpc(home, Request::HabitatList).await,
        HabitatCmd::Inspect { name } => rpc(home, Request::HabitatInspect { name }).await,
    }
}

async fn rpc(home: &PathBuf, request: Request) -> Result<(), String> {
    let sock = home.join("mycelium.sock");
    print_response(call(&sock, request).await?)
}

/// Poll IsotopeGet até ~3s (Decay pelas hifas).
async fn isotope_get_poll(home: &PathBuf, key: String) -> Result<(), String> {
    let sock = home.join("mycelium.sock");
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(3);
    let mut last_err = String::from("timeout");
    while tokio::time::Instant::now() < deadline {
        match call(&sock, Request::IsotopeGet { key: key.clone() }).await? {
            Response::Ok { message } => {
                println!("[🍄] {message}");
                return Ok(());
            }
            Response::Err { message } => {
                last_err = message;
                if !last_err.contains("decay em curso") {
                    return Err(last_err);
                }
            }
            Response::Status(_) => return Err("resposta inesperada".into()),
            _ => return Err("resposta inesperada".into()),
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
    Err(format!("isotope-get timeout: {last_err}"))
}

/// sow (opcional) → signal → espera ion → imprime URL do Event Horizon.
struct DeployOpts {
    plot: Option<String>,
    message: String,
    path: String,
    content: String,
    ion: String,
    name: String,
    quorum: usize,
    timeout: u64,
}

async fn deploy(home: &PathBuf, opts: DeployOpts) -> Result<(), String> {
    let sock = home.join("mycelium.sock");
    let plot_id = if let Some(p) = opts.plot {
        p
    } else {
        println!("[🍄] Semeando plot…");
        match call(
            &sock,
            Request::Sow {
                message: opts.message,
                path: opts.path,
                content: opts.content,
                qel: None,
                nostr: false,
                ghost: false,
                recipient: None,
            },
        )
        .await?
        {
            Response::Ok { message } => message
                .strip_prefix("plot semeado: ")
                .unwrap_or(&message)
                .to_string(),
            Response::Err { message } => return Err(message),
            Response::Status(_) => return Err("resposta inesperada no sow".into()),
            _ => return Err("resposta inesperada no sow".into()),
        }
    };
    println!("[🍄] Plot {plot_id}");
    println!("[🍄] Signal → ion `{}`…", opts.ion);
    match call(
        &sock,
        Request::Signal {
            plot: plot_id,
            quorum: opts.quorum,
            ion: opts.ion.clone(),
            name: opts.name,
        },
    )
    .await?
    {
        Response::Ok { message } => println!("[🍄] {message}"),
        Response::Err { message } => return Err(message),
        Response::Status(_) => return Err("resposta inesperada no signal".into()),
        _ => return Err("resposta inesperada no signal".into()),
    }

    let deadline =
        tokio::time::Instant::now() + tokio::time::Duration::from_secs(opts.timeout);
    while tokio::time::Instant::now() < deadline {
        if let Response::Status(s) = call(&sock, Request::Status).await? {
            if s.ions.iter().any(|n| n == &opts.ion) {
                let base = if s.event_horizon.ends_with('/') {
                    s.event_horizon.clone()
                } else {
                    format!("{}/", s.event_horizon)
                };
                let url = format!("{base}{}/", opts.ion);
                println!("[🍄] Vacuum Chamber pronta");
                println!("[🍄] Singularity Event Horizon: {url}");
                println!("[🍄] curl -s {url}");
                return Ok(());
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;
    }
    Err(format!(
        "deploy timeout: ion `{}` não apareceu em {}s",
        opts.ion, opts.timeout
    ))
}

fn print_response(resp: Response) -> Result<(), String> {
    match resp {
        Response::HabitatItem { item } => {
            println!("[🍄 Habitat] manifesto assinado e validado (registro local)");
            println!("{}", serde_json::to_string_pretty(&item).map_err(|e| e.to_string())?);
            Ok(())
        }
        Response::HabitatItems { items } => {
            println!("[🍄 Habitat] {} serviço(s) neste nó:", items.len());
            for item in items {
                println!("    {} | {:?} | {:?} | réplicas desejadas: {} | {}",
                    item.manifest.name, item.manifest.kind, item.manifest.privacy,
                    item.manifest.storage.target_replicas, item.manifest.service_id);
            }
            Ok(())
        }
        Response::Ok { message } => {
            println!("[🍄] {message}");
            Ok(())
        }
        Response::MintStatus {
            active,
            chain_id,
            current_epoch,
            total_supply,
            max_supply,
            epoch_budget,
            usdc_per_myc,
            total_supply_usdc,
            pending_claims,
            min_quorum,
        } => {
            let coin = mycelium_mint::COIN as f64;
            println!(
                "[🍄] Mainnet Mint ({})",
                if active { "ativo" } else { "inativo" }
            );
            println!("    chain_id     : {chain_id}");
            println!("    época atual  : {current_epoch}");
            println!(
                "    suprimento   : {:.8} / {:.8} MYC",
                total_supply as f64 / coin,
                max_supply as f64 / coin
            );
            println!(
                "    paridade     : 1 MYC = {usdc_per_myc} USDC (total ≈ {:.2} USDC)",
                total_supply_usdc as f64 / coin
            );
            println!("    orçamento    : {:.8} MYC/época", epoch_budget as f64 / coin);
            println!("    claims pend. : {pending_claims} (quórum mín.: {min_quorum})");
            Ok(())
        }
        Response::HabitatUsageReport {
            name,
            service_id,
            successful_responses,
            body_bytes,
            observation,
            payment_status,
        } => {
            println!("[🍄 Habitat] uso observado localmente — serviço {name}");
            println!("    service_id : {service_id}");
            println!("    respostas  : {successful_responses}");
            println!("    bytes      : {body_bytes}");
            println!("    origem     : {observation}");
            println!("    pagamento  : {payment_status}");
            Ok(())
        }
        Response::GatewayVeilProbeResult {
            proxy,
            hostname,
            connection_established,
            tls_verified,
            payment_submitted,
        } => {
            println!("[🍄] VEIL gateway: SOCKS5 CONNECT validado");
            println!("    proxy loopback : {proxy}");
            println!("    hostname       : {hostname}:443 (DNS remoto)");
            println!("    conectado      : {connection_established}");
            println!("    TLS verificado : {tls_verified}");
            println!("    pagamento      : {payment_submitted}");
            Ok(())
        }
        Response::GatewayPayResult {
            intent_id,
            gateway,
            state,
            external_ref,
            myc_micros,
            usdc_equivalent_micros,
            native_payload,
        } => {
            println!("[🍄] Supreme Meta-Gateway ({gateway}) — estado: {state}");
            println!("    intent_id    : {intent_id}");
            println!("    external_ref : {external_ref}");
            if myc_micros != 0 || usdc_equivalent_micros != 0 {
                println!(
                    "    referência   : {:.6} MYC ≈ {:.6} USDC (1 MYC = 8 USDC; não garante resgate)",
                    myc_micros as f64 / 1_000_000.0,
                    usdc_equivalent_micros as f64 / 1_000_000.0
                );
            } else {
                println!("    referência   : indisponível sem cotação verificável");
            }
            println!("    payload      : {native_payload}");
            Ok(())
        }
        Response::Status(s) => {
            println!("[🍄] Organismo vivo");
            println!("    home       : {}", s.home);
            println!("    NodeId     : {}", s.node_id);
            println!("    PeerId     : {}", s.peer_id);
            println!("    listen     : {:?}", s.listen_addrs);
            println!("    vizinhos   : {}", s.neighbors);
            println!("    plots      : {}", s.plots);
            println!("    signals    : {}", s.signals);
            println!("    ions       : {:?}", s.ions);
            println!(
                "    isotope    : shard={}/{} atoms={}",
                s.isotope_shard, s.isotope_ring, s.isotope_atoms
            );
            if !s.event_horizon.is_empty() {
                println!("    horizon    : {}", s.event_horizon);
            }
            for ep in &s.ion_endpoints {
                println!("    chamber    : {ep}");
            }
            for ion in &s.ions {
                println!(
                    "    curl       : curl -s {}{ion}/",
                    if s.event_horizon.ends_with('/') {
                        s.event_horizon.clone()
                    } else {
                        format!("{}/", s.event_horizon)
                    }
                );
            }
            println!(
                "    nutrientes : ATP={} Enzymes={} Mycelia={} Spores={} Resilience={}",
                s.atp, s.enzymes, s.mycelia, s.spores, s.resilience
            );
            println!(
                "    hifas      : anastomoses={} atrophies={} msg_in={} msg_out={}",
                s.anastomoses, s.atrophies, s.messages_in, s.messages_out
            );
            if !s.membrane.is_empty() {
                println!("    membrana   : {}", s.membrane);
            }
            if s.sporocarp {
                println!("    sporocarp  : sim");
            }
            println!(
                "    wan_reach  : {}",
                if s.wan_reachable { "sim" } else { "nao" }
            );
            if s.is_relay {
                println!("    is_relay   : sim");
            }
            if let Some(r) = &s.active_relay {
                println!("    active_relay: {r}");
            }
            if !s.relay_health.is_empty() {
                println!("    relay_mesh : {}", s.relay_health);
            }
            if !s.physarum_phase.is_empty() {
                println!("    physarum   : {}", s.physarum_phase);
            }
            if let Some(dns) = &s.dns_seed {
                println!("    dns_seed   : {dns}");
            }
            if let Some(socks) = &s.veil_socks5 {
                println!("    veil_socks5: {socks}");
            }
            Ok(())
        }
        Response::VeilStatusResult {
            active,
            role,
            mode,
            socks5_addr,
            listen_addr,
            descriptor,
            session_id,
            bytes_routed,
            mac_address,
            kill_switch,
            active_layers,
            entrada_ativa,
            entradas,
            tentativas_failover,
            motivos_falha,
        } => {
            println!("[🛡️] Mycelium VEIL Ω");
            println!("    estado     : {}", if active { "ativo 🟢" } else { "inativo ⚪" });
            if let Some(r) = role {
                println!("    papel      : {r}");
            }
            if let Some(m) = mode {
                println!("    modo       : {m}");
            }
            if let Some(s) = socks5_addr {
                println!("    socks5     : {s}");
            }
            if let Some(l) = listen_addr {
                println!("    escuta     : {l}");
            }
            if let Some(id) = session_id {
                println!("    sessão_id  : {id}");
            }
            if let Some(mac) = mac_address {
                println!("    mac_efêmero: {mac}");
            }
            println!("    kill_switch: {kill_switch}");
            println!("    camadas    : {active_layers}/7 camadas ligadas ao tráfego real");
            if active_layers < 7 {
                // O `LayerPipeline` de 7 camadas está projetado, não ligado à produção:
                // o número acima é o que REALMENTE atua, não o que existe implementado.
                println!("    pipeline   : 7 camadas projetadas, ainda não ligado ao tráfego");
            }
            println!("    tráfego    : {bytes_routed} bytes");
            if let Some(ea) = entrada_ativa {
                println!("    ponte ativa: {ea}");
            }
            if !entradas.is_empty() {
                println!("    pontes     : {}", entradas.join(", "));
            }
            if tentativas_failover > 0 {
                println!("    failovers  : {tentativas_failover}");
            }
            if !motivos_falha.is_empty() {
                println!("    falhas     : {}", motivos_falha.join("; "));
            }
            if let Some(d) = descriptor {
                println!("    descritor  : (use 'mycelium veil descriptor' para ver completo)");
                let _ = d; // silencia unused
            }
            Ok(())
        }
        Response::StoreCaps { caps } => {
            println!("\n⚡ === MYCELIUM STORE — Capacidades de Emulação Host === ⚡\n");
            println!(" ⚙️ QEMU Emulators:");
            for (arch, has) in &caps.has_qemu {
                println!("    • qemu-system-{:<8}: {}", arch, if *has { "✅ Instalado" } else { "❌ Ausente" });
            }
            println!(" ⚙️ RetroArch (Libretro): {}", if caps.has_retroarch { "✅ Instalado" } else { "❌ Ausente" });
            println!("    Cores encontrados: {:?}", caps.available_libretro_cores);
            println!(" ⚙️ MAME Arcade: {}", if caps.has_mame { "✅ Instalado" } else { "❌ Ausente" });
            println!(" ⚙️ Bubblewrap Sandbox (bwrap): {}\n", if caps.has_bwrap_sandbox { "✅ Disponível" } else { "❌ Não encontrado" });
            Ok(())
        }
        Response::StoreList { spores } => {
            if spores.is_empty() {
                println!("[🍄] Nenhum spore cadastrado no catálogo.");
            } else {
                println!("\n🎮 === MYCELIUM APP STORE — Catálogo P2P Retro ({}) === 🎮\n", spores.len());
                for spore in spores {
                    println!("🔹 ID: {}", spore.id);
                    println!("   Título: {}", spore.title);
                    println!("   Plataforma: {}", spore.platform.display_name());
                    println!("   Ano: {}", spore.release_year);
                    println!("   Licença: {}", spore.license.display_name());
                    println!("   Recomendado: {:?}", spore.execution_matrix.recommended);
                    println!("   Categorias/Tags: {:?}", spore.tags);
                    println!("   ContentId: {}", hex::encode(spore.content_id.0));
                    println!("------------------------------------------------------------");
                }
            }
            Ok(())
        }
        Response::StoreLaunched { spore_id, engine, message } => {
            println!("[🍄 Store] Spore '{spore_id}' iniciado via {engine}: {message}");
            Ok(())
        }
        Response::RepoPublished { cid, leaves, bytes } => {
            println!("[🍄 Repo] ✅ Publicado com sucesso!");
            println!("    ContentId : {cid}");
            println!("    Arquivos  : {leaves}");
            println!("    Tamanho   : {bytes} bytes");
            Ok(())
        }
        Response::RepoCloneResult { message, leaves } => {
            println!("[🍄 Repo] {message} ({} arquivos)", leaves.len());
            Ok(())
        }
        Response::InertiaRunResult {
            input_cid,
            build_attestation_cid,
            test_attestation_cid,
            artifact_cid,
            success,
        } => {
            println!("[🍄 Inertia] CID de entrada       : {input_cid}");
            println!("[🍄 Inertia] Atestação de build  : {build_attestation_cid}");
            if let Some(cid) = test_attestation_cid {
                println!("[🍄 Inertia] Atestação de teste  : {cid}");
            }
            if let Some(cid) = artifact_cid {
                println!("[🍄 Inertia] Artefato             : {cid}");
            }
            if success {
                println!("[🍄 Inertia] ✅ Build e testes aprovados");
            } else {
                println!("[🍄 Inertia] ❌ Falha no build ou testes");
            }
            Ok(())
        }
        Response::InertiaAttestationResult { cid, attestation } => {
            println!("[🍄 Inertia] Atestação {cid}:");
            println!("    Executor: {}", attestation.payload.executor);
            println!("    Signer  : {}", attestation.signer);
            println!("    Sucesso : {}", attestation.payload.success);
            println!("    Log CID : {}", attestation.payload.log_digest);
            Ok(())
        }
        Response::TransferResult { tx_id, kind, nutrient, amount, to } => {
            println!("[🍄] Transferência confirmada: {tx_id}");
            println!("    Nutriente : {nutrient} ({kind})");
            println!("    Quantidade: {amount}");
            println!("    Destino   : {to}");
            Ok(())
        }
        Response::LedgerReport { pubkey, balances, history, transfers } => {
            println!("[🍄] Ledger Local");
            println!("    Chave pública: {pubkey}");
            println!("    Saldos       :");
            for (k, v) in balances {
                println!("      {:?}: {}", k, v);
            }
            println!("    Histórico de trocas        : {} entradas", history.len());
            println!("    Transferências registradas : {} transferências", transfers.len());
            Ok(())
        }
        Response::AssetListResult { assets } => {
            if assets.is_empty() {
                println!("[🍄] Nenhum ativo cadastrado.");
            } else {
                println!("[🍄] Ativos registrados ({}):", assets.len());
                for a in assets {
                    println!("    • [{}] {} ({} cotas a {} ATP)", a.id, a.name, a.shares_total, a.price_per_share);
                }
            }
            Ok(())
        }
        Response::AssetSharesResult { asset, holdings } => {
            println!("[🍄] Cotas do ativo {asset}:");
            for h in holdings {
                println!("    • Holder {}: {} cotas", hex::encode(h.holder), h.shares);
            }
            Ok(())
        }
        Response::S1LiveMessages { messages } => {
            for message in messages {
                println!("{message}");
            }
            Ok(())
        }
        Response::S1LiveBindingsResult { bindings } => {
            for binding in bindings {
                println!("{binding}");
            }
            Ok(())
        }
        other @ (Response::AexBridgeCapabilities { .. }
        | Response::AexQelFragmentResult { .. }
        | Response::AexQelReconstructResult { .. }
        | Response::AexIpfsPutResult { .. }
        | Response::AexIpfsGetResult { .. }
        | Response::AexSporePutResult { .. }
        | Response::AexSporeGetResult { .. }
        | Response::AexDistancebridgeResult { .. }
        | Response::AexGhostSpawnResult { .. }
        | Response::AexGhostSignResult { .. }
        | Response::AexVerifyResult { .. }
        | Response::AexDtnSendResult { .. }
        | Response::AexDtnPollResult { .. }
        | Response::AexPqcKeygenResult { .. }
        | Response::AexPqcEncapResult { .. }
        | Response::AexPqcDecapResult { .. }
        | Response::AexZkHashChronicleResult { .. }
        | Response::AexZkPedersenCommitResult { .. }
        | Response::RhizomeJson { .. }) => {
            println!("{}", serde_json::to_string_pretty(&other).unwrap_or_default());
            Ok(())
        }
        Response::Err { message } => Err(message),
    }
}

async fn chamber_headers_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    let pid = std::process::id().to_string();
    if let Ok(val) = axum::http::HeaderValue::from_str(&pid) {
        resp.headers_mut().insert("x-chamber-pid", val);
    }
    if let Ok(val) = axum::http::HeaderValue::from_str("dynamic-process") {
        resp.headers_mut().insert("x-chamber-mode", val);
    }
    resp
}

async fn chamber_serve(port: u16, ion: String, root: PathBuf) -> Result<(), String> {
    let message = std::fs::read_to_string(root.join("message.txt"))
        .or_else(|_| std::fs::read_to_string(root.join("rootfs/MESSAGE")))
        .unwrap_or_else(|_| ion.clone());
    let ion_name = ion.clone();
    let msg = message.clone();
    let built_html = std::fs::read_to_string(root.join("rootfs/index.html")).ok();

    let app = Router::new()
        .route(
            "/",
            get({
                let ion = ion_name.clone();
                let msg = msg.clone();
                move || {
                    let ion = ion.clone();
                    let msg = msg.clone();
                    async move {
                        Json(json!({
                            "ion": ion,
                            "message": msg,
                            "substrate": "mycelium",
                            "runtime": "vacuum-chamber",
                        }))
                    }
                }
            }),
        )
        .route("/health", get(|| async { Json(json!({"ok": true})) }))
        .route(
            "/status",
            get({
                let ion = ion_name.clone();
                move || {
                    let ion = ion.clone();
                    let pid = std::process::id();
                    async move {
                        Json(json!({
                            "chamber_pid": pid,
                            "status": "active",
                            "ion": ion,
                        }))
                    }
                }
            }),
        )
        .route(
            "/index.html",
            get({
                let ion = ion_name;
                let msg = message;
                let built = built_html;
                move || {
                    let ion = ion.clone();
                    let msg = msg.clone();
                    let built = built.clone();
                    async move {
                        let body = built.unwrap_or_else(|| {
                            format!(
                                "<!doctype html><html><body style=\"font-family:system-ui;background:#0b1a14;color:#c8e6c9;padding:2rem\">\
                                <h1>🍄 {ion}</h1>\
                                <p>Servido por uma <b>Vacuum Chamber</b> (processo filho).</p>\
                                <pre>{msg}</pre>\
                                </body></html>"
                            )
                        });
                        (
                            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                            body,
                        )
                    }
                }
            }),
        )
        .layer(axum::middleware::from_fn(chamber_headers_middleware));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| e.to_string())?;
    axum::serve(listener, app)
        .await
        .map_err(|e| e.to_string())
}

fn store_cmd(home: &PathBuf, action: StoreCmd) -> Result<(), String> {
    let rt = tokio::runtime::Runtime::new().expect("tokio");
    rt.block_on(store_cmd_async(home, action))
}

async fn store_cmd_async(home: &PathBuf, action: StoreCmd) -> Result<(), String> {
    use mycelium_store::{
        catalog::StoreCatalog,
        runner::EmulatorRunner,
        spore::{ExecutionEngineType, SoftwareSpore, SporeLicense, TargetPlatform},
    };

    let sock = home.join("mycelium.sock");
    let daemon_running = sock.exists() || sock.with_extension("tcp").exists();

    match action {
        StoreCmd::List => {
            if daemon_running {
                return print_response(call(&sock, Request::StoreList).await?);
            }
            let catalog = StoreCatalog::open(home).map_err(|e| e.to_string())?;
            let spores = catalog.list_public_spores();
            println!("\n🎮 === MYCELIUM APP STORE — Catálogo P2P Retro === 🎮\n");
            for spore in spores {
                println!("🔹 ID: {}", spore.id);
                println!("   Título: {}", spore.title);
                println!("   Plataforma: {}", spore.platform.display_name());
                println!("   Ano: {}", spore.release_year);
                println!("   Licença: {}", spore.license.display_name());
                println!("   Recomendado: {:?}", spore.execution_matrix.recommended);
                println!("   Categorias/Tags: {:?}", spore.tags);
                println!("   ContentId: {}", hex::encode(spore.content_id.0));
                println!("------------------------------------------------------------");
            }
            Ok(())
        }
        StoreCmd::Caps => {
            if daemon_running {
                return print_response(call(&sock, Request::StoreCaps).await?);
            }
            let caps = EmulatorRunner::detect_capabilities();
            println!("\n⚡ === MYCELIUM STORE — Capacidades de Emulação Host === ⚡\n");
            println!(" ⚙️ QEMU Emulators:");
            for (arch, has) in caps.has_qemu {
                println!("    • qemu-system-{:<8}: {}", arch, if has { "✅ Instalado" } else { "❌ Ausente" });
            }
            println!(" ⚙️ RetroArch (Libretro): {}", if caps.has_retroarch { "✅ Instalado" } else { "❌ Ausente" });
            println!("    Cores encontrados: {:?}", caps.available_libretro_cores);
            println!(" ⚙️ MAME Arcade: {}", if caps.has_mame { "✅ Instalado" } else { "❌ Ausente" });
            println!(" ⚙️ Bubblewrap Sandbox (bwrap): {}\n", if caps.has_bwrap_sandbox { "✅ Disponível" } else { "❌ Não encontrado" });
            Ok(())
        }
        StoreCmd::Launch { id, engine, sandbox } => {
            if daemon_running {
                let req = Request::StoreLaunch { id, engine, sandbox };
                return print_response(call(&sock, req).await?);
            }
            let catalog = StoreCatalog::open(home).map_err(|e| e.to_string())?;
            let spore = catalog.get_spore(&id).ok_or_else(|| format!("Spore '{}' não encontrado", id))?;

            let caps = EmulatorRunner::detect_capabilities();

            let forced_engine = match engine.as_deref() {
                Some("native") => Some(ExecutionEngineType::Native),
                Some("retroarch") => Some(ExecutionEngineType::RetroArchLibretro),
                Some("mame") => Some(ExecutionEngineType::MAME),
                Some("qemu") => Some(ExecutionEngineType::QEMU),
                Some("wasm") => Some(ExecutionEngineType::WebAssembly),
                Some("cloud") => Some(ExecutionEngineType::P2PCloudStream),
                Some(other) => return Err(format!("Motor de execução desconhecido: '{}'", other)),
                None => None,
            };

            let resolved_engine = EmulatorRunner::resolve_best_engine(spore, &caps, forced_engine);
            println!("[🍄 Store] Preparando lançamento de '{}'...", spore.title);
            println!("[🍄 Store] Plataforma Alvo: {}", spore.platform.display_name());
            println!("[🍄 Store] Motor Escolhido: {:?}", resolved_engine);

            let dummy_path = home.join("store").join(&spore.main_binary_file);

            match EmulatorRunner::launch(spore, &dummy_path, resolved_engine, sandbox) {
                Ok(_child) => {
                    println!("[🍄 Store] Processo do emulador lançado com sucesso!");
                    Ok(())
                }
                Err(err) => Err(format!("Erro ao lançar o emulador: {}", err)),
            }
        }
        StoreCmd::Publish { id, title, platform, binary, license } => {
            if !binary.exists() {
                return Err(format!("Arquivo binário '{:?}' não existe", binary));
            }
            let bytes = std::fs::read(&binary).map_err(|e| e.to_string())?;

            let plat = match platform.to_lowercase().as_str() {
                "snes" => TargetPlatform::SNES,
                "nes" => TargetPlatform::NES,
                "megadrive" | "genesis" => TargetPlatform::MegaDrive,
                "msdos" | "dos" => TargetPlatform::MSDOS,
                "win98" | "win95" => TargetPlatform::Windows98,
                "arcade" | "mame" => TargetPlatform::ArcadeMame,
                "mac" | "ppc" => TargetPlatform::PowerPCMac,
                _ => TargetPlatform::NativeSystem,
            };

            let lic = match license.to_lowercase().as_str() {
                "shareware" => SporeLicense::Shareware,
                "freeware" => SporeLicense::Freeware,
                "open_source" | "opensource" | "open" => SporeLicense::OpenSource,
                "public_domain" | "publicdomain" | "pd" | "cc0" => SporeLicense::PublicDomain,
                _ => SporeLicense::Proprietary,
            };

            let mut catalog = StoreCatalog::open(home).map_err(|e| e.to_string())?;

            let main_file = binary.file_name().unwrap().to_string_lossy().to_string();
            let content_id = mycelium_core::ContentId::of(&bytes);

            let spore = SoftwareSpore {
                id: id.clone(),
                title,
                description: "Publicado via Mycelium Store CLI".to_string(),
                developer_or_publisher: "Comunidade Mycelium".to_string(),
                release_year: 2000,
                platform: plat,
                category: "software".to_string(),
                tags: vec!["p2p".to_string(), "spore".to_string()],
                license: lic,
                main_binary_file: main_file,
                content_id,
                execution_matrix: mycelium_store::ExecutionMatrix {
                    recommended: ExecutionEngineType::Native,
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

            let cid = catalog.publish_spore(spore, &bytes).map_err(|e| e.to_string())?;
            println!("[🍄 Store] Spore '{}' publicado com sucesso! ContentId: {}", id, hex::encode(cid.0));
            Ok(())
        }
    }
}

async fn repo_cmd(home: &PathBuf, action: RepoCmd) -> Result<(), String> {
    match action {
        RepoCmd::Publish { dir, repository, branch, expected_previous_cid, message } => {
            if !dir.is_dir() {
                return Err(format!("diretório não encontrado: {:?}", dir));
            }
            let leaves = pack_tree(&dir)?;
            if leaves.is_empty() {
                return Err("nenhum arquivo para publicar".into());
            }
            let bytes: usize = leaves.iter().map(|l| l.content.len()).sum();
            println!("[🍄 Repo] Empacotando {} arquivos ({} bytes) de {:?}", leaves.len(), bytes, dir);
            println!("[🍄 Repo] Enviando para o daemon (SporeBank + DHT + gossip)...");
            let repository = repository.or_else(|| dir.file_name().map(|v| v.to_string_lossy().into_owned()));
            let resp = call(&home.join("mycelium.sock"), Request::RepoPublish {
                repository,
                branch: Some(branch),
                expected_previous_cid,
                message,
                leaves,
            }).await?;
            match resp {
                Response::RepoPublished { cid, leaves, bytes } => {
                    println!("[🍄 Repo] ✅ Publicado!");
                    println!("    ContentId : {cid}");
                    println!("    Arquivos  : {leaves}");
                    println!("    Tamanho   : {bytes} bytes");
                    println!();
                    println!("  Distribua este ContentId (via Nostr/DHT). Qualquer nó pode:");
                    println!("    mycelium repo clone --cid {cid} --dest ./copia");
                    println!("    curl http://127.0.0.1:7474/src/{cid}/");
                    Ok(())
                }
                Response::Err { message } => Err(message),
                other => Err(format!("resposta inesperada: {:?}", other)),
            }
        }
        RepoCmd::Clone { cid, dest } => {
            let sock = home.join("mycelium.sock");
            let resp = call(&sock, Request::RepoClone { cid: cid.clone() }).await;
            match resp {
                Ok(Response::RepoCloneResult { message, leaves }) => {
                    println!("[🍄 Repo] {message}");
                    write_tree(&dest, &leaves)?;
                    let bytes: usize = leaves.iter().map(|l| l.content.len()).sum();
                    println!("[🍄 Repo] ✅ Árvore reconstruída em {:?} ({} arquivos, {} bytes)", dest, leaves.len(), bytes);
                    Ok(())
                }
                Ok(Response::Err { message }) => Err(message),
                Ok(other) => Err(format!("resposta inesperada: {:?}", other)),
                Err(e) => {
                    println!("[🍄 Repo] daemon offline ({e}) — tentando SporeBank local...");
                    match clone_from_local_bank(home, &cid) {
                        Some(leaves) => {
                            write_tree(&dest, &leaves)?;
                            let bytes: usize = leaves.iter().map(|l| l.content.len()).sum();
                            println!("[🍄 Repo] ✅ Árvore reconstruída do SporeBank local em {:?} ({} arquivos, {} bytes)", dest, leaves.len(), bytes);
                            Ok(())
                        }
                        None => Err(format!(
                            "repo {} não encontrado localmente. Suba o daemon (mycelium daemon) para buscar via DHT.",
                            cid
                        )),
                    }
                }
            }
        }
        RepoCmd::Validate { cid } => {
            let resp = call(
                &home.join("mycelium.sock"),
                Request::InertiaRun { cid: cid.clone() },
            )
            .await?;
            match resp {
                Response::InertiaRunResult {
                    input_cid,
                    build_attestation_cid,
                    test_attestation_cid,
                    artifact_cid,
                    success,
                } => {
                    println!("[🍄 Inertia] CID de entrada       : {input_cid}");
                    println!("[🍄 Inertia] Atestação de build  : {build_attestation_cid}");
                    if let Some(cid) = test_attestation_cid {
                        println!("[🍄 Inertia] Atestação de teste  : {cid}");
                    }
                    if let Some(cid) = artifact_cid {
                        println!("[🍄 Inertia] Artefato             : {cid}");
                    }
                    if success {
                        println!("[🍄 Inertia] ✅ Build e testes aprovados");
                        Ok(())
                    } else {
                        Err("validação Inertia reprovada; as atestações foram preservadas".into())
                    }
                }
                Response::Err { message } => Err(message),
                other => Err(format!("resposta inesperada: {:?}", other)),
            }
        }
        RepoCmd::Attestation { cid } => {
            let resp = call(
                &home.join("mycelium.sock"),
                Request::InertiaAttestation { cid: cid.clone() },
            )
            .await?;
            match resp {
                Response::InertiaAttestationResult { cid, attestation } => {
                    attestation
                        .verify()
                        .map_err(|e| format!("atestação {cid} inválida: {e}"))?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&attestation)
                            .map_err(|e| format!("serializar atestação: {e}"))?
                    );
                    Ok(())
                }
                Response::Err { message } => Err(message),
                other => Err(format!("resposta inesperada: {:?}", other)),
            }
        }
        RepoCmd::List => {
            let resp = call(&home.join("mycelium.sock"), Request::Status).await?;
            match resp {
                Response::Status(s) => {
                    println!("\n[🍄 Repo] Plots no SporeBank local: {}\n", s.plots);
                    for id in mycelium_store_list_local(home)? {
                        println!("    • {}", id);
                    }
                    Ok(())
                }
                _ => Err("resposta inesperada no status".into()),
            }
        }
    }
}

async fn veil_cmd(home: &PathBuf, action: VeilCmd) -> Result<(), String> {
    let sock = home.join("mycelium.sock");
    match action {
        VeilCmd::Status => {
            print_response(call(&sock, Request::VeilStatus).await?)
        }
        VeilCmd::Start {
            mode,
            port,
            role,
            listen,
            trust,
            advertise,
            identity,
            rotate_identity,
            egress_bind,
            bridges,
            bridge_listen,
            bridge_target,
        } => {
            print_response(call(&sock, Request::VeilStart {
                mode: Some(mode),
                socks5_port: Some(port),
                role,
                listen,
                trust,
                advertise,
                identity: identity.map(|p| p.display().to_string()),
                rotate_identity,
                egress_bind: egress_bind.map(|ip| ip.to_string()),
                bridges,
                bridge_listen,
                bridge_target,
            }).await?)
        }
        VeilCmd::Stop => {
            print_response(call(&sock, Request::VeilStop).await?)
        }
        VeilCmd::Descriptor => {
            print_response(call(&sock, Request::VeilDescriptor).await?)
        }
    }
}

fn write_tree(dest: &PathBuf, leaves: &[giggs::Leaf]) -> Result<(), String> {
    std::fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    let root = std::fs::canonicalize(dest).map_err(|e| format!("resolver destino: {e}"))?;
    let mut paths = std::collections::HashSet::new();
    for leaf in leaves {
        let relative = safe_repo_path(&leaf.path)?;
        if !paths.insert(relative.clone()) {
            return Err(format!("caminho duplicado no Plot: {}", leaf.path));
        }
        let target = root.join(&relative);
        let parent = target
            .parent()
            .ok_or_else(|| format!("caminho sem diretório pai: {}", leaf.path))?;
        create_safe_directories(&root, parent)?;
        if let Ok(metadata) = std::fs::symlink_metadata(&target) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!("destino inseguro ou não regular: {}", leaf.path));
            }
        }
        std::fs::write(&target, &leaf.content).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn safe_repo_path(path: &str) -> Result<PathBuf, String> {
    let candidate = Path::new(path);
    if path.is_empty() || candidate.is_absolute() {
        return Err(format!("caminho inseguro no Plot: {path:?}"));
    }
    let mut clean = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            _ => return Err(format!("caminho inseguro no Plot: {path:?}")),
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(format!("caminho inseguro no Plot: {path:?}"));
    }
    Ok(clean)
}

fn create_safe_directories(root: &Path, parent: &Path) -> Result<(), String> {
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| "diretório pai escapou do destino".to_string())?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(format!("componente inseguro no destino: {:?}", current));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current)
                    .map_err(|e| format!("criar diretório {:?}: {e}", current))?;
            }
            Err(error) => return Err(format!("inspecionar {:?}: {error}", current)),
        }
        let resolved = std::fs::canonicalize(&current)
            .map_err(|e| format!("resolver {:?}: {e}", current))?;
        if !resolved.starts_with(root) {
            return Err(format!("diretório escapou do destino: {:?}", current));
        }
    }
    Ok(())
}

fn clone_from_local_bank(home: &PathBuf, cid: &str) -> Option<Vec<giggs::Leaf>> {
    let hex_str = cid.strip_prefix("Qm").unwrap_or(cid);
    let plot_file = home.join("sporebank").join("plots").join(format!("{hex_str}.json"));
    let bytes = std::fs::read(&plot_file).ok()?;
    let plot: giggs::Plot = serde_json::from_slice(&bytes).ok()?;
    Some(plot.leaves)
}

fn pack_tree(dir: &PathBuf) -> Result<Vec<giggs::Leaf>, String> {
    fn skip(name: &str) -> bool {
        matches!(
            name,
            ".git" | "target" | "node_modules" | "dist" | "build" | ".cache"
                | "__pycache__" | ".venv" | "coverage" | ".data" | "graphify-out"
        )
    }
    fn sensitive_name(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        lower == ".env"
            || lower.starts_with(".env.")
            || matches!(
                lower.as_str(),
                ".npmrc" | ".pypirc" | ".netrc" | "credentials" | "credentials.json"
                    | "id_rsa" | "id_ed25519" | "secrets.yml" | "secrets.yaml"
            )
            || lower.ends_with(".pem")
            || lower.ends_with(".key")
            || lower.ends_with(".p12")
            || lower.ends_with(".pfx")
    }
    fn contains_secret(content: &[u8]) -> bool {
        let text = String::from_utf8_lossy(content);
        let lower = text.to_ascii_lowercase();
        if lower.contains("-----begin private key-----")
            || lower.contains("-----begin rsa private key-----")
            || lower.contains("-----begin openssh private key-----")
            || text.contains("github_pat_")
            || text.contains("ghp_")
            || text.contains("AKIA")
            || text.contains("xoxb-")
        {
            return true;
        }
        text.lines().any(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return false;
            }
            let Some((key, value)) = trimmed.split_once('=').or_else(|| trimmed.split_once(':')) else {
                return false;
            };
            let key = key.trim().to_ascii_lowercase().replace('-', "_");
            let value = value.trim().trim_matches(['\'', '"']);
            let secret_key = ["password", "passwd", "secret", "api_key", "private_key", "access_key"]
                .iter()
                .any(|needle| key.contains(needle))
                || key == "token"
                || key.ends_with("_token");
            let placeholder = value.is_empty()
                || value.starts_with('$')
                || value.starts_with("{{")
                || matches!(value.to_ascii_lowercase().as_str(), "changeme" | "example" | "placeholder" | "redacted");
            secret_key && !placeholder
        })
    }
    fn walk(dir: &PathBuf, prefix: &str, out: &mut Vec<giggs::Leaf>) -> Result<(), String> {
        let entries = std::fs::read_dir(dir).map_err(|e| format!("ler {:?}: {e}", dir))?;
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().to_string();
            if skip(&name) {
                continue;
            }
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|e| format!("inspecionar {:?}: {e}", path))?;
            if file_type.is_symlink() {
                return Err(format!("link simbólico não pode ser publicado: {rel}"));
            }
            if file_type.is_dir() {
                walk(&path, &rel, out)?;
            } else if file_type.is_file() {
                if sensitive_name(&name) {
                    return Err(format!("arquivo sensível não pode ser publicado: {rel}"));
                }
                let content = std::fs::read(&path).map_err(|e| format!("ler {:?}: {e}", path))?;
                if contains_secret(&content) {
                    return Err(format!("possível segredo detectado em: {rel}"));
                }
                out.push(giggs::Leaf { path: rel, content });
            } else {
                return Err(format!("entrada especial não pode ser publicada: {rel}"));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(dir, "", &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod repo_security_tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "mycelium-repo-security-{label}-{}-{}",
            std::process::id(),
            distribution_now()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn clone_rejects_traversal_and_absolute_paths() {
        let home = temp_dir("traversal");
        for path in ["../escape", "nested/../../escape", "/tmp/escape", "./file"] {
            let leaves = vec![giggs::Leaf { path: path.into(), content: b"x".to_vec() }];
            assert!(write_tree(&home, &leaves).is_err(), "accepted {path}");
        }
        std::fs::remove_dir_all(home).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn clone_rejects_symlinked_destination_components() {
        use std::os::unix::fs::symlink;
        let home = temp_dir("clone-symlink");
        let outside = temp_dir("clone-outside");
        symlink(&outside, home.join("linked")).unwrap();
        let leaves = vec![giggs::Leaf { path: "linked/file".into(), content: b"x".to_vec() }];
        assert!(write_tree(&home, &leaves).is_err());
        assert!(!outside.join("file").exists());
        std::fs::remove_dir_all(home).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn pack_rejects_sensitive_names_and_secret_content() {
        let named = temp_dir("secret-name");
        std::fs::write(named.join(".env"), "SAFE=value").unwrap();
        assert!(pack_tree(&named).is_err());
        std::fs::remove_dir_all(named).unwrap();

        let content = temp_dir("secret-content");
        std::fs::write(content.join("config.txt"), "api_key = real-sensitive-value").unwrap();
        assert!(pack_tree(&content).is_err());
        std::fs::remove_dir_all(content).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn pack_rejects_symlinks_without_following_them() {
        use std::os::unix::fs::symlink;
        let home = temp_dir("pack-symlink");
        let outside = temp_dir("pack-outside");
        std::fs::write(outside.join("secret"), "not scanned through link").unwrap();
        symlink(outside.join("secret"), home.join("linked")).unwrap();
        assert!(pack_tree(&home).is_err());
        std::fs::remove_dir_all(home).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn pack_allows_safe_hidden_metadata() {
        let home = temp_dir("safe-hidden");
        std::fs::write(home.join(".gitignore"), "target\n").unwrap();
        let leaves = pack_tree(&home).unwrap();
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].path, ".gitignore");
        std::fs::remove_dir_all(home).unwrap();
    }
}

fn mycelium_store_list_local(home: &PathBuf) -> Result<Vec<String>, String> {
    let bank_dir = home.join("sporebank").join("plots");
    let mut ids: Vec<String> = std::fs::read_dir(&bank_dir)
        .map_err(|e| format!("abrir sporebank: {e}"))?
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.strip_suffix(".json").map(|s| s.to_string())
        })
        .collect();
    ids.sort();
    Ok(ids)
}

async fn media_cmd(home: &PathBuf, action: MediaCmd) -> Result<(), String> {
    use mycelium_core::ContentId;
    use mycelium_media::{ingest_video, PinManager, VideoManifest};

    let sporebank_dir = home.join("sporebank");
    let media_dir = sporebank_dir.join("media");
    let chunks_dir = sporebank_dir.join("chunks");
    let pins_file = sporebank_dir.join("pinned_media.json");
    std::fs::create_dir_all(&media_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&chunks_dir).map_err(|e| e.to_string())?;

    match action {
        MediaCmd::Publish {
            file,
            title,
            channel,
            description,
            content_type,
            license,
            tags,
            chunk_mb,
        } => {
            if !file.is_file() {
                return Err(format!("Arquivo não encontrado: {:?}", file));
            }
            let data = std::fs::read(&file).map_err(|e| format!("Erro lendo arquivo: {e}"))?;
            let title_str = title.unwrap_or_else(|| {
                file.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "Vídeo Soberano".into())
            });
            let tag_list: Vec<String> = tags
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let node_id_str = NodeStore::open(home)
                .ok()
                .and_then(|ns| ns.load_or_create_gland().ok())
                .map(|g| g.node_id().to_string())
                .unwrap_or_else(|| "0000000000000000000000000000000000000000000000000000000000000000".to_string());

            let video_id = format!(
                "vid_{}",
                hex::encode(&blake3::hash(format!("{}:{}", title_str, data.len()).as_bytes()).as_bytes()[..8])
            );

            let chunk_bytes = chunk_mb.max(1) * 1024 * 1024;
            println!("[🍄 Media] Fatiando vídeo '{}' ({} bytes, chunks de {}MB)...", title_str, data.len(), chunk_mb);

            let result = ingest_video(
                &video_id,
                &node_id_str,
                &channel,
                &title_str,
                &description,
                &content_type,
                0,
                &license,
                tag_list,
                &data,
                Some(chunk_bytes),
            );

            // Persist chunks
            for chunk in &result.raw_chunks {
                let chunk_path = chunks_dir.join(format!("{}.bin", chunk.info.content_id));
                std::fs::write(&chunk_path, &chunk.data).map_err(|e| format!("Erro salvando chunk: {e}"))?;
            }

            // Persist manifest
            let manifest_json = serde_json::to_string_pretty(&result.manifest)
                .map_err(|e| format!("Erro serializando manifesto: {e}"))?;
            let manifest_path = media_dir.join(format!("{}.json", result.manifest_cid));
            std::fs::write(&manifest_path, &manifest_json)
                .map_err(|e| format!("Erro salvando manifesto: {e}"))?;

            // Pin locally
            if let Ok(pins) = PinManager::open(&pins_file) {
                pins.pin(result.manifest_cid);
                for c in &result.raw_chunks {
                    pins.pin(c.info.content_id);
                }
            }

            // Announce to daemon via IPC if socket exists
            let sock = home.join("mycelium.sock");
            if sock.exists() {
                let _ = call(
                    &sock,
                    Request::Sow {
                        message: format!("media:{}", result.manifest.title),
                        path: format!("media/{}.json", result.manifest_cid),
                        content: manifest_json,
                        qel: None,
                        nostr: false,
                        ghost: false,
                        recipient: None,
                    },
                )
                .await;
            }

            println!("\n[🍄 Media] ✅ Vídeo publicado com sucesso na malha soberana!");
            println!("    Título       : {}", result.manifest.title);
            println!("    Canal        : {}", result.manifest.channel_id);
            println!("    ContentId    : {}", result.manifest_cid);
            println!("    Fragmentos   : {} chunks (BLAKE3 endereçados)", result.raw_chunks.len());
            println!("    Tamanho      : {} bytes", result.manifest.total_byte_size);
            println!("    Licença      : {}", result.manifest.license);
            println!("    Armazenamento: Zero VPS (chunks distribuídos localmente no SporeBank)");
            println!("\nComandos úteis:");
            println!("    Inspecionar : mycelium media watch {}", result.manifest_cid);
            println!("    Fixar       : mycelium media pin {}", result.manifest_cid);
            println!("    EventHorizon: http://127.0.0.1:7474/plots/{}", result.manifest_cid);

            Ok(())
        }
        MediaCmd::Watch { cid } => {
            let manifest_path = media_dir.join(format!("{cid}.json"));
            if !manifest_path.is_file() {
                return Err(format!("Manifesto de vídeo '{cid}' não encontrado localmente em {:?}", manifest_path));
            }
            let data = std::fs::read(&manifest_path).map_err(|e| e.to_string())?;
            let manifest: VideoManifest = serde_json::from_slice(&data).map_err(|e| format!("Manifesto inválido: {e}"))?;

            println!("\n[🍄 Media] 📺 Vídeo Soberano — {}", manifest.title);
            println!("    ID           : {}", manifest.video_id);
            println!("    Canal        : {}", manifest.channel_id);
            println!("    Autor        : {}", manifest.author_pubkey);
            println!("    Formato      : {} ({})", manifest.content_type, manifest.resolution);
            println!("    Tamanho      : {} bytes", manifest.total_byte_size);
            println!("    Licença      : {}", manifest.license);
            println!("    Tags         : {}", manifest.tags.join(", "));
            println!("\n    Fragmentos (Chunks):");

            let mut available = 0;
            for chunk in &manifest.chunks {
                let chunk_path = chunks_dir.join(format!("{}.bin", chunk.content_id));
                let exists = chunk_path.is_file();
                if exists {
                    available += 1;
                }
                let status = if exists { "✓ disponível" } else { "✗ remoto/ausente" };
                println!("      #{} [{}] {} bytes — {}", chunk.index, chunk.content_id, chunk.byte_size, status);
            }

            println!("\n    Disponibilidade Local: {}/{} chunks ({:.1}%)", available, manifest.chunks.len(), (available as f64 / manifest.chunks.len().max(1) as f64) * 100.0);
            Ok(())
        }
        MediaCmd::Pin { cid } => {
            let id = ContentId::from_str(&cid).map_err(|_| format!("ContentId inválido: '{cid}'"))?;
            let pins = PinManager::open(&pins_file).map_err(|e| e.to_string())?;
            pins.pin(id);
            println!("[🍄 Media] 📌 Conteúdo {} fixado com sucesso no SporeBank local.", id);
            Ok(())
        }
        MediaCmd::Unpin { cid } => {
            let id = ContentId::from_str(&cid).map_err(|_| format!("ContentId inválido: '{cid}'"))?;
            let pins = PinManager::open(&pins_file).map_err(|e| e.to_string())?;
            if pins.unpin(&id) {
                println!("[🍄 Media] 🔓 Conteúdo {} desfixado com sucesso.", id);
            } else {
                println!("[🍄 Media] Conteúdo {} não estava fixado.", id);
            }
            Ok(())
        }
        MediaCmd::Pins => {
            let pins = PinManager::open(&pins_file).map_err(|e| e.to_string())?;
            let list = pins.list_pins();
            println!("\n[🍄 Media] Conteúdos Fixados (Pinned) no Nó Local: {}", list.len());
            for id in list {
                println!("  • {}", id);
            }
            Ok(())
        }
    }
}

async fn channel_cmd(home: &PathBuf, action: ChannelCmd) -> Result<(), String> {
    use mycelium_media::ChannelStore;

    let channels_dir = home.join("sporebank").join("channels");
    let store = ChannelStore::open(&channels_dir).map_err(|e| e.to_string())?;

    match action {
        ChannelCmd::Create { handle, display_name, bio } => {
            let node_id_str = NodeStore::open(home)
                .ok()
                .and_then(|ns| ns.load_or_create_gland().ok())
                .map(|g| g.node_id().to_string())
                .unwrap_or_else(|| "0000000000000000000000000000000000000000000000000000000000000000".to_string());

            let manifest = store.create_channel(
                &handle,
                &display_name,
                &node_id_str,
                &bio,
                "CC-BY-SA-4.0",
            );

            let cid = manifest.content_id().map_err(|e| e.to_string())?;

            // Anounce to daemon if running
            let sock = home.join("mycelium.sock");
            if sock.exists() {
                if let Ok(manifest_json) = serde_json::to_string_pretty(&manifest) {
                    let _ = call(
                        &sock,
                        Request::Sow {
                            message: format!("channel:{}", manifest.handle),
                            path: format!("channels/{}.json", manifest.channel_id),
                            content: manifest_json,
                            qel: None,
                            nostr: false,
                            ghost: false,
                            recipient: None,
                        },
                    )
                    .await;
                }
            }

            println!("\n[🍄 Canal] ✅ Canal soberano criado com sucesso!");
            println!("    ID           : {}", manifest.channel_id);
            println!("    Handle       : @{}", manifest.handle);
            println!("    Nome         : {}", manifest.display_name);
            println!("    Proprietário : {}", manifest.owner_pubkey);
            println!("    ContentId    : {}", cid);
            println!("    Revisão      : {}", manifest.revision);
            Ok(())
        }
        ChannelCmd::Publish { channel_id } => {
            let manifest = store.get_channel(&channel_id)
                .ok_or_else(|| format!("Canal '{}' não encontrado localmente.", channel_id))?;

            let sock = home.join("mycelium.sock");
            if sock.exists() {
                let manifest_json = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
                let _ = call(
                    &sock,
                    Request::Sow {
                        message: format!("channel:{}", manifest.handle),
                        path: format!("channels/{}.json", manifest.channel_id),
                        content: manifest_json,
                        qel: None,
                        nostr: false,
                        ghost: false,
                        recipient: None,
                    },
                )
                .await;
                println!("[🍄 Canal] ✅ Canal {} propagado na malha via gossipsub.", channel_id);
            } else {
                println!("[🍄 Canal] Canal {} salvo localmente (inicie o daemon para propagação em tempo real).", channel_id);
            }
            Ok(())
        }
        ChannelCmd::Show { channel_id } => {
            let manifest = store.get_channel(&channel_id)
                .ok_or_else(|| format!("Canal '{}' não encontrado localmente.", channel_id))?;

            println!("\n[🍄 Canal] Canal Soberano: {}", manifest.display_name);
            println!("    ID           : {}", manifest.channel_id);
            println!("    Handle       : @{}", manifest.handle);
            println!("    Bio          : {}", manifest.bio);
            println!("    Proprietário : {}", manifest.owner_pubkey);
            println!("    Revisão      : {}", manifest.revision);
            println!("    Vídeos ({})  :", manifest.videos.len());
            for v in manifest.videos {
                println!("      • {}", v);
            }
            Ok(())
        }
    }
}

async fn playlist_cmd(home: &PathBuf, action: PlaylistCmd) -> Result<(), String> {
    use mycelium_core::ContentId;
    use mycelium_media::PlaylistService;

    let playlists_dir = home.join("sporebank").join("playlists");
    std::fs::create_dir_all(&playlists_dir).map_err(|e| e.to_string())?;

    match action {
        PlaylistCmd::Create { title, description } => {
            let node_id_str = NodeStore::open(home)
                .ok()
                .and_then(|ns| ns.load_or_create_gland().ok())
                .map(|g| g.node_id().to_string())
                .unwrap_or_else(|| "0000000000000000000000000000000000000000000000000000000000000000".to_string());

            let playlist_id = format!(
                "pl_{}",
                hex::encode(&blake3::hash(format!("{}:{}", title, node_id_str).as_bytes()).as_bytes()[..8])
            );

            let manifest = PlaylistService::create_playlist(
                &playlist_id,
                &node_id_str,
                &title,
                &description,
                Vec::new(),
            );

            PlaylistService::save(&manifest, &playlists_dir).map_err(|e| e.to_string())?;

            println!("\n[🍄 Playlist] ✅ Playlist criada!");
            println!("    ID       : {}", manifest.playlist_id);
            println!("    Título   : {}", manifest.title);
            println!("    Autor    : {}", manifest.owner_pubkey);
            println!("    Revisão  : {}", manifest.revision);
            Ok(())
        }
        PlaylistCmd::Add { playlist_id, video_cid } => {
            let mut manifest = PlaylistService::load(&playlist_id, &playlists_dir)
                .map_err(|e| format!("Erro carregando playlist: {e}"))?;

            let cid = ContentId::from_str(&video_cid)
                .map_err(|_| format!("ContentId inválido: '{video_cid}'"))?;

            PlaylistService::append_video(&mut manifest, cid);
            PlaylistService::save(&manifest, &playlists_dir).map_err(|e| e.to_string())?;

            println!("\n[🍄 Playlist] ✅ Vídeo adicionado à playlist!");
            println!("    Playlist : {} ({})", manifest.title, manifest.playlist_id);
            println!("    Vídeo CID: {}", cid);
            println!("    Total    : {} vídeos (revisão {})", manifest.videos.len(), manifest.revision);
            Ok(())
        }
    }
}

async fn sclerotium_cmd(home: &PathBuf, action: SclerotiumCmd) -> Result<(), String> {
    use mycelium_core::NodeId;
    use mycelium_sclerotium::{
        EthernetCarrier, GhostCarrier, GhostLease, ImpulsePacket, LeaseCapability,
        WakeEndpoint, WakeReason, WakeToken,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    let sclerotium_dir = home.join("sclerotium");
    std::fs::create_dir_all(&sclerotium_dir).map_err(|e| e.to_string())?;
    let lease_file = sclerotium_dir.join("lease.json");

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    match action {
        SclerotiumCmd::Status => {
            println!("\n[🍄 Sclerotium] Estado do Protocolo de Dormência e Ghost Carrier");
            let gland_opt = NodeStore::open(home).ok().and_then(|ns| ns.load_or_create_gland().ok());
            if let Some(gland) = &gland_opt {
                println!("    NodeId Local      : {}", gland.node_id());
            } else {
                println!("    NodeId Local      : [não inicializado - execute `mycelium sprout`]");
            }

            println!("\n  Interfaces Físicas Locais (Ghost Carrier Ethernet / WoL):");
            let macs = EthernetCarrier::detect_local_macs();
            if macs.is_empty() {
                println!("    (nenhuma interface física com MAC detectada)");
            } else {
                for (mac, iface) in &macs {
                    let mac_str = format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                    );
                    println!("    • Interface {:<10} MAC: {}", iface, mac_str);
                }
            }

            println!("\n  GhostLease Local:");
            if lease_file.exists() {
                if let Ok(bytes) = std::fs::read(&lease_file) {
                    if let Ok(lease) = serde_json::from_slice::<GhostLease>(&bytes) {
                        let valid = lease.verify(now_secs).is_ok();
                        println!("    Origem            : {}", lease.origin_node_id);
                        println!("    Época             : {}", lease.epoch);
                        println!("    Válida até        : {} (agora: {})", lease.valid_until, now_secs);
                        println!("    Estado            : {}", if valid { "✅ ATIVA / VÁLIDA" } else { "❌ EXPIRADA" });
                        println!("    Capacidades       : {:?}", lease.capabilities);
                        println!("    Proxies Delegados : {}", if lease.authorized_proxies.is_empty() { "Aberto ao quórum de vizinhos".to_string() } else { format!("{:?}", lease.authorized_proxies) });
                        println!("    Endpoints Wake    : {:?}", lease.wake_endpoints);
                    } else {
                        println!("    (arquivo de lease corrompido)");
                    }
                }
            } else {
                println!("    (nenhuma lease ativa gerada - execute `mycelium sclerotium lease` antes de suspender)");
            }
            Ok(())
        }
        SclerotiumCmd::Hardware => {
            println!("\n[🍄 Sclerotium] Diagnóstico de Hardware e Portadoras Físicas");
            let macs = EthernetCarrier::detect_local_macs();
            println!("  Interfaces de Rede Ethernet / 802.11 detectadas: {}", macs.len());
            for (mac, iface) in &macs {
                let mac_str = format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                );
                let operstate = std::fs::read_to_string(format!("/sys/class/net/{}/operstate", iface))
                    .unwrap_or_else(|_| "desconhecido".into());
                println!("    • [{}] MAC: {} (estado: {})", iface, mac_str, operstate.trim());
            }

            println!("\n  Compatibilidade com Padrões:");
            println!("    • Linux ethtool / Wake-on-LAN : Suportado via pacotes Magic Packet SecureON");
            println!("    • IEEE 802.11ba WUR           : Compatível conceitualmente via ImpulsePacket de 50B");
            println!("    • MCU Sidecar (ESP32/RP2040)  : Compatível via Ghost Carrier Serial/LoRa");
            Ok(())
        }
        SclerotiumCmd::Lease { ttl_minutes, proxies, mac } => {
            let gland = NodeStore::open(home)
                .map_err(|e| e.to_string())?
                .load_or_create_gland()
                .map_err(|e| format!("Erro carregando gland: {e}"))?;

            let valid_until = now_secs + (ttl_minutes * 60);
            let mut authorized_proxies = Vec::new();
            for p in proxies {
                if let Ok(id) = NodeId::from_str(&p) {
                    authorized_proxies.push(id);
                }
            }

            let mut wake_endpoints = Vec::new();
            let mac_bytes = if let Some(m) = mac {
                let parts: Vec<&str> = m.split(':').collect();
                if parts.len() != 6 {
                    return Err("Endereço MAC deve ter formato XX:XX:XX:XX:XX:XX".into());
                }
                let mut b = [0u8; 6];
                for (i, p) in parts.iter().enumerate() {
                    b[i] = u8::from_str_radix(p, 16).map_err(|_| "Byte hexadecimal inválido no MAC")?;
                }
                Some(b)
            } else {
                EthernetCarrier::detect_local_macs().first().map(|(b, _)| *b)
            };

            if let Some(mac_arr) = mac_bytes {
                wake_endpoints.push(WakeEndpoint::EthernetWol { mac_address: mac_arr });
            }

            let capabilities = vec![
                LeaseCapability::AdvertiseContent,
                LeaseCapability::ReceiveMail,
                LeaseCapability::QueueJobs,
                LeaseCapability::RelayWake,
            ];

            let lease = GhostLease::create(
                &gland,
                1,
                valid_until,
                rand::random(),
                authorized_proxies,
                capabilities,
                vec![],
                wake_endpoints,
            );

            let json_str = serde_json::to_string_pretty(&lease).map_err(|e| e.to_string())?;
            std::fs::write(&lease_file, json_str).map_err(|e| e.to_string())?;

            println!("\n[🍄 Sclerotium] ✅ GhostLease criada e assinada com sucesso!");
            println!("    Nó de Origem      : {}", lease.origin_node_id);
            println!("    Válida até        : {} (por {} minutos)", lease.valid_until, ttl_minutes);
            println!("    Capacidades       : {:?}", lease.capabilities);
            println!("    Endpoints Wake    : {:?}", lease.wake_endpoints);
            println!("    Arquivo Salvo     : {}", lease_file.display());
            println!("    Agora você pode suspender o hardware. Os proxies manterão sua presença!");
            Ok(())
        }
        SclerotiumCmd::Wake { target, mac, reason } => {
            let target_node = NodeId::from_str(&target)
                .map_err(|_| format!("NodeId alvo inválido: '{target}'"))?;

            let parts: Vec<&str> = mac.split(':').collect();
            if parts.len() != 6 {
                return Err("Endereço MAC deve ter formato XX:XX:XX:XX:XX:XX".into());
            }
            let mut mac_arr = [0u8; 6];
            for (i, p) in parts.iter().enumerate() {
                mac_arr[i] = u8::from_str_radix(p, 16).map_err(|_| "Byte hexadecimal inválido no MAC")?;
            }

            let wake_reason = match reason.to_lowercase().as_str() {
                "urgent_compute" | "compute" => WakeReason::UrgentCompute,
                "exclusive_content" | "content" => WakeReason::ExclusiveContent,
                "direct_session" | "session" => WakeReason::DirectSession,
                "operator_manual" | "manual" => WakeReason::OperatorManual,
                _ => WakeReason::UrgentCompute,
            };

            let gland = NodeStore::open(home)
                .map_err(|e| e.to_string())?
                .load_or_create_gland()
                .map_err(|e| format!("Erro carregando gland: {e}"))?;

            let requester_id = gland.node_id();

            // Deriva chave de wake sintética
            let dummy_key = [0x42; 32];
            let token = WakeToken::new(
                &dummy_key,
                target_node,
                requester_id,
                now_secs,
                rand::random(),
                wake_reason,
            );

            let impulse = ImpulsePacket::from_token(&token);
            let carrier = EthernetCarrier::new(9);
            let endpoint = WakeEndpoint::EthernetWol { mac_address: mac_arr };

            carrier.send_impulse(&endpoint, &impulse).map_err(|e| e.to_string())?;

            println!("\n[🍄 Sclerotium] ⚡ Impulso de despertar disparado com sucesso!");
            println!("    Nó Alvo    : {}", target_node);
            println!("    MAC Destino: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac_arr[0], mac_arr[1], mac_arr[2], mac_arr[3], mac_arr[4], mac_arr[5]);
            println!("    Razão      : {:?}", wake_reason);
            println!("    Portadora  : Ethernet WoL Broadcast (porta 9 UDP) + ImpulsePacket (50B)");
            Ok(())
        }
    }
}

/// Normaliza e valida o hash de uma tx de pagamento (64 hex, com ou sem `0x`).
fn premium_tx_hash(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    let hex_part = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex_part.len() != 64 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "hash de pagamento inválido (esperado 64 dígitos hex, com ou sem 0x): '{raw}'"
        ));
    }
    Ok(format!("0x{}", hex_part.to_ascii_lowercase()))
}

/// `mycelium sub` — plano, emissão e verificação da lease de assinatura.
///
/// O pagamento (USDC na Base) é verificado fora, com
/// `mycelium-economy verify-base-usdc TX ENDEREÇO VALOR`; aqui o hash da tx é
/// registrado no ledger para que **uma tx gere exatamente uma lease**.
fn sub_cmd(home: &PathBuf, action: SubCmd) -> Result<(), String> {
    use mycelium_core::NodeId;
    use mycelium_sclerotium::{GhostLease, LeaseCapability};
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let premium_dir = home.join("premium");
    let plan_file = premium_dir.join("plan.json");
    let ledger_file = premium_dir.join("payments.jsonl");

    match action {
        SubCmd::Plan { usdc, days, recipient } => {
            if !(usdc.is_finite() && usdc > 0.0) {
                return Err("preço em USDC deve ser um número positivo".into());
            }
            if days == 0 {
                return Err("período do plano deve ser de 1 dia ou mais".into());
            }
            let addr = recipient.trim();
            let is_address = addr.len() == 42
                && addr.starts_with("0x")
                && addr.as_bytes()[2..].iter().all(|b| b.is_ascii_hexdigit());
            if !is_address {
                return Err(format!(
                    "endereço de recebimento inválido (esperado 0x + 40 hex): '{recipient}'"
                ));
            }

            std::fs::create_dir_all(&premium_dir).map_err(|e| e.to_string())?;
            let gland = NodeStore::open(home)
                .map_err(|e| e.to_string())?
                .load_or_create_gland()
                .map_err(|e| e.to_string())?;
            let plan = json!({
                "issuer": gland.node_id().to_string(),
                "price_usdc": usdc,
                "period_days": days,
                "recipient": addr.to_ascii_lowercase(),
                "chain": "base-8453",
                "published_at": now,
            });
            let serialized = serde_json::to_string_pretty(&plan).map_err(|e| e.to_string())?;
            std::fs::write(&plan_file, serialized).map_err(|e| e.to_string())?;

            println!("[🍄 Sub] ✅ Plano publicado: {}", plan_file.display());
            println!("    Preço     : US$ {usdc} por {days} dias");
            println!("    Receber   : {} (USDC, Base)", addr.to_ascii_lowercase());
            println!("    Exposto em: /vitrine/api/subscription");
            Ok(())
        }
        SubCmd::Issue {
            subscriber,
            payment_tx,
            days,
            valid_until,
            payment_verified,
            out,
        } => {
            let subscriber_id = NodeId::from_str(&subscriber)
                .map_err(|_| format!("NodeId do assinante inválido: '{subscriber}'"))?;
            let tx = premium_tx_hash(&payment_tx)?;
            std::fs::create_dir_all(&premium_dir).map_err(|e| e.to_string())?;

            // Período: --days, senão o plano publicado. --valid-until sobrepõe os dois.
            let period_days = match days {
                Some(d) => d,
                None => match valid_until {
                    Some(_) => 0,
                    None => {
                        let bytes = std::fs::read(&plan_file).map_err(|_| {
                            "plano não publicado — rode `mycelium sub plan` ou informe --days"
                                .to_string()
                        })?;
                        let plan: serde_json::Value =
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                        plan.get("period_days")
                            .and_then(|v| v.as_u64())
                            .ok_or_else(|| "plano sem period_days".to_string())? as u32
                    }
                },
            };
            if period_days == 0 && valid_until.is_none() {
                return Err("período da assinatura deve ser de 1 dia ou mais".into());
            }
            let valid_until_ts = match valid_until {
                Some(v) if v > 0 => v,
                Some(_) => return Err("--valid-until deve ser um timestamp Unix maior que zero".into()),
                None => now + u64::from(period_days) * 86_400,
            };

            // Fronteira de confiança: cada pagamento financia exatamente uma lease.
            if ledger_file.exists() {
                let ledger =
                    std::fs::read_to_string(&ledger_file).map_err(|e| e.to_string())?;
                for line in ledger.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let entry: serde_json::Value =
                        serde_json::from_str(line).map_err(|e| format!("ledger corrompido: {e}"))?;
                    if entry.get("payment_tx").and_then(|v| v.as_str()) == Some(tx.as_str()) {
                        return Err(format!(
                            "pagamento {tx} já utilizado (registro de {}) — uma tx gera uma lease",
                            entry.get("issued_at").and_then(|v| v.as_u64()).unwrap_or_default()
                        ));
                    }
                }
            }

            let gland = NodeStore::open(home)
                .map_err(|e| e.to_string())?
                .load_or_create_gland()
                .map_err(|e| e.to_string())?;
            let lease = GhostLease::create(
                &gland,
                1,
                valid_until_ts,
                rand::random(),
                vec![subscriber_id],
                vec![LeaseCapability::Subscriber],
                vec![],
                vec![],
            );
            // Compacta: a lease cabe num header HTTP e é colável no site.
            let lease_json = serde_json::to_string(&lease).map_err(|e| e.to_string())?;

            let out_path = out.unwrap_or_else(|| {
                premium_dir
                    .join("leases")
                    .join(format!("{subscriber_id}.json"))
            });
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&out_path, &lease_json).map_err(|e| e.to_string())?;

            let entry = json!({
                "payment_tx": tx,
                "payment_verified": payment_verified,
                "subscriber": subscriber_id.to_string(),
                "issuer": gland.node_id().to_string(),
                "period_days": period_days,
                "valid_until": valid_until_ts,
                "issued_at": now,
            });
            let mut ledger = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&ledger_file)
                .map_err(|e| e.to_string())?;
            writeln!(ledger, "{entry}").map_err(|e| e.to_string())?;

            println!("[🍄 Sub] ✅ Lease de assinatura emitida: {}", out_path.display());
            println!("    Assinante : {subscriber_id}");
            println!("    Válida até: {valid_until_ts} ({period_days} dias)");
            println!("    Pagamento : {tx} (verificado on-chain: {payment_verified})");
            println!("    Entregue o arquivo ao assinante. Teste do emissor:");
            println!(
                "    curl -H \"X-Subscription-Lease: $(cat {})\" http://127.0.0.1:7474/vitrine/premium",
                out_path.display()
            );
            Ok(())
        }
        SubCmd::Verify { lease, subscriber } => {
            let bytes = std::fs::read(&lease).map_err(|e| format!("{}: {e}", lease.display()))?;
            let parsed: GhostLease =
                serde_json::from_slice(&bytes).map_err(|e| format!("lease ilegível: {e}"))?;
            if !parsed.capabilities.contains(&LeaseCapability::Subscriber) {
                return Err("lease sem a capacidade de assinante".into());
            }
            if let Some(s) = subscriber {
                let expected = NodeId::from_str(&s)
                    .map_err(|_| format!("NodeId do assinante inválido: '{s}'"))?;
                if !parsed.authorized_proxies.contains(&expected) {
                    return Err("lease não foi emitida para este assinante".into());
                }
            }
            parsed.verify(now).map_err(|e| format!("lease INVÁLIDA: {e}"))?;
            println!(
                "[🍄 Sub] ✅ lease VÁLIDA até {} (resta {}s)",
                parsed.valid_until,
                parsed.valid_until.saturating_sub(now)
            );
            Ok(())
        }
    }
}

fn pkarr_transport(socks: std::net::SocketAddr, unsafe_direct: bool) -> mycelium_pkarr::Transport {
    if unsafe_direct {
        eprintln!("[🍄] ⚠️  --unsafe-direct: o relay verá o SEU IP. Sem anonimato.");
        mycelium_pkarr::Transport::DirectRevealsIp
    } else {
        mycelium_pkarr::Transport::Anonymous { socks5: socks }
    }
}

fn pkarr_relays(relays: Vec<String>) -> Vec<String> {
    if relays.is_empty() {
        mycelium_pkarr::DEFAULT_RELAYS
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        relays
    }
}

async fn pkarr_cmd(home: &PathBuf, action: PkarrCmd) -> Result<(), String> {
    use mycelium_pkarr::keystore::Keystore;
    use mycelium_pkarr::{now_secs, AnonRecord, Capability, Endpoint, RelayClient};

    let ks = Keystore::new(home.join("pkarr"));
    let load_cap = |ks: &Keystore| -> Result<_, String> {
        let (id, access) = ks.load().map_err(|e| e.to_string())?;
        let cap = Capability {
            master_public: id.public(),
            access_secret: access.clone(),
        };
        Ok((id, access, cap))
    };

    match action {
        PkarrCmd::Init { private } => {
            let (id, secret) = ks.init(private).map_err(|e| e.to_string())?;
            let cap = Capability {
                master_public: id.public(),
                access_secret: secret.map(zeroize_wrap),
            };
            println!(
                "[🍄] identidade anônima criada em {}",
                home.join("pkarr").display()
            );
            println!("[🍄] endereço: {}", cap.to_address());
            println!(
                "[🍄] guarde backup de {}/pkarr/ — sem ele o endereço morre.",
                home.display()
            );
            Ok(())
        }
        PkarrCmd::Address => {
            let (_, _, cap) = load_cap(&ks)?;
            println!("{}", cap.to_address());
            Ok(())
        }
        PkarrCmd::Publish {
            from_node,
            nostr_pubkey,
            nostr_relays,
            onion,
            veil_descriptor,
            plot,
            relays,
            socks,
            unsafe_direct,
            every,
            dry_run,
        } => {
            let (id, access, cap) = load_cap(&ks)?;
            let mut endpoints = Vec::new();
            if from_node {
                let (pubkey, relay) = node_nostr_endpoint(home).await?;
                println!("[🍄] endpoint do nó: {}… via {relay}", &pubkey[..16]);
                endpoints.push(Endpoint::Nostr {
                    pubkey,
                    relays: vec![relay],
                });
            }
            match (nostr_pubkey, nostr_relays.is_empty()) {
                (Some(pubkey), false) => endpoints.push(Endpoint::Nostr {
                    pubkey,
                    relays: nostr_relays,
                }),
                (None, true) => {}
                _ => return Err("--nostr-pubkey e --nostr-relay vão juntos".into()),
            }
            if let Some(addr) = onion {
                endpoints.push(Endpoint::Onion { addr });
            }
            if let Some(descriptor) = veil_descriptor {
                endpoints.push(Endpoint::Veil { descriptor });
            }
            for content_id in plot {
                endpoints.push(Endpoint::Plot { content_id });
            }
            let interval = every.map(|e| e.max(300));
            let client = if dry_run {
                None
            } else {
                Some(
                    RelayClient::new(&pkarr_relays(relays), pkarr_transport(socks, unsafe_direct))
                        .map_err(|e| e.to_string())?,
                )
            };
            loop {
                let now = now_secs();
                let validity = interval
                    .map(|i| i * 3)
                    .unwrap_or(mycelium_pkarr::EPOCH_SECS);
                let record = AnonRecord {
                    endpoints: endpoints.clone(),
                    not_after: now + validity,
                };
                let packet = mycelium_pkarr::seal(&id, access.as_deref(), &record, now)
                    .map_err(|e| e.to_string())?;
                // auto-checagem: o que publicamos tem de abrir com o endereço
                mycelium_pkarr::open(&cap, &packet, now)
                    .map_err(|e| format!("auto-checagem: {e}"))?;
                let size = packet.to_relay_payload().len();
                match &client {
                    None => {
                        println!(
                            "[🍄] dry-run ok · época {} · {size} bytes · chave da época {}",
                            mycelium_pkarr::epoch_of(now),
                            mycelium_pkarr::zbase32::encode(packet.public_key())
                        );
                        return Ok(());
                    }
                    Some(c) => match c.publish(&packet).await {
                        Ok(outcomes) => {
                            for o in outcomes {
                                let st = match o.result {
                                    Ok(()) => "ok".to_string(),
                                    Err(e) => e,
                                };
                                println!("[🍄] {} → {st}", o.relay);
                            }
                        }
                        Err(e) if interval.is_some() => eprintln!("[🍄] publicação falhou: {e}"),
                        Err(e) => return Err(e.to_string()),
                    },
                }
                let Some(i) = interval else { return Ok(()) };
                let jitter = rand::random::<f64>() * 0.4 - 0.2;
                let wait = ((i as f64) * (1.0 + jitter)) as u64;
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(wait)) => {}
                    _ = tokio::signal::ctrl_c() => return Ok(()),
                }
            }
        }
        PkarrCmd::Resolve {
            address,
            relays,
            socks,
            unsafe_direct,
        } => {
            let record = pkarr_resolve(&address, relays, socks, unsafe_direct).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        PkarrCmd::Connect {
            address,
            relays,
            socks,
            unsafe_direct,
        } => {
            let record = pkarr_resolve(&address, relays, socks, unsafe_direct).await?;
            let sock = home.join("mycelium.sock");
            let mut dialed = 0usize;
            for ep in &record.endpoints {
                match ep {
                    Endpoint::Nostr { pubkey, relays } => {
                        for relay in relays {
                            let req = Request::DialNostr {
                                relay: relay.clone(),
                                ghost: pubkey.clone(),
                            };
                            match call(&sock, req).await? {
                                Response::Ok { message } => {
                                    println!("[🍄] {message}");
                                    dialed += 1;
                                }
                                Response::Err { message } => eprintln!("[🍄] {relay}: {message}"),
                                other => eprintln!("[🍄] resposta inesperada: {other:?}"),
                            }
                        }
                    }
                    Endpoint::Plot { content_id } => {
                        println!("[🍄] Plot anunciado: Qm{content_id} (mycelium recall-code --plot Qm{content_id})")
                    }
                    Endpoint::Onion { addr } => println!("[🍄] onion anunciado: {addr}"),
                    Endpoint::Veil { .. } => println!("[🍄] descritor VEIL anunciado"),
                }
            }
            if dialed == 0 && record.endpoints.iter().any(|e| matches!(e, Endpoint::Nostr { .. })) {
                return Err("nenhum endpoint Nostr aceito pelo daemon".into());
            }
            println!("[🍄] acompanhe com `mycelium status` (vizinhos)");
            Ok(())
        }
    }
}

/// Resolve e decifra um endereço `myc1…` (época atual, depois a anterior).
async fn pkarr_resolve(
    address: &str,
    relays: Vec<String>,
    socks: std::net::SocketAddr,
    unsafe_direct: bool,
) -> Result<mycelium_pkarr::AnonRecord, String> {
    use mycelium_pkarr::{now_secs, Capability, RelayClient};
    let cap = Capability::from_address(address).map_err(|e| e.to_string())?;
    let client = RelayClient::new(&pkarr_relays(relays), pkarr_transport(socks, unsafe_direct))
        .map_err(|e| e.to_string())?;
    let now = now_secs();
    let mut errors = Vec::new();
    for (i, key) in cap
        .lookup_keys(now)
        .map_err(|e| e.to_string())?
        .into_iter()
        .enumerate()
    {
        let epoch = if i == 0 { "época atual" } else { "época anterior" };
        match client.resolve(&key).await {
            Ok(packet) => match mycelium_pkarr::open(&cap, &packet, now) {
                Ok(record) => return Ok(record),
                Err(e) => errors.push(format!("{epoch}: {e}")),
            },
            Err(e) => errors.push(format!("{epoch}: {e}")),
        }
    }
    Err(format!("não resolvido — {}", errors.join(" | ")))
}

/// GhostID e relay do transporte Nostr do daemon local, lidos do `status`.
async fn node_nostr_endpoint(home: &std::path::Path) -> Result<(String, String), String> {
    let sock = home.join("mycelium.sock");
    let Response::Status(report) = call(&sock, Request::Status).await? else {
        return Err("daemon não devolveu status".into());
    };
    for addr in &report.listen_addrs {
        let mut parts = addr.split('/').skip_while(|p| *p != "mycelium-nostr").skip(1);
        if let (Some(relay_hex), Some(ghost)) = (parts.next(), parts.next()) {
            let relay = hex::decode(relay_hex)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or("relay hex inválido no listen")?;
            return Ok((ghost.to_string(), relay));
        }
    }
    Err("o daemon não escuta no transporte Nostr (use --anonymous ou --nostr-transport)".into())
}

fn zeroize_wrap(secret: [u8; 32]) -> zeroize::Zeroizing<[u8; 32]> {
    zeroize::Zeroizing::new(secret)
}

fn root_paths(sel: RootSel) -> Result<Vec<PathBuf>, String> {
    let mut paths = sel.roots;
    if sel.auto {
        for p in mycelium_root::roots::scan() {
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    if paths.is_empty() {
        return Err("informe as raízes (ou --auto)".into());
    }
    Ok(paths)
}

fn root_cmd(action: RootCmd) -> Result<(), String> {
    use mycelium_root::log::Node;
    use mycelium_root::Vault;
    let err = |e: mycelium_root::RootError| e.to_string();
    match action {
        RootCmd::Init { k, label, roots } => {
            let v = Vault::create(&roots, k, &label).map_err(err)?;
            println!(
                "[🌱] Root {}-de-{} criado (cofre {}). Qualquer {} destas raízes abre tudo:",
                v.k(),
                v.n(),
                &v.vault_id()[..8],
                v.k()
            );
            for r in &roots {
                println!("     {}", r.display());
            }
            Ok(())
        }
        RootCmd::Ls { sel } => {
            let v = Vault::open(&root_paths(sel)?).map_err(err)?;
            println!("[🌱] raízes presentes {:?} de {} (K={})", v.present(), v.n(), v.k());
            for (path, node) in v.tree().iter() {
                match node {
                    Node::File { size, .. } => println!("{size:>12}  {path}"),
                    Node::Dir { .. } => println!("{:>12}  {path}/", "-"),
                }
            }
            Ok(())
        }
        RootCmd::Put { sel, files } => {
            let mut v = Vault::open(&root_paths(sel)?).map_err(err)?;
            let mut count = 0usize;
            let mut total = 0u64;
            let started = std::time::Instant::now();
            for f in files {
                let base = f.parent().map(|p| p.to_path_buf()).unwrap_or_default();
                let mut stack = vec![f.clone()];
                while let Some(p) = stack.pop() {
                    let rel = p.strip_prefix(&base).unwrap_or(&p).to_string_lossy().to_string();
                    if p.is_dir() {
                        v.mkdir(&rel).map_err(err)?;
                        for e in std::fs::read_dir(&p).map_err(|e| e.to_string())?.flatten() {
                            stack.push(e.path());
                        }
                    } else if p.is_file() {
                        let mut f = std::fs::File::open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                        let size = v.write_stream(&rel, &mut f).map_err(err)?;
                        total += size;
                        count += 1;
                        if count % 200 == 0 || size > 64 << 20 {
                            println!("[🌱] + {rel} ({size} bytes) · {count} arquivos, {} MB", total >> 20);
                        }
                    }
                }
            }
            let missing = v.n() as usize - v.present().len();
            let secs = started.elapsed().as_secs_f64().max(0.001);
            println!(
                "[🌱] {count} arquivo(s), {} MB gravado(s) em {secs:.0} s ({:.1} MB/s).",
                total >> 20,
                (total as f64 / 1048576.0) / secs
            );
            if missing > 0 {
                println!("[🌱] {missing} raiz(es) ausente(s) recebem os fragmentos por contato (`root sync`).");
            }
            Ok(())
        }
        RootCmd::Get { sel, args } => {
            let v = Vault::open(&root_paths(sel)?).map_err(err)?;
            let data = v.read_file(&args[0]).map_err(err)?;
            std::fs::write(&args[1], &data).map_err(|e| e.to_string())?;
            println!("[🌱] {} → {} ({} bytes)", args[0], args[1], data.len());
            Ok(())
        }
        RootCmd::Rm { sel, paths } => {
            let mut v = Vault::open(&root_paths(sel)?).map_err(err)?;
            for p in paths {
                v.remove(&p).map_err(err)?;
                println!("[🌱] - {p}");
            }
            Ok(())
        }
        RootCmd::Mount { sel, exec, mountpoint } => {
            let v = Vault::open(&root_paths(sel)?).map_err(err)?;
            let mp = &mountpoint[0];
            std::fs::create_dir_all(mp).map_err(|e| e.to_string())?;
            println!(
                "[🌱] Root montado em {} (raízes {:?}). Para desmontar: fusermount3 -u {}",
                mp.display(),
                v.present(),
                mp.display()
            );
            mycelium_root::mount::mount(v, mp, exec).map_err(err)
        }
        RootCmd::Sync { sel } => {
            let r = mycelium_root::sync(&root_paths(sel)?).map_err(err)?;
            println!(
                "[🌱] contato: {} entrada(s) de log copiada(s), {} fragmento(s) entregue(s)",
                r.log_copied, r.delivered
            );
            Ok(())
        }
        RootCmd::Heal { sel, replace, into } => {
            let mut v = Vault::open(&root_paths(sel)?).map_err(err)?;
            v.heal(replace, &into).map_err(err)?;
            println!("[🌱] raiz {replace} recriada em {}", into.display());
            Ok(())
        }
        RootCmd::Scan => {
            let found = mycelium_root::roots::scan();
            if found.is_empty() {
                println!("[🌱] nenhuma raiz em mídia montada");
            }
            for p in found {
                match mycelium_root::roots::Root::open(&p) {
                    Ok(r) => println!(
                        "{}  cofre {} · raiz {}/{} · K={} · {}",
                        p.display(),
                        &r.meta.vault[..8],
                        r.meta.index,
                        r.meta.n,
                        r.meta.k,
                        r.meta.label
                    ),
                    Err(e) => println!("{}  ({e})", p.display()),
                }
            }
            Ok(())
        }
    }
}

async fn rhizome_cmd(home: &PathBuf, action: RhizomeCmd) -> Result<(), String> {
    use mycelium_rhizome::{
        ChatMessageKind, FeedFilter, PostKind, RhizomeStore, VideoUploadMeta,
    };

    let sock = home.join("mycelium.sock");
    match action {
        RhizomeCmd::Ui { port } => {
            println!("[🌿 Mycelium Rhizome] Super-App Social Soberano ativo no Event Horizon:");
            println!("    👉 Web App     : http://127.0.0.1:{port}/rhizome/");
            println!("    👉 RSS 2.0     : http://127.0.0.1:{port}/rhizome/feed.xml");
            println!("    👉 ActivityPub : http://127.0.0.1:{port}/rhizome/ap/actor");
            println!("    👉 API Feed    : http://127.0.0.1:{port}/rhizome/api/feed");
            Ok(())
        }
        RhizomeCmd::Identity => {
            let mut store = RhizomeStore::open(home).map_err(|e| e.to_string())?;
            let ov = store.overview();
            println!("[🌿 Rhizome] Identidade Soberana:");
            println!("    Handle        : @{} ({})", ov.profile.handle, ov.profile.display_name);
            println!("    Gland NodeId  : {}", ov.identity.node_id);
            println!("    PKARR (myc1)  : {}", ov.identity.pkarr_addr);
            println!("    Nostr GhostID : {}", ov.identity.ghost_pubkey_hex);
            println!(
                "    ML-KEM-1024   : {}... ({} bytes)",
                &ov.identity.mlkem1024_pubkey_hex[..32],
                ov.identity.mlkem1024_pubkey_hex.len() / 2
            );
            Ok(())
        }
        RhizomeCmd::Profile { handle, name, bio } => {
            let mut store = RhizomeStore::open(home).map_err(|e| e.to_string())?;
            let (prof, env, plot) = store
                .update_profile(handle, name, bio, None, None, None)
                .map_err(|e| e.to_string())?;
            if sock.exists() {
                let _ = call(
                    &sock,
                    Request::RhizomeBroadcast {
                        event: env,
                        plots: plot.into_iter().collect(),
                        media_packets: vec![],
                    },
                )
                .await;
            }
            println!(
                "[🌿 Rhizome] Perfil atualizado: @{} ({}) rev. {}",
                prof.handle, prof.display_name, prof.revision
            );
            Ok(())
        }
        RhizomeCmd::Post {
            text,
            kind,
            title,
            community,
            reply_to,
            repost_of,
        } => {
            let mut store = RhizomeStore::open(home).map_err(|e| e.to_string())?;
            let post_kind = match kind.as_str() {
                "article" => PostKind::Article,
                "photo_gallery" | "photo" => PostKind::PhotoGallery,
                _ => PostKind::Microblog,
            };
            let (post, env, plot) = store
                .create_post(
                    post_kind,
                    title,
                    text,
                    vec![],
                    community,
                    vec![],
                    reply_to,
                    repost_of,
                    None,
                    None,
                )
                .map_err(|e| e.to_string())?;
            if sock.exists() {
                let _ = call(
                    &sock,
                    Request::RhizomeBroadcast {
                        event: env,
                        plots: plot.into_iter().collect(),
                        media_packets: vec![],
                    },
                )
                .await;
            }
            println!("[🌿 Rhizome] Post publicado e assinado: {}", post.post_id);
            Ok(())
        }
        RhizomeCmd::Story { caption, ttl_hours } => {
            let mut store = RhizomeStore::open(home).map_err(|e| e.to_string())?;
            let (story, isotope_key, atom, env) = store
                .create_story(caption, None, None, Some(ttl_hours.saturating_mul(3600)))
                .map_err(|e| e.to_string())?;
            if sock.exists() {
                let _ = call(
                    &sock,
                    Request::RhizomeStorySync {
                        isotope_key,
                        atom,
                        event: env,
                    },
                )
                .await;
            }
            println!(
                "[🌿 Rhizome] Story efêmero publicado ({}h TTL via Isotope): {}",
                ttl_hours, story.story_id
            );
            Ok(())
        }
        RhizomeCmd::Video {
            file,
            title,
            description,
            short,
            doc,
            commons,
            thumbnail,
            replicas,
            license,
            tags,
        } => {
            let mut store = RhizomeStore::open(home).map_err(|e| e.to_string())?;
            let mut extra_packets = Vec::new();
            let thumbnail_cid = if let Some(ref thumb_path) = thumbnail {
                let tb = std::fs::read(thumb_path)
                    .map_err(|e| format!("falha ao ler thumbnail {}: {e}", thumb_path.display()))?;
                let mime = mycelium_rhizome::detect_mime_from_bytes(&tb);
                let name = thumb_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("thumb.png");
                let (att, pkts) = store
                    .store_media_blob(name, mime, &tb, &title, None)
                    .map_err(|e| e.to_string())?;
                extra_packets = pkts;
                Some(att.cid)
            } else {
                None
            };

            let content_type = if short {
                "short".to_string()
            } else if doc {
                "doc".to_string()
            } else {
                "longform".to_string()
            };
            let profile = store.local_profile();
            let channel_id = profile
                .channel_id
                .clone()
                .unwrap_or_else(|| format!("ch_{}", &profile.node_id[..12.min(profile.node_id.len())]));
            let author_pk = store.keys().ed25519_pubkey_hex();
            let chunks_dir = store.chunks_dir();

            let prepared = mycelium_rhizome::prepare_video_ingest_from_file(
                &file,
                &chunks_dir,
                &author_pk,
                &channel_id,
                VideoUploadMeta {
                    title,
                    description,
                    is_short: short,
                    content_type,
                    duration_secs: 0,
                    resolution: if short { "1080x1920".into() } else { "1080p".into() },
                    mime_type: "video/mp4".into(),
                    license,
                    tags,
                    community_id: None,
                    commons_project_id: commons,
                    thumbnail_cid,
                    target_replicas: replicas,
                },
            )
            .map_err(|e| e.to_string())?;

            let (post, manifest, envs, plots, mut packets) = store
                .commit_prepared_video(prepared)
                .map_err(|e| e.to_string())?;
            let mcid = post.video_manifest_cid.clone().unwrap_or_default();
            let device = if cfg!(target_os = "android")
                || std::env::var("MYCELIUM_ANDROID").ok().as_deref() == Some("1")
            {
                "mobile"
            } else {
                "desktop"
            };
            let (rcpts, rcpt_envs) = store
                .issue_local_shard_receipts(&mcid, device)
                .unwrap_or_default();
            packets.extend(extra_packets);

            if sock.exists() {
                for (idx, env) in envs.into_iter().chain(rcpt_envs.into_iter().take(32)).enumerate() {
                    let batch_plots = if idx == 0 { plots.clone() } else { vec![] };
                    let batch_packets = if idx == 0 { packets.clone() } else { vec![] };
                    let _ = call(
                        &sock,
                        Request::RhizomeBroadcast {
                            event: env,
                            plots: batch_plots,
                            media_packets: batch_packets,
                        },
                    )
                    .await;
                }
            }
            println!(
                "[🎬 Rhizome Tube MMP] Vídeo publicado: {} ({} chunks BLAKE3, {} bytes, {} recibos PoS)",
                mcid,
                manifest.chunks.len(),
                manifest.total_byte_size,
                rcpts.len()
            );
            Ok(())
        }
        RhizomeCmd::Feed {
            lens,
            kind,
            query,
            limit,
        } => {
            let store = RhizomeStore::open(home).map_err(|e| e.to_string())?;
            let items = store.query_feed(&FeedFilter {
                kind,
                lens: Some(lens.clone()),
                query,
                limit: Some(limit),
                ..Default::default()
            });
            println!("[🌿 Rhizome Feed] Lente: {lens} · {} item(s)", items.len());
            for item in items {
                let p = item.post;
                println!(
                    "  • [{:?}] @{} ({}) — {}",
                    p.kind,
                    p.author_handle,
                    &p.post_id[..14.min(p.post_id.len())],
                    p.title.as_deref().unwrap_or(&p.body)
                );
            }
            Ok(())
        }
        RhizomeCmd::ChatSend {
            to,
            text,
            mlkem,
            nostr_fallback,
        } => {
            let mut store = RhizomeStore::open(home).map_err(|e| e.to_string())?;
            let (sealed, msg, nostr_ev) = store
                .send_direct_chat(
                    &to,
                    mlkem.as_deref(),
                    ChatMessageKind::Text,
                    text,
                    None,
                    None,
                    nostr_fallback,
                )
                .map_err(|e| e.to_string())?;
            let target_node = sealed.recipient_node_id.clone();
            if sock.exists() {
                let _ = call(
                    &sock,
                    Request::RhizomeChatSend {
                        to_node_id: target_node,
                        envelope: sealed,
                    },
                )
                .await;
            }
            println!(
                "[💬 Rhizome Zap PQ] Mensagem cifrada (ML-KEM-1024 + XChaCha20) enviada: {}",
                msg.plaintext.msg_id
            );
            if let Some(ev) = nostr_ev {
                println!(
                    "    ⚡ Fallback Nostr NIP-44 kind {}: {}",
                    ev.kind, ev.id
                );
            }
            Ok(())
        }
        RhizomeCmd::ChatInbox { conversation } => {
            let store = RhizomeStore::open(home).map_err(|e| e.to_string())?;
            if let Some(conv_id) = conversation {
                let msgs = store.get_conversation_messages(&conv_id);
                println!("[💬 Conversa {conv_id}] {} mensagem(ns):", msgs.len());
                for m in msgs {
                    println!(
                        "  [{}] {}: {} ({:?} · {})",
                        m.direction, m.plaintext.sender_handle, m.plaintext.body, m.status, m.transport
                    );
                }
            } else {
                let convs = store.list_conversations();
                println!("[💬 Rhizome Zap PQ] {} conversa(s):", convs.len());
                for c in convs {
                    println!(
                        "  • {} ({}) — {} msgs · última: {}",
                        c.title, c.conversation_id, c.message_count, c.last_message_preview
                    );
                }
            }
            Ok(())
        }
        RhizomeCmd::ImportX { file } => {
            let raw = std::fs::read_to_string(&file)
                .map_err(|e| format!("falha ao ler {}: {e}", file.display()))?;
            let mut store = RhizomeStore::open(home).map_err(|e| e.to_string())?;
            let (posts, envs, plots) = store.import_x_archive(&raw).map_err(|e| e.to_string())?;
            if sock.exists() {
                for (idx, env) in envs.into_iter().enumerate() {
                    let batch_plots = if idx == 0 { plots.clone() } else { vec![] };
                    let _ = call(
                        &sock,
                        Request::RhizomeBroadcast {
                            event: env,
                            plots: batch_plots,
                            media_packets: vec![],
                        },
                    )
                    .await;
                }
            }
            println!(
                "[𝕏 Importador] {} tweet(s) importados e assinados por Ed25519 no Rhizome.",
                posts.len()
            );
            Ok(())
        }
        RhizomeCmd::ImportWhatsapp { file, title } => {
            let raw = std::fs::read_to_string(&file)
                .map_err(|e| format!("falha ao ler {}: {e}", file.display()))?;
            let mut store = RhizomeStore::open(home).map_err(|e| e.to_string())?;
            let (conv_id, count) = store
                .import_whatsapp_chat(&title, &raw)
                .map_err(|e| e.to_string())?;
            println!(
                "[📱 Importador WhatsApp] {count} mensagem(ns) importadas para conversa {conv_id}."
            );
            Ok(())
        }
        RhizomeCmd::Bridge { format, post_id } => {
            let store = RhizomeStore::open(home).map_err(|e| e.to_string())?;
            match format.as_str() {
                "rss" => println!("{}", store.export_rss("http://127.0.0.1:7474/rhizome")),
                "ap-actor" => println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &store.export_activitypub_actor("http://127.0.0.1:7474/rhizome")
                    )
                    .unwrap_or_default()
                ),
                "ap-outbox" => println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &store.export_activitypub_outbox("http://127.0.0.1:7474/rhizome")
                    )
                    .unwrap_or_default()
                ),
                "nostr" => {
                    let pid = post_id.ok_or("informe --post-id <Qm...> para exportar em Nostr")?;
                    let ev = store
                        .export_post_as_nostr(&pid)
                        .map_err(|e| e.to_string())?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&ev).unwrap_or_default()
                    );
                }
                other => return Err(format!("formato de bridge desconhecido: {other}")),
            }
            Ok(())
        }
        RhizomeCmd::Sync => {
            if !sock.exists() {
                return Err("daemon mycelium não está em execução neste home".into());
            }
            match call(&sock, Request::RhizomeSyncNow).await {
                Ok(Response::Ok { message }) => {
                    println!("[🌿 Rhizome] {message}");
                    Ok(())
                }
                Ok(other) => Err(format!("resposta inesperada: {other:?}")),
                Err(e) => Err(e.to_string()),
            }
        }
        RhizomeCmd::CommonsCreate {
            slug,
            title,
            summary,
            goal,
            spores_pool,
            release_date,
        } => {
            let mut store = RhizomeStore::open(home).map_err(|e| e.to_string())?;
            let prof = store.local_profile();
            let default_splits = vec![
                mycelium_rhizome::SplitContractParty {
                    role: "Criador & Coordenador".into(),
                    pubkey: prof.ed25519_pubkey_hex,
                    name: prof.display_name,
                    split_percentage: 70,
                },
                mycelium_rhizome::SplitContractParty {
                    role: "Infraestrutura P2P".into(),
                    pubkey: "swarm_pool".into(),
                    name: "Enxame & Seeders P2P".into(),
                    split_percentage: 30,
                },
            ];
            let (proj, env, plot) = store
                .create_commons_project(
                    slug,
                    title,
                    summary,
                    String::new(),
                    goal,
                    spores_pool,
                    release_date,
                    vec![],
                    default_splits,
                    vec![],
                )
                .map_err(|e| e.to_string())?;
            if sock.exists() {
                let _ = call(
                    &sock,
                    Request::RhizomeBroadcast {
                        event: env,
                        plots: plot.into_iter().collect(),
                        media_packets: vec![],
                    },
                )
                .await;
            }
            println!(
                "[🌱 MCP Commons] Projeto publicado: {} ({}) · meta {} P2P",
                proj.title, proj.project_id, proj.funding_goal
            );
            Ok(())
        }
        RhizomeCmd::CommonsList => {
            let store = RhizomeStore::open(home).map_err(|e| e.to_string())?;
            let list = store.list_commons_projects();
            println!("[🌱 MCP Commons] {} projeto(s):", list.len());
            for v in list {
                println!(
                    "  • {} [{}] ({}) — {:.1}/{:.1} P2P · {} Spores · {} vídeos",
                    v.project.title,
                    v.project.slug,
                    v.project.project_id,
                    v.current_raised,
                    v.project.funding_goal,
                    v.spores_contributed,
                    v.linked_video_cids.len()
                );
            }
            Ok(())
        }
        RhizomeCmd::CommonsContribute {
            project,
            amount,
            spores,
            message,
        } => {
            let mut store = RhizomeStore::open(home).map_err(|e| e.to_string())?;
            let (contrib, view, env, plot) = store
                .contribute_to_commons(&project, String::new(), amount, spores, message)
                .map_err(|e| e.to_string())?;
            if sock.exists() {
                let _ = call(
                    &sock,
                    Request::RhizomeBroadcast {
                        event: env,
                        plots: plot.into_iter().collect(),
                        media_packets: vec![],
                    },
                )
                .await;
            }
            println!(
                "[💚 MCP] Contribuição registrada ({}): total agora {:.1}/{:.1} P2P",
                contrib.contribution_id, view.current_raised, view.project.funding_goal
            );
            Ok(())
        }
        RhizomeCmd::LensList => {
            let store = RhizomeStore::open(home).map_err(|e| e.to_string())?;
            let lenses = store.list_all_lenses();
            println!("[🔭 Lentes MEP] {} lente(s):", lenses.len());
            for l in lenses {
                println!("  • {} ({}) — {}", l.name, l.id, l.description);
            }
            Ok(())
        }
        RhizomeCmd::LensCreate {
            name,
            description,
            reciprocity,
            replication,
            freshness,
            commons,
        } => {
            let mut store = RhizomeStore::open(home).map_err(|e| e.to_string())?;
            let mut weights = std::collections::BTreeMap::new();
            weights.insert("reciprocity_score".into(), reciprocity);
            weights.insert("replication_health".into(), replication);
            weights.insert("freshness".into(), freshness);
            weights.insert("commons_weight".into(), commons);
            let (lens, env, plot) = store
                .create_custom_lens(name, description, weights)
                .map_err(|e| e.to_string())?;
            if sock.exists() {
                let _ = call(
                    &sock,
                    Request::RhizomeBroadcast {
                        event: env,
                        plots: plot.into_iter().collect(),
                        media_packets: vec![],
                    },
                )
                .await;
            }
            println!(
                "[🔭 Lente MEP] Lente criada e assinada: {} ({})",
                lens.name, lens.lens_id
            );
            Ok(())
        }
        RhizomeCmd::Swarm { port } => {
            let v = http_get_local_json(port, "/rhizome/api/swarm").await?;
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            Ok(())
        }
        RhizomeCmd::Wallet { port } => {
            if let Ok(v) = http_get_local_json(port, "/rhizome/api/wallet").await {
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
                return Ok(());
            }
            if sock.exists() {
                let resp = call(&sock, Request::LedgerInfo)
                    .await
                    .map_err(|e| e.to_string())?;
                println!("{resp:?}");
                return Ok(());
            }
            Err("daemon offline (Horizon HTTP e socket indisponíveis)".into())
        }
    }
}

async fn http_get_local_json(port: u16, path: &str) -> Result<serde_json::Value, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| format!("falha ao conectar a 127.0.0.1:{port}: {e}"))?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("falha ao enviar HTTP GET: {e}"))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("falha ao ler resposta HTTP: {e}"))?;
    let text = String::from_utf8_lossy(&buf);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .ok_or_else(|| "resposta HTTP inválida".to_string())?;
    serde_json::from_str(body).map_err(|e| format!("JSON inválido de {path}: {e}"))
}
