//! # Vitrine Ion — A Vitrine Soberana do Mycelium Network
//!
//! Reúne em uma experiência web única e unificada os 4 grandes pilares da rede:
//! 1. 🌐 **Substituto para Hospedagem Web (Adeus AWS/Vercel)**: Chambers do Vacuum, Singularity Event Horizon e CIDs imutáveis.
//! 2. 🐙 **Substituto para Git e GitHub (Adeus Microsoft/GitHub)**: Forja de código soberana, `mycelium repo publish/clone` e browser `/src/`.
//! 3. 📺 **Concorrente do YouTube (Mycelium Video)**: Streaming P2P em chunks BLAKE3 de 2MB, canais e playlists assinados via ed25519/GhostID.
//! 4. 🕹️ **Lojinha & SDK de Jogos Antigos (MicroEasy Studio LITE + Mycelium Store)**: Emulação (RetroArch, MAME, QEMU, WASM) e catálogo P2P.
//! 5. 🍄 **Substrato Basal (Sclerotium & Ghost Carrier)**: Nós dormentes com despertar seletivo e conservação de energia.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use mycelium_media::manifest::{ChannelManifest, PlaylistManifest};
use mycelium_sclerotium::{EthernetCarrier, GhostLease, LeaseCapability, LeaseError};
use serde_json::json;
use std::path::{Path as FsPath, PathBuf};

#[derive(Clone)]
pub struct VitrineState {
    pub home: PathBuf,
}

pub fn create_vitrine_router(home: impl AsRef<FsPath>) -> Router {
    Router::new()
        .route("/", get(showcase_ui))
        .route("/api/overview", get(overview_api))
        .route("/api/subscription", get(subscription_api))
        .route("/api/repos", get(repos_api))
        .route("/api/channels", get(channels_api))
        .route("/api/playlists", get(playlists_api))
        .route("/api/games", get(games_api))
        .route("/premium", get(premium))
        .with_state(VitrineState {
            home: home.as_ref().to_path_buf(),
        })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn showcase_ui() -> impl IntoResponse {
    let html = include_str!("../../../deploy/store-ui/vitrine.html");
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html.to_string(),
    )
}

async fn overview_api(State(state): State<VitrineState>) -> impl IntoResponse {
    let home = &state.home;

    // 1. Identidade e Nó
    let gland_seed_path = home.join("gland.seed");
    let node_id = if let Ok(seed_bytes) = std::fs::read(&gland_seed_path) {
        if seed_bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&seed_bytes);
            mycelium_pheromones::Gland::from_seed(arr).node_id().to_string()
        } else {
            "desconhecido".into()
        }
    } else {
        "não-inicializado".into()
    };

    // 2. Repositórios (Git soberano)
    let plots_dir = home.join("sporebank").join("plots");
    let mut repo_count = 0;
    if let Ok(entries) = std::fs::read_dir(&plots_dir) {
        repo_count = entries.flatten().count();
    }

    // 3. Canais e Vídeos (Mycelium Video)
    let channels_dir = home.join("sporebank").join("channels");
    let mut channel_count = 0;
    if let Ok(entries) = std::fs::read_dir(&channels_dir) {
        channel_count = entries.flatten().count();
    }

    // 4. Jogos da Store (Mycelium Store)
    let store_catalog = home.join("sporebank").join("store").join("catalog.json");
    let mut games_count = 0;
    if store_catalog.exists() {
        if let Ok(bytes) = std::fs::read(&store_catalog) {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if let Some(arr) = val.as_array() {
                    games_count = arr.len();
                }
            }
        }
    }

    // 5. Sclerotium e WoL
    let lease_file = home.join("sclerotium").join("lease.json");
    let mut lease_active = false;
    let mut lease_valid_until = 0u64;
    let now_secs = unix_now();

    if lease_file.exists() {
        if let Ok(bytes) = std::fs::read(&lease_file) {
            if let Ok(lease) = serde_json::from_slice::<GhostLease>(&bytes) {
                lease_active = lease.verify(now_secs).is_ok();
                lease_valid_until = lease.valid_until;
            }
        }
    }

    let physical_macs = EthernetCarrier::detect_local_macs()
        .into_iter()
        .map(|(mac, iface)| {
            format!(
                "{}: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                iface, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            )
        })
        .collect::<Vec<_>>();

    let response = json!({
        "status": "online",
        "substrate": "mycelium-network",
        "node_id": node_id,
        "pillars": {
            "hosting": {
                "title": "Hospedagem Web Descentralizada",
                "tagline": "Adeus VPS, AWS e Vercel",
                "status": "ativo",
                "gateway_url": "http://127.0.0.1:7474/",
                "features": [
                    "Conteúdo endereçado por hash BLAKE3 (ContentId)",
                    "Vacuum Chambers isoladas com bubblewrap",
                    "Singularity Event Horizon com roteamento de órbita"
                ]
            },
            "forge": {
                "title": "Forja Soberana de Código",
                "tagline": "Substituto Descentralizado do Git e GitHub",
                "status": "ativo",
                "repos_count": repo_count,
                "browser_url": "/hub/",
                "raw_browser_url": "/src/",
                "cli_commands": {
                    "publish": "mycelium repo publish --message 'feat: release' ./meu-app",
                    "clone": "mycelium repo clone --cid Qm..."
                }
            },
            "video": {
                "title": "Mycelium Video",
                "tagline": "Concorrente Descentralizado do YouTube",
                "status": "ativo",
                "channels_count": channel_count,
                "app_path": "/media/bruno/SAMBOOK/Mycelium Video/Mycelium Video/",
                "features": [
                    "Chunks de vídeo BLAKE3 de 2MB via gossipsub e DHT",
                    "Canais e playlists assinados criptograficamente",
                    "Zero moderação centralizada ou banimentos arbitrários"
                ]
            },
            "games": {
                "title": "MicroEasy Studio & Mycelium Store",
                "tagline": "Lojinha P2P e SDK de Jogos e Emulação",
                "status": "ativo",
                "games_count": games_count,
                "store_url": "/store/",
                "sdk_path": "/media/bruno/SAMBOOK/MicroEasy Studio LITE/microeasy-studio-p5-integration/",
                "supported_engines": ["RetroArch", "MAME", "QEMU", "WASM", "P5.js / Canvas"]
            },
            "sclerotium": {
                "title": "Protocolo Sclerotium & Ghost Carrier",
                "tagline": "Dormência Biológica e Economia Energética",
                "lease_active": lease_active,
                "lease_valid_until": lease_valid_until,
                "physical_interfaces": physical_macs,
                "features": [
                    "Transição biológica Live -> Dormant -> Ghost -> Dead",
                    "Wake-on-LAN Ethernet e Rádio Sub-GHz / LoRa",
                    "Despertar seletivo anti-Vampire Attacks via WakeToken"
                ]
            }
        }
    });

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
        response.to_string(),
    )
}

async fn repos_api(State(state): State<VitrineState>) -> impl IntoResponse {
    let plots_dir = state.home.join("sporebank").join("plots");
    let mut repos = Vec::new();

    if let Ok(entries) = std::fs::read_dir(plots_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(bytes) = std::fs::read(&path) {
                    if let Ok(plot) = serde_json::from_slice::<giggs::Plot>(&bytes) {
                        if plot.is_public() {
                            let cid_hex = path.file_stem().unwrap().to_string_lossy();
                            repos.push(json!({
                                "cid": format!("Qm{cid_hex}"),
                                "message": plot.message,
                                "author": plot.author.to_string(),
                                "leaves": plot.leaves.len(),
                                "url": format!("/src/Qm{cid_hex}")
                            }));
                        }
                    }
                }
            }
        }
    }

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
        json!({ "repos": repos }).to_string(),
    )
}

async fn channels_api(State(state): State<VitrineState>) -> impl IntoResponse {
    let channels_dir = state.home.join("sporebank").join("channels");
    let mut channels = Vec::new();

    if let Ok(entries) = std::fs::read_dir(channels_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(bytes) = std::fs::read(&p) {
                    if let Ok(manifest) = serde_json::from_slice::<ChannelManifest>(&bytes) {
                        channels.push(manifest);
                    }
                }
            }
        }
    }

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
        json!({ "channels": channels }).to_string(),
    )
}

async fn playlists_api(State(state): State<VitrineState>) -> impl IntoResponse {
    let playlists_dir = state.home.join("sporebank").join("playlists");
    let mut playlists = Vec::new();

    if let Ok(entries) = std::fs::read_dir(playlists_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(bytes) = std::fs::read(&p) {
                    if let Ok(manifest) = serde_json::from_slice::<PlaylistManifest>(&bytes) {
                        playlists.push(manifest);
                    }
                }
            }
        }
    }

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
        json!({ "playlists": playlists }).to_string(),
    )
}

async fn games_api(State(state): State<VitrineState>) -> impl IntoResponse {
    let store_catalog = state.home.join("sporebank").join("store").join("catalog.json");
    let mut games: Vec<serde_json::Value> = Vec::new();

    if store_catalog.exists() {
        if let Ok(bytes) = std::fs::read(&store_catalog) {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if let Some(arr) = val.as_array() {
                    games = arr.clone();
                }
            }
        }
    }

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
        json!({ "games": games }).to_string(),
    )
}

// ============================================================================
// 🍄 Assinatura premium — site e serviço SEM hospedagem, SEM domínio, SEM VPS
// ============================================================================
//
// O conteúdo público é servido pelo Event Horizon sem autenticação. O conteúdo
// premium é liberado por uma **lease de assinatura**: JSON compacto assinado
// ed25519 pelo emissor, com `valid_until` impondo o período cobrado e
// `LeaseCapability::Subscriber` impondo a autorização. Sem cookie, sem sessão,
// sem banco: a credencial é a própria assinatura criptográfica.
//
// ponytail: teto desta versão — a lease é um bearer token (quem a possui usa),
// sem revogação parcial e sem binding à identidade da requisição. Upgrade:
// desafio-assinatura com o NodeId do portador + revogação por nonce/epoch.

/// Extrai a lease enviada pelo cliente: `X-Subscription-Lease: <json compacto>`
/// ou `Authorization: Bearer <json compacto>`.
fn subscription_lease_from(headers: &HeaderMap) -> Option<&str> {
    if let Some(v) = headers.get("x-subscription-lease") {
        return v.to_str().ok();
    }
    let auth = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    auth.strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .map(str::trim)
}

/// Valida a credencial de assinatura. Resposta só com mensagens fixas: nenhum
/// texto vindo do cliente vira HTML (evita XSS via payload adulterado).
fn check_subscription(raw: &str, now: u64) -> Result<(), &'static str> {
    let lease: GhostLease = serde_json::from_str(raw.trim()).map_err(|_| "credencial inválida")?;
    if !lease.capabilities.contains(&LeaseCapability::Subscriber) {
        return Err("lease sem a capacidade de assinante");
    }
    lease.verify(now).map_err(|e| match e {
        LeaseError::Expired { .. } => "assinatura expirada",
        _ => "credencial inválida",
    })
}

/// Plano de assinatura publicado (preço, período, endereço de recebimento).
async fn subscription_api(State(state): State<VitrineState>) -> Response {
    let plan_file = state.home.join("premium").join("plan.json");
    match std::fs::read(&plan_file) {
        Ok(bytes) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
            bytes,
        )
            .into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
            json!({"error": "plano não publicado — `mycelium sub plan`"}).to_string(),
        )
            .into_response(),
    }
}

/// Resposta 401 com a landing do assinante (form para colar a lease recebida).
fn denied(reason: &'static str) -> Response {
    let html = include_str!("../../../deploy/store-ui/premium.html").replace("__REASON__", reason);
    (
        StatusCode::UNAUTHORIZED,
        [
            (axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (axum::http::header::WWW_AUTHENTICATE, "Bearer realm=\"premium\""),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        html,
    )
        .into_response()
}

/// Conteúdo premium: exige lease válida; caso contrário responde 401.
async fn premium(State(state): State<VitrineState>, headers: HeaderMap) -> Response {
    let raw = match subscription_lease_from(&headers) {
        Some(r) => r,
        None => return denied("credencial de assinatura ausente"),
    };
    if let Err(reason) = check_subscription(raw, unix_now()) {
        return denied(reason);
    }

    let content = state.home.join("premium").join("content.html");
    match std::fs::read(&content) {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (axum::http::header::CACHE_CONTROL, "no-store"),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
            json!({"error": "conteúdo premium não publicado — premium/content.html"}).to_string(),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycelium_core::NodeId;
    use mycelium_pheromones::Gland;

    fn subscriber_lease(valid_until: u64, caps: Vec<LeaseCapability>) -> String {
        let gland = Gland::germinate();
        let lease = GhostLease::create(
            &gland,
            1,
            valid_until,
            42,
            vec![NodeId::derive(b"subscriber-1")],
            caps,
            vec![],
            vec![],
        );
        serde_json::to_string(&lease).expect("lease serializa")
    }

    #[test]
    fn lease_de_assinante_valida_libera_acesso() {
        let raw = subscriber_lease(2000, vec![LeaseCapability::Subscriber]);
        assert_eq!(check_subscription(&raw, 1000), Ok(()));
    }

    #[test]
    fn lease_expirada_e_recusada() {
        let raw = subscriber_lease(2000, vec![LeaseCapability::Subscriber]);
        assert_eq!(check_subscription(&raw, 2001), Err("assinatura expirada"));
    }

    #[test]
    fn lease_de_dormencia_nao_concede_acesso_premium() {
        let raw = subscriber_lease(
            2000,
            vec![
                LeaseCapability::AdvertiseContent,
                LeaseCapability::ReceiveMail,
                LeaseCapability::RelayWake,
            ],
        );
        assert_eq!(
            check_subscription(&raw, 1000),
            Err("lease sem a capacidade de assinante")
        );
    }

    #[test]
    fn lease_adulterada_e_recusada() {
        let raw = subscriber_lease(2000, vec![LeaseCapability::Subscriber]);
        let mut value: serde_json::Value = serde_json::from_str(&raw).expect("json válido");
        // Adianta a validade sem poder re-quebrar a assinatura ed25519 do emissor.
        value["valid_until"] = serde_json::Value::from(9_999_999_999u64);
        let tampered = serde_json::to_string(&value).expect("json re-serializa");
        assert_eq!(check_subscription(&tampered, 1000), Err("credencial inválida"));
    }

    #[test]
    fn payload_nao_e_lease_e_recusado() {
        assert_eq!(check_subscription("não é uma lease", 1000), Err("credencial inválida"));
        assert_eq!(check_subscription("", 1000), Err("credencial inválida"));
    }

    #[test]
    fn header_de_assinatura_e_lido_nos_dois_formatos() {
        let mut headers = HeaderMap::new();
        assert_eq!(subscription_lease_from(&headers), None);

        headers.insert("x-subscription-lease", "lease-a".parse().unwrap());
        assert_eq!(subscription_lease_from(&headers), Some("lease-a"));

        let mut auth = HeaderMap::new();
        auth.insert(axum::http::header::AUTHORIZATION, "Bearer lease-b".parse().unwrap());
        assert_eq!(subscription_lease_from(&auth), Some("lease-b"));
    }
}
