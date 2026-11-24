//! # Rhizome Ion — Super-App Social Soberano no Event Horizon (`/rhizome/`)
//!
//! Expõe toda a experiência do Mycelium Rhizome (YouTube/Reels, Instagram/Stories,
//! Facebook/Comunidades, X/Microblog, WhatsApp E2EE Pós-Quântico, Importadores & Bridges)
//! ligada em tempo real ao `Organism` (gossipsub, Kademlia DHT, Isotope e DTN Store-and-Forward).

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use giggs::Plot;
use isotope::Atom;
use mycelium_nostr::NostrEvent;
use mycelium_rhizome::{
    prepare_video_ingest_from_file, BudgetItem, ChatMessageKind, ChatReceipt, CommunityVisibility,
    ExternalBridgeAdapter, FeedFilter, GroupManifest, MediaAttachment, MediaChunkPacket,
    MilestoneItem, ModerationFilters, PostKind, ReactionKind, RhizomeStore, SealedChatEnvelope,
    SplitContractParty, SyncEnvelope, VideoUploadMeta, WhatsAppCloudAdapter, XApiV2Adapter,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;

pub fn local_device_type() -> &'static str {
    if cfg!(target_os = "android")
        || matches!(
            std::env::var("MYCELIUM_ANDROID").ok().as_deref(),
            Some("1" | "true" | "yes")
        )
    {
        "mobile"
    } else {
        "desktop"
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwarmPeerInfo {
    pub node_id: String,
    pub peer_id: String,
    pub connected: bool,
    pub strength: u32,
    pub messages: u64,
    pub atrophy_count: u32,
    pub last_seen_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayLogEntry {
    pub ts: u64,
    pub asset_cid: String,
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwarmSnapshot {
    pub node_id: String,
    pub peer_id: String,
    pub ghost_pubkey_hex: String,
    pub pkarr_addr: String,
    pub listen_addrs: Vec<String>,
    pub neighbors: usize,
    pub membrane: String,
    pub physarum_phase: String,
    pub is_relay: bool,
    pub active_relay: Option<String>,
    pub relay_health: String,
    pub device_type: String,
    pub volunteer_donor: bool,
    pub chunks_relayed: u64,
    pub bytes_relayed: u64,
    pub queue_depth: usize,
    pub links: Vec<SwarmPeerInfo>,
    pub relay_log: Vec<RelayLogEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletTransferView {
    pub tx_id: String,
    pub kind: String,
    pub from_hex: String,
    pub to_hex: String,
    pub nutrient: String,
    pub amount: u64,
    pub memo: String,
    pub asset: Option<String>,
    pub ts: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletReport {
    pub pubkey_hex: String,
    pub node_id: String,
    pub balances: BTreeMap<String, u64>,
    pub history: Vec<Value>,
    pub transfers: Vec<WalletTransferView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferOutcome {
    pub tx_id: String,
    pub kind: String,
    pub nutrient: String,
    pub amount: u64,
    pub to_hex: String,
}

/// Mensagens assíncronas que o `rhizome_ion` envia ao laço vivo do `Organism`
/// para propagação imediata na malha libp2p/DHT/Isotope/DTN ou consulta viva
/// de carteira/enxame.
#[derive(Debug)]
pub enum RhizomeOutbound {
    BroadcastEvent {
        event: SyncEnvelope,
        plots: Vec<Plot>,
    },
    PublishPlots {
        plots: Vec<Plot>,
    },
    QueueMediaPackets {
        packets: Vec<MediaChunkPacket>,
    },
    WantMedia {
        asset_cid: String,
        is_video: bool,
        missing_indices: Vec<u32>,
    },
    SyncStory {
        isotope_key: String,
        atom: Atom,
        event: SyncEnvelope,
    },
    SendDirectChat {
        to_node_id: String,
        envelope: SealedChatEnvelope,
    },
    SendDirectReceipt {
        to_node_id: String,
        receipt: ChatReceipt,
    },
    SendGroupManifest {
        to_node_id: String,
        manifest: GroupManifest,
    },
    SyncSnapshotNow,
    GetSwarmSnapshot {
        reply: oneshot::Sender<SwarmSnapshot>,
    },
    GetWalletReport {
        reply: oneshot::Sender<WalletReport>,
    },
    ExecuteTransfer {
        to_hex: String,
        amount: u64,
        nutrient: String,
        kind: String,
        memo: String,
        asset: Option<String>,
        reply: oneshot::Sender<Result<TransferOutcome, String>>,
    },
    SetSwarmConfig {
        volunteer_donor: Option<bool>,
        device_type: Option<String>,
        reply: oneshot::Sender<SwarmSnapshot>,
    },
    GetVeilStatus {
        reply: oneshot::Sender<crate::ecosystem_ion::VeilStatusDto>,
    },
    StartVeil {
        mode: String,
        role: String,
        socks5_port: u16,
        guards: Vec<String>,
        middles: Vec<String>,
        exits: Vec<String>,
        trust: Vec<String>,
        listen: Option<String>,
        advertise: Option<String>,
        reply: oneshot::Sender<Result<crate::ecosystem_ion::VeilStatusDto, String>>,
    },
    StopVeil {
        reply: oneshot::Sender<crate::ecosystem_ion::VeilStatusDto>,
    },
    SetVeilKillSwitch {
        engaged: bool,
        reply: oneshot::Sender<Result<crate::ecosystem_ion::VeilStatusDto, String>>,
    },
    AexBridgeOp {
        op: crate::ecosystem_ion::AexBridgeOpReq,
        reply: oneshot::Sender<Value>,
    },
    GetMintReserveStatus {
        cpx_circulating_base: u128,
        reply: oneshot::Sender<Value>,
    },
    MintReserveSettle {
        units: u64,
        memo: String,
        reply: oneshot::Sender<Result<crate::ecosystem_ion::MintReserveSettleOutcome, String>>,
    },
    GetReservePolicy {
        reply: oneshot::Sender<Value>,
    },
    ConfigureReservePolicy {
        chain_id: Option<String>,
        min_quorum: usize,
        min_hashcash_bits: Option<u8>,
        extra_sporocarps: Vec<(String, String)>,
        include_self: bool,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    SubmitMintClaimP2p {
        units: u64,
        memo: String,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    DrainSettledMintReceipts {
        reply: oneshot::Sender<(Vec<mycelium_mint::MintReceipt>, mycelium_mint::MonetaryPolicy)>,
    },
}

#[derive(Clone)]
pub struct RhizomeIonState {
    pub store: Arc<Mutex<RhizomeStore>>,
    pub outbound: UnboundedSender<RhizomeOutbound>,
    pub ecosystem: crate::ecosystem_ion::EcosystemState,
}

pub fn create_rhizome_router(
    store: Arc<Mutex<RhizomeStore>>,
    outbound: UnboundedSender<RhizomeOutbound>,
) -> Router {
    let ecosystem = crate::ecosystem_ion::EcosystemState::open(store.clone(), outbound.clone());
    let state = RhizomeIonState {
        store,
        outbound,
        ecosystem: ecosystem.clone(),
    };
    Router::new()
        .route("/", get(rhizome_ui))
        .route("/manifest.webmanifest", get(manifest_webmanifest))
        .route("/feed.xml", get(rss_feed))
        .route("/ap/actor", get(ap_actor))
        .route("/ap/outbox", get(ap_outbox))
        .route("/api/overview", get(overview_api))
        .route("/api/profiles", get(profiles_api))
        .route("/api/profile", post(update_profile_api))
        .route("/api/feed", get(feed_api))
        .route("/api/posts", post(create_post_api))
        .route("/api/posts/{id}/react", post(react_post_api))
        .route("/api/posts/{id}/comments", post(comment_post_api))
        .route("/api/follow", post(follow_api))
        .route("/api/stories", get(list_stories_api).post(create_story_api))
        .route("/api/communities", get(list_communities_api).post(create_community_api))
        .route("/api/playlists", get(list_playlists_api).post(create_playlist_api))
        .route("/api/media/upload", post(upload_media_api))
        .route("/api/media/upload/{upload_id}/finish", post(media_upload_finish_api))
        .route("/api/media/{cid}", get(serve_media_api))
        .route("/api/videos/upload/start", post(video_upload_start_api))
        .route("/api/videos/upload/{upload_id}/chunk", post(video_upload_chunk_api))
        .route("/api/videos/upload/{upload_id}/finish", post(video_upload_finish_api))
        .route("/api/videos/{cid}/stream", get(stream_video_api))
        .route("/api/videos/{cid}/pin", post(pin_video_api))
        .route("/api/videos/{cid}/details", get(video_details_api))
        .route("/api/videos/{cid}/view", post(record_video_view_api))
        .route("/api/videos/{cid}/tip", post(tip_video_api))
        .route("/api/videos/{cid}/thumbnail", get(video_thumbnail_api))
        .route("/api/commons", get(list_commons_api).post(create_commons_api))
        .route("/api/commons/{id}", get(get_commons_api))
        .route("/api/commons/{id}/contribute", post(contribute_commons_api))
        .route("/api/lenses", get(list_lenses_api).post(create_lens_api))
        .route("/api/wallet", get(wallet_api))
        .route("/api/wallet/transfer", post(wallet_transfer_api))
        .route("/api/swarm", get(swarm_api))
        .route("/api/swarm/config", post(swarm_config_api))
        .route("/api/moderation", get(get_moderation_api).post(set_moderation_api))
        .route("/api/chat/conversations", get(list_conversations_api))
        .route("/api/chat/conversations/{id}/messages", get(conversation_messages_api))
        .route("/api/chat/conversations/{id}/read", post(mark_read_api))
        .route("/api/chat/send", post(send_chat_api))
        .route("/api/chat/groups", post(create_group_api))
        .route("/api/chat/groups/{id}/send", post(send_group_chat_api))
        .route("/api/import/x", post(import_x_api))
        .route("/api/import/whatsapp", post(import_whatsapp_api))
        .route("/api/bridges/nostr/post/{id}", get(export_nostr_post_api))
        .route("/api/bridges/nostr/import", post(import_nostr_api))
        .route("/api/bridges/preview", post(bridge_preview_api))
        .route("/api/bridges/whatsapp/webhook", post(whatsapp_webhook_api))
        .route("/api/sync", post(sync_now_api))
        .with_state(state)
        .merge(crate::ecosystem_ion::ecosystem_router(ecosystem))
}

fn json_ok(val: Value) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        val.to_string(),
    )
        .into_response()
}

fn json_err(status: StatusCode, msg: impl Into<String>) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        json!({ "error": msg.into() }).to_string(),
    )
        .into_response()
}

async fn rhizome_ui() -> impl IntoResponse {
    let html = include_str!("../../../deploy/store-ui/rhizome.html");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html.to_string(),
    )
}

async fn rss_feed(State(state): State<RhizomeIonState>) -> impl IntoResponse {
    let xml = state
        .store
        .lock()
        .unwrap()
        .export_rss("http://127.0.0.1:7474/rhizome");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/rss+xml; charset=utf-8")],
        xml,
    )
}

async fn ap_actor(State(state): State<RhizomeIonState>) -> impl IntoResponse {
    let doc = state
        .store
        .lock()
        .unwrap()
        .export_activitypub_actor("http://127.0.0.1:7474/rhizome");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/activity+json; charset=utf-8")],
        doc.to_string(),
    )
}

async fn ap_outbox(State(state): State<RhizomeIonState>) -> impl IntoResponse {
    let doc = state
        .store
        .lock()
        .unwrap()
        .export_activitypub_outbox("http://127.0.0.1:7474/rhizome");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/activity+json; charset=utf-8")],
        doc.to_string(),
    )
}

async fn overview_api(State(state): State<RhizomeIonState>) -> Response {
    let ov = state.store.lock().unwrap().overview();
    json_ok(serde_json::to_value(ov).unwrap_or_else(|_| json!({})))
}

async fn profiles_api(State(state): State<RhizomeIonState>) -> Response {
    let profiles = state.store.lock().unwrap().list_profiles();
    json_ok(json!({ "profiles": profiles }))
}

#[derive(Deserialize)]
struct UpdateProfileReq {
    handle: Option<String>,
    display_name: Option<String>,
    bio: Option<String>,
    avatar_cid: Option<String>,
    banner_cid: Option<String>,
    links: Option<Vec<String>>,
}

async fn update_profile_api(
    State(state): State<RhizomeIonState>,
    Json(req): Json<UpdateProfileReq>,
) -> Response {
    let res = state.store.lock().unwrap().update_profile(
        req.handle,
        req.display_name,
        req.bio,
        req.avatar_cid,
        req.banner_cid,
        req.links,
    );
    match res {
        Ok((profile, env, plot)) => {
            let _ = state.outbound.send(RhizomeOutbound::BroadcastEvent {
                event: env,
                plots: plot.into_iter().collect(),
            });
            json_ok(json!({ "profile": profile }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn feed_api(
    State(state): State<RhizomeIonState>,
    Query(filter): Query<FeedFilter>,
) -> Response {
    let items = state.store.lock().unwrap().query_feed(&filter);
    json_ok(json!({ "items": items }))
}

#[derive(Deserialize)]
struct CreatePostReq {
    kind: PostKind,
    title: Option<String>,
    body: String,
    #[serde(default)]
    media: Vec<MediaAttachment>,
    community_id: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    reply_to: Option<String>,
    repost_of: Option<String>,
    quote_of: Option<String>,
    location: Option<String>,
}

async fn create_post_api(
    State(state): State<RhizomeIonState>,
    Json(req): Json<CreatePostReq>,
) -> Response {
    let res = state.store.lock().unwrap().create_post(
        req.kind,
        req.title,
        req.body,
        req.media,
        req.community_id,
        req.tags,
        req.reply_to,
        req.repost_of,
        req.quote_of,
        req.location,
    );
    match res {
        Ok((post, env, plot)) => {
            let _ = state.outbound.send(RhizomeOutbound::BroadcastEvent {
                event: env,
                plots: plot.into_iter().collect(),
            });
            json_ok(json!({ "post": post }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[derive(Deserialize)]
struct ReactReq {
    kind: ReactionKind,
}

async fn react_post_api(
    State(state): State<RhizomeIonState>,
    Path(id): Path<String>,
    Json(req): Json<ReactReq>,
) -> Response {
    let res = state.store.lock().unwrap().toggle_reaction(id, req.kind);
    match res {
        Ok((reaction, env, plot)) => {
            let _ = state.outbound.send(RhizomeOutbound::BroadcastEvent {
                event: env,
                plots: plot.into_iter().collect(),
            });
            json_ok(json!({ "reaction": reaction }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[derive(Deserialize)]
struct CommentReq {
    body: String,
    parent_comment_id: Option<String>,
}

async fn comment_post_api(
    State(state): State<RhizomeIonState>,
    Path(id): Path<String>,
    Json(req): Json<CommentReq>,
) -> Response {
    let res = state
        .store
        .lock()
        .unwrap()
        .add_comment(id, req.parent_comment_id, req.body);
    match res {
        Ok((comment, env, plot)) => {
            let _ = state.outbound.send(RhizomeOutbound::BroadcastEvent {
                event: env,
                plots: plot.into_iter().collect(),
            });
            json_ok(json!({ "comment": comment }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[derive(Deserialize)]
struct FollowReq {
    target_id: String,
    #[serde(default = "default_user_kind")]
    target_kind: String,
}

fn default_user_kind() -> String {
    "user".into()
}

async fn follow_api(
    State(state): State<RhizomeIonState>,
    Json(req): Json<FollowReq>,
) -> Response {
    let res = state
        .store
        .lock()
        .unwrap()
        .toggle_follow(req.target_id, req.target_kind);
    match res {
        Ok((edge, env, plot)) => {
            let _ = state.outbound.send(RhizomeOutbound::BroadcastEvent {
                event: env,
                plots: plot.into_iter().collect(),
            });
            json_ok(json!({ "follow": edge }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn list_stories_api(State(state): State<RhizomeIonState>) -> Response {
    let stories = state.store.lock().unwrap().list_active_stories();
    json_ok(json!({ "stories": stories }))
}

#[derive(Deserialize)]
struct CreateStoryReq {
    caption: String,
    background: Option<String>,
    media: Option<MediaAttachment>,
    ttl_secs: Option<u64>,
}

async fn create_story_api(
    State(state): State<RhizomeIonState>,
    Json(req): Json<CreateStoryReq>,
) -> Response {
    let res = state.store.lock().unwrap().create_story(
        req.caption,
        req.background,
        req.media,
        req.ttl_secs,
    );
    match res {
        Ok((story, isotope_key, atom, env)) => {
            let _ = state.outbound.send(RhizomeOutbound::SyncStory {
                isotope_key,
                atom,
                event: env,
            });
            json_ok(json!({ "story": story }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn list_communities_api(State(state): State<RhizomeIonState>) -> Response {
    let raw = state.store.lock().unwrap().list_communities();
    let list: Vec<Value> = raw
        .into_iter()
        .map(|(community, members_count, joined)| {
            json!({
                "community": community,
                "members_count": members_count,
                "joined": joined
            })
        })
        .collect();
    json_ok(json!({ "communities": list }))
}

#[derive(Deserialize)]
struct CreateCommunityReq {
    slug: String,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    rules: Vec<String>,
    #[serde(default = "default_public_vis")]
    visibility: CommunityVisibility,
}

fn default_public_vis() -> CommunityVisibility {
    CommunityVisibility::Public
}

async fn create_community_api(
    State(state): State<RhizomeIonState>,
    Json(req): Json<CreateCommunityReq>,
) -> Response {
    let res = state.store.lock().unwrap().create_community(
        req.slug,
        req.name,
        req.description,
        req.rules,
        req.visibility,
    );
    match res {
        Ok((community, env, plot)) => {
            let _ = state.outbound.send(RhizomeOutbound::BroadcastEvent {
                event: env,
                plots: plot.into_iter().collect(),
            });
            json_ok(json!({ "community": community }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn list_playlists_api(State(state): State<RhizomeIonState>) -> Response {
    let playlists = state.store.lock().unwrap().list_playlists();
    json_ok(json!({ "playlists": playlists }))
}

#[derive(Deserialize)]
struct CreatePlaylistReq {
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    video_cids: Vec<String>,
}

async fn create_playlist_api(
    State(state): State<RhizomeIonState>,
    Json(req): Json<CreatePlaylistReq>,
) -> Response {
    let res = state
        .store
        .lock()
        .unwrap()
        .create_playlist(req.title, req.description, req.video_cids);
    match res {
        Ok((playlist, env)) => {
            let _ = state.outbound.send(RhizomeOutbound::BroadcastEvent {
                event: env,
                plots: vec![],
            });
            json_ok(json!({ "playlist": playlist }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[derive(Deserialize)]
struct MediaUploadReq {
    filename: String,
    mime_type: String,
    data_b64: String,
    #[serde(default)]
    alt_text: String,
    duration_secs: Option<u32>,
}

async fn upload_media_api(
    State(state): State<RhizomeIonState>,
    Json(req): Json<MediaUploadReq>,
) -> Response {
    let bytes = match BASE64.decode(&req.data_b64) {
        Ok(b) => b,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, format!("base64 inválido: {e}")),
    };
    let res = state.store.lock().unwrap().store_media_blob(
        &req.filename,
        &req.mime_type,
        &bytes,
        &req.alt_text,
        req.duration_secs,
    );
    match res {
        Ok((attachment, packets)) => {
            if !packets.is_empty() {
                let _ = state
                    .outbound
                    .send(RhizomeOutbound::QueueMediaPackets { packets });
            }
            json_ok(json!({ "attachment": attachment }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn media_upload_finish_api(
    State(state): State<RhizomeIonState>,
    Path(upload_id): Path<String>,
) -> Response {
    let (path, info) = {
        let mut guard = state.store.lock().unwrap();
        match guard.take_upload_session(&upload_id) {
            Ok((p, i, _, _)) => (p, i),
            Err(e) => return json_err(StatusCode::BAD_REQUEST, e.to_string()),
        }
    };
    let read_res = tokio::task::spawn_blocking(move || {
        let bytes = std::fs::read(&path)?;
        let _ = std::fs::remove_file(&path);
        Ok::<Vec<u8>, std::io::Error>(bytes)
    })
    .await;
    let bytes = match read_res {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return json_err(StatusCode::BAD_REQUEST, e.to_string()),
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let res = state.store.lock().unwrap().store_media_blob(
        &info.filename,
        &info.mime_type,
        &bytes,
        &info.filename,
        None,
    );
    match res {
        Ok((attachment, packets)) => {
            if !packets.is_empty() {
                let _ = state
                    .outbound
                    .send(RhizomeOutbound::QueueMediaPackets { packets });
            }
            json_ok(json!({ "attachment": attachment }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn serve_media_api(
    State(state): State<RhizomeIonState>,
    Path(cid): Path<String>,
) -> Response {
    let loaded = state.store.lock().unwrap().load_media_blob(&cid);
    match loaded {
        Some((bytes, mime)) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, mime),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable".into()),
            ],
            bytes,
        )
            .into_response(),
        None => {
            let _ = state.outbound.send(RhizomeOutbound::WantMedia {
                asset_cid: cid,
                is_video: false,
                missing_indices: vec![],
            });
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::RETRY_AFTER, "1")],
                "buscando mídia na malha P2P",
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct StartUploadReq {
    filename: String,
    #[serde(default)]
    mime_type: String,
}

async fn video_upload_start_api(
    State(state): State<RhizomeIonState>,
    Json(req): Json<StartUploadReq>,
) -> Response {
    match state
        .store
        .lock()
        .unwrap()
        .start_upload_session(&req.filename, &req.mime_type)
    {
        Ok(info) => json_ok(serde_json::to_value(info).unwrap_or_else(|_| json!({}))),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[derive(Deserialize)]
struct UploadChunkReq {
    data_b64: String,
}

async fn video_upload_chunk_api(
    State(state): State<RhizomeIonState>,
    Path(upload_id): Path<String>,
    Json(req): Json<UploadChunkReq>,
) -> Response {
    let bytes = match BASE64.decode(&req.data_b64) {
        Ok(b) => b,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, format!("base64 inválido: {e}")),
    };
    match state
        .store
        .lock()
        .unwrap()
        .append_upload_chunk(&upload_id, &bytes)
    {
        Ok(info) => json_ok(serde_json::to_value(info).unwrap_or_else(|_| json!({}))),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn video_upload_finish_api(
    State(state): State<RhizomeIonState>,
    Path(upload_id): Path<String>,
    Json(mut meta): Json<VideoUploadMeta>,
) -> Response {
    // 1. Retira metadados do upload sob lock mínimo (< 0.1ms)
    let (path, info, author_pk, channel_id, chunks_dir) = {
        let mut guard = state.store.lock().unwrap();
        let chunks_dir = guard.chunks_dir();
        match guard.take_upload_session(&upload_id) {
            Ok((p, i, pk, ch)) => (p, i, pk, ch, chunks_dir),
            Err(e) => return json_err(StatusCode::BAD_REQUEST, e.to_string()),
        }
    };

    if meta.mime_type.is_empty() {
        meta.mime_type = info.mime_type;
    }

    // 2. Fatiamento streaming BLAKE3 (chunks 32 KiB, O(1) RAM) fora do Mutex
    let path_for_ingest = path.clone();
    let prepared_res = tokio::task::spawn_blocking(move || {
        let res =
            prepare_video_ingest_from_file(&path_for_ingest, &chunks_dir, &author_pk, &channel_id, meta);
        let _ = std::fs::remove_file(&path_for_ingest);
        res
    })
    .await;

    let prepared = match prepared_res {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => return json_err(StatusCode::BAD_REQUEST, e.to_string()),
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, format!("worker vídeo: {e}")),
    };

    // 3. Assina e registra o manifesto/post sob lock rápido (< 3ms) e gera recibos criptográficos locais
    let (commit_res, receipts_envs) = {
        let mut guard = state.store.lock().unwrap();
        let res = guard.commit_prepared_video(prepared);
        let rcpt_envs = if let Ok((ref post, ref manifest, _, _, _)) = res {
            let mcid = post
                .video_manifest_cid
                .clone()
                .unwrap_or_else(|| manifest.video_id.to_string());
            match guard.issue_local_shard_receipts(&mcid, local_device_type()) {
                Ok((_, envs)) => envs,
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };
        (res, rcpt_envs)
    };
    match commit_res {
        Ok((post, manifest, envs, plots, packets)) => {
            if !plots.is_empty() {
                let _ = state.outbound.send(RhizomeOutbound::PublishPlots { plots });
            }
            for ev in envs {
                let _ = state.outbound.send(RhizomeOutbound::BroadcastEvent {
                    event: ev,
                    plots: vec![],
                });
            }
            let receipts_count = receipts_envs.len();
            for ev in receipts_envs.into_iter().take(32) {
                let _ = state.outbound.send(RhizomeOutbound::BroadcastEvent {
                    event: ev,
                    plots: vec![],
                });
            }
            if !packets.is_empty() {
                let _ = state
                    .outbound
                    .send(RhizomeOutbound::QueueMediaPackets { packets });
            }
            json_ok(json!({ "post": post, "manifest": manifest, "receipts_issued": receipts_count }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

/// Streaming HTTP Range (206 Partial Content / 200 OK) direto dos chunks BLAKE3 do `mycelium-media`!
async fn stream_video_api(
    State(state): State<RhizomeIonState>,
    Path(cid): Path<String>,
    headers: HeaderMap,
) -> Response {
    let range_hdr = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let (start, end_opt, is_range) = if let Some(ref rh) = range_hdr {
        if let Some(spec) = rh.strip_prefix("bytes=") {
            let mut parts = spec.split('-');
            let s = parts.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
            let e = parts.next().and_then(|v| {
                if v.trim().is_empty() {
                    None
                } else {
                    v.trim().parse::<u64>().ok()
                }
            });
            // Limita resposta por fatia de range a 1.5 MiB para streaming suave pelo proxy Singularity
            let capped_end = Some(e.unwrap_or(s + 1536 * 1024 - 1));
            (s, capped_end, true)
        } else {
            (0, None, false)
        }
    } else {
        (0, None, false)
    };

    let (res, missing_indices) = {
        let guard = state.store.lock().unwrap();
        let res = guard.read_video_range(&cid, start, end_opt);
        let missing = if res.is_err() {
            guard.missing_video_chunk_indices(&cid)
        } else {
            vec![]
        };
        (res, missing)
    };
    match res {
        Ok((bytes, s, e, total, mime)) => {
            let status = if is_range {
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            };
            let mut resp = (status, bytes).into_response();
            let h = resp.headers_mut();
            if let Ok(v) = mime.parse() {
                h.insert(header::CONTENT_TYPE, v);
            }
            h.insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
            if is_range {
                if let Ok(v) = format!("bytes {s}-{e}/{total}").parse() {
                    h.insert(header::CONTENT_RANGE, v);
                }
            }
            resp
        }
        Err(e) => {
            if !missing_indices.is_empty() {
                let _ = state.outbound.send(RhizomeOutbound::WantMedia {
                    asset_cid: cid,
                    is_video: true,
                    missing_indices,
                });
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::RETRY_AFTER, "1")],
                    e.to_string(),
                )
                    .into_response();
            }
            json_err(StatusCode::NOT_FOUND, e.to_string())
        }
    }
}

async fn pin_video_api(
    State(state): State<RhizomeIonState>,
    Path(cid): Path<String>,
) -> Response {
    let res = {
        let mut guard = state.store.lock().unwrap();
        match guard.pin_video(&cid) {
            Ok(newly_pinned) => {
                let envs = match guard.issue_local_shard_receipts(&cid, local_device_type()) {
                    Ok((_, envs)) => envs,
                    Err(_) => Vec::new(),
                };
                Ok((newly_pinned, envs))
            }
            Err(e) => Err(e),
        }
    };
    match res {
        Ok((newly_pinned, envs)) => {
            let receipts_count = envs.len();
            for ev in envs.into_iter().take(32) {
                let _ = state.outbound.send(RhizomeOutbound::BroadcastEvent {
                    event: ev,
                    plots: vec![],
                });
            }
            json_ok(json!({
                "pinned": true,
                "newly_pinned": newly_pinned,
                "receipts_issued": receipts_count
            }))
        }
        Err(e) => json_err(StatusCode::NOT_FOUND, e.to_string()),
    }
}

async fn list_conversations_api(State(state): State<RhizomeIonState>) -> Response {
    let conversations = state.store.lock().unwrap().list_conversations();
    json_ok(json!({ "conversations": conversations }))
}

async fn conversation_messages_api(
    State(state): State<RhizomeIonState>,
    Path(id): Path<String>,
) -> Response {
    let messages = state.store.lock().unwrap().get_conversation_messages(&id);
    json_ok(json!({ "messages": messages }))
}

async fn mark_read_api(
    State(state): State<RhizomeIonState>,
    Path(id): Path<String>,
) -> Response {
    let res = state.store.lock().unwrap().mark_conversation_read(&id);
    match res {
        Ok(receipts) => {
            let count = receipts.len();
            for r in receipts {
                let to_node_id = r.original_sender_node_id.clone();
                let _ = state.outbound.send(RhizomeOutbound::SendDirectReceipt {
                    to_node_id,
                    receipt: r,
                });
            }
            json_ok(json!({ "receipts_sent": count }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[derive(Deserialize)]
struct SendChatReq {
    to: String,
    body: String,
    #[serde(default = "default_text_kind")]
    kind: ChatMessageKind,
    media: Option<MediaAttachment>,
    reply_to: Option<String>,
    mlkem_pubkey_hex: Option<String>,
    #[serde(default)]
    nostr_fallback: bool,
}

fn default_text_kind() -> ChatMessageKind {
    ChatMessageKind::Text
}

async fn send_chat_api(
    State(state): State<RhizomeIonState>,
    Json(req): Json<SendChatReq>,
) -> Response {
    let res = state.store.lock().unwrap().send_direct_chat(
        &req.to,
        req.mlkem_pubkey_hex.as_deref(),
        req.kind,
        req.body,
        req.media,
        req.reply_to,
        req.nostr_fallback,
    );
    match res {
        Ok((sealed, message, nostr_ev)) => {
            let to_node_id = sealed.recipient_node_id.clone();
            let _ = state.outbound.send(RhizomeOutbound::SendDirectChat {
                to_node_id,
                envelope: sealed,
            });
            json_ok(json!({
                "message": message,
                "nostr_nip44_event": nostr_ev
            }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[derive(Deserialize)]
struct CreateGroupReq {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    members: Vec<String>,
}

async fn create_group_api(
    State(state): State<RhizomeIonState>,
    Json(req): Json<CreateGroupReq>,
) -> Response {
    let res = state
        .store
        .lock()
        .unwrap()
        .create_chat_group(req.name, req.description, req.members);
    match res {
        Ok(manifest) => {
            let my_nid = state.store.lock().unwrap().keys().node_id_hex();
            for member in &manifest.members {
                if member != &my_nid {
                    let _ = state.outbound.send(RhizomeOutbound::SendGroupManifest {
                        to_node_id: member.clone(),
                        manifest: manifest.clone(),
                    });
                }
            }
            json_ok(json!({ "group": manifest }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[derive(Deserialize)]
struct SendGroupReq {
    body: String,
    #[serde(default = "default_text_kind")]
    kind: ChatMessageKind,
    media: Option<MediaAttachment>,
    reply_to: Option<String>,
}

async fn send_group_chat_api(
    State(state): State<RhizomeIonState>,
    Path(group_id): Path<String>,
    Json(req): Json<SendGroupReq>,
) -> Response {
    let res = state
        .store
        .lock()
        .unwrap()
        .send_group_chat(&group_id, req.kind, req.body, req.media, req.reply_to);
    match res {
        Ok((sealed, targets, message)) => {
            for target in targets {
                let _ = state.outbound.send(RhizomeOutbound::SendDirectChat {
                    to_node_id: target,
                    envelope: sealed.clone(),
                });
            }
            json_ok(json!({ "message": message }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[derive(Deserialize)]
struct ImportXReq {
    raw: String,
}

async fn import_x_api(
    State(state): State<RhizomeIonState>,
    Json(req): Json<ImportXReq>,
) -> Response {
    let res = state.store.lock().unwrap().import_x_archive(&req.raw);
    match res {
        Ok((posts, envs, plots)) => {
            if !plots.is_empty() {
                let _ = state.outbound.send(RhizomeOutbound::PublishPlots { plots });
            }
            for ev in envs {
                let _ = state.outbound.send(RhizomeOutbound::BroadcastEvent {
                    event: ev,
                    plots: vec![],
                });
            }
            json_ok(json!({ "imported_count": posts.len(), "posts": posts }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[derive(Deserialize)]
struct ImportWaReq {
    #[serde(default)]
    title: String,
    raw: String,
}

async fn import_whatsapp_api(
    State(state): State<RhizomeIonState>,
    Json(req): Json<ImportWaReq>,
) -> Response {
    match state
        .store
        .lock()
        .unwrap()
        .import_whatsapp_chat(&req.title, &req.raw)
    {
        Ok((conversation_id, imported_count)) => {
            json_ok(json!({ "conversation_id": conversation_id, "imported_count": imported_count }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn export_nostr_post_api(
    State(state): State<RhizomeIonState>,
    Path(id): Path<String>,
) -> Response {
    match state.store.lock().unwrap().export_post_as_nostr(&id) {
        Ok(ev) => json_ok(serde_json::to_value(ev).unwrap_or_else(|_| json!({}))),
        Err(e) => json_err(StatusCode::NOT_FOUND, e.to_string()),
    }
}

async fn import_nostr_api(
    State(state): State<RhizomeIonState>,
    Json(event): Json<NostrEvent>,
) -> Response {
    match state.store.lock().unwrap().import_nostr_event(&event) {
        Ok((post, env, plot)) => {
            let _ = state.outbound.send(RhizomeOutbound::BroadcastEvent {
                event: env,
                plots: plot.into_iter().collect(),
            });
            json_ok(json!({ "post": post }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[derive(Deserialize)]
struct BridgePreviewReq {
    adapter: String,
    target: String,
    text: String,
}

async fn bridge_preview_api(Json(req): Json<BridgePreviewReq>) -> Response {
    let preview = match req.adapter.as_str() {
        "whatsapp_cloud_api" => WhatsAppCloudAdapter::from_env().build_outbound_preview(&req.target, &req.text),
        _ => XApiV2Adapter::from_env().build_outbound_preview(&req.target, &req.text),
    };
    json_ok(serde_json::to_value(preview).unwrap_or_else(|_| json!({})))
}

async fn whatsapp_webhook_api(
    State(state): State<RhizomeIonState>,
    Json(payload): Json<Value>,
) -> Response {
    match state
        .store
        .lock()
        .unwrap()
        .ingest_whatsapp_cloud_webhook(&payload)
    {
        Ok(ingested) => json_ok(json!({ "status": "ok", "ingested_messages": ingested })),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn sync_now_api(State(state): State<RhizomeIonState>) -> Response {
    let _ = state.outbound.send(RhizomeOutbound::SyncSnapshotNow);
    json_ok(json!({ "status": "sync_dispatched" }))
}

async fn manifest_webmanifest() -> impl IntoResponse {
    let doc = json!({
        "name": "Mycelium Rhizome — Super-App P2P Soberano",
        "short_name": "Rhizome P2P",
        "start_url": "/rhizome/",
        "scope": "/rhizome/",
        "display": "standalone",
        "background_color": "#060b07",
        "theme_color": "#10b981",
        "description": "Tube, Reels, Commons MCP, Feed, Enxame MEP e Zap Pós-Quântico 100% soberano sem nuvem nem Big Tech."
    });
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/manifest+json; charset=utf-8",
        )],
        doc.to_string(),
    )
}

async fn video_details_api(
    State(state): State<RhizomeIonState>,
    Path(cid): Path<String>,
) -> Response {
    match state.store.lock().unwrap().get_video_details(&cid) {
        Some(details) => json_ok(serde_json::to_value(details).unwrap_or_else(|_| json!({}))),
        None => json_err(
            StatusCode::NOT_FOUND,
            format!("vídeo '{cid}' não encontrado"),
        ),
    }
}

async fn record_video_view_api(
    State(state): State<RhizomeIonState>,
    Path(cid): Path<String>,
) -> Response {
    match state.store.lock().unwrap().record_video_view(&cid) {
        Ok(views) => json_ok(json!({ "manifest_cid": cid, "views_count": views })),
        Err(e) => json_err(StatusCode::NOT_FOUND, e.to_string()),
    }
}

fn default_spores_asset() -> String {
    "spores".into()
}

#[derive(Deserialize)]
struct TipVideoReq {
    #[serde(default = "default_spores_asset")]
    asset_type: String,
    amount: u64,
    #[serde(default)]
    memo: String,
    target_post_id: Option<String>,
    to_ghost_pubkey: Option<String>,
    execute_ledger: Option<bool>,
}

async fn tip_video_api(
    State(state): State<RhizomeIonState>,
    Path(cid): Path<String>,
    Json(req): Json<TipVideoReq>,
) -> Response {
    let (target_id, manifest_cid, recipient_ghost_hex, local_ghost_hex) = {
        let guard = state.store.lock().unwrap();
        let Some(details) = guard.get_video_details(&cid) else {
            return json_err(
                StatusCode::NOT_FOUND,
                format!("vídeo '{cid}' não encontrado"),
            );
        };
        let target_id = req
            .target_post_id
            .clone()
            .or_else(|| details.post.as_ref().map(|p| p.post_id.clone()))
            .unwrap_or_else(|| details.manifest_cid.clone());
        let rec_ghost = req
            .to_ghost_pubkey
            .clone()
            .or_else(|| {
                details.author_profile.as_ref().map(|p| {
                    p.wallet_pubkey_hex
                        .clone()
                        .unwrap_or_else(|| p.ghost_pubkey_hex.clone())
                })
            });
        let local_prof = guard.local_profile();
        let local_ghost = local_prof
            .wallet_pubkey_hex
            .unwrap_or(local_prof.ghost_pubkey_hex);
        (target_id, details.manifest_cid, rec_ghost, local_ghost)
    };

    let nutrient_norm = req.asset_type.trim().to_ascii_lowercase();
    let is_cpx = nutrient_norm == "cpx";
    let is_ledger_nutrient = matches!(
        nutrient_norm.as_str(),
        "spores" | "atp" | "mycelia" | "enzymes" | "resilience"
    );
    let mut ledger_tx_id = None;
    let mut cpx_royalty_dist: Option<Value> = None;

    if is_cpx && req.amount > 0 {
        // 1 CPX = 1_000_000 micros no mycelium-bank; aplica contrato de royalty se cadastrado para o CID
        let gross_micros = i64::try_from(req.amount.saturating_mul(1_000_000)).unwrap_or(i64::MAX);
        let tip_memo = if req.memo.trim().is_empty() {
            format!("gorjeta-cpx video:{manifest_cid}")
        } else {
            req.memo.clone()
        };
        let creator_account = recipient_ghost_hex
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("creator:{manifest_cid}"));

        let mut eco = state.ecosystem.persist.lock().unwrap();
        if eco.royalty_engine.contracts.contains_key(&manifest_cid) {
            match eco.settle_royalty_cpx(&manifest_cid, gross_micros, &tip_memo) {
                Ok(dist) => {
                    ledger_tx_id = Some(dist.payout_id.clone());
                    cpx_royalty_dist = serde_json::to_value(&dist).ok();
                }
                Err(e) => {
                    if req.execute_ledger.unwrap_or(true) {
                        return json_err(StatusCode::BAD_REQUEST, e);
                    }
                }
            }
        } else {
            match eco.transfer_cpx_direct(&creator_account, gross_micros, &tip_memo) {
                Ok(rec) => {
                    ledger_tx_id = Some(rec.record_hash);
                }
                Err(e) => {
                    if req.execute_ledger.unwrap_or(true) {
                        return json_err(StatusCode::BAD_REQUEST, e);
                    }
                }
            }
        }
    }

    let want_ledger = req.execute_ledger.unwrap_or(is_ledger_nutrient) && req.amount > 0;
    if want_ledger && is_ledger_nutrient {
        if let Some(ref to_hex) = recipient_ghost_hex {
            if !to_hex.is_empty() && to_hex != &local_ghost_hex {
                let (tx, rx) = oneshot::channel();
                if state
                    .outbound
                    .send(RhizomeOutbound::ExecuteTransfer {
                        to_hex: to_hex.clone(),
                        amount: req.amount,
                        nutrient: nutrient_norm.clone(),
                        kind: "consumption".into(),
                        memo: if req.memo.trim().is_empty() {
                            format!("gorjeta video:{manifest_cid}")
                        } else {
                            req.memo.clone()
                        },
                        asset: Some(manifest_cid.clone()),
                        reply: tx,
                    })
                    .is_ok()
                {
                    match tokio::time::timeout(std::time::Duration::from_secs(3), rx).await {
                        Ok(Ok(Ok(outcome))) => {
                            ledger_tx_id = Some(outcome.tx_id);
                        }
                        Ok(Ok(Err(e))) => {
                            return json_err(StatusCode::BAD_REQUEST, e);
                        }
                        _ => {
                            if req.execute_ledger == Some(true) {
                                return json_err(
                                    StatusCode::GATEWAY_TIMEOUT,
                                    "timeout na liquidação com o Organismo",
                                );
                            }
                        }
                    }
                }
            } else if req.execute_ledger == Some(true) {
                return json_err(
                    StatusCode::BAD_REQUEST,
                    "não é possível liquidar transferência para a própria carteira",
                );
            }
        } else if req.execute_ledger == Some(true) {
            return json_err(
                StatusCode::BAD_REQUEST,
                "perfil remoto do criador ainda não sincronizou a chave GhostID",
            );
        }
    }

    let memo = if req.memo.trim().is_empty() {
        "Apoio ao criador soberano".into()
    } else {
        req.memo
    };

    let res = state.store.lock().unwrap().record_tip(
        &target_id,
        req.asset_type,
        req.amount,
        memo,
        ledger_tx_id,
    );
    match res {
        Ok((tip, env, plot)) => {
            let _ = state.outbound.send(RhizomeOutbound::BroadcastEvent {
                event: env,
                plots: plot.into_iter().collect(),
            });
            json_ok(json!({
                "tip": tip,
                "ledger_tx_id": tip.ledger_tx_id,
                "royalty_distribution": cpx_royalty_dist,
            }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

fn escape_svg_text(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn video_thumbnail_api(
    State(state): State<RhizomeIonState>,
    Path(cid): Path<String>,
) -> Response {
    let (thumb_blob, details_opt) = {
        let guard = state.store.lock().unwrap();
        let details = guard.get_video_details(&cid);
        let blob = details
            .as_ref()
            .and_then(|d| d.manifest.thumbnail_cid.as_ref())
            .and_then(|tcid| guard.load_media_blob(&tcid.to_string()));
        (blob, details)
    };

    if let Some((bytes, mime)) = thumb_blob {
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, mime),
                (
                    header::CACHE_CONTROL,
                    "public, max-age=86400, immutable".into(),
                ),
            ],
            bytes,
        )
            .into_response();
    }

    let (title, badge, short_cid) = match details_opt {
        Some(d) => {
            let is_short = d
                .post
                .as_ref()
                .map(|p| matches!(p.kind, PostKind::Short))
                .unwrap_or(false);
            let ctype = d
                .post
                .as_ref()
                .and_then(|p| p.content_type.as_deref())
                .unwrap_or(if is_short { "short" } else { "longform" });
            let badge = match ctype {
                "doc" => "DOC & CINEMA · MMP",
                "short" => "REELS / SHORT · 9:16",
                _ => "TUBE · MMP BLAKE3",
            };
            let sc: String = d.manifest_cid.chars().take(18).collect();
            (d.manifest.title, badge.to_string(), format!("{sc}…"))
        }
        None => (
            "Vídeo Soberano".into(),
            "MYCELIUM MMP".into(),
            cid.chars().take(18).collect(),
        ),
    };

    let svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 360" width="640" height="360">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#07120c"/>
      <stop offset="55%" stop-color="#0d2318"/>
      <stop offset="100%" stop-color="#070d12"/>
    </linearGradient>
    <radialGradient id="glow" cx="72%" cy="28%" r="60%">
      <stop offset="0%" stop-color="#10b981" stop-opacity="0.30"/>
      <stop offset="100%" stop-color="#10b981" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="640" height="360" fill="url(#bg)"/>
  <rect width="640" height="360" fill="url(#glow)"/>
  <circle cx="512" cy="112" r="78" fill="none" stroke="#10b981" stroke-opacity="0.22" stroke-width="2"/>
  <circle cx="512" cy="112" r="46" fill="none" stroke="#34d399" stroke-opacity="0.34" stroke-width="2"/>
  <polygon points="500,92 500,132 536,112" fill="#34d399" fill-opacity="0.85"/>
  <rect x="34" y="34" width="215" height="28" rx="14" fill="#10b981" fill-opacity="0.16" stroke="#10b981" stroke-opacity="0.45"/>
  <text x="48" y="53" fill="#6ee7b7" font-family="system-ui,sans-serif" font-size="13" font-weight="700">{badge}</text>
  <text x="34" y="245" fill="#ecfdf5" font-family="system-ui,sans-serif" font-size="25" font-weight="700">{title}</text>
  <text x="34" y="286" fill="#94a3b8" font-family="monospace" font-size="14">{short_cid}</text>
</svg>"##,
        badge = escape_svg_text(&badge),
        title = escape_svg_text(&title.chars().take(42).collect::<String>()),
        short_cid = escape_svg_text(&short_cid)
    );
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        svg,
    )
        .into_response()
}

async fn list_commons_api(State(state): State<RhizomeIonState>) -> Response {
    let projects = state.store.lock().unwrap().list_commons_projects();
    json_ok(json!({ "projects": projects }))
}

#[derive(Deserialize)]
struct CreateCommonsReq {
    #[serde(default)]
    slug: String,
    title: String,
    summary: String,
    #[serde(default)]
    full_proposal: String,
    funding_goal: f64,
    #[serde(default)]
    spores_pool_allocated: u64,
    #[serde(default)]
    target_release_date: String,
    #[serde(default)]
    budget_ledger: Vec<BudgetItem>,
    split_agreement: Vec<SplitContractParty>,
    #[serde(default)]
    milestones: Vec<MilestoneItem>,
}

async fn create_commons_api(
    State(state): State<RhizomeIonState>,
    Json(req): Json<CreateCommonsReq>,
) -> Response {
    let res = state.store.lock().unwrap().create_commons_project(
        req.slug,
        req.title,
        req.summary,
        req.full_proposal,
        req.funding_goal,
        req.spores_pool_allocated,
        req.target_release_date,
        req.budget_ledger,
        req.split_agreement,
        req.milestones,
    );
    match res {
        Ok((project, env, plot)) => {
            let _ = state.outbound.send(RhizomeOutbound::BroadcastEvent {
                event: env,
                plots: plot.into_iter().collect(),
            });
            json_ok(json!({ "project": project }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn get_commons_api(
    State(state): State<RhizomeIonState>,
    Path(id): Path<String>,
) -> Response {
    match state.store.lock().unwrap().get_commons_project(&id) {
        Some(view) => json_ok(serde_json::to_value(view).unwrap_or_else(|_| json!({}))),
        None => json_err(
            StatusCode::NOT_FOUND,
            format!("projeto MCP '{id}' não encontrado"),
        ),
    }
}

#[derive(Deserialize)]
struct ContributeCommonsReq {
    #[serde(default)]
    contributor_name: String,
    #[serde(default)]
    amount_p2p: f64,
    #[serde(default)]
    spores_contributed: u64,
    #[serde(default)]
    message: String,
    #[serde(default)]
    execute_ledger: bool,
    nutrient: Option<String>,
}

async fn contribute_commons_api(
    State(state): State<RhizomeIonState>,
    Path(id): Path<String>,
    Json(req): Json<ContributeCommonsReq>,
) -> Response {
    if req.execute_ledger && req.spores_contributed > 0 {
        let (lead_ghost, local_ghost) = {
            let guard = state.store.lock().unwrap();
            let proj = guard.get_commons_project(&id);
            let lead_ghost = proj
                .as_ref()
                .and_then(|p| guard.get_profile(&p.project.lead_node_id))
                .map(|prof| {
                    prof.wallet_pubkey_hex
                        .unwrap_or(prof.ghost_pubkey_hex)
                });
            let local_prof = guard.local_profile();
            let local_wallet = local_prof
                .wallet_pubkey_hex
                .unwrap_or(local_prof.ghost_pubkey_hex);
            (lead_ghost, local_wallet)
        };
        if let Some(to_hex) = lead_ghost {
            if !to_hex.is_empty() && to_hex != local_ghost {
                let (tx, rx) = oneshot::channel();
                let nutrient = req.nutrient.clone().unwrap_or_else(|| "spores".into());
                if state
                    .outbound
                    .send(RhizomeOutbound::ExecuteTransfer {
                        to_hex,
                        amount: req.spores_contributed,
                        nutrient,
                        kind: "consumption".into(),
                        memo: format!("commons:{id}"),
                        asset: Some(id.clone()),
                        reply: tx,
                    })
                    .is_ok()
                {
                    match tokio::time::timeout(std::time::Duration::from_secs(3), rx).await {
                        Ok(Ok(Ok(_))) => {}
                        Ok(Ok(Err(e))) => return json_err(StatusCode::BAD_REQUEST, e),
                        _ => {
                            return json_err(
                                StatusCode::GATEWAY_TIMEOUT,
                                "timeout na liquidação do ledger",
                            )
                        }
                    }
                }
            }
        }
    }

    let res = state.store.lock().unwrap().contribute_to_commons(
        &id,
        req.contributor_name,
        req.amount_p2p,
        req.spores_contributed,
        req.message,
    );
    match res {
        Ok((contribution, project_view, env, plot)) => {
            let _ = state.outbound.send(RhizomeOutbound::BroadcastEvent {
                event: env,
                plots: plot.into_iter().collect(),
            });
            json_ok(json!({ "contribution": contribution, "project_view": project_view }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn list_lenses_api(State(state): State<RhizomeIonState>) -> Response {
    let lenses = state.store.lock().unwrap().list_all_lenses();
    json_ok(json!({ "lenses": lenses }))
}

#[derive(Deserialize)]
struct CreateLensReq {
    name: String,
    #[serde(default)]
    description: String,
    weights: BTreeMap<String, f64>,
}

async fn create_lens_api(
    State(state): State<RhizomeIonState>,
    Json(req): Json<CreateLensReq>,
) -> Response {
    match state
        .store
        .lock()
        .unwrap()
        .create_custom_lens(req.name, req.description, req.weights)
    {
        Ok((lens, env, plot)) => {
            let _ = state.outbound.send(RhizomeOutbound::BroadcastEvent {
                event: env,
                plots: plot.into_iter().collect(),
            });
            json_ok(json!({ "lens": lens }))
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn wallet_api(State(state): State<RhizomeIonState>) -> Response {
    let (tx, rx) = oneshot::channel();
    if state
        .outbound
        .send(RhizomeOutbound::GetWalletReport { reply: tx })
        .is_err()
    {
        return json_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "organismo offline para leitura de carteira",
        );
    }
    match tokio::time::timeout(std::time::Duration::from_secs(3), rx).await {
        Ok(Ok(report)) => json_ok(serde_json::to_value(report).unwrap_or_else(|_| json!({}))),
        _ => json_err(StatusCode::GATEWAY_TIMEOUT, "timeout ao ler carteira viva"),
    }
}

#[derive(Deserialize)]
struct WalletTransferReq {
    to_hex: String,
    amount: u64,
    #[serde(default = "default_spores_asset")]
    nutrient: String,
    #[serde(default = "default_consumption_kind")]
    kind: String,
    #[serde(default)]
    memo: String,
    asset: Option<String>,
}

fn default_consumption_kind() -> String {
    "consumption".into()
}

async fn wallet_transfer_api(
    State(state): State<RhizomeIonState>,
    Json(req): Json<WalletTransferReq>,
) -> Response {
    let (tx, rx) = oneshot::channel();
    if state
        .outbound
        .send(RhizomeOutbound::ExecuteTransfer {
            to_hex: req.to_hex,
            amount: req.amount,
            nutrient: req.nutrient,
            kind: req.kind,
            memo: req.memo,
            asset: req.asset,
            reply: tx,
        })
        .is_err()
    {
        return json_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "organismo offline para transferência",
        );
    }
    match tokio::time::timeout(std::time::Duration::from_secs(3), rx).await {
        Ok(Ok(Ok(outcome))) => {
            json_ok(serde_json::to_value(outcome).unwrap_or_else(|_| json!({})))
        }
        Ok(Ok(Err(msg))) => json_err(StatusCode::BAD_REQUEST, msg),
        _ => json_err(
            StatusCode::GATEWAY_TIMEOUT,
            "timeout na transferência Schnorr",
        ),
    }
}

async fn swarm_api(State(state): State<RhizomeIonState>) -> Response {
    let (tx, rx) = oneshot::channel();
    if state
        .outbound
        .send(RhizomeOutbound::GetSwarmSnapshot { reply: tx })
        .is_err()
    {
        return json_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "organismo offline para telemetria do enxame",
        );
    }
    match tokio::time::timeout(std::time::Duration::from_secs(3), rx).await {
        Ok(Ok(snap)) => json_ok(serde_json::to_value(snap).unwrap_or_else(|_| json!({}))),
        _ => json_err(
            StatusCode::GATEWAY_TIMEOUT,
            "timeout ao consultar enxame libp2p",
        ),
    }
}

#[derive(Deserialize)]
struct SwarmConfigReq {
    volunteer_donor: Option<bool>,
    device_type: Option<String>,
}

async fn swarm_config_api(
    State(state): State<RhizomeIonState>,
    Json(req): Json<SwarmConfigReq>,
) -> Response {
    let (tx, rx) = oneshot::channel();
    if state
        .outbound
        .send(RhizomeOutbound::SetSwarmConfig {
            volunteer_donor: req.volunteer_donor,
            device_type: req.device_type,
            reply: tx,
        })
        .is_err()
    {
        return json_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "organismo offline para configurar enxame",
        );
    }
    match tokio::time::timeout(std::time::Duration::from_secs(3), rx).await {
        Ok(Ok(snap)) => json_ok(serde_json::to_value(snap).unwrap_or_else(|_| json!({}))),
        _ => json_err(
            StatusCode::GATEWAY_TIMEOUT,
            "timeout ao configurar enxame",
        ),
    }
}

async fn get_moderation_api(State(state): State<RhizomeIonState>) -> Response {
    let filters = state.store.lock().unwrap().get_moderation_filters();
    json_ok(serde_json::to_value(filters).unwrap_or_else(|_| json!({})))
}

async fn set_moderation_api(
    State(state): State<RhizomeIonState>,
    Json(filters): Json<ModerationFilters>,
) -> Response {
    match state
        .store
        .lock()
        .unwrap()
        .set_moderation_filters(filters)
    {
        Ok(saved) => json_ok(serde_json::to_value(saved).unwrap_or_else(|_| json!({}))),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}
