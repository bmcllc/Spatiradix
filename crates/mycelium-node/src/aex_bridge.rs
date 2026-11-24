//! Ponte controlada entre o terminal AEX Sovereign Network (TypeScript) e o daemon Mycelium (Rust).
//!
//! Princípios de segurança inegociáveis:
//! - Nunca recebe nem armazena a Vault Master Key (VMK) ou chaves privadas permanentes da AEX.
//! - Chaves efêmeras GhostID (secp256k1) e ML-KEM-1024 residem exclusivamente em RAM (`ZeroizeOnDrop`).
//! - Eventos Nostr de shards QEL só podem ser emitidos com destinatário NIP-44 explícito.
//! - Blocos `mycelium-ipfs` são exclusivamente locais (ContentId BLAKE3).

use crate::control::{AexDtnInboxItem, AexTransportScoreDto, Response};
use base64::Engine;
use mycelium_distancebridge::{transport_potential, TransportContext};
use mycelium_ghostid::GhostId;
use mycelium_hyphae::{DtnBundle, HyphaeNode};
use mycelium_ipfs::BlockStore;
use mycelium_nostr::create_shard_event;
use mycelium_pqc::{mlkem_decapsulate, mlkem_encapsulate, mlkem_keygen, KemKeyPair};
use mycelium_qel::{fragment, reconstruct, QelConfig, QelShard, TransportHint, MAX_SHARD_PAYLOAD};
use mycelium_zkp::{hash_chronicle, pedersen_commit, pedersen_open};
use rand::RngCore;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const AEX_DTN_PREFIX: &[u8] = b"AEXDTN1:";
pub const MAX_AEX_DTN_INBOX: usize = 256;

#[derive(Default)]
pub struct AexBridgeState {
    pub ghost_sessions: HashMap<String, GhostId>,
    pub kem_keys: HashMap<String, KemKeyPair>,
    pub dtn_inbox: VecDeque<AexDtnInboxItem>,
}

fn b64_decode(raw: &str, label: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|e| format!("base64 inválido em {label}: {e}"))
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn hex_32(raw: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(raw).map_err(|e| format!("hex inválido em {label}: {e}"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("{label} deve ter 32 bytes (recebeu {})", v.len()))
}

fn sanitize_component(raw: &str) -> Result<String, String> {
    if raw.is_empty() || raw.len() > 160 || raw.contains("..") || raw.starts_with('/') {
        return Err("componente de chave inválido".into());
    }
    let clean: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    Ok(clean)
}

pub fn handle_bridge_info() -> Response {
    let mut features = vec![
        "qel".to_string(),
        "ipfs_local".to_string(),
        "spore_encrypted".to_string(),
        "ghostid".to_string(),
        "distancebridge".to_string(),
        "dtn".to_string(),
        "pqc_kem".to_string(),
        "zkp_pedersen".to_string(),
        "zkp_hash_chronicle".to_string(),
    ];
    let pqc_enabled = cfg!(feature = "pqc-transport");
    let veil_enabled = cfg!(feature = "veil");
    let nostr_transport_enabled = cfg!(feature = "nostr-transport");
    let license_enabled = cfg!(feature = "license");
    if pqc_enabled {
        features.push("pqc-transport".into());
    }
    if veil_enabled {
        features.push("veil".into());
    }
    if nostr_transport_enabled {
        features.push("nostr-transport".into());
    }
    if license_enabled {
        features.push("license".into());
    }
    if cfg!(feature = "webrtc") {
        features.push("webrtc".into());
    }
    Response::AexBridgeCapabilities {
        protocol_version: "aex-mycelium-bridge/1.0.0".into(),
        crates: vec![
            "mycelium-node".into(),
            "mycelium-hyphae".into(),
            "mycelium-qel".into(),
            "mycelium-ipfs".into(),
            "mycelium-ghostid".into(),
            "mycelium-pqc".into(),
            "mycelium-zkp".into(),
            "mycelium-distancebridge".into(),
            "mycelium-nostr".into(),
        ],
        features,
        pqc_enabled,
        veil_enabled,
        nostr_transport_enabled,
        license_enabled,
    }
}

pub fn handle_qel_fragment(
    data_b64: &str,
    content_id: &str,
    threshold: u8,
    total: u8,
    ttl_secs: u64,
    recipient_nostr_pubkey_hex: Option<&str>,
) -> Response {
    let bytes = match b64_decode(data_b64, "data_b64") {
        Ok(b) => b,
        Err(message) => return Response::Err { message },
    };
    if bytes.is_empty() || bytes.len() > MAX_SHARD_PAYLOAD {
        return Response::Err {
            message: format!(
                "QEL payload {} bytes fora do limite (1..={})",
                bytes.len(),
                MAX_SHARD_PAYLOAD
            ),
        };
    }
    let cfg = QelConfig {
        threshold,
        total,
        ttl_secs,
    };
    let shards = match fragment(&bytes, content_id, &cfg) {
        Ok(s) => s,
        Err(e) => {
            return Response::Err {
                message: e.to_string(),
            }
        }
    };

    let mut encrypted_nostr_events = Vec::new();
    if let Some(recipient_hex) = recipient_nostr_pubkey_hex {
        let sender_ghost = match GhostId::spawn_quick(ttl_secs.max(60)) {
            Ok(g) => g,
            Err(e) => {
                return Response::Err {
                    message: e.to_string(),
                }
            }
        };
        for s in &shards {
            match create_shard_event(&sender_ghost, s, Some(recipient_hex)) {
                Ok(ev) => match serde_json::to_string(&ev) {
                    Ok(json) => encrypted_nostr_events.push(json),
                    Err(e) => {
                        return Response::Err {
                            message: e.to_string(),
                        }
                    }
                },
                Err(e) => {
                    return Response::Err {
                        message: e.to_string(),
                    }
                }
            }
        }
    }

    let content_hash_hex = shards
        .first()
        .map(|s| hex::encode(s.content_hash))
        .unwrap_or_default();

    Response::AexQelFragmentResult {
        content_id: content_id.to_string(),
        content_hash_hex,
        shards,
        encrypted_nostr_events,
    }
}

pub fn handle_qel_reconstruct(shards: &[QelShard]) -> Response {
    if shards.is_empty() {
        return Response::Err {
            message: "nenhum shard informado para reconstrução QEL".into(),
        };
    }
    let content_id = shards[0].content_id.clone();
    let expected_hash = shards[0].content_hash;
    match reconstruct(shards) {
        Ok(data) => {
            let verified = *blake3::hash(&data).as_bytes() == expected_hash;
            Response::AexQelReconstructResult {
                data_b64: b64_encode(&data),
                content_id,
                verified,
            }
        }
        Err(e) => Response::Err {
            message: e.to_string(),
        },
    }
}

pub fn handle_ipfs_put_local(home: &Path, data_b64: &str) -> Response {
    let bytes = match b64_decode(data_b64, "data_b64") {
        Ok(b) => b,
        Err(message) => return Response::Err { message },
    };
    let store = match BlockStore::open(home) {
        Ok(s) => s,
        Err(e) => {
            return Response::Err {
                message: e.to_string(),
            }
        }
    };
    match store.put(&bytes) {
        Ok(cid) => Response::AexIpfsPutResult {
            content_id: cid.to_string(),
            byte_length: bytes.len(),
        },
        Err(e) => Response::Err {
            message: e.to_string(),
        },
    }
}

pub fn handle_ipfs_get_local(home: &Path, content_id: &str) -> Response {
    let store = match BlockStore::open(home) {
        Ok(s) => s,
        Err(e) => {
            return Response::Err {
                message: e.to_string(),
            }
        }
    };
    match store.get_str(content_id) {
        Ok(bytes) => Response::AexIpfsGetResult {
            found: true,
            data_b64: Some(b64_encode(&bytes)),
        },
        Err(_) => Response::AexIpfsGetResult {
            found: false,
            data_b64: None,
        },
    }
}

pub fn handle_spore_put_encrypted(
    home: &Path,
    namespace: &str,
    key: &str,
    ciphertext_b64: &str,
) -> Response {
    let ns = match sanitize_component(namespace) {
        Ok(v) => v,
        Err(message) => return Response::Err { message },
    };
    let parts: Result<Vec<String>, String> = key.split('/').map(sanitize_component).collect();
    let clean_key = match parts {
        Ok(p) => p.join("__"),
        Err(message) => return Response::Err { message },
    };
    let bytes = match b64_decode(ciphertext_b64, "ciphertext_b64") {
        Ok(b) => b,
        Err(message) => return Response::Err { message },
    };

    let dir = home.join("aex-spores").join(&ns);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return Response::Err {
            message: e.to_string(),
        };
    }
    let path = dir.join(format!("{clean_key}.bin"));
    if let Err(e) = std::fs::write(&path, &bytes) {
        return Response::Err {
            message: e.to_string(),
        };
    }
    let digest_hex = hex::encode(blake3::hash(&bytes).as_bytes());
    Response::AexSporePutResult {
        stored_key: format!("{ns}/{clean_key}"),
        digest_hex,
    }
}

pub fn handle_spore_get_encrypted(home: &Path, namespace: &str, key: &str) -> Response {
    let ns = match sanitize_component(namespace) {
        Ok(v) => v,
        Err(message) => return Response::Err { message },
    };
    let parts: Result<Vec<String>, String> = key.split('/').map(sanitize_component).collect();
    let clean_key = match parts {
        Ok(p) => p.join("__"),
        Err(message) => return Response::Err { message },
    };
    let path = home
        .join("aex-spores")
        .join(&ns)
        .join(format!("{clean_key}.bin"));
    match std::fs::read(&path) {
        Ok(bytes) => Response::AexSporeGetResult {
            found: true,
            ciphertext_b64: Some(b64_encode(&bytes)),
        },
        Err(_) => Response::AexSporeGetResult {
            found: false,
            ciphertext_b64: None,
        },
    }
}

pub fn handle_distancebridge_select(
    online: bool,
    latency_ms: u32,
    bandwidth_kbps: u32,
    packet_loss_pct: f32,
    anonymity_required: bool,
    payload_bytes: usize,
) -> Response {
    let _ = (latency_ms, bandwidth_kbps, packet_loss_pct, payload_bytes);
    let ctx = TransportContext {
        has_internet: online,
        ipfs_peers: usize::from(online && !anonymity_required),
        relay_available: online,
        lora_available: false,
        gsm_available: false,
        proximity_peers: 0,
    };
    let mut scored: Vec<(TransportHint, f64)> = [
        TransportHint::Nostr,
        TransportHint::Ipfs,
        TransportHint::RelayMesh,
        TransportHint::Dtn,
        TransportHint::Visual,
        TransportHint::LoRa,
        TransportHint::Sms,
        TransportHint::Proximity,
    ]
    .into_iter()
    .map(|hint| {
        let p = transport_potential(&hint, &ctx);
        (hint, p)
    })
    .collect();
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let transports = scored
        .into_iter()
        .map(|(hint, potential)| {
            let (channel, implemented_in_runtime, note) = match hint {
                TransportHint::RelayMesh => (
                    "relay_mesh",
                    true,
                    "libp2p QUIC/TCP + Noise + Yamux + Circuit Relay v2",
                ),
                TransportHint::Nostr => (
                    "nostr",
                    cfg!(feature = "nostr-transport"),
                    "Nostr CandidateRelay (kind 39401/39406) com NIP-44",
                ),
                TransportHint::Ipfs => (
                    "ipfs_local",
                    true,
                    "mycelium-ipfs local BLAKE3 blockstore (sem Bitswap WAN)",
                ),
                TransportHint::Dtn => (
                    "dtn",
                    true,
                    "mycelium-hyphae DtnBundleStore unicast store-and-forward",
                ),
                TransportHint::LoRa => (
                    "lora_hint",
                    false,
                    "Somente TransportHint (sem driver de rádio LoRa no host)",
                ),
                TransportHint::Sms => (
                    "sms_hint",
                    false,
                    "Somente TransportHint (sem modem SMS no host)",
                ),
                TransportHint::Proximity => (
                    "proximity_hint",
                    false,
                    "Somente TransportHint (sem BLE/NFC nativo conectado)",
                ),
                TransportHint::Visual => ("visual_qr_hint", true, "QR Code offline na PWA AEX"),
                TransportHint::Any => ("any", true, "Qualquer canal compatível"),
            };
            AexTransportScoreDto {
                channel: channel.into(),
                potential,
                implemented_in_runtime,
                note: note.into(),
            }
        })
        .collect();
    Response::AexDistancebridgeResult { transports }
}

pub fn handle_ghost_spawn(state: &mut AexBridgeState, ttl_secs: u64) -> Response {
    state.ghost_sessions.retain(|_, g| !g.is_expired());
    let ttl = ttl_secs.max(10);
    let ghost = match GhostId::spawn_quick(ttl) {
        Ok(g) => g,
        Err(e) => {
            return Response::Err {
                message: e.to_string(),
            }
        }
    };
    let pubkey_hex = ghost.nostr_pubkey_hex();
    let expires_at_secs = ghost.created_at_secs().saturating_add(ghost.ttl_secs());
    let mut id_bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut id_bytes);
    let handle = format!("ghost_{}", hex::encode(id_bytes));
    state.ghost_sessions.insert(handle.clone(), ghost);
    Response::AexGhostSpawnResult {
        handle,
        pubkey_hex,
        expires_at_secs,
    }
}

pub fn handle_ghost_sign(state: &mut AexBridgeState, handle: &str, payload_b64: &str) -> Response {
    let bytes = match b64_decode(payload_b64, "payload_b64") {
        Ok(b) => b,
        Err(message) => return Response::Err { message },
    };
    let Some(ghost) = state.ghost_sessions.get(handle) else {
        return Response::Err {
            message: "sessão GhostID não encontrada".into(),
        };
    };
    if let Err(e) = ghost.ensure_alive() {
        return Response::Err {
            message: e.to_string(),
        };
    }
    let sig = ghost.sign(&bytes);
    Response::AexGhostSignResult {
        signature_hex: hex::encode(sig),
    }
}

pub fn handle_ghost_verify(pubkey_hex: &str, payload_b64: &str, signature_hex: &str) -> Response {
    let pk = match hex_32(pubkey_hex, "pubkey_hex") {
        Ok(v) => v,
        Err(message) => return Response::Err { message },
    };
    let payload = match b64_decode(payload_b64, "payload_b64") {
        Ok(b) => b,
        Err(message) => return Response::Err { message },
    };
    let sig_vec = match hex::decode(signature_hex) {
        Ok(s) => s,
        Err(e) => {
            return Response::Err {
                message: e.to_string(),
            }
        }
    };
    let sig: [u8; 64] = match sig_vec.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return Response::Err {
                message: "assinatura GhostID deve ter 64 bytes".into(),
            }
        }
    };
    let valid = GhostId::verify(&pk, &payload, &sig).is_ok();
    Response::AexVerifyResult { valid }
}

pub fn handle_ghost_destroy(state: &mut AexBridgeState, handle: &str) -> Response {
    let removed = state.ghost_sessions.remove(handle).is_some();
    Response::Ok {
        message: if removed {
            "GhostID descartado e zeroizado da RAM".into()
        } else {
            "GhostID já ausente".into()
        },
    }
}

pub fn handle_dtn_send(
    hyphae: &mut HyphaeNode,
    target_peer: &str,
    target_node: Option<&str>,
    payload_b64: &str,
    ttl_secs: u64,
    max_hops: u32,
) -> Response {
    let raw_payload = match b64_decode(payload_b64, "payload_b64") {
        Ok(b) => b,
        Err(message) => return Response::Err { message },
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let dst_node = target_node.and_then(|s| s.parse::<mycelium_core::NodeId>().ok());

    let mut tagged_payload = Vec::with_capacity(AEX_DTN_PREFIX.len() + raw_payload.len());
    tagged_payload.extend_from_slice(AEX_DTN_PREFIX);
    tagged_payload.extend_from_slice(&raw_payload);

    let bundle_id = format!(
        "aex_{}",
        hex::encode(&blake3::hash(&tagged_payload).as_bytes()[..12])
    );
    let bundle = DtnBundle {
        bundle_id: bundle_id.clone(),
        src_peer: hyphae.peer_id().to_string(),
        dst_peer: target_peer.to_string(),
        dst_node,
        binding: None,
        created_at: now,
        ttl_secs: ttl_secs.max(60),
        hops: 0,
        max_hops: max_hops.max(1),
        payload: tagged_payload,
    };

    match hyphae.forward_or_store_dtn(bundle) {
        Ok(true) => Response::AexDtnSendResult {
            bundle_id,
            delivered_directly: true,
            queued_dtn: false,
        },
        Ok(false) => Response::AexDtnSendResult {
            bundle_id,
            delivered_directly: false,
            queued_dtn: true,
        },
        Err(e) => Response::Err {
            message: e.to_string(),
        },
    }
}

pub fn handle_dtn_poll(state: &mut AexBridgeState, limit: usize) -> Response {
    let take = limit.clamp(1, 128);
    let mut bundles = Vec::new();
    for _ in 0..take {
        match state.dtn_inbox.pop_front() {
            Some(item) => bundles.push(item),
            None => break,
        }
    }
    Response::AexDtnPollResult { bundles }
}

pub fn try_ingest_aex_dtn_bundle(state: &mut AexBridgeState, bundle: &DtnBundle) -> bool {
    if !bundle.payload.starts_with(AEX_DTN_PREFIX) {
        return false;
    }
    let opaque = &bundle.payload[AEX_DTN_PREFIX.len()..];
    if state.dtn_inbox.len() >= MAX_AEX_DTN_INBOX {
        state.dtn_inbox.pop_front();
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    state.dtn_inbox.push_back(AexDtnInboxItem {
        bundle_id: bundle.bundle_id.clone(),
        from_peer: bundle.src_peer.clone(),
        payload_b64: b64_encode(opaque),
        received_at: now,
    });
    true
}

pub fn handle_pqc_keygen(state: &mut AexBridgeState) -> Response {
    let kp = mlkem_keygen();
    let pk_hex = hex::encode(&kp.public_key);
    let mut id_bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut id_bytes);
    let handle = format!("kem_{}", hex::encode(id_bytes));
    state.kem_keys.insert(handle.clone(), kp);
    Response::AexPqcKeygenResult {
        handle,
        public_key_hex: pk_hex,
    }
}

pub fn handle_pqc_encapsulate(public_key_hex: &str) -> Response {
    let pk = match hex::decode(public_key_hex) {
        Ok(b) => b,
        Err(e) => {
            return Response::Err {
                message: e.to_string(),
            }
        }
    };
    match mlkem_encapsulate(&pk) {
        Ok(enc) => Response::AexPqcEncapResult {
            ciphertext_hex: hex::encode(&enc.ciphertext),
            shared_secret_hex: hex::encode(&enc.shared_secret),
        },
        Err(e) => Response::Err {
            message: e.to_string(),
        },
    }
}

pub fn handle_pqc_decapsulate(
    state: &AexBridgeState,
    handle: &str,
    ciphertext_hex: &str,
) -> Response {
    let Some(kp) = state.kem_keys.get(handle) else {
        return Response::Err {
            message: "chave ML-KEM não encontrada na sessão RAM".into(),
        };
    };
    let ct = match hex::decode(ciphertext_hex) {
        Ok(b) => b,
        Err(e) => {
            return Response::Err {
                message: e.to_string(),
            }
        }
    };
    match mlkem_decapsulate(kp.private_bytes(), &ct) {
        Ok(ss) => Response::AexPqcDecapResult {
            shared_secret_hex: hex::encode(&ss),
        },
        Err(e) => Response::Err {
            message: e.to_string(),
        },
    }
}

pub fn handle_zk_hash_chronicle(payload_b64: &str, prev_hex: Option<&str>) -> Response {
    let payload = match b64_decode(payload_b64, "payload_b64") {
        Ok(b) => b,
        Err(message) => return Response::Err { message },
    };
    let parents: Vec<[u8; 32]> = match prev_hex {
        Some(h) if !h.trim().is_empty() => match hex_32(h.trim(), "prev_hex") {
            Ok(p) => vec![p],
            Err(message) => return Response::Err { message },
        },
        _ => Vec::new(),
    };
    let digest = hash_chronicle(&payload, &parents);
    Response::AexZkHashChronicleResult {
        chronicle_hex: hex::encode(digest),
    }
}

pub fn handle_zk_pedersen_commit(value_str: &str, blinding_hex: Option<&str>) -> Response {
    let value: u64 = match value_str.parse() {
        Ok(v) => v,
        Err(e) => {
            return Response::Err {
                message: format!("value inválido: {e}"),
            }
        }
    };
    let blinding: [u8; 32] = match blinding_hex {
        Some(h) if !h.trim().is_empty() => match hex_32(h.trim(), "blinding_hex") {
            Ok(b) => b,
            Err(message) => return Response::Err { message },
        },
        _ => {
            let mut b = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut b);
            b
        }
    };
    let commitment = pedersen_commit(value, blinding);
    Response::AexZkPedersenCommitResult {
        commitment_hex: hex::encode(commitment),
        blinding_hex: hex::encode(blinding),
    }
}

pub fn handle_zk_pedersen_verify(
    commitment_hex: &str,
    value_str: &str,
    blinding_hex: &str,
) -> Response {
    let value: u64 = match value_str.parse() {
        Ok(v) => v,
        Err(e) => {
            return Response::Err {
                message: format!("value inválido: {e}"),
            }
        }
    };
    let c = match hex_32(commitment_hex, "commitment_hex") {
        Ok(v) => v,
        Err(message) => return Response::Err { message },
    };
    let b = match hex_32(blinding_hex, "blinding_hex") {
        Ok(v) => v,
        Err(message) => return Response::Err { message },
    };
    let valid = pedersen_open(&c, value, b);
    Response::AexVerifyResult { valid }
}
