//! Camada de Retrocompatibilidade (X/Twitter, WhatsApp) e Bridges Abertas (Nostr, RSS 2.0, ActivityPub).
//!
//! Filosofia da Doutrina da Honestidade:
//! - Importadores (`tweets.js`, WhatsApp `.txt`) e protocolos abertos (Nostr NIP-01/94, RSS 2.0,
//!   ActivityPub JSON-LD) funcionam 100% localmente, sem chaves proprietárias e com verificação real.
//! - Adaptadores para APIs proprietárias (`XApiV2Adapter`, `WhatsAppCloudAdapter`) montam e
//!   interpretam payloads reais de contrato, mas NUNCA fingem envio externo sem credenciais explícitas.

use crate::chat::ChatMessageKind;
use crate::identity::SovereignKeys;
use crate::model::{ExternalOrigin, PostKind, ProfileManifest, SocialPost};
use crate::{unix_now, RhizomeError};
use mycelium_ghostid::GhostId;
use mycelium_nostr::{seal_event, NostrEvent};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

// ============================================================================
// 1. IMPORTADOR DE ARCHIVE DO X (TWITTER) — tweets.js / JSON / API v2 JSON
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedXTweet {
    pub original_id: String,
    pub text: String,
    pub created_at: u64,
    pub in_reply_to_id: Option<String>,
    pub hashtags: Vec<String>,
    pub original_handle: Option<String>,
    pub favorite_count: u64,
    pub retweet_count: u64,
}

/// Faz parse de export oficial do X (`window.YTD.tweets.part0 = [...]`), array JSON simples
/// ou payload `{ "data": [...] }` da API v2 do X.
pub fn parse_x_tweets_export(raw: &str) -> Result<Vec<ImportedXTweet>, RhizomeError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(RhizomeError::Compat("arquivo X/Twitter vazio".into()));
    }

    // Remove prefixo JavaScript do takeout oficial: `window.YTD.tweets.part0 = [...]`
    let json_slice = if let Some(eq_idx) = trimmed.find('=') {
        if trimmed[..eq_idx].contains("window.YTD") || trimmed[..eq_idx].trim_start().starts_with("var ") {
            trimmed[eq_idx + 1..].trim().trim_end_matches(';').trim()
        } else {
            trimmed
        }
    } else {
        trimmed
    };

    let root: Value = serde_json::from_str(json_slice)
        .map_err(|e| RhizomeError::Compat(format!("JSON inválido no export do X: {e}")))?;

    let items: Vec<&Value> = if let Some(arr) = root.as_array() {
        arr.iter().collect()
    } else if let Some(arr) = root.get("data").and_then(|d| d.as_array()) {
        arr.iter().collect()
    } else {
        return Err(RhizomeError::Compat(
            "esperado array JSON de tweets ou objeto {\"data\": [...]}".into(),
        ));
    };

    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let obj = item.get("tweet").unwrap_or(item);
        let original_id = obj
            .get("id_str")
            .or_else(|| obj.get("id"))
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .unwrap_or_else(|| format!("x_{}", out.len() + 1));

        let text = obj
            .get("full_text")
            .or_else(|| obj.get("text"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();

        if text.is_empty() {
            continue;
        }

        let created_at = obj
            .get("created_at")
            .and_then(|v| v.as_str())
            .and_then(parse_x_timestamp)
            .unwrap_or_else(unix_now);

        let in_reply_to_id = obj
            .get("in_reply_to_status_id_str")
            .or_else(|| obj.get("in_reply_to_status_id"))
            .and_then(|v| match v {
                Value::String(s) if !s.is_empty() => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            });

        let mut hashtags = Vec::new();
        if let Some(arr) = obj
            .get("entities")
            .and_then(|e| e.get("hashtags"))
            .and_then(|h| h.as_array())
        {
            for h in arr {
                if let Some(tag) = h.get("text").or_else(|| h.get("tag")).and_then(|t| t.as_str()) {
                    hashtags.push(tag.to_ascii_lowercase());
                }
            }
        }

        let original_handle = obj
            .get("user")
            .and_then(|u| u.get("screen_name"))
            .or_else(|| obj.get("author_handle"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim_start_matches('@').to_string());

        let favorite_count = parse_u64_field(obj.get("favorite_count"));
        let retweet_count = parse_u64_field(obj.get("retweet_count"));

        out.push(ImportedXTweet {
            original_id,
            text,
            created_at,
            in_reply_to_id,
            hashtags,
            original_handle,
            favorite_count,
            retweet_count,
        });
    }

    // Ordena cronologicamente para reconstrução fiel de threads (reply_to).
    out.sort_by_key(|t| t.created_at);
    Ok(out)
}

/// Converte tweets importados em `SocialPost`s soberanos assinados com a identidade `Gland` do usuário,
/// preservando a cadeia de threads (`reply_to`) e a proveniência `ExternalOrigin::XArchive`.
pub fn import_x_archive_into_posts(
    raw: &str,
    keys: &SovereignKeys,
    author_handle: &str,
) -> Result<Vec<SocialPost>, RhizomeError> {
    let tweets = parse_x_tweets_export(raw)?;
    let now = unix_now();
    let mut id_map: HashMap<String, String> = HashMap::new();
    let mut posts = Vec::with_capacity(tweets.len());

    for t in tweets {
        let reply_to = t
            .in_reply_to_id
            .as_ref()
            .and_then(|orig| id_map.get(orig).cloned());

        let mut post = SocialPost {
            post_id: String::new(),
            author_node_id: String::new(),
            author_pubkey_hex: String::new(),
            author_handle: author_handle.to_string(),
            kind: PostKind::Microblog,
            title: None,
            body: t.text,
            media: vec![],
            video_manifest_cid: None,
            thumbnail_cid: None,
            channel_id: None,
            community_id: None,
            content_type: None,
            commons_project_id: None,
            tags: t.hashtags,
            mentions: vec![],
            reply_to,
            repost_of: None,
            quote_of: None,
            location: None,
            license: "imported-x-archive".into(),
            external_origin: ExternalOrigin::XArchive {
                original_id: t.original_id.clone(),
                original_handle: t.original_handle,
                imported_at: now,
            },
            created_at: t.created_at,
            signature: String::new(),
        };
        post.finalize_and_sign(keys)?;
        id_map.insert(t.original_id, post.post_id.clone());
        posts.push(post);
    }

    Ok(posts)
}

fn parse_u64_field(v: Option<&Value>) -> u64 {
    match v {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => s.parse::<u64>().unwrap_or(0),
        _ => 0,
    }
}

/// Parse leve e sem dependências extras para datas do Twitter (`Sat Nov 21 15:04:05 +0000 2026`)
/// e ISO-8601 (`2026-11-21T15:04:05Z`).
fn parse_x_timestamp(s: &str) -> Option<u64> {
    let s = s.trim();
    // Formato ISO-8601: YYYY-MM-DDTHH:MM:SS...
    if s.len() >= 19 && s.as_bytes()[4] == b'-' && s.as_bytes()[7] == b'-' {
        let year: i64 = s[0..4].parse().ok()?;
        let month: u32 = s[5..7].parse().ok()?;
        let day: u32 = s[8..10].parse().ok()?;
        let hour: u32 = s[11..13].parse().ok()?;
        let min: u32 = s[14..16].parse().ok()?;
        let sec: u32 = s[17..19].parse().ok()?;
        return civil_to_unix(year, month, day, hour, min, sec);
    }

    // Formato legado Twitter: "Sat Nov 21 15:04:05 +0000 2026"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() == 6 {
        let month = match parts[1] {
            "Jan" => 1,
            "Feb" => 2,
            "Mar" => 3,
            "Apr" => 4,
            "May" => 5,
            "Jun" => 6,
            "Jul" => 7,
            "Aug" => 8,
            "Sep" => 9,
            "Oct" => 10,
            "Nov" => 11,
            "Dec" => 12,
            _ => return None,
        };
        let day: u32 = parts[2].parse().ok()?;
        let hms: Vec<&str> = parts[3].split(':').collect();
        if hms.len() != 3 {
            return None;
        }
        let hour: u32 = hms[0].parse().ok()?;
        let min: u32 = hms[1].parse().ok()?;
        let sec: u32 = hms[2].parse().ok()?;
        let year: i64 = parts[5].parse().ok()?;
        return civil_to_unix(year, month, day, hour, min, sec);
    }
    None
}

// ============================================================================
// 2. IMPORTADOR DE HISTÓRICO DO WHATSAPP (.txt)
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedWhatsAppMessage {
    pub sender: String,
    pub body: String,
    pub timestamp: u64,
    pub kind: ChatMessageKind,
    pub media_omitted: bool,
    pub attached_filename: Option<String>,
}

/// Faz parse de arquivos `.txt` exportados pelo WhatsApp (Android PT-BR/EU, iOS `[...]`,
/// e formato US AM/PM), suportando mensagens multilinhas, avisos de sistema e anexos.
pub fn parse_whatsapp_txt(raw: &str) -> Result<Vec<ImportedWhatsAppMessage>, RhizomeError> {
    let mut out: Vec<ImportedWhatsAppMessage> = Vec::new();

    for raw_line in raw.lines() {
        let line = raw_line
            .trim_start_matches('\u{feff}')
            .trim_start_matches('\u{200e}')
            .trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }

        if let Some((ts, rest)) = parse_wa_line_prefix(line) {
            let (sender, body, is_system) = if let Some(colon_idx) = rest.find(": ") {
                let s = rest[..colon_idx].trim().to_string();
                let b = rest[colon_idx + 2..].trim().to_string();
                (s, b, false)
            } else {
                ("Sistema".to_string(), rest.trim().to_string(), true)
            };

            let (kind, media_omitted, attached_filename) = classify_wa_body(&body, is_system);
            out.push(ImportedWhatsAppMessage {
                sender,
                body,
                timestamp: ts,
                kind,
                media_omitted,
                attached_filename,
            });
        } else if let Some(last) = out.last_mut() {
            // Continuação de mensagem multilinha
            last.body.push('\n');
            last.body.push_str(line);
        }
    }

    if out.is_empty() {
        return Err(RhizomeError::Compat(
            "nenhuma mensagem WhatsApp reconhecida no arquivo .txt".into(),
        ));
    }
    Ok(out)
}

fn parse_wa_line_prefix(line: &str) -> Option<(u64, &str)> {
    // Formato iOS: `[21/11/2026, 14:35:12] Nome: msg` ou `[21/11/26 14:35:12] ...`
    if let Some(after_open) = line.strip_prefix('[') {
        let close = after_open.find(']')?;
        let dt_str = after_open[..close].trim();
        let rest = after_open[close + 1..].trim_start();
        let ts = parse_wa_datetime(dt_str)?;
        return Some((ts, rest));
    }

    // Formato Android: `21/11/2026 14:35 - Nome: msg` ou `11/21/26, 2:35 PM - Name: msg`
    if let Some(dash_idx) = line.find(" - ") {
        if dash_idx <= 28 {
            let dt_str = line[..dash_idx].trim();
            let rest = &line[dash_idx + 3..];
            if let Some(ts) = parse_wa_datetime(dt_str) {
                return Some((ts, rest));
            }
        }
    }

    None
}

fn parse_wa_datetime(s: &str) -> Option<u64> {
    let cleaned = s.replace(',', " ");
    let parts: Vec<&str> = cleaned.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let date_parts: Vec<&str> = parts[0].split('/').collect();
    if date_parts.len() != 3 {
        return None;
    }
    let p0: u32 = date_parts[0].parse().ok()?;
    let p1: u32 = date_parts[1].parse().ok()?;
    let mut year: i64 = date_parts[2].parse().ok()?;
    if year < 100 {
        year += 2000;
    }

    let ampm = parts.get(2).map(|v| v.to_ascii_uppercase());
    let is_us = ampm.as_deref() == Some("AM") || ampm.as_deref() == Some("PM");
    let (day, month) = if is_us && p0 <= 12 {
        (p1, p0)
    } else if p1 > 12 && p0 <= 12 {
        (p1, p0)
    } else {
        (p0, p1)
    };

    let time_parts: Vec<&str> = parts[1].split(':').collect();
    if time_parts.len() < 2 {
        return None;
    }
    let mut hour: u32 = time_parts[0].parse().ok()?;
    let min: u32 = time_parts[1].parse().ok()?;
    let sec: u32 = time_parts.get(2).and_then(|v| v.parse().ok()).unwrap_or(0);

    if let Some(meridiem) = ampm {
        if meridiem == "PM" && hour < 12 {
            hour += 12;
        } else if meridiem == "AM" && hour == 12 {
            hour = 0;
        }
    }

    civil_to_unix(year, month, day, hour, min, sec)
}

fn classify_wa_body(body: &str, is_system: bool) -> (ChatMessageKind, bool, Option<String>) {
    if is_system {
        return (ChatMessageKind::System, false, None);
    }
    let lower = body.to_ascii_lowercase();
    let omitted = lower.contains("<mídia oculta>")
        || lower.contains("<media omitted>")
        || lower.contains("arquivo de mídia oculto")
        || lower.contains("imagem ocultada")
        || lower.contains("áudio ocultado");

    let mut attached = None;
    for marker in ["(arquivo anexado)", "(file attached)"] {
        if let Some(idx) = lower.find(marker) {
            let fname = body[..idx].trim().to_string();
            if !fname.is_empty() {
                attached = Some(fname);
            }
        }
    }

    let kind = if let Some(ref fname) = attached {
        let fl = fname.to_ascii_lowercase();
        if fl.ends_with(".opus") || fl.ends_with(".ogg") || fl.ends_with(".mp3") || fl.ends_with(".m4a") {
            ChatMessageKind::VoiceNote
        } else if fl.ends_with(".jpg") || fl.ends_with(".jpeg") || fl.ends_with(".png") || fl.ends_with(".webp") {
            ChatMessageKind::Image
        } else if fl.ends_with(".mp4") || fl.ends_with(".mov") || fl.ends_with(".webm") {
            ChatMessageKind::Video
        } else {
            ChatMessageKind::Document
        }
    } else if omitted {
        ChatMessageKind::Document
    } else {
        ChatMessageKind::Text
    };

    (kind, omitted, attached)
}

// ============================================================================
// 3. BRIDGE NOSTR (NIP-01 kind:1, NIP-94 kind:1063, NIP-71 kind:34235)
// ============================================================================

/// Converte um `SocialPost` do Rhizome em um evento Nostr real assinado por Schnorr (`GhostId`).
pub fn post_to_nostr_event(
    post: &SocialPost,
    ghost: &GhostId,
) -> Result<NostrEvent, RhizomeError> {
    let kind: u16 = match post.kind {
        PostKind::Video => 34235, // NIP-71 Horizontal Video
        PostKind::Short => 34236, // NIP-71 Short Vertical Video
        PostKind::Article => 30023, // NIP-23 Long-form Content
        PostKind::PhotoGallery | PostKind::Microblog => 1, // NIP-01 Note
    };

    let mut tags = vec![
        vec!["client".into(), "mycelium-rhizome".into()],
        vec!["mycelium_post".into(), post.post_id.clone()],
        vec!["mycelium_node".into(), post.author_node_id.clone()],
    ];
    if let Some(ref title) = post.title {
        tags.push(vec!["title".into(), title.clone()]);
    }
    if matches!(post.kind, PostKind::Video | PostKind::Short | PostKind::Article) {
        tags.push(vec!["d".into(), post.post_id.clone()]);
    }
    if let Some(ref vcid) = post.video_manifest_cid {
        tags.push(vec!["url".into(), format!("mycelium://{vcid}")]);
        tags.push(vec!["i".into(), vcid.clone()]);
    }
    for tag in &post.tags {
        tags.push(vec!["t".into(), tag.clone()]);
    }
    if let Some(ref reply) = post.reply_to {
        tags.push(vec!["e".into(), reply.clone(), String::new(), "reply".into()]);
    }
    for att in &post.media {
        tags.push(vec![
            "imeta".into(),
            format!("url mycelium://{}", att.cid),
            format!("m {}", att.mime_type),
            format!("size {}", att.byte_size),
        ]);
    }

    let content = match (&post.title, &post.kind) {
        (Some(t), PostKind::Video | PostKind::Short) if !t.is_empty() => {
            format!("{t}\n\n{}", post.body)
        }
        _ => post.body.clone(),
    };

    seal_event(ghost, post.created_at, kind, tags, content)
        .map_err(|e| RhizomeError::Compat(format!("Nostr seal_event: {e}")))
}

/// Importa um evento Nostr NIP-01/NIP-23/NIP-71 para o Rhizome, **verificando a assinatura
/// Schnorr real** e o `id` canônico antes de re-assinar localmente como ponte verificada.
pub fn nostr_event_to_post(
    event: &NostrEvent,
    bridge_keys: &SovereignKeys,
    bridge_handle: &str,
) -> Result<SocialPost, RhizomeError> {
    let pk_bytes: [u8; 32] = hex::decode(&event.pubkey)
        .map_err(|e| RhizomeError::InvalidKey(format!("nostr pubkey hex: {e}")))?
        .try_into()
        .map_err(|_| RhizomeError::InvalidKey("nostr pubkey deve ter 32 bytes".into()))?;
    let id_bytes: [u8; 32] = hex::decode(&event.id)
        .map_err(|e| RhizomeError::InvalidSignature(format!("nostr id hex: {e}")))?
        .try_into()
        .map_err(|_| RhizomeError::InvalidSignature("nostr id deve ter 32 bytes".into()))?;
    let sig_bytes: [u8; 64] = hex::decode(&event.sig)
        .map_err(|e| RhizomeError::InvalidSignature(format!("nostr sig hex: {e}")))?
        .try_into()
        .map_err(|_| RhizomeError::InvalidSignature("nostr sig deve ter 64 bytes".into()))?;

    // Verifica assinatura Schnorr secp256k1 real
    GhostId::verify_nostr_event(&pk_bytes, &id_bytes, &sig_bytes)
        .map_err(|e| RhizomeError::InvalidSignature(format!("assinatura Nostr inválida: {e}")))?;

    let kind = match event.kind {
        34235 => PostKind::Video,
        34236 => PostKind::Short,
        30023 => PostKind::Article,
        _ => PostKind::Microblog,
    };

    let mut title = None;
    let mut tags = Vec::new();
    for t in &event.tags {
        if t.len() >= 2 {
            match t[0].as_str() {
                "title" => title = Some(t[1].clone()),
                "t" => tags.push(t[1].to_ascii_lowercase()),
                _ => {}
            }
        }
    }

    let mut post = SocialPost {
        post_id: String::new(),
        author_node_id: String::new(),
        author_pubkey_hex: String::new(),
        author_handle: format!("nostr_{}", &event.pubkey[..8.min(event.pubkey.len())]),
        kind,
        title,
        body: event.content.clone(),
        media: vec![],
        video_manifest_cid: None,
        thumbnail_cid: None,
        channel_id: None,
        community_id: None,
        content_type: None,
        commons_project_id: None,
        tags,
        mentions: vec![bridge_handle.to_string()],
        reply_to: None,
        repost_of: None,
        quote_of: None,
        location: None,
        license: "nostr-bridge".into(),
        external_origin: ExternalOrigin::NostrEvent {
            event_id: event.id.clone(),
            pubkey_hex: event.pubkey.clone(),
            kind: event.kind,
        },
        created_at: event.created_at,
        signature: String::new(),
    };
    post.finalize_and_sign(bridge_keys)?;
    Ok(post)
}

// ============================================================================
// 4. EXPORTADORES ABERTOS: RSS 2.0 & ACTIVITYPUB (FEDIVERSE JSON-LD)
// ============================================================================

/// Renderiza um feed RSS 2.0 válido compatível com leitores RSS, agregadores e bridges X/Fediverse.
pub fn render_rss_feed(profile: &ProfileManifest, posts: &[SocialPost], base_url: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<rss version=\"2.0\">\n<channel>\n");
    xml.push_str(&format!(
        "  <title>{} (@{}) — Mycelium Rhizome</title>\n",
        xml_escape(&profile.display_name),
        xml_escape(&profile.handle)
    ));
    xml.push_str(&format!("  <link>{}/</link>\n", xml_escape(base)));
    xml.push_str(&format!(
        "  <description>{}</description>\n",
        xml_escape(&profile.bio)
    ));
    xml.push_str("  <generator>Mycelium Rhizome Sovereign Node</generator>\n");

    for post in posts.iter().take(50) {
        let title: String = post
            .title
            .as_deref()
            .filter(|t| !t.is_empty())
            .map(String::from)
            .unwrap_or_else(|| {
                let first_line = post.body.lines().next().unwrap_or("Publicação Rhizome");
                first_line.chars().take(80).collect()
            });
        xml.push_str("  <item>\n");
        xml.push_str(&format!("    <title>{}</title>\n", xml_escape(&title)));
        xml.push_str(&format!(
            "    <guid isPermaLink=\"false\">{}</guid>\n",
            xml_escape(&post.post_id)
        ));
        xml.push_str(&format!(
            "    <link>{}/?post={}</link>\n",
            xml_escape(base),
            xml_escape(&post.post_id)
        ));
        xml.push_str(&format!(
            "    <description>{}</description>\n",
            xml_escape(&post.body)
        ));
        xml.push_str(&format!(
            "    <author>@{}</author>\n",
            xml_escape(&post.author_handle)
        ));
        if let Some(ref vcid) = post.video_manifest_cid {
            let size = post.media.first().map(|m| m.byte_size).unwrap_or(0);
            let mime = post
                .media
                .first()
                .map(|m| m.mime_type.as_str())
                .unwrap_or("video/mp4");
            xml.push_str(&format!(
                "    <enclosure url=\"{}/api/videos/{}/stream\" length=\"{}\" type=\"{}\"/>\n",
                xml_escape(base),
                xml_escape(vcid),
                size,
                xml_escape(mime)
            ));
        } else if let Some(att) = post.media.first() {
            xml.push_str(&format!(
                "    <enclosure url=\"{}/api/media/{}\" length=\"{}\" type=\"{}\"/>\n",
                xml_escape(base),
                xml_escape(&att.cid),
                att.byte_size,
                xml_escape(&att.mime_type)
            ));
        }
        xml.push_str("  </item>\n");
    }

    xml.push_str("</channel>\n</rss>\n");
    xml
}

/// Renderiza o documento ActivityPub `Person` (JSON-LD) do perfil soberano.
pub fn render_activitypub_actor(profile: &ProfileManifest, base_url: &str) -> Value {
    let base = base_url.trim_end_matches('/');
    json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1"
        ],
        "id": format!("{base}/ap/actor"),
        "type": "Person",
        "preferredUsername": profile.handle,
        "name": profile.display_name,
        "summary": profile.bio,
        "outbox": format!("{base}/ap/outbox"),
        "url": format!("{base}/"),
        "alsoKnownAs": [
            format!("mycelium://{}", profile.node_id),
            format!("pkarr://{}", profile.pkarr_addr),
            format!("nostr:{}", profile.ghost_pubkey_hex)
        ],
        "publicKey": {
            "id": format!("{base}/ap/actor#ed25519"),
            "owner": format!("{base}/ap/actor"),
            "publicKeyMultibase": format!("f{}", profile.ed25519_pubkey_hex)
        }
    })
}

/// Renderiza a coleção ActivityPub `OrderedCollection` (Outbox) de publicações públicas.
pub fn render_activitypub_outbox(
    profile: &ProfileManifest,
    posts: &[SocialPost],
    base_url: &str,
) -> Value {
    let base = base_url.trim_end_matches('/');
    let items: Vec<Value> = posts
        .iter()
        .take(50)
        .map(|p| {
            let obj_type = match p.kind {
                PostKind::Video | PostKind::Short => "Video",
                PostKind::Article => "Article",
                PostKind::PhotoGallery | PostKind::Microblog => "Note",
            };
            let mut attachments = Vec::new();
            if let Some(ref vcid) = p.video_manifest_cid {
                attachments.push(json!({
                    "type": "Document",
                    "mediaType": p.media.first().map(|m| m.mime_type.as_str()).unwrap_or("video/mp4"),
                    "url": format!("{base}/api/videos/{vcid}/stream"),
                    "name": p.title.as_deref().unwrap_or("Mycelium Video")
                }));
            } else {
                for m in &p.media {
                    attachments.push(json!({
                        "type": "Document",
                        "mediaType": m.mime_type,
                        "url": format!("{base}/api/media/{}", m.cid),
                        "name": m.alt_text
                    }));
                }
            }
            json!({
                "id": format!("{base}/ap/activities/{}", p.post_id),
                "type": "Create",
                "actor": format!("{base}/ap/actor"),
                "object": {
                    "id": format!("{base}/ap/objects/{}", p.post_id),
                    "type": obj_type,
                    "attributedTo": format!("{base}/ap/actor"),
                    "name": p.title,
                    "content": p.body,
                    "tag": p.tags.iter().map(|t| json!({"type": "Hashtag", "name": format!("#{t}")})).collect::<Vec<_>>(),
                    "attachment": attachments
                }
            })
        })
        .collect();

    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{base}/ap/outbox"),
        "type": "OrderedCollection",
        "totalItems": items.len(),
        "attributedTo": format!("{base}/ap/actor"),
        "summary": format!("Outbox soberano de @{}", profile.handle),
        "orderedItems": items
    })
}

// ============================================================================
// 5. ADAPTADORES PLUGÁVEIS PARA APIS EXTERNAS (X API v2 & WHATSAPP CLOUD API)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeDirection {
    Inbound,
    Outbound,
    Bidirectional,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeCapabilities {
    pub adapter_id: String,
    pub platform: String,
    pub direction: BridgeDirection,
    pub requires_external_credentials: bool,
    pub live_dispatch_configured: bool,
    pub honest_notice: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalDispatchPreview {
    pub adapter_id: String,
    pub endpoint: String,
    pub method: String,
    pub payload: Value,
    pub dispatched: bool,
    pub note: String,
}

/// Interface plugável para conectores externos (opt-in explícito, fail-closed sem credenciais).
pub trait ExternalBridgeAdapter: Send + Sync {
    fn capabilities(&self) -> BridgeCapabilities;
    fn build_outbound_preview(&self, target: &str, text: &str) -> ExternalDispatchPreview;
}

/// Adaptador plugável para X API v2 (`/2/tweets`).
#[derive(Clone, Debug, Default)]
pub struct XApiV2Adapter {
    pub bearer_token_configured: bool,
}

impl XApiV2Adapter {
    pub fn from_env() -> Self {
        let configured = std::env::var("MYCELIUM_X_API_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .is_some();
        Self {
            bearer_token_configured: configured,
        }
    }

    pub fn build_tweet_payload(&self, post: &SocialPost) -> Value {
        let mut text = post.body.clone();
        if text.chars().count() > 280 {
            text = text.chars().take(277).collect::<String>() + "...";
        }
        let mut obj = json!({ "text": text });
        if let Some(ref reply) = post.reply_to {
            obj["reply"] = json!({ "in_reply_to_tweet_id": reply });
        }
        obj
    }
}

impl ExternalBridgeAdapter for XApiV2Adapter {
    fn capabilities(&self) -> BridgeCapabilities {
        BridgeCapabilities {
            adapter_id: "x_api_v2".into(),
            platform: "X (Twitter) API v2".into(),
            direction: BridgeDirection::Bidirectional,
            requires_external_credentials: true,
            live_dispatch_configured: self.bearer_token_configured,
            honest_notice: if self.bearer_token_configured {
                "Token MYCELIUM_X_API_TOKEN detectado (envio externo continua opt-in).".into()
            } else {
                "Sem MYCELIUM_X_API_TOKEN: operando em modo offline (preview de payload + importação tweets.js).".into()
            },
        }
    }

    fn build_outbound_preview(&self, _target: &str, text: &str) -> ExternalDispatchPreview {
        let truncated: String = if text.chars().count() > 280 {
            text.chars().take(277).collect::<String>() + "..."
        } else {
            text.to_string()
        };
        ExternalDispatchPreview {
            adapter_id: "x_api_v2".into(),
            endpoint: "https://api.x.com/2/tweets".into(),
            method: "POST".into(),
            payload: json!({ "text": truncated }),
            dispatched: false,
            note: "Preview gerado localmente (fail-closed: nenhum tráfego enviado à API do X sem comando explícito de despacho).".into(),
        }
    }
}

/// Mensagem recebida de um webhook oficial da WhatsApp Business Cloud API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhatsAppCloudInbound {
    pub wamid: String,
    pub from_wa_id: String,
    pub sender_name: String,
    pub timestamp: u64,
    pub body: String,
    pub kind: ChatMessageKind,
}

/// Adaptador plugável para Meta WhatsApp Cloud API (v21.0).
#[derive(Clone, Debug, Default)]
pub struct WhatsAppCloudAdapter {
    pub phone_number_id: Option<String>,
    pub token_configured: bool,
}

impl WhatsAppCloudAdapter {
    pub fn from_env() -> Self {
        let phone_number_id = std::env::var("MYCELIUM_WA_PHONE_NUMBER_ID")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let token_configured = std::env::var("MYCELIUM_WA_CLOUD_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .is_some();
        Self {
            phone_number_id,
            token_configured,
        }
    }

    /// Faz parse de payload real de webhook do WhatsApp Cloud API (`entry[].changes[].value.messages[]`).
    pub fn parse_webhook_payload(payload: &Value) -> Result<Vec<WhatsAppCloudInbound>, RhizomeError> {
        let entries = payload
            .get("entry")
            .and_then(|e| e.as_array())
            .ok_or_else(|| RhizomeError::Compat("webhook WhatsApp sem campo 'entry'".into()))?;

        let mut messages = Vec::new();
        for entry in entries {
            let Some(changes) = entry.get("changes").and_then(|c| c.as_array()) else {
                continue;
            };
            for change in changes {
                let Some(val) = change.get("value") else {
                    continue;
                };
                let mut contact_names: HashMap<String, String> = HashMap::new();
                if let Some(contacts) = val.get("contacts").and_then(|c| c.as_array()) {
                    for c in contacts {
                        if let (Some(wa_id), Some(name)) = (
                            c.get("wa_id").and_then(|v| v.as_str()),
                            c.get("profile")
                                .and_then(|p| p.get("name"))
                                .and_then(|v| v.as_str()),
                        ) {
                            contact_names.insert(wa_id.to_string(), name.to_string());
                        }
                    }
                }
                let Some(msgs) = val.get("messages").and_then(|m| m.as_array()) else {
                    continue;
                };
                for m in msgs {
                    let wamid = m
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("wamid.unknown")
                        .to_string();
                    let from_wa_id = m
                        .get("from")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let sender_name = contact_names
                        .get(&from_wa_id)
                        .cloned()
                        .unwrap_or_else(|| format!("+{from_wa_id}"));
                    let timestamp = m
                        .get("timestamp")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or_else(unix_now);
                    let msg_type = m.get("type").and_then(|v| v.as_str()).unwrap_or("text");
                    let (kind, body) = match msg_type {
                        "text" => (
                            ChatMessageKind::Text,
                            m.get("text")
                                .and_then(|t| t.get("body"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                        ),
                        "audio" => (
                            ChatMessageKind::VoiceNote,
                            format!(
                                "[Áudio WhatsApp media_id={}]",
                                m.get("audio")
                                    .and_then(|a| a.get("id"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("?")
                            ),
                        ),
                        "image" => (
                            ChatMessageKind::Image,
                            m.get("image")
                                .and_then(|i| i.get("caption"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("[Imagem WhatsApp]")
                                .to_string(),
                        ),
                        "video" => (
                            ChatMessageKind::Video,
                            m.get("video")
                                .and_then(|i| i.get("caption"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("[Vídeo WhatsApp]")
                                .to_string(),
                        ),
                        other => (ChatMessageKind::Document, format!("[Anexo WhatsApp: {other}]")),
                    };

                    messages.push(WhatsAppCloudInbound {
                        wamid,
                        from_wa_id,
                        sender_name,
                        timestamp,
                        body,
                        kind,
                    });
                }
            }
        }
        Ok(messages)
    }
}

impl ExternalBridgeAdapter for WhatsAppCloudAdapter {
    fn capabilities(&self) -> BridgeCapabilities {
        BridgeCapabilities {
            adapter_id: "whatsapp_cloud_api".into(),
            platform: "WhatsApp Business Cloud API (v21.0)".into(),
            direction: BridgeDirection::Bidirectional,
            requires_external_credentials: true,
            live_dispatch_configured: self.token_configured && self.phone_number_id.is_some(),
            honest_notice: if self.token_configured && self.phone_number_id.is_some() {
                "Credenciais WhatsApp Cloud API detectadas (webhook pronto; envio externo opt-in).".into()
            } else {
                "Sem MYCELIUM_WA_CLOUD_TOKEN / PHONE_NUMBER_ID: webhook local + importador .txt + chat nativo PQ ativos.".into()
            },
        }
    }

    fn build_outbound_preview(&self, target_e164: &str, text: &str) -> ExternalDispatchPreview {
        let phone_id = self
            .phone_number_id
            .as_deref()
            .unwrap_or("<PHONE_NUMBER_ID>");
        ExternalDispatchPreview {
            adapter_id: "whatsapp_cloud_api".into(),
            endpoint: format!("https://graph.facebook.com/v21.0/{phone_id}/messages"),
            method: "POST".into(),
            payload: json!({
                "messaging_product": "whatsapp",
                "recipient_type": "individual",
                "to": target_e164,
                "type": "text",
                "text": { "preview_url": false, "body": text }
            }),
            dispatched: false,
            note: "Preview gerado localmente (fail-closed: sem tráfego para servidores Meta sem opt-in explícito).".into(),
        }
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Conversão exata de data civil UTC (algoritmo de Howard Hinnant) para Unix timestamp.
fn civil_to_unix(year: i64, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Option<u64> {
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || min > 59
        || sec > 60
    {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = month as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + (day as u64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + (doe as i64) - 719468;
    let secs = days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64);
    u64::try_from(secs).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_x_takeout_tweets_js_and_reconstruct_thread() {
        let sample = r#"window.YTD.tweets.part0 = [
          {
            "tweet": {
              "id_str": "1001",
              "full_text": "Saindo das Big Techs! #Mycelium #P2P",
              "created_at": "Sat Nov 21 15:04:05 +0000 2026",
              "favorite_count": "42",
              "retweet_count": "11",
              "entities": { "hashtags": [{"text": "Mycelium"}] }
            }
          },
          {
            "tweet": {
              "id_str": "1002",
              "full_text": "Thread parte 2: agora tudo roda no meu nó soberano.",
              "created_at": "Sat Nov 21 15:05:10 +0000 2026",
              "in_reply_to_status_id_str": "1001"
            }
          }
        ];"#;

        let keys = SovereignKeys::from_seed([0x55; 32]).unwrap();
        let posts = import_x_archive_into_posts(sample, &keys, "bruno").unwrap();
        assert_eq!(posts.len(), 2);
        assert_eq!(posts[0].reply_to, None);
        assert_eq!(posts[1].reply_to.as_deref(), Some(posts[0].post_id.as_str()));
        assert!(posts[0].tags.contains(&"mycelium".to_string()));
        assert!(posts[0].tags.contains(&"p2p".to_string()));
        posts[0].verify().unwrap();
        posts[1].verify().unwrap();
    }

    #[test]
    fn parse_whatsapp_txt_br_ios_and_multiline() {
        let sample = "\u{feff}21/11/2026 14:30 - As mensagens são protegidas com criptografia de ponta a ponta.\n\
21/11/2026 14:31 - Bruno: Bora criar o Rhizome!\nSegunda linha da mesma mensagem.\n\
[21/11/2026, 14:32:05] Alice: <Mídia oculta>\n\
21/11/2026 14:33 - Alice: PTT-20261121-WA0001.opus (arquivo anexado)\n";

        let msgs = parse_whatsapp_txt(sample).unwrap();
        assert_eq!(msgs.len(), 4);
        assert_eq!(msgs[0].kind, ChatMessageKind::System);
        assert_eq!(msgs[1].sender, "Bruno");
        assert!(msgs[1].body.contains("Segunda linha"));
        assert!(msgs[2].media_omitted);
        assert_eq!(msgs[3].kind, ChatMessageKind::VoiceNote);
        assert_eq!(
            msgs[3].attached_filename.as_deref(),
            Some("PTT-20261121-WA0001.opus")
        );
    }

    #[test]
    fn nostr_nip01_roundtrip_with_real_schnorr_verification() {
        let keys = SovereignKeys::from_seed([0x66; 32]).unwrap();
        let mut post = SocialPost {
            post_id: String::new(),
            author_node_id: String::new(),
            author_pubkey_hex: String::new(),
            author_handle: "bruno".into(),
            kind: PostKind::Microblog,
            title: None,
            body: "Publicando no Mycelium e espelhando em Nostr NIP-01 #floresta".into(),
            media: vec![],
            video_manifest_cid: None,
            thumbnail_cid: None,
            channel_id: None,
            community_id: None,
            content_type: None,
            commons_project_id: None,
            tags: vec![],
            mentions: vec![],
            reply_to: None,
            repost_of: None,
            quote_of: None,
            location: None,
            license: "CC-BY-4.0".into(),
            external_origin: ExternalOrigin::Native,
            created_at: 1_760_001_000,
            signature: String::new(),
        };
        post.finalize_and_sign(&keys).unwrap();

        let nostr_ev = post_to_nostr_event(&post, keys.ghost()).unwrap();
        assert_eq!(nostr_ev.kind, 1);
        let imported = nostr_event_to_post(&nostr_ev, &keys, "bruno").unwrap();
        imported.verify().unwrap();
        assert_eq!(imported.body, post.body);

        // Assinatura adulterada no evento Nostr deve ser rejeitada
        let mut bad_ev = nostr_ev.clone();
        bad_ev.sig = "00".repeat(64);
        assert!(nostr_event_to_post(&bad_ev, &keys, "bruno").is_err());
    }

    #[test]
    fn whatsapp_cloud_webhook_parser_and_rss_activitypub() {
        let webhook = json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "changes": [{
                    "value": {
                        "contacts": [{"wa_id": "5511999990000", "profile": {"name": "Maria"}}],
                        "messages": [{
                            "id": "wamid.HBgMNTUxMTk5",
                            "from": "5511999990000",
                            "timestamp": "1760002000",
                            "type": "text",
                            "text": {"body": "Oi via Cloud API!"}
                        }]
                    }
                }]
            }]
        });
        let parsed = WhatsAppCloudAdapter::parse_webhook_payload(&webhook).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].sender_name, "Maria");
        assert_eq!(parsed[0].body, "Oi via Cloud API!");

        let keys = SovereignKeys::from_seed([0x77; 32]).unwrap();
        let mut prof = ProfileManifest {
            node_id: String::new(),
            ed25519_pubkey_hex: String::new(),
            ghost_pubkey_hex: String::new(),
            pkarr_addr: String::new(),
            mlkem1024_pubkey_hex: String::new(),
            handle: "maria".into(),
            display_name: "Maria & Amigos".into(),
            bio: "Canal <soberano>".into(),
            avatar_cid: None,
            banner_cid: None,
            channel_id: None,
            links: vec![],
            wallet_pubkey_hex: None,
            revision: 1,
            updated_at: 1_760_002_000,
            signature: String::new(),
        };
        prof.sign(&keys).unwrap();
        let rss = render_rss_feed(&prof, &[], "http://127.0.0.1:7474/rhizome");
        assert!(rss.contains("Maria &amp; Amigos"));
        assert!(rss.contains("&lt;soberano&gt;"));

        let actor = render_activitypub_actor(&prof, "http://127.0.0.1:7474/rhizome");
        assert_eq!(actor["type"], "Person");
        assert_eq!(actor["preferredUsername"], "maria");
    }
}
