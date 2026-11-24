//! # Omnibridge Social — Cofre Cifrado de Credenciais, Feeds & Contatos para 9 Redes
//!
//! Unifica acesso a canais, contatos e publicações de **Instagram, Facebook, WhatsApp,
//! X, Telegram, Reddit, YouTube, Twitch e TikTok** dentro do Mycelium Rhizome sem precisar
//! abrir os aplicativos externos, operando estritamente sob a **Doutrina da Honestidade**:
//!
//! - Credenciais do usuário (tokens OAuth2 / Graph API / Bot Token / Client-ID / handles)
//!   são persistidas exclusivamente cifradas em repouso com **XChaCha20-Poly1305** usando chave
//!   derivada da `Gland` local (`BLAKE3::derive_key`).
//! - Nunca burla CAPTCHAs, anti-bot gates ou o isolamento de sandbox do Android/SO.
//! - Sincronização ao vivo usa exclusivamente APIs oficiais autenticadas com as credenciais
//!   do próprio usuário, feeds públicos oficiais (YouTube Atom XML, Reddit `.json`), e
//!   importação local de arquivos/contatos oficiais (`.vcf` vCard, JSON do Telegram/Instagram/
//!   Facebook/TikTok, `tweets.js`/`following.js` do X, `.txt` do WhatsApp).
//! - Todo tráfego de saída pode ser roteado pelo proxy **VEIL Ω SOCKS5** (`socks5h://`)
//!   para blindagem de IP e prevenção de vazamento DNS.

use crate::RhizomeError;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const VAULT_KEY_CONTEXT: &str = "mycelium/rhizome/omnibridge-vault/v1";
const VAULT_AAD: &[u8] = b"mycelium-omnibridge-vault-v1";
const VAULT_MAGIC: &[u8; 8] = b"MYCOBV01";

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocialPlatform {
    Instagram,
    Facebook,
    Whatsapp,
    X,
    Telegram,
    Reddit,
    Youtube,
    Twitch,
    Tiktok,
}

impl SocialPlatform {
    pub const ALL: [SocialPlatform; 9] = [
        SocialPlatform::Instagram,
        SocialPlatform::Facebook,
        SocialPlatform::Whatsapp,
        SocialPlatform::X,
        SocialPlatform::Telegram,
        SocialPlatform::Reddit,
        SocialPlatform::Youtube,
        SocialPlatform::Twitch,
        SocialPlatform::Tiktok,
    ];

    pub fn from_str_loose(s: &str) -> Result<Self, RhizomeError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "instagram" | "ig" => Ok(Self::Instagram),
            "facebook" | "fb" => Ok(Self::Facebook),
            "whatsapp" | "wa" | "zap" => Ok(Self::Whatsapp),
            "x" | "twitter" => Ok(Self::X),
            "telegram" | "tg" => Ok(Self::Telegram),
            "reddit" => Ok(Self::Reddit),
            "youtube" | "yt" => Ok(Self::Youtube),
            "twitch" => Ok(Self::Twitch),
            "tiktok" | "tt" => Ok(Self::Tiktok),
            other => Err(RhizomeError::InvalidInput(format!(
                "plataforma desconhecida no Omnibridge: {other}"
            ))),
        }
    }

    pub fn slug(&self) -> &'static str {
        match self {
            Self::Instagram => "instagram",
            Self::Facebook => "facebook",
            Self::Whatsapp => "whatsapp",
            Self::X => "x",
            Self::Telegram => "telegram",
            Self::Reddit => "reddit",
            Self::Youtube => "youtube",
            Self::Twitch => "twitch",
            Self::Tiktok => "tiktok",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Instagram => "Instagram",
            Self::Facebook => "Facebook",
            Self::Whatsapp => "WhatsApp",
            Self::X => "X (Twitter)",
            Self::Telegram => "Telegram",
            Self::Reddit => "Reddit",
            Self::Youtube => "YouTube",
            Self::Twitch => "Twitch",
            Self::Tiktok => "TikTok",
        }
    }

    pub fn android_package(&self) -> &'static str {
        match self {
            Self::Instagram => "com.instagram.android",
            Self::Facebook => "com.facebook.katana",
            Self::Whatsapp => "com.whatsapp",
            Self::X => "com.twitter.android",
            Self::Telegram => "org.telegram.messenger",
            Self::Reddit => "com.reddit.frontpage",
            Self::Youtube => "com.google.android.youtube",
            Self::Twitch => "tv.twitch.android.app",
            Self::Tiktok => "com.zhiliaoapp.musically",
        }
    }

    pub fn deep_link_for(&self, handle_or_id: &str) -> String {
        let clean = handle_or_id.trim().trim_start_matches('@');
        match self {
            Self::Instagram => format!("instagram://user?username={clean}"),
            Self::Facebook => format!("https://www.facebook.com/{clean}"),
            Self::Whatsapp => format!("whatsapp://send?phone={clean}"),
            Self::X => format!("twitter://user?screen_name={clean}"),
            Self::Telegram => format!("tg://resolve?domain={clean}"),
            Self::Reddit => format!("https://www.reddit.com/r/{clean}"),
            Self::Youtube => {
                if clean.starts_with("UC") {
                    format!("https://www.youtube.com/channel/{clean}")
                } else {
                    format!("https://www.youtube.com/@{clean}")
                }
            }
            Self::Twitch => format!("https://www.twitch.tv/{clean}"),
            Self::Tiktok => format!("https://www.tiktok.com/@{clean}"),
        }
    }

    pub fn official_capabilities_notice(&self) -> &'static str {
        match self {
            Self::Instagram => "Meta Graph API (token do usuário) + import JSON oficial + deep-link Android",
            Self::Facebook => "Meta Graph API (páginas/feed com token) + import JSON oficial + deep-link Android",
            Self::Whatsapp => "WhatsApp Cloud API + webhook local + import .txt/.vcf (vCard) + deep-link Android",
            Self::X => "X API v2 (OAuth2 Bearer) + import tweets.js/following.js + deep-link Android",
            Self::Telegram => "Telegram Bot API (getUpdates/getChat/sendMessage) + import JSON Desktop + tg://",
            Self::Reddit => "Reddit OAuth API + feeds públicos oficiais /r/<sub>/hot.json (zero key) + deep-link",
            Self::Youtube => "YouTube Data API v3 + feeds oficiais Atom/RSS por channel_id (zero key) + deep-link",
            Self::Twitch => "Twitch Helix API (Client-Id + Bearer: canais seguidos & lives) + deep-link Android",
            Self::Tiktok => "TikTok Display API v2 (OAuth2 Bearer) + import user_data.json + deep-link Android",
        }
    }

    pub fn supports_zero_key_public_feed(&self) -> bool {
        matches!(self, Self::Youtube | Self::Reddit)
    }
}

/// Credencial local cifrada por plataforma (nunca exposta em texto claro nas APIs GET).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlatformCredentialRecord {
    pub platform: SocialPlatform,
    pub account_handle: String,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub extra_id: Option<String>,
    #[serde(default)]
    pub watched_channels: Vec<String>,
    #[serde(default)]
    pub route_via_veil: bool,
    pub updated_at: u64,
}

/// Visão segura (sem segredo em texto claro) retornada à UI/API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlatformCredentialView {
    pub platform: SocialPlatform,
    pub slug: String,
    pub display_name: String,
    pub android_package: String,
    pub connected: bool,
    pub has_token: bool,
    pub token_hint: Option<String>,
    pub account_handle: String,
    pub client_id_set: bool,
    pub extra_id: Option<String>,
    pub watched_channels: Vec<String>,
    pub route_via_veil: bool,
    pub supports_public_feed: bool,
    pub capabilities_notice: String,
    pub contacts_count: usize,
    pub channels_count: usize,
    pub items_count: usize,
    pub last_sync_at: Option<u64>,
    pub last_sync_note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalContact {
    pub id: String,
    pub platform: SocialPlatform,
    pub external_id: String,
    pub handle: String,
    pub display_name: String,
    #[serde(default)]
    pub phone_or_email: Option<String>,
    pub deep_link: String,
    pub android_package: String,
    pub source_mode: String,
    pub synced_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalChannel {
    pub id: String,
    pub platform: SocialPlatform,
    pub external_id: String,
    pub handle: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub is_live: bool,
    #[serde(default)]
    pub subscriber_or_viewer_count: Option<u64>,
    pub deep_link: String,
    pub android_package: String,
    pub source_mode: String,
    pub synced_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalFeedItem {
    pub id: String,
    pub platform: SocialPlatform,
    pub external_id: String,
    pub channel_id: String,
    pub author: String,
    pub title: String,
    pub body: String,
    pub url: String,
    pub published_at: String,
    pub source_mode: String,
    pub synced_at: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OmnibridgeVault {
    pub credentials: BTreeMap<SocialPlatform, PlatformCredentialRecord>,
}

impl OmnibridgeVault {
    fn derive_key(secret_material: &[u8]) -> [u8; 32] {
        blake3::derive_key(VAULT_KEY_CONTEXT, secret_material)
    }

    /// Cifra o cofre inteiro com XChaCha20-Poly1305 (`MAGIC || nonce(24) || ciphertext`).
    pub fn seal(&self, secret_material: &[u8]) -> Result<Vec<u8>, RhizomeError> {
        let key = Self::derive_key(secret_material);
        let cipher = XChaCha20Poly1305::new(&key.into());
        let mut nonce_bytes = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let plaintext = serde_json::to_vec(self)?;
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &plaintext,
                    aad: VAULT_AAD,
                },
            )
            .map_err(|_| RhizomeError::Crypto("falha ao cifrar cofre Omnibridge".into()))?;
        let mut out = Vec::with_capacity(VAULT_MAGIC.len() + 24 + ct.len());
        out.extend_from_slice(VAULT_MAGIC);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open(sealed: &[u8], secret_material: &[u8]) -> Result<Self, RhizomeError> {
        if sealed.len() < VAULT_MAGIC.len() + 24 + 16 || &sealed[..8] != VAULT_MAGIC {
            return Err(RhizomeError::Corrupted(
                "cabeçalho do cofre Omnibridge inválido".into(),
            ));
        }
        let key = Self::derive_key(secret_material);
        let cipher = XChaCha20Poly1305::new(&key.into());
        let nonce = XNonce::from_slice(&sealed[8..32]);
        let pt = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &sealed[32..],
                    aad: VAULT_AAD,
                },
            )
            .map_err(|_| {
                RhizomeError::Crypto("autenticação AEAD do cofre Omnibridge falhou".into())
            })?;
        Ok(serde_json::from_slice(&pt)?)
    }

    pub fn save_to_path(&self, path: &Path, secret_material: &[u8]) -> Result<(), RhizomeError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let sealed = self.seal(secret_material)?;
        std::fs::write(path, sealed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn load_from_path(path: &Path, secret_material: &[u8]) -> Result<Self, RhizomeError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let sealed = std::fs::read(path)?;
        Self::open(&sealed, secret_material)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OmnibridgeIndex {
    pub contacts: BTreeMap<String, ExternalContact>,
    pub channels: BTreeMap<String, ExternalChannel>,
    pub items: BTreeMap<String, ExternalFeedItem>,
    pub last_sync_at: BTreeMap<SocialPlatform, u64>,
    pub last_sync_note: BTreeMap<SocialPlatform, String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OmnibridgeSyncDelta {
    pub contacts: Vec<ExternalContact>,
    pub channels: Vec<ExternalChannel>,
    pub items: Vec<ExternalFeedItem>,
    pub note: String,
}

impl OmnibridgeIndex {
    pub fn apply_delta(&mut self, platform: SocialPlatform, delta: OmnibridgeSyncDelta) {
        let now = unix_now();
        for c in delta.contacts {
            self.contacts.insert(c.id.clone(), c);
        }
        for ch in delta.channels {
            self.channels.insert(ch.id.clone(), ch);
        }
        for it in delta.items {
            self.items.insert(it.id.clone(), it);
        }
        self.last_sync_at.insert(platform, now);
        self.last_sync_note.insert(platform, delta.note);
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), RhizomeError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn load_from_path(path: &Path) -> Result<Self, RhizomeError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }

    pub fn platform_views(&self, vault: &OmnibridgeVault) -> Vec<PlatformCredentialView> {
        SocialPlatform::ALL
            .iter()
            .map(|&p| {
                let cred = vault.credentials.get(&p);
                let token_hint = cred
                    .and_then(|c| c.access_token.as_deref())
                    .filter(|t| !t.trim().is_empty())
                    .map(|t| {
                        let chars: Vec<char> = t.chars().collect();
                        if chars.len() <= 8 {
                            "••••".to_string()
                        } else {
                            let head: String = chars[..4].iter().collect();
                            let tail: String = chars[chars.len() - 4..].iter().collect();
                            format!("{head}••••{tail}")
                        }
                    });
                let contacts_count = self.contacts.values().filter(|c| c.platform == p).count();
                let channels_count = self.channels.values().filter(|c| c.platform == p).count();
                let items_count = self.items.values().filter(|i| i.platform == p).count();
                PlatformCredentialView {
                    platform: p,
                    slug: p.slug().into(),
                    display_name: p.display_name().into(),
                    android_package: p.android_package().into(),
                    connected: cred.is_some(),
                    has_token: token_hint.is_some(),
                    token_hint,
                    account_handle: cred.map(|c| c.account_handle.clone()).unwrap_or_default(),
                    client_id_set: cred
                        .and_then(|c| c.client_id.as_deref())
                        .map(|s| !s.trim().is_empty())
                        .unwrap_or(false),
                    extra_id: cred.and_then(|c| c.extra_id.clone()),
                    watched_channels: cred
                        .map(|c| c.watched_channels.clone())
                        .unwrap_or_default(),
                    route_via_veil: cred.map(|c| c.route_via_veil).unwrap_or(false),
                    supports_public_feed: p.supports_zero_key_public_feed(),
                    capabilities_notice: p.official_capabilities_notice().into(),
                    contacts_count,
                    channels_count,
                    items_count,
                    last_sync_at: self.last_sync_at.get(&p).copied(),
                    last_sync_note: self.last_sync_note.get(&p).cloned(),
                }
            })
            .collect()
    }
}

fn make_id(platform: SocialPlatform, kind: &str, external_id: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(platform.slug().as_bytes());
    h.update(b":");
    h.update(kind.as_bytes());
    h.update(b":");
    h.update(external_id.as_bytes());
    format!("{}_{}_{}", platform.slug(), kind, &h.finalize().to_hex()[..16])
}

fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

fn extract_xml_tag(chunk: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let start_pos = chunk.find(&open)?;
    let after_open = &chunk[start_pos + open.len()..];
    let gt = after_open.find('>')?;
    let body = &after_open[gt + 1..];
    let end = body.find(&close)?;
    Some(xml_unescape(body[..end].trim()))
}

/// Parser puro-Rust para feeds oficiais YouTube Atom XML (`https://www.youtube.com/feeds/videos.xml?channel_id=...`).
pub fn parse_youtube_atom_feed(xml: &str, channel_hint: &str) -> OmnibridgeSyncDelta {
    let now = unix_now();
    let mut delta = OmnibridgeSyncDelta::default();
    let feed_head = xml.split("<entry>").next().unwrap_or(xml);
    let channel_title = extract_xml_tag(feed_head, "title")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| channel_hint.to_string());
    let channel_ext_id = extract_xml_tag(feed_head, "yt:channelId")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| channel_hint.to_string());

    let ch_id = make_id(SocialPlatform::Youtube, "ch", &channel_ext_id);
    delta.channels.push(ExternalChannel {
        id: ch_id.clone(),
        platform: SocialPlatform::Youtube,
        external_id: channel_ext_id.clone(),
        handle: channel_hint.to_string(),
        title: channel_title.clone(),
        description: "Feed Atom oficial YouTube".into(),
        is_live: false,
        subscriber_or_viewer_count: None,
        deep_link: SocialPlatform::Youtube.deep_link_for(&channel_ext_id),
        android_package: SocialPlatform::Youtube.android_package().into(),
        source_mode: "public_feed".into(),
        synced_at: now,
    });

    for entry in xml.split("<entry>").skip(1) {
        let block = entry.split("</entry>").next().unwrap_or(entry);
        let vid = extract_xml_tag(block, "yt:videoId")
            .or_else(|| extract_xml_tag(block, "id"))
            .unwrap_or_default();
        if vid.is_empty() {
            continue;
        }
        let title = extract_xml_tag(block, "title").unwrap_or_else(|| vid.clone());
        let author = extract_xml_tag(block, "name").unwrap_or_else(|| channel_title.clone());
        let published = extract_xml_tag(block, "published").unwrap_or_default();
        let desc = extract_xml_tag(block, "media:description").unwrap_or_default();
        let url = format!("https://www.youtube.com/watch?v={vid}");
        delta.items.push(ExternalFeedItem {
            id: make_id(SocialPlatform::Youtube, "item", &vid),
            platform: SocialPlatform::Youtube,
            external_id: vid,
            channel_id: ch_id.clone(),
            author,
            title,
            body: desc.chars().take(400).collect(),
            url,
            published_at: published,
            source_mode: "public_feed".into(),
            synced_at: now,
        });
    }
    delta.note = format!(
        "YouTube Atom sincronizado: canal '{}' ({} vídeos)",
        channel_title,
        delta.items.len()
    );
    delta
}

/// Parser puro-Rust para listagens oficiais JSON do Reddit (`/r/<sub>/hot.json` ou `oauth.reddit.com/subreddits/mine/subscriber`).
pub fn parse_reddit_listing_json(raw: &str, hint: &str) -> Result<OmnibridgeSyncDelta, RhizomeError> {
    let v: Value = serde_json::from_str(raw)?;
    let now = unix_now();
    let mut delta = OmnibridgeSyncDelta::default();
    let children = v
        .get("data")
        .and_then(|d| d.get("children"))
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();

    let clean_sub = hint.trim().trim_start_matches("r/").trim_start_matches('/');
    let default_ch = make_id(SocialPlatform::Reddit, "ch", clean_sub);
    if !clean_sub.is_empty() {
        delta.channels.push(ExternalChannel {
            id: default_ch.clone(),
            platform: SocialPlatform::Reddit,
            external_id: clean_sub.into(),
            handle: format!("r/{clean_sub}"),
            title: format!("r/{clean_sub}"),
            description: "Subreddit sincronizado via Reddit JSON".into(),
            is_live: false,
            subscriber_or_viewer_count: None,
            deep_link: SocialPlatform::Reddit.deep_link_for(clean_sub),
            android_package: SocialPlatform::Reddit.android_package().into(),
            source_mode: "public_feed".into(),
            synced_at: now,
        });
    }

    for child in children {
        let kind = child.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        let Some(d) = child.get("data") else { continue };
        if kind == "t5" {
            let name = d
                .get("display_name")
                .and_then(|x| x.as_str())
                .unwrap_or("reddit");
            let title = d.get("title").and_then(|x| x.as_str()).unwrap_or(name);
            let subs = d.get("subscribers").and_then(|x| x.as_u64());
            delta.channels.push(ExternalChannel {
                id: make_id(SocialPlatform::Reddit, "ch", name),
                platform: SocialPlatform::Reddit,
                external_id: name.into(),
                handle: format!("r/{name}"),
                title: title.into(),
                description: d
                    .get("public_description")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .chars()
                    .take(240)
                    .collect(),
                is_live: false,
                subscriber_or_viewer_count: subs,
                deep_link: SocialPlatform::Reddit.deep_link_for(name),
                android_package: SocialPlatform::Reddit.android_package().into(),
                source_mode: "official_api".into(),
                synced_at: now,
            });
        } else {
            let ext_id = d.get("id").and_then(|x| x.as_str()).unwrap_or("");
            if ext_id.is_empty() {
                continue;
            }
            let author = d.get("author").and_then(|x| x.as_str()).unwrap_or("anon");
            let sub = d
                .get("subreddit")
                .and_then(|x| x.as_str())
                .unwrap_or(clean_sub);
            let title = d.get("title").and_then(|x| x.as_str()).unwrap_or("");
            let body = d.get("selftext").and_then(|x| x.as_str()).unwrap_or("");
            let permalink = d.get("permalink").and_then(|x| x.as_str()).unwrap_or("");
            let url = if permalink.starts_with('/') {
                format!("https://www.reddit.com{permalink}")
            } else {
                d.get("url")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            let created = d
                .get("created_utc")
                .and_then(|x| x.as_f64())
                .map(|t| (t as u64).to_string())
                .unwrap_or_default();
            delta.items.push(ExternalFeedItem {
                id: make_id(SocialPlatform::Reddit, "item", ext_id),
                platform: SocialPlatform::Reddit,
                external_id: ext_id.into(),
                channel_id: make_id(SocialPlatform::Reddit, "ch", sub),
                author: format!("u/{author}"),
                title: title.into(),
                body: body.chars().take(400).collect(),
                url,
                published_at: created,
                source_mode: "public_feed".into(),
                synced_at: now,
            });
            if author != "[deleted]" && author != "AutoModerator" {
                delta.contacts.push(ExternalContact {
                    id: make_id(SocialPlatform::Reddit, "contact", author),
                    platform: SocialPlatform::Reddit,
                    external_id: author.into(),
                    handle: format!("u/{author}"),
                    display_name: author.into(),
                    phone_or_email: None,
                    deep_link: format!("https://www.reddit.com/user/{author}"),
                    android_package: SocialPlatform::Reddit.android_package().into(),
                    source_mode: "public_feed".into(),
                    synced_at: now,
                });
            }
        }
    }
    delta.note = format!(
        "Reddit sincronizado: {} canais, {} posts, {} contatos",
        delta.channels.len(),
        delta.items.len(),
        delta.contacts.len()
    );
    Ok(delta)
}

/// Parser puro-Rust para Twitch Helix API (`/helix/channels/followed` e `/helix/streams`).
pub fn parse_twitch_helix_json(raw: &str) -> Result<OmnibridgeSyncDelta, RhizomeError> {
    let v: Value = serde_json::from_str(raw)?;
    let now = unix_now();
    let mut delta = OmnibridgeSyncDelta::default();
    let arr = v
        .get("data")
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default();
    for entry in arr {
        let login = entry
            .get("broadcaster_login")
            .or_else(|| entry.get("user_login"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        if login.is_empty() {
            continue;
        }
        let name = entry
            .get("broadcaster_name")
            .or_else(|| entry.get("user_name"))
            .and_then(|x| x.as_str())
            .unwrap_or(login);
        let viewers = entry.get("viewer_count").and_then(|x| x.as_u64());
        let is_live = entry.get("type").and_then(|x| x.as_str()) == Some("live");
        let title = entry
            .get("title")
            .and_then(|x| x.as_str())
            .unwrap_or(name);
        let ch_id = make_id(SocialPlatform::Twitch, "ch", login);
        delta.channels.push(ExternalChannel {
            id: ch_id.clone(),
            platform: SocialPlatform::Twitch,
            external_id: login.into(),
            handle: format!("@{login}"),
            title: name.into(),
            description: entry
                .get("game_name")
                .and_then(|x| x.as_str())
                .unwrap_or("Canal Twitch")
                .into(),
            is_live,
            subscriber_or_viewer_count: viewers,
            deep_link: SocialPlatform::Twitch.deep_link_for(login),
            android_package: SocialPlatform::Twitch.android_package().into(),
            source_mode: "official_api".into(),
            synced_at: now,
        });
        if is_live || entry.get("title").is_some() {
            let sid = entry
                .get("id")
                .and_then(|x| x.as_str())
                .unwrap_or(login);
            delta.items.push(ExternalFeedItem {
                id: make_id(SocialPlatform::Twitch, "item", sid),
                platform: SocialPlatform::Twitch,
                external_id: sid.into(),
                channel_id: ch_id,
                author: name.into(),
                title: title.into(),
                body: format!(
                    "{} · {} espectadores",
                    entry.get("game_name").and_then(|x| x.as_str()).unwrap_or("Live"),
                    viewers.unwrap_or(0)
                ),
                url: SocialPlatform::Twitch.deep_link_for(login),
                published_at: entry
                    .get("started_at")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .into(),
                source_mode: "official_api".into(),
                synced_at: now,
            });
        }
    }
    delta.note = format!(
        "Twitch Helix sincronizado: {} canais, {} transmissões",
        delta.channels.len(),
        delta.items.len()
    );
    Ok(delta)
}

/// Parser puro-Rust para Telegram (Bot API `getUpdates` + export oficial Telegram Desktop JSON).
pub fn parse_telegram_json(raw: &str, source_mode: &str) -> Result<OmnibridgeSyncDelta, RhizomeError> {
    let v: Value = serde_json::from_str(raw)?;
    let now = unix_now();
    let mut delta = OmnibridgeSyncDelta::default();

    // Formato 1: Bot API getUpdates (`{ "ok": true, "result": [...] }`)
    if let Some(results) = v.get("result").and_then(|r| r.as_array()) {
        for upd in results {
            let msg = upd.get("message").or_else(|| upd.get("channel_post"));
            let Some(m) = msg else { continue };
            let chat = m.get("chat");
            let chat_id = chat
                .and_then(|c| c.get("id"))
                .map(|x| x.to_string())
                .unwrap_or_else(|| "tg-chat".into());
            let chat_title = chat
                .and_then(|c| {
                    c.get("title")
                        .or_else(|| c.get("username"))
                        .or_else(|| c.get("first_name"))
                })
                .and_then(|x| x.as_str())
                .unwrap_or("Telegram Chat");
            let chat_user = chat
                .and_then(|c| c.get("username"))
                .and_then(|x| x.as_str())
                .unwrap_or(&chat_id);
            let ch_id = make_id(SocialPlatform::Telegram, "ch", &chat_id);
            delta.channels.push(ExternalChannel {
                id: ch_id.clone(),
                platform: SocialPlatform::Telegram,
                external_id: chat_id.clone(),
                handle: format!("@{chat_user}"),
                title: chat_title.into(),
                description: chat
                    .and_then(|c| c.get("type"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("chat")
                    .into(),
                is_live: false,
                subscriber_or_viewer_count: None,
                deep_link: SocialPlatform::Telegram.deep_link_for(chat_user),
                android_package: SocialPlatform::Telegram.android_package().into(),
                source_mode: source_mode.into(),
                synced_at: now,
            });
            if let Some(from) = m.get("from") {
                let uid = from
                    .get("id")
                    .map(|x| x.to_string())
                    .unwrap_or_default();
                let uname = from
                    .get("username")
                    .and_then(|x| x.as_str())
                    .unwrap_or(&uid);
                let fname = from
                    .get("first_name")
                    .and_then(|x| x.as_str())
                    .unwrap_or(uname);
                if !uid.is_empty() {
                    delta.contacts.push(ExternalContact {
                        id: make_id(SocialPlatform::Telegram, "contact", &uid),
                        platform: SocialPlatform::Telegram,
                        external_id: uid.clone(),
                        handle: format!("@{uname}"),
                        display_name: fname.into(),
                        phone_or_email: None,
                        deep_link: SocialPlatform::Telegram.deep_link_for(uname),
                        android_package: SocialPlatform::Telegram.android_package().into(),
                        source_mode: source_mode.into(),
                        synced_at: now,
                    });
                }
            }
            if let Some(text) = m.get("text").and_then(|x| x.as_str()) {
                let mid = m
                    .get("message_id")
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| now.to_string());
                delta.items.push(ExternalFeedItem {
                    id: make_id(SocialPlatform::Telegram, "item", &format!("{chat_id}:{mid}")),
                    platform: SocialPlatform::Telegram,
                    external_id: mid,
                    channel_id: ch_id,
                    author: chat_title.into(),
                    title: format!("Telegram · {chat_title}"),
                    body: text.chars().take(400).collect(),
                    url: SocialPlatform::Telegram.deep_link_for(chat_user),
                    published_at: m
                        .get("date")
                        .and_then(|x| x.as_u64())
                        .map(|t| t.to_string())
                        .unwrap_or_default(),
                    source_mode: source_mode.into(),
                    synced_at: now,
                });
            }
        }
    }

    // Formato 2: Export oficial Telegram Desktop (`contacts.list[]` e `chats.list[]`)
    if let Some(contacts) = v
        .get("contacts")
        .and_then(|c| c.get("list"))
        .and_then(|l| l.as_array())
    {
        for c in contacts {
            let first = c.get("first_name").and_then(|x| x.as_str()).unwrap_or("");
            let last = c.get("last_name").and_then(|x| x.as_str()).unwrap_or("");
            let phone = c.get("phone_number").and_then(|x| x.as_str()).unwrap_or("");
            let name = format!("{first} {last}").trim().to_string();
            let ext = if !phone.is_empty() { phone } else { &name };
            if ext.is_empty() {
                continue;
            }
            delta.contacts.push(ExternalContact {
                id: make_id(SocialPlatform::Telegram, "contact", ext),
                platform: SocialPlatform::Telegram,
                external_id: ext.into(),
                handle: ext.into(),
                display_name: if name.is_empty() { ext.into() } else { name.clone() },
                phone_or_email: if phone.is_empty() { None } else { Some(phone.into()) },
                deep_link: SocialPlatform::Telegram.deep_link_for(ext),
                android_package: SocialPlatform::Telegram.android_package().into(),
                source_mode: "local_import".into(),
                synced_at: now,
            });
        }
    }
    if let Some(chats) = v
        .get("chats")
        .and_then(|c| c.get("list"))
        .and_then(|l| l.as_array())
    {
        for ch in chats {
            let cid = ch.get("id").map(|x| x.to_string()).unwrap_or_default();
            let name = ch.get("name").and_then(|x| x.as_str()).unwrap_or(&cid);
            if cid.is_empty() {
                continue;
            }
            delta.channels.push(ExternalChannel {
                id: make_id(SocialPlatform::Telegram, "ch", &cid),
                platform: SocialPlatform::Telegram,
                external_id: cid.clone(),
                handle: name.into(),
                title: name.into(),
                description: ch
                    .get("type")
                    .and_then(|x| x.as_str())
                    .unwrap_or("chat")
                    .into(),
                is_live: false,
                subscriber_or_viewer_count: None,
                deep_link: SocialPlatform::Telegram.deep_link_for(name),
                android_package: SocialPlatform::Telegram.android_package().into(),
                source_mode: "local_import".into(),
                synced_at: now,
            });
        }
    }

    delta.note = format!(
        "Telegram sincronizado: {} canais, {} contatos, {} mensagens",
        delta.channels.len(),
        delta.contacts.len(),
        delta.items.len()
    );
    Ok(delta)
}

/// Parser puro-Rust para Meta Graph API e exports oficiais JSON de Instagram e Facebook.
pub fn parse_meta_json(
    platform: SocialPlatform,
    raw: &str,
    source_mode: &str,
) -> Result<OmnibridgeSyncDelta, RhizomeError> {
    let v: Value = serde_json::from_str(raw)?;
    let now = unix_now();
    let mut delta = OmnibridgeSyncDelta::default();

    // Graph API `{ "data": [...] }`
    if let Some(arr) = v.get("data").and_then(|d| d.as_array()) {
        for item in arr {
            let id = item
                .get("id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            if let Some(name) = item.get("name").and_then(|x| x.as_str()) {
                delta.channels.push(ExternalChannel {
                    id: make_id(platform, "ch", &id),
                    platform,
                    external_id: id.clone(),
                    handle: name.into(),
                    title: name.into(),
                    description: item
                        .get("category")
                        .and_then(|x| x.as_str())
                        .unwrap_or("Página / Conta Meta")
                        .into(),
                    is_live: false,
                    subscriber_or_viewer_count: None,
                    deep_link: platform.deep_link_for(name),
                    android_package: platform.android_package().into(),
                    source_mode: source_mode.into(),
                    synced_at: now,
                });
            }
            let body = item
                .get("caption")
                .or_else(|| item.get("message"))
                .or_else(|| item.get("story"))
                .and_then(|x| x.as_str())
                .unwrap_or("");
            if !body.is_empty() || item.get("permalink").is_some() {
                let url = item
                    .get("permalink")
                    .or_else(|| item.get("media_url"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                delta.items.push(ExternalFeedItem {
                    id: make_id(platform, "item", &id),
                    platform,
                    external_id: id.clone(),
                    channel_id: make_id(platform, "ch", "me"),
                    author: item
                        .get("username")
                        .and_then(|x| x.as_str())
                        .unwrap_or(platform.display_name())
                        .into(),
                    title: format!("{} · {}", platform.display_name(), &id[..id.len().min(12)]),
                    body: body.chars().take(400).collect(),
                    url,
                    published_at: item
                        .get("timestamp")
                        .or_else(|| item.get("created_time"))
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .into(),
                    source_mode: source_mode.into(),
                    synced_at: now,
                });
            }
        }
    }

    // Export oficial Instagram (`relationships_following[]`)
    if let Some(following) = v
        .get("relationships_following")
        .and_then(|f| f.as_array())
    {
        for entry in following {
            if let Some(list) = entry.get("string_list_data").and_then(|s| s.as_array()) {
                for s in list {
                    if let Some(val) = s.get("value").and_then(|x| x.as_str()) {
                        delta.contacts.push(ExternalContact {
                            id: make_id(platform, "contact", val),
                            platform,
                            external_id: val.into(),
                            handle: format!("@{val}"),
                            display_name: val.into(),
                            phone_or_email: None,
                            deep_link: platform.deep_link_for(val),
                            android_package: platform.android_package().into(),
                            source_mode: "local_import".into(),
                            synced_at: now,
                        });
                    }
                }
            }
        }
    }

    // Export oficial Facebook (`friends_v2[]`)
    if let Some(friends) = v.get("friends_v2").and_then(|f| f.as_array()) {
        for f in friends {
            if let Some(name) = f.get("name").and_then(|x| x.as_str()) {
                delta.contacts.push(ExternalContact {
                    id: make_id(platform, "contact", name),
                    platform,
                    external_id: name.into(),
                    handle: name.into(),
                    display_name: name.into(),
                    phone_or_email: None,
                    deep_link: platform.deep_link_for(name),
                    android_package: platform.android_package().into(),
                    source_mode: "local_import".into(),
                    synced_at: now,
                });
            }
        }
    }

    delta.note = format!(
        "{} sincronizado: {} canais, {} contatos, {} itens",
        platform.display_name(),
        delta.channels.len(),
        delta.contacts.len(),
        delta.items.len()
    );
    Ok(delta)
}

/// Parser puro-Rust para TikTok Display API v2 e export oficial `user_data.json`.
pub fn parse_tiktok_json(raw: &str, source_mode: &str) -> Result<OmnibridgeSyncDelta, RhizomeError> {
    let v: Value = serde_json::from_str(raw)?;
    let now = unix_now();
    let mut delta = OmnibridgeSyncDelta::default();

    // Display API v2 (`data.videos[]`)
    if let Some(videos) = v
        .get("data")
        .and_then(|d| d.get("videos"))
        .and_then(|arr| arr.as_array())
    {
        for vid in videos {
            let id = vid.get("id").and_then(|x| x.as_str()).unwrap_or("");
            if id.is_empty() {
                continue;
            }
            let title = vid
                .get("title")
                .or_else(|| vid.get("video_description"))
                .and_then(|x| x.as_str())
                .unwrap_or("Vídeo TikTok");
            delta.items.push(ExternalFeedItem {
                id: make_id(SocialPlatform::Tiktok, "item", id),
                platform: SocialPlatform::Tiktok,
                external_id: id.into(),
                channel_id: make_id(SocialPlatform::Tiktok, "ch", "me"),
                author: "TikTok".into(),
                title: title.into(),
                body: vid
                    .get("video_description")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .chars()
                    .take(400)
                    .collect(),
                url: vid
                    .get("share_url")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .into(),
                published_at: vid
                    .get("create_time")
                    .and_then(|x| x.as_u64())
                    .map(|t| t.to_string())
                    .unwrap_or_default(),
                source_mode: source_mode.into(),
                synced_at: now,
            });
        }
    }

    // Export oficial `user_data.json` (`Activity.Following List.Following[]`)
    if let Some(following) = v
        .get("Activity")
        .and_then(|a| a.get("Following List"))
        .and_then(|fl| fl.get("Following"))
        .and_then(|arr| arr.as_array())
    {
        for f in following {
            if let Some(user) = f.get("UserName").and_then(|x| x.as_str()) {
                delta.contacts.push(ExternalContact {
                    id: make_id(SocialPlatform::Tiktok, "contact", user),
                    platform: SocialPlatform::Tiktok,
                    external_id: user.into(),
                    handle: format!("@{user}"),
                    display_name: user.into(),
                    phone_or_email: None,
                    deep_link: SocialPlatform::Tiktok.deep_link_for(user),
                    android_package: SocialPlatform::Tiktok.android_package().into(),
                    source_mode: "local_import".into(),
                    synced_at: now,
                });
            }
        }
    }

    delta.note = format!(
        "TikTok sincronizado: {} contatos, {} vídeos",
        delta.contacts.len(),
        delta.items.len()
    );
    Ok(delta)
}

/// Parser puro-Rust para X API v2 (`data[]`) e `following.js`.
pub fn parse_x_json(raw: &str, source_mode: &str) -> Result<OmnibridgeSyncDelta, RhizomeError> {
    let trimmed = raw.trim();
    let json_slice = if let Some(idx) = trimmed.find('[') {
        if trimmed.starts_with("window.YTD.") {
            &trimmed[idx..]
        } else {
            trimmed
        }
    } else {
        trimmed
    };
    let v: Value = serde_json::from_str(json_slice)?;
    let now = unix_now();
    let mut delta = OmnibridgeSyncDelta::default();

    if let Some(arr) = v.get("data").and_then(|d| d.as_array()) {
        for entry in arr {
            let id = entry.get("id").and_then(|x| x.as_str()).unwrap_or("");
            if id.is_empty() {
                continue;
            }
            if let Some(username) = entry.get("username").and_then(|x| x.as_str()) {
                let name = entry.get("name").and_then(|x| x.as_str()).unwrap_or(username);
                delta.contacts.push(ExternalContact {
                    id: make_id(SocialPlatform::X, "contact", id),
                    platform: SocialPlatform::X,
                    external_id: id.into(),
                    handle: format!("@{username}"),
                    display_name: name.into(),
                    phone_or_email: None,
                    deep_link: SocialPlatform::X.deep_link_for(username),
                    android_package: SocialPlatform::X.android_package().into(),
                    source_mode: source_mode.into(),
                    synced_at: now,
                });
            } else if let Some(text) = entry.get("text").and_then(|x| x.as_str()) {
                delta.items.push(ExternalFeedItem {
                    id: make_id(SocialPlatform::X, "item", id),
                    platform: SocialPlatform::X,
                    external_id: id.into(),
                    channel_id: make_id(SocialPlatform::X, "ch", "timeline"),
                    author: entry
                        .get("author_id")
                        .and_then(|x| x.as_str())
                        .unwrap_or("X")
                        .into(),
                    title: format!("X · {id}"),
                    body: text.chars().take(400).collect(),
                    url: format!("https://x.com/i/web/status/{id}"),
                    published_at: entry
                        .get("created_at")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .into(),
                    source_mode: source_mode.into(),
                    synced_at: now,
                });
            }
        }
    } else if let Some(arr) = v.as_array() {
        for entry in arr {
            if let Some(acc_id) = entry
                .get("following")
                .and_then(|f| f.get("accountId"))
                .and_then(|x| x.as_str())
            {
                let link = entry
                    .get("following")
                    .and_then(|f| f.get("userLink"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("");
                delta.contacts.push(ExternalContact {
                    id: make_id(SocialPlatform::X, "contact", acc_id),
                    platform: SocialPlatform::X,
                    external_id: acc_id.into(),
                    handle: format!("id:{acc_id}"),
                    display_name: format!("Conta X {acc_id}"),
                    phone_or_email: None,
                    deep_link: if link.is_empty() {
                        SocialPlatform::X.deep_link_for(acc_id)
                    } else {
                        link.into()
                    },
                    android_package: SocialPlatform::X.android_package().into(),
                    source_mode: "local_import".into(),
                    synced_at: now,
                });
            }
        }
    }

    delta.note = format!(
        "X sincronizado: {} contatos, {} posts",
        delta.contacts.len(),
        delta.items.len()
    );
    Ok(delta)
}

/// Parser universal de contatos vCard (`.vcf`) para WhatsApp, Telegram e agenda local.
pub fn parse_vcard_contacts(vcf: &str, platform: SocialPlatform) -> OmnibridgeSyncDelta {
    let now = unix_now();
    let mut delta = OmnibridgeSyncDelta::default();
    let mut fn_name = String::new();
    let mut tel = String::new();
    let mut email = String::new();
    let mut in_card = false;

    for raw_line in vcf.lines() {
        let line = raw_line.trim();
        if line.eq_ignore_ascii_case("BEGIN:VCARD") {
            in_card = true;
            fn_name.clear();
            tel.clear();
            email.clear();
        } else if line.eq_ignore_ascii_case("END:VCARD") {
            if in_card && (!fn_name.is_empty() || !tel.is_empty()) {
                let clean_phone: String = tel
                    .chars()
                    .filter(|c| c.is_ascii_digit() || *c == '+')
                    .collect();
                let ext_id = if !clean_phone.is_empty() {
                    clean_phone.clone()
                } else {
                    fn_name.clone()
                };
                let phone_or_email = if !clean_phone.is_empty() {
                    Some(clean_phone.clone())
                } else if !email.is_empty() {
                    Some(email.clone())
                } else {
                    None
                };
                delta.contacts.push(ExternalContact {
                    id: make_id(platform, "contact", &ext_id),
                    platform,
                    external_id: ext_id.clone(),
                    handle: ext_id.clone(),
                    display_name: if fn_name.is_empty() {
                        ext_id.clone()
                    } else {
                        fn_name.clone()
                    },
                    phone_or_email,
                    deep_link: platform.deep_link_for(&ext_id),
                    android_package: platform.android_package().into(),
                    source_mode: "local_import".into(),
                    synced_at: now,
                });
            }
            in_card = false;
        } else if in_card {
            if let Some(val) = line.strip_prefix("FN:").or_else(|| {
                line.split_once(':').and_then(|(k, v)| {
                    if k.to_ascii_uppercase().starts_with("FN;") {
                        Some(v)
                    } else {
                        None
                    }
                })
            }) {
                fn_name = val.trim().to_string();
            } else if let Some((k, v)) = line.split_once(':') {
                let ku = k.to_ascii_uppercase();
                if ku == "TEL" || ku.starts_with("TEL;") {
                    if tel.is_empty() {
                        tel = v.trim().to_string();
                    }
                } else if (ku == "EMAIL" || ku.starts_with("EMAIL;")) && email.is_empty() {
                    email = v.trim().to_string();
                }
            }
        }
    }
    delta.note = format!(
        "vCard importado para {}: {} contatos",
        platform.display_name(),
        delta.contacts.len()
    );
    delta
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_vault_roundtrip_and_tamper_rejection() {
        let mut vault = OmnibridgeVault::default();
        vault.credentials.insert(
            SocialPlatform::Twitch,
            PlatformCredentialRecord {
                platform: SocialPlatform::Twitch,
                account_handle: "bruno_dev".into(),
                access_token: Some("oauth_secret_token_123456".into()),
                client_id: Some("client_abc".into()),
                extra_id: None,
                watched_channels: vec!["rustlang".into()],
                route_via_veil: true,
                updated_at: 1_700_000_000,
            },
        );
        let secret = [42u8; 32];
        let sealed = vault.seal(&secret).unwrap();
        // Segredo não aparece em texto claro no arquivo cifrado
        assert!(!String::from_utf8_lossy(&sealed).contains("oauth_secret_token_123456"));

        let opened = OmnibridgeVault::open(&sealed, &secret).unwrap();
        assert_eq!(
            opened.credentials[&SocialPlatform::Twitch].access_token.as_deref(),
            Some("oauth_secret_token_123456")
        );

        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(OmnibridgeVault::open(&tampered, &secret).is_err());
        assert!(OmnibridgeVault::open(&sealed, &[99u8; 32]).is_err());
    }

    #[test]
    fn parses_youtube_reddit_twitch_telegram_meta_tiktok_x_and_vcard() {
        let yt_xml = r#"<feed><yt:channelId>UC12345</yt:channelId><title>Canal Soberano</title>
            <entry><yt:videoId>vid01</yt:videoId><title>Rust &amp; P2P</title><author><name>Bruno</name></author><published>2026-01-01T00:00:00Z</published></entry></feed>"#;
        let yt = parse_youtube_atom_feed(yt_xml, "UC12345");
        assert_eq!(yt.channels.len(), 1);
        assert_eq!(yt.items.len(), 1);
        assert_eq!(yt.items[0].title, "Rust & P2P");

        let reddit_json = r#"{"data":{"children":[{"kind":"t3","data":{"id":"abc1","author":"ferris","subreddit":"rust","title":"Zero Google","selftext":"ok","permalink":"/r/rust/comments/abc1/zero_google/","created_utc":1700000000}}]}}"#;
        let rd = parse_reddit_listing_json(reddit_json, "rust").unwrap();
        assert_eq!(rd.items.len(), 1);
        assert_eq!(rd.contacts.len(), 1);

        let twitch_json = r#"{"data":[{"id":"s1","user_login":"mycelium_live","user_name":"MyceliumLive","type":"live","title":"Coding Rust","game_name":"Software","viewer_count":42}]}"#;
        let tw = parse_twitch_helix_json(twitch_json).unwrap();
        assert_eq!(tw.channels.len(), 1);
        assert!(tw.channels[0].is_live);
        assert_eq!(tw.items.len(), 1);

        let tg_json = r#"{"ok":true,"result":[{"message":{"message_id":7,"date":1700000000,"text":"Oi malha","chat":{"id":999,"title":"Grupo Dev","username":"grupodev","type":"supergroup"},"from":{"id":55,"username":"alice","first_name":"Alice"}}}]}"#;
        let tg = parse_telegram_json(tg_json, "official_api").unwrap();
        assert_eq!(tg.channels.len(), 1);
        assert_eq!(tg.contacts.len(), 1);
        assert_eq!(tg.items.len(), 1);

        let ig_json = r#"{"relationships_following":[{"string_list_data":[{"value":"criador_ig"}]}]}"#;
        let ig = parse_meta_json(SocialPlatform::Instagram, ig_json, "local_import").unwrap();
        assert_eq!(ig.contacts.len(), 1);
        assert_eq!(ig.contacts[0].handle, "@criador_ig");

        let tt_json = r#"{"Activity":{"Following List":{"Following":[{"UserName":"criador_tt"}]}}}"#;
        let tt = parse_tiktok_json(tt_json, "local_import").unwrap();
        assert_eq!(tt.contacts.len(), 1);

        let x_js = r#"window.YTD.following.part0 = [{"following":{"accountId":"123456","userLink":"https://x.com/intent/user?user_id=123456"}}]"#;
        let x = parse_x_json(x_js, "local_import").unwrap();
        assert_eq!(x.contacts.len(), 1);

        let vcf = "BEGIN:VCARD\nVERSION:3.0\nFN:Maria Silva\nTEL;TYPE=CELL:+55 11 99999-0000\nEND:VCARD\n";
        let wa = parse_vcard_contacts(vcf, SocialPlatform::Whatsapp);
        assert_eq!(wa.contacts.len(), 1);
        assert_eq!(wa.contacts[0].phone_or_email.as_deref(), Some("+5511999990000"));
    }
}
