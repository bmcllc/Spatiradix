//! Registro anônimo: o que vai dentro do pacote Pkarr de um nó único.
//!
//! Camadas, de fora para dentro:
//! 1. chave pública = chave **cegada da época** (`blind`), não a identidade;
//! 2. TXT `_myc` com `nonce ‖ XChaCha20-Poly1305(conteúdo)`, AAD = chave da
//!    época ‖ timestamp (impede transplantar o cifrado para outro pacote);
//! 3. conteúdo acolchoado a tamanho fixo (`PADDED_LEN`): todos os registros
//!    têm o mesmo tamanho na rede, independentemente de quantos endpoints;
//! 4. só endpoints que **não revelam IP** são aceitos, validados ao publicar
//!    *e* ao resolver (fail-closed nos dois lados).

use crate::blind::{blinded_public, epoch_of, MasterIdentity, EPOCH_SECS};
use crate::dns::{self, TxtRecord};
use crate::packet::SignedPacket;
use crate::{zbase32, PkarrError};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Tamanho fixo do texto claro (2 bytes de comprimento + JSON + zeros).
pub const PADDED_LEN: usize = 700;
/// Tolerância de relógio para timestamps no futuro.
pub const MAX_CLOCK_SKEW_SECS: u64 = 600;
pub const RECORD_LABEL: &str = "_myc";
const RECORD_TTL: u32 = 300;
const ADDRESS_PREFIX: &str = "myc1";
const CONTENT_SALT: &[u8] = b"mycelium-pkarr/content/v1";
const MAX_ENDPOINTS: usize = 8;
const MAX_RELAYS: usize = 6;

/// Como alcançar o serviço **sem** expor o IP do nó.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum Endpoint {
    /// Rendezvous Nostr: o nó só faz conexões de saída (via VEIL) até os relays.
    Nostr { pubkey: String, relays: Vec<String> },
    /// Descritor de entrada de circuito VEIL (hex, opaco para este crate).
    Veil { descriptor: String },
    /// Serviço onion v3 do Tor (`<56>.onion[:porta]`).
    Onion { addr: String },
    /// Conteúdo público no Spore Bank (ContentId blake3, 64 hex).
    Plot { content_id: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnonRecord {
    pub endpoints: Vec<Endpoint>,
    /// Unix secs após o qual o registro não deve mais ser usado.
    pub not_after: u64,
}

/// O que um cliente precisa para achar e ler o serviço: a chave mestra
/// pública e, opcionalmente, um segredo de acesso (modo privado).
#[derive(Clone)]
pub struct Capability {
    pub master_public: [u8; 32],
    pub access_secret: Option<Zeroizing<[u8; 32]>>,
}

impl Capability {
    /// `myc1<z32(chave)>` ou `myc1<z32(chave)>.<z32(segredo)>`.
    pub fn to_address(&self) -> String {
        let mut s = format!("{ADDRESS_PREFIX}{}", zbase32::encode(&self.master_public));
        if let Some(secret) = &self.access_secret {
            s.push('.');
            s.push_str(&zbase32::encode(secret.as_ref()));
        }
        s
    }

    pub fn from_address(addr: &str) -> Result<Self, PkarrError> {
        let rest = addr
            .trim()
            .strip_prefix(ADDRESS_PREFIX)
            .ok_or(PkarrError::Malformed("endereço sem prefixo myc1"))?;
        let (key, secret) = match rest.split_once('.') {
            Some((k, s)) => (k, Some(s)),
            None => (rest, None),
        };
        let master_public =
            zbase32::decode::<32>(key).ok_or(PkarrError::Malformed("chave do endereço"))?;
        // valida já que é um ponto utilizável
        blinded_public(&master_public, 0)?;
        let access_secret = match secret {
            Some(s) => Some(Zeroizing::new(
                zbase32::decode::<32>(s).ok_or(PkarrError::Malformed("segredo do endereço"))?,
            )),
            None => None,
        };
        Ok(Self {
            master_public,
            access_secret,
        })
    }

    /// Chaves cegadas a consultar agora: época atual e a anterior (cobre a
    /// virada de época e relógios ligeiramente adiantados do publicador).
    pub fn lookup_keys(&self, now_secs: u64) -> Result<Vec<[u8; 32]>, PkarrError> {
        let e = epoch_of(now_secs);
        let mut keys = vec![blinded_public(&self.master_public, e)?];
        if e > 0 {
            keys.push(blinded_public(&self.master_public, e - 1)?);
        }
        Ok(keys)
    }

    fn content_key(&self, epoch: u64) -> Zeroizing<[u8; 32]> {
        let mut ikm = Zeroizing::new(Vec::with_capacity(64));
        ikm.extend_from_slice(&self.master_public);
        if let Some(s) = &self.access_secret {
            ikm.extend_from_slice(s.as_ref());
        }
        let hk = Hkdf::<Sha256>::new(Some(CONTENT_SALT), &ikm);
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(&epoch.to_be_bytes(), okm.as_mut())
            .expect("32 bytes é um comprimento HKDF válido");
        okm
    }
}

impl AnonRecord {
    /// Recusa qualquer coisa que possa revelar endereço de rede do nó.
    pub fn validate(&self) -> Result<(), PkarrError> {
        if self.endpoints.is_empty() || self.endpoints.len() > MAX_ENDPOINTS {
            return Err(PkarrError::Leak("número de endpoints fora de 1..=8".into()));
        }
        for ep in &self.endpoints {
            match ep {
                Endpoint::Nostr { pubkey, relays } => {
                    check_hex(pubkey, 64, 64, "pubkey nostr")?;
                    if relays.is_empty() || relays.len() > MAX_RELAYS {
                        return Err(PkarrError::Leak("relays nostr fora de 1..=6".into()));
                    }
                    for r in relays {
                        check_relay_url(r)?;
                    }
                }
                Endpoint::Veil { descriptor } => check_hex(descriptor, 2, 256, "descritor veil")?,
                Endpoint::Onion { addr } => check_onion(addr)?,
                Endpoint::Plot { content_id } => check_hex(content_id, 64, 64, "content_id")?,
            }
        }
        Ok(())
    }
}

/// Monta, cifra e assina o pacote da época de `now_secs`.
pub fn seal(
    identity: &MasterIdentity,
    access_secret: Option<&[u8; 32]>,
    record: &AnonRecord,
    now_secs: u64,
) -> Result<SignedPacket, PkarrError> {
    record.validate()?;
    let epoch = epoch_of(now_secs);
    let mut record = record.clone();
    // Nunca anunciar além da época seguinte: limita o dano de um registro
    // velho que fique em cache.
    let ceiling = (epoch + 2) * EPOCH_SECS;
    if record.not_after <= now_secs {
        return Err(PkarrError::Expired);
    }
    record.not_after = record.not_after.min(ceiling);

    let cap = Capability {
        master_public: identity.public(),
        access_secret: access_secret.map(|s| Zeroizing::new(*s)),
    };
    let signer = identity.blinded_signer(epoch)?;
    let epoch_pub = signer.public();
    // timestamp em segundos inteiros (µs zerados): não vaza precisão do relógio
    let timestamp_us = now_secs * 1_000_000;

    let json =
        Zeroizing::new(serde_json::to_vec(&record).map_err(|_| PkarrError::Malformed("json"))?);
    if json.len() + 2 > PADDED_LEN {
        return Err(PkarrError::Malformed(
            "registro maior que o acolchoamento fixo",
        ));
    }
    let mut plain = Zeroizing::new(vec![0u8; PADDED_LEN]);
    plain[..2].copy_from_slice(&(json.len() as u16).to_be_bytes());
    plain[2..2 + json.len()].copy_from_slice(&json);

    let key = cap.content_key(epoch);
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let aad = aad(&epoch_pub, timestamp_us);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &aad,
            },
        )
        .map_err(|_| PkarrError::Crypto)?;
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);

    let dns = dns::encode(&[TxtRecord {
        name: record_name(&epoch_pub),
        ttl: RECORD_TTL,
        strings: dns::split_txt(&blob),
    }])?;
    SignedPacket::sign_expanded(&signer.esk, &signer.vk, timestamp_us, dns)
}

/// Verifica e decifra um pacote resolvido. `packet` já teve a assinatura
/// verificada em `SignedPacket::from_relay_payload`; aqui confere-se que a
/// chave é a cegada certa para a época do timestamp, frescor e conteúdo.
pub fn open(
    cap: &Capability,
    packet: &SignedPacket,
    now_secs: u64,
) -> Result<AnonRecord, PkarrError> {
    packet.verify()?;
    let ts_secs = packet.timestamp_us() / 1_000_000;
    if ts_secs > now_secs + MAX_CLOCK_SKEW_SECS {
        return Err(PkarrError::Malformed("timestamp no futuro"));
    }
    let epoch = epoch_of(ts_secs);
    let now_epoch = epoch_of(now_secs);
    if epoch + 1 < now_epoch {
        return Err(PkarrError::Expired);
    }
    let epoch_pub = blinded_public(&cap.master_public, epoch)?;
    if packet.public_key() != &epoch_pub {
        return Err(PkarrError::BadKey);
    }

    let want = record_name(&epoch_pub);
    let txt = dns::decode_txt(packet.dns())?
        .into_iter()
        .find(|r| r.name == want)
        .ok_or(PkarrError::Malformed("TXT _myc ausente"))?;
    let blob: Vec<u8> = txt.strings.concat();
    if blob.len() != 24 + PADDED_LEN + 16 {
        return Err(PkarrError::Malformed("tamanho do cifrado"));
    }
    let key = cap.content_key(epoch);
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&blob[..24]),
                Payload {
                    msg: &blob[24..],
                    aad: &aad(&epoch_pub, packet.timestamp_us()),
                },
            )
            .map_err(|_| PkarrError::Crypto)?,
    );
    let len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
    if 2 + len > plain.len() || plain[2 + len..].iter().any(|&b| b != 0) {
        return Err(PkarrError::Malformed("acolchoamento"));
    }
    let record: AnonRecord =
        serde_json::from_slice(&plain[2..2 + len]).map_err(|_| PkarrError::Malformed("json"))?;
    record.validate()?;
    if record.not_after <= now_secs {
        return Err(PkarrError::Expired);
    }
    Ok(record)
}

fn record_name(epoch_pub: &[u8; 32]) -> String {
    format!("{RECORD_LABEL}.{}", zbase32::encode(epoch_pub))
}

fn aad(epoch_pub: &[u8; 32], timestamp_us: u64) -> Vec<u8> {
    let mut v = epoch_pub.to_vec();
    v.extend_from_slice(&timestamp_us.to_be_bytes());
    v
}

fn check_hex(s: &str, min: usize, max: usize, what: &str) -> Result<(), PkarrError> {
    let ok = s.len() >= min
        && s.len() <= max
        && s.len() % 2 == 0
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(PkarrError::Leak(format!("{what}: esperado hex minúsculo")))
    }
}

/// Só `wss://` com nome de domínio público. IP literal, `localhost` e nomes
/// de rede local revelariam a localização/topologia do operador.
fn check_relay_url(raw: &str) -> Result<(), PkarrError> {
    let bad = |why: &str| Err(PkarrError::Leak(format!("relay {raw:?}: {why}")));
    if raw.len() > 120 {
        return bad("URL longa demais");
    }
    let url = match url::Url::parse(raw) {
        Ok(u) => u,
        Err(_) => return bad("URL inválida"),
    };
    if url.scheme() != "wss" {
        return bad("só wss:// (TLS) é aceito");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return bad("credenciais na URL");
    }
    if url.query().is_some() || url.fragment().is_some() {
        return bad("query/fragmento não permitidos");
    }
    match url.host() {
        Some(url::Host::Domain(d)) => {
            let d = d.to_ascii_lowercase();
            let local = [
                "localhost",
                ".local",
                ".lan",
                ".internal",
                ".home.arpa",
                ".onion",
            ];
            if d == "localhost" || local.iter().any(|s| d.ends_with(s)) || !d.contains('.') {
                return bad("nome local/não público");
            }
            Ok(())
        }
        Some(_) => bad("IP literal revela endereço"),
        None => bad("sem host"),
    }
}

fn check_onion(addr: &str) -> Result<(), PkarrError> {
    let (host, port) = match addr.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (addr, None),
    };
    let label = host
        .strip_suffix(".onion")
        .ok_or_else(|| PkarrError::Leak("onion: sufixo .onion ausente".into()))?;
    let v3 = label.len() == 56
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b));
    let port_ok = port.is_none_or(|p| p.parse::<u16>().is_ok_and(|n| n > 0));
    if v3 && port_ok {
        Ok(())
    } else {
        Err(PkarrError::Leak("onion: só endereço v3 (56 chars)".into()))
    }
}
