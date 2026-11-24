//! Mensageria E2EE Pós-Quântica do Mycelium Rhizome (paridade WhatsApp).
//!
//! - **1:1 Direct Messages**: encapsulamento `ML-KEM-1024` (FIPS 203 via `mycelium-pqc`)
//!   + derivação de chave BLAKE3 + `XChaCha20-Poly1305` com AAD vinculando emissor,
//!   destinatário, conversa e timestamp + assinatura Ed25519 estrita (`Gland`).
//! - **Grupos Criptografados**: chave simétrica de 32 bytes por época, embrulhada via
//!   `ML-KEM-1024` individualmente para cada participante do grupo.
//! - **Entrega Offline**: envelopes cifrados viajam por `Envelope::Direct` → `DtnBundleStore`
//!   (`mycelium-hyphae`) e aguardam o despertar/reconexão do par.
//! - **Fallback CGNAT**: encapsulamento opcional em evento Nostr NIP-44 (`mycelium-nostr`)
//!   para atravessar firewalls onde nenhum dos lados aceita inbound TCP/QUIC.
//! - **Recibos Assinados**: `Sent` (✓), `Delivered` (✓✓), `Read` (✓✓ azul).

use crate::identity::{verify_domain_signature, SovereignKeys};
use crate::model::{ExternalOrigin, MediaAttachment};
use crate::{unix_now, RhizomeError};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use mycelium_core::ContentId;
use mycelium_nostr::{decrypt_nip44_to_string, encrypt_nip44, seal_event, NostrEvent};
use mycelium_pqc::{mlkem_decapsulate, mlkem_encapsulate};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const DOMAIN_CHAT_ENVELOPE: &str = "mycelium-rhizome/chat-envelope/v1";
const DOMAIN_CHAT_RECEIPT: &str = "mycelium-rhizome/chat-receipt/v1";
const DOMAIN_GROUP_MANIFEST: &str = "mycelium-rhizome/group-manifest/v1";
const AEAD_KEY_CTX: &str = "mycelium-rhizome/chat-aead-key/v1";
const GROUP_WRAP_CTX: &str = "mycelium-rhizome/group-wrap-key/v1";

/// Kind Nostr usado para fallback cifrado NIP-44 (alinhado ao backchannel do Mycelium).
pub const KIND_RHIZOME_NOSTR_DM: u16 = 39406;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatMessageKind {
    Text,
    VoiceNote,
    Image,
    Video,
    Document,
    System,
}

/// Conteúdo em claro de uma mensagem de chat (sempre cifrado antes de sair do nó).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatPlaintext {
    pub msg_id: String,
    pub conversation_id: String,
    pub sender_node_id: String,
    pub sender_handle: String,
    pub kind: ChatMessageKind,
    pub body: String,
    #[serde(default)]
    pub media: Option<MediaAttachment>,
    #[serde(default)]
    pub reply_to: Option<String>,
    #[serde(default)]
    pub forwarded: bool,
    pub created_at: u64,
    #[serde(default)]
    pub external_origin: ExternalOrigin,
}

/// Envelope cifrado pós-quântico pronto para transporte P2P (DTN/Direct ou Nostr).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedChatEnvelope {
    pub msg_id: String,
    pub conversation_id: String,
    pub is_group: bool,
    pub sender_node_id: String,
    pub sender_pubkey_hex: String,
    /// Para DM 1:1: NodeId do destinatário. Para grupo: `group_id` ou NodeId do alvo do fanout.
    pub recipient_node_id: String,
    /// Ciphertext ML-KEM-1024 em Base64 (vazio apenas se `is_group == true` usando chave de época já entregue).
    pub mlkem_ciphertext_b64: String,
    /// Época da chave de grupo (0 para 1:1).
    #[serde(default)]
    pub group_epoch: u64,
    /// Nonce XChaCha20-Poly1305 (24 bytes em Base64).
    pub nonce_b64: String,
    /// Ciphertext AEAD em Base64.
    pub ciphertext_b64: String,
    pub created_at: u64,
    /// Assinatura Ed25519 estrita do remetente sobre todo o envelope cifrado.
    pub signature: String,
}

impl SealedChatEnvelope {
    /// Gera um `conversation_id` determinístico para um par 1:1 de nós.
    pub fn dm_conversation_id(node_a: &str, node_b: &str) -> String {
        let (lo, hi) = if node_a <= node_b {
            (node_a, node_b)
        } else {
            (node_b, node_a)
        };
        let h = blake3::hash(format!("mycelium-rhizome/dm/{lo}/{hi}").as_bytes());
        format!("dm_{}", hex::encode(&h.as_bytes()[..12]))
    }

    fn aad_bytes(
        msg_id: &str,
        conversation_id: &str,
        sender_node_id: &str,
        recipient_node_id: &str,
        created_at: u64,
    ) -> Vec<u8> {
        format!("{DOMAIN_CHAT_ENVELOPE}|{msg_id}|{conversation_id}|{sender_node_id}|{recipient_node_id}|{created_at}").into_bytes()
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    /// Verifica assinatura Ed25519 estrita do remetente antes mesmo de tentar decifrar.
    pub fn verify_signature(&self) -> Result<(), RhizomeError> {
        let bytes = self.canonical_bytes()?;
        verify_domain_signature(
            &self.sender_node_id,
            &self.sender_pubkey_hex,
            DOMAIN_CHAT_ENVELOPE,
            &bytes,
            &self.signature,
        )?;
        Ok(())
    }

    /// Cifra uma mensagem 1:1 usando a chave pública ML-KEM-1024 do destinatário.
    pub fn seal_direct(
        sender_keys: &SovereignKeys,
        recipient_node_id: &str,
        recipient_mlkem_pubkey_hex: &str,
        plaintext: &ChatPlaintext,
    ) -> Result<Self, RhizomeError> {
        let recip_ek = hex::decode(recipient_mlkem_pubkey_hex)
            .map_err(|e| RhizomeError::InvalidKey(format!("ML-KEM pubkey hex inválido: {e}")))?;
        let encap = mlkem_encapsulate(&recip_ek)
            .map_err(|e| RhizomeError::Crypto(format!("ML-KEM encapsulate: {e}")))?;

        let aead_key = derive_direct_aead_key(
            &encap.shared_secret,
            &sender_keys.node_id_hex(),
            recipient_node_id,
            &plaintext.msg_id,
        );
        let cipher = XChaCha20Poly1305::new((&*aead_key).into());

        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let aad = Self::aad_bytes(
            &plaintext.msg_id,
            &plaintext.conversation_id,
            &sender_keys.node_id_hex(),
            recipient_node_id,
            plaintext.created_at,
        );
        let plain_bytes = serde_json::to_vec(plaintext)?;
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plain_bytes,
                    aad: &aad,
                },
            )
            .map_err(|_| RhizomeError::Crypto("falha ao cifrar XChaCha20-Poly1305".into()))?;

        let mut env = Self {
            msg_id: plaintext.msg_id.clone(),
            conversation_id: plaintext.conversation_id.clone(),
            is_group: false,
            sender_node_id: sender_keys.node_id_hex(),
            sender_pubkey_hex: sender_keys.ed25519_pubkey_hex(),
            recipient_node_id: recipient_node_id.to_string(),
            mlkem_ciphertext_b64: BASE64.encode(&encap.ciphertext),
            group_epoch: 0,
            nonce_b64: BASE64.encode(nonce_bytes),
            ciphertext_b64: BASE64.encode(&ciphertext),
            created_at: plaintext.created_at,
            signature: String::new(),
        };
        let bytes = env.canonical_bytes()?;
        env.signature = sender_keys.sign_domain(DOMAIN_CHAT_ENVELOPE, &bytes);
        Ok(env)
    }

    /// Verifica assinatura Ed25519, decapsula ML-KEM-1024 com a chave privada do nó e decifra.
    pub fn open_direct(&self, recipient_keys: &SovereignKeys) -> Result<ChatPlaintext, RhizomeError> {
        self.verify_signature()?;
        if self.is_group {
            return Err(RhizomeError::Crypto(
                "envelope de grupo deve ser aberto com chave do grupo".into(),
            ));
        }
        if self.recipient_node_id != recipient_keys.node_id_hex() {
            return Err(RhizomeError::Crypto(
                "envelope não destinado a este nó".into(),
            ));
        }

        let kem_ct = BASE64
            .decode(&self.mlkem_ciphertext_b64)
            .map_err(|e| RhizomeError::Crypto(format!("base64 ML-KEM ct: {e}")))?;
        let ss = Zeroizing::new(
            mlkem_decapsulate(recipient_keys.mlkem().private_bytes(), &kem_ct)
                .map_err(|e| RhizomeError::Crypto(format!("ML-KEM decapsulate: {e}")))?,
        );

        let aead_key = derive_direct_aead_key(
            &ss,
            &self.sender_node_id,
            &self.recipient_node_id,
            &self.msg_id,
        );
        self.decrypt_with_key(&aead_key)
    }

    /// Cifra uma mensagem de grupo usando a chave simétrica da época do grupo.
    pub fn seal_group(
        sender_keys: &SovereignKeys,
        group_id: &str,
        group_epoch: u64,
        group_key: &[u8; 32],
        plaintext: &ChatPlaintext,
    ) -> Result<Self, RhizomeError> {
        let aead_key = derive_group_msg_key(group_key, group_id, group_epoch, &plaintext.msg_id);
        let cipher = XChaCha20Poly1305::new((&*aead_key).into());

        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let aad = Self::aad_bytes(
            &plaintext.msg_id,
            &plaintext.conversation_id,
            &sender_keys.node_id_hex(),
            group_id,
            plaintext.created_at,
        );
        let plain_bytes = serde_json::to_vec(plaintext)?;
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plain_bytes,
                    aad: &aad,
                },
            )
            .map_err(|_| RhizomeError::Crypto("falha ao cifrar mensagem de grupo".into()))?;

        let mut env = Self {
            msg_id: plaintext.msg_id.clone(),
            conversation_id: plaintext.conversation_id.clone(),
            is_group: true,
            sender_node_id: sender_keys.node_id_hex(),
            sender_pubkey_hex: sender_keys.ed25519_pubkey_hex(),
            recipient_node_id: group_id.to_string(),
            mlkem_ciphertext_b64: String::new(),
            group_epoch,
            nonce_b64: BASE64.encode(nonce_bytes),
            ciphertext_b64: BASE64.encode(&ciphertext),
            created_at: plaintext.created_at,
            signature: String::new(),
        };
        let bytes = env.canonical_bytes()?;
        env.signature = sender_keys.sign_domain(DOMAIN_CHAT_ENVELOPE, &bytes);
        Ok(env)
    }

    /// Abre uma mensagem de grupo usando a chave simétrica da época.
    pub fn open_group(&self, group_key: &[u8; 32]) -> Result<ChatPlaintext, RhizomeError> {
        self.verify_signature()?;
        if !self.is_group {
            return Err(RhizomeError::Crypto("envelope não é de grupo".into()));
        }
        let aead_key = derive_group_msg_key(
            group_key,
            &self.recipient_node_id,
            self.group_epoch,
            &self.msg_id,
        );
        self.decrypt_with_key(&aead_key)
    }

    fn decrypt_with_key(&self, aead_key: &[u8; 32]) -> Result<ChatPlaintext, RhizomeError> {
        let nonce_vec = BASE64
            .decode(&self.nonce_b64)
            .map_err(|e| RhizomeError::Crypto(format!("nonce base64: {e}")))?;
        let nonce_arr: [u8; 24] = nonce_vec
            .try_into()
            .map_err(|_| RhizomeError::Crypto("nonce XChaCha20 deve ter 24 bytes".into()))?;
        let ct = BASE64
            .decode(&self.ciphertext_b64)
            .map_err(|e| RhizomeError::Crypto(format!("ciphertext base64: {e}")))?;

        let aad = Self::aad_bytes(
            &self.msg_id,
            &self.conversation_id,
            &self.sender_node_id,
            &self.recipient_node_id,
            self.created_at,
        );
        let cipher = XChaCha20Poly1305::new(aead_key.into());
        let plain_bytes = cipher
            .decrypt(
                XNonce::from_slice(&nonce_arr),
                Payload {
                    msg: &ct,
                    aad: &aad,
                },
            )
            .map_err(|_| RhizomeError::Crypto("autenticação AEAD falhou (chave errada ou adulteração)".into()))?;

        let pt: ChatPlaintext = serde_json::from_slice(&plain_bytes)?;
        if pt.msg_id != self.msg_id
            || pt.conversation_id != self.conversation_id
            || pt.sender_node_id != self.sender_node_id
        {
            return Err(RhizomeError::Corrupted(
                "metadados internos divergem do envelope externo".into(),
            ));
        }
        Ok(pt)
    }
}

/// Chave de grupo (32B) embrulhada com ML-KEM-1024 + XChaCha20-Poly1305 para um membro específico.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedGroupKey {
    pub member_node_id: String,
    pub mlkem_ciphertext_b64: String,
    pub nonce_b64: String,
    pub wrapped_key_b64: String,
}

/// Manifesto assinado de um Grupo WhatsApp E2EE Pós-Quântico.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupManifest {
    pub group_id: String,
    pub name: String,
    pub description: String,
    pub creator_node_id: String,
    pub creator_pubkey_hex: String,
    pub epoch: u64,
    pub members: Vec<String>,
    pub wrapped_keys: BTreeMap<String, WrappedGroupKey>,
    pub updated_at: u64,
    pub signature: String,
}

impl GroupManifest {
    /// Cria um novo grupo criptografado com chave aleatória de 32 bytes embrulhada via ML-KEM-1024
    /// para todos os membros (incluindo o próprio criador).
    pub fn create(
        creator_keys: &SovereignKeys,
        name: &str,
        description: &str,
        member_mlkem_keys: &[(String, String)],
    ) -> Result<(Self, Zeroizing<[u8; 32]>), RhizomeError> {
        let now = unix_now();
        let mut group_key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(group_key.as_mut());

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let group_id_hash = blake3::hash(
            format!(
                "mycelium-rhizome/group/{}/{}/{}/{}",
                creator_keys.node_id_hex(),
                name,
                now,
                hex::encode(salt)
            )
            .as_bytes(),
        );
        let group_id = format!("grp_{}", hex::encode(&group_id_hash.as_bytes()[..12]));

        let mut members = Vec::new();
        let mut wrapped_keys = BTreeMap::new();

        // Garante que o criador sempre tem sua própria chave embrulhada.
        let mut all_members = member_mlkem_keys.to_vec();
        if !all_members
            .iter()
            .any(|(nid, _)| nid == &creator_keys.node_id_hex())
        {
            all_members.push((creator_keys.node_id_hex(), creator_keys.mlkem_pubkey_hex()));
        }

        for (member_nid, mlkem_hex) in all_members {
            let wrapped = wrap_group_key(&group_id, 1, &member_nid, &mlkem_hex, &group_key)?;
            members.push(member_nid.clone());
            wrapped_keys.insert(member_nid, wrapped);
        }
        members.sort();
        members.dedup();

        let mut manifest = Self {
            group_id,
            name: name.to_string(),
            description: description.to_string(),
            creator_node_id: creator_keys.node_id_hex(),
            creator_pubkey_hex: creator_keys.ed25519_pubkey_hex(),
            epoch: 1,
            members,
            wrapped_keys,
            updated_at: now,
            signature: String::new(),
        };
        let bytes = manifest.canonical_bytes()?;
        manifest.signature = creator_keys.sign_domain(DOMAIN_GROUP_MANIFEST, &bytes);
        Ok((manifest, group_key))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    pub fn verify(&self) -> Result<(), RhizomeError> {
        let bytes = self.canonical_bytes()?;
        verify_domain_signature(
            &self.creator_node_id,
            &self.creator_pubkey_hex,
            DOMAIN_GROUP_MANIFEST,
            &bytes,
            &self.signature,
        )?;
        Ok(())
    }

    /// Extrai a chave simétrica do grupo para o nó local via decapsulamento ML-KEM-1024.
    pub fn unwrap_my_key(&self, my_keys: &SovereignKeys) -> Result<Zeroizing<[u8; 32]>, RhizomeError> {
        self.verify()?;
        let wrapped = self
            .wrapped_keys
            .get(&my_keys.node_id_hex())
            .ok_or_else(|| RhizomeError::NotFound("nó não faz parte deste grupo".into()))?;
        unwrap_group_key(&self.group_id, self.epoch, my_keys, wrapped)
    }
}

fn wrap_group_key(
    group_id: &str,
    epoch: u64,
    member_node_id: &str,
    member_mlkem_hex: &str,
    group_key: &[u8; 32],
) -> Result<WrappedGroupKey, RhizomeError> {
    let ek = hex::decode(member_mlkem_hex)
        .map_err(|e| RhizomeError::InvalidKey(format!("ML-KEM pubkey membro: {e}")))?;
    let encap = mlkem_encapsulate(&ek)
        .map_err(|e| RhizomeError::Crypto(format!("ML-KEM wrap group key: {e}")))?;
    let kek = derive_group_wrap_key(&encap.shared_secret, group_id, epoch, member_node_id);
    let cipher = XChaCha20Poly1305::new((&*kek).into());
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let aad = format!("{GROUP_WRAP_CTX}|{group_id}|{epoch}|{member_node_id}").into_bytes();
    let wrapped_bytes = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: group_key,
                aad: &aad,
            },
        )
        .map_err(|_| RhizomeError::Crypto("falha ao embrulhar chave de grupo".into()))?;
    Ok(WrappedGroupKey {
        member_node_id: member_node_id.to_string(),
        mlkem_ciphertext_b64: BASE64.encode(&encap.ciphertext),
        nonce_b64: BASE64.encode(nonce_bytes),
        wrapped_key_b64: BASE64.encode(&wrapped_bytes),
    })
}

fn unwrap_group_key(
    group_id: &str,
    epoch: u64,
    my_keys: &SovereignKeys,
    wrapped: &WrappedGroupKey,
) -> Result<Zeroizing<[u8; 32]>, RhizomeError> {
    let kem_ct = BASE64
        .decode(&wrapped.mlkem_ciphertext_b64)
        .map_err(|e| RhizomeError::Crypto(format!("base64 group kem ct: {e}")))?;
    let ss = Zeroizing::new(
        mlkem_decapsulate(my_keys.mlkem().private_bytes(), &kem_ct)
            .map_err(|e| RhizomeError::Crypto(format!("ML-KEM unwrap group key: {e}")))?,
    );
    let kek = derive_group_wrap_key(&ss, group_id, epoch, &my_keys.node_id_hex());
    let nonce_arr: [u8; 24] = BASE64
        .decode(&wrapped.nonce_b64)
        .map_err(|e| RhizomeError::Crypto(format!("base64 group nonce: {e}")))?
        .try_into()
        .map_err(|_| RhizomeError::Crypto("nonce inválido".into()))?;
    let ct = BASE64
        .decode(&wrapped.wrapped_key_b64)
        .map_err(|e| RhizomeError::Crypto(format!("base64 wrapped key: {e}")))?;
    let aad = format!("{GROUP_WRAP_CTX}|{group_id}|{epoch}|{}", my_keys.node_id_hex()).into_bytes();
    let cipher = XChaCha20Poly1305::new((&*kek).into());
    let raw = cipher
        .decrypt(
            XNonce::from_slice(&nonce_arr),
            Payload { msg: &ct, aad: &aad },
        )
        .map_err(|_| RhizomeError::Crypto("falha ao desembrulhar chave de grupo".into()))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| RhizomeError::Crypto("chave de grupo inválida".into()))?;
    Ok(Zeroizing::new(arr))
}

fn derive_direct_aead_key(
    shared_secret: &[u8],
    sender_node_id: &str,
    recipient_node_id: &str,
    msg_id: &str,
) -> Zeroizing<[u8; 32]> {
    let mut h = blake3::Hasher::new_derive_key(AEAD_KEY_CTX);
    h.update(shared_secret);
    h.update(b"|");
    h.update(sender_node_id.as_bytes());
    h.update(b"|");
    h.update(recipient_node_id.as_bytes());
    h.update(b"|");
    h.update(msg_id.as_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

fn derive_group_msg_key(
    group_key: &[u8; 32],
    group_id: &str,
    epoch: u64,
    msg_id: &str,
) -> Zeroizing<[u8; 32]> {
    let mut h = blake3::Hasher::new_derive_key("mycelium-rhizome/group-msg-key/v1");
    h.update(group_key);
    h.update(group_id.as_bytes());
    h.update(&epoch.to_be_bytes());
    h.update(msg_id.as_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

fn derive_group_wrap_key(
    shared_secret: &[u8],
    group_id: &str,
    epoch: u64,
    member_node_id: &str,
) -> Zeroizing<[u8; 32]> {
    let mut h = blake3::Hasher::new_derive_key(GROUP_WRAP_CTX);
    h.update(shared_secret);
    h.update(group_id.as_bytes());
    h.update(&epoch.to_be_bytes());
    h.update(member_node_id.as_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Estado de entrega estilo WhatsApp (`✓`, `✓✓`, `✓✓ azul`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Sent,
    Delivered,
    Read,
}

/// Recibo criptográfico assinado pelo destinatário confirmando entrega ou leitura.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatReceipt {
    pub msg_id: String,
    pub conversation_id: String,
    pub original_sender_node_id: String,
    pub receiver_node_id: String,
    pub receiver_pubkey_hex: String,
    pub status: ReceiptStatus,
    pub timestamp: u64,
    pub signature: String,
}

impl ChatReceipt {
    pub fn create_and_sign(
        receiver_keys: &SovereignKeys,
        msg_id: &str,
        conversation_id: &str,
        original_sender_node_id: &str,
        status: ReceiptStatus,
    ) -> Result<Self, RhizomeError> {
        let mut r = Self {
            msg_id: msg_id.to_string(),
            conversation_id: conversation_id.to_string(),
            original_sender_node_id: original_sender_node_id.to_string(),
            receiver_node_id: receiver_keys.node_id_hex(),
            receiver_pubkey_hex: receiver_keys.ed25519_pubkey_hex(),
            status,
            timestamp: unix_now(),
            signature: String::new(),
        };
        let bytes = r.canonical_bytes()?;
        r.signature = receiver_keys.sign_domain(DOMAIN_CHAT_RECEIPT, &bytes);
        Ok(r)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    pub fn verify(&self) -> Result<(), RhizomeError> {
        let bytes = self.canonical_bytes()?;
        verify_domain_signature(
            &self.receiver_node_id,
            &self.receiver_pubkey_hex,
            DOMAIN_CHAT_RECEIPT,
            &bytes,
            &self.signature,
        )?;
        Ok(())
    }
}

/// Mensagem decifrada mantida no histórico local do usuário.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptedChatMessage {
    pub plaintext: ChatPlaintext,
    pub recipient_node_id: String,
    pub is_group: bool,
    pub direction: String, // "outbound" | "inbound" | "imported"
    pub status: ReceiptStatus,
    pub transport: String, // "pq_dtn_direct" | "pq_group" | "nostr_nip44" | "whatsapp_import" | "whatsapp_cloud"
    pub pq_verified: bool,
}

/// Resumo de uma conversa para a barra lateral estilo WhatsApp.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConversationSummary {
    pub conversation_id: String,
    pub title: String,
    pub peer_node_id: Option<String>,
    pub is_group: bool,
    pub last_message_preview: String,
    pub last_timestamp: u64,
    pub message_count: usize,
    pub unread_count: usize,
    pub pq_protected: bool,
}

/// Gera `msg_id` determinístico (ContentId) para uma mensagem.
pub fn new_message_id(sender_node_id: &str, conversation_id: &str, body: &str, ts: u64) -> String {
    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);
    let material = format!("{sender_node_id}|{conversation_id}|{ts}|{body}|{}", hex::encode(nonce));
    ContentId::of(material.as_bytes()).to_string()
}

/// Fallback CGNAT: encapsula uma mensagem (ou envelope PQ já selado) em evento Nostr NIP-44 assinado por Schnorr.
pub fn seal_for_nostr_nip44(
    sender_keys: &SovereignKeys,
    recipient_ghost_pubkey_hex: &str,
    plaintext: &ChatPlaintext,
) -> Result<NostrEvent, RhizomeError> {
    let json_payload = serde_json::to_string(plaintext)?;
    let encrypted = encrypt_nip44(sender_keys.ghost(), recipient_ghost_pubkey_hex, &json_payload)
        .map_err(|e| RhizomeError::Crypto(format!("NIP-44 encrypt: {e}")))?;
    let tags = vec![
        vec!["p".into(), recipient_ghost_pubkey_hex.to_string()],
        vec!["proto".into(), "mycelium-rhizome-chat-v1".into()],
        vec!["conv".into(), plaintext.conversation_id.clone()],
    ];
    seal_event(
        sender_keys.ghost(),
        plaintext.created_at,
        KIND_RHIZOME_NOSTR_DM,
        tags,
        encrypted,
    )
    .map_err(|e| RhizomeError::Crypto(format!("Nostr seal_event: {e}")))
}

/// Decifra um evento Nostr NIP-44 de fallback CGNAT, verificando antes a assinatura Schnorr NIP-01.
pub fn unseal_from_nostr_nip44(
    recipient_keys: &SovereignKeys,
    event: &NostrEvent,
) -> Result<ChatPlaintext, RhizomeError> {
    let sender_pk: [u8; 32] = hex::decode(&event.pubkey)
        .map_err(|e| RhizomeError::InvalidKey(format!("nostr pubkey hex: {e}")))?
        .try_into()
        .map_err(|_| RhizomeError::InvalidKey("nostr pubkey deve ter 32 bytes".into()))?;
    let event_id: [u8; 32] = hex::decode(&event.id)
        .map_err(|e| RhizomeError::InvalidSignature(format!("nostr id hex: {e}")))?
        .try_into()
        .map_err(|_| RhizomeError::InvalidSignature("nostr id deve ter 32 bytes".into()))?;
    let sig: [u8; 64] = hex::decode(&event.sig)
        .map_err(|e| RhizomeError::InvalidSignature(format!("nostr sig hex: {e}")))?
        .try_into()
        .map_err(|_| RhizomeError::InvalidSignature("nostr sig deve ter 64 bytes".into()))?;

    mycelium_ghostid::GhostId::verify_nostr_event(&sender_pk, &event_id, &sig)
        .map_err(|e| RhizomeError::InvalidSignature(format!("Schnorr Nostr inválida: {e}")))?;

    let plain_json = decrypt_nip44_to_string(
        recipient_keys.ghost_secret_bytes(),
        &event.pubkey,
        &event.content,
    )
    .map_err(|e| RhizomeError::Crypto(format!("NIP-44 decrypt: {e}")))?;

    Ok(serde_json::from_str(&plain_json)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem1024_direct_e2ee_roundtrip_and_tamper_rejection() {
        let alice = SovereignKeys::from_seed([0x11; 32]).unwrap();
        let bob = SovereignKeys::from_seed([0x22; 32]).unwrap();
        let mallory = SovereignKeys::from_seed([0x99; 32]).unwrap();

        let conv = SealedChatEnvelope::dm_conversation_id(&alice.node_id_hex(), &bob.node_id_hex());
        let msg = ChatPlaintext {
            msg_id: new_message_id(&alice.node_id_hex(), &conv, "Oi Bob!", 1_760_000_000),
            conversation_id: conv.clone(),
            sender_node_id: alice.node_id_hex(),
            sender_handle: "alice".into(),
            kind: ChatMessageKind::Text,
            body: "Oi Bob! Mensagem pós-quântica sem servidor.".into(),
            media: None,
            reply_to: None,
            forwarded: false,
            created_at: 1_760_000_000,
            external_origin: ExternalOrigin::Native,
        };

        let sealed = SealedChatEnvelope::seal_direct(
            &alice,
            &bob.node_id_hex(),
            &bob.mlkem_pubkey_hex(),
            &msg,
        )
        .unwrap();

        // Bob decifra perfeitamente
        let opened = sealed.open_direct(&bob).unwrap();
        assert_eq!(opened, msg);

        // Mallory não consegue decifrar
        assert!(sealed.open_direct(&mallory).is_err());

        // Adulteração do ciphertext invalida assinatura e AEAD
        let mut tampered = sealed.clone();
        tampered.ciphertext_b64.push_str("AA");
        assert!(tampered.open_direct(&bob).is_err());

        // Recibo assinado por Bob
        let receipt = ChatReceipt::create_and_sign(
            &bob,
            &msg.msg_id,
            &conv,
            &alice.node_id_hex(),
            ReceiptStatus::Read,
        )
        .unwrap();
        receipt.verify().unwrap();
    }

    #[test]
    fn mlkem1024_encrypted_group_roundtrip() {
        let alice = SovereignKeys::from_seed([0x01; 32]).unwrap();
        let bob = SovereignKeys::from_seed([0x02; 32]).unwrap();
        let eve = SovereignKeys::from_seed([0x03; 32]).unwrap();

        let (manifest, alice_gkey) = GroupManifest::create(
            &alice,
            "Floresta Core",
            "Grupo E2EE PQ",
            &[(bob.node_id_hex(), bob.mlkem_pubkey_hex())],
        )
        .unwrap();

        let bob_gkey = manifest.unwrap_my_key(&bob).unwrap();
        assert_eq!(*alice_gkey, *bob_gkey);
        assert!(manifest.unwrap_my_key(&eve).is_err());

        let msg = ChatPlaintext {
            msg_id: new_message_id(&alice.node_id_hex(), &manifest.group_id, "Salve grupo!", 1_760_000_100),
            conversation_id: manifest.group_id.clone(),
            sender_node_id: alice.node_id_hex(),
            sender_handle: "alice".into(),
            kind: ChatMessageKind::Text,
            body: "Salve grupo!".into(),
            media: None,
            reply_to: None,
            forwarded: false,
            created_at: 1_760_000_100,
            external_origin: ExternalOrigin::Native,
        };

        let sealed = SealedChatEnvelope::seal_group(
            &alice,
            &manifest.group_id,
            manifest.epoch,
            &alice_gkey,
            &msg,
        )
        .unwrap();
        let opened = sealed.open_group(&bob_gkey).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn nostr_nip44_cgnat_fallback_roundtrip() {
        let alice = SovereignKeys::from_seed([0x41; 32]).unwrap();
        let bob = SovereignKeys::from_seed([0x42; 32]).unwrap();

        let msg = ChatPlaintext {
            msg_id: "Qm_test_nip44".into(),
            conversation_id: "dm_test".into(),
            sender_node_id: alice.node_id_hex(),
            sender_handle: "alice".into(),
            kind: ChatMessageKind::Text,
            body: "Atravessando CGNAT via Nostr NIP-44!".into(),
            media: None,
            reply_to: None,
            forwarded: false,
            created_at: 1_760_000_200,
            external_origin: ExternalOrigin::Native,
        };

        let ev = seal_for_nostr_nip44(&alice, &bob.ghost_pubkey_hex(), &msg).unwrap();
        assert_eq!(ev.kind, KIND_RHIZOME_NOSTR_DM);
        assert!(!ev.content.contains("CGNAT")); // texto realmente cifrado

        let decrypted = unseal_from_nostr_nip44(&bob, &ev).unwrap();
        assert_eq!(decrypted, msg);
    }
}
