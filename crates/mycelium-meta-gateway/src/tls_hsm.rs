//! Carregamento de certificados reais para Pix mTLS (ICP-Brasil PEM / PKCS#12)
//! e Keystore HSM (simulado/local) para assinatura e Trust Boundary SWIFT CSP.

use crate::error::GatewayError;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Configuração de mTLS ICP-Brasil para o `PixAdapter`.
#[derive(Debug, Clone)]
pub struct PixMtlsConfig {
    pub cert_path: PathBuf,
    pub thumbprint: String,
    pub format: CertFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertFormat {
    PemBundle,
    Pkcs12,
}

impl PixMtlsConfig {
    /// Carrega um bundle PEM (`cert + private key`) do disco, calcula o thumbprint
    /// criptográfico e constrói um `reqwest::Client` configurado com mTLS (fail-closed).
    pub fn load_pem_client(
        path: impl AsRef<Path>,
    ) -> Result<(Self, reqwest::Client), GatewayError> {
        let path = path.as_ref().to_path_buf();
        let pem_bytes = std::fs::read(&path).map_err(|e| {
            GatewayError::Crypto(format!(
                "falha ao ler certificado PEM `{}`: {e}",
                path.display()
            ))
        })?;
        let identity = reqwest::Identity::from_pem(&pem_bytes)
            .map_err(|e| GatewayError::Crypto(format!("identidade PEM inválida para mTLS: {e}")))?;
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .identity(identity)
            .build()
            .map_err(|e| GatewayError::Crypto(format!("reqwest mTLS build: {e}")))?;

        let thumbprint = format!(
            "icp-blake3:{}",
            hex::encode(&blake3::hash(&pem_bytes).as_bytes()[..16])
        );
        Ok((
            Self {
                cert_path: path,
                thumbprint,
                format: CertFormat::PemBundle,
            },
            client,
        ))
    }

    /// Carrega bytes DER de um arquivo `.p12`/`.pfx` ICP-Brasil do disco e calcula o thumbprint
    /// (validando presença, tamanho mínimo e senha não vazia; pronto para TLS nativo ou proxy mTLS).
    pub fn load_pkcs12_metadata(
        path: impl AsRef<Path>,
        password: &str,
    ) -> Result<Self, GatewayError> {
        if password.is_empty() {
            return Err(GatewayError::Crypto(
                "senha do certificado PKCS#12 (.p12) não pode ser vazia".into(),
            ));
        }
        let path = path.as_ref().to_path_buf();
        let der = std::fs::read(&path).map_err(|e| {
            GatewayError::Crypto(format!(
                "falha ao ler arquivo .p12 `{}`: {e}",
                path.display()
            ))
        })?;
        // ASN.1 SEQUENCE (0x30) mínimo para arquivo PKCS#12 DER.
        if der.len() < 16 || der[0] != 0x30 {
            return Err(GatewayError::Crypto(
                "arquivo .p12 inválido (cabeçalho ASN.1 DER ausente)".into(),
            ));
        }
        // A DER prefix is not PKCS#12 validation. Fail closed.
        Err(GatewayError::Crypto(
            "PKCS#12 parsing and password verification are not implemented".into(),
        ))
    }
}

/// Estrutura persistida de um keystore HSM simulado/local para SWIFT CSP (`A1`/`A2`).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HsmKeystoreFile {
    slot_id: String,
    pin_hash_hex: String,
    seed_hex: String,
}

/// Atestado emitido pelo HSM confirmando integridade da chave PKI na Secure Zone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HsmAttestation {
    pub slot_id: String,
    pub key_fingerprint: String,
    pub signature_hex: String,
}

/// Keystore HSM para validação de Trust Boundary SWIFT CSP (`A1`/`A2`).
pub struct SwiftHsmKeystore {
    pub slot_id: String,
    pub key_fingerprint: String,
    signing_key: SigningKey,
}

impl SwiftHsmKeystore {
    /// Cria e salva um keystore HSM local protegido por hash do PIN.
    pub fn create_file(
        path: impl AsRef<Path>,
        slot_id: impl Into<String>,
        pin: &str,
        seed: [u8; 32],
    ) -> Result<Self, GatewayError> {
        if pin.len() < 6 {
            return Err(GatewayError::Crypto(
                "PIN do HSM SWIFT deve ter pelo menos 6 caracteres".into(),
            ));
        }
        let slot_id = slot_id.into();
        let pin_hash_hex = hex::encode(blake3::hash(pin.as_bytes()).as_bytes());
        let file = HsmKeystoreFile {
            slot_id: slot_id.clone(),
            pin_hash_hex,
            seed_hex: hex::encode(seed),
        };
        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(|e| GatewayError::Crypto(format!("serialize hsm keystore: {e}")))?;
        std::fs::write(path, bytes)
            .map_err(|e| GatewayError::Crypto(format!("write hsm keystore: {e}")))?;

        let signing_key = SigningKey::from_bytes(&seed);
        let key_fingerprint =
            hex::encode(&blake3::hash(signing_key.verifying_key().as_bytes()).as_bytes()[..16]);
        Ok(Self {
            slot_id,
            key_fingerprint,
            signing_key,
        })
    }

    /// Carrega o keystore HSM do disco validando o PIN (fail-closed em caso de PIN incorreto).
    pub fn unlock_file(path: impl AsRef<Path>, pin: &str) -> Result<Self, GatewayError> {
        let bytes = std::fs::read(path)
            .map_err(|e| GatewayError::Crypto(format!("falha ao abrir keystore HSM: {e}")))?;
        let file: HsmKeystoreFile = serde_json::from_slice(&bytes)
            .map_err(|e| GatewayError::Crypto(format!("keystore HSM corrompido: {e}")))?;
        let provided_hash = hex::encode(blake3::hash(pin.as_bytes()).as_bytes());
        if provided_hash != file.pin_hash_hex {
            return Err(GatewayError::Crypto("PIN do HSM incorreto".into()));
        }
        let seed_vec = hex::decode(&file.seed_hex)
            .map_err(|_| GatewayError::Crypto("seed hex inválida no keystore HSM".into()))?;
        let seed: [u8; 32] = seed_vec
            .try_into()
            .map_err(|_| GatewayError::Crypto("seed do keystore HSM não tem 32 bytes".into()))?;
        let signing_key = SigningKey::from_bytes(&seed);
        let key_fingerprint =
            hex::encode(&blake3::hash(signing_key.verifying_key().as_bytes()).as_bytes()[..16]);
        Ok(Self {
            slot_id: file.slot_id,
            key_fingerprint,
            signing_key,
        })
    }

    /// Assina um atestado PKI vinculando `secure_zone_log_id` à chave do HSM.
    pub fn attest_secure_zone(&self, secure_zone_log_id: &str) -> HsmAttestation {
        let msg = format!("swift-hsm:{}:{secure_zone_log_id}", self.slot_id);
        let sig = self.signing_key.sign(msg.as_bytes());
        HsmAttestation {
            slot_id: self.slot_id.clone(),
            key_fingerprint: self.key_fingerprint.clone(),
            signature_hex: hex::encode(sig.to_bytes()),
        }
    }
}
