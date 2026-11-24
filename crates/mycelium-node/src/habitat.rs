//! Mycelium Habitat — registro local de serviços soberanos.
//!
//! Manifestos assinados pela Gland; NÃO há publicação/gossip, execução ou
//! replicação implícita. As políticas são intenções verificáveis e são
//! aplicadas à camada de rede/armazenamento apenas quando estas as adotarem.
//! O arquivo é privado ao usuário local; nenhum dado de aplicação entra aqui.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use mycelium_core::{ContentId, NodeId};
use mycelium_pheromones::Gland;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const SIGNING_DOMAIN: &[u8] = b"mycelium-habitat-manifest-v1\0";
const SERVICE_DOMAIN: &[u8] = b"mycelium-habitat-service-id-v1\0";

#[derive(Debug, thiserror::Error)]
pub enum HabitatError {
    #[error("política inválida: {0}")]
    Policy(String),
    #[error("serviço já cadastrado: {0}")]
    Exists(String),
    #[error("serviço não encontrado: {0}")]
    NotFound(String),
    #[error("assinatura ou identidade inválida no registro")]
    InvalidSignature,
    #[error("registro corrompido ou incompatível: {0}")]
    InvalidRegistry(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Privacy {
    Local,
    Private,
    Public,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    Data,
    Compute,
    Site,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportPolicy {
    LocalOnly,
    AuthenticatedMesh,
    PublicMesh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPolicy {
    OwnerOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicy {
    /// Desejado, não é uma afirmação de que réplicas já foram disponibilizadas.
    pub target_replicas: u8,
    /// Obrigatório para conteúdo privado antes de sair do host.
    pub encryption_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceManifest {
    pub protocol_version: u16,
    /// Identificador estável (owner + name) independente das revisões do manifesto.
    pub service_id: ContentId,
    pub owner: NodeId,
    pub name: String,
    pub kind: ServiceKind,
    pub privacy: Privacy,
    pub storage: StoragePolicy,
    pub transport: TransportPolicy,
    pub execution: ExecutionPolicy,
    /// Identidades permitidas; não são senhas, nem grants de rede em vigor.
    pub permitted_nodes: Vec<NodeId>,
}

impl ServiceManifest {
    pub fn service_id_for(owner: NodeId, name: &str) -> ContentId {
        let mut b = Vec::with_capacity(SERVICE_DOMAIN.len() + 32 + name.len() + 8);
        b.extend_from_slice(SERVICE_DOMAIN);
        b.extend_from_slice(&owner.0);
        b.extend_from_slice(&(name.len() as u64).to_be_bytes());
        b.extend_from_slice(name.as_bytes());
        ContentId::of(&b)
    }

    pub fn validate(&self) -> Result<(), HabitatError> {
        let valid_name = !self.name.is_empty()
            && self.name.len() <= 64
            && self
                .name
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            && !self.name.starts_with('-')
            && !self.name.ends_with('-');
        if !valid_name {
            return Err(HabitatError::Policy(
                "nome deve ter 1..64 caracteres [a-z0-9-], sem '-' nas pontas".into(),
            ));
        }
        if self.protocol_version != 1
            || self.service_id != Self::service_id_for(self.owner, &self.name)
        {
            return Err(HabitatError::Policy("versão ou service_id inválido".into()));
        }
        if !(1..=9).contains(&self.storage.target_replicas) {
            return Err(HabitatError::Policy(
                "target_replicas deve estar entre 1 e 9".into(),
            ));
        }
        if self.permitted_nodes.len() > 8
            || self.permitted_nodes.contains(&self.owner)
            || self.permitted_nodes.iter().any(|n| n.0 == [0; 32])
            || self.permitted_nodes.iter().collect::<BTreeSet<_>>().len()
                != self.permitted_nodes.len()
        {
            return Err(HabitatError::Policy(
                "permitted_nodes inválidos, duplicados ou em excesso".into(),
            ));
        }
        if self.execution != ExecutionPolicy::OwnerOnly {
            return Err(HabitatError::Policy(
                "execução remota não disponível nesta fase".into(),
            ));
        }
        match self.privacy {
            Privacy::Local
                if self.transport == TransportPolicy::LocalOnly
                    && self.storage.target_replicas == 1
                    && self.permitted_nodes.is_empty() => {}
            Privacy::Private
                if self.transport == TransportPolicy::AuthenticatedMesh
                    && self.storage.encryption_required
                    && usize::from(self.storage.target_replicas)
                        <= self.permitted_nodes.len() + 1 => {}
            Privacy::Public
                if self.transport == TransportPolicy::PublicMesh
                    && self.permitted_nodes.is_empty() => {}
            _ => {
                return Err(HabitatError::Policy(
                    "visibilidade, transporte, cifra, réplicas e permissões incompatíveis".into(),
                ))
            }
        }
        Ok(())
    }

    /// Decisão apenas para o *manifesto*. Não autoriza leitura do conteúdo
    /// nem bypass de política de tráfego: essas ações precisam de gates próprios.
    pub fn may_view_manifest(&self, requester: NodeId) -> bool {
        requester == self.owner
            || match self.privacy {
                Privacy::Local => false,
                Privacy::Private => self.permitted_nodes.contains(&requester),
                Privacy::Public => true,
            }
    }

    fn signed_payload(&self) -> Result<Vec<u8>, HabitatError> {
        let bytes = serde_json::to_vec(self)?;
        let mut payload = Vec::with_capacity(SIGNING_DOMAIN.len() + bytes.len());
        payload.extend_from_slice(SIGNING_DOMAIN);
        payload.extend_from_slice(&bytes);
        Ok(payload)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceManifest {
    pub manifest: ServiceManifest,
    pub owner_public_key: [u8; 32],
    pub signature: Vec<u8>,
}

impl SignedServiceManifest {
    pub fn sign(manifest: ServiceManifest, gland: &Gland) -> Result<Self, HabitatError> {
        manifest.validate()?;
        if manifest.owner != gland.node_id() {
            return Err(HabitatError::Policy(
                "somente o proprietário pode assinar o manifesto".into(),
            ));
        }
        let signature = gland.sign_bytes(&manifest.signed_payload()?);
        let item = Self {
            manifest,
            owner_public_key: gland.verifying_key().to_bytes(),
            signature,
        };
        item.verify()?;
        Ok(item)
    }

    pub fn verify(&self) -> Result<(), HabitatError> {
        self.manifest.validate()?;
        if NodeId::derive(&self.owner_public_key) != self.manifest.owner {
            return Err(HabitatError::InvalidSignature);
        }
        let key = VerifyingKey::from_bytes(&self.owner_public_key)
            .map_err(|_| HabitatError::InvalidSignature)?;
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| HabitatError::InvalidSignature)?;
        key.verify(&self.manifest.signed_payload()?, &signature)
            .map_err(|_| HabitatError::InvalidSignature)
    }

    pub fn manifest_cid(&self) -> Result<ContentId, HabitatError> {
        Ok(ContentId::of(&self.manifest.signed_payload()?))
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    protocol_version: u16,
    services: BTreeMap<String, SignedServiceManifest>,
}

/// Escritor único é o daemon, através do control socket local.
pub struct HabitatRegistry {
    path: PathBuf,
    owner: NodeId,
    services: BTreeMap<String, SignedServiceManifest>,
}

impl HabitatRegistry {
    pub fn open(home: impl AsRef<Path>, gland: &Gland) -> Result<Self, HabitatError> {
        let dir = home.as_ref().join("habitat");
        fs::create_dir_all(&dir)?;
        if fs::symlink_metadata(&dir)?.file_type().is_symlink() {
            return Err(HabitatError::InvalidRegistry("diretório é symlink".into()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        let path = dir.join("services.json");
        let owner = gland.node_id();
        let services = if path.exists() {
            if fs::symlink_metadata(&path)?.file_type().is_symlink() {
                return Err(HabitatError::InvalidRegistry("índice é symlink".into()));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    return Err(HabitatError::InvalidRegistry(
                        "índice legível por grupo/outros".into(),
                    ));
                }
            }
            let bytes = fs::read(&path)?;
            let file: RegistryFile = serde_json::from_slice(&bytes)?;
            if file.protocol_version != 1 {
                return Err(HabitatError::InvalidRegistry("versão desconhecida".into()));
            }
            for (name, item) in &file.services {
                if name != &item.manifest.name || item.manifest.owner != owner {
                    return Err(HabitatError::InvalidRegistry(
                        "registro de outro proprietário".into(),
                    ));
                }
                item.verify()?;
            }
            file.services
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            path,
            owner,
            services,
        })
    }

    pub fn register(
        &mut self,
        gland: &Gland,
        name: String,
        kind: ServiceKind,
        privacy: Privacy,
        replicas: u8,
        permitted_nodes: Vec<NodeId>,
    ) -> Result<SignedServiceManifest, HabitatError> {
        if gland.node_id() != self.owner {
            return Err(HabitatError::Policy(
                "proprietário do registro diferente".into(),
            ));
        }
        if self.services.contains_key(&name) {
            return Err(HabitatError::Exists(name));
        }
        let transport = match privacy {
            Privacy::Local => TransportPolicy::LocalOnly,
            Privacy::Private => TransportPolicy::AuthenticatedMesh,
            Privacy::Public => TransportPolicy::PublicMesh,
        };
        let manifest = ServiceManifest {
            protocol_version: 1,
            service_id: ServiceManifest::service_id_for(self.owner, &name),
            owner: self.owner,
            name: name.clone(),
            kind,
            privacy,
            storage: StoragePolicy {
                target_replicas: replicas,
                encryption_required: privacy != Privacy::Public,
            },
            transport,
            execution: ExecutionPolicy::OwnerOnly,
            permitted_nodes,
        };
        let signed = SignedServiceManifest::sign(manifest, gland)?;
        self.services.insert(name.clone(), signed.clone());
        if let Err(error) = self.save() {
            self.services.remove(&name);
            return Err(error);
        }
        Ok(signed)
    }

    pub fn get(&self, name: &str) -> Result<SignedServiceManifest, HabitatError> {
        self.services
            .get(name)
            .cloned()
            .ok_or_else(|| HabitatError::NotFound(name.into()))
    }

    pub fn list(&self) -> Vec<SignedServiceManifest> {
        self.services.values().cloned().collect()
    }

    fn save(&self) -> Result<(), HabitatError> {
        let content = serde_json::to_vec_pretty(&RegistryFile {
            protocol_version: 1,
            services: self.services.clone(),
        })?;
        let dir = self
            .path
            .parent()
            .ok_or_else(|| HabitatError::InvalidRegistry("sem diretório".into()))?;
        let tmp = dir.join(format!(".services-{:016x}.tmp", rand::random::<u64>()));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut writer = opts.open(&tmp)?;
        let result = (|| -> Result<(), HabitatError> {
            writer.write_all(&content)?;
            writer.sync_all()?;
            fs::rename(&tmp, &self.path)?;
            #[cfg(unix)]
            fs::File::open(dir)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner() -> Gland {
        Gland::from_seed([0x51; 32])
    }
    fn peer(b: u8) -> NodeId {
        NodeId::derive(&[b; 32])
    }

    #[test]
    fn local_registry_roundtrip_is_signed_and_private() {
        let tmp = tempfile::tempdir().unwrap();
        let gland = owner();
        let mut reg = HabitatRegistry::open(tmp.path(), &gland).unwrap();
        let signed = reg
            .register(
                &gland,
                "meu-servico".into(),
                ServiceKind::Data,
                Privacy::Local,
                1,
                vec![],
            )
            .unwrap();
        assert!(signed.verify().is_ok());
        assert!(!signed.manifest.may_view_manifest(peer(4)));
        assert!(signed.manifest.may_view_manifest(gland.node_id()));
        assert_eq!(signed.manifest.storage.target_replicas, 1);
        let restored = HabitatRegistry::open(tmp.path(), &gland).unwrap();
        assert_eq!(restored.get("meu-servico").unwrap(), signed);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = fs::metadata(tmp.path().join("habitat/services.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(perm, 0o600);
        }
    }

    #[test]
    fn private_replicas_require_explicit_authorized_nodes() {
        let tmp = tempfile::tempdir().unwrap();
        let gland = owner();
        let mut reg = HabitatRegistry::open(tmp.path(), &gland).unwrap();
        assert!(reg
            .register(
                &gland,
                "private".into(),
                ServiceKind::Data,
                Privacy::Private,
                2,
                vec![]
            )
            .is_err());
        let item = reg
            .register(
                &gland,
                "private".into(),
                ServiceKind::Data,
                Privacy::Private,
                2,
                vec![peer(9)],
            )
            .unwrap();
        assert!(item.manifest.may_view_manifest(peer(9)));
        assert!(!item.manifest.may_view_manifest(peer(10)));
        assert!(item.manifest.storage.encryption_required);
        assert!(reg
            .register(
                &gland,
                "private".into(),
                ServiceKind::Data,
                Privacy::Private,
                2,
                vec![peer(9)]
            )
            .is_err());
    }

    #[test]
    fn rejects_owner_spoofing_and_mutation_of_signed_policy() {
        let gland = owner();
        let manifest = ServiceManifest {
            protocol_version: 1,
            service_id: ServiceManifest::service_id_for(gland.node_id(), "demo"),
            owner: gland.node_id(),
            name: "demo".into(),
            kind: ServiceKind::Site,
            privacy: Privacy::Public,
            storage: StoragePolicy {
                target_replicas: 1,
                encryption_required: false,
            },
            transport: TransportPolicy::PublicMesh,
            execution: ExecutionPolicy::OwnerOnly,
            permitted_nodes: vec![],
        };
        let mut signed = SignedServiceManifest::sign(manifest.clone(), &gland).unwrap();
        signed.manifest.privacy = Privacy::Private;
        assert!(signed.verify().is_err());
        let other = Gland::from_seed([0x52; 32]);
        assert!(SignedServiceManifest::sign(manifest, &other).is_err());
    }

    #[test]
    fn tampered_file_refuses_to_load_without_resetting_state() {
        let tmp = tempfile::tempdir().unwrap();
        let gland = owner();
        let mut reg = HabitatRegistry::open(tmp.path(), &gland).unwrap();
        reg.register(
            &gland,
            "demo".into(),
            ServiceKind::Compute,
            Privacy::Local,
            1,
            vec![],
        )
        .unwrap();
        let path = tmp.path().join("habitat/services.json");
        let mut data: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        data["services"]["demo"]["manifest"]["kind"] = serde_json::json!("site");
        fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
        assert!(matches!(
            HabitatRegistry::open(tmp.path(), &gland),
            Err(HabitatError::InvalidSignature)
        ));
        assert!(path.exists());
    }

    #[test]
    fn prohibits_unintended_replication_and_bad_names() {
        let tmp = tempfile::tempdir().unwrap();
        let gland = owner();
        let mut reg = HabitatRegistry::open(tmp.path(), &gland).unwrap();
        for name in ["../secret", "UPPER", "two words", "-bad", "bad-", ""] {
            assert!(reg
                .register(
                    &gland,
                    name.into(),
                    ServiceKind::Data,
                    Privacy::Local,
                    1,
                    vec![]
                )
                .is_err());
        }
        assert!(reg
            .register(
                &gland,
                "local".into(),
                ServiceKind::Data,
                Privacy::Local,
                2,
                vec![]
            )
            .is_err());
        assert!(reg
            .register(
                &gland,
                "duplicates".into(),
                ServiceKind::Data,
                Privacy::Private,
                2,
                vec![peer(9), peer(9)]
            )
            .is_err());
        let public = reg
            .register(
                &gland,
                "public".into(),
                ServiceKind::Site,
                Privacy::Public,
                1,
                vec![],
            )
            .unwrap();
        assert!(public.manifest.may_view_manifest(peer(1)));
        // A descrição pública continua só no disco local — não é publicada.
        assert_eq!(reg.list().len(), 1);
    }
}
