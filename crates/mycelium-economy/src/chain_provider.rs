//! Pinned chain providers for the read-only Base adapter.
//!
//! "It is on localhost" is not an identity. Any process able to bind a free
//! loopback port can serve synthetic chain answers and drive the legitimate
//! verification path into a genuine `proof_verified: true` receipt without
//! forging a single signature: it only has to replace the source of truth.
//!
//! The endpoint therefore never comes from argv. It is pinned out-of-band (the
//! payment policy file written at `create_new` time) and its identity has to be
//! enforceable by the kernel. A Unix domain socket at a fixed path is the only
//! local transport with that property: `connect(2)` is gated on the ownership
//! and permission bits of the socket inode, which a TCP port never is.
//!
//! This module pins and validates; it does not speak JSON-RPC. The transport
//! itself lives in [`crate::base_usdc`].

use crate::{EconomyError, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
};

/// Development/test-only override. A production deployment pins the provider
/// in the payment policy file instead; this variable is never read from a
/// service unit, and it can select a loopback HTTP endpoint, which has no
/// verifiable identity.
pub const DEV_PROVIDER_ENV: &str = "MYCELIUM_DEV_BASE_PROVIDER";

/// Canonical spelling of the default pinned provider.
pub const DEFAULT_PROVIDER_SOCKET_URI: &str = "unix:///run/mycelium-verifier.sock";
/// Filesystem path of the default pinned provider.
pub const DEFAULT_PROVIDER_SOCKET_PATH: &str = "/run/mycelium-verifier.sock";

/// UID that must own the socket when the pin does not name one. A dedicated
/// verifier service runs as root; a socket owned by an unprivileged uid is
/// only trustworthy when the operator says so explicitly in the pin.
pub const DEFAULT_PROVIDER_SOCKET_UID: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainTransport {
    /// Unix domain socket. Identity is enforced by the kernel via the socket
    /// inode ownership/permissions.
    UnixSocket,
    /// Loopback HTTP/TCP. Reachable by anything on the host that can bind the
    /// port, therefore never usable as a policy pin.
    LoopbackHttp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedChainProvider {
    pub transport: ChainTransport,
    /// Canonical endpoint string, e.g. `unix:///run/mycelium-verifier.sock`.
    pub endpoint: String,
    /// UID that must own the socket. `None` means root.
    #[serde(default)]
    pub socket_owner_uid: Option<u32>,
}

impl PinnedChainProvider {
    pub fn unix_socket(path: impl AsRef<Path>, socket_owner_uid: Option<u32>) -> Result<Self> {
        let path = path.as_ref();
        let endpoint = canonical_socket_uri(path)?;
        Ok(Self {
            transport: ChainTransport::UnixSocket,
            endpoint,
            socket_owner_uid,
        })
    }

    /// Parses an operator-supplied spec.
    ///
    /// Accepted: `unix:///abs/path`, `unix:/abs/path`, a bare absolute path, or
    /// a loopback HTTP(S) URL. Everything else is rejected. Loopback HTTP is
    /// accepted here because this parser is also used for the dev-only
    /// environment override; [`Self::validate_policy_pin`] is what keeps it
    /// out of the payment policy.
    pub fn parse(spec: &str, socket_owner_uid: Option<u32>) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(EconomyError::Invalid(
                "chain provider spec cannot be empty".into(),
            ));
        }
        if let Some(path) = spec
            .strip_prefix("unix://")
            .or_else(|| spec.strip_prefix("unix:"))
        {
            return Self::unix_socket(Path::new(path), socket_owner_uid);
        }
        if spec.starts_with('/') {
            return Self::unix_socket(Path::new(spec), socket_owner_uid);
        }
        if is_loopback_http(spec) {
            if socket_owner_uid.is_some() {
                return Err(EconomyError::Invalid(
                    "socket owner uid is meaningless for a loopback HTTP provider".into(),
                ));
            }
            return Ok(Self {
                transport: ChainTransport::LoopbackHttp,
                endpoint: spec.to_ascii_lowercase(),
                socket_owner_uid: None,
            });
        }
        Err(EconomyError::Invalid(format!(
            "chain provider must be a unix socket path ({DEFAULT_PROVIDER_SOCKET_URI}) \
             or a loopback HTTP endpoint; got {spec}"
        )))
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn transport(&self) -> ChainTransport {
        self.transport
    }

    /// True when the endpoint's identity is enforced by the kernel.
    pub fn identity_kernel_enforced(&self) -> bool {
        self.transport == ChainTransport::UnixSocket
    }

    pub fn socket_path(&self) -> Result<PathBuf> {
        match self.transport {
            ChainTransport::UnixSocket => Ok(PathBuf::from(
                self.endpoint
                    .strip_prefix("unix://")
                    .unwrap_or(&self.endpoint),
            )),
            ChainTransport::LoopbackHttp => Err(EconomyError::Invalid(format!(
                "pinned provider is not a unix socket: {}",
                self.endpoint
            ))),
        }
    }

    pub fn socket_owner_uid_or_default(&self) -> u32 {
        self.socket_owner_uid.unwrap_or(DEFAULT_PROVIDER_SOCKET_UID)
    }

    /// Syntax-only re-validation, applied whenever a pin crosses a trust
    /// boundary (policy file load). Catches a hand-edited policy file.
    pub fn validate_shape(&self) -> Result<()> {
        match self.transport {
            ChainTransport::UnixSocket => {
                let path = self.socket_path()?;
                canonical_socket_uri(&path)?;
            }
            ChainTransport::LoopbackHttp => {
                if !is_loopback_http(&self.endpoint) {
                    return Err(EconomyError::Invalid(format!(
                        "chain provider is not a loopback endpoint: {}",
                        self.endpoint
                    )));
                }
                if self.socket_owner_uid.is_some() {
                    return Err(EconomyError::Invalid(
                        "loopback chain provider cannot pin a socket owner uid".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// A payment policy pin must be a unix socket. A loopback TCP port is an
    /// address, not an identity: pinning it would only move the attacker from
    /// "bind 8546" to "bind whatever the operator pinned".
    pub fn validate_policy_pin(&self) -> Result<()> {
        self.validate_shape()?;
        if !self.identity_kernel_enforced() {
            return Err(EconomyError::Invalid(format!(
                "payment policy provider pin must be a unix socket with kernel-checked \
                 ownership ({DEFAULT_PROVIDER_SOCKET_URI}); a loopback TCP endpoint has \
                 no verifiable identity: {}",
                self.endpoint
            )));
        }
        Ok(())
    }

    /// Kernel-enforced identity check, run before the verifier opens the
    /// socket.
    pub fn verify_socket_identity(&self) -> Result<()> {
        let path = self.socket_path()?;
        let display = path.display();
        // lstat, not stat: the ownership check must apply to the inode the
        // verifier actually connects to, so a symlink is refused outright.
        let meta = fs::symlink_metadata(&path).map_err(|e| {
            EconomyError::Invalid(format!(
                "pinned chain provider socket {display} is unusable: {e}"
            ))
        })?;
        if meta.file_type().is_symlink() {
            return Err(EconomyError::Invalid(format!(
                "pinned chain provider socket {display} is a symlink; ownership of the \
                 target would not be checkable here"
            )));
        }
        if !meta.file_type().is_socket() {
            return Err(EconomyError::Invalid(format!(
                "pinned chain provider socket {display} is not a unix socket"
            )));
        }
        let mode = meta.mode() & 0o7777;
        if mode & 0o022 != 0 {
            return Err(EconomyError::Invalid(format!(
                "pinned chain provider socket {display} is group/other-writable \
                 (mode {mode:04o}); connect(2) must stay owner-only"
            )));
        }
        let expected = self.socket_owner_uid_or_default();
        if meta.uid() != expected {
            return Err(EconomyError::Invalid(format!(
                "pinned chain provider socket {display} is owned by uid {}, expected uid {expected}",
                meta.uid()
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSource {
    /// [`DEV_PROVIDER_ENV`], explicit opt-in for development and tests.
    DevEnvOverride,
    /// The payment policy file, written out-of-band at create_new time.
    PolicyPin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedChainProvider {
    pub provider: PinnedChainProvider,
    pub source: ProviderSource,
}

impl ResolvedChainProvider {
    pub fn identity_kernel_enforced(&self) -> bool {
        self.provider.identity_kernel_enforced()
    }

    pub fn is_dev_override(&self) -> bool {
        self.source == ProviderSource::DevEnvOverride
    }

    /// The pinned provider underneath the resolution, so a caller that needs to
    /// describe the identity to something outside this crate — P4b's
    /// `ProviderIdentityConstraints`, which is what a signed policy is scoped to
    /// — does not have to re-parse the spec.
    ///
    /// Additive and deliberately plain: the resolved value *is* a pinned
    /// provider plus where it came from. A caller that scopes a policy to this
    /// should still check [`Self::identity_kernel_enforced`] first, because a
    /// dev override resolves to a `PinnedChainProvider` whose identity is an
    /// address rather than an identity.
    pub fn as_pinned(&self) -> &PinnedChainProvider {
        &self.provider
    }
}

/// Resolution order, and the only one there is:
///
/// 1. [`DEV_PROVIDER_ENV`], when set to a non-empty value. Development/test
///    only, and the only way to select a loopback HTTP endpoint.
/// 2. The provider pinned in the payment policy file.
/// 3. Otherwise refuse. There is no default endpoint and no fallback: a
///    verifier with no pinned source of truth is the `vacuum`
///    `IsolationUnavailable` case, not something to degrade around.
pub fn resolve(
    dev_override: Option<&str>,
    policy_pin: Option<&PinnedChainProvider>,
) -> Result<ResolvedChainProvider> {
    if let Some(spec) = dev_override.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(ResolvedChainProvider {
            provider: PinnedChainProvider::parse(spec, None)?,
            source: ProviderSource::DevEnvOverride,
        });
    }
    match policy_pin {
        Some(pin) => {
            pin.validate_policy_pin()?;
            Ok(ResolvedChainProvider {
                provider: pin.clone(),
                source: ProviderSource::PolicyPin,
            })
        }
        None => Err(EconomyError::ProviderUnpinned(format!(
            "no pinned Base provider. Pin one out-of-band with \
             `mycelium-economy --home DIR payment-policy-pin-provider \
             {DEFAULT_PROVIDER_SOCKET_URI}` (the verifier service must own that \
             path as uid {DEFAULT_PROVIDER_SOCKET_UID}), or set {DEV_PROVIDER_ENV} \
             for tests only. There is no default endpoint."
        ))),
    }
}

fn canonical_socket_uri(path: &Path) -> Result<String> {
    if !path.is_absolute() {
        return Err(EconomyError::Invalid(format!(
            "chain provider socket path must be absolute: {}",
            path.display()
        )));
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(EconomyError::Invalid(format!(
            "chain provider socket path cannot contain '..': {}",
            path.display()
        )));
    }
    let endpoint = format!("unix://{}", path.display());
    if endpoint.contains('\0') {
        return Err(EconomyError::Invalid(
            "chain provider socket path contains a NUL byte".into(),
        ));
    }
    Ok(endpoint)
}

/// The pre-existing loopback guard. Kept verbatim as the transport rule for the
/// read-only verifier: a non-loopback endpoint is refused even when an
/// operator pins it. Loopback remains *necessary* and no longer *sufficient*.
fn is_loopback_http(url: &str) -> bool {
    url.starts_with("http://127.0.0.1:")
        || url.starts_with("https://127.0.0.1:")
        || url.starts_with("http://localhost:")
        || url.starts_with("https://localhost:")
        || url.starts_with("http://[::1]:")
        || url.starts_with("https://[::1]:")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_test_server::FakeRpcSocket;

    #[test]
    fn missing_provider_fails_closed() {
        let err = resolve(None, None).unwrap_err();
        assert!(matches!(err, EconomyError::ProviderUnpinned(_)));
        let msg = err.to_string();
        assert!(msg.contains("no pinned Base provider"));
        assert!(msg.contains("payment-policy-pin-provider"));
        assert!(msg.contains(DEV_PROVIDER_ENV));
    }

    #[test]
    fn empty_dev_override_does_not_count_as_configuration() {
        assert!(matches!(
            resolve(Some("   "), None).unwrap_err(),
            EconomyError::ProviderUnpinned(_)
        ));
    }

    #[test]
    fn dev_override_takes_precedence_over_policy_pin() {
        let policy = PinnedChainProvider::unix_socket(
            DEFAULT_PROVIDER_SOCKET_PATH,
            Some(7),
        )
        .unwrap();
        let resolved =
            resolve(Some("http://127.0.0.1:8546"), Some(&policy)).unwrap();
        assert_eq!(resolved.source, ProviderSource::DevEnvOverride);
        assert!(resolved.is_dev_override());
        assert!(!resolved.identity_kernel_enforced());
    }

    #[test]
    fn policy_pin_is_used_when_no_override_is_set() {
        let policy = PinnedChainProvider::unix_socket(
            DEFAULT_PROVIDER_SOCKET_PATH,
            Some(7),
        )
        .unwrap();
        let resolved = resolve(None, Some(&policy)).unwrap();
        assert_eq!(resolved.source, ProviderSource::PolicyPin);
        assert!(resolved.identity_kernel_enforced());
        assert_eq!(resolved.provider.socket_path().unwrap(), PathBuf::from(DEFAULT_PROVIDER_SOCKET_PATH));
    }

    #[test]
    fn loopback_http_can_never_be_a_policy_pin() {
        let loopback = PinnedChainProvider::parse("http://127.0.0.1:8546", None).unwrap();
        assert_eq!(loopback.transport(), ChainTransport::LoopbackHttp);
        assert!(!loopback.identity_kernel_enforced());
        let err = resolve(None, Some(&loopback)).unwrap_err();
        assert!(err.to_string().contains("no verifiable identity"));
    }

    #[test]
    fn hand_edited_policy_pin_cannot_smuggle_a_remote_endpoint() {
        let forged = PinnedChainProvider {
            transport: ChainTransport::UnixSocket,
            endpoint: "http://attacker.example:8546".into(),
            socket_owner_uid: Some(0),
        };
        assert!(forged.validate_policy_pin().is_err());
        let forged = PinnedChainProvider {
            transport: ChainTransport::LoopbackHttp,
            endpoint: "http://10.0.0.5:8546".into(),
            socket_owner_uid: None,
        };
        assert!(forged.validate_policy_pin().is_err());
    }

    #[test]
    fn non_loopback_and_relative_endpoints_are_rejected() {
        assert!(PinnedChainProvider::parse("https://example.com", None).is_err());
        assert!(PinnedChainProvider::parse("http://192.168.0.1:8546", None).is_err());
        assert!(PinnedChainProvider::parse("unix://relative/path.sock", None).is_err());
        assert!(PinnedChainProvider::parse("unix:///run/../run/x.sock", None).is_err());
        assert!(PinnedChainProvider::parse("", None).is_err());
    }

    #[test]
    fn unix_socket_specs_are_canonicalised() {
        let pin = PinnedChainProvider::parse("unix:/run/a.sock", Some(3)).unwrap();
        assert_eq!(pin.endpoint(), "unix:///run/a.sock");
        assert_eq!(pin.transport(), ChainTransport::UnixSocket);
        assert_eq!(pin.socket_path().unwrap(), PathBuf::from("/run/a.sock"));
        assert_eq!(pin.socket_owner_uid_or_default(), 3);
        let bare = PinnedChainProvider::parse("/run/a.sock", None).unwrap();
        assert_eq!(bare.endpoint(), "unix:///run/a.sock");
        assert_eq!(bare.socket_owner_uid_or_default(), DEFAULT_PROVIDER_SOCKET_UID);
    }

    #[test]
    fn socket_identity_rejects_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-socket");
        fs::write(&path, b"x").unwrap();
        let pin = PinnedChainProvider::unix_socket(&path, None).unwrap();
        let err = pin.verify_socket_identity().unwrap_err();
        assert!(err.to_string().contains("not a unix socket"));
    }

    #[test]
    fn socket_identity_rejects_a_missing_socket() {
        let dir = tempfile::tempdir().unwrap();
        let pin = PinnedChainProvider::unix_socket(dir.path().join("absent.sock"), None).unwrap();
        let err = pin.verify_socket_identity().unwrap_err();
        assert!(err.to_string().contains("unusable"));
    }

    #[test]
    fn socket_identity_rejects_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = FakeRpcSocket::bind(dir.path().join("real.sock"));
        let link = dir.path().join("link.sock");
        std::os::unix::fs::symlink(real.path(), &link).unwrap();
        let pin = PinnedChainProvider::unix_socket(&link, Some(real.uid())).unwrap();
        let err = pin.verify_socket_identity().unwrap_err();
        assert!(err.to_string().contains("symlink"));
    }

    #[test]
    fn socket_identity_rejects_group_or_other_writable() {
        let dir = tempfile::tempdir().unwrap();
        let server = FakeRpcSocket::bind(dir.path().join("open.sock"));
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(server.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let pin =
            PinnedChainProvider::unix_socket(server.path(), Some(server.uid())).unwrap();
        let err = pin.verify_socket_identity().unwrap_err();
        assert!(err.to_string().contains("group/other-writable"));
    }

    #[test]
    fn socket_identity_rejects_the_wrong_owner() {
        let dir = tempfile::tempdir().unwrap();
        let server = FakeRpcSocket::bind(dir.path().join("owned.sock"));
        let pin = PinnedChainProvider::unix_socket(
            server.path(),
            Some(server.uid().wrapping_add(1)),
        )
        .unwrap();
        let err = pin.verify_socket_identity().unwrap_err();
        assert!(err.to_string().contains("expected uid"));
    }

    #[test]
    fn socket_identity_accepts_a_locked_down_owned_socket() {
        let dir = tempfile::tempdir().unwrap();
        let server = FakeRpcSocket::bind(dir.path().join("good.sock"));
        let pin = PinnedChainProvider::unix_socket(server.path(), Some(server.uid())).unwrap();
        pin.verify_socket_identity().unwrap();
        let root_default =
            PinnedChainProvider::unix_socket(server.path(), None).unwrap();
        assert_eq!(
            root_default.socket_owner_uid_or_default(),
            DEFAULT_PROVIDER_SOCKET_UID
        );
    }
}