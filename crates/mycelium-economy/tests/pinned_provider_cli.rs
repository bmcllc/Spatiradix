//! End-to-end checks on the CLI trust boundary.
//!
//! The regression these guard is the audit's cheapest real attack: a caller
//! passing a loopback URL as a positional argument and having the verifier
//! treat that endpoint as the source of truth.

use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener},
    },
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;

const BIN: &str = env!("CARGO_BIN_EXE_mycelium-economy");
const DEV_PROVIDER_ENV: &str = "MYCELIUM_DEV_BASE_PROVIDER";

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .arg("--home")
        .arg(home)
        .args(args)
        .env_remove(DEV_PROVIDER_ENV)
        .output()
        .expect("run mycelium-economy")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// A loopback listener that accepts nothing: if the verifier ever connects,
/// the attack succeeded and the test notices.
struct SilentListener {
    port: u16,
    _listener: TcpListener,
}

impl SilentListener {
    fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().unwrap().port();
        listener
            .set_nonblocking(true)
            .expect("set nonblocking");
        Self {
            port,
            _listener: listener,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// True when something actually connected.
    fn contacted(&self) -> bool {
        self._listener.accept().is_ok()
    }
}

/// Minimal read-only JSON-RPC responder on a Unix socket, standing in for the
/// dedicated verifier socket service.
struct SocketService {
    path: std::path::PathBuf,
}

impl SocketService {
    fn bind(dir: &Path, name: &str) -> Self {
        let path = dir.join(name);
        let listener = UnixListener::bind(&path).expect("bind service socket");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut raw = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    let Ok(n) = stream.read(&mut buf) else { break };
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    if String::from_utf8_lossy(&raw).contains("\r\n\r\n") {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&raw).to_string();
                let method = serde_json::from_str::<serde_json::Value>(
                    text.split("\r\n\r\n").nth(1).unwrap_or("{}"),
                )
                .ok()
                .and_then(|v| {
                    v.get("method").and_then(|m| m.as_str()).map(String::from)
                })
                .unwrap_or_default();
                let result = match method.as_str() {
                    "eth_chainId" => serde_json::json!("0x2105"),
                    "eth_blockNumber" => serde_json::json!("0x64"),
                    "eth_getCode" => serde_json::json!("0x6080604052"),
                    _ => serde_json::Value::Null,
                };
                let body = serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "result": result
                })
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self { path }
    }

    fn uri(&self) -> String {
        format!("unix://{}", self.path.display())
    }

    fn uid(&self) -> u32 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(&self.path).unwrap().uid()
    }
}

#[test]
fn rpc_endpoint_as_positional_argument_is_refused_everywhere() {
    let home = tempdir().unwrap();
    let listener = SilentListener::bind();
    let url = listener.url();

    for args in [
        vec!["rpc-check-base", url.as_str()],
        vec![
            "verify-base-usdc",
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            "0x1234567890abcdef1234567890abcdef12345678",
            "1.0",
            url.as_str(),
        ],
        vec![
            "settle-base-usdc",
            "job-1",
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            url.as_str(),
        ],
        vec![
            "payment-instructions",
            "job-1",
            url.as_str(),
        ],
        vec![
            "s1-reconcile-outcome",
            "/tmp/receipt.json",
            "agent-1",
            "opp-1",
            url.as_str(),
        ],
    ] {
        let out = run(home.path(), &args);
        assert!(
            !out.status.success(),
            "{args:?} unexpectedly succeeded: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            stderr(&out).contains("no longer accepts an RPC endpoint"),
            "{args:?} did not explain the removed argument: {}",
            stderr(&out)
        );
    }

    // The heart of the regression: the caller's endpoint was never contacted.
    assert!(
        !listener.contacted(),
        "the verifier connected to the caller-supplied endpoint"
    );
}

#[test]
fn unconfigured_provider_fails_closed_naming_what_to_configure() {
    let home = tempdir().unwrap();
    let out = run(home.path(), &["rpc-check-base"]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("chain provider not pinned"), "{err}");
    assert!(err.contains("payment-policy-pin-provider"), "{err}");
    assert!(err.contains(DEV_PROVIDER_ENV), "{err}");
}

#[test]
fn loopback_url_cannot_be_pinned_as_a_policy_provider() {
    let home = tempdir().unwrap();
    let out = run(home.path(), &[
        "payment-policy-pin-provider",
        "http://127.0.0.1:8546",
    ]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("no verifiable identity"), "{err}");
}

#[test]
fn pinned_unix_socket_provider_serves_rpc_check_base() {
    let home = tempdir().unwrap();
    let service = SocketService::bind(home.path(), "verifier.sock");

    // Pinning is refused when the socket the pin names does not exist.
    let missing = run(
        home.path(),
        &["payment-policy-pin-provider", "unix:///run/absent.sock"],
    );
    assert!(!missing.status.success());
    assert!(stderr(&missing).contains("payment policy"), "{}", stderr(&missing));

    // Provision the policy with the provider pinned at create time.
    let init = run(
        home.path(),
        &[
            "payment-policy-init",
            "0x1234567890abcdef1234567890abcdef12345678",
            "2",
            &service.uri(),
        ],
    );
    assert!(init.status.success(), "{}", stderr(&init));
    let policy: serde_json::Value = serde_json::from_slice(&init.stdout).unwrap();
    assert_eq!(
        policy["chain_provider"]["transport"],
        serde_json::json!("unix_socket")
    );
    assert_eq!(
        policy["chain_provider"]["endpoint"],
        serde_json::json!(service.uri())
    );
    // No explicit owner: the pin defaults to uid 0, so a socket owned by an
    // unprivileged uid does not satisfy it. The kernel check is the point,
    // not a formality over a path string.
    assert_eq!(
        policy["chain_provider"]["socket_owner_uid"],
        serde_json::Value::Null
    );
    let refused = run(home.path(), &["rpc-check-base"]);
    assert!(!refused.status.success());
    let err = stderr(&refused);
    assert!(err.contains("expected uid 0"), "{err}");

    // Re-pinning with the owner named is the operator's explicit decision.
    let pin = run(
        home.path(),
        &[
            "payment-policy-pin-provider",
            &service.uri(),
            &service.uid().to_string(),
        ],
    );
    assert!(pin.status.success(), "{}", stderr(&pin));

    let out = run(home.path(), &["rpc-check-base"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let health: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(health["chain_id"], serde_json::json!(8453));
    assert_eq!(health["provider_identity_verified"], serde_json::json!(true));
    assert_eq!(
        health["broadcast_supported_by_verifier"],
        serde_json::json!(false)
    );
}

#[test]
fn pinning_an_existing_policy_keeps_it_usable() {
    let home = tempdir().unwrap();
    let service = SocketService::bind(home.path(), "verifier.sock");

    let init = run(
        home.path(),
        &["payment-policy-init", "0x1234567890abcdef1234567890abcdef12345678", "2"],
    );
    assert!(init.status.success(), "{}", stderr(&init));

    // No provider yet: fail closed.
    let blocked = run(home.path(), &["rpc-check-base"]);
    assert!(!blocked.status.success());
    assert!(stderr(&blocked).contains("chain provider not pinned"));

    // Pinning an existing policy keeps the payout address and chain id.
    let pin = run(
        home.path(),
        &[
            "payment-policy-pin-provider",
            &service.uri(),
            &service.uid().to_string(),
        ],
    );
    assert!(pin.status.success(), "{}", stderr(&pin));
    let policy: serde_json::Value = serde_json::from_slice(&pin.stdout).unwrap();
    assert_eq!(
        policy["payout_address"],
        serde_json::json!("0x1234567890abcdef1234567890abcdef12345678")
    );
    assert_eq!(policy["chain_id"], serde_json::json!(8453));

    let out = run(home.path(), &["rpc-check-base"]);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn dev_only_override_is_the_only_way_to_use_a_loopback_endpoint() {
    let home = tempdir().unwrap();
    let listener = SilentListener::bind();
    let url = listener.url();

    let out = Command::new(BIN)
        .arg("--home")
        .arg(home.path())
        .args(["rpc-check-base"])
        .env(DEV_PROVIDER_ENV, &url)
        .output()
        .expect("run mycelium-economy");
    // The override is honoured as an explicit opt-in: it attempts the
    // endpoint, which then has nothing to say.
    assert!(!out.status.success());
    assert!(
        !stderr(&out).contains("chain provider not pinned"),
        "{}",
        stderr(&out)
    );
    assert!(listener.contacted(), "the dev override should be attempted");
}