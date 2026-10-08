//! Minimal fake Base JSON-RPC server on a Unix domain socket.
//!
//! Test-only support for [`crate::base_usdc`]: it exercises the real pinned
//! unix-socket transport end to end (socket identity check, minimal HTTP/1.1
//! request, chain-id comparison) without a live node.

use serde_json::{json, Value};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::MetadataExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

/// How long the accept loop sleeps between polls of the non-blocking listener.
///
/// Long enough that an idle socket does not spin a core, short enough that
/// [`FakeRpcSocket`]'s `Drop` observes the stop flag within a millisecond or
/// two and never has to depend on an inbound connection to wake the thread.
const ACCEPT_POLL: Duration = Duration::from_millis(1);

/// How long a single `read` on an accepted connection may block.
///
/// Connections are served INLINE on the one loop thread, so a client that
/// connects and then says nothing parks that thread — and `Drop` joins it, so
/// the park becomes a hang for the whole test binary. 1000 ms is orders of
/// magnitude longer than a local `write` of a few hundred bytes needs (the
/// real client in [`crate::base_usdc`] finishes in microseconds even on a
/// loaded machine), while still bounding the join to about a second per
/// silent client — far below the multi-second budget the tests allow.
///
/// This is a per-READ timeout, not a per-request deadline: a client that drips
/// bytes just under it on every read can still hold the loop. It is a guard
/// against the silent-connect failure mode (a client that connects and never
/// speaks), which is the one that hangs the binary, and not a claim that every
/// conceivable slow client is bounded.
const READ_TIMEOUT: Duration = Duration::from_millis(1000);

pub struct FakeRpcSocket {
    path: PathBuf,
    uid: u32,
    connections: Arc<AtomicU64>,
    methods: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    accept_error: Arc<Mutex<Option<io::Error>>>,
    handle: Option<JoinHandle<()>>,
}

impl FakeRpcSocket {
    /// Serves the three methods `health()` needs, on Base chain id.
    pub fn bind(path: impl AsRef<Path>) -> Self {
        Self::with_responses(
            path,
            vec![
                ("eth_chainId", json!("0x2105")),
                ("eth_blockNumber", json!("0x64")),
                ("eth_getCode", json!("0x6080604052")),
                ("eth_getTransactionReceipt", Value::Null),
            ],
        )
    }

    pub fn with_responses(
        path: impl AsRef<Path>,
        responses: Vec<(&str, Value)>,
    ) -> Self {
        let responses: Vec<(String, Value)> = responses
            .into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect();
        Self::serve(
            path,
            Arc::new(move |method: &str, _params: &Value| {
                responses
                    .iter()
                    .find(|(name, _)| name == method)
                    .map(|(_, value)| value.clone())
            }),
        )
    }

    /// Serves each request from a closure over `(method, params)`, instead of
    /// from a fixed method→response map.
    ///
    /// The fixed map can only ever describe one world, so a socket built with
    /// [`Self::with_responses`] can confirm exactly one transfer: it answers
    /// every `eth_getTransactionReceipt` with the same receipt, and
    /// `BoundaryCrossing::with_verified_proof` requires the proof's
    /// `transaction_hash` to be the crossing's own. A test that needs two
    /// distinct on-chain facts in one ledger — two transactions, or two logs in
    /// one transaction — has to answer per request. Returning `None` is the
    /// `-32601` a missing method gets, so an unknown method is still an error
    /// rather than a null success.
    pub fn with_dispatch(
        path: impl AsRef<Path>,
        handler: impl Fn(&str, &Value) -> Option<Value> + Send + Sync + 'static,
    ) -> Self {
        Self::serve(path, Arc::new(handler))
    }

    fn serve(
        path: impl AsRef<Path>,
        dispatcher: Arc<dyn Fn(&str, &Value) -> Option<Value> + Send + Sync>,
    ) -> Self {
        let path = path.as_ref().to_path_buf();
        let listener = UnixListener::bind(&path).expect("bind fake rpc socket");
        {
            // A real dedicated verifier service sets owner-only permissions on
            // its socket; without this the ambient umask would decide, and the
            // identity check would be testing the umask instead of the pin.
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("lock down fake rpc socket");
        }
        let uid = std::fs::symlink_metadata(&path).expect("stat socket").uid();

        let connections = Arc::new(AtomicU64::new(0));
        let methods = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let accept_error: Arc<Mutex<Option<io::Error>>> = Arc::new(Mutex::new(None));

        // The loop below polls a non-blocking listener rather than parking in
        // `accept`, so it observes the stop flag on its own. This is
        // load-bearing, not an optimisation: `Drop` used to wake a BLOCKING
        // `accept` by connecting to the socket file, and that wake-up fails
        // silently — the `connect` result was discarded — whenever the directory
        // holding the file has already been removed, which is exactly what a
        // harness that declares its `TempDir` before this socket produces. The
        // loop then never woke and `Drop`'s `join` hung forever. Failing loudly
        // here keeps that failure mode from coming back.
        listener
            .set_nonblocking(true)
            .expect("put fake rpc listener in non-blocking mode");

        let handle = {
            let connections = Arc::clone(&connections);
            let methods = Arc::clone(&methods);
            let stop = Arc::clone(&stop);
            let accept_error = Arc::clone(&accept_error);
            thread::spawn(move || {
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            // Checked before the connection is counted, exactly
                            // as the old `incoming()` loop checked it: the
                            // wake-up `connect` in `Drop` must never show up in
                            // `connections()`.
                            if stop.load(Ordering::SeqCst) {
                                break;
                            }
                            // `read_request` reads until the request body is
                            // complete, so the stream it serves has to be a
                            // blocking one whatever the listener's mode is:
                            // a `WouldBlock` mid-body would look like a
                            // truncated request and be answered as silence.
                            let mut stream = stream;
                            if stream.set_nonblocking(false).is_err() {
                                continue;
                            }
                            // ORDER IS LOAD-BEARING, AND IT IS THE WHOLE POINT
                            // OF THIS BLOCK: the read timeout is only honoured
                            // by a BLOCKING stream. With `O_NONBLOCK` still set,
                            // `read` returns `WouldBlock` immediately, so the
                            // kernel never waits on `SO_RCVTIMEO` — the timeout
                            // below would look like it armed successfully while
                            // doing nothing at all, and a silent client would
                            // park this thread anyway. `set_nonblocking(false)`
                            // must therefore stay ABOVE `set_read_timeout`; if
                            // anyone ever reorders these two lines, `Drop`'s
                            // join can hang again.
                            //
                            // Arming it is not best-effort either. A failure here
                            // means the connection cannot be bounded, and
                            // serving an unbounded connection is exactly the hang
                            // this removes, so it is dropped unanswered like any
                            // other unusable connection.
                            if stream.set_read_timeout(Some(READ_TIMEOUT)).is_err() {
                                continue;
                            }
                            connections.fetch_add(1, Ordering::SeqCst);
                            let Some(body) = read_request(&mut stream) else {
                                // `READ_TIMEOUT` expired, the peer reset, or the
                                // client closed before a full body arrived. The
                                // connection is abandoned silently — no response,
                                // no panic, the listener keeps serving — because
                                // the loop is single threaded and has to get back
                                // to `accept` for the next client.
                                continue;
                            };
                            let Ok(request) = serde_json::from_str::<Value>(&body) else {
                                continue;
                            };
                            let method = request
                                .get("method")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string();
                            let params = request
                                .get("params")
                                .cloned()
                                .unwrap_or(Value::Array(Vec::new()));
                            methods.lock().unwrap().push(method.clone());
                            let result = dispatcher(&method, &params);
                            let payload = match result {
                                Some(result) => json!({
                                    "jsonrpc": "2.0", "id": 1, "result": result
                                }),
                                None => json!({
                                    "jsonrpc": "2.0", "id": 1,
                                    "error": {"code": -32601, "message": method}
                                }),
                            };
                            let body = payload.to_string();
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = stream.write_all(response.as_bytes());
                            let _ = stream.flush();
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            // Nothing waiting: the one place the stop flag is
                            // honoured without any help from `Drop`.
                            if stop.load(Ordering::SeqCst) {
                                break;
                            }
                            thread::sleep(ACCEPT_POLL);
                        }
                        Err(e) => {
                            if e.kind() == io::ErrorKind::Interrupted {
                                // A signal arrived mid-syscall. Not a fault,
                                // and no connection was consumed, so just poll
                                // again rather than record it as one.
                                continue;
                            }
                            // Anything else means this listener can no longer
                            // serve. Retrying would spin, and dropping the
                            // error on the floor would leave every later
                            // request unanswered with nothing to show for it,
                            // so it is recorded and readable via
                            // [`Self::accept_error`].
                            *accept_error.lock().unwrap() = Some(e);
                            break;
                        }
                    }
                }
            })
        };

        Self {
            path,
            uid,
            connections,
            methods,
            stop,
            accept_error,
            handle: Some(handle),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// How many clients ever reached this socket. Zero means the verifier
    /// refused before it opened the endpoint.
    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::SeqCst)
    }

    pub fn requested_methods(&self) -> Vec<String> {
        self.methods.lock().unwrap().clone()
    }

    /// The error that stopped the accept loop, if it stopped on one.
    ///
    /// `None` on a socket that served and was stopped normally. `Some` means
    /// the listener stopped accepting for a reason other than the stop flag,
    /// which would otherwise be invisible: every later request would simply
    /// never be answered.
    pub fn accept_error(&self) -> Option<String> {
        self.accept_error
            .lock()
            .unwrap()
            .as_ref()
            .map(|error| error.to_string())
    }
}

impl Drop for FakeRpcSocket {
    fn drop(&mut self) {
        // All the loop actually needs. It polls `stop`, so it exits within
        // ACCEPT_POLL of this store whether or not anything else happens.
        self.stop.store(true, Ordering::SeqCst);
        // Belt and braces: a real inbound connection wakes it at once instead
        // of after the next poll. Strictly best-effort — the socket file is
        // routinely already gone, because a harness is free to declare its
        // `TempDir` ahead of this socket — so the error is discarded on
        // purpose, and it can never be a reason to skip the join.
        let _ = UnixStream::connect(&self.path);
        // The join below is bounded for two independent reasons, and this is
        // the second. The loop polls `stop`, so it leaves `accept` within
        // ACCEPT_POLL of the store above. And it can only be inside a
        // connection's body read for at most READ_TIMEOUT per read, because
        // the accept loop arms that timeout before reading: a client that
        // connects and then says nothing can no longer park this join
        // indefinitely, which is what used to hang the whole test binary.
        // Without READ_TIMEOUT the connect above could not rescue that case —
        // a thread already parked in `read_request` never reaches `accept` to
        // be woken by it.
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Reads one request body, or `None` if the client never delivered one.
///
/// # What the stream must already be
///
/// The accept loop puts every accepted stream into BLOCKING mode and arms
/// [`READ_TIMEOUT`] on it BEFORE calling this, and the order matters — see
/// the comment at that call site. Between them they are what make this loop
/// return: with no timeout a silent client would park the one serving thread,
/// and `Drop` joins that thread.
///
/// A timed-out read is an ordinary read error here: it becomes `None`, and the
/// caller abandons that connection unanswered and moves on. No error kind is
/// matched, which is deliberate — the same `SO_RCVTIMEO` expiry surfaces as
/// `WouldBlock` on Linux and can surface as `TimedOut` elsewhere, and both are
/// simply a read that did not happen.
fn read_request(stream: &mut UnixStream) -> Option<String> {
    let mut raw: Vec<u8> = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&raw).to_string();
        let Some(split) = text.find("\r\n\r\n") else {
            continue;
        };
        let len = content_length(&text[..split]);
        if text.len() >= split + 4 + len {
            return Some(text[split + 4..split + 4 + len].to_string());
        }
    }
    String::from_utf8(raw).ok()
}

fn content_length(head: &str) -> usize {
    head.split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// How long a client of these tests waits for an answer.
    ///
    /// The server serves connections INLINE, so a request behind a silent
    /// connection is not answered until that connection has been abandoned —
    /// i.e. after `READ_TIMEOUT`. This is therefore deliberately larger than
    /// `READ_TIMEOUT`, and it doubles as a bound: a server that never answers
    /// fails the test here with a message instead of hanging the binary.
    const CLIENT_WAIT: Duration = Duration::from_secs(8);

    /// How long `drop_of_a_silent_server` may take.
    ///
    /// Generous on purpose. `READ_TIMEOUT` is 1s, so a correct drop costs about
    /// a second, and this machine may be loaded or thermally throttled; the
    /// assertion under test is "bounded", not "fast". It is only tight enough
    /// to catch the regression, which never returns at all.
    const DROP_BOUND: Duration = Duration::from_secs(5);

    /// An HTTP/1.1 POST carrying `body` as JSON-RPC.
    fn request(body: &str) -> Vec<u8> {
        format!(
            "POST / HTTP/1.1\r\nHost: mycelium-verifier\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// Reads a response to EOF, which is where `Connection: close` puts its end.
    fn read_response(stream: &mut UnixStream) -> String {
        let mut raw = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => raw.extend_from_slice(&buf[..n]),
                Err(e) => panic!(
                    "reading the fake RPC response failed after {} bytes: {e}",
                    raw.len()
                ),
            }
        }
        String::from_utf8_lossy(&raw).to_string()
    }

    /// Connects and sends `method`, returning the raw HTTP response.
    fn call(socket: &Path, method: &str) -> String {
        let mut stream = UnixStream::connect(socket).expect("connect to fake rpc socket");
        stream
            .set_read_timeout(Some(CLIENT_WAIT))
            .expect("bound the client read wait");
        let body = request(&format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{method}\",\"params\":[]}}"
        ));
        stream
            .write_all(&body)
            .expect("write fake rpc request");
        stream.flush().expect("flush fake rpc request");
        read_response(&mut stream)
    }

    /// Connects and sends NOTHING, so the server parks in its body read.
    fn connect_silently(socket: &Path) -> UnixStream {
        UnixStream::connect(socket).expect("connect a silent client")
    }

    /// Waits until the loop has counted `want` connections, i.e. reached the
    /// body read of the last one.
    ///
    /// Bounded on purpose: without this, a loop that never gets that far would
    /// fail by hanging the test binary rather than by an assertion.
    fn wait_for_connections(server: &FakeRpcSocket, want: u64) {
        let deadline = Instant::now() + CLIENT_WAIT;
        while server.connections() < want {
            assert!(
                Instant::now() < deadline,
                "the accept loop counted {} connections, expected {want}",
                server.connections()
            );
            thread::sleep(ACCEPT_POLL);
        }
    }

    /// Drops `server` while `_client` is still connected and silent, and returns
    /// how long the drop took.
    ///
    /// The client must still be OPEN, and the borrow is what enforces it: a
    /// client closed first would give the server's read an EOF, and the test
    /// would pass even with no timeout at all.
    fn drop_of_a_silent_server(server: FakeRpcSocket, _client: &UnixStream) -> Duration {
        let started = Instant::now();
        drop(server);
        started.elapsed()
    }

    #[test]
    fn a_client_that_never_sends_does_not_block_the_server() {
        let dir = tempfile::tempdir().expect("temp dir");
        let server = FakeRpcSocket::bind(dir.path().join("silent.sock"));
        let silent = connect_silently(server.path());
        // Prove the loop really is inside the body read before the drop, or
        // this would pass merely because the connection was never served.
        wait_for_connections(&server, 1);

        let elapsed = drop_of_a_silent_server(server, &silent);

        assert!(
            elapsed < DROP_BOUND,
            "dropping the socket with a silent client attached took {elapsed:?}, \
             which is not bounded: the serving thread is still parked in the \
             body read and the join will never return"
        );
        drop(silent);
    }

    #[test]
    fn a_hung_client_does_not_stop_later_requests_from_being_served() {
        let dir = tempfile::tempdir().expect("temp dir");
        let server = FakeRpcSocket::bind(dir.path().join("hung.sock"));
        let _silent = connect_silently(server.path());
        wait_for_connections(&server, 1);

        // One serving thread, so this is only answered once the silent
        // connection has been abandoned by READ_TIMEOUT. If it is never
        // answered, `call` fails on the client read wait rather than hanging.
        let response = call(server.path(), "eth_chainId");

        assert!(
            response.contains("\"result\":\"0x2105\""),
            "second connection was not answered with the Base chain id: {response}"
        );
        // The silent client contributed nothing but its connection count.
        assert_eq!(server.requested_methods(), vec!["eth_chainId".to_string()]);
        assert_eq!(server.connections(), 2);
        assert_eq!(server.accept_error(), None);
    }

    #[test]
    fn a_normal_request_is_unaffected_by_the_read_timeout() {
        let dir = tempfile::tempdir().expect("temp dir");
        let server = FakeRpcSocket::bind(dir.path().join("normal.sock"));

        let response = call(server.path(), "eth_chainId");

        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "malformed response head: {response}"
        );
        assert!(
            response.contains("\"jsonrpc\":\"2.0\"") && response.contains("\"id\":1"),
            "response is not the documented JSON-RPC envelope: {response}"
        );
        assert!(
            response.contains("\"result\":\"0x2105\""),
            "eth_chainId was not answered with the Base chain id: {response}"
        );
        // Accounting is unchanged: one connection, one method, no accept error.
        assert_eq!(server.connections(), 1);
        assert_eq!(server.requested_methods(), vec!["eth_chainId".to_string()]);
        assert_eq!(server.accept_error(), None);
    }
}