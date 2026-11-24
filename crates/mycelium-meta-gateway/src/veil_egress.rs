//! Strict, opt-in TCP egress through a local VEIL SOCKS5 circuit.
//!
//! This connector only establishes SOCKS5 CONNECT with an unresolved domain
//! (ATYP=03). It never resolves the destination locally, never silently
//! connects directly, and does not claim the remote end is an authenticated
//! bank. TLS/mTLS and counterparty authorization remain separate layers.
//! The financial adapters do NOT use network dispatch yet.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::GatewayError;

const EGRESS_TIMEOUT: Duration = Duration::from_secs(5);

/// A SOCKS5 gateway controlled by the local Mycelium daemon.
///
/// This is an I/O connector, not proof of anonymity, bank settlement, or
/// successful transmission of any payment payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VeilEgress {
    proxy: SocketAddr,
}

impl VeilEgress {
    pub fn new(proxy: SocketAddr) -> Result<Self, GatewayError> {
        if !proxy.ip().is_loopback() || proxy.port() == 0 {
            return Err(Self::error("VEIL SOCKS5 must bind a nonzero loopback port"));
        }
        Ok(Self { proxy })
    }

    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy
    }

    fn error(message: &str) -> GatewayError {
        GatewayError::Crypto(format!("veil egress: {message}"))
    }

    /// Only DNS names are accepted: IPs would skip domain-based remote DNS.
    /// Reserved local domains are blocked; the exit must also block resolved
    /// private addresses to prevent DNS rebinding or SSRF.
    fn validate_host(host: &str, port: u16) -> Result<(), GatewayError> {
        if port != 443 {
            return Err(Self::error(
                "financial proxy connector allows HTTPS port 443 only",
            ));
        }
        if host.parse::<IpAddr>().is_ok()
            || host.len() > 253
            || host.len() < 4
            || !host.is_ascii()
            || host.contains(':')
            || host.contains('/')
            || !host.contains('.')
        {
            return Err(Self::error("destination must be a public DNS hostname"));
        }
        let host_lower = host.to_ascii_lowercase();
        if [
            "localhost",
            ".localhost",
            ".local",
            ".internal",
            ".invalid",
            ".test",
            ".example",
        ]
        .iter()
        .any(|suffix| host_lower == *suffix || host_lower.ends_with(suffix))
        {
            return Err(Self::error("local or reserved destination refused"));
        }
        for label in host.split('.') {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(Self::error("invalid domain label"));
            }
        }
        Ok(())
    }

    /// Establish a TCP stream through the local VEIL proxy. The destination
    /// must still be protected by actual TLS/mTLS before sending any data.
    pub async fn connect_tls_endpoint(&self, host: &str) -> Result<TcpStream, GatewayError> {
        Self::validate_host(host, 443)?;
        let host = host.as_bytes().to_vec();
        let io = async {
            let mut stream = TcpStream::connect(self.proxy)
                .await
                .map_err(|e| Self::error(&format!("SOCKS5 proxy unreachable: {e}")))?;
            stream
                .write_all(&[0x05, 0x01, 0x00])
                .await
                .map_err(|e| Self::error(&format!("SOCKS greeting: {e}")))?;
            let mut method = [0u8; 2];
            stream
                .read_exact(&mut method)
                .await
                .map_err(|e| Self::error(&format!("SOCKS greeting response: {e}")))?;
            if method != [0x05, 0x00] {
                return Err(Self::error("SOCKS proxy declined no-auth method"));
            }
            // SOCKS5 ATYP=domain, never local DNS or IP encoding.
            let mut request = Vec::with_capacity(host.len() + 7);
            request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
            request.extend_from_slice(&host);
            request.extend_from_slice(&443u16.to_be_bytes());
            stream
                .write_all(&request)
                .await
                .map_err(|e| Self::error(&format!("SOCKS CONNECT: {e}")))?;
            let mut header = [0u8; 4];
            stream
                .read_exact(&mut header)
                .await
                .map_err(|e| Self::error(&format!("SOCKS response: {e}")))?;
            if header[0] != 0x05 || header[2] != 0x00 {
                return Err(Self::error("malformed SOCKS response"));
            }
            if header[1] != 0 {
                return Err(Self::error("VEIL exit refused or could not connect"));
            }
            let addr_len = match header[3] {
                0x01 => 4,
                0x04 => 16,
                0x03 => {
                    let mut len = [0u8; 1];
                    stream
                        .read_exact(&mut len)
                        .await
                        .map_err(|_| Self::error("truncated SOCKS address"))?;
                    if len[0] == 0 {
                        return Err(Self::error("empty SOCKS reply host"));
                    }
                    len[0] as usize
                }
                _ => return Err(Self::error("unknown SOCKS reply address type")),
            };
            let mut tail = vec![0u8; addr_len + 2];
            stream
                .read_exact(&mut tail)
                .await
                .map_err(|_| Self::error("truncated SOCKS reply"))?;
            Ok(stream)
        };
        timeout(EGRESS_TIMEOUT, io)
            .await
            .map_err(|_| Self::error("SOCKS connection timed out"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn domain_is_forwarded_unresolved_to_veil_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            s.write_all(&[5, 0]).await.unwrap();
            let mut header = [0u8; 5];
            s.read_exact(&mut header).await.unwrap();
            assert_eq!(&header[..4], &[5, 1, 0, 3]);
            let mut domain = vec![0u8; header[4] as usize];
            s.read_exact(&mut domain).await.unwrap();
            assert_eq!(domain, b"psp.payment.example.org");
            let mut port = [0u8; 2];
            s.read_exact(&mut port).await.unwrap();
            assert_eq!(u16::from_be_bytes(port), 443);
            s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                .await
                .unwrap();
            s.write_all(b"mock-transport").await.unwrap();
        });
        let veil = VeilEgress::new(addr).unwrap();
        let mut stream = veil
            .connect_tls_endpoint("psp.payment.example.org")
            .await
            .unwrap();
        let mut message = [0u8; 14];
        stream.read_exact(&mut message).await.unwrap();
        assert_eq!(&message, b"mock-transport");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn denied_socks_connection_never_falls_back_to_direct() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[5, 0]).await.unwrap();
            let mut header = [0u8; 5];
            s.read_exact(&mut header).await.unwrap();
            let mut remaining = vec![0u8; header[4] as usize + 2];
            s.read_exact(&mut remaining).await.unwrap();
            s.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });
        let veil = VeilEgress::new(addr).unwrap();
        assert!(veil
            .connect_tls_endpoint("psp.payment.example.org")
            .await
            .is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn declines_loopback_proxy_absence_and_bad_target() {
        assert!(VeilEgress::new("192.0.2.5:1080".parse().unwrap()).is_err());
        assert!(VeilEgress::new("127.0.0.1:0".parse().unwrap()).is_err());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let veil = VeilEgress::new(addr).unwrap();
        for host in [
            "127.0.0.1",
            "localhost",
            "foo.local",
            "bad..org",
            "foo.org:123",
            "xn--a_.org",
            "2001:db8::1",
        ] {
            assert!(veil.connect_tls_endpoint(host).await.is_err());
        }
        assert!(veil
            .connect_tls_endpoint("psp.payment.example.org")
            .await
            .is_err());
    }
}
