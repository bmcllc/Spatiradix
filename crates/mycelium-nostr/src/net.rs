//! Conexão WebSocket com política de saída do processo.
//!
//! Quando um proxy SOCKS5 está configurado (modo anônimo do daemon, ou
//! `MYCELIUM_SOCKS5` no ambiente), **toda** conexão a relay Nostr passa por ele,
//! com o nome do host resolvido do outro lado (sem DNS local). Não existe
//! fallback para conexão direta: proxy configurado e indisponível = erro.

use std::net::SocketAddr;
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::handshake::client::Response;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Variável de ambiente com o SOCKS5 local (`127.0.0.1:9050`).
pub const SOCKS5_ENV: &str = "MYCELIUM_SOCKS5";

static PROXY: OnceLock<SocketAddr> = OnceLock::new();

/// Fixa o proxy do processo. Só loopback (o trecho até o proxy não é
/// cifrado). Uma vez fixado não muda: chamar de novo com outro endereço é erro.
pub fn set_socks5_proxy(addr: SocketAddr) -> Result<(), String> {
    if !addr.ip().is_loopback() {
        return Err(format!("SOCKS5 precisa ser loopback; recusado {addr}"));
    }
    let current = PROXY.get_or_init(|| addr);
    if *current != addr {
        return Err(format!("SOCKS5 já fixado em {current}"));
    }
    Ok(())
}

/// Proxy em vigor: o fixado no processo, senão `MYCELIUM_SOCKS5`.
/// Valor de ambiente inválido é erro (nunca "ignora e sai direto").
pub fn socks5_proxy() -> Result<Option<SocketAddr>, String> {
    if let Some(p) = PROXY.get() {
        return Ok(Some(*p));
    }
    match std::env::var(SOCKS5_ENV) {
        Ok(v) if !v.trim().is_empty() => {
            let addr: SocketAddr = v
                .trim()
                .parse()
                .map_err(|e| format!("{SOCKS5_ENV} inválido ({v:?}): {e}"))?;
            if !addr.ip().is_loopback() {
                return Err(format!("{SOCKS5_ENV} precisa ser loopback; recusado {addr}"));
            }
            Ok(Some(addr))
        }
        _ => Ok(None),
    }
}

/// Circuitos Tor/VEIL somam segundos de latência a cada conexão nova; os
/// timeouts calibrados para conexão direta estourariam sempre. Com proxy em
/// vigor, cada prazo vira `max(5×, 20 s)`; sem proxy fica igual.
pub fn proxied_timeout(direct: std::time::Duration) -> std::time::Duration {
    match socks5_proxy() {
        Ok(Some(_)) => (direct * 5).max(std::time::Duration::from_secs(20)),
        _ => direct,
    }
}

/// Substituto de `tokio_tungstenite::connect_async` que respeita o proxy
/// e funciona no Android (sem `/etc/resolv.conf` e sem Google DNS).
pub async fn connect_ws(url: &str) -> Result<(WsStream, Response), String> {
    let Some(proxy) = socks5_proxy()? else {
        if std::path::Path::new("/etc/resolv.conf").exists() {
            return tokio_tungstenite::connect_async(url)
                .await
                .map_err(|e| e.to_string());
        }
        let parsed = url::Url::parse(url).map_err(|e| format!("URL inválida: {e}"))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| format!("URL sem host: {url}"))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| format!("URL sem porta conhecida: {url}"))?;
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            let stream = TcpStream::connect(SocketAddr::new(ip, port))
                .await
                .map_err(|e| format!("TCP {host}:{port}: {e}"))?;
            return tokio_tungstenite::client_async_tls_with_config(url, stream, None, None)
                .await
                .map_err(|e| e.to_string());
        }
        let ip = resolve_without_resolv_conf(&host).await?;
        let stream = TcpStream::connect(SocketAddr::new(ip, port))
            .await
            .map_err(|e| format!("TCP {host}:{port}: {e}"))?;
        return tokio_tungstenite::client_async_tls_with_config(url, stream, None, None)
            .await
            .map_err(|e| e.to_string());
    };
    let parsed = url::Url::parse(url).map_err(|e| format!("URL inválida: {e}"))?;
    // ws:// por um proxy anônimo entregaria o conteúdo em claro ao nó de saída.
    if parsed.scheme() != "wss" {
        return Err(format!("modo SOCKS5 exige wss:// (recusado {url})"));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("URL sem host: {url}"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = parsed.port().unwrap_or(443);
    let stream = socks5_connect(proxy, &host, port).await?;
    tokio_tungstenite::client_async_tls_with_config(url, stream, None, None)
        .await
        .map_err(|e| e.to_string())
}

async fn resolve_without_resolv_conf(host: &str) -> Result<std::net::IpAddr, String> {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;

    let cf = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
    if let Ok(resp) = cf.lookup_ip(host).await {
        if let Some(ip) = resp.iter().next() {
            return Ok(ip);
        }
    }
    let q9 = TokioAsyncResolver::tokio(ResolverConfig::quad9(), ResolverOpts::default());
    let resp = q9
        .lookup_ip(host)
        .await
        .map_err(|e| format!("DNS sem resolv.conf ({host}): {e}"))?;
    resp.iter()
        .next()
        .ok_or_else(|| format!("nenhum IP retornado para {host}"))
}

/// Handshake SOCKS5 (RFC 1928) sem autenticação, CONNECT por **nome**
/// (ATYP=3): o proxy resolve o DNS, nada é resolvido localmente.
pub async fn socks5_connect(proxy: SocketAddr, host: &str, port: u16) -> Result<TcpStream, String> {
    let io = |e: std::io::Error| format!("SOCKS5 {proxy}: {e}");
    let host_bytes = host.as_bytes();
    let host_len = u8::try_from(host_bytes.len()).map_err(|_| "host longo demais".to_string())?;
    if host_bytes.is_empty() {
        return Err("host vazio".into());
    }
    let mut s = TcpStream::connect(proxy).await.map_err(io)?;
    s.write_all(&[5, 1, 0]).await.map_err(io)?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await.map_err(io)?;
    if reply != [5, 0] {
        return Err(format!("SOCKS5 {proxy}: método recusado {reply:?}"));
    }
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.extend_from_slice(&[5, 1, 0, 3, host_len]);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.map_err(io)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.map_err(io)?;
    if head[0] != 5 || head[1] != 0 {
        return Err(format!("SOCKS5 {proxy}: CONNECT recusado (código {})", head[1]));
    }
    let skip = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.map_err(io)?;
            l[0] as usize
        }
        t => return Err(format!("SOCKS5 {proxy}: ATYP desconhecido {t}")),
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest).await.map_err(io)?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn socks5_sends_hostname_not_ip() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap();
            assert_eq!(g, [5, 1, 0]);
            s.write_all(&[5, 0]).await.unwrap();
            let mut head = [0u8; 5];
            s.read_exact(&mut head).await.unwrap();
            let mut name = vec![0u8; head[4] as usize + 2];
            s.read_exact(&mut name).await.unwrap();
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            (head[3], String::from_utf8_lossy(&name[..name.len() - 2]).to_string(), u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]))
        });
        socks5_connect(addr, "nos.lol", 443).await.unwrap();
        let (atyp, host, port) = server.await.unwrap();
        assert_eq!((atyp, host.as_str(), port), (3, "nos.lol", 443));
    }

    #[test]
    fn non_loopback_proxy_refused() {
        assert!(set_socks5_proxy("203.0.113.1:9050".parse().unwrap()).is_err());
    }
}
