//! Cliente de relays Pkarr (HTTP) com política de transporte fail-closed.
//!
//! Por que relay HTTP e não a Mainline DHT direto: falar UDP com a DHT expõe
//! o IP do nó a centenas de nós desconhecidos, e UDP não passa por SOCKS5 do
//! VEIL/Tor. O relay recebe o pacote **por dentro do circuito** e o grava na
//! DHT por nós; ele vê só a chave cegada e o cifrado, nunca o IP de origem.

use crate::packet::{SignedPacket, MAX_RELAY_PAYLOAD};
use crate::{zbase32, PkarrError};
use rand::seq::SliceRandom;
use std::net::SocketAddr;
use std::time::Duration;

/// Relays públicos padrão do Pkarr (substituíveis; nenhum é autoridade).
pub const DEFAULT_RELAYS: &[&str] = &["https://relay.pkarr.org", "https://pkarr.pubky.org"];
/// Porta padrão do SOCKS5 do VEIL (`mycelium-veil`, `socks5_bind`).
pub const VEIL_SOCKS5_DEFAULT: &str = "127.0.0.1:1080";

#[derive(Clone, Debug)]
pub enum Transport {
    /// Todo tráfego por um SOCKS5 local (VEIL ou Tor), com DNS resolvido do
    /// outro lado (`socks5h`). Único modo que preserva o anonimato.
    Anonymous { socks5: SocketAddr },
    /// Conexão direta: **revela o IP** ao relay. Só para testes/serviço público.
    DirectRevealsIp,
}

pub struct RelayClient {
    http: reqwest::Client,
    relays: Vec<url::Url>,
}

#[derive(Debug)]
pub struct RelayOutcome {
    pub relay: String,
    pub result: Result<(), String>,
}

impl RelayClient {
    pub fn new(relays: &[String], transport: Transport) -> Result<Self, PkarrError> {
        if relays.is_empty() {
            return Err(PkarrError::Policy("nenhum relay configurado".into()));
        }
        let mut parsed = Vec::with_capacity(relays.len());
        for r in relays {
            let u = url::Url::parse(r)
                .map_err(|_| PkarrError::Policy(format!("relay inválido: {r}")))?;
            if u.scheme() != "https" {
                return Err(PkarrError::Policy(format!("relay sem TLS recusado: {r}")));
            }
            if u.query().is_some() || !u.username().is_empty() || u.password().is_some() {
                return Err(PkarrError::Policy(format!(
                    "relay com query/credencial: {r}"
                )));
            }
            parsed.push(u);
        }

        let mut builder = reqwest::Client::builder()
            // ignora HTTP(S)_PROXY do ambiente: o único proxy é o configurado
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(60))
            .timeout(Duration::from_secs(90))
            // sem User-Agent identificável
            .user_agent("");
        if let Transport::Anonymous { socks5 } = transport {
            if !socks5.ip().is_loopback() {
                // O trecho até o proxy não é cifrado: proxy remoto vazaria tudo.
                return Err(PkarrError::Policy(format!(
                    "SOCKS5 precisa ser local (loopback); recusado {socks5}"
                )));
            }
            let proxy = reqwest::Proxy::all(format!("socks5h://{socks5}"))
                .map_err(|e| PkarrError::Policy(format!("proxy: {e}")))?;
            builder = builder.proxy(proxy);
        }
        let http = builder
            .build()
            .map_err(|e| PkarrError::Policy(format!("cliente http: {e}")))?;
        Ok(Self {
            http,
            relays: parsed,
        })
    }

    fn url_for(relay: &url::Url, key: &[u8; 32]) -> String {
        format!(
            "{}/{}",
            relay.as_str().trim_end_matches('/'),
            zbase32::encode(key)
        )
    }

    /// Ordem aleatória a cada chamada: nenhum relay fica sempre "primeiro".
    fn shuffled(&self) -> Vec<url::Url> {
        let mut v = self.relays.clone();
        v.shuffle(&mut rand::thread_rng());
        v
    }

    /// Publica em todos os relays; sucesso se pelo menos um aceitou.
    pub async fn publish(&self, packet: &SignedPacket) -> Result<Vec<RelayOutcome>, PkarrError> {
        packet.verify()?;
        let body = packet.to_relay_payload();
        let mut outcomes = Vec::new();
        for relay in self.shuffled() {
            let url = Self::url_for(&relay, packet.public_key());
            let result = match self
                .http
                .put(&url)
                .header("content-type", "application/pkarr.org/relays#payload")
                .body(body.clone())
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => Ok(()),
                Ok(r) => Err(format!("HTTP {}", r.status())),
                Err(e) => Err(redact(&e)),
            };
            outcomes.push(RelayOutcome {
                relay: relay.to_string(),
                result,
            });
        }
        if outcomes.iter().any(|o| o.result.is_ok()) {
            Ok(outcomes)
        } else {
            Err(PkarrError::AllRelaysFailed(
                outcomes
                    .iter()
                    .map(|o| format!("{}: {}", o.relay, o.result.as_ref().unwrap_err()))
                    .collect::<Vec<_>>()
                    .join("; "),
            ))
        }
    }

    /// Consulta todos os relays e devolve o pacote válido mais recente.
    /// Respostas inválidas (assinatura, tamanho) são descartadas.
    pub async fn resolve(&self, key: &[u8; 32]) -> Result<SignedPacket, PkarrError> {
        let mut best: Option<SignedPacket> = None;
        let mut errors = Vec::new();
        for relay in self.shuffled() {
            let url = Self::url_for(&relay, key);
            match self.fetch(&url).await {
                Ok(bytes) => match SignedPacket::from_relay_payload(key, &bytes) {
                    Ok(p) => {
                        if best
                            .as_ref()
                            .is_none_or(|b| p.timestamp_us() > b.timestamp_us())
                        {
                            best = Some(p);
                        }
                    }
                    Err(e) => errors.push(format!("{relay}: {e}")),
                },
                Err(e) => errors.push(format!("{relay}: {e}")),
            }
        }
        best.ok_or_else(|| PkarrError::NotFound(errors.join("; ")))
    }

    async fn fetch(&self, url: &str) -> Result<Vec<u8>, String> {
        let mut resp = self.http.get(url).send().await.map_err(|e| redact(&e))?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| redact(&e))? {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_RELAY_PAYLOAD {
                return Err("resposta maior que o limite".into());
            }
        }
        Ok(body)
    }
}

/// Mensagem de erro sem URL completa (não registrar chaves consultadas em log).
fn redact(e: &reqwest::Error) -> String {
    let kind = if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "falha de conexão (proxy/relay)"
    } else if e.is_request() {
        "requisição"
    } else {
        "transporte"
    };
    kind.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_is_fail_closed() {
        let relays = vec!["https://relay.pkarr.org".to_string()];
        let remote: SocketAddr = "203.0.113.5:1080".parse().unwrap();
        assert!(RelayClient::new(&relays, Transport::Anonymous { socks5: remote }).is_err());
        let local: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        assert!(RelayClient::new(&relays, Transport::Anonymous { socks5: local }).is_ok());
        let plain = vec!["http://relay.pkarr.org".to_string()];
        assert!(RelayClient::new(&plain, Transport::Anonymous { socks5: local }).is_err());
        assert!(RelayClient::new(&[], Transport::Anonymous { socks5: local }).is_err());
    }
}
