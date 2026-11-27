//! W10: executable local-only authentication test. No production PSP transport.
use reqwest::{Client, StatusCode};
use serde_json::Value;
use std::{path::Path, time::Duration};
type R<T> = Result<T, Box<dyn std::error::Error>>;
fn client(dir: &Path, identity: Option<&str>, trusted: bool) -> R<Client> {
    let mut b = Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .https_only(true)
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(5));
    if trusted {
        b = b.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            dir.join("ca.crt"),
        )?)?);
    }
    if let Some(name) = identity {
        let mut pem = zeroize::Zeroizing::new(std::fs::read(dir.join(format!("{name}.crt")))?);
        pem.extend_from_slice(&std::fs::read(dir.join(format!("{name}.key")))?);
        b = b.identity(reqwest::Identity::from_pem(&pem)?);
    }
    Ok(b.build()?)
}
async fn token(c: &Client, base: &str, id: &str, scope: &str) -> R<reqwest::Response> {
    Ok(c.post(format!("{base}/lab/oauth/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", id),
            ("scope", scope),
        ])
        .send()
        .await?)
}
async fn get(c: &Client, base: &str, path: &str, t: Option<&str>) -> R<reqwest::Response> {
    let mut r = c.get(format!("{base}{path}"));
    if let Some(t) = t {
        r = r.bearer_auth(t);
    }
    Ok(r.send().await?)
}
async fn take_token(r: reqwest::Response) -> R<String> {
    if r.status() != StatusCode::OK {
        return Err("token refused".into());
    }
    let v: Value = serde_json::from_str(&r.text().await?)?;
    Ok(v["access_token"]
        .as_str()
        .ok_or("missing lab token")?
        .to_owned())
}
fn check(name: &str, actual: bool) -> R<()> {
    if !actual {
        return Err(format!("W10 failed: {name}").into());
    }
    println!("PASS {name}");
    Ok(())
}
#[tokio::main]
async fn main() -> R<()> {
    let mut args = std::env::args().skip(1);
    let port: u16 = args.next().ok_or("missing ephemeral lab port")?.parse()?;
    let dir = std::path::PathBuf::from(args.next().ok_or("missing temp fixture dir")?);
    if args.next().is_some() || port == 0 {
        return Err("invalid lab arguments".into());
    }
    // No host, URL, production endpoint or payment arguments accepted.
    let base = format!("https://127.0.0.1:{port}");
    let a = client(&dir, Some("client-a"), true)?;
    let b = client(&dir, Some("client-b"), true)?;
    let absent = client(&dir, None, true)?;
    let untrusted = client(&dir, Some("client-a"), false)?;
    let foreign = client(&dir, Some("client-foreign"), true)?;
    let path = "/lab/api/cob/fixture";
    check(
        "no-client-cert",
        get(&absent, &base, path, None).await.is_err(),
    )?;
    check(
        "untrusted-server",
        get(&untrusted, &base, path, None).await.is_err(),
    )?;
    check(
        "untrusted-client",
        get(&foreign, &base, path, None).await.is_err(),
    )?;
    check(
        "wrong-client-id",
        token(&a, &base, "lab-b", "lab.cob.read").await?.status() == StatusCode::UNAUTHORIZED,
    )?;
    check(
        "unknown-scope",
        token(&a, &base, "lab-a", "lab.write").await?.status() == StatusCode::BAD_REQUEST,
    )?;
    check(
        "missing-token",
        get(&a, &base, path, None).await?.status() == StatusCode::UNAUTHORIZED,
    )?;
    let t = take_token(token(&a, &base, "lab-a", "lab.cob.read").await?).await?;
    check(
        "token-certificate-binding",
        get(&b, &base, path, Some(&t)).await?.status() == StatusCode::UNAUTHORIZED,
    )?;
    check(
        "unknown-token",
        get(&a, &base, path, Some("invalid-fixture"))
            .await?
            .status()
            == StatusCode::UNAUTHORIZED,
    )?;
    check(
        "ownership",
        get(&a, &base, "/lab/api/cob/other", Some(&t))
            .await?
            .status()
            == StatusCode::FORBIDDEN,
    )?;
    let limited = take_token(token(&a, &base, "lab-a", "lab.metadata.read").await?).await?;
    check(
        "scope-denial",
        get(&a, &base, path, Some(&limited)).await?.status() == StatusCode::FORBIDDEN,
    )?;
    let response = get(&a, &base, path, Some(&t)).await?;
    check("authenticated-read", response.status() == StatusCode::OK)?;
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body = response.text().await?;
    let trace=serde_json::json!({"method":"GET","path":path,"status":200,"content_type":content_type,"body":body}).to_string();
    let obs = mycelium_meta_gateway::observe_http_trace(&trace)?;
    check(
        "W3-metadata-only",
        obs.body_state == mycelium_meta_gateway::bse_web_http::BodyState::MetadataOnly
            && !obs.is_verified(),
    )?;
    let p = mycelium_meta_gateway::inspect_pix_json(
        &body,
        mycelium_meta_gateway::bse_web_pix_json::PayloadKind::Cob,
        mycelium_meta_gateway::bse_web_pix_json::Context::Dynamic,
    )?;
    check(
        "W2-synthetic-response",
        p.final_cents == Some(1234) && !p.is_verified(),
    )?;
    // Fixture server uses 2-second lifetimes; no wall-clock changes.
    let exp = take_token(token(&a, &base, "lab-a", "lab.cob.read").await?).await?;
    tokio::time::sleep(Duration::from_millis(2300)).await;
    check(
        "expired-token",
        get(&a, &base, path, Some(&exp)).await?.status() == StatusCode::UNAUTHORIZED,
    )?;
    check(
        "no-write-route",
        a.put(format!("{base}{path}"))
            .bearer_auth(&exp)
            .send()
            .await?
            .status()
            == StatusCode::METHOD_NOT_ALLOWED,
    )?;
    println!("15/15 authenticated lab checks passed; no settlement");
    Ok(())
}
