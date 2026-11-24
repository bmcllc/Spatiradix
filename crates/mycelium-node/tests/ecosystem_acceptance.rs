//! Teste de aceitação ponta a ponta dos 4 novos subsistemas integrados ao Mycelium Rhizome:
//! 1. Moeda unificada CPX + `mycelium-mint` como Reserva + `mycelium-bank` + `mycelium-pay` +
//!    GhostID × NFC (NDEF + BIP-340 + ML-KEM-1024 + anti-replay) + `mycelium-royalty` para criadores.
//! 2. Sessão AEX World & Cameon PX (`aex-mycelium-bridge/1.0.0`, GhostID efêmero, Pedersen ZKP,
//!    QEL fragment e simulador Asset-to-Capital UMPC-R).
//! 3. VEIL Ω como Proxy/VPN local (circuito telescópico ML-KEM-1024 + SOCKS5 RFC 1928 real +
//!    Kill Switch fail-closed).
//! 4. Omnibridge Social (9 redes: Instagram, Facebook, WhatsApp, X, Telegram, Reddit, YouTube,
//!    Twitch e TikTok) com cofre cifrado `XChaCha20-Poly1305` + importação unificada de contatos/canais/feed.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use mycelium_node::{call, run_daemon, DaemonOptions, Request, Response};
use serde_json::{json, Value};
use std::time::Duration;
use tempfile::tempdir;

async fn wait_for_sock(sock_path: &std::path::Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    while tokio::time::Instant::now() < deadline {
        if sock_path.exists() && tokio::net::UnixStream::connect(sock_path).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("Timeout aguardando socket {:?}", sock_path);
}

async fn wait_for_rhizome(client: &reqwest::Client, base_url: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if let Ok(resp) = client
            .get(format!("{base_url}/rhizome/api/overview"))
            .send()
            .await
        {
            if resp.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
    panic!("Timeout aguardando /rhizome/ em {base_url}");
}

#[tokio::test]
async fn ecosystem_cpx_reserve_nfc_royalty_aex_veil_and_omnibridge_e2e() {
    std::env::set_var("MYCELIUM_RATE_MAX", "2000");

    let dir = tempdir().unwrap();
    let home = dir.path().to_path_buf();
    let sock = home.join("mycelium.sock");

    let opts = DaemonOptions {
        listen: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
        horizon_port: 0,
        no_mdns: true,
        ..Default::default()
    };
    let h = home.clone();
    let daemon = tokio::spawn(async move {
        let _ = run_daemon(h, opts).await;
    });
    wait_for_sock(&sock).await;

    let base_url = match call(&sock, Request::Status).await.unwrap() {
        Response::Status(s) => s.event_horizon.trim_end_matches('/').to_string(),
        other => panic!("esperado Status, obtido {other:?}"),
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    wait_for_rhizome(&client, &base_url).await;

    // =========================================================================
    // 1. FINANÇAS CPX + MINT RESERVA + GHOSTID × NFC + BANK + PAY + ROYALTIES
    // =========================================================================
    let fin0: Value = client
        .get(format!("{base_url}/rhizome/api/finance"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fin0["platform_currency"]["symbol"], "CPX");
    assert_eq!(fin0["bank"]["ledger_chain_valid"], true);
    assert_eq!(
        fin0["identity"]["ghost_pubkey_hex"].as_str().unwrap().len(),
        64
    );

    // 1a. Liquida reserva PoUW no mycelium-mint -> trava MYC na reserva -> emite 8x CPX
    let minted_resp = client
        .post(format!("{base_url}/rhizome/api/finance/mint-reserve"))
        .json(&json!({ "units": 250, "memo": "prova-reserva-pouw" }))
        .send()
        .await
        .unwrap();
    assert!(
        minted_resp.status().is_success(),
        "mint-reserve falhou: {}",
        minted_resp.text().await.unwrap()
    );
    let minted: Value = minted_resp.json().await.unwrap();
    let local_cpx = minted["local_cpx_micros"].as_i64().unwrap();
    let reserve_myc = minted["reserve_myc_micros"].as_i64().unwrap();
    assert!(reserve_myc > 0, "reserva MYC deveria ser > 0");
    assert_eq!(
        local_cpx,
        reserve_myc * 8,
        "lastro CPX deve obedecer 1 MYC reserva = 8 CPX"
    );

    // 1b. Cria frame NFC NDEF com GhostID Schnorr + Ed25519 + ML-KEM + mycelium-pay CBOR
    let nfc_req_resp = client
        .post(format!("{base_url}/rhizome/api/finance/nfc/request"))
        .json(&json!({
            "to_account": "merchant:padaria-soberana",
            "amount_cpx_micros": 1_500_000,
            "memo": "Café espresso CPX NFC"
        }))
        .send()
        .await
        .unwrap();
    assert!(nfc_req_resp.status().is_success());
    let nfc_req: Value = nfc_req_resp.json().await.unwrap();
    let ndef_uri = nfc_req["ndef_uri"].as_str().unwrap().to_string();
    assert!(ndef_uri.starts_with("urn:mycelium:nfc:cpx:v1:"));
    assert!(!nfc_req["ndef_record_b64"].as_str().unwrap().is_empty());
    assert!(!nfc_req["pay_request_cbor_b64"].as_str().unwrap().is_empty());
    assert_eq!(nfc_req["verified_ghostid_schnorr"], true);
    assert_eq!(nfc_req["verified_pay_cbor_bip340"], true);

    // 1c. Executa o Tap NFC real e liquida no mycelium-bank + emite recibo BIP-340 mycelium-pay
    let tap_resp = client
        .post(format!("{base_url}/rhizome/api/finance/nfc/tap"))
        .json(&json!({ "ndef_uri": ndef_uri }))
        .send()
        .await
        .unwrap();
    assert!(tap_resp.status().is_success());
    let tap: Value = tap_resp.json().await.unwrap();
    assert_eq!(tap["nfc_log"]["amount_cpx_micros"], 1_500_000);
    assert!(!tap["pay_receipt_cbor_b64"].as_str().unwrap().is_empty());
    assert_eq!(
        tap["balance_cpx_micros"].as_i64().unwrap(),
        local_cpx - 1_500_000
    );

    // 1d. Anti-replay: reapresentar o mesmo tap NFC DEVE retornar 409 Conflict!
    let replay_resp = client
        .post(format!("{base_url}/rhizome/api/finance/nfc/tap"))
        .json(&json!({ "ndef_uri": ndef_uri }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        replay_resp.status(),
        reqwest::StatusCode::CONFLICT,
        "anti-replay NFC deve rejeitar nonce repetido com 409"
    );

    // 1e. Royalties em CPX para criadores (70% criador principal + 30% editor + 5% taxa de reserva)
    let contract_resp = client
        .post(format!("{base_url}/rhizome/api/royalties/contract"))
        .json(&json!({
            "content_id": "cid_documentario_soberano_01",
            "license": "CC-BY-SA-4.0 / CPX",
            "reserve_fee_bps": 500,
            "splits": [
                { "beneficiary_id": "creator:alice", "role": "diretora", "share_bps": 7000 },
                { "beneficiary_id": "creator:bob", "role": "editor", "share_bps": 3000 }
            ]
        }))
        .send()
        .await
        .unwrap();
    assert!(contract_resp.status().is_success());
    let contract_json: Value = contract_resp.json().await.unwrap();
    assert!(contract_json["isotope_key"]
        .as_str()
        .unwrap()
        .starts_with("royalty/license/"));

    let payout_resp = client
        .post(format!("{base_url}/rhizome/api/royalties/payout"))
        .json(&json!({
            "content_id": "cid_documentario_soberano_01",
            "gross_cpx_micros": 10_000_000,
            "memo": "Royalty streaming mês 01"
        }))
        .send()
        .await
        .unwrap();
    assert!(payout_resp.status().is_success());
    let payout: Value = payout_resp.json().await.unwrap();
    assert_eq!(payout["distribution"]["reserve_fee_cpx_micros"], 500_000);
    let allocs = payout["distribution"]["allocations"].as_array().unwrap();
    assert_eq!(allocs[0]["cpx_micros"], 6_650_000);
    assert_eq!(allocs[1]["cpx_micros"], 2_850_000);

    // =========================================================================
    // 2. SESSÃO AEX WORLD & CAMEON PX + PONTE `aex-mycelium-bridge/1.0.0`
    // =========================================================================
    let aex_status: Value = client
        .get(format!("{base_url}/rhizome/api/aex/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        aex_status["mycelium_bridge"]["protocol_version"],
        "aex-mycelium-bridge/1.0.0"
    );
    assert!(aex_status["non_alienation_covenant"]
        .as_str()
        .unwrap()
        .contains("propriedade"));

    let aex_sim: Value = client
        .post(format!("{base_url}/rhizome/api/aex/simulate"))
        .json(&json!({
            "asset_status": "PRODUCTIVE",
            "class": "AEX-REV",
            "units": 1000,
            "unit_price_cpx": 10.0,
            "share_bps": 1500,
            "projected_gross_revenue_cpx": 5000.0,
            "deductible_costs_cpx": 1000.0,
            "ceiling_cpx": 15000.0,
            "periods": 12
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(aex_sim["result"]["non_alienation_verified"], true);
    assert_eq!(aex_sim["result"]["ownership_transferred_pct"], 0.0);
    assert!(aex_sim["result"]["total_distributed_cpx"].as_f64().unwrap() > 0.0);

    // Operações reais via ponte AEX: GhostID spawn -> sign -> destroy + Pedersen + QEL
    let ghost_spawn: Value = client
        .post(format!("{base_url}/rhizome/api/aex/bridge"))
        .json(&json!({ "op": "ghost_spawn", "ttl_secs": 120 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let handle = ghost_spawn["handle"].as_str().unwrap().to_string();
    assert_eq!(ghost_spawn["pubkey_hex"].as_str().unwrap().len(), 64);

    let ghost_sign: Value = client
        .post(format!("{base_url}/rhizome/api/aex/bridge"))
        .json(&json!({
            "op": "ghost_sign",
            "handle": handle,
            "payload_b64": BASE64.encode(b"covenant-non-alienation-proof")
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ghost_sign["signature_hex"].as_str().unwrap().len(), 128);

    let pedersen: Value = client
        .post(format!("{base_url}/rhizome/api/aex/bridge"))
        .json(&json!({ "op": "pedersen_commit", "value": 42000 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!pedersen["commitment_hex"].as_str().unwrap().is_empty());

    let qel: Value = client
        .post(format!("{base_url}/rhizome/api/aex/bridge"))
        .json(&json!({
            "op": "qel_fragment",
            "data_b64": BASE64.encode(b"ativo-aex-lastreado-sem-alienacao"),
            "content_id": "aex-doc-01",
            "threshold": 2,
            "total": 3
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(qel["shards"].as_array().unwrap().len(), 3);

    // =========================================================================
    // 3. VEIL Ω PROXY / VPN (ML-KEM-1024 + SOCKS5 RFC 1928 + KILL SWITCH)
    // =========================================================================
    let veil0: Value = client
        .get(format!("{base_url}/rhizome/api/veil/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(veil0["compiled"], true);
    assert_eq!(veil0["active"], false);

    let veil_start_resp = client
        .post(format!("{base_url}/rhizome/api/veil/start"))
        .json(&json!({ "mode": "veil", "port": 0 }))
        .send()
        .await
        .unwrap();
    assert!(
        veil_start_resp.status().is_success(),
        "veil start falhou: {}",
        veil_start_resp.text().await.unwrap()
    );
    let veil_on: Value = veil_start_resp.json().await.unwrap();
    assert_eq!(veil_on["active"], true);
    assert!(veil_on["socks5_uri"]
        .as_str()
        .unwrap()
        .starts_with("socks5h://127.0.0.1:"));

    // Handshake real RFC 1928 contra o socket TCP do proxy VEIL!
    let veil_test: Value = client
        .post(format!("{base_url}/rhizome/api/veil/test"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(veil_test["ok"], true);

    // Aciona Kill Switch fail-closed e depois reabilita + desliga VEIL
    let ks_on: Value = client
        .post(format!("{base_url}/rhizome/api/veil/killswitch"))
        .json(&json!({ "engaged": true }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ks_on["kill_switch_state"], "triggered");

    let veil_off: Value = client
        .post(format!("{base_url}/rhizome/api/veil/stop"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(veil_off["active"], false);

    // =========================================================================
    // 4. OMNIBRIDGE SOCIAL (9 REDES + COFRE XCHACHA20-POLY1305 + DIRETÓRIO)
    // =========================================================================
    let omni0: Value = client
        .get(format!("{base_url}/rhizome/api/omnibridge/overview"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(omni0["platforms"].as_array().unwrap().len(), 9);

    // Salva credencial no cofre XChaCha20-Poly1305 e verifica que o segredo NÃO aparece em texto claro no disco
    let secret_token = "tok_super_secreto_omnibridge_999";
    let conn_resp = client
        .post(format!("{base_url}/rhizome/api/omnibridge/connect"))
        .json(&json!({
            "platform": "telegram",
            "account_label": "@soberano_tg",
            "access_token": secret_token,
            "channels": ["canal_mycelium"],
            "route_via_veil": true
        }))
        .send()
        .await
        .unwrap();
    assert!(conn_resp.status().is_success());

    let vault_disk =
        std::fs::read(home.join("ecosystem").join("omnibridge_vault.enc")).unwrap();
    assert!(
        !vault_disk
            .windows(secret_token.len())
            .any(|w| w == secret_token.as_bytes()),
        "credencial não pode jamais ficar em texto claro no disco!"
    );

    // Importa contatos vCard (WhatsApp) + canais/feed de YouTube, Reddit e Instagram
    let vcard = "BEGIN:VCARD\nVERSION:3.0\nFN:Maria Soberana\nTEL:+5511999998888\nEND:VCARD\n";
    let imp_wa: Value = client
        .post(format!("{base_url}/rhizome/api/omnibridge/import"))
        .json(&json!({
            "platform": "whatsapp",
            "format": "vcard",
            "payload": vcard
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(imp_wa["contacts_imported"], 1);

    let yt_atom = r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns:yt="http://www.youtube.com/xml/schemas/2015">
  <yt:channelId>UC_MYCELIUM_DEMO</yt:channelId>
  <title>Canal Mycelium Demo</title>
  <entry>
    <yt:videoId>vid12345</yt:videoId>
    <title>Arquitetura Soberana CPX</title>
    <published>2026-11-24T12:00:00Z</published>
    <author><name>Canal Mycelium Demo</name></author>
    <link rel="alternate" href="https://www.youtube.com/watch?v=vid12345"/>
  </entry>
</feed>"#;
    let imp_yt: Value = client
        .post(format!("{base_url}/rhizome/api/omnibridge/import"))
        .json(&json!({
            "platform": "youtube",
            "format": "auto",
            "payload": yt_atom
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(imp_yt["channels_imported"], 1);
    assert_eq!(imp_yt["items_imported"], 1);

    let dir_json: Value = client
        .get(format!("{base_url}/rhizome/api/omnibridge/directory"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(dir_json["contacts"].as_array().unwrap().len() >= 1);
    assert!(dir_json["channels"].as_array().unwrap().len() >= 1);
    assert!(dir_json["items"].as_array().unwrap().len() >= 1);

    // =========================================================================
    // 5. THEFIELD (`/field/`) — FORJA DE CÓDIGO + SIGNALS AO VIVO (ZERO CODE HUB)
    // =========================================================================
    let field_html = client
        .get(format!("{base_url}/field/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(field_html.contains("TheField"));
    assert!(!field_html.to_ascii_lowercase().contains("code hub"));

    let emitted: Value = client
        .post(format!("{base_url}/field/api/signals"))
        .json(&json!({ "kind": "release", "version": "v0.3.0-sovereign", "quorum": 1 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(emitted["signal"]["state"], "Fired");

    let sigs: Value = client
        .get(format!("{base_url}/field/api/signals"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(sigs["count"].as_u64().unwrap() >= 1);

    daemon.abort();
}

#[tokio::test]
async fn two_node_quorum_reserve_and_remote_veil_relay_client_e2e() {
    std::env::set_var("MYCELIUM_RATE_MAX", "2000");

    let dir_a = tempdir().unwrap();
    let home_a = dir_a.path().to_path_buf();
    let sock_a = home_a.join("mycelium.sock");

    let dir_b = tempdir().unwrap();
    let home_b = dir_b.path().to_path_buf();
    let sock_b = home_b.join("mycelium.sock");

    let opts_a = DaemonOptions {
        listen: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
        horizon_port: 0,
        no_mdns: true,
        ..Default::default()
    };
    let ha = home_a.clone();
    let da = tokio::spawn(async move {
        let _ = run_daemon(ha, opts_a).await;
    });
    wait_for_sock(&sock_a).await;

    let url_a = match call(&sock_a, Request::Status).await.unwrap() {
        Response::Status(s) => s.event_horizon.trim_end_matches('/').to_string(),
        other => panic!("{other:?}"),
    };
    let listen_file = home_a.join("listen_addrs.json");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    while tokio::time::Instant::now() < deadline && !listen_file.exists() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let addrs: Vec<String> =
        serde_json::from_str(&std::fs::read_to_string(&listen_file).unwrap()).unwrap();
    let tcp_a = addrs
        .into_iter()
        .find(|a| a.contains("/tcp/") && !a.contains("/quic"))
        .expect("tcp addr A");

    let opts_b = DaemonOptions {
        listen: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
        bootstrap: vec![tcp_a],
        horizon_port: 0,
        no_mdns: true,
        ..Default::default()
    };
    let hb = home_b.clone();
    let db = tokio::spawn(async move {
        let _ = run_daemon(hb, opts_b).await;
    });
    wait_for_sock(&sock_b).await;

    let url_b = match call(&sock_b, Request::Status).await.unwrap() {
        Response::Status(s) => s.event_horizon.trim_end_matches('/').to_string(),
        other => panic!("{other:?}"),
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    wait_for_rhizome(&client, &url_a).await;
    wait_for_rhizome(&client, &url_b).await;

    // Aguarda descoberta P2P (gossipsub mesh entre A e B)
    let mesh_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < mesh_deadline {
        if let Ok(Response::Status(s)) = call(&sock_b, Request::Status).await {
            if s.neighbors >= 1 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
    tokio::time::sleep(Duration::from_millis(800)).await;

    // 1. Configura Quórum Multi-Esporocarpo (2-de-2) em AMBOS os nós!
    let pol_a0: Value = client
        .get(format!("{url_a}/rhizome/api/finance/reserve-policy"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let pol_b0: Value = client
        .get(format!("{url_b}/rhizome/api/finance/reserve-policy"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let sp_a = json!({
        "node_id": pol_a0["self_node_id"],
        "pubkey_hex": pol_a0["self_pubkey_hex"],
    });
    let sp_b = json!({
        "node_id": pol_b0["self_node_id"],
        "pubkey_hex": pol_b0["self_pubkey_hex"],
    });

    for (url, extra) in [(&url_a, sp_b.clone()), (&url_b, sp_a.clone())] {
        let r = client
            .post(format!("{url}/rhizome/api/finance/reserve-policy"))
            .json(&json!({
                "chain_id": "mycelium-consortium-2of2",
                "min_quorum": 2,
                "min_hashcash_bits": 4,
                "include_self": true,
                "sporocarps": [extra],
            }))
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success(), "config policy falhou: {}", r.text().await.unwrap());
    }

    // Submete claim no Nó A -> propaga via Gossipsub -> Nó A e Nó B atestam -> época liquida em quórum 2/2 -> CPX creditado!
    let claim_res: Value = client
        .post(format!("{url_a}/rhizome/api/finance/mint-claim"))
        .json(&json!({ "units": 200, "memo": "quorum-2of2-p2p" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(claim_res["min_quorum"], 2);

    let mut settled_cpx = 0i64;
    let mut settled_myc = 0i64;
    let q_deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    while tokio::time::Instant::now() < q_deadline {
        let fin: Value = client
            .get(format!("{url_a}/rhizome/api/finance"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        settled_cpx = fin["balances"]["cpx_micros"].as_i64().unwrap_or(0);
        settled_myc = fin["balances"]["reserve_myc_micros"].as_i64().unwrap_or(0);
        if settled_cpx > 0 && settled_myc > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(settled_myc > 0, "reserva MYC deveria liquidar via quórum 2-de-2 P2P");
    assert_eq!(settled_cpx, settled_myc * 8, "lastro CPX 8x em quórum multi-esporocarpo");

    // 2. VEIL Ω Remoto: Nó B atua como Exit remoto e Nó A conecta como Cliente + TUN bridge!
    let exit_on: Value = client
        .post(format!("{url_b}/rhizome/api/veil/start"))
        .json(&json!({
            "mode": "geo",
            "role": "exit",
            "listen": "127.0.0.1:0",
            "advertise": "127.0.0.1:19951"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // Como porta 0 muda o endpoint real, iniciamos com porta fixa livre para o descritor bater
    let _ = client.post(format!("{url_b}/rhizome/api/veil/stop")).send().await;
    let free_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let exit_resp = client
        .post(format!("{url_b}/rhizome/api/veil/start"))
        .json(&json!({
            "mode": "geo",
            "role": "exit",
            "listen": format!("127.0.0.1:{free_port}"),
            "advertise": format!("127.0.0.1:{free_port}")
        }))
        .send()
        .await
        .unwrap();
    assert!(exit_resp.status().is_success());
    let exit_json: Value = exit_resp.json().await.unwrap();
    let exit_desc = exit_json["local_descriptor"].as_str().unwrap().to_string();
    let _ = exit_on;

    let cli_resp = client
        .post(format!("{url_a}/rhizome/api/veil/start"))
        .json(&json!({
            "mode": "geo",
            "role": "client",
            "port": 0,
            "exits": [exit_desc]
        }))
        .send()
        .await
        .unwrap();
    assert!(cli_resp.status().is_success(), "veil client falhou: {}", cli_resp.text().await.unwrap());
    let cli_json: Value = cli_resp.json().await.unwrap();
    assert_eq!(cli_json["active"], true);
    assert_eq!(cli_json["remote_hops_configured"], true);
    assert!(cli_json["tun_bridge_port"].as_u64().unwrap_or(0) > 0);

    let v_test: Value = client
        .post(format!("{url_a}/rhizome/api/veil/test"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v_test["ok"], true);

    da.abort();
    db.abort();
}
