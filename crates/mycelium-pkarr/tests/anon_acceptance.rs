//! Aceitação do Pkarr anônimo de nó único.
//!
//! Cobre: interoperabilidade com a implementação de referência (`pkarr` 8),
//! cifragem/cegamento, recusa de vazamento de IP, adulteração, expiração e
//! que o cliente HTTP só sai pelo SOCKS5 local com DNS remoto (`socks5h`).

use mycelium_pkarr::{
    dns, open, seal, AnonRecord, Capability, Endpoint, MasterIdentity, PkarrError, RelayClient,
    SignedPacket, Transport, EPOCH_SECS,
};
use zeroize::Zeroizing;

const NOW: u64 = 1_790_000_000;

fn nostr_record() -> AnonRecord {
    AnonRecord {
        endpoints: vec![Endpoint::Nostr {
            pubkey: "ab".repeat(32),
            relays: vec!["wss://nos.lol".into(), "wss://relay.damus.io".into()],
        }],
        not_after: NOW + 3600,
    }
}

fn cap_of(id: &MasterIdentity, secret: Option<[u8; 32]>) -> Capability {
    Capability {
        master_public: id.public(),
        access_secret: secret.map(Zeroizing::new),
    }
}

#[test]
fn reference_pkarr_accepts_our_anonymous_packet() {
    let id = MasterIdentity::generate();
    let packet = seal(&id, None, &nostr_record(), NOW).unwrap();
    let payload = bytes::Bytes::from(packet.to_relay_payload());
    let pk = pkarr::PublicKey::try_from(packet.public_key()).unwrap();
    let theirs = pkarr::SignedPacket::from_relay_payload(&pk, &payload)
        .expect("relays Pkarr precisam aceitar nosso pacote");
    assert_eq!(theirs.timestamp().as_u64(), NOW * 1_000_000);
    assert_eq!(theirs.resource_records("_myc").count(), 1);
}

#[test]
fn we_accept_reference_pkarr_packet() {
    let kp = pkarr::Keypair::random();
    let txt = pkarr::dns::rdata::TXT::new().with_string("ola").unwrap();
    let theirs = pkarr::SignedPacket::builder()
        .txt(pkarr::dns::Name::new("_teste").unwrap(), txt, 300)
        .sign(&kp)
        .unwrap();
    let key: [u8; 32] = *kp.public_key().as_bytes();
    let ours = SignedPacket::from_relay_payload(&key, &theirs.to_relay_payload()).unwrap();
    let recs = dns::decode_txt(ours.dns()).unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].name, format!("_teste.{}", kp.public_key().to_z32()));
    assert_eq!(recs[0].strings, vec![b"ola".to_vec()]);
}

#[test]
fn seal_open_roundtrip_and_address() {
    let id = MasterIdentity::generate();
    let rec = nostr_record();
    let packet = seal(&id, None, &rec, NOW).unwrap();

    let addr = cap_of(&id, None).to_address();
    let cap = Capability::from_address(&addr).unwrap();
    assert!(cap.lookup_keys(NOW).unwrap().contains(packet.public_key()));

    // passa pelo formato do relay, como na rede
    let wire =
        SignedPacket::from_relay_payload(packet.public_key(), &packet.to_relay_payload()).unwrap();
    assert_eq!(open(&cap, &wire, NOW + 60).unwrap(), rec);
}

#[test]
fn observer_sees_neither_identity_nor_content() {
    let id = MasterIdentity::generate();
    let rec = AnonRecord {
        not_after: NOW + 3 * EPOCH_SECS,
        ..nostr_record()
    };
    let p1 = seal(&id, None, &rec, NOW).unwrap();
    let p2 = seal(&id, None, &rec, NOW + EPOCH_SECS).unwrap();
    assert_ne!(p1.public_key(), p2.public_key(), "chave muda a cada época");
    for p in [&p1, &p2] {
        let raw = p.to_relay_payload();
        let master = id.public();
        assert!(
            !raw.windows(32).any(|w| w == master),
            "chave mestra não pode aparecer"
        );
        assert!(
            !raw.windows(7).any(|w| w == b"nos.lol"),
            "endpoint não pode aparecer em claro"
        );
        assert!(!raw.windows(4).any(|w| w == b"wss:"));
    }
}

#[test]
fn all_records_have_the_same_size() {
    let id = MasterIdentity::generate();
    let small = AnonRecord {
        endpoints: vec![Endpoint::Plot {
            content_id: "0".repeat(64),
        }],
        not_after: NOW + 10,
    };
    let big = AnonRecord {
        endpoints: vec![
            Endpoint::Nostr {
                pubkey: "cd".repeat(32),
                relays: vec![
                    "wss://nos.lol".into(),
                    "wss://relay.damus.io".into(),
                    "wss://relay.primal.net".into(),
                ],
            },
            Endpoint::Onion {
                addr: format!("{}.onion:443", "a".repeat(56)),
            },
            Endpoint::Plot {
                content_id: "f".repeat(64),
            },
        ],
        not_after: NOW + 10,
    };
    let a = seal(&id, None, &small, NOW).unwrap().to_relay_payload();
    let b = seal(&id, None, &big, NOW).unwrap().to_relay_payload();
    assert_eq!(a.len(), b.len());
    assert!(a.len() <= mycelium_pkarr::packet::MAX_RELAY_PAYLOAD);
}

#[test]
fn private_mode_requires_access_secret() {
    let id = MasterIdentity::generate();
    let secret = [9u8; 32];
    let packet = seal(&id, Some(&secret), &nostr_record(), NOW).unwrap();
    assert!(matches!(
        open(&cap_of(&id, None), &packet, NOW),
        Err(PkarrError::Crypto)
    ));
    assert!(matches!(
        open(&cap_of(&id, Some([8u8; 32])), &packet, NOW),
        Err(PkarrError::Crypto)
    ));
    let full = cap_of(&id, Some(secret));
    let parsed = Capability::from_address(&full.to_address()).unwrap();
    assert!(open(&parsed, &packet, NOW).is_ok());
}

#[test]
fn other_identity_cannot_impersonate() {
    let victim = MasterIdentity::generate();
    let attacker = MasterIdentity::generate();
    let forged = seal(&attacker, None, &nostr_record(), NOW).unwrap();
    assert!(matches!(
        open(&cap_of(&victim, None), &forged, NOW),
        Err(PkarrError::BadKey)
    ));
}

#[test]
fn tampering_is_detected() {
    let id = MasterIdentity::generate();
    let packet = seal(&id, None, &nostr_record(), NOW).unwrap();
    let body = packet.to_relay_payload();
    let mut flipped = 0;
    for i in (0..body.len()).step_by(17) {
        let mut bad = body.clone();
        bad[i] ^= 0x01;
        let res = SignedPacket::from_relay_payload(packet.public_key(), &bad)
            .and_then(|p| open(&cap_of(&id, None), &p, NOW));
        assert!(res.is_err(), "byte {i} adulterado passou");
        flipped += 1;
    }
    assert!(flipped > 40);
}

#[test]
fn freshness_rules() {
    let id = MasterIdentity::generate();
    let cap = cap_of(&id, None);
    let packet = seal(&id, None, &nostr_record(), NOW).unwrap();
    // registro além do not_after
    assert!(matches!(
        open(&cap, &packet, NOW + 3601),
        Err(PkarrError::Expired)
    ));
    // duas épocas depois: velho demais mesmo com not_after longo
    let long = AnonRecord {
        not_after: NOW + 10 * EPOCH_SECS,
        ..nostr_record()
    };
    let p = seal(&id, None, &long, NOW).unwrap();
    assert!(open(&cap, &p, NOW + EPOCH_SECS).is_ok());
    assert!(open(&cap, &p, NOW + 3 * EPOCH_SECS).is_err());
    // publicado "no futuro" além da tolerância
    let future = seal(&id, None, &long, NOW + 3600).unwrap();
    assert!(open(&cap, &future, NOW).is_err());
    // not_after já vencido não é nem publicado
    let dead = AnonRecord {
        not_after: NOW - 1,
        ..nostr_record()
    };
    assert!(matches!(
        seal(&id, None, &dead, NOW),
        Err(PkarrError::Expired)
    ));
}

#[test]
fn ip_revealing_endpoints_are_refused() {
    let id = MasterIdentity::generate();
    let bad_relays = [
        "wss://203.0.113.7",
        "wss://[2804:7f7::1]:443",
        "ws://nos.lol",
        "https://nos.lol",
        "wss://localhost",
        "wss://meu-pc.local",
        "wss://roteador.lan",
        "wss://user:senha@nos.lol",
        "wss://nos.lol/?id=abc",
        "wss://intranet",
    ];
    for r in bad_relays {
        let rec = AnonRecord {
            endpoints: vec![Endpoint::Nostr {
                pubkey: "ab".repeat(32),
                relays: vec![r.into()],
            }],
            not_after: NOW + 60,
        };
        assert!(
            matches!(seal(&id, None, &rec, NOW), Err(PkarrError::Leak(_))),
            "{r} deveria ser recusado"
        );
    }
    let bad_eps = [
        Endpoint::Onion {
            addr: "abcdefghijklmnop.onion".into(),
        }, // v2
        Endpoint::Onion {
            addr: "192.168.0.1:80".into(),
        },
        Endpoint::Veil {
            descriptor: "10.0.0.1:4001".into(),
        },
        Endpoint::Plot {
            content_id: "/ip4/1.2.3.4/tcp/4001".into(),
        },
    ];
    for ep in bad_eps {
        let rec = AnonRecord {
            endpoints: vec![ep.clone()],
            not_after: NOW + 60,
        };
        assert!(
            seal(&id, None, &rec, NOW).is_err(),
            "{ep:?} deveria ser recusado"
        );
    }
}

#[test]
fn resolver_rejects_unknown_fields() {
    // Mesmo um publicador legítimo não consegue enfiar campos extras: o
    // resolvedor recusa (deny_unknown_fields) em vez de ignorar.
    let json = r#"{"endpoints":[{"t":"plot","content_id":"00","ip":"1.2.3.4"}],"not_after":1}"#;
    assert!(serde_json::from_str::<AnonRecord>(json).is_err());
}

/// SOCKS5 falso em loopback: aceita a saudação, lê o CONNECT e devolve
/// (ATYP, destino); depois fecha. Prova que o cliente (1) usa o proxy e
/// (2) manda o **nome** (ATYP=3), sem resolver DNS localmente.
#[tokio::test]
async fn relay_traffic_goes_only_through_local_socks5h() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut hello = [0u8; 2];
        s.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello[0], 5, "não é SOCKS5");
        let mut methods = vec![0u8; hello[1] as usize];
        s.read_exact(&mut methods).await.unwrap();
        s.write_all(&[5, 0]).await.unwrap();
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await.unwrap();
        let atyp = head[3];
        let target = if atyp == 3 {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await.unwrap();
            let mut name = vec![0u8; len[0] as usize];
            s.read_exact(&mut name).await.unwrap();
            String::from_utf8(name).unwrap()
        } else {
            String::new()
        };
        // 0x05 = conexão recusada
        let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        (atyp, target)
    });

    let client = RelayClient::new(
        &["https://relay.pkarr.org".to_string()],
        Transport::Anonymous { socks5: addr },
    )
    .unwrap();
    let id = MasterIdentity::generate();
    let packet = seal(&id, None, &nostr_record(), NOW).unwrap();
    let res = client.publish(&packet).await;
    assert!(
        matches!(res, Err(PkarrError::AllRelaysFailed(_))),
        "deve falhar fechado: {res:?}"
    );

    let (atyp, target) = server.await.unwrap();
    assert_eq!(atyp, 3, "DNS precisa ser resolvido no proxy (socks5h)");
    assert_eq!(target, "relay.pkarr.org");
}

#[tokio::test]
async fn dead_proxy_never_falls_back_to_direct() {
    // porta loopback sem ninguém escutando
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let client = RelayClient::new(
        &["https://relay.pkarr.org".to_string()],
        Transport::Anonymous { socks5: addr },
    )
    .unwrap();
    let key = [3u8; 32];
    match client.resolve(&key).await {
        Err(PkarrError::NotFound(why)) => assert!(why.contains("falha de conexão"), "{why}"),
        other => panic!("esperava falha de conexão ao proxy, veio {other:?}"),
    }
}
