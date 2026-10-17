use mycelium_bank::accounts::Portfolio;
use mycelium_bank::assets::{Amount, Asset};
use mycelium_bank::*;
use tempfile::tempdir;

#[test]
fn wallet_sign_verify() {
    let w = identity::SovereignWallet::generate();
    let msg = b"hello";
    let sig = w.sign(msg);
    assert!(identity::SovereignWallet::verify(
        &w.verifying_key(),
        msg,
        &sig
    ));
}

#[test]
fn kem_roundtrip() {
    let a = identity::SovereignWallet::generate();
    let b = identity::SovereignWallet::generate();
    let enc = mycelium_pqc::mlkem_encapsulate(&b.public_kem).unwrap();
    let ss_b = b.decapsulate(&enc.ciphertext).unwrap();
    assert_eq!(ss_b, enc.shared_secret);
    // sender can encapsulate to self too
    let _ = a.encapsulate_to();
}

#[test]
fn nfc_proof_verifies() {
    let payer = identity::SovereignWallet::generate();
    let receiver = identity::SovereignWallet::generate();
    let intent = payments::PaymentIntent::new(
        &payer.account_id,
        &receiver.account_id,
        Amount::new(Asset::Usdc, 1_000_000),
        "cafe".into(),
        100,
    );
    let proof = payments::NfcProof::create(&payer, &intent);
    assert!(payments::validate_nfc_payment(&intent, &proof).is_ok());
    let mut tampered = intent.clone();
    tampered.amount = Amount::new(Asset::Usdc, 2_000_000);
    assert!(payments::validate_nfc_payment(&tampered, &proof).is_err());
}

#[test]
fn ledger_hash_chain() {
    let dir = tempdir().unwrap();
    let ledger = ledger::SovereignLedger::open(dir.path()).unwrap();
    let r1 = ledger
        .append(ledger::Entry::Credit {
            account_id: "a".into(),
            asset: "USDC".into(),
            micros: 100,
            ref_id: "r1".into(),
            at: 1,
        })
        .unwrap();
    let r2 = ledger
        .append(ledger::Entry::Debit {
            account_id: "a".into(),
            asset: "USDC".into(),
            micros: 10,
            ref_id: "r2".into(),
            at: 2,
        })
        .unwrap();
    assert_eq!(r2.prev_hash, r1.record_hash);
    assert!(ledger.audit().unwrap());
    let all = ledger.read_all().unwrap();
    assert_eq!(all.len(), 2);
}

#[test]
fn account_transfer() {
    let mut p = Portfolio::default();
    let a = p.open_account("a", "owner", 1).unwrap();
    a.credit(Asset::Usdc, 1000).unwrap();
    p.open_account("b", "owner2", 1).unwrap();
    // reopen mutable
    {
        let acc_a = p.get_mut("a").unwrap();
        acc_a.debit(Asset::Usdc, 400).unwrap();
    }
    let acc_b = p.get_mut("b").unwrap();
    acc_b.credit(Asset::Usdc, 400).unwrap();
    assert_eq!(p.get("a").unwrap().balance(Asset::Usdc), 600);
    assert_eq!(p.get("b").unwrap().balance(Asset::Usdc), 400);
}

#[test]
fn exchange_match() {
    use mycelium_bank::orders::{Order, OrderBook, Side};
    let mut ob = OrderBook::new();
    ob.place(Order {
        id: "buy1".into(),
        account_id: "a".into(),
        base: Asset::Btc,
        quote: Asset::Usdc,
        side: Side::Buy,
        price_micros: 100,
        qty_micros: 10,
        remaining_micros: 10,
        created_at_unix: 1,
    })
    .unwrap();
    ob.place(Order {
        id: "sell1".into(),
        account_id: "b".into(),
        base: Asset::Btc,
        quote: Asset::Usdc,
        side: Side::Sell,
        price_micros: 90,
        qty_micros: 10,
        remaining_micros: 10,
        created_at_unix: 2,
    })
    .unwrap();
    let trades = ob.match_orders(3);
    assert_eq!(trades.len(), 1);
    assert_eq!(trades[0].qty_micros, 10);
}

#[test]
fn nfc_tap_frame_roundtrip() {
    use mycelium_bank::nfc::TapFrame;
    let payer = identity::SovereignWallet::generate();
    let receiver = identity::SovereignWallet::generate();
    let intent = payments::PaymentIntent::new(
        &payer.account_id,
        &receiver.account_id,
        Amount::new(Asset::Usdc, 5),
        "x".into(),
        5,
    );
    let proof = payments::NfcProof::create(&payer, &intent);
    let frame = TapFrame::encode(&intent, &proof).unwrap();
    let (i2, p2) = TapFrame::decode(&frame).unwrap();
    assert_eq!(i2.id, intent.id);
    assert!(payments::validate_nfc_payment(&i2, &p2).is_ok());
}
