//! # mycelium-mint
//!
//! Motor determinístico de emissão cripto de mainnet (PoUW-DAG, paridade 1 MYC = 8 USDC)
//! integrado com `mycelium-zkp` e `mycelium-nutrients`.

pub mod arq;
pub mod engine;
pub mod error;
pub mod policy;
pub mod proof;

pub use arq::{ArqMintDecision, ArqMintPolicy, ArqRegime};
pub use engine::{CpxReserveStatus, MainnetMintEngine};
pub use error::MintError;
pub use policy::{
    MonetaryPolicy, COIN, DEFAULT_CPX_PER_MYC, DEFAULT_HALVING_EPOCHS,
    DEFAULT_INITIAL_EPOCH_BUDGET, DEFAULT_MAX_NODE_SHARE_BPS, DEFAULT_MAX_SUPPLY,
    DEFAULT_MIN_HASHCASH_BITS, DEFAULT_USDC_PER_MYC,
};
pub use proof::{MintReceipt, SporocarpAttestation, WorkClaim};

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mycelium_core::{ContentId, NodeId, Nutrient};
    use mycelium_nutrients::{Ledger, TxKind};
    use std::collections::HashMap;

    fn key_from_byte(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn node_id_of(key: &SigningKey) -> NodeId {
        NodeId::derive(key.verifying_key().as_bytes())
    }

    fn make_sporocarps(seeds: &[u8]) -> (Vec<SigningKey>, HashMap<NodeId, [u8; 32]>) {
        let mut keys = Vec::new();
        let mut map = HashMap::new();
        for &s in seeds {
            let sk = key_from_byte(s);
            let pk = sk.verifying_key().to_bytes();
            map.insert(NodeId::derive(&pk), pk);
            keys.push(sk);
        }
        (keys, map)
    }

    fn sign_batch(
        engine: &MainnetMintEngine,
        claims: &[WorkClaim],
        validators: &[SigningKey],
    ) -> Vec<SporocarpAttestation> {
        let root = engine.compute_batch_root(engine.current_epoch, claims);
        validators
            .iter()
            .map(|sk| SporocarpAttestation::sign(&engine.chain_id, engine.current_epoch, root, sk))
            .collect()
    }

    #[test]
    fn arq_genesis_commits_policy_and_quorum_cannot_bypass_budget_rules() {
        let (validator_keys, validators) = make_sporocarps(&[2, 3, 4]);
        let mut monetary = MonetaryPolicy::mainnet();
        monetary.min_hashcash_bits = 4;
        monetary.initial_epoch_budget = 100;
        monetary.max_node_share_bps = 10_000;
        monetary.max_supply = 200;
        let governance = ArqMintPolicy::default();
        let mut engine = MainnetMintEngine::genesis_arq(
            "mint-arq-test",
            b"genesis-arq",
            monetary.clone(),
            validators.clone(),
            2,
            governance.clone(),
        )
        .unwrap();
        assert_eq!(engine.arq_policy(), Some(&governance));
        let legacy_engine = MainnetMintEngine::genesis(
            "mint-arq-test",
            b"genesis-arq",
            monetary.clone(),
            validators.clone(),
            2,
        )
        .unwrap();
        assert_ne!(engine.epoch_parents, legacy_engine.epoch_parents);

        let claims = vec![
            WorkClaim::build_signed(
                "mint-arq-test",
                0,
                NodeId::derive(b"producer-a"),
                &key_from_byte(90),
                ContentId::of(b"arq-seeding"),
                TxKind::Seeding,
                100,
                1000,
                1000,
                4,
            ),
            WorkClaim::build_signed(
                "mint-arq-test",
                0,
                NodeId::derive(b"producer-b"),
                &key_from_byte(91),
                ContentId::of(b"arq-compute"),
                TxKind::Compute,
                100,
                1000,
                1000,
                4,
            ),
        ];
        let (arq_root, decision) = engine.compute_arq_batch_root(&claims).unwrap();
        assert_eq!(decision.regime, ArqRegime::Healthy);
        assert_eq!(decision.allowed_epoch_budget, 100);
        let raw = engine.compute_batch_root(engine.current_epoch, &claims);
        assert_ne!(arq_root, raw);

        let legacy_attestations: Vec<_> = validator_keys[..2]
            .iter()
            .map(|k| SporocarpAttestation::sign(&engine.chain_id, engine.current_epoch, raw, k))
            .collect();
        assert_eq!(
            engine
                .settle_epoch(&claims, &legacy_attestations)
                .unwrap_err(),
            MintError::ArqModeMismatch,
        );
        assert!(engine
            .settle_epoch_arq(&claims, &legacy_attestations)
            .is_err());
        assert_eq!(engine.total_supply, 0);
        assert_eq!(engine.current_epoch, 0);

        let valid_attestations: Vec<_> = validator_keys[..2]
            .iter()
            .map(|k| {
                SporocarpAttestation::sign(&engine.chain_id, engine.current_epoch, arq_root, k)
            })
            .collect();
        let receipts = engine
            .settle_epoch_arq(&claims, &valid_attestations)
            .unwrap();
        assert_eq!(receipts.len(), 2);
        assert!(engine.total_supply <= decision.allowed_epoch_budget);
        assert_eq!(
            receipts.iter().map(|r| r.amount).sum::<u64>(),
            engine.total_supply
        );
        assert_eq!(engine.current_epoch, 1);
        let restored: MainnetMintEngine =
            serde_json::from_str(&serde_json::to_string(&engine).unwrap()).unwrap();
        assert_eq!(restored.arq_policy(), Some(&governance));
        assert_eq!(restored.total_supply, engine.total_supply);
        assert!(engine
            .settle_epoch_arq(&claims, &valid_attestations)
            .is_err());
    }

    #[test]
    fn arq_stressed_single_producer_receives_only_fraction_of_issuance() {
        let (validator_keys, validators) = make_sporocarps(&[12, 13, 14]);
        let mut monetary = MonetaryPolicy::mainnet();
        monetary.min_hashcash_bits = 4;
        monetary.initial_epoch_budget = 100;
        monetary.max_node_share_bps = 10_000;
        let mut engine = MainnetMintEngine::genesis_arq(
            "mint-arq-test",
            b"genesis-stressed",
            monetary,
            validators,
            2,
            ArqMintPolicy::default(),
        )
        .unwrap();
        let claims = vec![WorkClaim::build_signed(
            "mint-arq-test",
            0,
            NodeId::derive(b"solo-worker"),
            &key_from_byte(99),
            ContentId::of(b"arq-solo"),
            TxKind::Compute,
            100,
            1000,
            1000,
            4,
        )];
        let (root, decision) = engine.compute_arq_batch_root(&claims).unwrap();
        assert_eq!(decision.regime, ArqRegime::Stressed);
        assert_eq!(decision.allowed_epoch_budget, 25);
        let attestations: Vec<_> = validator_keys[..2]
            .iter()
            .map(|k| SporocarpAttestation::sign(&engine.chain_id, engine.current_epoch, root, k))
            .collect();
        let receipts = engine.settle_epoch_arq(&claims, &attestations).unwrap();
        assert_eq!(receipts[0].amount, 25);
        assert_eq!(engine.total_supply, 25);
        assert_eq!(engine.current_epoch, 1);
    }

    #[test]
    fn halving_schedule_and_shift_saturation() {
        let policy = MonetaryPolicy::mainnet();
        assert_eq!(policy.epoch_budget(0, 0), 50 * COIN);
        assert_eq!(policy.epoch_budget(209_999, 0), 50 * COIN);
        assert_eq!(policy.epoch_budget(210_000, 0), 25 * COIN);
        assert_eq!(policy.epoch_budget(420_000, 0), 12_5000_0000);
        assert_eq!(policy.epoch_budget(630_000, 0), 6_2500_0000);
        assert_eq!(policy.epoch_budget(210_000 * 64, 0), 0);
        assert_eq!(policy.epoch_budget(u64::MAX, 0), 0);
    }

    #[test]
    fn usdc_parity_conversion_1_myc_equals_8_usdc() {
        let policy = MonetaryPolicy::mainnet();
        assert_eq!(policy.usdc_per_myc, 8);
        assert_eq!(policy.myc_to_usdc(COIN), 8 * COIN as u128);
        assert_eq!(policy.myc_to_usdc(50 * COIN), 400 * COIN as u128);
        assert_eq!(policy.usdc_to_myc(8 * COIN as u128), COIN);
        assert_eq!(policy.usdc_to_myc(400 * COIN as u128), 50 * COIN);
    }

    #[test]
    fn supply_cap_never_exceeded() {
        let (val_keys, sporocarps) = make_sporocarps(&[1, 2, 3]);
        let mut policy = MonetaryPolicy::mainnet();
        policy.max_supply = 120;
        policy.initial_epoch_budget = 100;
        policy.halving_epochs = 10;
        policy.max_node_share_bps = 10_000;
        policy.min_hashcash_bits = 4;

        let mut engine =
            MainnetMintEngine::genesis("mycelium-test", b"genesis", policy, sporocarps, 2)
                .expect("genesis válido");

        let producer = NodeId::derive(b"produtor-1");
        let client = key_from_byte(99);

        let c0 = WorkClaim::build_signed(
            "mycelium-test",
            0,
            producer,
            &client,
            ContentId::of(b"work-0"),
            TxKind::Compute,
            10,
            5_000,
            5_000,
            4,
        );
        let att0 = sign_batch(&engine, &[c0.clone()], &val_keys[..2]);
        let r0 = engine.settle_epoch(&[c0], &att0).expect("época 0 ok");
        assert_eq!(r0[0].amount, 100);
        assert_eq!(engine.total_supply, 100);

        let c1 = WorkClaim::build_signed(
            "mycelium-test",
            1,
            producer,
            &client,
            ContentId::of(b"work-1"),
            TxKind::Compute,
            10,
            5_000,
            5_000,
            4,
        );
        let att1 = sign_batch(&engine, &[c1.clone()], &val_keys[..2]);
        let r1 = engine.settle_epoch(&[c1], &att1).expect("época 1 ok");
        assert_eq!(r1[0].amount, 20);
        assert_eq!(engine.total_supply, 120);

        let c2 = WorkClaim::build_signed(
            "mycelium-test",
            2,
            producer,
            &client,
            ContentId::of(b"work-2"),
            TxKind::Compute,
            10,
            5_000,
            5_000,
            4,
        );
        let att2 = sign_batch(&engine, &[c2.clone()], &val_keys[..2]);
        assert_eq!(
            engine.settle_epoch(&[c2], &att2).unwrap_err(),
            MintError::SupplyExhausted
        );
    }

    #[test]
    fn anti_replay_blocks_duplicate_claim_same_and_future_epoch() {
        let (val_keys, sporocarps) = make_sporocarps(&[10, 11, 12]);
        let mut policy = MonetaryPolicy::mainnet();
        policy.min_hashcash_bits = 4;
        policy.max_node_share_bps = 5_000;

        let mut engine =
            MainnetMintEngine::genesis("mycelium-replay", b"seed", policy, sporocarps, 2)
                .expect("genesis válido");

        let producer = NodeId::derive(b"produtor-replay");
        let client = key_from_byte(42);
        let work_id = ContentId::of(b"plot-unico-1");

        let claim = WorkClaim::build_signed(
            "mycelium-replay",
            0,
            producer,
            &client,
            work_id,
            TxKind::Seeding,
            50,
            2_000,
            2_000,
            4,
        );

        let dup_batch = vec![claim.clone(), claim.clone()];
        let att_dup = sign_batch(&engine, &dup_batch, &val_keys[..2]);
        assert_eq!(
            engine.settle_epoch(&dup_batch, &att_dup).unwrap_err(),
            MintError::ReplayedClaim
        );

        let att0 = sign_batch(&engine, &[claim.clone()], &val_keys[..2]);
        assert!(engine.settle_epoch(&[claim], &att0).is_ok());

        let replay_next = WorkClaim::build_signed(
            "mycelium-replay",
            1,
            producer,
            &client,
            work_id,
            TxKind::Seeding,
            50,
            2_000,
            2_000,
            4,
        );
        let att1 = sign_batch(&engine, &[replay_next.clone()], &val_keys[..2]);
        assert_eq!(
            engine.settle_epoch(&[replay_next], &att1).unwrap_err(),
            MintError::ReplayedClaim
        );
    }

    #[test]
    fn anti_whale_cap_limits_single_node_share() {
        let (val_keys, sporocarps) = make_sporocarps(&[21, 22, 23]);
        let mut policy = MonetaryPolicy::mainnet();
        policy.initial_epoch_budget = 10_000;
        policy.max_node_share_bps = 500;
        policy.min_hashcash_bits = 4;

        let mut engine =
            MainnetMintEngine::genesis("mycelium-whale", b"seed", policy, sporocarps, 2)
                .expect("genesis válido");

        let whale = NodeId::derive(b"no-baleia");
        let client = key_from_byte(77);

        let claim = WorkClaim::build_signed(
            "mycelium-whale",
            0,
            whale,
            &client,
            ContentId::of(b"mega-job"),
            TxKind::Compute,
            1_000_000,
            10_000,
            10_000,
            4,
        );
        let att = sign_batch(&engine, &[claim.clone()], &val_keys[..2]);
        let receipts = engine
            .settle_epoch(&[claim], &att)
            .expect("época liquidada");

        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].amount, 500);
        assert_eq!(engine.total_supply, 500);
    }

    #[test]
    fn quorum_rejects_insufficient_duplicate_and_unauthorized_validators() {
        let (val_keys, sporocarps) = make_sporocarps(&[31, 32, 33]);
        let rogue = key_from_byte(99);
        let mut policy = MonetaryPolicy::mainnet();
        policy.min_hashcash_bits = 4;

        let mut engine =
            MainnetMintEngine::genesis("mycelium-quorum", b"seed", policy, sporocarps, 2)
                .expect("genesis válido");

        let claim = WorkClaim::build_signed(
            "mycelium-quorum",
            0,
            NodeId::derive(b"prod-q"),
            &key_from_byte(88),
            ContentId::of(b"work-q"),
            TxKind::Relay,
            10,
            1_000,
            1_000,
            4,
        );

        let att_one = sign_batch(&engine, &[claim.clone()], &val_keys[..1]);
        assert_eq!(
            engine.settle_epoch(&[claim.clone()], &att_one).unwrap_err(),
            MintError::InsufficientQuorum { got: 1, need: 2 }
        );

        let att_dup = sign_batch(
            &engine,
            &[claim.clone()],
            &[val_keys[0].clone(), val_keys[0].clone()],
        );
        assert_eq!(
            engine.settle_epoch(&[claim.clone()], &att_dup).unwrap_err(),
            MintError::DuplicateValidator(node_id_of(&val_keys[0]))
        );

        let att_rogue = sign_batch(
            &engine,
            &[claim.clone()],
            &[val_keys[0].clone(), rogue.clone()],
        );
        assert_eq!(
            engine.settle_epoch(&[claim], &att_rogue).unwrap_err(),
            MintError::UnauthorizedValidator(node_id_of(&rogue))
        );
    }

    #[test]
    fn pedersen_chronicle_and_nutrient_ledger_integration() {
        let (val_keys, sporocarps) = make_sporocarps(&[41, 42, 43]);
        let mut policy = MonetaryPolicy::mainnet();
        policy.initial_epoch_budget = 1_000;
        policy.max_node_share_bps = 10_000;
        policy.min_hashcash_bits = 4;

        let mut engine =
            MainnetMintEngine::genesis("mycelium-e2e", b"genesis-e2e", policy, sporocarps, 2)
                .expect("genesis válido");

        let genesis_parent = engine.epoch_parents[0];
        let producer = NodeId::derive(b"produtor-e2e");
        let client = key_from_byte(55);

        let claim = WorkClaim::build_signed(
            "mycelium-e2e",
            0,
            producer,
            &client,
            ContentId::of(b"re-provm-proof-1"),
            TxKind::Compute,
            100,
            5_000,
            5_000,
            4,
        );
        let att = sign_batch(&engine, &[claim.clone()], &val_keys[..2]);
        let receipts = engine.settle_epoch(&[claim], &att).expect("liquidação e2e");

        assert_eq!(receipts.len(), 1);
        let receipt = &receipts[0];
        assert_eq!(receipt.nutrient, Nutrient::Atp);
        assert_eq!(receipt.amount, 1_000);
        assert!(receipt.verify_commitment().is_ok());
        assert_ne!(engine.epoch_parents[0], genesis_parent);
        assert_eq!(engine.epoch_parents[0], receipt.chronicle_hash);

        let mut ledger = Ledger::new();
        MainnetMintEngine::apply_receipt_to_ledger(receipt, &mut ledger)
            .expect("crédito no ledger");
        assert_eq!(ledger.balance(Nutrient::Atp), 1_000);
        assert_eq!(ledger.history().len(), 1);
        assert_eq!(ledger.history()[0].kind, Some(TxKind::Compute));
    }
}
