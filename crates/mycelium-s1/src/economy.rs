//! Customer checkout through the existing, operator-authorised Economy verifier.
//! Neither HTTP requests nor environment variables may install payment authority.
use crate::billing::Store;
use fs2::FileExt;
use mycelium_economy::{
    base_usdc::{BaseUsdcVerifier, BASE_CHAIN_ID, BASE_USDC},
    boundary::{ControlledAddressRegistry, SettlementAsset},
    chain_provider,
    policy_auth::{validate_outcome_policy, PinnedTrustStore, PolicyExpectations, ProviderIdentityConstraints, ValidatedOutcomePolicy},
    policy_watermark::{load_signed_policy, PolicyHighWaterMarkStore, PolicyStanding},
    verified_view::VerifiedRevenueView,
    verifier_key_store::{load_bound_verifier_runtime_key, TrustRoot},
    JobRequest, JobType, LedgerRecord, LocalEconomy, PaymentIntent, PaymentPolicy,
    SettlementMode, SettlementReceipt, WorkReceipt, SCHEMA_VERSION, now_unix, stable_id,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{fs::{self, File, OpenOptions}, io::Write, path::{Path, PathBuf}};

fn err(e: impl std::fmt::Display) -> String { e.to_string() }
fn valid_id(s: &str) -> bool { !s.is_empty() && s.len() <= 80 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b)) }

/// Reject symlinks in every existing path component, including parent directories.
pub(crate) fn no_symlinks(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for part in path.components() {
        if matches!(part, std::path::Component::ParentDir) { return Err("parent paths are forbidden".into()); }
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(m) if m.file_type().is_symlink() => return Err("symlink storage is forbidden".into()),
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(err(e)),
        }
    }
    Ok(())
}
pub(crate) fn private_dir(path: &Path) -> Result<(), String> {
    no_symlinks(path)?;
    fs::create_dir_all(path).map_err(err)?;
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(err)?; }
    Ok(())
}
pub(crate) fn private_file(path: &Path) -> Result<(), String> {
    no_symlinks(path)?;
    let m = fs::metadata(path).map_err(err)?;
    if !m.is_file() { return Err("regular file required".into()); }
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; if m.permissions().mode() & 0o077 != 0 { return Err("private file permissions required".into()); } }
    Ok(())
}
pub(crate) fn private_options() -> OpenOptions {
    let mut o = OpenOptions::new();
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; o.mode(0o600); }
    o
}
pub(crate) fn atomic_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    no_symlinks(path)?;
    let parent = path.parent().ok_or("missing storage directory")?;
    let mut nonce = [0;16]; rand::rngs::OsRng.fill_bytes(&mut nonce);
    let temp = parent.join(format!(".pending-{}", hex::encode(nonce)));
    let result = (|| {
        let mut file = private_options().write(true).create_new(true).open(&temp).map_err(err)?;
        file.write_all(&serde_json::to_vec(value).map_err(err)?).map_err(err)?;
        file.sync_all().map_err(err)?;
        fs::rename(&temp,path).map_err(err)?;
        File::open(parent).and_then(|f| f.sync_all()).map_err(err)
    })();
    if result.is_err() { let _ = fs::remove_file(temp); }
    result
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct CreditPack { pub id: &'static str, pub evaluations: u64, pub amount_raw: u64 }
pub const CREDIT_PACKS: [CreditPack;4] = [
    CreditPack{id:"100k",evaluations:100_000,amount_raw:1_500_000},
    CreditPack{id:"1m",evaluations:1_000_000,amount_raw:12_000_000},
    CreditPack{id:"10m",evaluations:10_000_000,amount_raw:80_000_000},
    CreditPack{id:"100m",evaluations:100_000_000,amount_raw:500_000_000},
];
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckoutQuote {
    pub studio: String, pub order_id: String, pub pack_id: String,
    pub evaluations: u64, pub chain_id: u64, pub token: String,
    pub recipient: String, pub exact_amount_raw: u64,
    pub min_confirmations: u64, pub job_id: String,
    pub payment_intent_id: String, pub policy_hash: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Order { quote: CheckoutQuote, transaction_hash: Option<String> }
#[derive(Debug, Serialize)]
pub struct CheckoutConfirmation { pub order_id: String, pub transaction_hash: String, pub evaluations: u64, pub balance: u64 }
#[derive(Debug, Serialize)]
pub struct CheckoutReadiness { pub enabled: bool, pub reason: String }
struct Authority {
    economy: LocalEconomy, registry: ControlledAddressRegistry,
    verifier: BaseUsdcVerifier, policy: ValidatedOutcomePolicy, payment: PaymentPolicy,
}
pub struct EconomyCheckout { s1_home: PathBuf, economy_home: PathBuf, trust_root: TrustRoot }
impl EconomyCheckout {
    pub fn new(s1_home: impl Into<PathBuf>, economy_home: impl Into<PathBuf>) -> Self {
        Self {s1_home:s1_home.into(),economy_home:economy_home.into(),trust_root:TrustRoot::system_default()}
    }
    fn authority(&self) -> Result<Authority,String> {
        // Check existing configuration before open() can initialise any storage.
        private_file(&self.economy_home.join("payment-policy.json"))?;
        let payment: PaymentPolicy = serde_json::from_slice(&fs::read(self.economy_home.join("payment-policy.json")).map_err(err)?).map_err(err)?;
        if payment.chain_id != BASE_CHAIN_ID || !payment.token.eq_ignore_ascii_case(BASE_USDC) || payment.min_confirmations == 0 { return Err("Base USDC policy required".into()); }
        let pin = payment.chain_provider.as_ref().ok_or("operator-pinned verifier required")?;
        pin.validate_policy_pin().map_err(err)?;
        pin.verify_socket_identity().map_err(err)?;
        let resolved = chain_provider::resolve(None,Some(pin)).map_err(err)?;
        let registry = ControlledAddressRegistry::from_policy(&payment).map_err(err)?;
        let constraints = ProviderIdentityConstraints::from_pinned_provider(pin);
        let signed = load_signed_policy(&self.economy_home).map_err(err)?;
        let trust = PinnedTrustStore::load(self.trust_root.trust_store_config()).map_err(err)?;
        let policy = validate_outcome_policy(&signed,&trust,PolicyExpectations {chain_id:BASE_CHAIN_ID,registry:&registry,provider:&constraints}).map_err(err)?;
        if !policy.executor().as_str().eq_ignore_ascii_case(&payment.payout_address) || policy.min_confirmations() != payment.min_confirmations { return Err("payment policy mismatch".into()); }
        let standing = PolicyHighWaterMarkStore::open(&self.economy_home).map_err(err)?.evaluate(&policy).map_err(err)?;
        if !matches!(standing,PolicyStanding::AlreadyInForce) { return Err("operator must activate signed policy".into()); }
        load_bound_verifier_runtime_key(&policy,&self.trust_root.key_store_config()).map_err(err)?;
        let verifier = BaseUsdcVerifier::from_resolved(&resolved,payment.min_confirmations).map_err(err)?;
        let economy = LocalEconomy::open(&self.economy_home).map_err(err)?;
        Ok(Authority {economy,registry,verifier,policy,payment})
    }
    pub fn readiness(&self) -> CheckoutReadiness {
        let enabled = self.authority().is_ok();
        CheckoutReadiness {enabled,reason:if enabled {"trusted_verifier_ready"} else {"requires_operator_payment_policy_and_trusted_verifier"}.into()}
    }
    fn lock(&self) -> Result<File,String> {
        private_dir(&self.s1_home)?;
        let path = self.s1_home.join("checkout.lock"); no_symlinks(&path)?;
        let f = private_options().read(true).write(true).create(true).truncate(false).open(path).map_err(err)?;
        f.try_lock_exclusive().map_err(err)?;
        Ok(f)
    }
    fn order_path(&self, studio: &str, order: &str) -> PathBuf {
        self.s1_home.join("orders").join(format!("{}.json",stable_id("order",&[studio,order])))
    }
    fn read_order(&self,path:&Path) -> Result<Order,String> {
        private_file(path)?;
        serde_json::from_slice(&fs::read(path).map_err(err)?).map_err(err)
    }
    fn validate_quote(&self,a:&Authority,q:&CheckoutQuote,studio:&str,order:&str) -> Result<PaymentIntent,String> {
        let pack = CREDIT_PACKS.iter().find(|p| p.id == q.pack_id).ok_or("unknown credit pack")?;
        if q.studio != studio || q.order_id != order || q.evaluations != pack.evaluations || q.exact_amount_raw != pack.amount_raw || q.chain_id != BASE_CHAIN_ID || !q.token.eq_ignore_ascii_case(BASE_USDC) || !q.recipient.eq_ignore_ascii_case(&a.payment.payout_address) || q.min_confirmations != a.payment.min_confirmations || q.policy_hash != a.policy.policy_hash().map_err(err)?.as_str() { return Err("order binding mismatch".into()); }
        if q.job_id != stable_id("s1checkout",&[studio,order]) { return Err("job binding mismatch".into()); }
        let intent = a.economy.payment_intent_for_job(&q.job_id).map_err(err)?.ok_or("payment intent missing")?;
        if intent.payment_intent_id != q.payment_intent_id || intent.chain_id != q.chain_id || !intent.token.eq_ignore_ascii_case(&q.token) || !intent.recipient.eq_ignore_ascii_case(&q.recipient) || intent.exact_amount_raw != q.exact_amount_raw { return Err("intent binding mismatch".into()); }
        let job = a.economy.job(&q.job_id).map_err(err)?.ok_or("job missing")?;
        if job.requester_id != studio || job.internal_work || job.max_price_musd_micros != pack.amount_raw || job.input_hash != stable_id("s1pack",&[studio,order,pack.id]) { return Err("job mismatch".into()); }
        Ok(intent)
    }
    pub fn quote(&self, studio:&str, order_id:&str, pack_id:&str) -> Result<CheckoutQuote,String> {
        if !valid_id(studio) || !valid_id(order_id) { return Err("invalid order identity".into()); }
        let pack = CREDIT_PACKS.iter().find(|p| p.id == pack_id).ok_or("unknown pack")?;
        let a = self.authority()?;
        let _lock = self.lock()?;
        let path = self.order_path(studio,order_id);
        if path.exists() {
            let order = self.read_order(&path)?;
            self.validate_quote(&a,&order.quote,studio,order_id)?;
            if order.quote.pack_id != pack_id { return Err("order already binds another pack".into()); }
            return Ok(order.quote);
        }
        let job_id = stable_id("s1checkout",&[studio,order_id]);
        let input_hash = stable_id("s1pack",&[studio,order_id,pack.id]);
        if let Some(job) = a.economy.job(&job_id).map_err(err)? {
            if job.requester_id != studio || job.input_hash != input_hash || job.max_price_musd_micros != pack.amount_raw || job.internal_work { return Err("existing job mismatch".into()); }
        } else {
            a.economy.append_job(JobRequest {schema_version:SCHEMA_VERSION,job_id:job_id.clone(),created_at_unix:now_unix(),requester_id:studio.into(),job_type:JobType::Inference,input_hash,max_price_musd_micros:pack.amount_raw,internal_work:false,description:format!("S1 credit pack {}",pack.id)}).map_err(err)?;
        }
        let intent = if let Some(intent) = a.economy.payment_intent_for_job(&job_id).map_err(err)? { intent } else {
            let anchor = a.verifier.anchor().map_err(err)?;
            a.economy.create_payment_intent(&job_id,anchor.block_number,&anchor.block_hash,anchor.block_timestamp_unix).map_err(err)?
        };
        let quote = CheckoutQuote {studio:studio.into(),order_id:order_id.into(),pack_id:pack.id.into(),evaluations:pack.evaluations,chain_id:BASE_CHAIN_ID,token:BASE_USDC.into(),recipient:a.payment.payout_address.clone(),exact_amount_raw:pack.amount_raw,min_confirmations:a.payment.min_confirmations,job_id,payment_intent_id:intent.payment_intent_id,policy_hash:a.policy.policy_hash().map_err(err)?.as_str().into()};
        self.validate_quote(&a,&quote,studio,order_id)?;
        private_dir(&self.s1_home.join("orders"))?;
        atomic_json(&path,&Order {quote:quote.clone(),transaction_hash:None})?;
        Ok(quote)
    }
    pub fn confirm(&self,studio:&str,order_id:&str,tx_hash:&str) -> Result<CheckoutConfirmation,String> {
        if !valid_id(studio) || !valid_id(order_id) || tx_hash.len()!=66 || !tx_hash.starts_with("0x") || !tx_hash[2..].bytes().all(|b| b.is_ascii_hexdigit()) { return Err("invalid payment identity".into()); }
        let tx = tx_hash.to_ascii_lowercase();
        let a = self.authority()?;
        let _lock = self.lock()?;
        let path = self.order_path(studio,order_id);
        let mut order = self.read_order(&path)?;
        let intent = self.validate_quote(&a,&order.quote,studio,order_id)?;
        if order.transaction_hash.as_ref().is_some_and(|old| old != &tx) { return Err("order already paid with another transaction".into()); }
        let records = a.economy.records().map_err(err)?;
        let mut settlement = None;
        for record in &records {
            if let LedgerRecord::Settlement {settlement:s,..} = record {
                if s.payment_proof_hash.as_ref().is_some_and(|h| h.eq_ignore_ascii_case(&tx)) && s.job_id != intent.job_id { return Err("transaction already used".into()); }
                if s.job_id == intent.job_id {
                    if !s.payment_proof_hash.as_ref().is_some_and(|h| h.eq_ignore_ascii_case(&tx)) { return Err("order already settled".into()); }
                    settlement = Some(s.clone());
                }
            }
        }
        if settlement.is_none() {
            let proof = a.verifier.verify_transfer(&tx,&intent.recipient,intent.exact_amount_raw).map_err(err)?;
            if !proof.verified || !proof.provider_identity_verified || proof.chain_id != intent.chain_id || !proof.token.eq_ignore_ascii_case(&intent.token) || !proof.recipient.eq_ignore_ascii_case(&intent.recipient) || proof.matched_raw != intent.exact_amount_raw || proof.confirmations < order.quote.min_confirmations || proof.block_number <= intent.anchor_block || proof.block_timestamp_unix < intent.anchor_timestamp_unix { return Err("payment not confirmed".into()); }
            let work_id = stable_id("s1creditwork",&[&intent.job_id]);
            if !records.iter().any(|r| matches!(r,LedgerRecord::Work {receipt,..} if receipt.job_id == intent.job_id)) {
                a.economy.append_work(WorkReceipt {schema_version:SCHEMA_VERSION,receipt_id:work_id.clone(),job_id:intent.job_id.clone(),worker_id:"s1-credit-issuer".into(),started_at_unix:intent.created_at_unix,completed_at_unix:now_unix(),result_hash:stable_id("s1credits",&[&intent.job_id,&order.quote.evaluations.to_string()]),useful_work_units:order.quote.evaluations,verifier_id:"s1-checkout".into(),verified_at_unix:now_unix(),verified:true}).map_err(err)?;
            }
            let s = SettlementReceipt {schema_version:SCHEMA_VERSION,settlement_id:stable_id("s1settlement",&[&intent.job_id]),job_id:intent.job_id.clone(),work_receipt_id:work_id,settled_at_unix:now_unix(),mode:SettlementMode::External,settlement_asset:SettlementAsset::base_usdc(),settled_amount_micros:intent.exact_amount_raw,usd_equivalent_micros:intent.exact_amount_raw,payment_intent_id:Some(intent.payment_intent_id.clone()),payment_block_number:Some(proof.block_number),payment_proof_hash:Some(tx.clone()),payment_proof_verified:true,external_paid:true,internal_work:false};
            a.economy.append_settlement(s.clone()).map_err(err)?;
            settlement = Some(s);
        }
        let settlement = settlement.ok_or("settlement missing")?;
        // Reissue an identical attestation after interruption; flags grant no credit.
        let key = load_bound_verifier_runtime_key(&a.policy,&self.trust_root.key_store_config()).map_err(err)?;
        let attestation = key.attest_settlement(&a.policy,&settlement,&intent).map_err(err)?;
        a.economy.record_settlement_attestation(&attestation).map_err(err)?;
        let evidence = VerifiedRevenueView::provider_pinned(&a.economy,&a.registry,&a.verifier,&a.policy).map_err(err)?.settlement_evidence().map_err(err)?;
        if !evidence.iter().any(|e| e.settlement_id == settlement.settlement_id && e.job_id == intent.job_id && e.counted && e.policy_hash.as_deref() == Some(order.quote.policy_hash.as_str())) { return Err("settlement lacks verified authority".into()); }
        let mut store = Store::open(&self.s1_home).map_err(err)?;
        // Receipt identity is global across studios and case-independent.
        store.ledger.credit(&format!("base-usdc:{tx}"),studio,order.quote.evaluations)?;
        store.save().map_err(err)?;
        order.transaction_hash = Some(tx.clone());
        atomic_json(&path,&order)?;
        Ok(CheckoutConfirmation {order_id:order_id.into(),transaction_hash:tx,evaluations:order.quote.evaluations,balance:store.ledger.balances.get(studio).copied().unwrap_or(0)})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_configuration_does_not_initialise_economy_or_s1() {
        let d = tempfile::tempdir().unwrap();
        let checkout = EconomyCheckout::new(d.path().join("s1"),d.path().join("economy"));
        assert!(!checkout.readiness().enabled);
        assert!(checkout.quote("studio","order","1m").is_err());
        assert!(!d.path().join("economy").exists());
        assert!(!d.path().join("s1").exists());
    }
    #[test]
    fn invalid_identity_never_touches_storage() {
        let d = tempfile::tempdir().unwrap();
        let checkout = EconomyCheckout::new(d.path().join("s1"),d.path().join("economy"));
        assert!(checkout.quote("../studio","order","1m").is_err());
        assert!(checkout.confirm("studio","order","0x123").is_err());
        assert!(!d.path().join("s1").exists());
    }
}
