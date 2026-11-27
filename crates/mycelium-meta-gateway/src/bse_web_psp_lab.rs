//! W6: isolated, in-memory PSP/DICT teaching model. All credits are fictional.
//! No production identities, BRL balances, bank messages, webhooks or network.
use crate::pix_state::{validate_transition, Entity, LabConditions, State};
use std::collections::BTreeMap;

pub const MAX_CHARGES: usize = 128;
const MAX_CREDITS: u64 = 100_000;
type R<T> = Result<T, LabError>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabError {
    UnknownKey,
    UnknownCharge,
    InvalidId,
    InvalidAmount,
    Conflict,
    Capacity,
    Closed,
    InsufficientCredits,
    SelfTransfer,
    InternalInvariant,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Account {
    Buyer,
    Merchant,
    Other,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabPsp {
    Alpha,
    Beta,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabDirectoryEntry {
    pub account: Account,
    pub psp: LabPsp,
}
/// Only these non-routable, fixed fixture names exist; no fallback or remote lookup.
pub fn resolve_lab_key(key: &str) -> R<LabDirectoryEntry> {
    let (account, psp) = match key {
        "buyer@lab.invalid" => (Account::Buyer, LabPsp::Alpha),
        "merchant@lab.invalid" => (Account::Merchant, LabPsp::Beta),
        "other@lab.invalid" => (Account::Other, LabPsp::Beta),
        _ => return Err(LabError::UnknownKey),
    };
    Ok(LabDirectoryEntry { account, psp })
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargeKind {
    Immediate,
    Due,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabChargeState {
    Open,
    ClosedBySimulation,
    Cancelled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabCharge {
    pub kind: ChargeKind,
    pub recipient: Account,
    pub credits: u64,
    pub state: LabChargeState,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateResult {
    Created,
    Existing,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulateResult {
    Applied,
    AlreadyApplied,
}
/// State is never persisted or exported as a payment receipt. No production
/// gateway engine, callbacks, signing keys, bank account or currency is touched.
pub struct LabPspSimulator {
    balances: BTreeMap<Account, u64>,
    charges: BTreeMap<u32, LabCharge>,
    simulated_by: BTreeMap<u32, Account>,
}
impl Default for LabPspSimulator {
    fn default() -> Self {
        Self::new()
    }
}
impl LabPspSimulator {
    pub fn new() -> Self {
        Self {
            balances: BTreeMap::from([
                (Account::Buyer, 1000),
                (Account::Merchant, 0),
                (Account::Other, 50),
            ]),
            charges: BTreeMap::new(),
            simulated_by: BTreeMap::new(),
        }
    }
    pub fn credits(&self, a: Account) -> u64 {
        self.balances[&a]
    }
    pub fn total_credits(&self) -> u64 {
        self.balances.values().sum()
    }
    pub fn charge(&self, id: u32) -> R<LabCharge> {
        self.charges
            .get(&id)
            .copied()
            .ok_or(LabError::UnknownCharge)
    }
    /// Fixture ID is deliberately an integer, not a real Pix TXID.
    pub fn create(
        &mut self,
        id: u32,
        kind: ChargeKind,
        recipient_key: &str,
        credits: u64,
    ) -> R<CreateResult> {
        if id == 0 {
            return Err(LabError::InvalidId);
        }
        if !(1..=MAX_CREDITS).contains(&credits) {
            return Err(LabError::InvalidAmount);
        }
        let recipient = resolve_lab_key(recipient_key)?.account;
        if let Some(c) = self.charges.get(&id) {
            return if (c.kind, c.recipient, c.credits) == (kind, recipient, credits) {
                Ok(CreateResult::Existing)
            } else {
                Err(LabError::Conflict)
            };
        }
        if self.charges.len() >= MAX_CHARGES {
            return Err(LabError::Capacity);
        }
        self.charges.insert(
            id,
            LabCharge {
                kind,
                recipient,
                credits,
                state: LabChargeState::Open,
            },
        );
        Ok(CreateResult::Created)
    }
    fn entity(kind: ChargeKind) -> Entity {
        match kind {
            ChargeKind::Immediate => Entity::Cob,
            ChargeKind::Due => Entity::Cobv,
        }
    }
    /// Explicit local simulation action, not an authorization or settlement.
    pub fn simulate_transfer(&mut self, id: u32, source: Account) -> R<SimulateResult> {
        let c = self.charge(id)?;
        if c.state == LabChargeState::ClosedBySimulation {
            return if self.simulated_by.get(&id) == Some(&source) {
                Ok(SimulateResult::AlreadyApplied)
            } else {
                Err(LabError::Closed)
            };
        }
        if c.state != LabChargeState::Open {
            return Err(LabError::Closed);
        }
        if c.recipient == source {
            return Err(LabError::SelfTransfer);
        }
        let debit = self
            .credits(source)
            .checked_sub(c.credits)
            .ok_or(LabError::InsufficientCredits)?;
        let credit = self
            .credits(c.recipient)
            .checked_add(c.credits)
            .ok_or(LabError::InternalInvariant)?;
        validate_transition(
            Self::entity(c.kind),
            State::Ativa,
            State::Concluida,
            LabConditions {
                simulated_attempt_paid: true,
                ..Default::default()
            },
        )
        .map_err(|_| LabError::InternalInvariant)?;
        self.balances.insert(source, debit);
        self.balances.insert(c.recipient, credit);
        self.charges.get_mut(&id).unwrap().state = LabChargeState::ClosedBySimulation;
        self.simulated_by.insert(id, source);
        Ok(SimulateResult::Applied)
    }
    pub fn cancel(&mut self, id: u32) -> R<()> {
        let c = self.charge(id)?;
        if c.state == LabChargeState::Cancelled {
            return Ok(());
        }
        if c.state != LabChargeState::Open {
            return Err(LabError::Closed);
        }
        validate_transition(
            Self::entity(c.kind),
            State::Ativa,
            State::RemovidoPeloUsuarioRecebedor,
            LabConditions::default(),
        )
        .map_err(|_| LabError::InternalInvariant)?;
        self.charges.get_mut(&id).unwrap().state = LabChargeState::Cancelled;
        Ok(())
    }
}
/// No externally usable identifiers, raw payment payload or financial receipt.
#[derive(Debug, PartialEq, Eq)]
pub struct LabReport {
    pub directory_ok: bool,
    pub idempotency_ok: bool,
    pub simulated_transfer_ok: bool,
    pub insufficient_credits_rejected: bool,
    pub duplicate_prevented: bool,
    pub cancel_ok: bool,
    pub conserved: bool,
    pub buyer_credits: u64,
    pub merchant_credits: u64,
    pub w1_fixture_ok: bool,
    pub w2_fixture_ok: bool,
    pub w3_fixture_ok: bool,
    pub w5_fixture_ok: bool,
}
impl LabReport {
    pub const fn is_verified(&self) -> bool {
        false
    }
}
pub fn run_lab() -> R<LabReport> {
    use crate::http_observer::{observe_http_trace, BodyState};
    use crate::iso20022::{inspect_iso, Family};
    use crate::pix_json::{inspect_json, Context, PayloadKind};
    let mut s = LabPspSimulator::new();
    let initial = s.total_credits();
    let directory_ok = resolve_lab_key("merchant@lab.invalid")?.psp == LabPsp::Beta
        && resolve_lab_key("unknown@lab.invalid").is_err();
    s.create(1, ChargeKind::Immediate, "merchant@lab.invalid", 120)?;
    let idempotency_ok =
        s.create(1, ChargeKind::Immediate, "merchant@lab.invalid", 120)? == CreateResult::Existing;
    let simulated_transfer_ok = s.simulate_transfer(1, Account::Buyer)? == SimulateResult::Applied;
    let duplicate_prevented = s.simulate_transfer(1, Account::Buyer)?
        == SimulateResult::AlreadyApplied
        && s.credits(Account::Merchant) == 120;
    s.create(2, ChargeKind::Due, "merchant@lab.invalid", 900)?;
    let insufficient_credits_rejected =
        s.simulate_transfer(2, Account::Buyer) == Err(LabError::InsufficientCredits);
    s.cancel(2)?;
    let cancel_ok = s.charge(2)?.state == LabChargeState::Cancelled;
    // Existing public manual sample, inspected only. No QR emitted or accessed.
    let w1_fixture_ok=crate::inspect_pix("00020101021226700014br.gov.bcb.pix2548pix.example.com/8b3da2f39a4140d1a91abd93113bd4415204000053039865802BR5913Fulano de Tal6008BRASILIA62070503***630464E4").is_ok();
    let body=serde_json::json!({"revisao":0,"calendario":{"criacao":"2026-11-25T10:00:00Z","apresentacao":"2026-11-25T10:01:00Z"},"valor":{"original":"12.34"},"chave":"fixture@example.invalid","txid":"ABCDEFGHIJKLMNOPQRSTUVWXYZ","status":"ATIVA"}).to_string();
    let w2_fixture_ok =
        inspect_json(&body, PayloadKind::Cob, Context::Dynamic).is_ok_and(|p| !p.is_verified());
    let trace=serde_json::json!({"method":"GET","path":"/lab/payload/cob","status":200,"content_type":"application/json","body":body}).to_string();
    let w3_fixture_ok = observe_http_trace(&trace)
        .is_ok_and(|p| p.body_state == BodyState::DecodedJson && !p.is_verified());
    let w5_fixture_ok=inspect_iso(r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pain.009.001.01"><MndtInitnReq/></Document>"#).is_ok_and(|p|p.family==Family::Pain009&&!p.missing_selected.is_empty()&&!p.is_verified());
    Ok(LabReport {
        directory_ok,
        idempotency_ok,
        simulated_transfer_ok,
        insufficient_credits_rejected,
        duplicate_prevented,
        cancel_ok,
        conserved: s.total_credits() == initial,
        buyer_credits: s.credits(Account::Buyer),
        merchant_credits: s.credits(Account::Merchant),
        w1_fixture_ok,
        w2_fixture_ok,
        w3_fixture_ok,
        w5_fixture_ok,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn lab() -> LabPspSimulator {
        let mut s = LabPspSimulator::new();
        s.create(1, ChargeKind::Immediate, "merchant@lab.invalid", 100)
            .unwrap();
        s
    }
    #[test]
    fn exact_directory() {
        assert_eq!(
            resolve_lab_key("buyer@lab.invalid").unwrap().psp,
            LabPsp::Alpha
        );
        for k in [
            "real@example.com",
            "merchant@lab.invalid ",
            "12345678900",
            "MERCHANT@lab.invalid",
        ] {
            assert_eq!(resolve_lab_key(k), Err(LabError::UnknownKey));
        }
    }
    #[test]
    fn unique_ids() {
        let mut s = lab();
        assert_eq!(
            s.create(1, ChargeKind::Immediate, "merchant@lab.invalid", 100),
            Ok(CreateResult::Existing)
        );
        assert_eq!(
            s.create(1, ChargeKind::Due, "merchant@lab.invalid", 100),
            Err(LabError::Conflict)
        );
        assert_eq!(
            s.create(1, ChargeKind::Immediate, "other@lab.invalid", 100),
            Err(LabError::Conflict)
        );
    }
    #[test]
    fn invalid_input() {
        let mut s = lab();
        assert_eq!(
            s.create(0, ChargeKind::Due, "merchant@lab.invalid", 100),
            Err(LabError::InvalidId)
        );
        for n in [0, u64::MAX] {
            assert_eq!(
                s.create(2, ChargeKind::Due, "merchant@lab.invalid", n),
                Err(LabError::InvalidAmount)
            );
        }
    }
    #[test]
    fn unknown_charge() {
        let mut s = lab();
        assert_eq!(
            s.simulate_transfer(2, Account::Buyer),
            Err(LabError::UnknownCharge)
        );
    }
    #[test]
    fn conservation() {
        let mut s = lab();
        let t = s.total_credits();
        assert_eq!(
            s.simulate_transfer(1, Account::Buyer),
            Ok(SimulateResult::Applied)
        );
        assert_eq!(s.credits(Account::Buyer), 900);
        assert_eq!(s.credits(Account::Merchant), 100);
        assert_eq!(s.total_credits(), t);
    }
    #[test]
    fn duplicate() {
        let mut s = lab();
        s.simulate_transfer(1, Account::Buyer).unwrap();
        assert_eq!(
            s.simulate_transfer(1, Account::Buyer),
            Ok(SimulateResult::AlreadyApplied)
        );
        assert_eq!(
            s.simulate_transfer(1, Account::Other),
            Err(LabError::Closed)
        );
        assert_eq!(s.credits(Account::Merchant), 100);
    }
    #[test]
    fn insufficient_atomic() {
        let mut s = lab();
        let t = s.total_credits();
        assert_eq!(
            s.simulate_transfer(1, Account::Other),
            Err(LabError::InsufficientCredits)
        );
        assert_eq!(s.credits(Account::Other), 50);
        assert_eq!(s.charge(1).unwrap().state, LabChargeState::Open);
        assert_eq!(s.total_credits(), t);
    }
    #[test]
    fn self_transfer() {
        let mut s = lab();
        assert_eq!(
            s.simulate_transfer(1, Account::Merchant),
            Err(LabError::SelfTransfer)
        );
        assert_eq!(s.charge(1).unwrap().state, LabChargeState::Open);
    }
    #[test]
    fn cancel() {
        let mut s = lab();
        s.cancel(1).unwrap();
        s.cancel(1).unwrap();
        assert_eq!(
            s.simulate_transfer(1, Account::Buyer),
            Err(LabError::Closed)
        );
        assert_eq!(s.credits(Account::Buyer), 1000);
    }
    #[test]
    fn terminal_immutable() {
        let mut s = lab();
        s.simulate_transfer(1, Account::Buyer).unwrap();
        assert_eq!(s.cancel(1), Err(LabError::Closed));
        assert_eq!(
            s.create(1, ChargeKind::Immediate, "merchant@lab.invalid", 100),
            Ok(CreateResult::Existing)
        );
        assert_eq!(
            s.charge(1).unwrap().state,
            LabChargeState::ClosedBySimulation
        );
    }
    #[test]
    fn capacity() {
        let mut s = LabPspSimulator::new();
        for i in 1..=MAX_CHARGES as u32 {
            s.create(i, ChargeKind::Immediate, "merchant@lab.invalid", 1)
                .unwrap();
        }
        assert_eq!(
            s.create(999, ChargeKind::Immediate, "merchant@lab.invalid", 1),
            Err(LabError::Capacity)
        );
    }
    #[test]
    fn integrated_lab() {
        let r = run_lab().unwrap();
        assert!(
            r.directory_ok
                && r.idempotency_ok
                && r.simulated_transfer_ok
                && r.insufficient_credits_rejected
                && r.duplicate_prevented
                && r.cancel_ok
                && r.conserved
                && r.w1_fixture_ok
                && r.w2_fixture_ok
                && r.w3_fixture_ok
                && r.w5_fixture_ok
        );
        assert_eq!((r.buyer_credits, r.merchant_credits), (880, 120));
        assert!(!r.is_verified());
    }
}
