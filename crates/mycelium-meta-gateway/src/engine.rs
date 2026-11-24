//! Livro VI (Josué): O Roteador Supremo (`MetaGatewayEngine`) com resolução PKARR,
//! selo pós-quântico (ML-KEM-1024), persistência automática no `SporeBank` logo no
//! `CryptographicSeal`, e liquidação unificada MYC ↔ USDC (`1 MYC = 8 USDC`).

#[cfg(feature = "brics")]
use crate::adapters::BricsPayAdapter;
#[cfg(feature = "pix")]
use crate::adapters::PixAdapter;
#[cfg(feature = "swift")]
use crate::adapters::SwiftAdapter;
use crate::adapters::{MetaGatewayAdapter, MycSettlementAdapter};
use crate::compliance::CompliancePolicy;
use crate::core::{DispatchReceipt, GatewayType, PaymentIntent, TransactionState};
use crate::error::GatewayError;
use crate::persistence::SporebankIntentStore;
use crate::pkarr_resolver::PkarrIdentityResolver;
use ed25519_dalek::{Signer, SigningKey};
use mycelium_core::ContentId;
use mycelium_mint::MonetaryPolicy;
use mycelium_pqc::{mlkem_encapsulate, mlkem_keygen, KemKeyPair};
use mycelium_zkp::{hash_chronicle, pedersen_commit};

/// Resultado completo da execução de uma intenção no Meta-Gateway.
#[derive(Debug, Clone)]
pub struct ExecutionOutcome {
    pub intent: PaymentIntent,
    pub receipt: DispatchReceipt,
}

/// Orquestrador descentralizado (Source Port Financeiro do Mycelium).
pub struct MetaGatewayEngine {
    #[cfg(feature = "pix")]
    pub pix: Option<PixAdapter>,
    #[cfg(feature = "swift")]
    pub swift: Option<SwiftAdapter>,
    #[cfg(feature = "brics")]
    pub brics: Option<BricsPayAdapter>,
    pub myc_rail: MycSettlementAdapter,
    pub compliance: CompliancePolicy,
    pub monetary_policy: MonetaryPolicy,
    /// Resolvedor PKARR (DHT/SignedPacket) para descentralizar `sender_did` e `receiver_id`.
    pub pkarr: PkarrIdentityResolver,
    /// Persistência imutável no `SporeBank` (`[private]` Plots encadeados por `ContentId`).
    pub sporebank: Option<SporebankIntentStore>,
    node_signing_key: SigningKey,
    pqc_keypair: KemKeyPair,
    chronicle_head: [u8; 32],
}

impl MetaGatewayEngine {
    /// Inicializa o motor com identidade Ed25519, ML-KEM-1024, PKARR e política `1 MYC = 8 USDC`.
    pub fn new(node_signing_key: SigningKey, genesis_tag: &[u8]) -> Self {
        let chronicle_head = hash_chronicle(genesis_tag, &[]);
        Self {
            #[cfg(feature = "pix")]
            pix: None,
            #[cfg(feature = "swift")]
            swift: None,
            #[cfg(feature = "brics")]
            brics: None,
            myc_rail: MycSettlementAdapter::default(),
            compliance: CompliancePolicy::default(),
            monetary_policy: MonetaryPolicy::mainnet(),
            pkarr: PkarrIdentityResolver::new(),
            sporebank: None,
            node_signing_key,
            pqc_keypair: mlkem_keygen(),
            chronicle_head,
        }
    }

    /// Anexa uma instância de `SporebankIntentStore` para persistência automática em disco.
    pub fn with_sporebank(mut self, store: SporebankIntentStore) -> Self {
        self.sporebank = Some(store);
        self
    }

    fn require_encrypted_store(&self) -> Result<(), GatewayError> {
        if self.sporebank.as_ref().is_some_and(SporebankIntentStore::is_encrypted) {
            Ok(())
        } else {
            Err(GatewayError::AdapterUnavailable("sovereign-encrypted-store"))
        }
    }

    pub fn chronicle_head(&self) -> [u8; 32] {
        self.chronicle_head
    }

    pub fn recall_by_id(&self, intent_id: &str) -> Result<Option<PaymentIntent>, GatewayError> {
        match self.sporebank.as_ref() {
            Some(store) => store.load_by_id(intent_id),
            None => Ok(None),
        }
    }

    pub fn recall_by_external_ref(
        &self,
        external_ref: &str,
    ) -> Result<Option<PaymentIntent>, GatewayError> {
        match self.sporebank.as_ref() {
            Some(store) => store.load_by_external_ref(external_ref),
            None => Ok(None),
        }
    }

    pub fn latest_sporebank_cid(&self, intent_id: &str) -> Option<ContentId> {
        self.sporebank
            .as_ref()
            .and_then(|s| s.latest_cid(intent_id))
    }

    /// Resolve `receiver_id` (e valida `sender_did`) via PKARR antes de rotear e executar.
    pub fn resolve_and_execute(
        &mut self,
        amount_micros: u64,
        currency: impl Into<String>,
        sender_did: impl Into<String>,
        receiver_id: impl Into<String>,
        compliance_metadata: serde_json::Value,
    ) -> Result<ExecutionOutcome, GatewayError> {
        // Refuse even identity discovery when the private audit store is absent.
        self.require_encrypted_store()?;
        let sender = sender_did.into();
        if PkarrIdentityResolver::extract_zbase32(&sender).is_some() {
            let _ = self.pkarr.resolve_route(&sender)?;
        }

        let raw_receiver = receiver_id.into();
        let resolved_receiver = if PkarrIdentityResolver::extract_zbase32(&raw_receiver).is_some() {
            self.pkarr.resolve_route(&raw_receiver)?
        } else {
            raw_receiver
        };

        let intent = PaymentIntent::auto_route(
            amount_micros,
            currency,
            sender,
            resolved_receiver,
            compliance_metadata,
        )?;
        self.execute(intent)
    }

    /// Executa o fluxo completo com persistência imediata no `SporeBank` assim que o
    /// `CryptographicSeal` é gerado (recuperável em caso de queda antes da resposta externa).
    pub fn execute(&mut self, mut intent: PaymentIntent) -> Result<ExecutionOutcome, GatewayError> {
        if PkarrIdentityResolver::extract_zbase32(&intent.receiver_id).is_some() {
            let resolved = self.pkarr.resolve_route(&intent.receiver_id)?;
            let gw = GatewayType::infer_from_receiver(&resolved)
                .ok_or_else(|| GatewayError::InvalidTarget(resolved.clone()))?;
            intent.receiver_id = resolved;
            intent.gateway = gw;
        }

        // Sovereign-by-default: refuse payments if their audit state would
        // be lost or persisted as plaintext. No implicit fallback.
        self.require_encrypted_store()?;

        // 1. Compliance-as-Code
        self.compliance.enforce(&intent)?;
        // Third-party rails reveal a recipient and amount outside Mycelium.
        // Require explicit per-intent opt-in before even preparing their payload.
        if !matches!(intent.gateway, GatewayType::MycRail)
            && intent.compliance_metadata.get("external_disclosure_consent")
                .and_then(|v| v.as_bool()) != Some(true)
        {
            return Err(GatewayError::ComplianceViolation {
                rule: "external_disclosure_consent",
                detail: "consentimento explícito para expor dados ao trilho externo é obrigatório".into(),
            });
        }
        // Refuse fake settlement while ledger posting is not connected.
        if matches!(intent.gateway, GatewayType::MycRail) {
            return Err(GatewayError::AdapterUnavailable("myc-ledger-settlement"));
        }
        // Reject repeated intent identifiers until persisted replay receipts exist.
        if self.recall_by_id(&intent.id)?.is_some() {
            return Err(GatewayError::InvalidTarget(format!(
                "duplicate intent {}",
                intent.id
            )));
        }

        // 2. Selo Pós-Quântico + Prova de Intenção no Lattice
        let canonical = intent.canonical_bytes();
        let sig = self.node_signing_key.sign(&canonical);
        let pqc_encap = mlkem_encapsulate(&self.pqc_keypair.public_key)
            .map_err(|e| GatewayError::Crypto(e.to_string()))?;

        let (myc_micros, usdc_micros) = intent.myc_usdc_parity(&self.monetary_policy);
        let blinding = *blake3::hash(&sig.to_bytes()).as_bytes();
        let commit = pedersen_commit(myc_micros, blinding);
        let next_chronicle = hash_chronicle(&canonical, &[self.chronicle_head]);

        intent.transition_to(TransactionState::CryptographicSeal {
            chronicle_hash: hex::encode(next_chronicle),
            pqc_ciphertext_len: pqc_encap.ciphertext.len(),
            signature_hex: hex::encode(sig.to_bytes()),
            pedersen_commit_hex: hex::encode(commit),
        })?;
        // 2b. Persistência imediata no SporeBank antes do despacho externo
        if let Some(store) = self.sporebank.as_mut() {
            store.persist_intent(&intent, None)?;
        }
        // Advance the head only after durable pre-dispatch persistence succeeds.
        self.chronicle_head = next_chronicle;

        // 3. Despacho para o adaptador correspondente
        let receipt = match intent.gateway {
            GatewayType::Pix => {
                #[cfg(feature = "pix")]
                {
                    let adapter = self
                        .pix
                        .as_ref()
                        .ok_or(GatewayError::AdapterUnavailable("pix"))?;
                    adapter.dispatch(&intent)?
                }
                #[cfg(not(feature = "pix"))]
                {
                    return Err(GatewayError::AdapterUnavailable("pix"));
                }
            }
            GatewayType::Swift => {
                #[cfg(feature = "swift")]
                {
                    let adapter = self
                        .swift
                        .as_ref()
                        .ok_or(GatewayError::AdapterUnavailable("swift"))?;
                    adapter.dispatch(&intent)?
                }
                #[cfg(not(feature = "swift"))]
                {
                    return Err(GatewayError::AdapterUnavailable("swift"));
                }
            }
            GatewayType::BricsPay => {
                #[cfg(feature = "brics")]
                {
                    let adapter = self
                        .brics
                        .as_ref()
                        .ok_or(GatewayError::AdapterUnavailable("brics"))?;
                    adapter.dispatch(&intent)?
                }
                #[cfg(not(feature = "brics"))]
                {
                    return Err(GatewayError::AdapterUnavailable("brics"));
                }
            }
            // This dispatch remains unreachable with preflight rejecting MYC;
            // retain it for compilability when optional adapters are disabled.
            GatewayType::MycRail => self.myc_rail.dispatch(&intent)?,
        };

        // 4. Avança a FSM e persiste o novo estado indexado por `external_ref`
        intent.transition_to(TransactionState::AwaitingGatewayResponse {
            external_ref: receipt.external_ref.clone(),
        })?;

        if receipt.settled_immediately {
            intent.transition_to(TransactionState::Settled {
                external_tx_id: receipt.external_ref.clone(),
                myc_micros,
                usdc_equivalent_micros: usdc_micros,
            })?;
        }

        if let Some(store) = self.sporebank.as_mut() {
            store.persist_intent(&intent, Some(&receipt.external_ref))?;
        }

        Ok(ExecutionOutcome { intent, receipt })
    }

    /// Confirma liquidação assíncrona (webhook Pix `cobv`, SWIFT `pacs.002` ou DCMS) e persiste no `SporeBank`.
    pub fn confirm_settlement(
        &mut self,
        intent: &mut PaymentIntent,
        external_tx_id: impl Into<String>,
    ) -> Result<(), GatewayError> {
        self.require_encrypted_store()?;
        let tx_id = external_tx_id.into();
        let (myc_micros, usdc_micros) = intent.myc_usdc_parity(&self.monetary_policy);
        let mut committed = intent.clone();
        committed.transition_to(TransactionState::Settled {
            external_tx_id: tx_id.clone(),
            myc_micros,
            usdc_equivalent_micros: usdc_micros,
        })?;
        if let Some(store) = self.sporebank.as_mut() {
            store.persist_intent(&committed, Some(&tx_id))?;
        }
        *intent = committed;
        Ok(())
    }

    /// Registra falha explícita (ex.: `RJCT` no SWIFT `pacs.002`) e persiste no `SporeBank`.
    pub fn fail_intent(
        &mut self,
        intent: &mut PaymentIntent,
        code: u32,
        reason: impl Into<String>,
    ) -> Result<(), GatewayError> {
        self.require_encrypted_store()?;
        let mut committed = intent.clone();
        committed.transition_to(TransactionState::Failed {
            code,
            reason: reason.into(),
        })?;
        if let Some(store) = self.sporebank.as_mut() {
            store.persist_intent(&committed, None)?;
        }
        *intent = committed;
        Ok(())
    }
}
