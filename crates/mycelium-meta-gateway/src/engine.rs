//! Livro VI (Josué): O Roteador Supremo (`MetaGatewayEngine`) com selo pós-quântico
//! (ML-KEM-1024), assinatura Ed25519, âncora causal (`hash_chronicle`), compromisso
//! de Pedersen e liquidação unificada MYC ↔ USDC (`1 MYC = 8 USDC`).

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
use ed25519_dalek::{Signer, SigningKey};
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
    node_signing_key: SigningKey,
    pqc_keypair: KemKeyPair,
    chronicle_head: [u8; 32],
}

impl MetaGatewayEngine {
    /// Inicializa o motor com identidade Ed25519, par pós-quântico ML-KEM-1024 e política `1 MYC = 8 USDC`.
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
            node_signing_key,
            pqc_keypair: mlkem_keygen(),
            chronicle_head,
        }
    }

    /// Cabeça causal atual (BLAKE3 `hash_chronicle`) de todas as intenções seladas neste nó.
    pub fn chronicle_head(&self) -> [u8; 32] {
        self.chronicle_head
    }

    /// Executa o fluxo completo:
    /// 1. Compliance-as-Code
    /// 2. Selo Criptográfico (Ed25519 + ML-KEM-1024 + Pedersen + `hash_chronicle`)
    /// 3. Despacho pelo adaptador isolado
    /// 4. Transição FSM para `AwaitingGatewayResponse` ou `Settled` (quando instantâneo).
    pub fn execute(&mut self, mut intent: PaymentIntent) -> Result<ExecutionOutcome, GatewayError> {
        // 1. Compliance-as-Code
        self.compliance.enforce(&intent)?;

        // 2. Selo Pós-Quântico + Prova de Intenção no Lattice antes do disparo legado
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
            GatewayType::MycRail => self.myc_rail.dispatch(&intent)?,
        };

        // 4. Avança a FSM: AwaitingGatewayResponse -> Settled (se liquidação imediata)
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

        Ok(ExecutionOutcome { intent, receipt })
    }

    /// Confirma liquidação assíncrona (webhook/callback SWIFT ou liquidação externa).
    pub fn confirm_settlement(
        &self,
        intent: &mut PaymentIntent,
        external_tx_id: impl Into<String>,
    ) -> Result<(), GatewayError> {
        let (myc_micros, usdc_micros) = intent.myc_usdc_parity(&self.monetary_policy);
        intent.transition_to(TransactionState::Settled {
            external_tx_id: external_tx_id.into(),
            myc_micros,
            usdc_equivalent_micros: usdc_micros,
        })
    }
}
