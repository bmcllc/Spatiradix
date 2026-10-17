use crate::error::BankError;
use crate::payments::PaymentIntent;
use serde::{Deserialize, Serialize};

/// Mensagem que trafega na malha Mycelium (gossip/DHT), selada por assinatura.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BankMessage {
    /// Anúncio de intenção de pagamento (para liquidação remota).
    PaymentIntentAnnounced {
        intent: PaymentIntent,
        node_id: String,
    },
    /// Confirmação de recebimento NFC por um nó.
    PaymentConfirmed { payment_id: String, node_id: String },
    /// Ordem de corretora propagada (livro distribuído).
    OrderAnnounced { order_json: String, node_id: String },
    /// Sincronização de estado de conta (hash, não segredo).
    AccountDigest {
        account_id: String,
        root_hash: String,
        node_id: String,
    },
}

/// Adaptador mínimo para a malha Mycelium. Implementações concretas conectam
/// a libp2p (hyphae) via spawn do daemon ou canal FFI. O core não depende
/// de transporte concreto — permanece testável offline.
pub trait MyceliumTransport {
    fn publish(&mut self, msg: &BankMessage) -> Result<(), BankError>;
    fn peers(&mut self) -> Vec<String>;
}

/// Transporte nulo (offline / modo soberano local). Usado em testes e em
/// nós sem conectividade.
#[derive(Default, Clone)]
pub struct NullTransport;

impl MyceliumTransport for NullTransport {
    fn publish(&mut self, _msg: &BankMessage) -> Result<(), BankError> {
        Ok(())
    }
    fn peers(&mut self) -> Vec<String> {
        vec![]
    }
}
