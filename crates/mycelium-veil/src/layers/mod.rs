//! As 7 Camadas de Privacidade e Anonimato do Mycelium VEIL Ω (Fusão ET-COSMIC-OLD).
//!
//! AVISO DE STATUS: estas 7 camadas **não estão no caminho de dados de produção**.
//! Leia o banner de comentário logo abaixo antes de usar este módulo.

// ============================================================================
// AVISO HONESTO — `LayerPipeline` NÃO ESTÁ NO CAMINHO DE DADOS DE PRODUÇÃO
// ============================================================================
//
// STATUS: **PROJETADO, NÃO LIGADO** (*designed, not wired*).
//
// O `LayerPipeline` definido aqui (as 7 camadas, ~976 linhas em `layer0_identity`
// … `layer6_zerotrace`) NÃO participa do tráfego real:
//
// * Os únicos chamadores de `LayerPipeline::process`/`recover` são
//   `VeilEngine::route` e `VeilEngine::decode` (em `crate::lib.rs`), e ambos são
//   exercitados **apenas pelos testes** deste crate.
// * O caminho de dados de produção é outro: `LiveCircuitClient`
//   (`connect` / `connect_production` / `connect_via_entries`), `VeilHopRouter`,
//   `BridgeRelay` e `EntryPool`, em `planes/live.rs` e `bridge.rs`. Nenhum desses
//   símbolos toca este pipeline.
// * A única coisa de `layers/` reaproveitada fora do módulo é o helper estático
//   `ObfuscationLayer::generate_poisson_delay_ms`, usado por `planes/mix.rs` —
//   que, por sua vez, também não é instanciado pelo nó.
//
// CONSEQUÊNCIA PARA A TELEMETRIA: o operador NÃO deve ser informado de que "7
// camadas estão ativas". `VeilEngine::wired_layer_count()` (crate::lib.rs)
// devolve 0 enquanto o pipeline não estiver ligado, e é esse número que alimenta
// `VeilStatusResult::active_layers`, reportado por `Request::VeilStatus` em
// `mycelium-node`. `VeilSession::active_layers` segue a mesma regra, e
// `VeilEngine::new` também emite um `tracing::warn!` no arranque do nó, para que
// essa condição fique visível em tempo de execução e não apenas no código.
//
// POR QUE O MÓDULO ESTÁ AQUI: as camadas são compiladas, tipadas e testadas, e
// documentam o comportamento pretendido. O módulo é mantido **de propósito** — nenhuma
// camada foi removida. Ligá-las ao plano LIVE é uma mudança arquitetural grande
// (encapsulamento dentro da célula de 512 bytes, ordem de recuperação e contrato de
// metadados do `LiveCircuit`) e está FORA DO ESCOPO desta correção de honestidade.
// ============================================================================

pub mod layer0_identity;
pub mod layer1_fragmentation;
pub mod layer2_transport;
pub mod layer3_consensus;
pub mod layer4_execution;
pub mod layer5_obfuscation;
pub mod layer6_zerotrace;

pub use layer0_identity::IdentityLayer;
pub use layer1_fragmentation::FragmentationLayer;
pub use layer2_transport::TransportLayer;
pub use layer3_consensus::ConsensusLayer;
pub use layer4_execution::ExecutionLayer;
pub use layer5_obfuscation::ObfuscationLayer;
pub use layer6_zerotrace::ZeroTraceLayer;

use crate::VeilError;

/// Trait comum para todas as 7 camadas do Veil.
pub trait VeilLayer: Send + Sync {
    /// Nome descritivo da camada.
    fn name(&self) -> &'static str;

    /// Indica se a camada está ativa na sessão corrente.
    fn is_active(&self) -> bool;

    /// Ativa ou desativa a camada dinamicamente.
    fn set_active(&mut self, active: bool);

    /// Processa dados no sentido de saída (aplicação -> rede / encapsulamento).
    fn process(&self, data: &[u8]) -> Result<Vec<u8>, VeilError>;

    /// Recupera dados no sentido de entrada (rede -> aplicação / desencapsulamento).
    fn recover(&self, data: &[u8]) -> Result<Vec<u8>, VeilError>;
}

/// Pipeline orquestrador das 7 camadas de processamento.
///
/// ATENÇÃO: este pipeline **não está ligado ao caminho de dados de produção** —
/// ver o banner no topo deste módulo.
pub struct LayerPipeline {
    pub layers: Vec<Box<dyn VeilLayer>>,
}

impl Default for LayerPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl LayerPipeline {
    /// Cria o pipeline com as 7 camadas inicializadas em ordem (0 a 6).
    pub fn new() -> Self {
        Self {
            layers: vec![
                Box::new(IdentityLayer::new()),
                Box::new(FragmentationLayer::new(2, 3)), // Shamir 2-of-3 por padrão
                Box::new(TransportLayer::new()),
                Box::new(ConsensusLayer::new()),
                Box::new(ExecutionLayer::new()),
                Box::new(ObfuscationLayer::new(512)),
                Box::new(ZeroTraceLayer::new()),
            ],
        }
    }

    /// Ativa todas as camadas do pipeline.
    pub fn activate_all(&mut self) {
        for layer in &mut self.layers {
            layer.set_active(true);
        }
    }

    /// Processa dados sequencialmente através de todas as camadas ativas (0 -> 6).
    pub fn process(&self, data: &[u8]) -> Result<Vec<u8>, VeilError> {
        let mut current = data.to_vec();
        for layer in &self.layers {
            if layer.is_active() {
                current = layer.process(&current)?;
            }
        }
        Ok(current)
    }

    /// Recupera dados na ordem reversa das camadas ativas (6 -> 0).
    pub fn recover(&self, data: &[u8]) -> Result<Vec<u8>, VeilError> {
        let mut current = data.to_vec();
        for layer in self.layers.iter().rev() {
            if layer.is_active() {
                current = layer.recover(&current)?;
            }
        }
        Ok(current)
    }
}
