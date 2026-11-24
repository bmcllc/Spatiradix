//! Livro V (Deuteronômio): Compliance-as-Code obrigatório antes de qualquer
//! despacho para gateways legados ou trilhos soberanos.

use crate::core::{GatewayType, PaymentIntent, MICRO_UNIT};
use crate::error::GatewayError;

/// Limite noturno padrão do Pix (R$ 1.000,00 em micro-unidades = 1_000 * 1_000_000).
pub const DEFAULT_PIX_NIGHT_LIMIT_MICROS: u64 = 1_000 * MICRO_UNIT;

/// Regras de conformidade executáveis em tempo de roteamento.
#[derive(Debug, Clone)]
pub struct CompliancePolicy {
    pub pix_night_limit_micros: u64,
    pub require_swift_secure_zone_log: bool,
}

impl Default for CompliancePolicy {
    fn default() -> Self {
        Self {
            pix_night_limit_micros: DEFAULT_PIX_NIGHT_LIMIT_MICROS,
            require_swift_secure_zone_log: true,
        }
    }
}

impl CompliancePolicy {
    /// Valida a intenção contra as regras regulatórias do gateway alvo.
    pub fn enforce(&self, intent: &PaymentIntent) -> Result<(), GatewayError> {
        if intent.amount_micros == 0 {
            return Err(GatewayError::InvalidAmount);
        }
        if intent.sender_did.trim().is_empty() {
            return Err(GatewayError::ComplianceViolation {
                rule: "sender_did_required",
                detail: "sender_did não pode ser vazio".into(),
            });
        }

        match intent.gateway {
            GatewayType::Swift => {
                let csp_ok = intent
                    .compliance_metadata
                    .get("swift_csp_compliant")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if !csp_ok {
                    return Err(GatewayError::ComplianceViolation {
                        rule: "swift_csp_cscf",
                        detail: "flag compliance_metadata.swift_csp_compliant=true é obrigatória"
                            .into(),
                    });
                }
                if self.require_swift_secure_zone_log {
                    let has_log = intent
                        .compliance_metadata
                        .get("secure_zone_log_id")
                        .and_then(|v| v.as_str())
                        .map(|s| !s.trim().is_empty())
                        .unwrap_or(false);
                    if !has_log {
                        return Err(GatewayError::ComplianceViolation {
                            rule: "swift_secure_zone_log",
                            detail: "secure_zone_log_id ausente nos metadados de auditoria".into(),
                        });
                    }
                }
            }
            GatewayType::Pix => {
                let key = intent
                    .receiver_id
                    .strip_prefix("pix:")
                    .unwrap_or(&intent.receiver_id)
                    .trim();
                if key.is_empty() {
                    return Err(GatewayError::InvalidTarget(intent.receiver_id.clone()));
                }
                // Verifica janela noturna (20:00–05:59 horário local/informado).
                if let Some(hour) = intent
                    .compliance_metadata
                    .get("local_hour")
                    .and_then(|v| v.as_u64())
                {
                    let is_night = !(6..20).contains(&hour);
                    if is_night && intent.amount_micros > self.pix_night_limit_micros {
                        return Err(GatewayError::ComplianceViolation {
                            rule: "pix_night_limit",
                            detail: format!(
                                "valor ({} micros) excede teto noturno ({} micros) às {}h",
                                intent.amount_micros, self.pix_night_limit_micros, hour
                            ),
                        });
                    }
                }
            }
            GatewayType::BricsPay => {
                let target = intent
                    .receiver_id
                    .strip_prefix("brics:")
                    .or_else(|| intent.receiver_id.strip_prefix("dcms:"))
                    .unwrap_or(&intent.receiver_id)
                    .trim();
                if target.is_empty() {
                    return Err(GatewayError::InvalidTarget(intent.receiver_id.clone()));
                }
            }
            GatewayType::MycRail => {
                let target = intent
                    .receiver_id
                    .strip_prefix("myc:")
                    .or_else(|| intent.receiver_id.strip_prefix("usdc:"))
                    .unwrap_or(&intent.receiver_id)
                    .trim();
                if target.is_empty() {
                    return Err(GatewayError::InvalidTarget(intent.receiver_id.clone()));
                }
            }
        }

        Ok(())
    }
}
