//! W4: pure, hypothetical state-transition validation for Pix lab fixtures.
//! No PSP messages, payment dispatch, authorization, ledger or settlement effects.
use serde::Deserialize;
type R<T> = Result<T, &'static str>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Entity {
    Cob,
    Cobv,
    Devolucao,
    Rec,
    SolicRec,
    Cobr,
    Tentativa,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum State {
    Ativa,
    Concluida,
    RemovidoPeloUsuarioRecebedor,
    RemovidoPeloPsp,
    EmProcessamento,
    Devolvido,
    NaoRealizado,
    Criada,
    Aprovada,
    Rejeitada,
    Expirada,
    Cancelada,
    Enviada,
    Recebida,
    Aceita,
    Solicitada,
    Agendada,
    Paga,
}
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabConditions {
    #[serde(default)]
    pub jornada1: bool,
    #[serde(default)]
    pub validity_elapsed: bool,
    #[serde(default)]
    pub before_original_date: bool,
    #[serde(default)]
    pub simulated_attempt_paid: bool,
    #[serde(default)]
    pub simulated_attempts_exhausted: bool,
    #[serde(default)]
    pub simulated_terminal_rejection: bool,
    #[serde(default)]
    pub simulated_cancellation: bool,
}
pub fn initial(entity: Entity) -> State {
    use Entity::*;
    use State::*;
    match entity {
        Cob | Cobv => Ativa,
        Devolucao => EmProcessamento,
        Rec | SolicRec | Cobr => Criada,
        Tentativa => Solicitada,
    }
}
/// Validate one state edge under explicit hypothetical conditions. No evidence is authenticated.
pub fn validate_transition(entity: Entity, from: State, to: State, c: LabConditions) -> R<()> {
    use Entity::*;
    use State::*;
    let allowed = match entity {
        Cob | Cobv => {
            matches!(
                (from, to),
                (Ativa, RemovidoPeloUsuarioRecebedor | RemovidoPeloPsp)
            ) || (from == Ativa && to == Concluida && c.simulated_attempt_paid)
        }
        Devolucao => from == EmProcessamento && matches!(to, Devolvido | NaoRealizado),
        Rec => {
            matches!(
                (from, to),
                (Criada, Aprovada | Cancelada) | (Aprovada, Cancelada)
            ) || (from == Criada && to == Rejeitada && c.jornada1)
                || (matches!(from, Criada | Aprovada) && to == Expirada && c.validity_elapsed)
        }
        SolicRec => {
            matches!(
                (from, to),
                (Criada, Enviada)
                    | (Enviada, Recebida | Rejeitada)
                    | (Recebida, Aceita | Rejeitada)
            ) || (matches!(from, Criada | Enviada | Recebida)
                && to == Cancelada
                && c.simulated_cancellation)
                || (matches!(from, Criada | Enviada | Recebida)
                    && to == Expirada
                    && c.validity_elapsed)
        }
        Cobr => {
            matches!((from, to), (Criada, Ativa))
                || (matches!(from, Criada | Ativa)
                    && to == Cancelada
                    && c.before_original_date
                    && c.simulated_cancellation)
                || (from == Ativa && to == Concluida && c.simulated_attempt_paid)
                || (from == Ativa && to == Expirada && c.simulated_attempts_exhausted)
                || (from == Ativa && to == Rejeitada && c.simulated_terminal_rejection)
        }
        Tentativa => {
            matches!((from, to), (Solicitada, Agendada | Rejeitada))
                || (from == Agendada && to == Paga && c.simulated_attempt_paid)
                || (from == Agendada && to == Expirada && c.validity_elapsed)
                || (from == Agendada && to == Cancelada && c.simulated_cancellation)
        }
    };
    if allowed {
        Ok(())
    } else {
        Err("edge or lab condition not allowed")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionImpact {
    AttemptOnly,
    ChargeAndAttempt,
}
/// Exact PAIN.014 table on pp. 93–94; unknown codes are not inferred.
pub fn rejection_impact(code: &str) -> R<RejectionImpact> {
    use RejectionImpact::*;
    match code {
        "AC05" | "AM09" | "DENC" | "DS27" | "DTED" | "MIDI" | "MSUC" | "NITX" | "RC09" | "UDEI" => {
            Ok(ChargeAndAttempt)
        }
        "AB10" | "AC06" | "AM02" | "DTNT" | "FBRD" | "IRNT" | "NIEC" | "NIPA" | "QUNT" => {
            Ok(AttemptOnly)
        }
        _ => Err("unknown PAIN.014 code"),
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryPolicy {
    NaoPermite,
    Permite3r7d,
}
/// Validate only the count/day constraints of post-due retries, not eligibility,
/// scheduling windows, local calendars, intraday errors or PSP approval.
pub fn validate_retry_days(policy: RetryPolicy, days: &[u8]) -> R<()> {
    if !days.is_empty() && policy == RetryPolicy::NaoPermite {
        return Err("retries disabled");
    }
    if days.len() > 3
        || days.iter().any(|d| !(1..=7).contains(d))
        || days.windows(2).any(|w| w[0] >= w[1])
    {
        return Err("retry days outside policy");
    }
    Ok(())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabAttempt {
    pub day: u8,
    pub state: State,
}
/// Cross-check a snapshot of a normal/post-due CobR history. This conservative
/// subset excludes RIFL/intraday retry and does not infer timeout from a clock.
pub fn validate_cobr_snapshot(
    charge: State,
    policy: RetryPolicy,
    attempts: &[LabAttempt],
) -> R<()> {
    use State::*;
    if attempts.len() > 4 {
        return Err("too many attempts in lab subset");
    }
    if charge == Criada {
        return if attempts.is_empty() {
            Ok(())
        } else {
            Err("created charge with attempts")
        };
    }
    if charge == Cancelada && attempts.is_empty() {
        return Ok(());
    }
    if attempts.is_empty() || attempts[0].day != 0 {
        return Err("missing original attempt");
    }
    let days: Vec<_> = attempts.iter().skip(1).map(|a| a.day).collect();
    validate_retry_days(policy, &days)?;
    for a in attempts {
        if !matches!(
            a.state,
            Solicitada | Agendada | Paga | Expirada | Cancelada | Rejeitada
        ) {
            return Err("invalid attempt state");
        }
    }
    if attempts[..attempts.len() - 1]
        .iter()
        .any(|a| !matches!(a.state, Expirada | Cancelada | Rejeitada))
    {
        return Err("prior attempt not closed");
    }
    let last = attempts.last().unwrap().state;
    let ok = match charge {
        Ativa => matches!(
            last,
            Solicitada | Agendada | Expirada | Cancelada | Rejeitada
        ),
        Concluida => last == Paga,
        Expirada => matches!(last, Expirada | Cancelada | Rejeitada),
        Rejeitada => last == Rejeitada,
        Cancelada => last == Cancelada,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err("charge and latest attempt inconsistent")
    }
}
/// Result is a hypothetical trace, never authenticated bank state.
#[derive(Debug, PartialEq, Eq)]
pub struct LabReplay {
    pub entity: Entity,
    pub final_state: State,
    pub steps: usize,
}
impl LabReplay {
    pub const fn is_verified(&self) -> bool {
        false
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayInput {
    entity: Entity,
    steps: Vec<Step>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    to: State,
    #[serde(default)]
    conditions: LabConditions,
}
pub const MAX_REPLAY_BYTES: usize = 65536;
pub fn replay_json(input: &str) -> R<LabReplay> {
    if input.len() > MAX_REPLAY_BYTES {
        return Err("trace too large");
    }
    let r: ReplayInput = serde_json::from_str(input).map_err(|_| "invalid lab trace")?;
    if r.steps.len() > 128 {
        return Err("too many steps");
    }
    let mut state = initial(r.entity);
    for step in &r.steps {
        validate_transition(r.entity, state, step.to, step.conditions)?;
        state = step.to;
    }
    Ok(LabReplay {
        entity: r.entity,
        final_state: state,
        steps: r.steps.len(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use Entity::*;
    use State::*;
    fn d() -> LabConditions {
        LabConditions::default()
    }
    #[test]
    fn initial_states() {
        assert_eq!(initial(Cob), Ativa);
        assert_eq!(initial(Cobv), Ativa);
        assert_eq!(initial(Devolucao), EmProcessamento);
        assert_eq!(initial(Rec), Criada);
        assert_eq!(initial(SolicRec), Criada);
        assert_eq!(initial(Cobr), Criada);
        assert_eq!(initial(Tentativa), Solicitada);
    }
    #[test]
    fn charge_edges() {
        for e in [Cob, Cobv] {
            assert!(validate_transition(e, Ativa, Concluida, d()).is_err());
            assert!(validate_transition(
                e,
                Ativa,
                Concluida,
                LabConditions {
                    simulated_attempt_paid: true,
                    ..d()
                }
            )
            .is_ok());
            assert!(validate_transition(e, Ativa, RemovidoPeloPsp, d()).is_ok());
            assert!(validate_transition(e, Concluida, Ativa, d()).is_err());
        }
    }
    #[test]
    fn refunds() {
        for s in [Devolvido, NaoRealizado] {
            assert!(validate_transition(Devolucao, EmProcessamento, s, d()).is_ok());
            assert!(validate_transition(Devolucao, s, EmProcessamento, d()).is_err());
        }
    }
    #[test]
    fn rec_journey() {
        assert!(validate_transition(Rec, Criada, Rejeitada, d()).is_err());
        assert!(validate_transition(
            Rec,
            Criada,
            Rejeitada,
            LabConditions {
                jornada1: true,
                ..d()
            }
        )
        .is_ok());
        assert!(validate_transition(
            Rec,
            Aprovada,
            Rejeitada,
            LabConditions {
                jornada1: true,
                ..d()
            }
        )
        .is_err());
    }
    #[test]
    fn rec_expiry() {
        for s in [Criada, Aprovada] {
            assert!(validate_transition(Rec, s, Expirada, d()).is_err());
            assert!(validate_transition(
                Rec,
                s,
                Expirada,
                LabConditions {
                    validity_elapsed: true,
                    ..d()
                }
            )
            .is_ok());
        }
    }
    #[test]
    fn solicit_order() {
        assert!(validate_transition(SolicRec, Criada, Aceita, d()).is_err());
        assert!(validate_transition(SolicRec, Criada, Enviada, d()).is_ok());
        assert!(validate_transition(SolicRec, Enviada, Recebida, d()).is_ok());
        assert!(validate_transition(SolicRec, Recebida, Aceita, d()).is_ok());
    }
    #[test]
    fn solicit_cancel() {
        for s in [Criada, Enviada, Recebida] {
            assert!(validate_transition(
                SolicRec,
                s,
                Cancelada,
                LabConditions {
                    simulated_cancellation: true,
                    ..d()
                }
            )
            .is_ok());
        }
        assert!(validate_transition(
            SolicRec,
            Aceita,
            Cancelada,
            LabConditions {
                simulated_cancellation: true,
                ..d()
            }
        )
        .is_err());
    }
    #[test]
    fn cobr_guards() {
        assert!(validate_transition(Cobr, Ativa, Concluida, d()).is_err());
        assert!(validate_transition(
            Cobr,
            Ativa,
            Expirada,
            LabConditions {
                simulated_attempts_exhausted: true,
                ..d()
            }
        )
        .is_ok());
        assert!(validate_transition(
            Cobr,
            Ativa,
            Rejeitada,
            LabConditions {
                simulated_terminal_rejection: true,
                ..d()
            }
        )
        .is_ok());
    }
    #[test]
    fn cancel_deadline() {
        let c = LabConditions {
            simulated_cancellation: true,
            ..d()
        };
        assert!(validate_transition(Cobr, Ativa, Cancelada, c).is_err());
        assert!(validate_transition(
            Cobr,
            Ativa,
            Cancelada,
            LabConditions {
                before_original_date: true,
                ..c
            }
        )
        .is_ok());
    }
    #[test]
    fn attempts() {
        assert!(validate_transition(Tentativa, Solicitada, Agendada, d()).is_ok());
        assert!(validate_transition(
            Tentativa,
            Solicitada,
            Paga,
            LabConditions {
                simulated_attempt_paid: true,
                ..d()
            }
        )
        .is_err());
        assert!(validate_transition(
            Tentativa,
            Agendada,
            Paga,
            LabConditions {
                simulated_attempt_paid: true,
                ..d()
            }
        )
        .is_ok());
    }
    #[test]
    fn rejection_table() {
        for code in [
            "AC05", "AM09", "DENC", "DS27", "DTED", "MIDI", "MSUC", "NITX", "RC09", "UDEI",
        ] {
            assert_eq!(
                rejection_impact(code),
                Ok(RejectionImpact::ChargeAndAttempt)
            );
        }
        for code in [
            "AB10", "AC06", "AM02", "DTNT", "FBRD", "IRNT", "NIEC", "NIPA", "QUNT",
        ] {
            assert_eq!(rejection_impact(code), Ok(RejectionImpact::AttemptOnly));
        }
        assert!(rejection_impact("OTHER").is_err());
    }
    #[test]
    fn retry_policy() {
        use RetryPolicy::*;
        assert!(validate_retry_days(NaoPermite, &[1]).is_err());
        assert!(validate_retry_days(Permite3r7d, &[1, 3, 7]).is_ok());
        for a in [
            &[1, 1][..],
            &[0][..],
            &[8][..],
            &[1, 2, 3, 4][..],
            &[4, 2][..],
        ] {
            assert!(validate_retry_days(Permite3r7d, a).is_err());
        }
    }
    #[test]
    fn cobr_snapshot() {
        use RetryPolicy::*;
        let a = [
            LabAttempt {
                day: 0,
                state: Expirada,
            },
            LabAttempt {
                day: 3,
                state: Paga,
            },
        ];
        assert!(validate_cobr_snapshot(Concluida, Permite3r7d, &a).is_ok());
        assert!(validate_cobr_snapshot(Ativa, Permite3r7d, &a).is_err());
        assert!(validate_cobr_snapshot(Concluida, NaoPermite, &a).is_err());
    }
    #[test]
    fn concurrent_attempts() {
        use RetryPolicy::*;
        let a = [
            LabAttempt {
                day: 0,
                state: Agendada,
            },
            LabAttempt {
                day: 1,
                state: Agendada,
            },
        ];
        assert!(validate_cobr_snapshot(Ativa, Permite3r7d, &a).is_err());
    }
    #[test]
    fn replay_unverified() {
        let x=replay_json(r#"{"entity":"solic_rec","steps":[{"to":"ENVIADA"},{"to":"RECEBIDA"},{"to":"ACEITA"}]}"#).unwrap();
        assert_eq!(x.final_state, Aceita);
        assert!(!x.is_verified());
    }
    #[test]
    fn replay_rejects_unknown_or_duplicate() {
        for s in [
            r#"{"entity":"rec","steps":[{"to":"APROVADA","conditions":{"secret":"x"}}]}"#,
            r#"{"entity":"rec","entity":"cob","steps":[]}"#,
            r#"{"entity":"rec","steps":[{"to":"PAGA"}]}"#,
        ] {
            assert!(replay_json(s).is_err());
        }
    }
}
