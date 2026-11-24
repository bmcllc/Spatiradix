//! Inbound Listener (Webhooks Axum) para liquidação assíncrona de Pix (`cob`/`cobv`),
//! SWIFT (`pacs.002`) e BRICS Pay (DCMS), atualizando o `TransactionState` no `SporeBank`.

use crate::core::TransactionState;
use crate::engine::MetaGatewayEngine;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;

/// Estado compartilhado do servidor de webhooks inbound.
pub struct WebhookServiceState {
    pub engine: MetaGatewayEngine,
    /// Segredo compartilhado usado para autenticar callbacks via MAC BLAKE3 keyed.
    pub webhook_secret: [u8; 32],
}

impl WebhookServiceState {
    /// Calcula a assinatura autenticada (`blake3::keyed_hash`) para um payload canônico de webhook.
    pub fn sign_callback(secret: &[u8; 32], canonical: &str) -> String {
        hex::encode(blake3::keyed_hash(secret, canonical.as_bytes()).as_bytes())
    }

    fn verify_callback(&self, canonical: &str, provided_hex: &str) -> bool {
        let Ok(provided) = hex::decode(provided_hex.trim()) else {
            return false;
        };
        let expected = blake3::keyed_hash(&self.webhook_secret, canonical.as_bytes());
        bool::from(provided.as_slice().ct_eq(expected.as_bytes()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PixWebhookEvent {
    pub txid: String,
    pub end_to_end_id: String,
    /// `"CONCLUIDA"` ou `"DEVOLVIDA"` / `"REJEITADA"`.
    pub status: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftWebhookEvent {
    pub uetr: String,
    /// ISO 20022 `pacs.002`: `"ACSC"` (liquidado) ou `"RJCT"` (rejeitado).
    pub status_code: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BricsWebhookEvent {
    pub dcms_tx_id: String,
    pub status: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookAck {
    pub intent_id: String,
    pub state: String,
    pub sporebank_cid: Option<String>,
}

/// Constrói o `axum::Router` inbound para receber callbacks assíncronos dos gateways.
pub fn build_webhook_router(state: Arc<Mutex<WebhookServiceState>>) -> Router {
    Router::new()
        .route("/webhooks/pix", post(handle_pix_webhook))
        .route("/webhooks/swift", post(handle_swift_webhook))
        .route("/webhooks/brics", post(handle_brics_webhook))
        .with_state(state)
}

async fn handle_pix_webhook(
    State(state): State<Arc<Mutex<WebhookServiceState>>>,
    Json(ev): Json<PixWebhookEvent>,
) -> Result<Json<WebhookAck>, (StatusCode, String)> {
    let canonical = format!("pix:{}:{}:{}", ev.txid, ev.end_to_end_id, ev.status);
    let mut guard = state
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;
    if !guard.verify_callback(&canonical, &ev.signature_hex) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "assinatura de webhook Pix inválida".into(),
        ));
    }

    let mut intent = guard
        .engine
        .recall_by_external_ref(&ev.txid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("txid `{}` não encontrado", ev.txid),
            )
        })?;

    if let TransactionState::Settled { external_tx_id, .. } = &intent.state {
        if ev.status.eq_ignore_ascii_case("CONCLUIDA") && external_tx_id == &ev.end_to_end_id {
            return Ok(Json(WebhookAck {
                intent_id: intent.id.clone(),
                state: intent.state.label().into(),
                sporebank_cid: guard
                    .engine
                    .latest_sporebank_cid(&intent.id)
                    .map(|c| c.to_string()),
            }));
        }
        return Err((
            StatusCode::CONFLICT,
            "Pix settlement already finalized with different evidence".into(),
        ));
    }
    if ev.status.eq_ignore_ascii_case("CONCLUIDA") {
        guard
            .engine
            .confirm_settlement(&mut intent, ev.end_to_end_id)
            .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    } else if ev.status.eq_ignore_ascii_case("REJEITADA") {
        guard
            .engine
            .fail_intent(&mut intent, 422, format!("pix status: {}", ev.status))
            .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    } else {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("Pix status {} requires a distinct transition", ev.status),
        ));
    }

    let cid = guard
        .engine
        .latest_sporebank_cid(&intent.id)
        .map(|c| c.to_string());
    Ok(Json(WebhookAck {
        intent_id: intent.id,
        state: intent.state.label().to_string(),
        sporebank_cid: cid,
    }))
}

async fn handle_swift_webhook(
    State(state): State<Arc<Mutex<WebhookServiceState>>>,
    Json(ev): Json<SwiftWebhookEvent>,
) -> Result<Json<WebhookAck>, (StatusCode, String)> {
    let canonical = format!(
        "swift:{}:{}:{}",
        ev.uetr,
        ev.status_code,
        ev.reason.as_deref().unwrap_or("")
    );
    let mut guard = state
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;
    if !guard.verify_callback(&canonical, &ev.signature_hex) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "assinatura de webhook SWIFT inválida".into(),
        ));
    }

    let mut intent = guard
        .engine
        .recall_by_external_ref(&ev.uetr)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("UETR `{}` não encontrado", ev.uetr),
            )
        })?;

    if let TransactionState::Settled { external_tx_id, .. } = &intent.state {
        if ev.status_code.eq_ignore_ascii_case("ACSC") && external_tx_id == &ev.uetr {
            return Ok(Json(WebhookAck {
                intent_id: intent.id.clone(),
                state: intent.state.label().into(),
                sporebank_cid: guard
                    .engine
                    .latest_sporebank_cid(&intent.id)
                    .map(|c| c.to_string()),
            }));
        }
        return Err((
            StatusCode::CONFLICT,
            "SWIFT settlement already finalized".into(),
        ));
    }
    if ev.status_code.eq_ignore_ascii_case("ACSC") {
        guard
            .engine
            .confirm_settlement(&mut intent, ev.uetr)
            .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    } else if ev.status_code.eq_ignore_ascii_case("RJCT") {
        guard
            .engine
            .fail_intent(
                &mut intent,
                502,
                ev.reason
                    .unwrap_or_else(|| format!("SWIFT pacs.002 {}", ev.status_code)),
            )
            .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    } else {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("SWIFT status {} is not final", ev.status_code),
        ));
    }

    let cid = guard
        .engine
        .latest_sporebank_cid(&intent.id)
        .map(|c| c.to_string());
    Ok(Json(WebhookAck {
        intent_id: intent.id,
        state: intent.state.label().to_string(),
        sporebank_cid: cid,
    }))
}

async fn handle_brics_webhook(
    State(state): State<Arc<Mutex<WebhookServiceState>>>,
    Json(ev): Json<BricsWebhookEvent>,
) -> Result<Json<WebhookAck>, (StatusCode, String)> {
    let canonical = format!("brics:{}:{}", ev.dcms_tx_id, ev.status);
    let mut guard = state
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;
    if !guard.verify_callback(&canonical, &ev.signature_hex) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "assinatura de webhook BRICS inválida".into(),
        ));
    }

    let mut intent = guard
        .engine
        .recall_by_external_ref(&ev.dcms_tx_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("dcms_tx_id `{}` não encontrado", ev.dcms_tx_id),
            )
        })?;

    if let TransactionState::Settled { external_tx_id, .. } = &intent.state {
        if ev.status.eq_ignore_ascii_case("SETTLED") && external_tx_id == &ev.dcms_tx_id {
            return Ok(Json(WebhookAck {
                intent_id: intent.id.clone(),
                state: intent.state.label().into(),
                sporebank_cid: guard
                    .engine
                    .latest_sporebank_cid(&intent.id)
                    .map(|c| c.to_string()),
            }));
        }
        return Err((
            StatusCode::CONFLICT,
            "DCMS settlement already finalized".into(),
        ));
    }
    if ev.status.eq_ignore_ascii_case("SETTLED") {
        guard
            .engine
            .confirm_settlement(&mut intent, ev.dcms_tx_id)
            .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    } else if ev.status.eq_ignore_ascii_case("FAILED") || ev.status.eq_ignore_ascii_case("REJECTED")
    {
        guard
            .engine
            .fail_intent(&mut intent, 502, format!("DCMS status: {}", ev.status))
            .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    } else {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("DCMS status {} is not final", ev.status),
        ));
    }

    let cid = guard
        .engine
        .latest_sporebank_cid(&intent.id)
        .map(|c| c.to_string());
    Ok(Json(WebhookAck {
        intent_id: intent.id,
        state: intent.state.label().to_string(),
        sporebank_cid: cid,
    }))
}
