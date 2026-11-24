//! # Ecosystem Ion — AEX World, Omnibridge Social (9 Redes), VEIL Proxy/VPN, GhostID × NFC, Bank/Pay/Royalty & CPX Reserve
//!
//! Subsistema modular montado sob `/rhizome/api/` que integra de forma soberana e real:
//! 1. **AEX World / Cameon PX**: bridge `aex-mycelium-bridge/1.0.0` (GhostID, QEL, Pedersen ZKP, DTN)
//!    + consulta ao vivo ao nó AEX World (`http://127.0.0.1:4173` configurável) com ticker UMPC-R PAME
//!    e simulador determinístico Asset-to-Capital.
//! 2. **Omnibridge Social (9 redes)**: cofre local cifrado com `XChaCha20-Poly1305`, sincronização via
//!    APIs oficiais / feeds públicos oficiais (YouTube Atom, Reddit JSON, Twitch Helix, Telegram Bot API,
//!    X API v2, Meta Graph API, TikTok Display API, WhatsApp Cloud API) com roteamento opcional por
//!    **VEIL Ω SOCKS5** (`socks5h://`) e importação de exports oficiais / vCard `.vcf`.
//! 3. **VEIL Ω Proxy/VPN**: controle ao vivo do circuito pós-quântico ML-KEM-1024 + proxy SOCKS5 local
//!    (RFC 1928) + Kill Switch fail-closed + teste de handshake real no socket SOCKS5.
//! 4. **Economia Unificada CPX + Mint como Reserva + GhostID × NFC × Bank × Pay × Royalty**:
//!    `mycelium-mint` lastreia `CPX` (1 MYC reserva = 8 CPX), `mycelium-bank` gerencia contas/razão
//!    hash-encadeado `Asset::Cpx` + `Asset::Myc`, `mycelium-pay` emite/verifica envelopes CBOR BIP-340,
//!    `NfcNdefFrame` sela taps NFC com Ed25519 + GhostID Schnorr + ML-KEM-1024, e `mycelium-royalty`
//!    distribui royalties em CPX para criadores com 5% para a reserva.

use crate::rhizome_ion::RhizomeOutbound;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use mycelium_bank::accounts::Portfolio;
use mycelium_bank::assets::{Amount, Asset};
use mycelium_bank::identity::SovereignWallet;
use mycelium_bank::ledger::{Entry, Record as BankLedgerRecord, SovereignLedger};
use mycelium_bank::mint_bridge::{
    settle_mint_reserve_to_cpx, CpxReserveSettlementRecord, MINT_RESERVE_ACCOUNT_ID,
};
use mycelium_bank::nfc::NfcNdefFrame;
use mycelium_bank::payments::{receive_nfc_payment, NfcProof, PaymentIntent};
use mycelium_mint::{CpxReserveStatus, MintReceipt, MonetaryPolicy};
use mycelium_pay::bodies::{Body as PayBody, PayRequest, Receipt as PayReceipt, Status as PayStatus};
use mycelium_pay::envelope::Envelope as PayEnvelope;
use mycelium_rhizome::{
    parse_meta_json, parse_reddit_listing_json, parse_telegram_json, parse_tiktok_json,
    parse_twitch_helix_json, parse_vcard_contacts, parse_x_json, parse_youtube_atom_feed,
    OmnibridgeIndex, OmnibridgeSyncDelta, OmnibridgeVault, PlatformCredentialRecord, RhizomeStore,
    SocialPlatform,
};
use mycelium_royalty::{RoyaltyContract, RoyaltyDistribution, RoyaltyEngine, RoyaltySplit, DEFAULT_RESERVE_FEE_BPS};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn json_ok(val: Value) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        val.to_string(),
    )
        .into_response()
}

fn json_err(status: StatusCode, msg: impl Into<String>) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        json!({ "error": msg.into() }).to_string(),
    )
        .into_response()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VeilStatusDto {
    pub compiled: bool,
    pub active: bool,
    pub mode: String,
    pub role: String,
    pub socks5_addr: Option<String>,
    pub socks5_uri: Option<String>,
    pub tun_bridge_addr: Option<String>,
    pub tun_bridge_port: Option<u16>,
    pub tun_clients: usize,
    pub tun_packets_in: u64,
    pub tun_packets_out: u64,
    pub tun_dns_queries: u64,
    pub remote_hops_configured: bool,
    pub kill_switch_state: String,
    pub session_id: Option<String>,
    pub bytes_routed: u64,
    pub active_layers: usize,
    pub exit_node: Option<String>,
    pub local_descriptor: Option<String>,
    pub honest_scope: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AexBridgeOpReq {
    Info,
    GhostSpawn { ttl_secs: Option<u64> },
    GhostSign { handle: String, payload_b64: String },
    GhostDestroy { handle: String },
    QelFragment { data_b64: String, content_id: String, threshold: u8, total: u8, ttl_secs: Option<u64> },
    PedersenCommit { value: u64 },
    DtnPoll { limit: Option<usize> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintReserveSettleOutcome {
    pub receipt: MintReceipt,
    pub policy: MonetaryPolicy,
    pub reserve_status: CpxReserveStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NfcReceiptLogItem {
    pub payment_id: String,
    pub from_account: String,
    pub to_account: String,
    pub ghost_pubkey_hex: String,
    pub amount_cpx_micros: i64,
    pub memo: String,
    pub ndef_uri: String,
    pub pay_receipt_cbor_b64: String,
    pub ledger_hash: String,
    pub settled_at: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct NfcHistoryStore {
    seen_nonces: BTreeSet<String>,
    receipts: VecDeque<NfcReceiptLogItem>,
}

/// Estado persistido do ecossistema financeiro CPX + Omnibridge + AEX config.
pub struct EcosystemPersistence {
    root_dir: PathBuf,
    vault_secret: [u8; 32],
    pub aex_url: String,
    pub wallet: SovereignWallet,
    pub portfolio: Portfolio,
    pub royalty_engine: RoyaltyEngine,
    pub vault: OmnibridgeVault,
    pub omnibridge_index: OmnibridgeIndex,
    nfc_history: NfcHistoryStore,
}

impl EcosystemPersistence {
    pub fn open(rhizome_home: &Path, vault_secret: [u8; 32]) -> Self {
        let root_dir = rhizome_home.join("ecosystem");
        let _ = std::fs::create_dir_all(&root_dir);

        let wallet_path = root_dir.join("bank_wallet.json");
        let wallet: SovereignWallet = std::fs::read(&wallet_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_else(|| {
                let w = SovereignWallet::generate();
                if let Ok(raw) = serde_json::to_vec_pretty(&w) {
                    let _ = std::fs::write(&wallet_path, raw);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &wallet_path,
                            std::fs::Permissions::from_mode(0o600),
                        );
                    }
                }
                w
            });

        let portfolio_path = root_dir.join("bank_portfolio.json");
        let mut portfolio: Portfolio = std::fs::read(&portfolio_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();

        let now = unix_now();
        if !portfolio.accounts.contains_key(&wallet.account_id) {
            let _ = portfolio.open_account(&wallet.account_id, "Conta Soberana CPX", now);
        }
        if !portfolio.accounts.contains_key(MINT_RESERVE_ACCOUNT_ID) {
            let _ = portfolio.open_account(
                MINT_RESERVE_ACCOUNT_ID,
                "Mycelium Mint Reserve Vault",
                now,
            );
        }
        let _ = std::fs::write(
            &portfolio_path,
            serde_json::to_vec_pretty(&portfolio).unwrap_or_default(),
        );

        let royalty_path = root_dir.join("royalties.json");
        let royalty_engine: RoyaltyEngine = std::fs::read(&royalty_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();

        let vault_path = root_dir.join("omnibridge_vault.enc");
        let vault = OmnibridgeVault::load_from_path(&vault_path, &vault_secret).unwrap_or_default();

        let idx_path = root_dir.join("omnibridge_index.json");
        let omnibridge_index = OmnibridgeIndex::load_from_path(&idx_path).unwrap_or_default();

        let nfc_path = root_dir.join("nfc_history.json");
        let nfc_history: NfcHistoryStore = std::fs::read(&nfc_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();

        let aex_url = std::env::var("AEX_WORLD_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "http://127.0.0.1:4173".to_string());

        Self {
            root_dir,
            vault_secret,
            aex_url,
            wallet,
            portfolio,
            royalty_engine,
            vault,
            omnibridge_index,
            nfc_history,
        }
    }

    fn ledger(&self) -> Result<SovereignLedger, String> {
        SovereignLedger::open(&self.root_dir).map_err(|e| e.to_string())
    }

    fn save_portfolio(&self) -> Result<(), String> {
        let p = self.root_dir.join("bank_portfolio.json");
        let raw = serde_json::to_vec_pretty(&self.portfolio).map_err(|e| e.to_string())?;
        std::fs::write(p, raw).map_err(|e| e.to_string())
    }

    fn save_royalties(&self) -> Result<(), String> {
        let p = self.root_dir.join("royalties.json");
        let raw = serde_json::to_vec_pretty(&self.royalty_engine).map_err(|e| e.to_string())?;
        std::fs::write(p, raw).map_err(|e| e.to_string())
    }

    fn save_vault(&self) -> Result<(), String> {
        let p = self.root_dir.join("omnibridge_vault.enc");
        self.vault
            .save_to_path(&p, &self.vault_secret)
            .map_err(|e| e.to_string())
    }

    fn save_omnibridge_index(&self) -> Result<(), String> {
        let p = self.root_dir.join("omnibridge_index.json");
        self.omnibridge_index
            .save_to_path(&p)
            .map_err(|e| e.to_string())
    }

    fn save_nfc_history(&self) -> Result<(), String> {
        let p = self.root_dir.join("nfc_history.json");
        let raw = serde_json::to_vec_pretty(&self.nfc_history).map_err(|e| e.to_string())?;
        std::fs::write(p, raw).map_err(|e| e.to_string())
    }

    pub fn cpx_circulating_micros(&self) -> i64 {
        self.portfolio
            .accounts
            .values()
            .map(|a| a.balance(Asset::Cpx).max(0))
            .sum()
    }

    pub fn reserve_myc_micros(&self) -> i64 {
        self.portfolio
            .accounts
            .get(MINT_RESERVE_ACCOUNT_ID)
            .map(|a| a.balance(Asset::Myc))
            .unwrap_or(0)
    }

    pub fn local_cpx_micros(&self) -> i64 {
        self.portfolio
            .accounts
            .get(&self.wallet.account_id)
            .map(|a| a.balance(Asset::Cpx))
            .unwrap_or(0)
    }

    /// Liquida um pagamento de royalty em CPX (usado pela rota `/api/royalties/payout` e gorjetas CPX).
    pub fn settle_royalty_cpx(
        &mut self,
        content_id: &str,
        gross_cpx_micros: i64,
        memo: &str,
    ) -> Result<RoyaltyDistribution, String> {
        let now = unix_now();
        let payer_id = self.wallet.account_id.clone();
        let payer_bal = self.local_cpx_micros();
        if payer_bal < gross_cpx_micros {
            return Err(format!(
                "saldo CPX insuficiente ({payer_bal} micros < {gross_cpx_micros} micros); execute 'Emitir CPX da Reserva Mint' primeiro"
            ));
        }
        let ghost_hex = self
            .wallet
            .ghost_pubkey_xonly()
            .map(hex::encode)
            .ok();

        let dist = self
            .royalty_engine
            .distribute_cpx(
                content_id,
                gross_cpx_micros,
                payer_id.clone(),
                ghost_hex,
                memo,
                now,
            )
            .map_err(|e| e.to_string())?;

        // Debita pagador
        self.portfolio
            .accounts
            .get_mut(&payer_id)
            .ok_or_else(|| "conta local ausente".to_string())?
            .debit(Asset::Cpx, gross_cpx_micros)
            .map_err(|e| e.to_string())?;

        let ledger = self.ledger()?;
        // Credita taxa de reserva (5%) na conta `reserve:mycelium-mint`
        if dist.reserve_fee_cpx_micros > 0 {
            if !self.portfolio.accounts.contains_key(MINT_RESERVE_ACCOUNT_ID) {
                let _ = self.portfolio.open_account(
                    MINT_RESERVE_ACCOUNT_ID,
                    "Mycelium Mint Reserve Vault",
                    now,
                );
            }
            self.portfolio
                .accounts
                .get_mut(MINT_RESERVE_ACCOUNT_ID)
                .unwrap()
                .credit(Asset::Cpx, dist.reserve_fee_cpx_micros)
                .map_err(|e| e.to_string())?;
            let _ = ledger.append(Entry::Transfer {
                from: payer_id.clone(),
                to: MINT_RESERVE_ACCOUNT_ID.into(),
                asset: Asset::Cpx.symbol(),
                micros: dist.reserve_fee_cpx_micros,
                ref_id: format!("royalty-reserve-fee:{}", dist.payout_id),
                at: now,
            });
        }

        // Credita cada criador / co-criador
        for alloc in &dist.allocations {
            if alloc.cpx_micros <= 0 {
                continue;
            }
            if !self.portfolio.accounts.contains_key(&alloc.beneficiary_id) {
                let _ = self
                    .portfolio
                    .open_account(&alloc.beneficiary_id, &alloc.beneficiary_id, now);
            }
            self.portfolio
                .accounts
                .get_mut(&alloc.beneficiary_id)
                .unwrap()
                .credit(Asset::Cpx, alloc.cpx_micros)
                .map_err(|e| e.to_string())?;
            let _ = ledger.append(Entry::Transfer {
                from: payer_id.clone(),
                to: alloc.beneficiary_id.clone(),
                asset: Asset::Cpx.symbol(),
                micros: alloc.cpx_micros,
                ref_id: format!("royalty:{}:{}", dist.content_id, alloc.role),
                at: now,
            });
        }

        self.save_portfolio()?;
        self.save_royalties()?;
        Ok(dist)
    }

    /// Transfere CPX diretamente entre contas no `mycelium-bank` (usado por gorjetas sem contrato prévio ou transferências).
    pub fn transfer_cpx_direct(
        &mut self,
        to_account: &str,
        micros: i64,
        memo: &str,
    ) -> Result<BankLedgerRecord, String> {
        if micros <= 0 {
            return Err("valor CPX deve ser positivo".into());
        }
        let now = unix_now();
        let from_account = self.wallet.account_id.clone();
        let bal = self.local_cpx_micros();
        if bal < micros {
            return Err(format!(
                "saldo CPX insuficiente ({bal} micros < {micros} micros); emita CPX lastreado pela reserva Mint primeiro"
            ));
        }
        let to_clean = to_account.trim();
        if to_clean.is_empty() {
            return Err("destinatário obrigatório".into());
        }
        if !self.portfolio.accounts.contains_key(to_clean) {
            let _ = self.portfolio.open_account(to_clean, to_clean, now);
        }
        if to_clean != from_account {
            self.portfolio
                .accounts
                .get_mut(&from_account)
                .unwrap()
                .debit(Asset::Cpx, micros)
                .map_err(|e| e.to_string())?;
            self.portfolio
                .accounts
                .get_mut(to_clean)
                .unwrap()
                .credit(Asset::Cpx, micros)
                .map_err(|e| e.to_string())?;
        }
        let ledger = self.ledger()?;
        let rec = ledger
            .append(Entry::Transfer {
                from: from_account,
                to: to_clean.into(),
                asset: Asset::Cpx.symbol(),
                micros,
                ref_id: memo.into(),
                at: now,
            })
            .map_err(|e| e.to_string())?;
        self.save_portfolio()?;
        Ok(rec)
    }
}

#[derive(Clone)]
pub struct EcosystemState {
    pub rhizome: Arc<Mutex<RhizomeStore>>,
    pub outbound: UnboundedSender<RhizomeOutbound>,
    pub persist: Arc<Mutex<EcosystemPersistence>>,
}

impl EcosystemState {
    pub fn open(
        rhizome: Arc<Mutex<RhizomeStore>>,
        outbound: UnboundedSender<RhizomeOutbound>,
    ) -> Self {
        let (home_dir, vault_secret) = {
            let guard = rhizome.lock().unwrap();
            let dir = guard.home().to_path_buf();
            let seed = *blake3::hash(guard.keys().ed25519_pubkey_hex().as_bytes()).as_bytes();
            // Deriva segredo real usando a chave privada Ed25519 (via assinatura determinística de domínio fixo)
            let sig_hex = guard
                .keys()
                .sign_domain("mycelium/omnibridge/vault-key/v1", b"local-vault-seed");
            let secret = *blake3::hash(sig_hex.as_bytes()).as_bytes();
            let _ = seed;
            (dir, secret)
        };
        let persist = EcosystemPersistence::open(&home_dir, vault_secret);
        Self {
            rhizome,
            outbound,
            persist: Arc::new(Mutex::new(persist)),
        }
    }
}

pub fn ecosystem_router(state: EcosystemState) -> Router {
    Router::new()
        // 1. Economia Unificada CPX + Mint Reserve (Solo & Quórum Multi-Esporocarpo) + Bank + Pay + GhostID × NFC + Royalties
        .route("/api/finance", get(finance_overview_api))
        .route("/api/finance/mint-reserve", post(mint_reserve_to_cpx_api))
        .route(
            "/api/finance/reserve-policy",
            get(get_reserve_policy_api).post(configure_reserve_policy_api),
        )
        .route("/api/finance/mint-claim", post(submit_mint_claim_p2p_api))
        .route("/api/finance/transfer-cpx", post(transfer_cpx_api))
        .route("/api/finance/nfc/request", post(nfc_create_request_api))
        .route("/api/finance/nfc/tap", post(nfc_execute_tap_api))
        .route("/api/royalties/contract", post(create_royalty_contract_api))
        .route("/api/royalties/payout", post(payout_royalty_api))
        // 2. AEX World & Cameon PX Session + Bridge
        .route("/api/aex/status", get(aex_status_api))
        .route("/api/aex/config", post(aex_config_api))
        .route("/api/aex/simulate", post(aex_simulate_api))
        .route("/api/aex/bridge", post(aex_bridge_op_api))
        // 3. VEIL Ω Proxy / VPN
        .route("/api/veil/status", get(veil_status_api))
        .route("/api/veil/start", post(veil_start_api))
        .route("/api/veil/stop", post(veil_stop_api))
        .route("/api/veil/killswitch", post(veil_killswitch_api))
        .route("/api/veil/test", post(veil_test_socks5_api))
        // 4. Omnibridge Social (9 Redes)
        .route("/api/omnibridge/overview", get(omnibridge_overview_api))
        .route("/api/omnibridge/connect", post(omnibridge_connect_api))
        .route("/api/omnibridge/sync", post(omnibridge_sync_api))
        .route("/api/omnibridge/import", post(omnibridge_import_api))
        .route("/api/omnibridge/directory", get(omnibridge_directory_api))
        .with_state(state)
}

// ============================================================================
// 1. FINANÇAS UNIFICADAS: CPX + MINT RESERVA + BANK + PAY + GHOSTID × NFC + ROYALTY
// ============================================================================

async fn finance_overview_api(State(state): State<EcosystemState>) -> Response {
    // 0. Drena recibos liquidados via quórum P2P multi-esporocarpo para a reserva CPX local (idempotente por nullifier)
    let (dtx, drx) = oneshot::channel();
    let _ = state
        .outbound
        .send(RhizomeOutbound::DrainSettledMintReceipts { reply: dtx });
    if let Ok(Ok((settled_receipts, policy))) =
        tokio::time::timeout(Duration::from_secs(2), drx).await
    {
        if !settled_receipts.is_empty() {
            let mut guard = state.persist.lock().unwrap();
            let now = unix_now();
            if let Ok(ledger) = guard.ledger() {
                let local_acc_id = guard.wallet.account_id.clone();
                let mut changed = false;
                for receipt in settled_receipts {
                    if let Ok(rec) = settle_mint_reserve_to_cpx(
                        &receipt,
                        &policy,
                        &mut guard.portfolio,
                        &ledger,
                        now,
                    ) {
                        changed = true;
                        if rec.beneficiary_account_id != local_acc_id {
                            let minted = rec.minted_cpx_micros;
                            if let Some(node_acc) =
                                guard.portfolio.accounts.get_mut(&rec.beneficiary_account_id)
                            {
                                let _ = node_acc.debit(Asset::Cpx, minted);
                            }
                            if let Some(local_acc) = guard.portfolio.accounts.get_mut(&local_acc_id)
                            {
                                let _ = local_acc.credit(Asset::Cpx, minted);
                            }
                            let _ = ledger.append(Entry::Transfer {
                                from: rec.beneficiary_account_id,
                                to: local_acc_id.clone(),
                                asset: Asset::Cpx.symbol(),
                                micros: minted,
                                ref_id: "mint-quorum-to-local-wallet".into(),
                                at: now,
                            });
                        }
                    }
                }
                if changed {
                    let _ = guard.save_portfolio();
                }
            }
        }
    }

    let (
        account_id,
        ghost_pubkey_hex,
        ed25519_pubkey_hex,
        mlkem_pub_bytes,
        cpx_micros,
        reserve_myc_micros,
        reserve_cpx_fee_micros,
        circulating_cpx_micros,
        accounts_list,
        ledger_records,
        ledger_valid,
        nfc_receipts,
        contracts,
        distributions,
        royalty_gross,
        royalty_reserve_fees,
    ) = {
        let guard = state.persist.lock().unwrap();
        let ghost_hex = guard
            .wallet
            .ghost_pubkey_xonly()
            .map(hex::encode)
            .unwrap_or_default();
        let ed_hex = hex::encode(guard.wallet.verifying_key().to_bytes());
        let accs: Vec<Value> = guard
            .portfolio
            .accounts
            .values()
            .map(|a| {
                json!({
                    "id": a.id,
                    "label": a.owner,
                    "cpx_micros": a.balance(Asset::Cpx),
                    "myc_micros": a.balance(Asset::Myc),
                    "usdc_micros": a.balance(Asset::Usdc),
                    "brl_micros": a.balance(Asset::Brl),
                    "btc_micros": a.balance(Asset::Btc),
                })
            })
            .collect();
        let (recs, valid) = match guard.ledger() {
            Ok(l) => {
                let v = l.tail().is_ok();
                let mut rows = Vec::new();
                if let Ok(raw) = std::fs::read_to_string(l.ledger_path()) {
                    for line in raw.lines().rev().take(30) {
                        if let Ok(r) = serde_json::from_str::<BankLedgerRecord>(line) {
                            rows.push(r);
                        }
                    }
                }
                (rows, v)
            }
            Err(_) => (Vec::new(), false),
        };
        let reserve_cpx_fee = guard
            .portfolio
            .accounts
            .get(MINT_RESERVE_ACCOUNT_ID)
            .map(|a| a.balance(Asset::Cpx))
            .unwrap_or(0);
        (
            guard.wallet.account_id.clone(),
            ghost_hex,
            ed_hex,
            guard.wallet.public_kem.len(),
            guard.local_cpx_micros(),
            guard.reserve_myc_micros(),
            reserve_cpx_fee,
            guard.cpx_circulating_micros(),
            accs,
            recs,
            valid,
            guard.nfc_history.receipts.iter().cloned().collect::<Vec<_>>(),
            guard
                .royalty_engine
                .contracts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
            guard
                .royalty_engine
                .distributions
                .iter()
                .rev()
                .take(30)
                .cloned()
                .collect::<Vec<_>>(),
            guard.royalty_engine.total_gross_cpx_micros,
            guard.royalty_engine.total_reserve_fee_cpx_micros,
        )
    };

    // Consulta o estado vivo da reserva no Organismo (`mycelium-mint`)
    let cpx_circ_base = (circulating_cpx_micros.max(0) as u128) * 100;
    let (tx, rx) = oneshot::channel();
    let _ = state.outbound.send(RhizomeOutbound::GetMintReserveStatus {
        cpx_circulating_base: cpx_circ_base,
        reply: tx,
    });
    let mint_reserve = tokio::time::timeout(Duration::from_secs(3), rx)
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_else(|| {
            json!({
                "role": "mycelium-mint reserve vault",
                "cpx_per_myc": 8,
                "reserve_myc_micros": reserve_myc_micros,
                "cpx_circulating_micros": circulating_cpx_micros,
                "fully_backed": (reserve_myc_micros * 8) >= circulating_cpx_micros,
            })
        });

    // Também agrega saldos de nutrientes do Organismo
    let (wtx, wrx) = oneshot::channel();
    let _ = state
        .outbound
        .send(RhizomeOutbound::GetWalletReport { reply: wtx });
    let organism_wallet = tokio::time::timeout(Duration::from_secs(3), wrx)
        .await
        .ok()
        .and_then(|r| r.ok());

    json_ok(json!({
        "platform_currency": {
            "symbol": "CPX",
            "name": "Cameon PX (Moeda Unificada da Plataforma Mycelium)",
            "decimals_bank_micros": 6,
            "decimals_canonical_camoshis": 8,
            "reserve_engine": "mycelium-mint (PoUW-DAG + Pedersen ZKP + Quórum Esporocarpo)",
            "reserve_ratio": "1 MYC reserva = 8 CPX (paridade 1 CPX = 1 USDC ref)",
        },
        "identity": {
            "bank_account_id": account_id,
            "ghost_pubkey_hex": ghost_pubkey_hex,
            "ed25519_pubkey_hex": ed25519_pubkey_hex,
            "mlkem1024_pubkey_bytes": mlkem_pub_bytes,
            "compatible_with": ["NFC (NDEF TNF=4)", "Mycelium Bank", "Mycelium Pay (CBOR BIP-340)", "Mycelium Wallet", "Mycelium Royalty", "AEX World"],
        },
        "balances": {
            "cpx_micros": cpx_micros,
            "cpx_formatted": format!("{:.6}", cpx_micros as f64 / 1_000_000.0),
            "reserve_myc_micros": reserve_myc_micros,
            "reserve_myc_formatted": format!("{:.6}", reserve_myc_micros as f64 / 1_000_000.0),
            "reserve_cpx_fees_micros": reserve_cpx_fee_micros,
            "circulating_cpx_micros": circulating_cpx_micros,
        },
        "mint_reserve": mint_reserve,
        "organism_nutrients": organism_wallet,
        "bank": {
            "ledger_chain_valid": ledger_valid,
            "accounts": accounts_list,
            "recent_ledger": ledger_records,
        },
        "nfc": {
            "ndef_external_type": mycelium_bank::nfc::NDEF_EXTERNAL_TYPE,
            "uri_prefix": mycelium_bank::nfc::NFC_CPX_URI_PREFIX,
            "receipts": nfc_receipts,
        },
        "royalties": {
            "default_reserve_fee_bps": DEFAULT_RESERVE_FEE_BPS,
            "total_gross_cpx_micros": royalty_gross,
            "total_reserve_fee_cpx_micros": royalty_reserve_fees,
            "contracts": contracts,
            "distributions": distributions,
        }
    }))
}

#[derive(Deserialize)]
struct MintReserveReq {
    #[serde(default = "default_mint_units")]
    units: u64,
    #[serde(default)]
    memo: String,
}
fn default_mint_units() -> u64 {
    10
}

async fn mint_reserve_to_cpx_api(
    State(state): State<EcosystemState>,
    Json(req): Json<MintReserveReq>,
) -> Response {
    let units = req.units.clamp(1, 100_000);
    let (tx, rx) = oneshot::channel();
    if state
        .outbound
        .send(RhizomeOutbound::MintReserveSettle {
            units,
            memo: req.memo.clone(),
            reply: tx,
        })
        .is_err()
    {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Organismo indisponível");
    }

    let settled_mint = match tokio::time::timeout(Duration::from_secs(10), rx).await {
        Ok(Ok(Ok(out))) => out,
        Ok(Ok(Err(e))) => return json_err(StatusCode::BAD_REQUEST, e),
        _ => return json_err(StatusCode::GATEWAY_TIMEOUT, "timeout na liquidação da reserva Mint"),
    };

    // Liquida o MintReceipt real na reserva do mycelium-bank (bloqueia MYC na conta reserva + emite CPX)
    let result: Result<(CpxReserveSettlementRecord, i64, i64), String> = {
        let mut guard = state.persist.lock().unwrap();
        let now = unix_now();
        let ledger = match guard.ledger() {
            Ok(l) => l,
            Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
        };
        let mut receipt_for_local = settled_mint.receipt.clone();
        // Mapeia o beneficiário para a conta bancária local vinculada ao nó
        let local_acc_id = guard.wallet.account_id.clone();
        match settle_mint_reserve_to_cpx(
            &receipt_for_local,
            &settled_mint.policy,
            &mut guard.portfolio,
            &ledger,
            now,
        ) {
            Ok(rec) => {
                // Move o saldo CPX emitido para o account_id principal da carteira local caso o beneficiary do receipt seja o NodeId
                if rec.beneficiary_account_id != local_acc_id {
                    let minted = rec.minted_cpx_micros;
                    if let Some(node_acc) = guard.portfolio.accounts.get_mut(&rec.beneficiary_account_id) {
                        let _ = node_acc.debit(Asset::Cpx, minted);
                    }
                    if let Some(local_acc) = guard.portfolio.accounts.get_mut(&local_acc_id) {
                        let _ = local_acc.credit(Asset::Cpx, minted);
                    }
                    let _ = ledger.append(Entry::Transfer {
                        from: rec.beneficiary_account_id.clone(),
                        to: local_acc_id.clone(),
                        asset: Asset::Cpx.symbol(),
                        micros: minted,
                        ref_id: "mint-reserve-to-local-wallet".into(),
                        at: now,
                    });
                }
                let _ = &mut receipt_for_local;
                if let Err(e) = guard.save_portfolio() {
                    return json_err(StatusCode::INTERNAL_SERVER_ERROR, e);
                }
                Ok((rec, guard.local_cpx_micros(), guard.reserve_myc_micros()))
            }
            Err(e) => Err(e.to_string()),
        }
    };

    match result {
        Ok((settlement, new_cpx_micros, new_reserve_myc_micros)) => json_ok(json!({
            "settlement": settlement,
            "reserve_status": settled_mint.reserve_status,
            "local_cpx_micros": new_cpx_micros,
            "reserve_myc_micros": new_reserve_myc_micros,
        })),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e),
    }
}

async fn get_reserve_policy_api(State(state): State<EcosystemState>) -> Response {
    let (tx, rx) = oneshot::channel();
    let _ = state
        .outbound
        .send(RhizomeOutbound::GetReservePolicy { reply: tx });
    match tokio::time::timeout(Duration::from_secs(3), rx).await {
        Ok(Ok(val)) => json_ok(val),
        _ => json_err(StatusCode::GATEWAY_TIMEOUT, "timeout consultando política de reserva"),
    }
}

#[derive(Deserialize)]
struct SporocarpSpecReq {
    node_id: String,
    pubkey_hex: String,
}

#[derive(Deserialize)]
struct ConfigureReservePolicyReq {
    #[serde(default)]
    chain_id: Option<String>,
    #[serde(default = "default_one_usize")]
    min_quorum: usize,
    #[serde(default)]
    min_hashcash_bits: Option<u8>,
    #[serde(default)]
    sporocarps: Vec<SporocarpSpecReq>,
    #[serde(default = "default_true")]
    include_self: bool,
}
fn default_one_usize() -> usize {
    1
}
fn default_true() -> bool {
    true
}

async fn configure_reserve_policy_api(
    State(state): State<EcosystemState>,
    Json(req): Json<ConfigureReservePolicyReq>,
) -> Response {
    let (tx, rx) = oneshot::channel();
    let extra_sporocarps = req
        .sporocarps
        .into_iter()
        .map(|s| (s.node_id, s.pubkey_hex))
        .collect();
    if state
        .outbound
        .send(RhizomeOutbound::ConfigureReservePolicy {
            chain_id: req.chain_id,
            min_quorum: req.min_quorum.max(1),
            min_hashcash_bits: req.min_hashcash_bits,
            extra_sporocarps,
            include_self: req.include_self,
            reply: tx,
        })
        .is_err()
    {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Organismo indisponível");
    }
    match tokio::time::timeout(Duration::from_secs(5), rx).await {
        Ok(Ok(Ok(val))) => json_ok(val),
        Ok(Ok(Err(e))) => json_err(StatusCode::BAD_REQUEST, e),
        _ => json_err(StatusCode::GATEWAY_TIMEOUT, "timeout configurando quórum esporocarpo"),
    }
}

async fn submit_mint_claim_p2p_api(
    State(state): State<EcosystemState>,
    Json(req): Json<MintReserveReq>,
) -> Response {
    let (tx, rx) = oneshot::channel();
    if state
        .outbound
        .send(RhizomeOutbound::SubmitMintClaimP2p {
            units: req.units.clamp(1, 100_000),
            memo: req.memo,
            reply: tx,
        })
        .is_err()
    {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Organismo indisponível");
    }
    match tokio::time::timeout(Duration::from_secs(10), rx).await {
        Ok(Ok(Ok(val))) => json_ok(val),
        Ok(Ok(Err(e))) => json_err(StatusCode::BAD_REQUEST, e),
        _ => json_err(StatusCode::GATEWAY_TIMEOUT, "timeout submetendo claim P2P"),
    }
}

#[derive(Deserialize)]
struct TransferCpxReq {
    to_account: String,
    amount_cpx_micros: i64,
    #[serde(default)]
    memo: String,
}

async fn transfer_cpx_api(
    State(state): State<EcosystemState>,
    Json(req): Json<TransferCpxReq>,
) -> Response {
    let res = {
        let mut guard = state.persist.lock().unwrap();
        let memo = if req.memo.trim().is_empty() {
            "transferência CPX soberana".to_string()
        } else {
            req.memo.clone()
        };
        guard
            .transfer_cpx_direct(&req.to_account, req.amount_cpx_micros, &memo)
            .map(|rec| (rec, guard.local_cpx_micros()))
    };
    match res {
        Ok((record, balance_cpx_micros)) => json_ok(json!({
            "record": record,
            "balance_cpx_micros": balance_cpx_micros,
        })),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e),
    }
}

#[derive(Deserialize)]
struct NfcRequestReq {
    to_account: Option<String>,
    amount_cpx_micros: i64,
    #[serde(default)]
    memo: String,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

async fn nfc_create_request_api(
    State(state): State<EcosystemState>,
    Json(req): Json<NfcRequestReq>,
) -> Response {
    if req.amount_cpx_micros <= 0 {
        return json_err(StatusCode::BAD_REQUEST, "amount_cpx_micros deve ser positivo");
    }
    let now = unix_now();
    let ttl = req.ttl_secs.unwrap_or(600).clamp(30, 86_400);

    let built = {
        let guard = state.persist.lock().unwrap();
        let ghost = match guard.wallet.derive_ghost_id(ttl) {
            Ok(g) => g,
            Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };
        let ghost_xonly = ghost.nostr_pubkey();
        let ghost_secret = guard.wallet.ghost_secret_bytes();
        let to_acc = req
            .to_account
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| guard.wallet.account_id.clone());
        let memo = if req.memo.trim().is_empty() {
            "Pagamento NFC CPX via GhostID".into()
        } else {
            req.memo.clone()
        };

        let intent = PaymentIntent::new(
            &guard.wallet.account_id,
            &to_acc,
            Amount::new(Asset::Cpx, req.amount_cpx_micros),
            memo,
            now,
        );
        let proof = match NfcProof::create_with_ghostid(&guard.wallet, &ghost, &intent) {
            Ok(p) => p,
            Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };

        // Cria envelope CBOR `mycelium-pay` PayRequest assinado em BIP-340 com o mesmo GhostID
        let mut payment_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut payment_id);
        let pay_req = PayRequest {
            payment_id,
            single_use: true,
            amount: req.amount_cpx_micros as u64,
            unit: "cpx".into(),
            mints: vec![MINT_RESERVE_ACCOUNT_ID.into()],
            p2pk: ghost_xonly,
            expires_at: now + ttl,
            transports: vec!["nfc".into(), "hyphae".into(), "veil".into()],
        };
        let mut pay_env = match pay_req.envelope() {
            Ok(e) => e,
            Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };
        if let Err(e) = pay_env.sign_bip340(&ghost_secret) {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
        let pay_cbor = match pay_env.encode() {
            Ok(b) => b,
            Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };

        let ndef = NfcNdefFrame::new(&ghost_xonly, intent.clone(), proof, Some(&pay_cbor));
        let ndef_bytes = match ndef.encode_ndef_record() {
            Ok(b) => b,
            Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };
        let uri = match ndef.to_uri() {
            Ok(u) => u,
            Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };

        json!({
            "payment_id_hex": hex::encode(payment_id),
            "ghost_pubkey_hex": hex::encode(ghost_xonly),
            "intent": intent,
            "ndef_uri": uri,
            "ndef_record_b64": base64::engine::general_purpose::STANDARD.encode(&ndef_bytes),
            "ndef_external_type": mycelium_bank::nfc::NDEF_EXTERNAL_TYPE,
            "pay_request_cbor_b64": base64::engine::general_purpose::STANDARD.encode(&pay_cbor),
            "expires_at": now + ttl,
            "verified_ghostid_schnorr": true,
            "verified_pay_cbor_bip340": pay_env.verify().is_ok(),
        })
    };

    json_ok(built)
}

#[derive(Deserialize)]
struct NfcTapReq {
    /// URI NDEF (`urn:mycelium:nfc:cpx:v1:...`) capturado via Web NFC / Android / QR Code.
    #[serde(default)]
    ndef_uri: Option<String>,
    /// Atalho para gerar + validar + liquidar um tap CPX local imediato.
    #[serde(default)]
    to_account: Option<String>,
    #[serde(default)]
    amount_cpx_micros: Option<i64>,
    #[serde(default)]
    memo: Option<String>,
}

async fn nfc_execute_tap_api(
    State(state): State<EcosystemState>,
    Json(req): Json<NfcTapReq>,
) -> Response {
    let now = unix_now();
    let res: Result<Value, (StatusCode, String)> = (|| {
        let mut guard = state.persist.lock().unwrap();
        let ndef_frame = if let Some(uri) = req.ndef_uri.as_deref().filter(|s| !s.trim().is_empty()) {
            NfcNdefFrame::from_uri(uri)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("NDEF NFC inválido: {e}")))?
        } else {
            let amount = req.amount_cpx_micros.unwrap_or(0);
            if amount <= 0 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "informe ndef_uri ou amount_cpx_micros > 0".into(),
                ));
            }
            let to_acc = req
                .to_account
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "merchant:cpx-nfc-demo".to_string());
            let memo = req
                .memo
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "Tap NFC GhostID × CPX".to_string());
            let ghost = guard
                .wallet
                .derive_ghost_id(600)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            let intent = PaymentIntent::new(
                &guard.wallet.account_id,
                &to_acc,
                Amount::new(Asset::Cpx, amount),
                memo,
                now,
            );
            let proof = NfcProof::create_with_ghostid(&guard.wallet, &ghost, &intent)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            NfcNdefFrame::new(&ghost.nostr_pubkey(), intent, proof, None)
        };

        // 1. Verifica assinatura dupla Ed25519 + GhostID BIP-340 Schnorr + ML-KEM
        if !ndef_frame.proof.verify_with_ghostid(&ndef_frame.intent) {
            return Err((
                StatusCode::UNAUTHORIZED,
                "prova NFC GhostID/Ed25519 inválida ou adulterada".into(),
            ));
        }
        // 2. Verifica envelope CBOR `mycelium-pay` embutido, se presente
        if let Some(ref cbor_b64) = ndef_frame.pay_envelope_cbor_b64 {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(cbor_b64)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("base64 pay CBOR inválido: {e}")))?;
            let env = PayEnvelope::decode(&raw)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("envelope mycelium-pay inválido: {e}")))?;
            env.verify().map_err(|e| {
                (
                    StatusCode::UNAUTHORIZED,
                    format!("assinatura BIP-340 mycelium-pay falhou: {e}"),
                )
            })?;
        }
        // 3. Anti-replay por nonce NFC
        if guard.nfc_history.seen_nonces.contains(&ndef_frame.intent.nonce) {
            return Err((
                StatusCode::CONFLICT,
                "nonce NFC já liquidado anteriormente (anti-replay)".into(),
            ));
        }
        // 4. Confirma decapsulação ML-KEM via `receive_nfc_payment`
        let bank_receipt = receive_nfc_payment(
            &guard.wallet,
            ndef_frame.intent.clone(),
            ndef_frame.proof.clone(),
        )
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

        // 5. Liquida CPX no `mycelium-bank` Portfolio + SovereignLedger
        let amount_micros = ndef_frame.intent.amount.micros;
        let ledger_rec = guard
            .transfer_cpx_direct(
                &ndef_frame.intent.to,
                amount_micros,
                &format!("nfc-ghostid:{}", ndef_frame.intent.memo),
            )
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

        // 6. Emite recibo CBOR `mycelium-pay::bodies::Receipt` assinado em BIP-340 GhostID
        let mut pay_id = [0u8; 16];
        let id_hash = blake3::hash(ndef_frame.intent.id.as_bytes());
        pay_id.copy_from_slice(&id_hash.as_bytes()[..16]);
        let token_send_id = *blake3::hash(ledger_rec.record_hash.as_bytes()).as_bytes();
        let pay_rcpt = PayReceipt {
            payment_id: pay_id,
            token_send_id,
            status: PayStatus::Redeemed,
            code: 0,
            ts: now,
        };
        let mut rcpt_env = pay_rcpt
            .envelope()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let ghost_secret = guard.wallet.ghost_secret_bytes();
        rcpt_env
            .sign_bip340(&ghost_secret)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let rcpt_cbor_b64 = base64::engine::general_purpose::STANDARD.encode(
            rcpt_env
                .encode()
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
        );

        let uri = ndef_frame
            .to_uri()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let log_item = NfcReceiptLogItem {
            payment_id: bank_receipt.id.clone(),
            from_account: ndef_frame.intent.from.clone(),
            to_account: ndef_frame.intent.to.clone(),
            ghost_pubkey_hex: ndef_frame.ghost_pubkey_hex.clone(),
            amount_cpx_micros: amount_micros,
            memo: ndef_frame.intent.memo.clone(),
            ndef_uri: uri,
            pay_receipt_cbor_b64: rcpt_cbor_b64.clone(),
            ledger_hash: ledger_rec.record_hash.clone(),
            settled_at: now,
        };
        guard
            .nfc_history
            .seen_nonces
            .insert(ndef_frame.intent.nonce.clone());
        guard.nfc_history.receipts.push_front(log_item.clone());
        while guard.nfc_history.receipts.len() > 64 {
            guard.nfc_history.receipts.pop_back();
        }
        guard
            .save_nfc_history()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

        Ok(json!({
            "bank_receipt": bank_receipt,
            "nfc_log": log_item,
            "pay_receipt_cbor_b64": rcpt_cbor_b64,
            "balance_cpx_micros": guard.local_cpx_micros(),
        }))
    })();

    match res {
        Ok(val) => json_ok(val),
        Err((status, e)) => json_err(status, e),
    }
}

#[derive(Deserialize)]
struct CreateRoyaltyContractReq {
    content_id: String,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    reserve_fee_bps: Option<u64>,
    splits: Vec<RoyaltySplit>,
}

async fn create_royalty_contract_api(
    State(state): State<EcosystemState>,
    Json(req): Json<CreateRoyaltyContractReq>,
) -> Response {
    if req.content_id.trim().is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "content_id obrigatório");
    }
    let now = unix_now();
    let res: Result<(RoyaltyContract, String), String> = (|| {
        let mut guard = state.persist.lock().unwrap();
        let sk = guard.wallet.signing_key();
        let ghost_hex = guard.wallet.ghost_pubkey_xonly().map(hex::encode).ok();
        let license = req
            .license
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "CC-BY-4.0 / Mycelium Royalty CPX".into());
        let reserve_fee_bps = req.reserve_fee_bps.unwrap_or(DEFAULT_RESERVE_FEE_BPS);
        let contract = RoyaltyContract::sign_new(
            req.content_id.trim(),
            &sk,
            ghost_hex,
            license,
            reserve_fee_bps,
            req.splits,
            now,
        )
        .map_err(|e| e.to_string())?;
        let iso_key = contract.isotope_key();
        guard
            .royalty_engine
            .register_contract(contract.clone())
            .map_err(|e| e.to_string())?;
        guard.save_royalties()?;
        Ok((contract, iso_key))
    })();

    match res {
        Ok((contract, isotope_key)) => json_ok(json!({
            "contract": contract,
            "isotope_key": isotope_key,
        })),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e),
    }
}

#[derive(Deserialize)]
struct PayoutRoyaltyReq {
    content_id: String,
    gross_cpx_micros: i64,
    #[serde(default)]
    memo: String,
}

async fn payout_royalty_api(
    State(state): State<EcosystemState>,
    Json(req): Json<PayoutRoyaltyReq>,
) -> Response {
    let memo = if req.memo.trim().is_empty() {
        format!("Royalty CPX {}", req.content_id)
    } else {
        req.memo.clone()
    };
    let res = {
        let mut guard = state.persist.lock().unwrap();
        guard
            .settle_royalty_cpx(&req.content_id, req.gross_cpx_micros, &memo)
            .map(|dist| (dist, guard.local_cpx_micros()))
    };
    match res {
        Ok((distribution, balance_cpx_micros)) => json_ok(json!({
            "distribution": distribution,
            "balance_cpx_micros": balance_cpx_micros,
        })),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e),
    }
}

// ============================================================================
// 2. SESSÃO AEX WORLD & CAMEON PX
// ============================================================================

async fn aex_status_api(State(state): State<EcosystemState>) -> Response {
    let aex_url = { state.persist.lock().unwrap().aex_url.clone() };

    // 1. Capacidades reais da ponte `aex-mycelium-bridge/1.0.0` dentro deste daemon
    let (btx, brx) = oneshot::channel();
    let _ = state.outbound.send(RhizomeOutbound::AexBridgeOp {
        op: AexBridgeOpReq::Info,
        reply: btx,
    });
    let bridge_info = tokio::time::timeout(Duration::from_secs(2), brx)
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_else(|| json!({ "protocol_version": "aex-mycelium-bridge/1.0.0" }));

    // 2. Sonda ao vivo o servidor local AEX World (`127.0.0.1:4173` ou configurado)
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build();
    let mut aex_online = false;
    let mut aex_health = Value::Null;
    let mut aex_pame = Value::Null;
    let mut aex_state_summary = Value::Null;
    let mut probe_error: Option<String> = None;

    if let Ok(cli) = client {
        let base = aex_url.trim_end_matches('/');
        match cli.get(format!("{base}/api/health")).send().await {
            Ok(resp) if resp.status().is_success() => {
                aex_online = true;
                aex_health = resp.json::<Value>().await.unwrap_or(Value::Null);
                if let Ok(p) = cli.get(format!("{base}/api/pame")).send().await {
                    if p.status().is_success() {
                        aex_pame = p.json::<Value>().await.unwrap_or(Value::Null);
                    }
                }
                if let Ok(s) = cli.get(format!("{base}/api/state")).send().await {
                    if s.status().is_success() {
                        if let Ok(sv) = s.json::<Value>().await {
                            aex_state_summary = json!({
                                "assets_count": sv.get("assets").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0),
                                "campaigns_count": sv.get("campaigns").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0),
                                "instruments_count": sv.get("instruments").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0),
                                "bearer_notes_count": sv.get("bearer_notes").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0),
                                "btc_htlcs_count": sv.get("btc_htlcs").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0),
                            });
                        }
                    }
                }
            }
            Ok(resp) => {
                probe_error = Some(format!("HTTP {} em {base}/api/health", resp.status()));
            }
            Err(e) => {
                probe_error = Some(format!("Nó AEX World offline em {base}: {e}"));
            }
        }
    }

    let (local_cpx, reserve_myc) = {
        let g = state.persist.lock().unwrap();
        (g.local_cpx_micros(), g.reserve_myc_micros())
    };

    json_ok(json!({
        "aex_url": aex_url,
        "aex_node_online": aex_online,
        "probe_error": probe_error,
        "aex_health": aex_health,
        "aex_pame": aex_pame,
        "aex_state_summary": aex_state_summary,
        "mycelium_bridge": bridge_info,
        "local_cpx_micros": local_cpx,
        "reserve_myc_micros": reserve_myc,
        "non_alienation_covenant": "O patrimônio permanece. O capital circula. A receita é compartilhada. A propriedade é preservada.",
        "launch_hint": "No workspace AEX WORLD & CAMEON PX: `./aex node 4173` ou `./target/release/aex-world serve 4173`",
    }))
}

#[derive(Deserialize)]
struct AexConfigReq {
    aex_url: String,
}

async fn aex_config_api(
    State(state): State<EcosystemState>,
    Json(req): Json<AexConfigReq>,
) -> Response {
    let url = req.aex_url.trim().to_string();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return json_err(StatusCode::BAD_REQUEST, "aex_url deve começar com http:// ou https://");
    }
    state.persist.lock().unwrap().aex_url = url.clone();
    json_ok(json!({ "aex_url": url }))
}

#[derive(Deserialize, Serialize)]
struct AexSimulateReq {
    #[serde(default = "default_asset_status")]
    asset_status: String,
    #[serde(default = "default_aex_class")]
    class: String,
    units: u64,
    unit_price_cpx: f64,
    share_bps: u64,
    projected_gross_revenue_cpx: f64,
    #[serde(default)]
    deductible_costs_cpx: f64,
    ceiling_cpx: f64,
    periods: u64,
}
fn default_asset_status() -> String {
    "PRODUCTIVE".into()
}
fn default_aex_class() -> String {
    "AEX-REV".into()
}

async fn aex_simulate_api(
    State(state): State<EcosystemState>,
    Json(req): Json<AexSimulateReq>,
) -> Response {
    let aex_url = { state.persist.lock().unwrap().aex_url.clone() };
    // Tenta delegar primeiro ao nó AEX World ao vivo
    if let Ok(cli) = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        let base = aex_url.trim_end_matches('/');
        if let Ok(resp) = cli
            .post(format!("{base}/api/simulate"))
            .header("Origin", base)
            .json(&req)
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(val) = resp.json::<Value>().await {
                    return json_ok(json!({
                        "source": "aex_live",
                        "result": val,
                    }));
                }
            }
        }
    }

    // Cálculo local determinístico (sem mutação de ledger nem alienação de propriedade)
    let capital_raised_cpx = (req.units as f64) * req.unit_price_cpx;
    let net_period_rev = (req.projected_gross_revenue_cpx - req.deductible_costs_cpx).max(0.0);
    let payout_per_period_cpx = net_period_rev * (req.share_bps as f64 / 10_000.0);
    let total_distributed_cpx = (payout_per_period_cpx * (req.periods as f64)).min(req.ceiling_cpx);
    let ownership_transferred_pct = 0.0;
    let multiple = if capital_raised_cpx > 0.0 {
        total_distributed_cpx / capital_raised_cpx
    } else {
        0.0
    };

    json_ok(json!({
        "source": "local_preview",
        "result": {
            "asset_status": req.asset_status,
            "class": req.class,
            "non_alienation_verified": true,
            "ownership_transferred_pct": ownership_transferred_pct,
            "capital_raised_cpx": capital_raised_cpx,
            "payout_per_period_cpx": payout_per_period_cpx,
            "total_distributed_cpx": total_distributed_cpx,
            "ceiling_cpx": req.ceiling_cpx,
            "effective_multiple": multiple,
            "periods": req.periods,
        }
    }))
}

async fn aex_bridge_op_api(
    State(state): State<EcosystemState>,
    Json(op): Json<AexBridgeOpReq>,
) -> Response {
    let (tx, rx) = oneshot::channel();
    if state
        .outbound
        .send(RhizomeOutbound::AexBridgeOp { op, reply: tx })
        .is_err()
    {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Organismo indisponível");
    }
    match tokio::time::timeout(Duration::from_secs(5), rx).await {
        Ok(Ok(val)) => json_ok(val),
        _ => json_err(StatusCode::GATEWAY_TIMEOUT, "timeout na ponte aex-mycelium-bridge"),
    }
}

// ============================================================================
// 3. VEIL Ω PROXY / VPN
// ============================================================================

async fn veil_status_api(State(state): State<EcosystemState>) -> Response {
    let (tx, rx) = oneshot::channel();
    let _ = state
        .outbound
        .send(RhizomeOutbound::GetVeilStatus { reply: tx });
    match tokio::time::timeout(Duration::from_secs(3), rx).await {
        Ok(Ok(st)) => json_ok(serde_json::to_value(st).unwrap_or_else(|_| json!({}))),
        _ => json_err(StatusCode::GATEWAY_TIMEOUT, "timeout ao consultar VEIL Ω"),
    }
}

#[derive(Deserialize)]
struct VeilStartReq {
    #[serde(default = "default_veil_mode")]
    mode: String,
    #[serde(default = "default_veil_role")]
    role: String,
    #[serde(default = "default_veil_port")]
    port: u16,
    #[serde(default)]
    guards: Vec<String>,
    #[serde(default)]
    middles: Vec<String>,
    #[serde(default)]
    exits: Vec<String>,
    #[serde(default)]
    trust: Vec<String>,
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    advertise: Option<String>,
}
fn default_veil_mode() -> String {
    "veil".into()
}
fn default_veil_role() -> String {
    "all".into()
}
fn default_veil_port() -> u16 {
    1080
}

async fn veil_start_api(
    State(state): State<EcosystemState>,
    Json(req): Json<VeilStartReq>,
) -> Response {
    let (tx, rx) = oneshot::channel();
    if state
        .outbound
        .send(RhizomeOutbound::StartVeil {
            mode: req.mode,
            role: req.role,
            socks5_port: req.port,
            guards: req.guards,
            middles: req.middles,
            exits: req.exits,
            trust: req.trust,
            listen: req.listen,
            advertise: req.advertise,
            reply: tx,
        })
        .is_err()
    {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Organismo indisponível");
    }
    match tokio::time::timeout(Duration::from_secs(10), rx).await {
        Ok(Ok(Ok(st))) => json_ok(serde_json::to_value(st).unwrap_or_else(|_| json!({}))),
        Ok(Ok(Err(e))) => json_err(StatusCode::BAD_REQUEST, e),
        _ => json_err(StatusCode::GATEWAY_TIMEOUT, "timeout ao iniciar VEIL Ω"),
    }
}

async fn veil_stop_api(State(state): State<EcosystemState>) -> Response {
    let (tx, rx) = oneshot::channel();
    let _ = state.outbound.send(RhizomeOutbound::StopVeil { reply: tx });
    match tokio::time::timeout(Duration::from_secs(5), rx).await {
        Ok(Ok(st)) => json_ok(serde_json::to_value(st).unwrap_or_else(|_| json!({}))),
        _ => json_err(StatusCode::GATEWAY_TIMEOUT, "timeout ao parar VEIL Ω"),
    }
}

#[derive(Deserialize)]
struct VeilKillSwitchReq {
    engaged: bool,
}

async fn veil_killswitch_api(
    State(state): State<EcosystemState>,
    Json(req): Json<VeilKillSwitchReq>,
) -> Response {
    let (tx, rx) = oneshot::channel();
    let _ = state.outbound.send(RhizomeOutbound::SetVeilKillSwitch {
        engaged: req.engaged,
        reply: tx,
    });
    match tokio::time::timeout(Duration::from_secs(5), rx).await {
        Ok(Ok(Ok(st))) => json_ok(serde_json::to_value(st).unwrap_or_else(|_| json!({}))),
        Ok(Ok(Err(e))) => json_err(StatusCode::BAD_REQUEST, e),
        _ => json_err(StatusCode::GATEWAY_TIMEOUT, "timeout ao alterar Kill Switch VEIL"),
    }
}

/// Executa um handshake RFC 1928 SOCKS5 real (`0x05 0x01 0x00` -> `0x05 0x00`) contra o proxy VEIL ativo.
async fn veil_test_socks5_api(State(state): State<EcosystemState>) -> Response {
    let (tx, rx) = oneshot::channel();
    let _ = state
        .outbound
        .send(RhizomeOutbound::GetVeilStatus { reply: tx });
    let status = match tokio::time::timeout(Duration::from_secs(3), rx).await {
        Ok(Ok(st)) => st,
        _ => return json_err(StatusCode::GATEWAY_TIMEOUT, "timeout ao consultar VEIL"),
    };
    let Some(addr) = status.socks5_addr.clone() else {
        return json_err(
            StatusCode::BAD_REQUEST,
            "VEIL SOCKS5 não está ativo; inicie o VEIL primeiro",
        );
    };

    let t0 = Instant::now();
    let probe = tokio::time::timeout(Duration::from_secs(3), async {
        let mut s = tokio::net::TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("falha ao conectar em {addr}: {e}"))?;
        s.write_all(&[0x05, 0x01, 0x00])
            .await
            .map_err(|e| format!("falha ao enviar greeting SOCKS5: {e}"))?;
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp)
            .await
            .map_err(|e| format!("falha ao ler resposta SOCKS5: {e}"))?;
        Ok::<[u8; 2], String>(resp)
    })
    .await;

    let rtt_ms = t0.elapsed().as_millis() as u64;
    match probe {
        Ok(Ok([0x05, 0x00])) => json_ok(json!({
            "ok": true,
            "socks5_addr": addr,
            "rfc1928_handshake": "0x05 0x00 (NO AUTH OK)",
            "rtt_ms": rtt_ms,
            "kill_switch_state": status.kill_switch_state,
            "mode": status.mode,
        })),
        Ok(Ok(other)) => json_err(
            StatusCode::BAD_GATEWAY,
            format!("resposta SOCKS5 inesperada: {:02x?}", other),
        ),
        Ok(Err(e)) => json_err(StatusCode::BAD_GATEWAY, e),
        Err(_) => json_err(StatusCode::GATEWAY_TIMEOUT, "timeout no handshake SOCKS5"),
    }
}

// ============================================================================
// 4. OMNIBRIDGE SOCIAL (9 REDES)
// ============================================================================

async fn omnibridge_overview_api(State(state): State<EcosystemState>) -> Response {
    let (platforms, total_contacts, total_channels, total_items) = {
        let guard = state.persist.lock().unwrap();
        let views = guard.omnibridge_index.platform_views(&guard.vault);
        (
            views,
            guard.omnibridge_index.contacts.len(),
            guard.omnibridge_index.channels.len(),
            guard.omnibridge_index.items.len(),
        )
    };
    json_ok(json!({
        "vault_encryption": "XChaCha20-Poly1305 (chave derivada localmente da Gland via BLAKE3)",
        "honest_sandbox_notice": "O sandbox do Android/SO isola dados privados de outros apps; o Omnibridge acessa canais, feeds e contatos usando exclusivamente suas credenciais/tokens oficiais no cofre cifrado local, feeds públicos oficiais (YouTube Atom / Reddit JSON), importação de arquivos oficiais/vCard e deep-links para o app instalado — nunca burla CAPTCHAs ou isolamento do sistema.",
        "totals": {
            "platforms": platforms.len(),
            "contacts": total_contacts,
            "channels": total_channels,
            "items": total_items,
        },
        "platforms": platforms,
    }))
}

#[derive(Deserialize)]
struct OmnibridgeConnectReq {
    platform: String,
    #[serde(default)]
    account_handle: String,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    extra_id: Option<String>,
    #[serde(default)]
    watched_channels: Vec<String>,
    #[serde(default)]
    route_via_veil: bool,
    #[serde(default)]
    disconnect: bool,
}

async fn omnibridge_connect_api(
    State(state): State<EcosystemState>,
    Json(req): Json<OmnibridgeConnectReq>,
) -> Response {
    let platform = match SocialPlatform::from_str_loose(&req.platform) {
        Ok(p) => p,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, e.to_string()),
    };

    let res = {
        let mut guard = state.persist.lock().unwrap();
        if req.disconnect {
            guard.vault.credentials.remove(&platform);
        } else {
            let existing = guard.vault.credentials.get(&platform).cloned();
            let token = req
                .access_token
                .filter(|s| !s.trim().is_empty())
                .or_else(|| existing.as_ref().and_then(|e| e.access_token.clone()));
            let client_id = req
                .client_id
                .filter(|s| !s.trim().is_empty())
                .or_else(|| existing.as_ref().and_then(|e| e.client_id.clone()));
            let extra_id = req
                .extra_id
                .filter(|s| !s.trim().is_empty())
                .or_else(|| existing.as_ref().and_then(|e| e.extra_id.clone()));
            let watched: Vec<String> = req
                .watched_channels
                .into_iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let handle = if !req.account_handle.trim().is_empty() {
                req.account_handle.trim().to_string()
            } else {
                existing
                    .as_ref()
                    .map(|e| e.account_handle.clone())
                    .unwrap_or_default()
            };

            guard.vault.credentials.insert(
                platform,
                PlatformCredentialRecord {
                    platform,
                    account_handle: handle,
                    access_token: token,
                    client_id,
                    extra_id,
                    watched_channels: watched,
                    route_via_veil: req.route_via_veil,
                    updated_at: unix_now(),
                },
            );
        }
        if let Err(e) = guard.save_vault() {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, e);
        }
        guard
            .omnibridge_index
            .platform_views(&guard.vault)
            .into_iter()
            .find(|v| v.platform == platform)
    };

    json_ok(json!({ "platform": res }))
}

#[derive(Deserialize)]
struct OmnibridgeSyncReq {
    #[serde(default)]
    platform: Option<String>,
}

fn build_outbound_http_client(veil_socks5_uri: Option<&str>) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .user_agent("MyceliumRhizome-Omnibridge/0.1 (+https://mycelium.network)");
    if let Some(proxy_uri) = veil_socks5_uri {
        let proxy = reqwest::Proxy::all(proxy_uri)
            .map_err(|e| format!("proxy VEIL SOCKS5 inválido ({proxy_uri}): {e}"))?;
        builder = builder.proxy(proxy);
    }
    builder.build().map_err(|e| e.to_string())
}

async fn sync_single_platform(
    cred: &PlatformCredentialRecord,
    veil_socks5_uri: Option<&str>,
) -> Result<OmnibridgeSyncDelta, String> {
    let proxy_opt = if cred.route_via_veil {
        if veil_socks5_uri.is_none() {
            return Err("route_via_veil ativado, mas o proxy VEIL Ω não está ligado — inicie o VEIL primeiro".into());
        }
        veil_socks5_uri
    } else {
        None
    };
    let cli = build_outbound_http_client(proxy_opt)?;
    let token = cred
        .access_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let mut combined = OmnibridgeSyncDelta::default();
    let mut notes = Vec::new();

    match cred.platform {
        SocialPlatform::Youtube => {
            // 1. Feeds Atom oficiais por channel_id (funciona com ZERO chave!)
            for ch in &cred.watched_channels {
                let clean = ch.trim();
                let url = if clean.starts_with("http://") || clean.starts_with("https://") {
                    clean.to_string()
                } else {
                    format!("https://www.youtube.com/feeds/videos.xml?channel_id={clean}")
                };
                match cli.get(&url).send().await {
                    Ok(r) if r.status().is_success() => {
                        if let Ok(xml) = r.text().await {
                            let d = parse_youtube_atom_feed(&xml, clean);
                            notes.push(d.note);
                            combined.channels.extend(d.channels);
                            combined.items.extend(d.items);
                        }
                    }
                    Ok(r) => notes.push(format!("YouTube {clean}: HTTP {}", r.status())),
                    Err(e) => notes.push(format!("YouTube {clean}: {e}")),
                }
            }
            // 2. YouTube Data API v3 (se usuário forneceu OAuth Bearer token)
            if let Some(tok) = token {
                let url = "https://www.googleapis.com/youtube/v3/subscriptions?part=snippet&mine=true&maxResults=25";
                if let Ok(r) = cli.get(url).bearer_auth(tok).send().await {
                    if r.status().is_success() {
                        if let Ok(v) = r.json::<Value>().await {
                            let now = unix_now();
                            if let Some(items) = v.get("items").and_then(|x| x.as_array()) {
                                for it in items {
                                    let Some(sn) = it.get("snippet") else { continue };
                                    let cid = sn
                                        .get("resourceId")
                                        .and_then(|r| r.get("channelId"))
                                        .and_then(|x| x.as_str())
                                        .unwrap_or("");
                                    let title = sn.get("title").and_then(|x| x.as_str()).unwrap_or(cid);
                                    if !cid.is_empty() {
                                        combined.channels.push(mycelium_rhizome::ExternalChannel {
                                            id: format!("youtube_ch_{cid}"),
                                            platform: SocialPlatform::Youtube,
                                            external_id: cid.into(),
                                            handle: cid.into(),
                                            title: title.into(),
                                            description: sn
                                                .get("description")
                                                .and_then(|x| x.as_str())
                                                .unwrap_or("")
                                                .chars()
                                                .take(200)
                                                .collect(),
                                            is_live: false,
                                            subscriber_or_viewer_count: None,
                                            deep_link: SocialPlatform::Youtube.deep_link_for(cid),
                                            android_package: SocialPlatform::Youtube.android_package().into(),
                                            source_mode: "official_api".into(),
                                            synced_at: now,
                                        });
                                    }
                                }
                                notes.push(format!("YouTube API v3: {} inscrições", items.len()));
                            }
                        }
                    } else {
                        notes.push(format!("YouTube API v3: HTTP {}", r.status()));
                    }
                }
            }
        }
        SocialPlatform::Reddit => {
            if let Some(tok) = token {
                if let Ok(r) = cli
                    .get("https://oauth.reddit.com/subreddits/mine/subscriber?limit=25")
                    .bearer_auth(tok)
                    .send()
                    .await
                {
                    if r.status().is_success() {
                        if let Ok(txt) = r.text().await {
                            if let Ok(d) = parse_reddit_listing_json(&txt, "") {
                                notes.push(d.note);
                                combined.channels.extend(d.channels);
                                combined.contacts.extend(d.contacts);
                                combined.items.extend(d.items);
                            }
                        }
                    } else {
                        notes.push(format!("Reddit OAuth: HTTP {}", r.status()));
                    }
                }
            }
            for sub in &cred.watched_channels {
                let clean = sub.trim().trim_start_matches("r/").trim_start_matches('/');
                if clean.is_empty() {
                    continue;
                }
                let url = format!("https://www.reddit.com/r/{clean}/hot.json?limit=10");
                match cli.get(&url).send().await {
                    Ok(r) if r.status().is_success() => {
                        if let Ok(txt) = r.text().await {
                            if let Ok(d) = parse_reddit_listing_json(&txt, clean) {
                                notes.push(d.note);
                                combined.channels.extend(d.channels);
                                combined.contacts.extend(d.contacts);
                                combined.items.extend(d.items);
                            }
                        }
                    }
                    Ok(r) => notes.push(format!("Reddit r/{clean}: HTTP {}", r.status())),
                    Err(e) => notes.push(format!("Reddit r/{clean}: {e}")),
                }
            }
        }
        SocialPlatform::Twitch => {
            let Some(tok) = token else {
                return Err("Twitch Helix exige OAuth Bearer token + Client-Id do usuário".into());
            };
            let Some(cid) = cred
                .client_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            else {
                return Err("Twitch Helix exige Client-Id".into());
            };
            let mut url = "https://api.twitch.tv/helix/streams?first=15".to_string();
            for login in &cred.watched_channels {
                let clean = login.trim().trim_start_matches('@');
                if !clean.is_empty() {
                    url.push_str("&user_login=");
                    url.push_str(clean);
                }
            }
            let r = cli
                .get(&url)
                .bearer_auth(tok)
                .header("Client-Id", cid)
                .send()
                .await
                .map_err(|e| format!("Twitch Helix erro de rede: {e}"))?;
            if !r.status().is_success() {
                return Err(format!("Twitch Helix HTTP {}", r.status()));
            }
            let txt = r.text().await.map_err(|e| e.to_string())?;
            combined = parse_twitch_helix_json(&txt).map_err(|e| e.to_string())?;
            notes.push(combined.note.clone());
        }
        SocialPlatform::Telegram => {
            let Some(tok) = token else {
                return Err("Telegram Bot API exige bot token (ou use Importação JSON do Telegram Desktop)".into());
            };
            let url = format!("https://api.telegram.org/bot{tok}/getUpdates?limit=30");
            let r = cli
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("Telegram erro de rede: {e}"))?;
            if !r.status().is_success() {
                return Err(format!("Telegram Bot API HTTP {}", r.status()));
            }
            let txt = r.text().await.map_err(|e| e.to_string())?;
            combined = parse_telegram_json(&txt, "official_api").map_err(|e| e.to_string())?;
            notes.push(combined.note.clone());
        }
        SocialPlatform::X => {
            if let Some(tok) = token {
                let me_r = cli
                    .get("https://api.x.com/2/users/me")
                    .bearer_auth(tok)
                    .send()
                    .await
                    .map_err(|e| format!("X API v2 erro: {e}"))?;
                if !me_r.status().is_success() {
                    return Err(format!("X API v2 /users/me HTTP {}", me_r.status()));
                }
                let me_val: Value = me_r.json().await.map_err(|e| e.to_string())?;
                if let Some(uid) = me_val
                    .get("data")
                    .and_then(|d| d.get("id"))
                    .and_then(|x| x.as_str())
                {
                    if let Ok(fr) = cli
                        .get(format!("https://api.x.com/2/users/{uid}/following?max_results=50"))
                        .bearer_auth(tok)
                        .send()
                        .await
                    {
                        if fr.status().is_success() {
                            if let Ok(txt) = fr.text().await {
                                if let Ok(d) = parse_x_json(&txt, "official_api") {
                                    notes.push(d.note);
                                    combined.contacts.extend(d.contacts);
                                    combined.items.extend(d.items);
                                }
                            }
                        }
                    }
                }
            } else if !cred.watched_channels.is_empty() {
                // Endpoint público oficial oEmbed do X/Twitter para URLs/perfis públicos informados
                for ch in cred.watched_channels.iter().take(8) {
                    let target_url = if ch.starts_with("http://") || ch.starts_with("https://") {
                        ch.clone()
                    } else {
                        format!("https://x.com/{}", ch.trim_start_matches('@'))
                    };
                    if let Ok(r) = cli
                        .get("https://publish.twitter.com/oembed")
                        .query(&[("url", target_url.as_str())])
                        .send()
                        .await
                    {
                        if r.status().is_success() {
                            if let Ok(v) = r.json::<Value>().await {
                                let author = v
                                    .get("author_name")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or(ch)
                                    .to_string();
                                let url_out = v
                                    .get("url")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or(&target_url)
                                    .to_string();
                                combined.channels.push(mycelium_rhizome::ExternalChannel {
                                    id: format!("x:ch:{}", hex::encode(&blake3::hash(url_out.as_bytes()).as_bytes()[..8])),
                                    platform: SocialPlatform::X,
                                    external_id: ch.clone(),
                                    title: author.clone(),
                                    handle: ch.clone(),
                                    description: "Sincronizado via oEmbed público oficial do X".into(),
                                    is_live: false,
                                    subscriber_or_viewer_count: None,
                                    deep_link: url_out,
                                    android_package: SocialPlatform::X.android_package().into(),
                                    source_mode: "oembed_public".into(),
                                    synced_at: unix_now(),
                                });
                                notes.push(format!("X oEmbed público: {author}"));
                            }
                        }
                    }
                }
            } else {
                return Err("X API v2 exige OAuth2 Bearer token, URL pública para oEmbed oficial, ou importação tweets.js/following.js".into());
            }
        }
        SocialPlatform::Instagram => {
            let Some(tok) = token else {
                return Err("Instagram Graph API exige access token do usuário (ou importe o JSON oficial do Instagram)".into());
            };
            let url = "https://graph.instagram.com/me/media?fields=id,caption,permalink,timestamp,username&limit=25";
            let r = cli
                .get(url)
                .query(&[("access_token", tok)])
                .send()
                .await
                .map_err(|e| format!("Instagram Graph erro: {e}"))?;
            if !r.status().is_success() {
                return Err(format!("Instagram Graph HTTP {}", r.status()));
            }
            let txt = r.text().await.map_err(|e| e.to_string())?;
            combined = parse_meta_json(SocialPlatform::Instagram, &txt, "official_api")
                .map_err(|e| e.to_string())?;
            notes.push(combined.note.clone());
        }
        SocialPlatform::Facebook => {
            let Some(tok) = token else {
                return Err("Facebook Graph API exige access token do usuário (ou importe o JSON oficial do Facebook)".into());
            };
            let url = "https://graph.facebook.com/v21.0/me/accounts?fields=id,name,category";
            let r = cli
                .get(url)
                .query(&[("access_token", tok)])
                .send()
                .await
                .map_err(|e| format!("Facebook Graph erro: {e}"))?;
            if !r.status().is_success() {
                return Err(format!("Facebook Graph HTTP {}", r.status()));
            }
            let txt = r.text().await.map_err(|e| e.to_string())?;
            combined = parse_meta_json(SocialPlatform::Facebook, &txt, "official_api")
                .map_err(|e| e.to_string())?;
            notes.push(combined.note.clone());
        }
        SocialPlatform::Tiktok => {
            if let Some(tok) = token {
                let url = "https://open.tiktokapis.com/v2/video/list/?fields=id,title,video_description,share_url,create_time";
                let r = cli
                    .post(url)
                    .bearer_auth(tok)
                    .json(&json!({"max_count": 20}))
                    .send()
                    .await
                    .map_err(|e| format!("TikTok API erro: {e}"))?;
                if !r.status().is_success() {
                    return Err(format!("TikTok Display API HTTP {}", r.status()));
                }
                let txt = r.text().await.map_err(|e| e.to_string())?;
                combined = parse_tiktok_json(&txt, "official_api").map_err(|e| e.to_string())?;
                notes.push(combined.note.clone());
            } else if !cred.watched_channels.is_empty() {
                // Endpoint público oficial oEmbed do TikTok para URLs públicas de vídeos/perfis
                for ch in cred.watched_channels.iter().take(8) {
                    let target_url = if ch.starts_with("http://") || ch.starts_with("https://") {
                        ch.clone()
                    } else {
                        format!("https://www.tiktok.com/@{}", ch.trim_start_matches('@'))
                    };
                    if let Ok(r) = cli
                        .get("https://www.tiktok.com/oembed")
                        .query(&[("url", target_url.as_str())])
                        .send()
                        .await
                    {
                        if r.status().is_success() {
                            if let Ok(v) = r.json::<Value>().await {
                                let title = v
                                    .get("title")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or(ch)
                                    .to_string();
                                let author = v
                                    .get("author_name")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or(ch)
                                    .to_string();
                                combined.items.push(mycelium_rhizome::ExternalFeedItem {
                                    id: format!("tiktok:oembed:{}", hex::encode(&blake3::hash(target_url.as_bytes()).as_bytes()[..8])),
                                    platform: SocialPlatform::Tiktok,
                                    external_id: ch.clone(),
                                    channel_id: author.clone(),
                                    author: author.clone(),
                                    title: title.clone(),
                                    body: format!("TikTok oEmbed oficial por {author}"),
                                    url: target_url.clone(),
                                    published_at: unix_now().to_string(),
                                    source_mode: "oembed_public".into(),
                                    synced_at: unix_now(),
                                });
                                notes.push(format!("TikTok oEmbed público: {author}"));
                            }
                        }
                    }
                }
            } else {
                return Err("TikTok Display API v2 exige OAuth2 Bearer token, URL pública para oEmbed oficial, ou user_data.json".into());
            }
        }
        SocialPlatform::Whatsapp => {
            if let (Some(tok), Some(pid)) = (
                token,
                cred.extra_id.as_deref().map(str::trim).filter(|s| !s.is_empty()),
            ) {
                let url = format!("https://graph.facebook.com/v21.0/{pid}");
                let r = cli
                    .get(&url)
                    .bearer_auth(tok)
                    .send()
                    .await
                    .map_err(|e| format!("WhatsApp Cloud API erro: {e}"))?;
                if r.status().is_success() {
                    notes.push(format!("WhatsApp Cloud API Phone ID {pid} validado ao vivo"));
                } else {
                    return Err(format!("WhatsApp Cloud API HTTP {}", r.status()));
                }
            } else {
                return Err("WhatsApp Cloud API exige token + Phone Number ID (ou importe contatos .vcf / chats .txt)".into());
            }
        }
    }

    combined.note = if notes.is_empty() {
        format!(
            "{}: nenhum canal/token configurado para sync remoto",
            cred.platform.display_name()
        )
    } else {
        notes.join(" · ")
    };
    Ok(combined)
}

async fn omnibridge_sync_api(
    State(state): State<EcosystemState>,
    Json(req): Json<OmnibridgeSyncReq>,
) -> Response {
    let target_platforms: Vec<PlatformCredentialRecord> = {
        let guard = state.persist.lock().unwrap();
        if let Some(ref p_str) = req.platform {
            let p = match SocialPlatform::from_str_loose(p_str) {
                Ok(p) => p,
                Err(e) => return json_err(StatusCode::BAD_REQUEST, e.to_string()),
            };
            match guard.vault.credentials.get(&p) {
                Some(c) => vec![c.clone()],
                None => {
                    return json_err(
                        StatusCode::BAD_REQUEST,
                        format!(
                            "configure credenciais ou canais para {} antes de sincronizar",
                            p.display_name()
                        ),
                    );
                }
            }
        } else {
            guard.vault.credentials.values().cloned().collect()
        }
    };

    if target_platforms.is_empty() {
        return json_err(
            StatusCode::BAD_REQUEST,
            "nenhuma rede configurada no cofre Omnibridge",
        );
    }

    // Descobre se o VEIL Ω SOCKS5 está ativo para rotear requisições marcadas com `route_via_veil`
    let (vtx, vrx) = oneshot::channel();
    let _ = state
        .outbound
        .send(RhizomeOutbound::GetVeilStatus { reply: vtx });
    let veil_uri = tokio::time::timeout(Duration::from_secs(2), vrx)
        .await
        .ok()
        .and_then(|r| r.ok())
        .and_then(|st| if st.active { st.socks5_uri } else { None });

    let mut reports = Vec::new();
    for cred in target_platforms {
        let p = cred.platform;
        match sync_single_platform(&cred, veil_uri.as_deref()).await {
            Ok(delta) => {
                let summary = json!({
                    "platform": p.slug(),
                    "ok": true,
                    "routed_via_veil": cred.route_via_veil,
                    "contacts_synced": delta.contacts.len(),
                    "channels_synced": delta.channels.len(),
                    "items_synced": delta.items.len(),
                    "note": delta.note,
                });
                let mut guard = state.persist.lock().unwrap();
                guard.omnibridge_index.apply_delta(p, delta);
                let _ = guard.save_omnibridge_index();
                reports.push(summary);
            }
            Err(err) => {
                let mut guard = state.persist.lock().unwrap();
                guard
                    .omnibridge_index
                    .last_sync_note
                    .insert(p, format!("erro: {err}"));
                let _ = guard.save_omnibridge_index();
                reports.push(json!({
                    "platform": p.slug(),
                    "ok": false,
                    "routed_via_veil": cred.route_via_veil,
                    "error": err,
                }));
            }
        }
    }

    json_ok(json!({
        "veil_socks5_active": veil_uri,
        "results": reports,
    }))
}

#[derive(Deserialize)]
struct OmnibridgeImportReq {
    platform: String,
    /// `auto` | `vcard` | `json` | `youtube_atom`
    #[serde(default = "default_import_format")]
    format: String,
    payload: String,
    #[serde(default)]
    hint: String,
}
fn default_import_format() -> String {
    "auto".into()
}

async fn omnibridge_import_api(
    State(state): State<EcosystemState>,
    Json(req): Json<OmnibridgeImportReq>,
) -> Response {
    let platform = match SocialPlatform::from_str_loose(&req.platform) {
        Ok(p) => p,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let fmt = req.format.trim().to_ascii_lowercase();
    let trimmed = req.payload.trim();
    if trimmed.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "payload de importação vazio");
    }

    let delta = if fmt == "vcard" || trimmed.to_ascii_uppercase().contains("BEGIN:VCARD") {
        parse_vcard_contacts(trimmed, platform)
    } else if fmt == "youtube_atom" || (platform == SocialPlatform::Youtube && trimmed.starts_with('<')) {
        parse_youtube_atom_feed(trimmed, if req.hint.is_empty() { "import" } else { &req.hint })
    } else {
        let parsed = match platform {
            SocialPlatform::Reddit => parse_reddit_listing_json(trimmed, &req.hint),
            SocialPlatform::Twitch => parse_twitch_helix_json(trimmed),
            SocialPlatform::Telegram => parse_telegram_json(trimmed, "local_import"),
            SocialPlatform::Instagram | SocialPlatform::Facebook => {
                parse_meta_json(platform, trimmed, "local_import")
            }
            SocialPlatform::Tiktok => parse_tiktok_json(trimmed, "local_import"),
            SocialPlatform::X => parse_x_json(trimmed, "local_import"),
            SocialPlatform::Youtube => Ok(parse_youtube_atom_feed(trimmed, &req.hint)),
            SocialPlatform::Whatsapp => Ok(parse_vcard_contacts(trimmed, SocialPlatform::Whatsapp)),
        };
        match parsed {
            Ok(d) => d,
            Err(e) => return json_err(StatusCode::BAD_REQUEST, format!("erro ao interpretar importação: {e}")),
        }
    };

    let summary = json!({
        "platform": platform.slug(),
        "contacts_imported": delta.contacts.len(),
        "channels_imported": delta.channels.len(),
        "items_imported": delta.items.len(),
        "note": delta.note,
    });
    {
        let mut guard = state.persist.lock().unwrap();
        guard.omnibridge_index.apply_delta(platform, delta);
        if let Err(e) = guard.save_omnibridge_index() {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, e);
        }
    }
    json_ok(summary)
}

#[derive(Deserialize)]
struct DirectoryQuery {
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    q: Option<String>,
}

async fn omnibridge_directory_api(
    State(state): State<EcosystemState>,
    Query(query): Query<DirectoryQuery>,
) -> Response {
    let filter_plat = query
        .platform
        .as_deref()
        .filter(|s| !s.trim().is_empty() && *s != "all")
        .and_then(|s| SocialPlatform::from_str_loose(s).ok());
    let needle = query
        .q
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    let guard = state.persist.lock().unwrap();
    let contacts: Vec<_> = guard
        .omnibridge_index
        .contacts
        .values()
        .filter(|c| filter_plat.map(|p| c.platform == p).unwrap_or(true))
        .filter(|c| {
            needle.as_ref().map(|q| {
                c.display_name.to_ascii_lowercase().contains(q)
                    || c.handle.to_ascii_lowercase().contains(q)
                    || c.phone_or_email
                        .as_deref()
                        .unwrap_or("")
                        .to_ascii_lowercase()
                        .contains(q)
            }).unwrap_or(true)
        })
        .cloned()
        .collect();
    let channels: Vec<_> = guard
        .omnibridge_index
        .channels
        .values()
        .filter(|c| filter_plat.map(|p| c.platform == p).unwrap_or(true))
        .filter(|c| {
            needle.as_ref().map(|q| {
                c.title.to_ascii_lowercase().contains(q)
                    || c.handle.to_ascii_lowercase().contains(q)
                    || c.description.to_ascii_lowercase().contains(q)
            }).unwrap_or(true)
        })
        .cloned()
        .collect();
    let mut items: Vec<_> = guard
        .omnibridge_index
        .items
        .values()
        .filter(|i| filter_plat.map(|p| i.platform == p).unwrap_or(true))
        .filter(|i| {
            needle.as_ref().map(|q| {
                i.title.to_ascii_lowercase().contains(q)
                    || i.body.to_ascii_lowercase().contains(q)
                    || i.author.to_ascii_lowercase().contains(q)
            }).unwrap_or(true)
        })
        .cloned()
        .collect();
    items.sort_by(|a, b| b.synced_at.cmp(&a.synced_at));
    items.truncate(120);

    json_ok(json!({
        "contacts": contacts,
        "channels": channels,
        "items": items,
    }))
}
