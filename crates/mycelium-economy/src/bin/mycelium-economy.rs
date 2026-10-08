use mycelium_economy::{
    autonomy::{
        AutonomyPayload, AutonomousEconomy, EconomicAgentManifest,
        EconomicPolicy, ExternalValueReceipt, OpportunityCandidate,
    },
    base_usdc::BaseUsdcVerifier,
    boundary::{BoundaryCrossing, ControlledAddressRegistry},
    chain_provider::ResolvedChainProvider,
    discovery::{
        AdapterRegistry, DiscoveryMachine, S1ShadowEvidenceAdapter,
        S1ShadowEvidenceConfig, SearchAttempt, SearchObservation, SearchPolicy,
        ThresholdAudit, SEARCH_MEMORY_FILE,
    },
    flash_arb_adapter::FlashArbConfig,
    mupp_adapter::{
        merge_reinvestment_signals, merge_scale_telemetry, read_mupp_gate,
        MuppAdapterPolicy,
    },
    now_unix, s1_adapter::import_shadow_scan,
    s1_perception_adapter::import_perception_report,
    policy_auth::{
        validate_outcome_policy, PinnedTrustStore, PolicyExpectations,
        ProviderIdentityConstraints, SignedOutcomePolicy,
        ValidatedOutcomePolicy, OUTCOME_POLICY_FILE,
    },
    reinvestment::{
        ReinvestmentController, ReinvestmentPolicy, ReinvestmentSignals,
    },
    s1_outcome::{
        init_policy as init_s1_outcome_policy,
        init_policy_with_provider as init_s1_outcome_policy_with_provider,
        load_policy as load_s1_outcome_policy,
        pin_policy_provider as pin_s1_outcome_provider,
        verify_reconciled_receipt_pinned as verify_s1_reconciled_receipt_pinned,
    },
    scaling::{decide_scale, ScalePolicy, ScaleTelemetry},
    stable_id,
    terr_research::{
        import_terr_snapshot, TerrResearchEngine, TerrResearchPolicy,
    },
    verifier_key_store::{
        load_bound_verifier_runtime_key, load_verifier_runtime_key, TrustRoot,
    },
    verified_view::{
        TrustMode, VerifiedEconomyView, VerifiedRevenueView,
    },
    JobRequest, JobType,
    LocalEconomy, SettlementAsset, SettlementMode, SettlementReceipt,
    WorkReceipt,
    SCHEMA_VERSION,
};
use mycelium_economy::{
    policy_auth::VerifierRuntimeKey,
    receipt_auth::AuthenticatedExternalValueReceipt,
    settlement_auth::AuthenticatedSettlementReceipt,
    LedgerRecord,
};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
};

/// The authority identity the read side executes, reported verbatim so an
/// operator can tell from the output which derivation produced a number.
const AUTHORITY_IDENTITY: &str =
    "VerifiedNev = VerifyChain(DeriveBoundary(VerifyReceiptSig(VerifyPolicy(Evidence))))";

/// How the CLI asked for the read side to be built.
///
/// Every economic command resolves this once and reports it, so an operator can
/// never mistake a number derived offline for one a chain read confirmed. There
/// is no flag to force the weak mode: with no provider pinned — or with no
/// validated outcome policy, which is P4b's requirement — the commands run in
/// `TrustMode::Unverified` and say so in their output.
struct EconomyViews<'a> {
    registry: ControlledAddressRegistry,
    mode: TrustMode,
    verifier: Option<BaseUsdcVerifier>,
    policy: Option<ValidatedOutcomePolicy>,
    /// Why the policy is or is not in force, for the trust report.
    policy_note: String,
    policy_path: PathBuf,
    /// Where the authenticated-policy layer's files live, and whether an
    /// operator relocated them out of the root-owned default.
    trust_root: TrustRoot,
    _marker: std::marker::PhantomData<&'a ()>,
}

/// Reads and validates the operator's signed outcome policy.
///
/// Returns `(None, note)` when there is nothing to validate — no document, no
/// usable trust anchor, or a document that does not validate — with the note
/// saying which. Never guesses and never degrades into a default policy: an
/// authority the process did not verify is not an authority, which is the whole
/// point of P4a.
fn load_outcome_policy(
    home: &Path,
    registry: &ControlledAddressRegistry,
    provider: Option<&ResolvedChainProvider>,
    trust_root: &TrustRoot,
) -> (Option<ValidatedOutcomePolicy>, String) {
    let path = home.join(OUTCOME_POLICY_FILE);
    let raw = match fs::read(&path) {
        Ok(raw) => raw,
        Err(_) => {
            return (
                None,
                format!(
                    "no signed outcome policy at {}; nothing on this economy can be \
                     attested",
                    path.display()
                ),
            )
        }
    };
    let signed: SignedOutcomePolicy = match serde_json::from_slice(&raw) {
        Ok(s) => s,
        Err(e) => {
            return (
                None,
                format!(
                    "signed outcome policy at {} cannot be parsed: {e}",
                    path.display()
                ),
            )
        }
    };
    // The pin is resolved through the trust root rather than hardcoded, so that
    // an operator who provisioned a trust root gets the pin they provisioned.
    // The filesystem checks are unchanged: same
    // `TrustStoreConfig` semantics, same two-stage identity check.
    let pin_path = trust_root.pin_path();
    let trust = match PinnedTrustStore::load(trust_root.trust_store_config()) {
        Ok(trust) => trust,
        Err(e) => {
            return (
                None,
                format!(
                    "no usable policy authority pin at {}: {e}{}",
                    pin_path.display(),
                    if trust_root.relocated() {
                        format!(
                            " (trust root relocated by {}; it must be owned by \
                             uid {})",
                            mycelium_economy::verifier_key_store::TRUST_ROOT_ENV,
                            trust_root.expected_owner_uid()
                        )
                    } else {
                        String::new()
                    }
                ),
            )
        }
    };
    let Some(provider) = provider else {
        return (
            None,
            "no chain provider is pinned, so no policy can be scoped to a provider \
             identity"
                .to_string(),
        );
    };
    if !provider.identity_kernel_enforced() {
        return (
            None,
            format!(
                "resolved provider {} has no kernel-enforced identity, so no \
                 outcome policy can be scoped to it",
                provider.as_pinned().endpoint()
            ),
        );
    }
    let constraints =
        ProviderIdentityConstraints::from_pinned_provider(provider.as_pinned());
    match validate_outcome_policy(
        &signed,
        &trust,
        PolicyExpectations {
            chain_id: mycelium_economy::base_usdc::BASE_CHAIN_ID,
            registry,
            provider: &constraints,
        },
    ) {
        Ok(policy) => {
            let note = format!(
                "validated outcome policy version {} against {}",
                policy.policy_version(),
                trust.pin_path().display()
            );
            (Some(policy), note)
        }
        Err(e) => (None, format!("signed outcome policy did not validate: {e}")),
    }
}

impl<'a> EconomyViews<'a> {
    fn resolve(econ: &LocalEconomy, home: &Path) -> Self {
        // The controlled set comes from the create-once payment policy, never
        // from the ledger and never from argv.
        let registry = match econ.payment_policy() {
            Ok(policy) => ControlledAddressRegistry::from_policy(&policy)
                .unwrap_or_default(),
            Err(_) => ControlledAddressRegistry::new(),
        };
        // Resolved once, for the pin and for the signing key, so the two can
        // never be configured to different trust roots.
        let trust_root = TrustRoot::resolve();
        // Same resolution order as every other chain read in the crate: the
        // dev-only environment override first, then the pin. The override yields
        // a verifier whose `provider_identity_verified` is false, so the view
        // below refuses to enter ProviderPinned mode with it.
        let provider = econ.chain_provider().ok();
        let verifier = provider
            .as_ref()
            .and_then(|provider| BaseUsdcVerifier::from_resolved(provider, 2).ok());
        // P4b: the policy is part of the mode, not an optional extra. A chain
        // read with no validated policy cannot check a receipt signature and
        // cannot compare a `policy_hash`, so it attests nothing and the commands
        // stay in the explicitly labelled offline mode.
        let (policy, policy_note) = load_outcome_policy(
            home,
            &registry,
            provider.as_ref(),
            &trust_root,
        );
        let mode = match (verifier.as_ref(), policy.as_ref()) {
            (Some(v), Some(_)) if v.provider_identity_verified() => {
                TrustMode::ProviderPinned
            }
            _ => TrustMode::Unverified,
        };
        Self {
            registry,
            mode,
            verifier,
            policy,
            policy_note,
            policy_path: home.join(OUTCOME_POLICY_FILE),
            trust_root,
            _marker: std::marker::PhantomData,
        }
    }

    fn autonomy<'v>(
        &'v self,
        autonomous: &'v AutonomousEconomy,
    ) -> Result<VerifiedEconomyView<'v>, String> {
        match (self.mode, self.verifier.as_ref(), self.policy.as_ref()) {
            (TrustMode::ProviderPinned, Some(verifier), Some(policy)) => {
                VerifiedEconomyView::provider_pinned(
                    autonomous,
                    &self.registry,
                    verifier,
                    policy,
                )
                .map_err(|e| e.to_string())
            }
            _ => Ok(VerifiedEconomyView::unverified(
                autonomous,
                &self.registry,
            )),
        }
    }

    fn revenue<'v>(
        &'v self,
        econ: &'v LocalEconomy,
    ) -> Result<VerifiedRevenueView<'v>, String> {
        match (self.mode, self.verifier.as_ref(), self.policy.as_ref()) {
            (TrustMode::ProviderPinned, Some(verifier), Some(policy)) => {
                VerifiedRevenueView::provider_pinned(
                    econ,
                    &self.registry,
                    verifier,
                    policy,
                )
                .map_err(|e| e.to_string())
            }
            _ => Ok(VerifiedRevenueView::unverified(
                econ,
                &self.registry,
            )),
        }
    }

    /// One object for the dashboard, so its two halves cannot disagree about
    /// which derivation produced them.
    fn trust_report(&self) -> serde_json::Value {
        serde_json::json!({
            "trust_mode": self.mode,
            "chain_provider": self.verifier.as_ref().map(|v| v.endpoint()),
            "provider_identity_verified": self
                .verifier
                .as_ref()
                .map(BaseUsdcVerifier::provider_identity_verified)
                .unwrap_or(false),
            "controlled_addresses": self.registry.len(),
            "outcome_policy": {
                "path": self.policy_path.display().to_string(),
                "validated": self.policy.is_some(),
                "note": self.policy_note,
                "policy_hash": self
                    .policy
                    .as_ref()
                    .and_then(|p| p.policy_hash().ok())
                    .map(|h| h.to_string()),
                "policy_version": self.policy.as_ref().map(|p| p.policy_version()),
                "verifier_key_id": self.policy.as_ref().map(|p| p.verifier_key_id().to_string()),
                "authority_key_id": self.policy.as_ref().map(|p| p.authority_key_id().to_string()),
            },
            "signing_key": self.signing_key_report(),
            "authority_identity": AUTHORITY_IDENTITY,
        })
    }

    /// What the signing side would need in order to sign, and what it found.
    ///
    /// Reported rather than merely implied, because "the signing key is at
    /// /etc/mycelium/trust/verifier-runtime.key and is not there" is a fact an
    /// operator needs before the first `settlement-attest`, and the answer
    /// changes as the trust root is relocated or a policy is rotated.
    fn signing_key_report(&self) -> serde_json::Value {
        let cfg = self.trust_root.key_store_config();
        let loaded = load_verifier_runtime_key(&cfg);
        let (key_id, error) = match &loaded {
            Ok(key) => (Some(key.key_id().to_string()), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let delegated = self.policy.as_ref().map(|p| p.verifier_key_id().to_string());
        serde_json::json!({
            "trust_root": self.trust_root.dir().display().to_string(),
            // A relocated trust root is a directory the invoking principal
            // controls, which is a weaker posture than the root-owned default.
            // It is stated here rather than left to be inferred from a path.
            "trust_root_relocated": self.trust_root.relocated(),
            "trust_root_env": mycelium_economy::verifier_key_store::TRUST_ROOT_ENV,
            "expected_owner_uid": self.trust_root.expected_owner_uid(),
            "policy_authority_pin": self.trust_root.pin_path().display().to_string(),
            "verifier_key_path": cfg.key_path().display().to_string(),
            "verifier_key_id": key_id,
            "policy_delegates_to": delegated,
            "bound_to_policy": matches!((&loaded, &delegated), (Ok(key), Some(d)) if key.key_id().to_string() == *d),
            "error": error,
            "note": "signing requires a validated outcome policy AND a verifier \
                     runtime key whose identity is the one that policy delegates \
                     to; either one alone refuses",
        })
    }

    /// The validated policy and the signing key it delegates to, or the typed
    /// refusal that says why there is not a pair.
    ///
    /// The fail-closed point for every command that signs. Both preconditions
    /// are checked here and neither is recoverable in-process: there is no
    /// policy, so no delegation to check against and no signing key this
    /// process is entitled to use; there is a policy but no usable key file, so
    /// there is nothing that could produce a signature the policy would accept.
    ///
    /// Returns the loaded key rather than just validating it so the call sites
    /// cannot accidentally sign with a *second*, differently-resolved load.
    fn signing_key(
        &self,
    ) -> Result<(&ValidatedOutcomePolicy, VerifierRuntimeKey), String> {
        let policy = self.policy.as_ref().ok_or_else(|| {
            format!(
                "refusing to sign: {} A validated outcome policy is required \
                 before this process will sign anything, and none is in force.",
                self.policy_note
            )
        })?;
        let key =
            load_bound_verifier_runtime_key(policy, &self.trust_root.key_store_config())
                .map_err(|e| format!("refusing to sign: {e}"))?;
        Ok((policy, key))
    }
}

fn usage() -> ! {
    eprintln!(
        "Usage:
  mycelium-economy --home DIR job-create TYPE REQUESTER INPUT_HASH MAX_MUSD INTERNAL DESCRIPTION
  mycelium-economy --home DIR work-verify JOB_ID WORKER RESULT_HASH UNITS VERIFIER
  mycelium-economy --home DIR work-verify-file JOB_ID WORKER ARTIFACT_PATH VERIFIER
  mycelium-economy --home DIR settle-sim JOB_ID ASSET AMOUNT_MUSD
  mycelium-economy --home DIR payment-policy-init PAYOUT_ADDRESS [MIN_CONFIRMATIONS] [PROVIDER_URI]
  mycelium-economy --home DIR payment-policy-pin-provider PROVIDER_URI [OWNER_UID]
  mycelium-economy --home DIR payment-policy-show
  mycelium-economy --home DIR outcome-policy-show
  mycelium-economy --home DIR payment-instructions JOB_ID
  mycelium-economy --home DIR rpc-check-base
  mycelium-economy --home DIR verify-base-usdc TX_HASH RECIPIENT AMOUNT_USDC
  mycelium-economy --home DIR settle-base-usdc JOB_ID TX_HASH
  mycelium-economy --home DIR settlement-attest SETTLEMENT_ID
  mycelium-economy --home DIR receipt-attest SOURCE_ID
  mycelium-economy --home DIR verifier-key-show
  mycelium-economy --home DIR revenue
  mycelium-economy --home DIR audit-ledger
  mycelium-economy --home DIR rv-status
  mycelium-economy --home DIR agent-register-json MANIFEST_JSON
  mycelium-economy --home DIR agent-list
  mycelium-economy --home DIR opportunity-submit-json OPPORTUNITY_JSON
  mycelium-economy --home DIR orchestrate OPPORTUNITY_ID MIN_NET_EDGE_MUSD
  mycelium-economy --home DIR external-value-candidate-json RECEIPT_JSON
  mycelium-economy --home DIR autonomy-status
  mycelium-economy --home DIR autonomy-audit
  mycelium-economy --home DIR arv-status
  mycelium-economy --home DIR s1-import-opportunities REPORT_JSON AGENT_ID JOB_COST_MUSD TTL_SECONDS
  mycelium-economy --home DIR s1-import-perception REPORT_JSON AGENT_ID JOB_COST_MUSD TTL_SECONDS
  mycelium-economy --home DIR s1-outcome-policy-init EXECUTOR [MIN_CONFIRMATIONS] [PROVIDER_URI]
  mycelium-economy --home DIR s1-outcome-policy-pin-provider PROVIDER_URI [OWNER_UID]
  mycelium-economy --home DIR s1-outcome-policy-show
  mycelium-economy --home DIR s1-reconcile-outcome RECEIPT_JSON AGENT_ID OPPORTUNITY_ID
  mycelium-economy --home DIR terr-import-research SNAPSHOT_JSON AGENT_ID JOB_TYPE JOB_COST_MUSD TTL_SECONDS
  mycelium-economy --home DIR terr-orchestrate HINT_ID AGENT_ID MIN_TRANSITION MAX_UNCERTAINTY MIN_ABS_SCORE
  mycelium-economy --home DIR terr-status
  mycelium-economy --home DIR terr-audit
  mycelium-economy --home DIR reinvestment-decision SIGNALS_JSON [POLICY_JSON]
  mycelium-economy --home DIR reinvestment-commit JOB_INTENT_ID AGENT_ID SIGNALS_JSON [POLICY_JSON]
  mycelium-economy --home DIR reinvestment-status
  mycelium-economy --home DIR economy-dashboard
  mycelium-economy --home DIR scale-decision TELEMETRY_JSON [POLICY_JSON]
  mycelium-economy --home DIR mupp-gate STATE_JSON [MUPP_POLICY_JSON]
  mycelium-economy --home DIR reinvestment-decision-mupp SIGNALS_JSON MUPP_STATE [REINVEST_POLICY_JSON] [MUPP_POLICY_JSON]
  mycelium-economy --home DIR scale-decision-mupp TELEMETRY_JSON MUPP_STATE [SCALE_POLICY_JSON] [MUPP_POLICY_JSON]
  mycelium-economy --home DIR discovery-run SOURCE_JSON AGENT_ID JOB_COST_MUSD TTL_SECONDS MUPP_STATE [POLICY_JSON] [MUPP_POLICY_JSON]
  mycelium-economy --home DIR discovery-observe OBSERVATION_JSON MUPP_STATE [POLICY_JSON] [MUPP_POLICY_JSON]
  mycelium-economy --home DIR discovery-status [POLICY_JSON]
  mycelium-economy --home DIR discovery-validate-policy MIN_NET_EDGE_MUSD [POLICY_JSON]"
    );
    process::exit(2)
}

/// The RPC endpoint used to be a positional argument on every chain command.
/// It is gone: a caller who chooses the endpoint chooses the source of truth,
/// and a loopback TCP port is not an identity. Operators pin the provider
/// out-of-band instead (`payment-policy-pin-provider`, or
/// `payment-policy-init ... PROVIDER_URI`).
const RPC_ARG_REMOVED: &str =
    "this command no longer accepts an RPC endpoint as a positional argument; \
     a caller must not choose the chain data source. Pin a provider with \
     `mycelium-economy --home DIR payment-policy-pin-provider unix:///run/mycelium-verifier.sock`, \
     or set MYCELIUM_DEV_BASE_PROVIDER for tests only";

/// Parses an optional provider URI plus optional socket owner UID.
fn parse_provider(
    uri: &str,
    owner_uid: Option<&String>,
) -> Result<mycelium_economy::chain_provider::PinnedChainProvider, String> {
    let uid = match owner_uid {
        None => None,
        Some(raw) => Some(raw.parse::<u32>().map_err(|_| {
            format!("socket owner uid must be an integer: {raw}")
        })?),
    };
    mycelium_economy::chain_provider::PinnedChainProvider::parse(uri, uid)
        .map_err(|e| e.to_string())
}

fn micros(s: &str) -> u64 {
    let v: f64 = s.parse().unwrap_or_else(|_| usage());
    if !v.is_finite() || v < 0.0 {
        usage();
    }
    (v * 1_000_000.0).round() as u64
}

fn job_type(s: &str) -> JobType {
    match s {
        "compute" => JobType::Compute,
        "storage" => JobType::Storage,
        "bandwidth" => JobType::Bandwidth,
        "build" => JobType::Build,
        "replication" => JobType::Replication,
        "simulation" => JobType::Simulation,
        "quote" => JobType::Quote,
        "backtest" => JobType::Backtest,
        "inference" => JobType::Inference,
        "data_transform" => JobType::DataTransform,
        "validation" => JobType::Validation,
        _ => usage(),
    }
}

fn unit_interval(s: &str) -> f64 {
    let v: f64 = s.parse().unwrap_or_else(|_| usage());
    if !v.is_finite() || !(0.0..=1.0).contains(&v) {
        usage();
    }
    v
}

fn main() {
    let mut a = env::args().skip(1).collect::<Vec<_>>();
    if a.len() < 3 || a[0] != "--home" {
        usage();
    }
    let home = PathBuf::from(a.remove(1));
    a.remove(0);
    let command = a.remove(0);

    let econ = LocalEconomy::open(&home).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        process::exit(1)
    });
    let autonomous = AutonomousEconomy::open(&home).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        process::exit(1)
    });
    let terr_research = TerrResearchEngine::open(&home).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        process::exit(1)
    });
    let reinvestment = ReinvestmentController::open(&home).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        process::exit(1)
    });
    // Resolved once, for every economic command below. The provider is never an
    // argument: with none pinned the commands degrade to an explicitly labelled
    // offline view instead of silently reporting an attested number.
    let views = EconomyViews::resolve(&econ, &home);

    let result: Result<serde_json::Value, String> = match command.as_str() {
        "job-create" if a.len() == 6 => {
            let now = now_unix();
            let jt = job_type(&a[0]);
            let internal = match a[4].as_str() {
                "true" => true,
                "false" => false,
                _ => usage(),
            };
            let id = stable_id(
                "job",
                &[&a[1], &a[2], &now.to_string(), &a[5]],
            );
            econ.append_job(JobRequest {
                schema_version: SCHEMA_VERSION,
                job_id: id,
                created_at_unix: now,
                requester_id: a[1].clone(),
                job_type: jt,
                input_hash: a[2].clone(),
                max_price_musd_micros: micros(&a[3]),
                internal_work: internal,
                description: a[5].clone(),
            })
            .map(|v| serde_json::to_value(v).unwrap())
            .map_err(|e| e.to_string())
        }
        "work-verify" if a.len() == 5 => {
            let now = now_unix();
            let id = stable_id(
                "work",
                &[&a[0], &a[1], &a[2], &now.to_string()],
            );
            econ.append_work(WorkReceipt {
                schema_version: SCHEMA_VERSION,
                receipt_id: id,
                job_id: a[0].clone(),
                worker_id: a[1].clone(),
                started_at_unix: now.saturating_sub(1),
                completed_at_unix: now,
                result_hash: a[2].clone(),
                useful_work_units: a[3].parse().unwrap_or_else(|_| usage()),
                verifier_id: a[4].clone(),
                verified_at_unix: now,
                verified: true,
            })
            .map(|v| serde_json::to_value(v).unwrap())
            .map_err(|e| e.to_string())
        }
        "work-verify-file" if a.len() == 4 => {
            let now = now_unix();
            let artifact = PathBuf::from(&a[2]);
            let meta = fs::metadata(&artifact)
                .map_err(|e| format!("artifact metadata: {e}"));
            match meta {
                Err(e) => Err(e),
                Ok(meta) if !meta.is_file() => Err("artifact must be a regular file".into()),
                Ok(meta) if meta.len() == 0 => Err("artifact must not be empty".into()),
                Ok(meta) => {
                    let bytes = fs::read(&artifact)
                        .map_err(|e| format!("artifact read: {e}"));
                    match bytes {
                        Err(e) => Err(e),
                        Ok(bytes) => {
                            let result_hash = format!("blake3:{}", blake3::hash(&bytes).to_hex());
                            let id = stable_id(
                                "work",
                                &[&a[0], &a[1], &result_hash, &now.to_string()],
                            );
                            econ.append_work(WorkReceipt {
                                schema_version: SCHEMA_VERSION,
                                receipt_id: id,
                                job_id: a[0].clone(),
                                worker_id: a[1].clone(),
                                started_at_unix: now.saturating_sub(1),
                                completed_at_unix: now,
                                result_hash,
                                useful_work_units: meta.len(),
                                verifier_id: a[3].clone(),
                                verified_at_unix: now,
                                verified: true,
                            })
                            .map(|v| serde_json::to_value(v).unwrap())
                            .map_err(|e| e.to_string())
                        }
                    }
                }
            }
        }
        "settle-sim" if a.len() == 3 => settle(&econ, &a, SettlementMode::Simulated, None),
        "payment-policy-init" if a.len() <= 3 => {
            let confirmations = a
                .get(1)
                .map(|v| v.parse::<u64>().unwrap_or_else(|_| usage()))
                .unwrap_or(2);
            match a.get(2) {
                None => econ
                    .init_payment_policy(&a[0], confirmations)
                    .map(|v| serde_json::to_value(v).unwrap())
                    .map_err(|e| e.to_string()),
                Some(uri) => match parse_provider(uri, None) {
                    Err(e) => Err(e),
                    Ok(provider) => econ
                        .init_payment_policy_with_provider(
                            &a[0],
                            confirmations,
                            Some(&provider),
                        )
                        .map(|v| serde_json::to_value(v).unwrap())
                        .map_err(|e| e.to_string()),
                },
            }
        }
        "payment-policy-pin-provider" if a.len() == 1 || a.len() == 2 => {
            match parse_provider(&a[0], a.get(1)) {
                Err(e) => Err(e),
                Ok(provider) => econ
                    .pin_chain_provider(&provider)
                    .map(|v| serde_json::to_value(v).unwrap())
                    .map_err(|e| e.to_string()),
            }
        }
        "payment-policy-show" if a.is_empty() => econ
            .payment_policy()
            .map(|v| serde_json::to_value(v).unwrap())
            .map_err(|e| e.to_string()),
        // P4b. Reports whether the operator's signed outcome policy is in force
        // and, if not, why not. Deliberately reports rather than repairs: this
        // binary holds no authority private key, so it cannot sign one, and it
        // has no business guessing a substitute.
        "outcome-policy-show" if a.is_empty() => {
            Ok(views.trust_report()["outcome_policy"].clone())
        }
        "payment-instructions" if a.len() == 2 => {
            Err(RPC_ARG_REMOVED.to_string())
        }
        "payment-instructions" if a.len() == 1 => {
            payment_instructions(&econ, &a[0])
        }
        "rpc-check-base" if a.len() == 1 => Err(RPC_ARG_REMOVED.to_string()),
        "rpc-check-base" if a.is_empty() => {
            pinned_verifier(&econ, 2).and_then(|v| {
                v.health().map_err(|e| e.to_string())
            })
        }
        "verify-base-usdc" if a.len() == 4 => {
            Err(RPC_ARG_REMOVED.to_string())
        }
        "verify-base-usdc" if a.len() == 3 => {
            let amount = micros(&a[2]);
            pinned_verifier(&econ, 2).and_then(|v| {
                v.verify_transfer(&a[0], &a[1], amount)
                    .map(|proof| serde_json::to_value(proof).unwrap())
                    .map_err(|e| e.to_string())
            })
        }
        "settle-base-usdc" if a.len() == 3 => {
            Err(RPC_ARG_REMOVED.to_string())
        }
        "settle-base-usdc" if a.len() == 2 => {
            settle_base_usdc(&econ, &views, &a)
        }
        // The second half of settling, and deliberately a separate command.
        // `settle-base-usdc` verifies a transfer over a provider pinned
        // out-of-band and appends a settlement; this one signs that settlement
        // with the key a validated policy delegates to. Keeping them apart is
        // what makes "verified but not yet signed" a state the ledger can
        // actually be in, with its own record and its own timestamp in its own
        // hash-chained file — see `settle_base_usdc`'s doc comment.
        "settlement-attest" if a.len() == 1 => {
            attest_settlement(&econ, &views, &a[0])
        }
        // The autonomy-side equivalent. Same two halves, same separation: the
        // receipt is submitted and recorded first, and only a later, explicit
        // command turns it into an attestation.
        "receipt-attest" if a.len() == 1 => {
            attest_receipt(&autonomous, &views, &a[0])
        }
        // Read-only. Reports which key would sign, without signing and without
        // printing a secret byte.
        "verifier-key-show" if a.is_empty() => {
            Ok(views.trust_report()["signing_key"].clone())
        }
        "audit-ledger" if a.is_empty() => econ
            .audit_ledger()
            .map(|v| serde_json::to_value(v).unwrap())
            .map_err(|e| e.to_string()),
        "revenue" if a.is_empty() => views.revenue(&econ).and_then(|view| {
            view.revenue_summary()
                .map(|mut v| {
                    v.attestation_note = format!(
                        "{} trust={}",
                        v.attestation_note,
                        views.trust_report()
                    );
                    serde_json::to_value(v).unwrap()
                })
                .map_err(|e| e.to_string())
        }),
        "rv-status" if a.is_empty() => views.revenue(&econ).and_then(|view| {
            view.rv_status(now_unix())
                .map(|mut v| {
                    v.attestation_note = format!(
                        "{} trust={}",
                        v.attestation_note,
                        views.trust_report()
                    );
                    serde_json::to_value(v).unwrap()
                })
                .map_err(|e| e.to_string())
        }),
        "agent-register-json" if a.len() == 1 => read_json::<EconomicAgentManifest>(&a[0])
            .and_then(|manifest| autonomous
                .register_agent(manifest)
                .map_err(|e| e.to_string()))
            .map(|v| serde_json::to_value(v).unwrap()),
        "agent-list" if a.is_empty() => autonomous
            .agents()
            .map(|v| serde_json::to_value(v).unwrap())
            .map_err(|e| e.to_string()),
        "opportunity-submit-json" if a.len() == 1 => read_json::<OpportunityCandidate>(&a[0])
            .and_then(|opportunity| autonomous
                .submit_opportunity(opportunity)
                .map_err(|e| e.to_string()))
            .map(|v| serde_json::to_value(v).unwrap()),
        "orchestrate" if a.len() == 2 => {
            let min_edge = micros(&a[1]);
            match autonomous.orchestrate(
                &a[0],
                &EconomicPolicy {
                    min_net_edge_musd_micros: min_edge,
                    ..EconomicPolicy::default()
                },
                now_unix(),
            ) {
                Err(e) => Err(e.to_string()),
                Ok(out) => {
                    let materialize_result: Result<(bool, Option<JobRequest>), String> =
                        match out.job_request_template.clone() {
                            None => Ok((false, None)),
                            Some(template) => match econ.job(&template.job_id) {
                                Err(e) => Err(e.to_string()),
                                Ok(Some(existing)) => Ok((false, Some(existing))),
                                Ok(None) => econ
                                    .append_job(template)
                                    .map(|created| (true, Some(created)))
                                    .map_err(|e| e.to_string()),
                            },
                        };
                    match materialize_result {
                        Err(e) => Err(e),
                        Ok((materialized, job)) => Ok(serde_json::json!({
                            "decision": out.decision,
                            "job_intent": out.job_intent,
                            "job_request": job,
                            "job_materialized": materialized
                        })),
                    }
                }
            }
        }
        "external-value-candidate-json" if a.len() == 1 => {
            read_json::<ExternalValueReceipt>(&a[0]).and_then(|mut receipt| {
                // User/bot submitted data is evidence-candidate only.
                // It can never self-assert verification through this CLI.
                receipt.proof_verified = false;
                receipt.verifier_id.clear();
                autonomous
                    .record_external_value(receipt)
                    .map_err(|e| e.to_string())
                    .map(|v| serde_json::to_value(v).unwrap())
            })
        }
        "autonomy-status" if a.is_empty() => views.autonomy(&autonomous).and_then(|view| {
            view.autonomy_summary()
                .map(|mut v| {
                    v.attestation_note = format!(
                        "{} trust={}",
                        v.attestation_note,
                        views.trust_report()
                    );
                    serde_json::to_value(v).unwrap()
                })
                .map_err(|e| e.to_string())
        }),
        "autonomy-audit" if a.is_empty() => autonomous
            .records()
            .map(|records| {
                let head = records
                    .last()
                    .map(|r| r.record_hash.clone())
                    .unwrap_or_else(|| mycelium_economy::autonomy::AUTONOMY_GENESIS_HASH.to_string());
                let stored_claims = records
                    .iter()
                    .filter(|r| {
                        matches!(
                            r.payload,
                            mycelium_economy::autonomy::AutonomyPayload::ExternalValue {
                                ..
                            }
                        )
                    })
                    .count();
                serde_json::json!({
                    "valid": true,
                    "records": records.len(),
                    "head_hash": head,
                    "ledger_path": autonomous.ledger_path(),
                    // Diagnostics only: how many receipts still carry the
                    // pre-P3 `proof_verified: true` claim. No economic path
                    // reads it; the view re-derives instead.
                    "stored_proof_verified_claims": stored_claims,
                    "note": "proof_verified is a stored claim, not an authority input; \
                             TrustedNEV = VerifyChain(VerifyPolicy(DeriveBoundary(Evidence)))"
                })
            })
            .map_err(|e| e.to_string()),
        "arv-status" if a.is_empty() => views.autonomy(&autonomous).and_then(|view| {
            view.arv_status(now_unix())
                .map(|mut v| {
                    v.attestation_note = format!(
                        "{} trust={}",
                        v.attestation_note,
                        views.trust_report()
                    );
                    serde_json::to_value(v).unwrap()
                })
                .map_err(|e| e.to_string())
        }),
        "s1-outcome-policy-init" if a.len() <= 3 => {
            let confirmations = a
                .get(1)
                .map(|v| v.parse::<u64>().unwrap_or_else(|_| usage()))
                .unwrap_or(2);
            match a.get(2) {
                None => init_s1_outcome_policy(&home, &a[0], confirmations)
                    .map(|v| serde_json::to_value(v).unwrap())
                    .map_err(|e| e.to_string()),
                Some(uri) => match parse_provider(uri, None) {
                    Err(e) => Err(e),
                    Ok(provider) => init_s1_outcome_policy_with_provider(
                        &home,
                        &a[0],
                        confirmations,
                        Some(&provider),
                    )
                    .map(|v| serde_json::to_value(v).unwrap())
                    .map_err(|e| e.to_string()),
                },
            }
        }
        "s1-outcome-policy-pin-provider" if a.len() == 1 || a.len() == 2 => {
            match parse_provider(&a[0], a.get(1)) {
                Err(e) => Err(e),
                Ok(provider) => pin_s1_outcome_provider(&home, &provider)
                    .map(|v| serde_json::to_value(v).unwrap())
                    .map_err(|e| e.to_string()),
            }
        }
        "s1-outcome-policy-show" if a.is_empty() => {
            load_s1_outcome_policy(&home)
                .map(|v| serde_json::to_value(v).unwrap())
                .map_err(|e| e.to_string())
        }
        "s1-reconcile-outcome" if a.len() == 4 => {
            Err(RPC_ARG_REMOVED.to_string())
        }
        "s1-reconcile-outcome" if a.len() == 3 => {
            match load_s1_outcome_policy(&home) {
                Err(e) => Err(e.to_string()),
                Ok(policy) => match verify_s1_reconciled_receipt_pinned(
                    &a[0], &a[1], &a[2], &policy
                ) {
                    Err(e) => Err(e.to_string()),
                    Ok(verified) => {
                        // The typed path: evidence is recorded, the crossing is
                        // derived from it against the operator's registry, the
                        // pinned proof is bound to that crossing, and only then
                        // does the receipt enter the ledger. This is what makes
                        // the booked value re-derivable on read instead of a
                        // claim.
                        let booked = (|| -> Result<_, String> {
                            let crossing = BoundaryCrossing::derive(
                                &verified.boundary_evidence,
                                &views.registry,
                            )
                            .map_err(|e| e.to_string())?
                            .with_verified_proof(verified.payment_proof.clone())
                            .map_err(|e| e.to_string())?;
                            autonomous
                                .record_boundary_crossing(
                                    &verified.boundary_evidence,
                                    &views.registry,
                                )
                                .map_err(|e| e.to_string())?;
                            let booked = autonomous
                                .record_external_value_with_crossing(
                                    verified.external_value.clone(),
                                    &crossing,
                                )
                                .map_err(|e| e.to_string())?;
                            Ok(booked)
                        })();
                        match booked {
                            Err(e) => Err(e),
                            Ok(booked) => match views.autonomy(&autonomous) {
                                Err(e) => Err(e),
                                Ok(view) => match view.arv_status(now_unix()) {
                                    Err(e) => Err(e.to_string()),
                                    Ok(arv) => Ok(serde_json::json!({
                                        "verified_outcome": verified,
                                        "external_value_booked": booked,
                                        "arv": arv
                                    })),
                                },
                            },
                        }
                    }
                }
            }
        }
        "s1-import-opportunities" if a.len() == 4 => {
            let now = now_unix();
            let ttl = a[3].parse::<u64>().unwrap_or_else(|_| usage());
            match import_shadow_scan(
                &a[0],
                &a[1],
                micros(&a[2]),
                now,
                ttl,
            ) {
                Err(e) => Err(e.to_string()),
                Ok(report) => {
                    let mut imported = Vec::new();
                    let mut error: Option<String> = None;
                    for opportunity in report.opportunities.iter().cloned() {
                        match autonomous.submit_opportunity(opportunity) {
                            Ok(v) => imported.push(v),
                            Err(e) => {
                                error = Some(e.to_string());
                                break;
                            }
                        }
                    }
                    match error {
                        Some(e) => Err(e),
                        None => Ok(serde_json::json!({
                            "source_path": report.source_path,
                            "source_hash": report.source_hash,
                            "imported": imported.len(),
                            "opportunities": imported,
                            "profit_is_real": false,
                            "external_value_booked": false
                        })),
                    }
                }
            }
        }
        "s1-import-perception" if a.len() == 4 => {
            let ttl = a[3].parse::<u64>().unwrap_or_else(|_| usage());
            match import_perception_report(
                &a[0],
                &a[1],
                micros(&a[2]),
                ttl,
            ) {
                Err(e) => Err(e.to_string()),
                Ok(report) => {
                    let mut imported = Vec::new();
                    let mut error: Option<String> = None;
                    for opportunity in report.opportunities.iter().cloned() {
                        match autonomous.submit_opportunity(opportunity) {
                            Ok(v) => imported.push(v),
                            Err(e) => {
                                error = Some(e.to_string());
                                break;
                            }
                        }
                    }
                    match error {
                        Some(e) => Err(e),
                        None => Ok(serde_json::json!({
                            "source_path": report.source_path,
                            "source_hash": report.source_hash,
                            "status": report.status,
                            "cycles_requested": report.cycles_requested,
                            "cycles_completed": report.cycles_completed,
                            "candidates_seen": report.candidates_seen,
                            "imported": imported.len(),
                            "best_observed_token_edge_usdc_raw":
                                report.best_observed_token_edge_usdc_raw,
                            "best_observed_robust_net_usdc_raw":
                                report.best_observed_robust_net_usdc_raw,
                            "thermal_start_max_c": report.thermal_start_max_c,
                            "end_temp_c": report.end_temp_c,
                            "broadcast": report.broadcast,
                            "anvil": report.anvil,
                            "profit_is_real": false,
                            "external_value_booked": false,
                            "opportunities": imported
                        })),
                    }
                }
            }
        }
        "terr-import-research" if a.len() == 5 => {
            let ttl = a[4].parse::<u64>().unwrap_or_else(|_| usage());
            match import_terr_snapshot(
                &a[0],
                &a[1],
                job_type(&a[2]),
                micros(&a[3]),
                ttl,
            ) {
                Err(e) => Err(e.to_string()),
                Ok(hint) => terr_research
                    .record_hint(hint)
                    .map(|v| serde_json::to_value(v).unwrap())
                    .map_err(|e| e.to_string()),
            }
        }
        "terr-orchestrate" if a.len() == 5 => {
            match autonomous.agent(&a[1]) {
                Err(e) => Err(e.to_string()),
                Ok(None) => Err(format!("agent not found: {}", a[1])),
                Ok(Some(agent)) => {
                    let policy = TerrResearchPolicy {
                        min_transition_probability: unit_interval(&a[2]),
                        max_uncertainty: unit_interval(&a[3]),
                        min_abs_terr_score: unit_interval(&a[4]),
                    };
                    match terr_research.orchestrate(
                        &a[0],
                        &agent,
                        &policy,
                        now_unix(),
                    ) {
                        Err(e) => Err(e.to_string()),
                        Ok(plan) => {
                            let materialize_result: Result<(bool, Option<JobRequest>), String> =
                                match plan.job_request_template.clone() {
                                    None => Ok((false, None)),
                                    Some(template) => match econ.job(&template.job_id) {
                                        Err(e) => Err(e.to_string()),
                                        Ok(Some(existing)) => Ok((false, Some(existing))),
                                        Ok(None) => econ
                                            .append_job(template)
                                            .map(|created| (true, Some(created)))
                                            .map_err(|e| e.to_string()),
                                    },
                                };
                            match materialize_result {
                                Err(e) => Err(e),
                                Ok((materialized, job)) => Ok(serde_json::json!({
                                    "decision": plan.decision,
                                    "job_intent": plan.job_intent,
                                    "job_request": job,
                                    "job_materialized": materialized,
                                    "capital_authorized": false,
                                    "external_value_booked": false
                                })),
                            }
                        }
                    }
                }
            }
        }
        "terr-status" if a.is_empty() => terr_research
            .summary()
            .map(|v| serde_json::to_value(v).unwrap())
            .map_err(|e| e.to_string()),
        "terr-audit" if a.is_empty() => terr_research
            .summary()
            .map(|v| serde_json::json!({
                "valid": v.ledger_valid,
                "head_hash": v.head_hash,
                "ledger_path": terr_research.ledger_path(),
                "hints": v.hints,
                "job_plans": v.job_plans
            }))
            .map_err(|e| e.to_string()),
        "reinvestment-decision" if a.len() == 1 || a.len() == 2 => {
            match read_json::<ReinvestmentSignals>(&a[0]) {
                Err(e) => Err(e),
                Ok(signals) => {
                    let policy_result: Result<ReinvestmentPolicy, String> =
                        if let Some(path) = a.get(1) {
                            read_json(path)
                        } else {
                            Ok(ReinvestmentPolicy::default())
                        };
                    match policy_result {
                        Err(e) => Err(e),
                        Ok(policy) => views
                            .autonomy(&autonomous)
                            .and_then(|view| {
                                reinvestment
                                    .decide_from_view(
                                        &view,
                                        &signals,
                                        &policy,
                                        now_unix(),
                                    )
                                    .map_err(|e| e.to_string())
                            })
                            .map(|v| serde_json::to_value(v).unwrap()),
                    }
                }
            }
        }
        "reinvestment-commit" if a.len() == 3 || a.len() == 4 => {
            let job_intent_id = &a[0];
            let agent_id = &a[1];
            let signals_result = read_json::<ReinvestmentSignals>(&a[2]);
            let policy_result: Result<ReinvestmentPolicy, String> =
                if let Some(path) = a.get(3) {
                    read_json(path)
                } else {
                    Ok(ReinvestmentPolicy::default())
                };
            match (signals_result, policy_result) {
                (Err(e), _) | (_, Err(e)) => Err(e),
                (Ok(signals), Ok(policy)) => {
                    let job = autonomous
                        .job_intents()
                        .map_err(|e| e.to_string())
                        .and_then(|jobs| {
                            jobs.into_iter()
                                .find(|j| j.job_intent_id == *job_intent_id)
                                .ok_or_else(|| format!(
                                    "job intent not found: {job_intent_id}"
                                ))
                        });
                    let agent = autonomous
                        .agent(agent_id)
                        .map_err(|e| e.to_string())
                        .and_then(|v| v.ok_or_else(|| format!(
                            "agent not found: {agent_id}"
                        )));
                    match (job, agent) {
                (Err(e), _) | (_, Err(e)) => Err(e.clone()),
                        (Ok(job), Ok(agent)) => views
                            .autonomy(&autonomous)
                            .and_then(|view| {
                                reinvestment
                                    .commit_job_from_view(
                                        &view,
                                        &agent,
                                        &job,
                                        &signals,
                                        &policy,
                                        now_unix(),
                                    )
                                    .map_err(|e| e.to_string())
                            })
                            .map(|v| serde_json::to_value(v).unwrap()),
                    }
                }
            }
        }
        "reinvestment-status" if a.is_empty() => reinvestment
            .status(now_unix())
            .map(|v| serde_json::to_value(v).unwrap())
            .map_err(|e| e.to_string()),
        "economy-dashboard" if a.is_empty() => {
            let now = now_unix();
            let autonomy_view = views.autonomy(&autonomous);
            let revenue_view = views.revenue(&econ);
            match (
                &autonomy_view,
                &revenue_view,
            ) {
                (Ok(autonomy), Ok(revenue)) => {
                    match (
                        revenue.revenue_summary(),
                        revenue.rv_status(now),
                        autonomy.autonomy_summary(),
                        autonomy.arv_status(now),
                        terr_research.summary(),
                        reinvestment.status(now),
                    ) {
                        (
                            Ok(revenue),
                            Ok(rv),
                            Ok(autonomy_summary),
                            Ok(arv),
                            Ok(terr),
                            Ok(reinvest),
                        ) => Ok(serde_json::json!({
                            "timestamp_unix": now,
                            "trust": views.trust_report(),
                            "revenue_validation": {
                                "paid_demand_musd": revenue.paid_demand_musd(),
                                "unattested_paid_demand_musd": revenue
                                    .unattested_paid_demand_musd_micros as f64
                                    / 1_000_000.0,
                                "external_paid_jobs": revenue.external_paid_jobs,
                                "rv": rv
                            },
                            "autonomous_economy": {
                                "summary": autonomy_summary,
                                "arv": arv
                            },
                            "terr_research": terr,
                            "reinvestment": reinvest,
                            "invariants": {
                                "internal_volume_is_revenue": false,
                                "myc_emission_is_revenue": false,
                                "bot_service_spend_is_external_value": false,
                                "terr_can_authorize_capital": false,
                                "stored_proof_verified_is_authority": false
                            }
                        })),
                        _ => Err(
                            "economy dashboard could not validate one or more ledgers"
                                .into(),
                        ),
                    }
                }
                (Err(e), _) | (_, Err(e)) => Err(e.clone()),
            }
        }
        "scale-decision" if a.len() == 1 || a.len() == 2 => {
            match read_json::<ScaleTelemetry>(&a[0]) {
                Err(e) => Err(e),
                Ok(telemetry) => {
                    let policy_result: Result<ScalePolicy, String> =
                        if let Some(path) = a.get(1) {
                            read_json(path)
                        } else {
                            Ok(ScalePolicy::default())
                        };
                    match policy_result {
                        Err(e) => Err(e),
                        Ok(policy) => decide_scale(&telemetry, &policy)
                            .map(|v| serde_json::to_value(v).unwrap())
                            .map_err(|e| e.to_string()),
                    }
                }
            }
        }
        "mupp-gate" if a.len() == 1 || a.len() == 2 => {
            let policy_result: Result<MuppAdapterPolicy, String> =
                if let Some(path) = a.get(1) {
                    read_json(path)
                } else {
                    Ok(MuppAdapterPolicy::default())
                };
            match policy_result {
                Err(e) => Err(e),
                Ok(policy) => read_mupp_gate(
                    &a[0],
                    now_unix() as f64,
                    &policy,
                )
                .map(|v| serde_json::to_value(v).unwrap())
                .map_err(|e| e.to_string()),
            }
        }
        "reinvestment-decision-mupp" if a.len() >= 2 && a.len() <= 4 => {
            let signals_result = read_json::<ReinvestmentSignals>(&a[0]);
            let reinvest_policy_result: Result<ReinvestmentPolicy, String> =
                if let Some(path) = a.get(2) {
                    read_json(path)
                } else {
                    Ok(ReinvestmentPolicy::default())
                };
            let mupp_policy_result: Result<MuppAdapterPolicy, String> =
                if let Some(path) = a.get(3) {
                    read_json(path)
                } else {
                    Ok(MuppAdapterPolicy::default())
                };
            match (signals_result, reinvest_policy_result, mupp_policy_result) {
                (Ok(signals), Ok(policy), Ok(mupp_policy)) => {
                    match read_mupp_gate(
                        &a[1],
                        now_unix() as f64,
                        &mupp_policy,
                    ) {
                        Err(e) => Err(e.to_string()),
                        Ok(gate) => {
                            let merged = merge_reinvestment_signals(signals, &gate);
                            match views.autonomy(&autonomous) {
                                Err(e) => Err(e),
                                Ok(view) => {
                                    match reinvestment.decide_from_view(
                                        &view,
                                        &merged,
                                        &policy,
                                        now_unix(),
                                    ) {
                                        Err(e) => Err(e.to_string()),
                                        Ok(decision) => Ok(serde_json::json!({
                                            "mupp": gate,
                                            "merged_signals": merged,
                                            "decision": decision
                                        })),
                                    }
                                }
                            }
                        }
                    }
                }
                (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => Err(e),
            }
        }
        "scale-decision-mupp" if a.len() >= 2 && a.len() <= 4 => {
            let telemetry_result = read_json::<ScaleTelemetry>(&a[0]);
            let scale_policy_result: Result<ScalePolicy, String> =
                if let Some(path) = a.get(2) {
                    read_json(path)
                } else {
                    Ok(ScalePolicy::default())
                };
            let mupp_policy_result: Result<MuppAdapterPolicy, String> =
                if let Some(path) = a.get(3) {
                    read_json(path)
                } else {
                    Ok(MuppAdapterPolicy::default())
                };
            match (telemetry_result, scale_policy_result, mupp_policy_result) {
                (Ok(telemetry), Ok(policy), Ok(mupp_policy)) => {
                    match read_mupp_gate(
                        &a[1],
                        now_unix() as f64,
                        &mupp_policy,
                    ) {
                        Err(e) => Err(e.to_string()),
                        Ok(gate) => {
                            let merged = merge_scale_telemetry(telemetry, &gate);
                            match decide_scale(&merged, &policy) {
                                Err(e) => Err(e.to_string()),
                                Ok(decision) => Ok(serde_json::json!({
                                    "mupp": gate,
                                    "merged_telemetry": merged,
                                    "decision": decision
                                })),
                            }
                        }
                    }
                }
                (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => Err(e),
            }
        }
        "discovery-run" if a.len() >= 5 && a.len() <= 7 => {
            discovery_run(&home, &a)
        }
        "discovery-observe" if a.len() >= 2 && a.len() <= 4 => {
            discovery_observe(&home, &a)
        }
        "discovery-status" if a.is_empty() || a.len() == 1 => discovery_status(&home, &a),
        "discovery-validate-policy" if a.len() == 1 || a.len() == 2 => {
            discovery_validate_policy(&a)
        }
        _ => usage(),
    };

    match result {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    }
}

fn read_json<T: serde::de::DeserializeOwned>(
    path: &str,
) -> Result<T, String> {
    let bytes = fs::read(path)
        .map_err(|e| format!("read {path}: {e}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse {path}: {e}"))
}

// ---------------------------------------------------------------------------
// P6 — the search state machine
// ---------------------------------------------------------------------------
//
// Four commands, and the shape of all four is the same: read what a measurement
// produced, hand it to `DiscoveryMachine`, print one explicit report. None of
// them submits anything to the autonomy ledger, signs, orders or broadcasts, and
// none of them accepts an RPC endpoint. `discovery-run` and `discovery-observe`
// take a MUPP state path **positionally and without an optional form**: a search
// may not run on a machine whose thermal state nobody read, and the audit found
// that the existing thermal brake is opt-in at the CLI.

/// Loads an optional policy file, defaulting to the crate defaults.
fn search_policy(a: &[String], index: usize) -> Result<SearchPolicy, String> {
    let policy: SearchPolicy = match a.get(index) {
        Some(path) => read_json(path)?,
        None => SearchPolicy::default(),
    };
    policy.validate().map_err(|e| e.to_string())?;
    Ok(policy)
}

fn mupp_policy(a: &[String], index: usize) -> Result<MuppAdapterPolicy, String> {
    match a.get(index) {
        Some(path) => read_json(path),
        None => Ok(MuppAdapterPolicy::default()),
    }
}

/// Every threshold P6 consumed, with the surface each came from.
///
/// The caller's `min_net_edge_musd_micros` is the one threshold that can change
/// whether an opportunity is promoted, so it is the one recorded here — with a
/// `degenerate` verdict, which blocks promotion while it is in force.
fn threshold_audit() -> ThresholdAudit {
    ThresholdAudit::from_economic_policy(&EconomicPolicy::default()).with_crate_defaults()
}

/// Build the discovery adapter registry, including the on-chain flash loan
/// arbitrage scanner when a pinned Base RPC provider is available.
///
/// Falls back to just the S1 shadow evidence adapter when the provider cannot
/// be resolved (e.g. no payment policy pinned yet), so the CLI stays usable
/// without a live Base connection.
fn build_registry(
    home: &Path,
    s1_config: S1ShadowEvidenceConfig,
) -> Result<AdapterRegistry, String> {
    let local = LocalEconomy::open(home).map_err(|e| e.to_string())?;
    // Try to resolve a pinned provider for the flash arb adapter.
    let provider = local.chain_provider().ok();
    if let Some(provider) = &provider {
        let verifier = BaseUsdcVerifier::from_resolved(provider, 2)
            .map_err(|e| e.to_string())?;
        AdapterRegistry::crate_default(
            s1_config,
            FlashArbConfig::default(),
            verifier,
        )
        .map_err(|e| e.to_string())
    } else {
        // No pinned provider: register only the S1 shadow adapter.
        let mut registry = AdapterRegistry::new();
        registry.register(Box::new(
            S1ShadowEvidenceAdapter::new(s1_config).map_err(|e| e.to_string())?,
        ));
        Ok(registry)
    }
}

/// One full step over the crate's only real adapter.
fn discovery_run(home: &Path, a: &[String]) -> Result<serde_json::Value, String> {
    let machine = DiscoveryMachine::open(home).map_err(|e| e.to_string())?;
    let policy = search_policy(a, 5)?;
    let mupp = mupp_policy(a, 6)?;
    let gate = read_mupp_gate(&a[4], now_unix() as f64, &mupp).map_err(|e| e.to_string())?;
    let registry = build_registry(home, S1ShadowEvidenceConfig {
        source_path: a[0].clone(),
        agent_id: a[1].clone(),
        estimated_job_cost_musd_micros: micros(&a[2]),
        ttl_seconds: a[3]
            .parse::<u64>()
            .map_err(|_| "TTL must be an integer number of seconds".to_string())?,
    })
    .map_err(|e| e.to_string())?;

    let mut memory = machine.load().map_err(|e| e.to_string())?;
    let thresholds = threshold_audit();
    let attempt = machine
        .begin_search(&mut memory, &registry, &policy, Some(&gate), now_unix())
        .map_err(|e| e.to_string())?;

    let permit = match attempt {
        SearchAttempt::Proceed(permit) => permit,
        SearchAttempt::Denied(denial) => {
            machine.store(&memory).map_err(|e| e.to_string())?;
            return Ok(serde_json::json!({
                "state": memory.state,
                "state_name": memory.state.state(),
                "action": memory.state.action(),
                "action_name": memory.state.action().state(),
                "completed": false,
                "denied": denial,
                "scheduler": memory.wait_status(),
                "note": "no search ran and nothing was learned about any market"
            }));
        }
    };

    let adapter = registry
        .adapter(permit.class, "s1_shadow_scan")
        .or_else(|| registry.adapters_for(permit.class).into_iter().next())
        .ok_or_else(|| "adapter vanished between permit and observe".to_string())?;
    let observation: SearchObservation = adapter
        .observe(&permit, now_unix())
        .map_err(|e| e.to_string())?;
    let report = machine
        .observe(
            &mut memory,
            &permit,
            &observation,
            &registry,
            &policy,
            &thresholds,
            now_unix(),
        )
        .map_err(|e| e.to_string())?;
    machine.store(&memory).map_err(|e| e.to_string())?;

    let mut value = serde_json::to_value(&report).map_err(|e| e.to_string())?;
    value["observation"] =
        serde_json::to_value(&observation).map_err(|e| e.to_string())?;
    value["memory_path"] =
        serde_json::to_value(machine.memory_path()).map_err(|e| e.to_string())?;
    value["scheduler"] = serde_json::to_value(memory.wait_status()).map_err(|e| e.to_string())?;
    Ok(value)
}

/// Classify an observation produced by an adapter that lives outside this crate.
///
/// This is how a class with no in-crate adapter can be fed without a stub ever
/// being registered here. Support is still decided by the machine's own
/// registry, so an unimplemented class stays `unsupported_class` however good
/// the observation looks.
fn discovery_observe(home: &Path, a: &[String]) -> Result<serde_json::Value, String> {
    let machine = DiscoveryMachine::open(home).map_err(|e| e.to_string())?;
    let policy = search_policy(a, 2)?;
    let mupp = mupp_policy(a, 3)?;
    let gate = read_mupp_gate(&a[1], now_unix() as f64, &mupp).map_err(|e| e.to_string())?;
    let observation: SearchObservation = read_json(&a[0])?;
    let registry = build_registry(home, S1ShadowEvidenceConfig {
        source_path: a[0].clone(),
        agent_id: "external".into(),
        estimated_job_cost_musd_micros: 1,
        ttl_seconds: 1,
    })
    .map_err(|e| e.to_string())?;

    let mut memory = machine.load().map_err(|e| e.to_string())?;
    let thresholds = threshold_audit();
    let attempt = machine
        .begin_search(&mut memory, &registry, &policy, Some(&gate), now_unix())
        .map_err(|e| e.to_string())?;
    let permit = match attempt {
        SearchAttempt::Proceed(permit) => permit,
        SearchAttempt::Denied(denial) => {
            machine.store(&memory).map_err(|e| e.to_string())?;
            return Ok(serde_json::json!({
                "state": memory.state,
                "state_name": memory.state.state(),
                "denied": denial,
                "completed": false,
                "scheduler": memory.wait_status(),
                "note": "no search ran and nothing was learned about any market"
            }));
        }
    };
    if observation.class != permit.class || observation.cycle != permit.cycle {
        return Err(format!(
            "observation is class={} cycle={} but the permit is class={} cycle={}; \
             the machine refuses evidence that disagrees with the permit it was \
             issued for",
            observation.class, observation.cycle, permit.class, permit.cycle
        ));
    }
    let report = machine
        .observe(
            &mut memory,
            &permit,
            &observation,
            &registry,
            &policy,
            &thresholds,
            now_unix(),
        )
        .map_err(|e| e.to_string())?;
    machine.store(&memory).map_err(|e| e.to_string())?;
    let mut value = serde_json::to_value(&report).map_err(|e| e.to_string())?;
    value["scheduler"] = serde_json::to_value(memory.wait_status()).map_err(|e| e.to_string())?;
    Ok(value)
}

/// The machine's current state, its health vector and its coverage rows.
///
/// `search memory is a cache of search activity; no authority input reads it`
/// is in the output because a JSON file on disk that records coverage is exactly
/// the kind of artefact a future reader might mistake for evidence.
fn discovery_status(home: &Path, a: &[String]) -> Result<serde_json::Value, String> {
    let machine = DiscoveryMachine::open(home).map_err(|e| e.to_string())?;
    let policy = search_policy(a, 0)?;
    let registry = build_registry(home, S1ShadowEvidenceConfig {
        source_path: SEARCH_MEMORY_FILE.into(),
        agent_id: "status".into(),
        estimated_job_cost_musd_micros: 1,
        ttl_seconds: 1,
    })
    .map_err(|e| e.to_string())?;
    let memory = machine.load().map_err(|e| e.to_string())?;
    let health = memory.health(&registry);
    let verdict = health
        .verdict(&policy.health_minimums)
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "memory_path": machine.memory_path(),
        "cycle": memory.cycle,
        "current_class": memory.current_class,
        "scheduler": memory.wait_status(),
        "state": memory.state,
        "state_name": memory.state.state(),
        "action": memory.state.action(),
        "action_name": memory.state.action().state(),
        "health": health,
        "health_verdict": verdict,
        "cold": memory.cold_summary(&registry, &policy),
        "adapters": registry.identities(),
        "searchable_classes": policy.searchable_classes(&registry),
        "thresholds": threshold_audit(),
        "note": "search memory is a cache of search activity; no authority input \
                 reads it and nothing in it can authorise capital"
    }))
}

/// Answers "was this number the operator's?" before anything is decided with it.
fn discovery_validate_policy(a: &[String]) -> Result<serde_json::Value, String> {
    let requested = micros(&a[0]);
    let mut policy = SearchPolicy {
        min_net_edge: mycelium_economy::discovery::MinNetEdge::new(requested)
            .map_err(|e| e.to_string())?,
        ..SearchPolicy::default()
    };
    if let Some(path) = a.get(1) {
        let overlay: SearchPolicy = read_json(path)?;
        policy.health_minimums = overlay.health_minimums;
        policy.backoff = overlay.backoff;
        policy.budget = overlay.budget;
        policy.required_thermal_headroom = overlay.required_thermal_headroom;
        policy.thermal_cooldown_cycles = overlay.thermal_cooldown_cycles;
        policy.enabled_classes = overlay.enabled_classes;
    }
    policy.validate().map_err(|e| e.to_string())?;
    let audit = ThresholdAudit::from_economic_policy(&EconomicPolicy {
        min_net_edge_musd_micros: requested,
        ..EconomicPolicy::default()
    })
    .with_crate_defaults();
    Ok(serde_json::json!({
        "valid": true,
        "min_net_edge_musd_micros": policy.min_net_edge.micros(),
        "thresholds": audit,
        "promotion_blocked_by_degenerate_threshold": audit.any_degenerate(),
        "budget": policy.budget,
        "hard_thermal_ceiling_c": mycelium_economy::discovery::HARD_THERMAL_CEILING_C,
        "backoff": policy.backoff,
        "note": "min_net_edge=0 is unrepresentable in this module; a caller-supplied \
                 0 on autonomy::EconomicPolicy is recorded here and blocks promotion"
    }))
}

/// Builds the read-only verifier from the provider pinned out-of-band. The
/// endpoint is never an argument here, so no command can redirect it.
fn pinned_verifier(
    econ: &LocalEconomy,
    min_confirmations: u64,
) -> Result<BaseUsdcVerifier, String> {
    let provider = econ.chain_provider().map_err(|e| e.to_string())?;
    BaseUsdcVerifier::from_resolved(&provider, min_confirmations)
        .map_err(|e| e.to_string())
}

fn settle(
    econ: &LocalEconomy,
    a: &[String],
    mode: SettlementMode,
    proof: Option<String>,
) -> Result<serde_json::Value, String> {
    let job_id = &a[0];
    let work = econ
        .records()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find_map(|r| match r {
            mycelium_economy::LedgerRecord::Work { receipt, .. }
                if receipt.job_id == *job_id =>
            {
                Some(receipt)
            }
            _ => None,
        })
        .ok_or_else(|| format!("no work receipt for job {job_id}"))?;

    let now = now_unix();
    let amount = micros(&a[2]);
    let external = false;
    let id = stable_id(
        "settlement",
        &[job_id, &a[1], &a[2], &now.to_string()],
    );
    let settlement_asset =
        SettlementAsset::classify_symbol(&a[1]).map_err(|e| e.to_string())?;

    econ.append_settlement(SettlementReceipt {
        schema_version: SCHEMA_VERSION,
        settlement_id: id,
        job_id: job_id.clone(),
        work_receipt_id: work.receipt_id,
        settled_at_unix: now,
        mode,
        settlement_asset,
        settled_amount_micros: amount,
        usd_equivalent_micros: amount,
        payment_intent_id: None,
        payment_block_number: None,
        payment_proof_hash: proof,
        payment_proof_verified: false,
        external_paid: external,
        internal_work: false,
    })
    .map(|v| serde_json::to_value(v).unwrap())
    .map_err(|e| e.to_string())
}


fn payment_instructions(
    econ: &LocalEconomy,
    job_id: &str,
) -> Result<serde_json::Value, String> {
    let policy = econ.payment_policy().map_err(|e| e.to_string())?;
    let job = econ
        .job(job_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("job not found: {job_id}"))?;
    if job.internal_work {
        return Err("internal work cannot receive external PaidDemand".into());
    }

    let intent = match econ
        .payment_intent_for_job(job_id)
        .map_err(|e| e.to_string())?
    {
        Some(intent) => intent,
        None => {
            let verifier = pinned_verifier(econ, policy.min_confirmations)?;
            let anchor = verifier.anchor().map_err(|e| e.to_string())?;
            econ.create_payment_intent(
                job_id,
                anchor.block_number,
                &anchor.block_hash,
                anchor.block_timestamp_unix,
            )
            .map_err(|e| e.to_string())?
        }
    };

    Ok(serde_json::json!({
        "payment_intent_id": intent.payment_intent_id,
        "job_id": job.job_id,
        "chain_id": intent.chain_id,
        "asset": "USDC_BASE",
        "token": intent.token,
        "recipient": intent.recipient,
        "exact_amount_usdc": intent.exact_amount_raw as f64 / 1_000_000.0,
        "exact_amount_raw": intent.exact_amount_raw,
        "min_confirmations": policy.min_confirmations,
        "anchor_block": intent.anchor_block,
        "anchor_block_hash": intent.anchor_block_hash,
        "anchor_timestamp_unix": intent.anchor_timestamp_unix,
        "note": "Payment must be an exact USDC Transfer in a block strictly after the recorded Base anchor."
    }))
}

/// Settles a verified Base USDC transfer, without signing it.
///
/// Two steps, and the split is deliberate rather than an ergonomic accident:
///
/// * This command does a **chain read** through a provider pinned out-of-band
///   and appends a `SettlementReceipt`. It exercises no private key.
/// * `settlement-attest` does the **key operation**.
///
/// Why not one command: the settlement and its attestation are separate
/// hash-chained ledgers with separate sequence numbers and separate
/// `recorded_at_unix` values, and the read side distinguishes
/// `UnsignedSettlement` from every other gap. Collapsing them would make
/// "verified but not yet signed" unreachable, which is the one state an
/// operator most needs to be able to observe — a settlement that was
/// chain-verified on Monday and signed on Tuesday after a key rotation is a
/// normal thing, and inline signing would erase the evidence that it was
/// ever the former.
///
/// It also keeps a failure independent: if the signing key is missing, the
/// payment confirmation still lands in the ledger and the operator still gets
/// their settlement, with the reason it is unsigned rather than nothing.
fn settle_base_usdc(
    econ: &LocalEconomy,
    views: &EconomyViews<'_>,
    a: &[String],
) -> Result<serde_json::Value, String> {
    let job_id = &a[0];
    let tx_hash = &a[1];

    let policy = econ.payment_policy().map_err(|e| e.to_string())?;
    let job = econ
        .job(job_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("job not found: {job_id}"))?;
    if job.internal_work {
        return Err("internal work cannot be externally settled".into());
    }

    let work = econ
        .records()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find_map(|r| match r {
            mycelium_economy::LedgerRecord::Work { receipt, .. }
                if receipt.job_id == *job_id && receipt.verified =>
            {
                Some(receipt)
            }
            _ => None,
        })
        .ok_or_else(|| format!("no verified work receipt for job {job_id}"))?;

    let intent = econ
        .payment_intent_for_job(job_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            format!(
                "no payment intent for job {job_id}; run payment-instructions first"
            )
        })?;

    let verifier = pinned_verifier(econ, policy.min_confirmations)?;
    let proof = verifier
        .verify_transfer(
            tx_hash,
            &intent.recipient,
            intent.exact_amount_raw,
        )
        .map_err(|e| e.to_string())?;

    if proof.block_number <= intent.anchor_block {
        return Err(format!(
            "payment block {} is not after payment-intent anchor {}",
            proof.block_number, intent.anchor_block
        ));
    }

    let id = stable_id(
        "settlement",
        &[job_id, tx_hash, &intent.payment_intent_id],
    );

    let settlement = econ
        .append_settlement(SettlementReceipt {
            schema_version: SCHEMA_VERSION,
            settlement_id: id,
            job_id: job_id.clone(),
            work_receipt_id: work.receipt_id,
            settled_at_unix: proof.block_timestamp_unix,
            mode: SettlementMode::External,
            settlement_asset: SettlementAsset::classify_symbol("USDC_BASE")
                .map_err(|e| e.to_string())?,
            settled_amount_micros: proof.matched_raw,
            usd_equivalent_micros: proof.matched_raw,
            payment_intent_id: Some(intent.payment_intent_id.clone()),
            payment_block_number: Some(proof.block_number),
            payment_proof_hash: Some(proof.transaction_hash.clone()),
            payment_proof_verified: proof.verified,
            external_paid: true,
            internal_work: false,
        })
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "chain_provider": {
            "endpoint": proof.rpc,
            "identity_verified_by_kernel": proof.provider_identity_verified,
            "pinned_out_of_band": true
        },
        "payment_verification": proof,
        "settlement": settlement,
        // The settlement is on the ledger and it counts for nothing yet. Both
        // halves of that are stated here, with the command that changes it, so
        // a two-step flow cannot turn into a dead end.
        "attestation": {
            "signed": false,
            "reason": "a chain read and a signature are separate acts; \
                       `settle-base-usdc` performs the first and nothing signs \
                       until `settlement-attest` runs against a validated \
                       outcome policy",
            "next_command": format!(
                "mycelium-economy --home DIR settlement-attest {}",
                settlement.settlement_id
            ),
            "signing_key": views.trust_report()["signing_key"].clone(),
        }
    }))
}

/// Signs one settlement with the key a validated policy delegates to, and
/// records the attestation.
///
/// The preconditions are checked by [`EconomyViews::signing_key`] before
/// anything is loaded or written: no validated policy, or no key bound to it,
/// is a refusal with an actionable message and no side effect. Nothing here can
/// reach the signing path without passing it, because `attest_settlement` is
/// reached only after it returns the policy.
fn attest_settlement(
    econ: &LocalEconomy,
    views: &EconomyViews<'_>,
    settlement_id: &str,
) -> Result<serde_json::Value, String> {
    let (policy, key) = views.signing_key()?;

    let settlement = econ
        .records()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find_map(|r| match r {
            LedgerRecord::Settlement { settlement, .. }
                if settlement.settlement_id == settlement_id =>
            {
                Some(settlement)
            }
            _ => None,
        })
        .ok_or_else(|| {
            format!(
                "no settlement {settlement_id} on the ledger at {}. A \
                 settlement is created by `settle-base-usdc`; its \
                 `settlement_id` is in that command's output.",
                econ.ledger_path().display()
            )
        })?;

    // The intent is the ledger's own, not one the caller supplies: the
    // attestation body is rebuilt from it at verification time, so signing
    // against anything else could only produce an attestation that fails.
    let intent = econ
        .payment_intent_for_job(&settlement.job_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            format!(
                "settlement {settlement_id} has no payment intent for job {}; \
                 run `payment-instructions {}` before settling",
                settlement.job_id, settlement.job_id
            )
        })?;

    let attestation: AuthenticatedSettlementReceipt =
        key.attest_settlement(policy, &settlement, &intent)
            .map_err(|e| format!("refusing to sign: {e}"))?;
    let attestation_hash = attestation.attestation_hash().to_string();
    let verifier_key_id = attestation.verifier_key_id().to_string();
    let policy_hash = attestation.policy_hash().to_string();
    econ.record_settlement_attestation(&attestation)
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "settlement_id": settlement.settlement_id,
        "job_id": settlement.job_id,
        "attestation": {
            "attestation_hash": attestation_hash,
            "verifier_key_id": verifier_key_id,
            "policy_hash": policy_hash,
        },
        "ledger": econ.settlement_attestation_ledger_path().display().to_string(),
        "signing_key": views.trust_report()["signing_key"].clone(),
        "note": "the attestation is re-verified against the policy in force \
                 on every read; a policy rotation stops it matching and the \
                 settlement is reported unattested until it is re-signed"
    }))
}

/// Signs one external-value receipt with the key a validated policy delegates
/// to, and records the attestation.
///
/// The autonomy-side mirror of [`attest_settlement`], with the same ordering
/// and the same refusals. The evidence signed over is looked up in the autonomy
/// ledger by the receipt's own `proof_hash`, never supplied by the caller, and
/// the *first* matching crossing is chosen for exactly the reason the read side
/// chooses the first: `VerifiedEconomyView` verifies the signature against
/// `candidates.first()`, so signing over a different copy would produce an
/// attestation that can never verify.
fn attest_receipt(
    autonomous: &AutonomousEconomy,
    views: &EconomyViews<'_>,
    source_id: &str,
) -> Result<serde_json::Value, String> {
    let (policy, key) = views.signing_key()?;

    let receipt = autonomous
        .records()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find_map(|r| match r.payload {
            AutonomyPayload::ExternalValue { receipt }
                if receipt.source_id == source_id =>
            {
                Some(receipt)
            }
            _ => None,
        })
        .ok_or_else(|| {
            format!(
                "no external-value receipt with source_id {source_id}. \
                 Receipts are recorded by `external-value-candidate-json` and \
                 by `s1-reconcile-outcome`; `autonomy-audit` lists what is on \
                 the ledger."
            )
        })?;

    mycelium_economy::base_usdc::validate_hash32("proof_hash", &receipt.proof_hash)
        .map_err(|_| {
            format!(
                "receipt {source_id} cites proof_hash {:?}, which is not a \
                 transaction hash, so there is no boundary evidence to sign \
                 over. This receipt predates the boundary and cannot be \
                 attested.",
                receipt.proof_hash
            )
        })?;
    let cited = receipt.proof_hash.to_ascii_lowercase();
    let evidence = autonomous
        .boundary_evidence()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|e| e.tx_hash.to_ascii_lowercase() == cited)
        .ok_or_else(|| {
            format!(
                "receipt {source_id} cites transaction {cited}, but the \
                 autonomy ledger holds no boundary crossing for it. The \
                 crossing is the evidence a receipt is verified against; \
                 without one there is nothing to sign."
            )
        })?;

    let attestation: AuthenticatedExternalValueReceipt =
        key.attest(policy, &receipt, &evidence)
            .map_err(|e| format!("refusing to sign: {e}"))?;
    let attestation_hash = attestation.attestation_hash().to_string();
    let verifier_key_id = attestation.verifier_key_id().to_string();
    let policy_hash = attestation.policy_hash().to_string();
    autonomous
        .record_receipt_attestation(&attestation)
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "source_id": receipt.source_id,
        "agent_id": receipt.agent_id,
        "opportunity_id": receipt.opportunity_id,
        "attestation": {
            "attestation_hash": attestation_hash,
            "verifier_key_id": verifier_key_id,
            "policy_hash": policy_hash,
            "signed_over_evidence": {
                "tx_hash": evidence.tx_hash,
                "block_hash": evidence.block_hash,
                "amount_raw": evidence.amount_raw,
            },
        },
        "ledger": autonomous.attestation_ledger_path().display().to_string(),
        "signing_key": views.trust_report()["signing_key"].clone(),
        "note": "the boundary derivation and the class, asset and sign checks \
                 are re-run on every read; this signature removes none of them"
    }))
}
