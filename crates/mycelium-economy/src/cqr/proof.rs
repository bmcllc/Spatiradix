//! CQR Result Proof — Cryptographic binding proving execution integrity.
//!
//! A `CqrResultProof` proves:
//! "this specific computation was executed honestly from this input state to
//! this output state under this implementation version, satisfying the declared
//! validation suite".
//!
//! Crucially, it does NOT prove:
//! 1. "This physical model is an accurate representation of nature"
//! 2. "This work has positive external economic value"
//! 3. "This computation grants NEV"
//!
//! Those properties belong to separate scientific and economic validation domains.

use super::state_bus::blake3_derive_key;
use serde::{Deserialize, Serialize};

/// Domain separation string for BLAKE3 hashes on CQR Result Proofs.
pub const CQR_PROOF_DOMAIN: &[u8] = b"mycelium:cqr:result_proof:v1";

/// Cryptographic proof binding job, inputs, outputs, validation, and worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CqrResultProof {
    pub schema_version: u32,
    pub proof_id: String,
    pub job_id: String,
    pub job_hash: String,
    pub input_state_hash: String,
    pub output_state_hash: String,
    pub implementation_id: String,
    pub implementation_version: String,
    pub validation_suite_digest: String,
    pub result_digest: String,
    pub worker_identity: String,
    pub proof_digest: String,
}

impl CqrResultProof {
    /// Constructs a result proof from canonical components.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proof_id: impl Into<String>,
        job_id: impl Into<String>,
        job_hash: impl Into<String>,
        input_state_hash: impl Into<String>,
        output_state_hash: impl Into<String>,
        implementation_id: impl Into<String>,
        implementation_version: impl Into<String>,
        validation_suite_digest: impl Into<String>,
        result_digest: impl Into<String>,
        worker_identity: impl Into<String>,
    ) -> Self {
        let proof_id = proof_id.into();
        let job_id = job_id.into();
        let job_hash = job_hash.into();
        let input_state_hash = input_state_hash.into();
        let output_state_hash = output_state_hash.into();
        let implementation_id = implementation_id.into();
        let implementation_version = implementation_version.into();
        let validation_suite_digest = validation_suite_digest.into();
        let result_digest = result_digest.into();
        let worker_identity = worker_identity.into();

        let proof_digest = Self::compute_proof_digest(
            &job_hash,
            &input_state_hash,
            &output_state_hash,
            &implementation_id,
            &implementation_version,
            &validation_suite_digest,
            &result_digest,
            &worker_identity,
        );

        Self {
            schema_version: 1,
            proof_id,
            job_id,
            job_hash,
            input_state_hash,
            output_state_hash,
            implementation_id,
            implementation_version,
            validation_suite_digest,
            result_digest,
            worker_identity,
            proof_digest,
        }
    }

    /// Computes the canonical proof digest.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_proof_digest(
        job_hash: &str,
        input_state_hash: &str,
        output_state_hash: &str,
        implementation_id: &str,
        implementation_version: &str,
        validation_suite_digest: &str,
        result_digest: &str,
        worker_identity: &str,
    ) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&blake3_derive_key(CQR_PROOF_DOMAIN));
        hasher.update(job_hash.as_bytes());
        hasher.update(input_state_hash.as_bytes());
        hasher.update(output_state_hash.as_bytes());
        hasher.update(implementation_id.as_bytes());
        hasher.update(implementation_version.as_bytes());
        hasher.update(validation_suite_digest.as_bytes());
        hasher.update(result_digest.as_bytes());
        hasher.update(worker_identity.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Verifies the internal integrity of this proof.
    pub fn verify_integrity(&self) -> bool {
        let expected = Self::compute_proof_digest(
            &self.job_hash,
            &self.input_state_hash,
            &self.output_state_hash,
            &self.implementation_id,
            &self.implementation_version,
            &self.validation_suite_digest,
            &self.result_digest,
            &self.worker_identity,
        );
        self.proof_digest == expected
    }

    /// Canonical preimage bytes for verifier attestation.
    pub fn attestation_preimage(&self, policy_hash: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        crate::policy_auth::push_tagged(&mut buf, b"domain", b"MYCELIUM-ECONOMY/CQR-ATTESTATION/V1");
        crate::policy_auth::push_tagged(&mut buf, b"policy_hash", policy_hash.as_bytes());
        crate::policy_auth::push_tagged(&mut buf, b"proof_digest", self.proof_digest.as_bytes());
        crate::policy_auth::push_tagged(&mut buf, b"result_digest", self.result_digest.as_bytes());
        crate::policy_auth::push_tagged(&mut buf, b"job_hash", self.job_hash.as_bytes());
        buf
    }
}

/// An authenticated verifier attestation over a CQR Result Proof.
///
/// Crucial distinction:
/// * `CqrResultProof` is an integrity commitment generated by the worker.
/// * `CqrResultAttestation` is an authenticated cryptographic statement
///   signed by the delegated verifier key of a validated outcome policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CqrResultAttestation {
    pub proof_digest: String,
    pub policy_hash: String,
    pub verifier_key_id: String,
    pub signature_hex: String,
}

impl CqrResultAttestation {
    /// Constructs a signed attestation using a delegated verifier runtime key under a validated policy.
    pub fn attest(
        proof: &CqrResultProof,
        policy: &crate::policy_auth::ValidatedOutcomePolicy,
        verifier: &crate::policy_auth::VerifierRuntimeKey,
    ) -> Result<Self, crate::policy_auth::PolicyError> {
        if !proof.verify_integrity() {
            return Err(crate::policy_auth::PolicyError::InvalidField {
                field: "proof_digest",
                reason: "proof internal integrity verification failed".into(),
            });
        }
        let policy_hash = policy.policy_hash()?;
        let preimage = proof.attestation_preimage(policy_hash.as_str());
        let signature = verifier.sign_preimage(&preimage);

        Ok(Self {
            proof_digest: proof.proof_digest.clone(),
            policy_hash: policy_hash.to_string(),
            verifier_key_id: verifier.key_id().to_string(),
            signature_hex: format!("0x{}", hex::encode(signature.to_bytes())),
        })
    }

    /// Verifies this attestation against the delegated verifier of a validated outcome policy.
    pub fn verify(
        &self,
        proof: &CqrResultProof,
        policy: &crate::policy_auth::ValidatedOutcomePolicy,
    ) -> Result<(), crate::policy_auth::PolicyError> {
        if !proof.verify_integrity() {
            return Err(crate::policy_auth::PolicyError::InvalidField {
                field: "proof_digest",
                reason: "proof internal integrity failed".into(),
            });
        }
        if self.proof_digest != proof.proof_digest {
            return Err(crate::policy_auth::PolicyError::InvalidField {
                field: "proof_digest",
                reason: format!("attestation digest {} != proof {}", self.proof_digest, proof.proof_digest),
            });
        }
        let expected_policy_hash = policy.policy_hash()?;
        if self.policy_hash != expected_policy_hash.as_str() {
            return Err(crate::policy_auth::PolicyError::InvalidField {
                field: "policy_hash",
                reason: format!("attestation policy {} != policy in force {}", self.policy_hash, expected_policy_hash),
            });
        }
        let trusted_verifier = policy.trusted_verifier();
        if self.verifier_key_id != trusted_verifier.key_id().to_string() {
            return Err(crate::policy_auth::PolicyError::InvalidField {
                field: "verifier_key_id",
                reason: format!("attestation key {} != delegated key {}", self.verifier_key_id, trusted_verifier.key_id()),
            });
        }

        let raw_sig = self.signature_hex.strip_prefix("0x").unwrap_or(&self.signature_hex);
        let sig_bytes = hex::decode(raw_sig).map_err(|e| crate::policy_auth::PolicyError::InvalidField {
            field: "signature_hex",
            reason: format!("malformed hex: {e}"),
        })?;
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|_| crate::policy_auth::PolicyError::BadSignature)?;

        let preimage = proof.attestation_preimage(&self.policy_hash);
        let verifying_key = trusted_verifier.verifying_key()?;
        verifying_key.verify_strict(&preimage, &signature)
            .map_err(|_| crate::policy_auth::PolicyError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_proof() -> CqrResultProof {
        CqrResultProof::new(
            "proof-unit-1",
            "job-001",
            "0xjobhash0000000000000000000000000000000000000000000000000000000001",
            "0xinputhash00000000000000000000000000000000000000000000000000000002",
            "0xoutputhash000000000000000000000000000000000000000000000000000003",
            "cqr-symplectic-kernel",
            "1.0.0",
            "0xsuitedigest00000000000000000000000000000000000000000000000000004",
            "0xresultdigest0000000000000000000000000000000000000000000000000005",
            "worker-unit-01",
        )
    }

    #[test]
    fn proof_integrity_and_tamper_detection() {
        let proof = sample_proof();
        assert!(proof.verify_integrity());

        let mut tampered = proof.clone();
        tampered.worker_identity = "impostor-worker".into();
        assert!(!tampered.verify_integrity());

        let mut tampered2 = proof.clone();
        tampered2.output_state_hash = "0xforged0000000000000000000000000000000000000000000000000000000000".into();
        assert!(!tampered2.verify_integrity());
    }

    #[test]
    fn attestation_and_cryptographic_verification() {
        let proof = sample_proof();
        let temp_dir = tempfile::tempdir().unwrap();
        let socket = crate::rpc_test_server::FakeRpcSocket::bind(temp_dir.path().join("rpc.sock"));
        let registry = crate::boundary::ControlledAddressRegistry::new();
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry,
        );
        let policy = auth.validated();

        // Legitimate attestation by delegated verifier
        let attestation = CqrResultAttestation::attest(&proof, &policy, &auth.verifier)
            .expect("attestation succeeds");

        assert_eq!(attestation.proof_digest, proof.proof_digest);
        assert_eq!(attestation.verifier_key_id, auth.verifier.key_id().to_string());

        // Verification passes
        assert!(attestation.verify(&proof, &policy).is_ok());

        // Tampered proof fails verification
        let mut tampered_proof = proof.clone();
        tampered_proof.result_digest = "0xchanged0000000000000000000000000000000000000000000000000000000000".into();
        assert!(attestation.verify(&tampered_proof, &policy).is_err());

        // Impostor verifier key fails verification
        let impostor = crate::policy_auth::VerifierRuntimeKey::generate();
        let impostor_attestation = CqrResultAttestation::attest(&proof, &policy, &impostor)
            .expect("impostor can sign locally");
        let err = impostor_attestation.verify(&proof, &policy).unwrap_err();
        assert!(format!("{err}").contains("attestation key"));
    }
}

