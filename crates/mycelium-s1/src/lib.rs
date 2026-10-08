pub mod billing;
pub mod benchmark;
pub mod economy;
pub mod publication;
pub mod training;
pub mod http;
pub use http::{configured_router, router};
// Local fixed-logit decisions and signed offline allowances. No network inference.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Model {
    pub actions: Vec<String>,
    pub weights: Vec<Vec<f64>>,
    pub bias: Vec<f64>,
}
impl Model {
    pub fn evaluate(&self, features: &[f64], allowed: &[bool]) -> Result<Vec<f64>, String> {
        let n = self.actions.len();
        if n == 0
            || n > 4096
            || self.weights.len() != n
            || self.bias.len() != n
            || allowed.len() != n
            || !allowed.iter().any(|x| *x)
        {
            return Err("invalid action dimensions or mask".into());
        }
        if !features.iter().all(|v| v.is_finite()) {
            return Err("non-finite features".into());
        }
        let mut logits = Vec::with_capacity(n);
        for (w, b) in self.weights.iter().zip(&self.bias) {
            if w.len() != features.len()
                || !w.iter().chain(std::iter::once(b)).all(|v| v.is_finite())
            {
                return Err("invalid weights".into());
            }
            let v = w.iter().zip(features).fold(*b, |a, (w, x)| a + w * x);
            if !v.is_finite() {
                return Err("logit overflow".into());
            }
            logits.push(v);
        }
        let max = logits
            .iter()
            .zip(allowed)
            .filter(|(_, a)| **a)
            .map(|(v, _)| *v)
            .fold(f64::NEG_INFINITY, f64::max);
        let mut p: Vec<f64> = logits
            .iter()
            .zip(allowed)
            .map(|(v, a)| if *a { (v - max).exp() } else { 0. })
            .collect();
        let sum: f64 = p.iter().sum();
        for v in &mut p {
            *v /= sum;
        }
        Ok(p)
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Allowance {
    pub id: String,
    pub studio: String,
    pub model: String,
    pub device: String,
    pub evaluations: u64,
    pub expires_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Ticket {
    pub allowance: Allowance,
    pub signature: String,
}
impl Ticket {
    pub fn issue(allowance: Allowance, key: &SigningKey) -> Result<Self, String> {
        let bytes = serde_json::to_vec(&allowance).map_err(|e| e.to_string())?;
        Ok(Self {
            allowance,
            signature: hex::encode(key.sign(&bytes).to_bytes()),
        })
    }
    pub fn verify(
        &self,
        key: &VerifyingKey,
        now: u64,
        model: &str,
        device: &str,
    ) -> Result<(), String> {
        let bytes = hex::decode(&self.signature).map_err(|_| "invalid signature")?;
        let signature = Signature::from_slice(&bytes).map_err(|_| "invalid signature")?;
        key.verify(
            &serde_json::to_vec(&self.allowance).map_err(|e| e.to_string())?,
            &signature,
        )
        .map_err(|_| "invalid signature")?;
        if now >= self.allowance.expires_at
            || model != self.allowance.model
            || device != self.allowance.device
        {
            return Err("expired or mismatched allowance".into());
        }
        Ok(())
    }
}
/// Persist consumed counts in a trusted host store. Client-controlled files cannot prevent rollback.
pub struct Bucket {
    ticket: Ticket,
    consumed: u64,
}
impl Bucket {
    pub fn new(ticket: Ticket, consumed: u64) -> Result<Self, String> {
        if consumed > ticket.allowance.evaluations {
            return Err("invalid counter".into());
        }
        Ok(Self { ticket, consumed })
    }
    pub fn consume(
        &mut self,
        key: &VerifyingKey,
        now: u64,
        model: &str,
        device: &str,
    ) -> Result<u64, String> {
        self.ticket.verify(key, now, model, device)?;
        if self.consumed >= self.ticket.allowance.evaluations {
            return Err("credits exhausted".into());
        }
        self.consumed += 1;
        Ok(self.consumed)
    }
}
#[derive(Deserialize)]
pub struct Evaluation {
    pub model: Model,
    pub features: Vec<f64>,
    pub allowed: Vec<bool>,
}
/// C ABI: input must point to a valid NUL-terminated UTF-8 JSON string.
/// Returned allocation must be released exactly once using s1_free.
///
/// # Safety
/// `input` must be null or point to readable, NUL-terminated memory for this call.
#[no_mangle]
pub unsafe extern "C" fn s1_evaluate(input: *const std::ffi::c_char) -> *mut std::ffi::c_char {
    if input.is_null() {
        return std::ptr::null_mut();
    }
    let result = std::ffi::CStr::from_ptr(input)
        .to_str()
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str::<Evaluation>(s).map_err(|e| e.to_string()))
        .and_then(|r| r.model.evaluate(&r.features, &r.allowed));
    let value = match result {
        Ok(p) => serde_json::json!({"probabilities":p}),
        Err(e) => serde_json::json!({"error":e}),
    };
    std::ffi::CString::new(value.to_string())
        .unwrap()
        .into_raw()
}
/// Releases the allocation returned by `s1_evaluate`.
///
/// # Safety
/// `ptr` must be null or a pointer returned by `s1_evaluate` that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn s1_free(ptr: *mut std::ffi::c_char) {
    if !ptr.is_null() {
        drop(std::ffi::CString::from_raw(ptr));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stable_masked_softmax() {
        let m = Model {
            actions: vec!["a".into(), "b".into(), "c".into()],
            weights: vec![vec![], vec![], vec![]],
            bias: vec![1000., 1000., 9999.],
        };
        assert_eq!(
            m.evaluate(&[], &[true, true, false]).unwrap(),
            vec![0.5, 0.5, 0.]
        );
        assert!(m.evaluate(&[], &[false, false, false]).is_err());
    }
    #[test]
    fn signed_ticket_exhaustion_and_tampering() {
        let k = SigningKey::from_bytes(&[7; 32]);
        let mut t = Ticket::issue(
            Allowance {
                id: "1".into(),
                studio: "studio".into(),
                model: "npc".into(),
                device: "pc".into(),
                evaluations: 1,
                expires_at: 100,
            },
            &k,
        )
        .unwrap();
        let mut b = Bucket::new(t.clone(), 0).unwrap();
        assert_eq!(b.consume(&k.verifying_key(), 99, "npc", "pc").unwrap(), 1);
        assert!(b.consume(&k.verifying_key(), 99, "npc", "pc").is_err());
        assert!(t.verify(&k.verifying_key(), 100, "npc", "pc").is_err());
        t.allowance.evaluations = 999;
        assert!(t.verify(&k.verifying_key(), 99, "npc", "pc").is_err());
    }
}
