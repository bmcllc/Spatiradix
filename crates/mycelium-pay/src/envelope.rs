//! Envelope v1 (§7.1): `{0:v, 1:type, 2:body, 3:[Sig]}`; assina-se `msg`, nunca o envelope.

use crate::cbor::{self, Value};
use crate::PayError;
use secp256k1::{schnorr, Keypair, SecretKey, XOnlyPublicKey, SECP256K1};

pub const V: u64 = 1;
pub const ALG_BIP340: u8 = 1;
pub const ALG_MLDSA87: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    PayRequest = 1,
    TokenSend = 2,
    Receipt = 3,
    LnInvoice = 4,
}

impl Type {
    pub fn name(self) -> &'static str {
        match self {
            Type::PayRequest => "PayRequest",
            Type::TokenSend => "TokenSend",
            Type::Receipt => "Receipt",
            Type::LnInvoice => "LnInvoice",
        }
    }
    fn from_u64(n: u64) -> Result<Self, PayError> {
        Ok(match n {
            1 => Type::PayRequest,
            2 => Type::TokenSend,
            3 => Type::Receipt,
            4 => Type::LnInvoice,
            _ => return Err(PayError::Envelope("type desconhecido")),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sig {
    pub alg: u8,
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub ty: Type,
    /// CBOR canônico (validado em `decode`/`new`).
    pub body: Vec<u8>,
    pub sigs: Vec<Sig>,
}

impl Envelope {
    pub fn new(ty: Type, body: &Value) -> Result<Self, PayError> {
        Ok(Self { ty, body: cbor::encode(body)?, sigs: vec![] })
    }

    /// `id = BLAKE3(body)`
    pub fn id(&self) -> [u8; 32] {
        *blake3::hash(&self.body).as_bytes()
    }

    /// `msg = BLAKE3::derive_key("mycelium/v1/pay/sig/" ‖ type_name, body)`
    pub fn msg(&self) -> [u8; 32] {
        blake3::derive_key(&format!("mycelium/v1/pay/sig/{}", self.ty.name()), &self.body)
    }

    pub fn sign_bip340(&mut self, secret: &[u8; 32]) -> Result<(), PayError> {
        let sk = SecretKey::from_byte_array(*secret).map_err(|_| PayError::Envelope("chave inválida"))?;
        let kp = Keypair::from_secret_key(SECP256K1, &sk);
        let sig = SECP256K1.sign_schnorr_no_aux_rand(&self.msg(), &kp);
        self.sigs.push(Sig {
            alg: ALG_BIP340,
            pubkey: kp.x_only_public_key().0.serialize().to_vec(),
            sig: sig.as_ref().to_vec(),
        });
        Ok(())
    }

    /// Exige ≥1 assinatura e que todas verifiquem; alg desconhecido/sem suporte = falha (fechada).
    pub fn verify(&self) -> Result<(), PayError> {
        if self.sigs.is_empty() {
            return Err(PayError::BadSignature);
        }
        let msg = self.msg();
        for s in &self.sigs {
            let ok = match s.alg {
                ALG_BIP340 => {
                    let pk = XOnlyPublicKey::from_byte_array(s.pubkey.as_slice().try_into().map_err(|_| PayError::BadSignature)?)
                        .map_err(|_| PayError::BadSignature)?;
                    let sig = schnorr::Signature::from_byte_array(s.sig.as_slice().try_into().map_err(|_| PayError::BadSignature)?);
                    SECP256K1.verify_schnorr(&sig, &msg, &pk).is_ok()
                }
                #[cfg(feature = "mldsa")]
                ALG_MLDSA87 => mycelium_zkp::license::mldsa_verify(&s.pubkey, &msg, &s.sig),
                _ => false,
            };
            if !ok {
                return Err(PayError::BadSignature);
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, PayError> {
        let sigs = self
            .sigs
            .iter()
            .map(|s| {
                Value::Map(vec![
                    (0, Value::Uint(s.alg as u64)),
                    (1, Value::Bytes(s.pubkey.clone())),
                    (2, Value::Bytes(s.sig.clone())),
                ])
            })
            .collect();
        cbor::encode(&Value::Map(vec![
            (0, Value::Uint(V)),
            (1, Value::Uint(self.ty as u64)),
            (2, Value::Bytes(self.body.clone())),
            (3, Value::Array(sigs)),
        ]))
    }

    pub fn decode(buf: &[u8]) -> Result<Self, PayError> {
        let bad = PayError::Envelope("estrutura inválida");
        let Value::Map(m) = cbor::decode(buf)? else { return Err(bad) };
        let [(0, Value::Uint(v)), (1, Value::Uint(ty)), (2, Value::Bytes(body)), (3, Value::Array(sigs))] = <[_; 4]>::try_from(m).map_err(|_| PayError::Envelope("estrutura inválida"))? else {
            return Err(PayError::Envelope("estrutura inválida"));
        };
        if v != V {
            return Err(PayError::Envelope("versão não suportada"));
        }
        cbor::decode(&body)?; // body precisa ser CBOR canônico
        let sigs = sigs
            .into_iter()
            .map(|s| match s {
                Value::Map(m) => match <[_; 3]>::try_from(m) {
                    Ok([(0, Value::Uint(alg)), (1, Value::Bytes(pubkey)), (2, Value::Bytes(sig))]) => Ok(Sig {
                        alg: u8::try_from(alg).map_err(|_| PayError::Envelope("alg"))?,
                        pubkey,
                        sig,
                    }),
                    _ => Err(PayError::Envelope("Sig inválida")),
                },
                _ => Err(PayError::Envelope("Sig inválida")),
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { ty: Type::from_u64(ty)?, body, sigs })
    }
}
