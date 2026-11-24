//! Corpos tipados do §7.2. Mapas de chaves inteiras, exatamente as listadas (campo extra = erro).

use crate::cbor::Value;
use crate::envelope::{Envelope, Type};
use crate::PayError;

fn bad(m: &'static str) -> PayError {
    PayError::Envelope(m)
}

/// Exige o mapa com exatamente `keys`, em ordem; devolve os valores.
fn fields(v: Value, keys: &[u64]) -> Result<Vec<Value>, PayError> {
    let Value::Map(m) = v else { return Err(bad("corpo não é mapa")) };
    if m.len() != keys.len() || m.iter().zip(keys).any(|((k, _), w)| k != w) {
        return Err(bad("campos do corpo diferentes do esperado"));
    }
    Ok(m.into_iter().map(|(_, v)| v).collect())
}

fn uint(v: Value) -> Result<u64, PayError> {
    if let Value::Uint(n) = v { Ok(n) } else { Err(bad("esperava inteiro")) }
}
fn bytes<const N: usize>(v: Value) -> Result<[u8; N], PayError> {
    match v {
        Value::Bytes(b) => b.try_into().map_err(|_| bad("tamanho de bstr")),
        _ => Err(bad("esperava bstr")),
    }
}
fn text(v: Value) -> Result<String, PayError> {
    if let Value::Text(t) = v { Ok(t) } else { Err(bad("esperava texto")) }
}
fn texts(v: Value) -> Result<Vec<String>, PayError> {
    match v {
        Value::Array(a) => a.into_iter().map(text).collect(),
        _ => Err(bad("esperava array")),
    }
}
fn strs(a: &[String]) -> Value {
    Value::Array(a.iter().cloned().map(Value::Text).collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayRequest {
    pub payment_id: [u8; 16],
    pub single_use: bool,
    pub amount: u64,
    pub unit: String,
    pub mints: Vec<String>,
    /// Chave P2PK por pagamento (x-only), `mycelium/v1/p2pk/{n}`.
    pub p2pk: [u8; 32],
    pub expires_at: u64,
    pub transports: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSend {
    pub payment_id: [u8; 16],
    /// Token `cashuB…`: mint, unidade e keyset já estão nele (fonte única de verdade).
    pub token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Received = 1,
    Redeemed = 2,
    Error = 3,
}

/// Códigos §7.4. `0` = sem erro.
pub const MAX_CODE: u64 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub payment_id: [u8; 16],
    pub token_send_id: [u8; 32],
    pub status: Status,
    pub code: u64,
    pub ts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LnInvoice {
    pub payment_id: [u8; 16],
    pub bolt11: String,
}

pub trait Body: Sized {
    const TYPE: Type;
    fn to_value(&self) -> Value;
    fn from_value(v: Value) -> Result<Self, PayError>;

    fn envelope(&self) -> Result<Envelope, PayError> {
        Envelope::new(Self::TYPE, &self.to_value())
    }
    /// Confere o tipo do envelope e decodifica o corpo.
    fn from_envelope(e: &Envelope) -> Result<Self, PayError> {
        if e.ty != Self::TYPE {
            return Err(bad("tipo de envelope diferente do esperado"));
        }
        Self::from_value(crate::cbor::decode(&e.body)?)
    }
}

impl Body for PayRequest {
    const TYPE: Type = Type::PayRequest;
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (0, Value::Bytes(self.payment_id.to_vec())),
            (1, Value::Uint(self.single_use as u64)),
            (2, Value::Uint(self.amount)),
            (3, Value::Text(self.unit.clone())),
            (4, strs(&self.mints)),
            (5, Value::Bytes(self.p2pk.to_vec())),
            (6, Value::Uint(self.expires_at)),
            (7, strs(&self.transports)),
        ])
    }
    fn from_value(v: Value) -> Result<Self, PayError> {
        let mut f = fields(v, &[0, 1, 2, 3, 4, 5, 6, 7])?.into_iter();
        let mut n = || f.next().unwrap();
        Ok(Self {
            payment_id: bytes(n())?,
            single_use: match uint(n())? {
                0 => false,
                1 => true,
                _ => return Err(bad("single_use deve ser 0 ou 1")),
            },
            amount: uint(n())?,
            unit: text(n())?,
            mints: texts(n())?,
            p2pk: bytes(n())?,
            expires_at: uint(n())?,
            transports: texts(n())?,
        })
    }
}

impl Body for TokenSend {
    const TYPE: Type = Type::TokenSend;
    fn to_value(&self) -> Value {
        Value::Map(vec![(0, Value::Bytes(self.payment_id.to_vec())), (1, Value::Text(self.token.clone()))])
    }
    fn from_value(v: Value) -> Result<Self, PayError> {
        let mut f = fields(v, &[0, 1])?.into_iter();
        Ok(Self { payment_id: bytes(f.next().unwrap())?, token: text(f.next().unwrap())? })
    }
}

impl Body for Receipt {
    const TYPE: Type = Type::Receipt;
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (0, Value::Bytes(self.payment_id.to_vec())),
            (1, Value::Bytes(self.token_send_id.to_vec())),
            (2, Value::Uint(self.status as u64)),
            (3, Value::Uint(self.code)),
            (4, Value::Uint(self.ts)),
        ])
    }
    fn from_value(v: Value) -> Result<Self, PayError> {
        let mut f = fields(v, &[0, 1, 2, 3, 4])?.into_iter();
        let mut n = || f.next().unwrap();
        let (payment_id, token_send_id) = (bytes(n())?, bytes(n())?);
        let status = match uint(n())? {
            1 => Status::Received,
            2 => Status::Redeemed,
            3 => Status::Error,
            _ => return Err(bad("status desconhecido")),
        };
        let code = uint(n())?;
        // erro exige código 1..=8 (8 = duplicate, informativo); os demais status, 0
        if code > MAX_CODE || (status == Status::Error) == (code == 0) {
            return Err(bad("código incompatível com o status"));
        }
        Ok(Self { payment_id, token_send_id, status, code, ts: uint(n())? })
    }
}

impl Body for LnInvoice {
    const TYPE: Type = Type::LnInvoice;
    fn to_value(&self) -> Value {
        Value::Map(vec![(0, Value::Bytes(self.payment_id.to_vec())), (1, Value::Text(self.bolt11.clone()))])
    }
    fn from_value(v: Value) -> Result<Self, PayError> {
        let mut f = fields(v, &[0, 1])?.into_iter();
        Ok(Self { payment_id: bytes(f.next().unwrap())?, bolt11: text(f.next().unwrap())? })
    }
}
