#!/usr/bin/env python3
"""Verificador independente do envelope v1 (spec Sovereign Finance §7.1), sem código Rust.
Usa cbor2 (decodificação + checagem de forma canônica), blake3 e BIP-340 de referência.
    pip install cbor2 blake3 && python3 verify_vectors.py
O vetor híbrido só tem a estrutura conferida: ML-KEM não está implementado aqui."""
import hashlib, json, pathlib, sys
import cbor2
from blake3 import blake3

V = pathlib.Path(__file__).resolve().parent.parent / "tests" / "vectors"
TYPE_NAMES = {1: "PayRequest", 2: "TokenSend", 3: "Receipt", 4: "LnInvoice"}

# --- BIP-340 (verificação, do código de referência do BIP) ---
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and a[1] != b[1]: return None
    lam = (3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) if a == b
           else (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P)) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)

def mul(pt, k):
    r = None
    for i in range(256):
        if (k >> i) & 1: r = add(r, pt)
        pt = add(pt, pt)
    return r

def tagged(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()

def lift_x(x):
    if x >= P: return None
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    if pow(y, 2, P) != (pow(x, 3, P) + 7) % P: return None
    return (x, y if y % 2 == 0 else P - y)

def bip340_verify(pub, msg, sig):
    pt = lift_x(int.from_bytes(pub, "big"))
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if pt is None or r >= P or s >= N: return False
    e = int.from_bytes(tagged("BIP0340/challenge", sig[:32] + pub + msg), "big") % N
    R = add(mul(G, s), mul(pt, N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r

# --- envelope ---
def check(cond, what):
    if not cond: sys.exit(f"FALHOU: {what}")
    print(f"ok   {what}")

def verify_envelope(v):
    wire = bytes.fromhex(v["wire"])
    env = cbor2.loads(wire)
    check(cbor2.dumps(env, canonical=True) == wire, "envelope é CBOR canônico (RFC 8949 §4.2.1)")
    check(sorted(env) == [0, 1, 2, 3] and env[0] == 1, "chaves 0..3 e v=1")
    body = env[2]
    check(body.hex() == v["body"], "body")
    check(cbor2.dumps(cbor2.loads(body), canonical=True) == body, "body é CBOR canônico")
    check(blake3(body).hexdigest() == v["id"], "id = BLAKE3(body)")
    ctx = "mycelium/v1/pay/sig/" + TYPE_NAMES[env[1]]
    msg = blake3(body, derive_key_context=ctx).digest()
    check(msg.hex() == v["msg"], "msg = derive_key(domínio‖tipo, body)")
    check(len(env[3]) >= 1, "ao menos uma assinatura")
    for s in env[3]:
        check(sorted(s) == [0, 1, 2] and s[0] == 1, "Sig alg=BIP340")
        check(bip340_verify(s[1], msg, s[2]), "assinatura BIP-340 válida")
    tampered = bytearray(body); tampered[0] ^= 1
    check(not bip340_verify(env[3][0][1], blake3(bytes(tampered), derive_key_context=ctx).digest(), env[3][0][2]),
          "corpo adulterado invalida a assinatura")

def verify_hybrid_shape():
    wire = bytes.fromhex((V / "hybrid_v1.hex").read_text().strip())
    check(wire[:2] == b"\x01\x01", "híbrido: v=1, pq_flag=1")
    check(len(wire) == 2 + 32 + 1568 + len(b"envelope-bytes-go-here") + 16,
          "híbrido: E(32) + ct ML-KEM-1024(1568) + AEAD(msg+tag 16)")

if __name__ == "__main__":
    verify_envelope(json.loads((V / "envelope_v1.json").read_text()))
    verify_hybrid_shape()
    print("tudo ok")
