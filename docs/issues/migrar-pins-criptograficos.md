# Issue: migrar pins exatos (`=`) de crates criptográficas

Spec Sovereign Finance §12: pins exatos só em crates criptográficas, com issue de migração por pin.

| Pin | Onde | Por que fixo | Condição para soltar |
|---|---|---|---|
| `ml-dsa =0.1.2` | `crates/mycelium-zkp` (feature `license`) | `SigningKey::from_seed` e formato de chave do KAT FIPS 204 | revalidar `tests/mldsa_kat.rs` e `license::tests` numa versão nova, então trocar por `0.1` |
| `bulletproofs =4.0.0`, `merlin =3.0.0`, `curve25519-dalek-ng =4.1.1` | `mycelium-zkp` (feature `range-proof`) | fork `dalek-ng` | sair do fork antes de usar Bulletproofs (spec §10, G5) |
| `lightning-invoice =0.33.2` | `mycelium-zkp` (feature `bolt11`) | parse BOLT11 | alinhar com a versão do LDK no G4 |

Pendente: `secp256k1` convive em 0.29 (keyring, ghostid) e 0.31 (pay, nostr). Alinhar com a versão do `cdk` no G1.
