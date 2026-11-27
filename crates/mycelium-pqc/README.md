# 🛡️ mycelium-pqc — Criptografia Pós-Quântica

Primitivos pós-quânticos nativos usados pelo Spatiradix.

## Implementado hoje

- **ML-KEM-1024 (FIPS 203 / Kyber)**
  - geração de par de chaves;
  - encapsulamento;
  - decapsulamento;
  - restauração do par a partir da chave privada;
  - zeroização do segredo compartilhado em memória.

O transporte PQC do `mycelium-hyphae` reutiliza este crate.

## Ainda não implementado neste crate

- ML-KEM-768;
- ML-DSA-65;
- ML-DSA-87;
- ratchet híbrido X25519 + ML-KEM.

Esses itens não possuem stubs que fingem suporte. O código-fonte e o `Cargo.toml`
devem ser considerados a fonte de verdade sobre os algoritmos atualmente disponíveis.
