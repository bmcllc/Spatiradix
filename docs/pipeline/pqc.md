# Criptografia pós-quântica (PQC)

## ML-KEM-1024 (FIPS 203)

O crate oferece operações ML-KEM-1024 em Rust, sem dependência de WASM. A API
usa a biblioteca `ml-kem` para gerar chaves, encapsular e decapsular segredos.

**Crate:** `mycelium-pqc` em `crates/mycelium-pqc/`

```rust
pub fn mlkem_keygen() -> KemKeyPair
pub fn mlkem_encapsulate(public_key: &[u8]) -> Result<KemEncap, PqcError>
pub fn mlkem_decapsulate(private_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, PqcError>
```

- Chave pública: 1568 bytes
- Ciphertext: 1568 bytes
- Shared secret: 32 bytes

## Funções de handshake híbrido

**Módulo:** `mycelium-hyphae/src/pqc.rs` (feature `pqc-transport`)

O módulo também fornece funções que combinam um segredo Noise fornecido pelo
chamador com um segredo ML-KEM:

```
combined = blake3(noise_secret || pqc_shared_secret)
```

```rust
// Cliente: encapsula para a chave pública do servidor
let (client_hybrid, ciphertext) = pqc::client_handshake(&server_pk, &noise_secret)?;

// Servidor: decapsula o ciphertext do cliente
let server_hybrid = pqc::server_handshake(&private_key, &ciphertext, &noise_secret)?;

assert_eq!(server_hybrid.combined, client_hybrid.combined);
```

### Multiaddr

O endereço de escuta codificado pelo transporte usa
`/tcp/<porta>/unix/mycelium-pqc-<pk_hex>`. Para discagem, o parser também
aceita endereço IP ou DNS no multiaddr.

### PeerId

O transporte usa Noise com o par de chaves de identidade libp2p fornecido ao
construtor. A chave pública ML-KEM no endereço tem outra função: o handshake KEM.

### Testes

```
cargo test --features pqc-transport -p mycelium-hyphae
```

- `hybrid_handshake_roundtrip` — ambos os lados chegam no mesmo combined
- `different_noise_gives_different_combined` — noise_secret diferente → combined diferente
- `pqc_multiaddr_roundtrip` — encode/decode de multiaddr

## Transporte libp2p

O módulo `pqc.rs` também implementa `PqcTransport` para TCP e KEM. Com a
feature `pqc-transport`, o construtor da malha registra esse transporte no
swarm e usa Noise e Yamux. Essa implementação é distinta das funções auxiliares
de handshake mostradas acima.

O registro da feature e os testes locais não comprovam segurança ou
interoperabilidade em redes reais. Consulte [Validação](../VALIDACAO.md) para
os limites de testes do projeto.
