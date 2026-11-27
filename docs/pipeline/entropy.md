# Entropy — Segredos com meia-vida

## Conceito

O cofre divide um segredo em **Shades** usando Shamir Secret Sharing sobre
GF(256). São necessárias M das N partes para reconstruí-lo. O daemon possui
mensagens de oferta e solicitação por gossip, mas o fluxo atual de `shatter`
mantém todas as partes no cofre local e anuncia ofertas com o próprio nó como
custodiante. Isso não comprova custódia independente em nós remotos.

Ao reconstruir o segredo, `ChaosKey` mantém os bytes em memória e limita por
quanto tempo `reveal()` permite lê-los. O prazo padrão é de 30 segundos.
Expirar não apaga os bytes automaticamente: `evaporate()` precisa ser chamado
para zerar o buffer mantido pela chave.

## Implementação

- **Crate:** `entropy` em `crates/entropy/`
- **Shamir real sobre GF(256)** com polinômio irredutível `x^8 + x^4 + x^3 + x + 1` (0x11b)
- **Aritmética:** gf_add (XOR), gf_mul (shift-and-add), gf_inv (a^254 via exp squaring)
- **Lagrange interpolation** em x=0 para reconstrução

### Tipos

```rust
pub struct Shade {
    pub index: u8,        // x ∈ [1, 255] no polinômio
    pub shares: Vec<u8>,  // y = f(x) para cada byte do segredo
}

pub struct ChaosKey {
    bytes: Vec<u8>,        // segredo materializado
    born: Instant,         // momento da materialização
    half_life: Duration,   // default 30s
}

pub struct Vault {
    custody: Vec<(NodeId, Shade)>,  // shades custodidas
}
```

### Funcionalidades existentes

- `Vault::shatter(secret, m, n)` — divide segredo em N shades (M necessárias)
- `ChaosKey::materialize(shades, threshold)` — reconstrói o segredo
- `ChaosKey::reveal()` — lê o segredo se não evaporou
- `ChaosKey::evaporate()` — zera o buffer imediatamente
- `Vault::hold(custodian, shade)` — custodia uma shade
- `Vault::gather()` — coleta shades custodiadas
- CLI: `mycelium entropy shatter|reconstruct|status`
- Organismo: `Vault` integrado, comandos no controle socket

### Limites do fluxo atual

- As mensagens `ShadeOffer` e `ShadeRequest` existem, mas a atribuição de
  custodiantes remotos e a coleta confiável exigem validação adicional.
- A custódia local de todas as partes significa que o limiar não protege o
  segredo contra comprometimento desse nó.
- Verifique proteção em trânsito e persistência antes de usar dados sensíveis.

## CLI

O exemplo usa um texto fictício. Argumentos de linha de comando podem aparecer
no histórico do shell e na lista de processos; não passe segredos reais assim.

```bash
# Fragmenta um segredo em 5 shades (precisa de 3 pra reconstruir)
mycelium entropy shatter --secret "minha-chave-super-secreta" -k 3 -n 5

# Reconstrói o segredo
mycelium entropy reconstruct -k 3

# Mostra shades em custódia
mycelium entropy status
```

## Testes

```
cargo test -p entropy
```

Testes cobrem: roundtrip, threshold insuficiente, half-life evaporação,
bad threshold, vault hold+gather.

## Esboço histórico da integração com hifas

O formato abaixo é um esboço, não o `Envelope` atual. Veja
`crates/mycelium-node/src/protocol.rs` e `organism.rs` para a implementação.

```rust
// Envelope (protocol.rs)
enum Envelope {
    // ... existentes ...
    ShadeOffer {
        shard_index: u8,
        total: u8,
        shade_bytes: Vec<u8>,
        custodian: NodeId,
    },
    ShadeRequest {
        threshold: u8,
        requester: NodeId,
    },
}
```

1. **Shatter local** → distribui shades via `ShadeOffer` para peers aleatórios
2. **Peer recebe** → `hold()` a shade no vault local + persiste
3. **Reconstruct** → envia `ShadeRequest` → peers respondem com `ShadeOffer` →
   `gather()` + `materialize()`
