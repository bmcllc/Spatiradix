# Mycelium Bank: arquitetura

## Visão

O Mycelium Bank reúne identidade, contas, razão, livro de ordens e estruturas
de pagamento sobre o Mycelium Network. O estado do banco é mantido localmente;
o transporte pode trocar mensagens com outros nós. O fluxo NFC descrito abaixo
usa uma interface abstrata: a integração com hardware ainda estava pendente
na etapa registrada ao final deste documento.

## Princípios

- **Soberania de dados**: nenhuma conta/saldo pode ser alterado por terceiro sem
  recibo assinado disponível localmente.
- **PQC por padrão**: ML-KEM-1024 para confidencialidade em trânsito, Ed25519
  para autoria (ML-DSA será adotado quando a crate estabilizar — sem stub).
- **Auditabilidade**: toda mutação econômica gera um `Entry` em um ledger
  hash-encadeado (BLAKE3) verificável com `audit()`.
- **Offline-first**: `NullTransport` permite operação sem rede; a malha é
  opcional e pluggable via `MyceliumTransport`.

## Módulos (`crates/mycelium-bank`)

| Módulo | Responsabilidade |
|---|---|
| `identity` | `SovereignWallet`: ed25519 + ML-KEM, conta derivada por BLAKE3. |
| `assets` | `Asset` (BRL/USD/USDC/BTC/ETH/MYC/TOKEN) e `Amount` em micros. |
| `accounts` | `Account`, `Portfolio`, crédito/débito/transferência. |
| `ledger` | `SovereignLedger` hash-encadeado (jsonl), `audit()`. |
| `orders` | `OrderBook` com matching price-time. |
| `payments` | `PaymentIntent`, `NfcProof`, `PaymentReceipt`. |
| `nfc` | Trait `NfcTap` + `TapFrame` (binário compacto). |
| `network` | `BankMessage`, `MyceliumTransport`, `NullTransport`. |
| `error` | `BankError`. |

## Fluxo de pagamento NFC (tap-to-pay)

1. Pagador cria `PaymentIntent` (from, to, amount, nonce).
2. Pagador assina intent com ed25519 → `NfcProof`.
3. Encapsula segredo ML-KEM para a chave pública do recebedor (confidencialidade).
4. `TapFrame::encode` serializa intent + proof.
5. Tap NFC transmite ao recebedor, que decodifica e `validate_nfc_payment`.
6. Recebedor grava `PaymentNfc` no ledger hash-encadeado.

## Integração com Mycelium Network

`MyceliumTransport` é o único ponto de contato com a malha. Implementações
concretas devem publicar `BankMessage` via gossipsub e persistir Plot/layer quando
necessário. `NullTransport` mantém o banco operável em modo soberano offline.

## Segurança

- Chaves privadas (signing + kem) nunca saem do nó; `SovereignWallet` zera
  memória no Drop.
- Todo pagamento exige assinatura verificável do pagador; nonce impede replay.
- Ledger hash-encadeado detecta adulteração (`audit()`).
- Recibos são locais; promoção a "paid demand" só com confirmação de
  provedor (padrão `mycelium-economy`).

## Build e testes

```bash
cargo build -p mycelium-bank
cargo test  -p mycelium-bank
```

## Estado após rodada de extensão (contornos implementados)

- `MyceliumTransport` real disponível via feature `transport-mycelium`
  (`HyphaeTransport` sobre `HyphaeNode`/`broadcast_lattice`).
- Persistência local: `BankStore` (`accounts.json` + ledger hash-encadeado).
- ML-DSA pós-quântico disponível via feature `pqc-ml-dsa` (crate `ml-dsa`),
  com assinatura composta descrita em `pqc::ml_dsa`.
- NFC continua abstrato por trait + IPC externo (hardware segue pendente).
- Matching permanece in-memory, mas com `OrderBook` persistível e estrutura
  para leveis por preço; compliance/KYC continua responsabilidade operacional.
