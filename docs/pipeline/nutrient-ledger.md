# Nutrient Ledger Distribuído

## Liquidação por voucher assinado (implementado)

O fluxo de vouchers permite registrar uma transferência de nutrientes entre
nós sem uma câmara de compensação central:

```
Voucher {
    payer, payee: NodeId,
    nutrient: Nutrient, amount: u64,
    memo: String, clock: u64,
    payer_key: [u8; 32],   // ed25519 pub — NodeId::derive(payer_key) == payer
    signature: Vec<u8>,    // assina o payload canônico
}
```

1. Pagador debita o saldo local e broadcast `Envelope::VoucherRedeem`
   (ex.: `issue_hosting_voucher` paga 5 ATP pela réplica que nasceu).
2. Beneficiário verifica ligação chave↔payer + assinatura (`Voucher::verify`),
   credita `Ledger::redeem_voucher` e registra `ContentId` anti-replay.
3. Replay do mesmo voucher → `NutrientError::Replayed`.

Testemunho multi-nó: `scripts/scaling-demo.sh`
("voucher de hospedagem emitido" no pagador / "voucher resgatado" no beneficiário).

## Problema

Cada nó mantém seu `Ledger` local (ATP, Enzymes, Mycelia, Spores e Resilience).
O fluxo de voucher descrito acima trata pagamentos pontuais; a proposta abaixo
discute uma forma adicional de sincronizar saldos entre nós.

## Solução proposta: CRDT sobre gossip

Usar o mesmo padrão do Isotope: **LWW (Last-Writer-Wins) register** replicado
via gossip no tópico `mycelium/nutrients/v1`.

### Design

```
Envelope::BalanceSync {
    node_id: NodeId,
    balances: HashMap<Nutrient, u64>,
    clock: u64,            // timestamp UNIX
    delta: i64,            // último delta (para verificação)
    signature: [u8; 64],   // assinatura ed25519 do node_id
}
```

### Regras

1. Cada nó publica seu próprio balance no gossip a cada 60s
2. Ao receber um `BalanceSync`:
   - Verificar assinatura
   - Se `clock > local_clock` para aquele `node_id`: aceitar
   - Se `clock == local_clock`: usar o maior balance (LWW tiebreak)
3. Ao executar trabalho remoto (`MomentumReport`):
   - Emissor debita ATP da contraparte
   - Executor credita ATP na contraparte
   - Ambos publicam `BalanceSync` atualizado

### Envelope

```rust
enum Envelope {
    // ... existentes ...
    BalanceSync {
        node_id: NodeId,
        balances: HashMap<Nutrient, u64>,
        clock: u64,
    },
}
```

### Implementação proposta

1. **Ledger remoto** — `RemoteLedger` struct que mantém `HashMap<NodeId, (HashMap<Nutrient, u64>, u64)>`
2. **Tick de publish** — a cada 60s, publica `BalanceSync` no gossip
3. **Handle** — no `handle_envelope`, processa `BalanceSync` entrante
4. **MomentumReport** — ao receber report de trabalho remoto, ajusta balance local + publica sync

### CLI proposta

```bash
mycelium balance          # mostra balance local + remotos conhecidos
mycelium balance --peer   # mostra balance de um peer específico
```

## Riscos

- Sem consenso BFT: um nó malicioso pode mentir seu balance
- Solução futura: zk-proof de recursos ou consenso leve (Raft entre esporocarps)
- Para MVP, confiança baseada em reputação (Spores + Scent)
