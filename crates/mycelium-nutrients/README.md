# 🧪 `mycelium-nutrients` — Economia Bioquímica e Ledger de Nutrientes

O livro-razão contábil (*Nutrient Ledger*) que governa a circulação dos 5 nutrientes fundamentais na economia de subsistência e recompensa do Spatiradix.

---

## 🎯 As 5 Moedas Bioquímicas

1. **`ATP`**:
   - Energia computacional líquida para processamento, execução de WASM/Chambers e roteamento prioritário.
2. **`Enzymes`**:
   - Catalisadores de transações, validação e consenso causal.
3. **`Mycelia`**:
   - Reputação e staking biológico de nós da floresta.
4. **`Spores`**:
   - Crédito de armazenamento de longo prazo para blocos e dados persistentes.
5. **`Resilience`**:
   - Reserva de emergência concedida a nós que mantêm conexões estáveis sob censura ou condições adversas.

---

## 🔒 Segurança Criptográfica

- Todas as transferências utilizam assinaturas ed25519 (`SignedTransfer`).
- Proteção contra double-spending baseada em sequência causal monotônica e nonces anti-replay.
- Vouchers emitidos automaticamente em resposta a heartbeats válidos e prestação de serviço de relay/hospedagem.
