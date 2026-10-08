# 🌌 `mycelium-qel` — Quantum Entanglement Layer (Fragmentação Segura)

Camada de fragmentação criptográfica, dispersão de informação e codificação de apagamento pós-quântica do ecossistema COSMIC / Mycelium.

---

## 🎯 Arquitetura QEL

O QEL assegura que nenhum nó intermediário na rede ou observador físico possa reconstruir dados observando canais individuais:
- **Sharding K-de-N (Cauchy / Reed-Solomon)**:
  - Um bloco de dados é fatiado em $N$ fragmentos criptográficos independentes.
  - A recuperação requer estritamente $K$ fragmentos válidos ($K \le N$).
- **Isolamento de Chaves de Sessão**:
  - Ao contrário de implementações antigas, o QEL moderno não vaza a chave de sessão em nenhum cabeçalho de fragmento.
- **Verificação Criptográfica de Blocos**:
  - Cada fragmento possui autenticação AEAD ChaCha20-Poly1305 e prova de integridade BLAKE3.
