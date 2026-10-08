# ⚡ `mycelium-nostr` & `mycelium-nostr-transport` — Barramento Nostr e Transporte Descentralizado

Integração nativa com o protocolo Nostr (NIPs) e transporte assíncrono sobre relays soberanos e públicos.

---

## 🎯 Arquitetura

- **Eventos Nostr Customizados**:
  - Encapsulamento de feromônios, anúncios de nós e mensagens DTN em eventos assinados (NIP-01, NIP-04, NIP-44).
- **Transporte Alternativo Resiliente**:
  - Quando portas P2P convencionais (QUIC/TCP) sofrem bloqueio por provedores, o Mycelium utiliza relays Nostr globais via WebSocket seguro (WSS) como meio de transporte invisível de pacotes fragmentados.
- **Assinaturas Schnorr e Chaves secp256k1**:
  - Interoperabilidade total com chaves Nostr (`npub` / `nsec`).
