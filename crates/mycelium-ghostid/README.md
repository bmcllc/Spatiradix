# 👻 `mycelium-ghostid` — Identidade Efêmera e Anonimato L0

Módulo de identidade descartável, rotação de chaves e spoofing de endereço MAC local para privacidade em nível de enlace e transporte.

---

## 🎯 Capacidades

- **GhostID Efêmero**:
  - Geração de identidades criptográficas de curta duração para sessões interativas e circuitos VEIL.
- **Administração Local de MAC**:
  - Geração e rotação de endereços MAC válidos no padrão IEEE 802 (bits *Locally Administered* e *Unicast* habilitados), impedindo rastreamento por pontos de acesso Wi-Fi ou switches locais.
- **Isolamento de Credenciais**:
  - Impossibilidade de correlacionar a identidade pública do nó (`NodeId` de longo prazo) com sessões pontuais no plano cebola.
