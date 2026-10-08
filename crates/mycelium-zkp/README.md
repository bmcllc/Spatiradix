# 🔒 `mycelium-zkp` — Provas de Conhecimento Zero e Compromissos de Pedersen

Módulo criptográfico de provas de conhecimento zero (ZKP), compromissos homomórficos de Pedersen e algoritmos anti-Sybil.

---

## 🎯 Primitivos

- **Compromissos de Pedersen Independentes**:
  - Geração de compromissos $C = r \cdot G + v \cdot H$ com geradores $G$ e $H$ estritamente independentes (resolvendo vulnerabilidades históricas de logaritmo discreto).
- **PoW Anti-Sybil (Hashcash SHA-3)**:
  - Provas de trabalho computacional leves para mitigar spam na emissão de feromônios e conexões na rede.
- **Verificação Zero-Trace**:
  - Validação de saldo e autorizações sem expor valores ou identidades subjacentes.
