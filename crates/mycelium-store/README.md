# 🏪 `mycelium-store` — Câmaras de Execução e App Store Soberana

Motor de execução de processos isolados (*Chambers*), gerenciamento de ciclo de vida de aplicações soberanas e controle de acesso via token criptográfico.

---

## 🎯 Arquitetura de Isolamento

- **Chambers**:
  - Ambientes de execução de serviços (Web, APIs, workers) associados a um `PID`, diretório isolado e porta local dedicada.
- **Autorização por Token**:
  - Chamadas de controle administrativo exigem cabeçalho `X-Control-Token` derivado criptograficamente com permissões restritas `0600`.
- **Registro de Pacotes e Aplicações**:
  - Catálogo de apps e CIDs assinados pelo autor, prontos para instalação e execução local ou na rede.
