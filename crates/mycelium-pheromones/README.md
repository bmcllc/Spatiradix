# 🧪 `mycelium-pheromones` — Identidade Química e Feromônios

Sistema de identidade criptográfica descentralizada, reputação orgânica e comunicação química estocástica no Mycelium Network.

---

## 🎯 Componentes Centrais

- **`Gland`**:
  - A glândula criptográfica do nó, responsável por guardar a chave privada ed25519 e assinar todas as emissões bioquímicas (`sign_bytes()`, `germinate()`, `from_seed()`).
- **`Pheromone`**:
  - Mensagem de presença e estado emitida periodicamente pelo nó, contendo:
    - `scent`: O odor/reputação acumulada do nó.
    - `trail`: O rastro de trabalho e interações recentes.
    - `decay_secs`: Tempo de meia-vida para evaporação química natural do anúncio na rede.
- **Alarmes Químicos**:
  - Mecanismo de difusão rápida de alerta em caso de detecção de nós maliciosos, ataques Sybil ou censura ativa.
