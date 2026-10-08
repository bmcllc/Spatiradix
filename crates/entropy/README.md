# 🎲 `entropy` — Coleta de Ruído Quântico e Entropia do Sistema

Módulo de alta segurança para coleta, mistura e fornecimento de números pseudo-aleatórios criptograficamente seguros (CSPRNG) para chaves de sessão e desafios pós-quânticos.

---

## 🎯 Arquitetura de Coleta

- **Múltiplas Fontes**:
  - `getrandom` do sistema operacional (Linux `/dev/urandom` / `getrandom(2)`).
  - Jitter de hardware e temporização de alta precisão de clocks de CPU (`RDTSC`).
  - Ruído ambiental e estocasticidade de rede (latência de pacotes recebidos).
- **Esponja Criptográfica**:
  - Mistura contínua de entropia via BLAKE3 e Keccak/SHA-3 para garantir avanço irreversível de estado (*Forward Secrecy*).
