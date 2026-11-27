# 🕳️ `singularity` — Event Horizon e Roteamento por Gravidade

Ponto de entrada HTTP/HTTPS e WebSocket público do Spatiradix (*The Event Horizon*), roteando tráfego do mundo externo para câmaras de nós internos com balanceamento bio-gravitacional.

---

## 🎯 Arquitetura

O `singularity` atua como o portal limítrofe entre a internet legada e o micélio soberano:
- **Porta Padrão**: `:7474` (Event Horizon).
- **Roteamento por Gravidade**:
  - Cada câmara (*Chamber*) e nó possui uma métrica de **Gravidade** calculada a partir de sua capacidade computacional, tempo de resposta, disponibilidade e acúmulo de nutrientes ATP.
  - O proxy HTTP roteia requisições dinamicamente para o nó com maior atração gravitacional.
- **Rizomorfos**:
  - Túneis bidirecionais de alta capacidade entre o Horizon e instâncias do daemon local/remoto.
- **Roteamento de Host e Domínio**:
  - Mapeamento dinâmico de domínios (ex.: `*.mycelium`, `*.sol`) para CIDs ou processos em execução.
