# 🌿 `mycelium-core` — Núcleo e Primitivos Substratais

Tipos de dados fundamentais, identificadores criptográficos, estruturas metabólicas e o trait central [`FruitingBody`] do Mycelium Network.

---

## 🎯 Tipos e Estruturas Fundamentais

- **`NodeId`**:
  - Identificador único de 32 bytes de um nó na malha, derivado via hash BLAKE3 da sua chave pública criptográfica (`derive(pubkey)`).
- **`ContentId`**:
  - Hash BLAKE3 de conteúdo imutável (*Content-Addressing*), formatado com prefixo canônico `Qm...` em representação legível.
- **`Resources`**:
  - Vetor de recursos computacionais ofertados ou requisitados:
    - `cpu_cores`: Quantidade de núcleos lógicos de processamento.
    - `ram_mib`: Memória volátil disponível em MiB.
    - `storage_gib`: Armazenamento persistente em GiB.
    - `bandwidth_mbps`: Vazão de rede simétrica em Mbps.
- **`Nutrient`**:
  - As 5 unidades metabólicas do micélio: `Atp`, `Enzymes`, `Mycelia`, `Spores`, `Resilience`.
- **`Membrane`**:
  - Modos de acoplamento físico e tráfego: `Floresta` (completo), `Raiz` (serviços de ancoragem e infra), `Folha` (cliente leve móvel), `Esporocarp` (relay público / borda CDN).
- **`trait FruitingBody`**:
  - Contrato que todo serviço descentralizado implementa para "brotar" sobre o substrato Mycelium, recebendo eventos de ciclo de vida e trocas de nutrientes.
