# 🍄 MYCELIUM NETWORK & ECOSSISTEMA COSMIC / VEIL Ω
## Documentação Técnica Completa e Definitiva de Engenharia

> 📌 **Estado de validação**: ver [`docs/VALIDACAO.md`](VALIDACAO.md) para o nível de validação real e o número canônico de testes. Este documento descreve escopo e intenção de projeto; onde afirma prontidão, prevalece o registro em `VALIDACAO.md`.

> **Versão do Sistema**: 0.1.0-alpha  
> **Linguagem Base**: Rust (Edição 2021)  
> **Arquitetura**: Monorepo Descentralizado, Pós-Quântico, Orientado a Fisiologia Biológica  
> **Crates Documentados**: 30 crates e plataformas  
> **Data de Homologação**: 2026-09-24  

---

## 📑 Sumário Executivo

1. [Visão Geral & Filosofia Biológica](#1-visão-geral--filosofia-biológica)
2. [Arquitetura Sistêmica em Camadas (L0 a L4)](#2-arquitetura-sistêmica-em-camadas-l0-a-l4)
3. [Protocolo VEIL Ω — Onion Routing Pós-Quântico](#3-protocolo-veil-ω--onion-routing-pós-quântico)
4. [Ecossistema COSMIC — Computação Soberana & QEL Sharding](#4-ecossistema-cosmic--computação-soberana--qel-sharding)
5. [Sclerotium & Ghost Carrier — Dormência Biológica & Despertar Físico](#5-sclerotium--ghost-carrier--dormência-biológica--despertar-físico)
6. [Dicionário Exaustivo de Crates do Monorepo](#6-dicionário-exaustivo-de-crates-do-monorepo)
7. [Fronteira e Aplicações: Event Horizon, Vitrine & Streaming](#7-fronteira-e-aplicações-event-horizon-vitrine--streaming)
8. [Manual Operacional da CLI & Deployment](#8-manual-operacional-da-cli--deployment)

---

## 1. Visão Geral & Filosofia Biológica

A **Mycelium Network** é uma infraestrutura de comunicação, computação e armazenamento distribuída projetada para operar em ambientes hostis, redes sob censura e cenários de adversidade extrema (como o colapso de infraestruturas centralizadas da Internet comercial).

### A Metáfora Fúngica
Diferente das redes tradicionais baseadas no modelo cliente-servidor (hierárquico, frágil e centralizado), a Mycelium Network inspira-se no micélio biológico das florestas:

```
    [ Árvore / Cliente ]           [ Árvore / Cliente ]
            │                              │
    ┌───────▼──────────────────────────────▼───────┐
    │              REDE MICELIAL                   │
    │  (Hifas, Rizomorfos, Esporos e Nutrientes)   │
    └───────┬──────────────────────────────┬───────┘
            │                              │
    [ Nó / Esporocarpo ]           [ Nó / Sclerotium ]
      (Relay Público)                (Nó Dormente)
```

1. **Hifas (*Hyphae*)**: Conexões ponto-a-ponto ativas (QUIC, TCP, Noise, WebRTC, Nostr).
2. **Rizomorfos (*Rhizomorphs*)**: Feixes de alta capacidade que canalizam grandes volumes de tráfego entre clusters.
3. **Esporos (*Spores*)**: Fragmentos de dados imutáveis endereçados por conteúdo (BLAKE3 Content-Addressing).
4. **Nutrientes (*Nutrients*)**: O sangue econômico da rede (`ATP`, `Enzymes`, `Mycelia`, `Spores`, `Resilience`), recompensando nós que cooperam no transporte e armazenamento.
5. **Esporocarpo (*Sporocarp*)**: Nós com IP público ou servidores de borda que atuam como relays, sementes de bootstrap e pontos de presença CDN.
6. **Escleródio (*Sclerotium*)**: Estrutura dormente que preserva a identidade de nós desligados ou suspensos sem consumir energia de CPU.

---

## 2. Arquitetura Sistêmica em Camadas (L0 a L4)

A arquitetura do Mycelium organiza-se em 5 camadas complementares e intercambiáveis:

```mermaid
flowchart TD
    subgraph L4 ["L4 - Aplicações & Fronteira"]
        Singularity["Singularity (Event Horizon :7474)"]
        Media["Mycelium Media (HLS Streaming)"]
        Vitrine["Vitrine da Floresta / Console Web"]
        Store["Mycelium Store & Chambers"]
    end

    subgraph L3 ["L3 - Computação, Armazenamento & Metabolismo"]
        Cosmic["COSMIC Compute (VOID-00 ML-DSA-87)"]
        QEL["QEL Sharding K/N (Cauchy/RS)"]
        SporeBank["SporeBank (Armazenamento de Blocos BLAKE3)"]
        Nutrients["Nutrient Ledger (ATP, Enzimas, Esporos)"]
        Plasma["Plasma Sandbox (WASM & Processos)"]
    end

    subgraph L2 ["L2 - Anonimato, Ofuscação & Criptografia"]
        VeilLive["VEIL Ω LIVE (3-Hop Onion Routing)"]
        VeilMix["VEIL Ω MIX (Poisson Delay Mixnet)"]
        PQC["Criptografia Pós-Quântica (ML-KEM-1024, ML-DSA-87)"]
        ZKP["ZKP (Pedersen Commitments, Hashcash SHA-3)"]
        DistanceBridge["DistanceBridge (Multi-Canal & Evasão)"]
    end

    subgraph L1 ["L1 - Transporte & Malha Viva"]
        Hyphae["mycelium-hyphae (libp2p, QUIC, TCP, Noise)"]
        Kademlia["Kademlia DHT & Gossipsub v1.2"]
        NostrTrans["Nostr Transport (WSS Fallback)"]
        DTN["DTN Mailbox (Store-and-Forward)"]
    end

    subgraph L0 ["L0 - Substrato Físico, Identidade & Hardware"]
        Sclerotium["Sclerotium (Dormência Biológica)"]
        GhostCarrier["Ghost Carrier (Sub-GHz / WoL / 802.11ba)"]
        GhostID["GhostID (Identidade Efêmera & MAC Spoofing)"]
        Vacuum["Vacuum (Zero-Trace RAM Sanitizer)"]
        Entropy["Entropy (CSPRNG & Coleta de Ruído)"]
    end

    L4 --> L3
    L3 --> L2
    L2 --> L1
    L1 --> L0
```

---

## 3. Protocolo VEIL Ω — Onion Routing Pós-Quântico

O **VEIL Ω** é a evolução soberana dos protocolos de anonimato, concebido para superar as limitações históricas da rede Tor e do I2P contra adversários com computadores quânticos e capacidade de análise global de tráfego.

### 3.1. Criptografia em Camadas ML-KEM-1024 + AEAD ChaCha20-Poly1305
O circuito de 3 saltos (*Entry Guard* $\to$ *Relay* $\to$ *Exit*) encapsula cada pacote em 3 camadas concêntricas:

$$\text{Packet} = \mathcal{E}_{K_{\text{guard}}}(\mathcal{E}_{K_{\text{relay}}}(\mathcal{E}_{K_{\text{exit}}}(\text{Payload})))$$

- **Troca de Chaves**: Baseada em **ML-KEM-1024** (FIPS 203), com derivação de chave de sessão via HKDF-SHA256 e BLAKE3.
- **Cifragem de Fluxo**: **ChaCha20-Poly1305** com verificação de integridade a cada salto. Nenhum nó intermediário conhece a rota completa:
  - O **Guard** conhece a origem e o Relay, mas não o Exit nem o Payload.
  - O **Relay** conhece o Guard e o Exit, mas não a origem nem o destino final.
  - O **Exit** conhece o Relay e o destino final, mas não sabe quem originou o tráfego.

### 3.2. Os Dois Planos de Operação
1. **Plano LIVE (Baixa Latência)**:
   - Destinado a tráfego interativo (navegação HTTP via SOCKS5, chamadas RPC, streaming de áudio).
   - Otimizado para latências mínimas com multiplexação em streams independentes.
2. **Plano MIX (Alta Ofuscação / Mixnet Estocástica)**:
   - Destinado a mensagens assíncronas, propagação de blocos e transações confidenciais.
   - Aplica atrasos estocásticos modelados por um **Processo de Poisson** ($\lambda = 0.5 \text{ a } 2.0\text{ s}$).
   - Injeta pacotes de cobertura (*chaff traffic*) com tamanho fixo (1280 bytes), impedindo que a correlação de tamanho e tempo revele a identidade dos comunicadores.

### 3.3. As 7 Camadas Herdadas e Corrigidas do ET-COSMIC-OLD (GhostVPN)
O VEIL Ω incorpora e corrige as vulnerabilidades do antigo ecossistema ET-COSMIC:
- **Camada 0 — Identidade Efêmera**: `GhostID` rotacionado a cada sessão com MAC local administrado (IEEE 802).
- **Camada 1 — Fragmentação Segura**: O QEL particiona pacotes sem embutir a chave simétrica de sessão nos cabeçalhos.
- **Camada 2 — Transporte Fantasma**: `DistanceBridge` com envio concorrente por múltiplos canais (Ethernet + Wi-Fi + Nostr) e chaveamento anti-DPI.
- **Camada 3 — Consenso Causal e Anti-Replay**: Registro contínuo `HashChronicle` e validação por Cone de Luz relativístico ($|\Delta x| \le c \cdot \Delta t$).
- **Camada 4 — Execução Invisível**: Execução de chamadas dentro da sandbox confinada `plasma`.
- **Camada 5 — Ofuscação Temporal**: *Quantized Rate Control* (QRC) com padding estocástico constante.
- **Camada 6 — Zero-Trace em RAM & ZKP**: Uso do `vacuum` para sobrescrever chaves e compromissos de Pedersen com geradores independentes $G \neq H$.

### 3.4. Proxy SOCKS5 Local e Prevenção Anti-SSRF
- O nó sobe um proxy SOCKS5 local na porta `:9050`.
- **DNS Leak Prevention**: Requisições de nome de domínio nunca são resolvidas pelo DNS do sistema operacional local; os nomes são empacotados dentro do túnel cebola e resolvidos apenas no nó de saída.
- **Anti-SSRF (Server-Side Request Forgery)**: O nó de saída do VEIL bloqueia qualquer tentativa de conexão direcionada a endereços privados (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), CGNAT (`100.64.0.0/10`) e metadados de provedores de nuvem (`169.254.169.254`).

---

## 4. Ecossistema COSMIC — Computação Soberana & QEL Sharding

O **COSMIC** é a infraestrutura de computação distribuída e armazenamento particionado pós-quântico do Mycelium.

### 4.1. QEL (Quantum Entanglement Layer) Sharding
O particionamento de arquivos no COSMIC não utiliza replicação ingênua de arquivos completos. Em vez disso, aplica um esquema **$K$-de-$N$ de Codificação de Apagamento**:
- Um arquivo é dividido em $N$ fragmentos (*shards*) criptográficos.
- Qualquer subconjunto de $K$ fragmentos ($K < N$) é suficiente para reconstituir o arquivo original de forma exata.
- Menos de $K$ fragmentos fornecem **zero bits de informação** sobre o arquivo original (segurança da teoria da informação).

```text
                  Arquivo Original (ex.: 10 MB)
                               │
                       [ QEL Encoder ]
                     K = 3  |  N = 7
                               │
       ┌──────┬──────┬──────┬──┴───┬──────┬──────┬──────┐
       ▼      ▼      ▼      ▼      ▼      ▼      ▼
    Shard1 Shard2 Shard3 Shard4 Shard5 Shard6 Shard7
    (PeerA) (PeerB) (PeerC) (PeerD) (PeerE) (PeerF) (PeerG)
```

Se 4 de 7 nós forem destruídos ou desconectados, os 3 nós restantes reconstroem o arquivo instantaneamente.

### 4.2. Licenças Criptográficas VOID-00 (ML-DSA-87)
Para contratação e autorização de computação na malha, o COSMIC utiliza certificados **VOID-00**:
- Assinados com **ML-DSA-87** (Dilithium5 - Nível 5 do NIST).
- Define o detentor da licença (`holder_pubkey`), a validade (`valid_until`), o escopo de execução (`scope`) e o limite de consumo de `ATP`.
- Impossível de ser forjada mesmo com computadores quânticos munidos do algoritmo de Shor.

---

## 5. Sclerotium & Ghost Carrier — Dormência Biológica & Despertar Físico

A solução do Mycelium para o dilema de alta disponibilidade sem consumo de energia 24/7 é o protocolo **Sclerotium**:

```text
               ┌──────────┐
               │   LIVE   │ ◄─────── Acordar via WakeToken
               └────┬─────┘
                    │
                    ▼ Suspensão / Inatividade
               ┌──────────┐
      ┌─────── │ DORMANT  │ ◄─────── Standby / Receptor PHY ativo
      │        └────┬─────┘
      │             │
      │             ▼ Desligamento Total / Sem Sinal
      │        ┌──────────┐
      │        │  GHOST   │ ◄─────── Peers mantêm GhostLease
      │        └────┬─────┘
      │             │
      │             ▼ Expiração da GhostLease
      │        ┌──────────┐
      │        │   DEAD   │
      │        └──────────┘
```

### 5.1. Os Quatro Estados de Vitalidade
1. **`LIVE`**: CPU/RAM ativas, pilha libp2p conectada, provendo rotas, computação e armazenamento.
2. **`DORMANT`**: CPU principal suspensa; placa de rede (NIC) ou microcontrolador auxiliar de baixíssimo consumo (ESP32 / RP2040) monitora o canal de despertar.
3. **`GHOST`**: Nó sem conectividade; peers vizinhos mantêm sua **`GhostLease`** criptográfica assinada, atendendo consultas de localização de conteúdo, recebendo mensagens em mailboxes DTN e emitindo pulsos de despertar sob demanda.
4. **`DEAD`**: Tempo de vida da `GhostLease` expirado sem renovação.

### 5.2. O `WakeToken` Criptográfico Anti-DoS
Para impedir que ruído de rádio ou atacantes enviem pacotes falsos para forçar o despertar de máquinas (esgotando baterias), o pacote mágico de despertar requer um `WakeToken`:

$$\text{WakeToken} = \text{BLAKE3-MAC}(K_{\text{node}}, \text{requester} \parallel \text{epoch} \parallel \text{nonce} \parallel \text{reason})$$

A NIC ou o receptor auxiliar valida a assinatura antes de energizar a placa-mãe via linha PCIe / Wake-on-LAN.

---

## 6. Dicionário Exaustivo de Crates do Monorepo

O monorepo do Mycelium organiza-se em 30 crates e plataformas Rust:

| Crate | Diretório | Papel Principal | Dependências Chave |
|---|---|---|---|
| `mycelium-core` | `crates/mycelium-core` | Primitivos do sistema (`NodeId`, `ContentId`, `trait FruitingBody`, `Nutrient`) | `blake3`, `serde`, `thiserror` |
| `mycelium-hyphae` | `crates/mycelium-hyphae` | Malha P2P viva sobre libp2p, Kademlia DHT, Gossipsub, QUIC, TCP, DTN | `libp2p`, `tokio`, `sled` |
| `mycelium-veil` | `crates/mycelium-veil` | Protocolo VEIL Ω, circuitos onion 3 saltos, SOCKS5, Anti-SSRF, planos LIVE/MIX | `mycelium-pqc`, `chacha20poly1305`, `tokio` |
| `mycelium-sclerotium` | `crates/mycelium-sclerotium` | Fisiologia da dormência, `GhostLease`, `WakeToken`, portadora analógica | `ed25519-dalek`, `blake3`, `tokio` |
| `mycelium-pqc` | `crates/mycelium-pqc` | Criptografia pós-quântica (ML-KEM-768/1024, ML-DSA-65/87) | `fips203`, `fips204` |
| `mycelium-qel` | `crates/mycelium-qel` | Fragmentação e codificação de apagamento pós-quântica K-de-N | `reed-solomon-erasure`, `blake3` |
| `mycelium-ghostid` | `crates/mycelium-ghostid` | Identidade efêmera e administração local de endereços MAC | `rand`, `blake3` |
| `mycelium-distancebridge` | `crates/mycelium-distancebridge` | Transporte fantasma L2 multi-canal e evasão de censura | `tokio`, `async-trait` |
| `mycelium-zkp` | `crates/mycelium-zkp` | Provas de conhecimento zero, compromissos de Pedersen e PoW anti-Sybil | `curve25519-dalek`, `sha3` |
| `vacuum` | `crates/vacuum` | Limpeza e sanitização zero-trace de memória sensível em RAM | `zeroize` |
| `mycelium-pheromones` | `crates/mycelium-pheromones` | Identidade química, glândulas ed25519, trilhas de feromônios | `ed25519-dalek`, `blake3` |
| `mycelium-nutrients` | `crates/mycelium-nutrients` | Ledger bioquímico (`ATP`, Enzimas, Esporos) e liquidação de transferências | `serde`, `ed25519-dalek` |
| `mycelium-sporebank` | `crates/mycelium-sporebank` | Banco de esporos imutáveis endereçados por conteúdo | `sled`, `blake3` |
| `singularity` | `crates/singularity` | Event Horizon (`:7474`), balanceamento por gravidade e rizomorfos | `axum`, `hyper`, `tokio` |
| `mycelium-store` | `crates/mycelium-store` | Gerenciador de câmaras de execução de processos e apps | `tokio`, `serde_json` |
| `mycelium-media` | `crates/mycelium-media` | Fatiamento HLS e streaming P2P de áudio e vídeo soberano | `tokio`, `bytes` |
| `mycelium-node` | `crates/mycelium-node` | O organismo completo: une hifas, VEIL, esporos, console web e vitrine | Todas as crates acima |
| `mycelium-cli` | `cli/mycelium-cli` | Linha de comando do operador Mycelium | `clap`, `tokio`, `reqwest` |
| `cosmic-cli` | `crates/cosmic-cli` | CLI de computação soberana, sharding QEL e certificados VOID-00 | `clap`, `mycelium-qel` |
| `plasma` | `crates/plasma` | Runtime de sandbox WASM e micro-containers efêmeros | `wasmtime`, `tokio` |
| `thefield` | `crates/thefield` | Dinâmica de campo unificado e equilíbrio harmônico da malha | `nalgebra` |
| `entropy` | `crates/entropy` | CSPRNG e coletor de ruído de alta entropia | `getrandom`, `blake3` |
| `mycelium-nostr` | `crates/mycelium-nostr` | Integração com eventos Nostr (NIPs) e assinaturas Schnorr | `nostr`, `secp256k1` |
| `mycelium-nostr-transport` | `crates/mycelium-nostr-transport` | Transporte P2P invisível envelopado sobre relays Nostr WSS | `tokio-tungstenite` |
| `mycelium-ipfs` | `crates/mycelium-ipfs` | Ponte de interoperabilidade com nós e blocos IPFS/UnixFS | `cid`, `multihash` |
| `mycelium-tropical` | `crates/mycelium-tropical` | Álgebra tropical (semianéis min-plus) para cálculo de menores rotas | `num-traits` |
| `isotope` | `crates/isotope` | Exportação de telemetria e métricas Prometheus | `prometheus` |
| `giggs` | `crates/giggs` | Orquestrador de tarefas assíncronas periódicas e limpeza | `tokio` |
| `inertia` | `crates/inertia` | Persistência local e amortecimento de panes de energia | `serde_json` |
| `cosmoplanck` | `platforms/cosmoplanck` | SDK de integração da plataforma Planck com a malha | `reqwest` |

---

## 7. Fronteira e Aplicações: Event Horizon, Vitrine & Streaming

### 7.1. Event Horizon (`:7474`)
O crate `singularity` expõe o ponto de contato do micélio com a Internet pública:
- Roteamento transparente baseado em gravidade de nós.
- Balanceamento autônomo: nós que acumulam mais nutrientes `ATP` e menor latência absorvem maior fração do tráfego externo.

### 7.2. Vitrine da Floresta Iônica (`/vitrine`)
Interface visual de demonstração das capacidades soberanas da rede:
- **Hospedagem Web Soberana**: Servindo páginas estáticas e SPAs sem intermediários centrais.
- **Git Descentralizado**: Repositórios de código versionados por esporos BLAKE3.
- **Mycelium Video**: Demonstração de streaming P2P com fragmentação HLS e distribuição por esporos.
- **MicroEasy Studio**: Loja e runtime de preservação de jogos retrô e emulação soberana.

### 7.3. Mycelium Code Hub (`/hub/`) — O Hub e Forja Soberana de Repositórios
Interface web completa para substituição do GitHub e forjas centralizadas de código:
- **Catálogo de Repositórios**: Lista todos os repositórios persistentes na `RefStore` e snapshots do `SporeBank`.
- **Explorador de Arquivos & Código**: Navegação por diretórios em breadcrumbs e visualizador de código fonte com hashes BLAKE3 por folha.
- **Genealogia de Commits (Lineage DAG)**: Rastreamento do histórico completo de Plots a partir do nó raiz.
- **Chamber CI Integrado**: Validação e verificação de integridade automatizada em Vacuum Chambers com sanitização zero-trace de memória.
- **Comandos de Clone Prontos**: Integração com a CLI `mycelium repo clone --cid <CID> --dest <pasta>` e `mycelium hub`.

---

## 8. Manual Operacional da CLI & Deployment

### 8.1. Compilação do Workspace
```bash
# Compilar todo o ecossistema com verificações estritas
cargo build --release --workspace

# Executar testes unitários e de integração
cargo test --workspace

# Gerar documentação HTML completa
cargo doc --workspace --no-deps --open
```

### 8.2. Inicialização do Daemon
```bash
# Iniciar o nó completo com interface de console
./target/release/mycelium daemon --port 4001 --horizon 7474 --socks5 9050

# Abrir no navegador:
# http://localhost:7474/console
# http://localhost:7474/vitrine
```

### 8.3. Operações com o Protocolo VEIL Ω
```bash
# Consultar status do circuito cebola
./target/release/mycelium veil status

# Navegar através do proxy SOCKS5 pós-quântico
curl -x socks5h://127.0.0.1:9050 https://check.torproject.org
```

### 8.4. Operações com o COSMIC
```bash
# Particionar e enviar arquivo via QEL Sharding (3 de 7)
./target/release/cosmic put arquivo_sensivel.tar.gz --k 3 --n 7

# Baixar e reconstruir arquivo via ContentId
./target/release/cosmic get Qm... --out restaurado.tar.gz

# Emitir certificado de computação VOID-00 (ML-DSA-87)
./target/release/cosmic license issue --holder <pubkey> --scope "compute:wasm"
```

### 8.5. Operações com o Sclerotium (Dormência)
```bash
# Verificar suporte de hardware a Wake-on-LAN
./target/release/mycelium sclerotium hardware

# Gerar GhostLease para delegar presença a nós vizinhos
./target/release/mycelium sclerotium lease --ttl 86400

# Enviar pulso de despertar com WakeToken
./target/release/mycelium sclerotium wake --mac 00:11:22:33:44:55 --reason 1
```

---

> **Mycelium Network & COSMIC Ecosystem** — Projetado para a soberania digital contínua, privacidade inviolável e resiliência biológica perpétua.
