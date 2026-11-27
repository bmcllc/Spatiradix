# Arquitetura geral do Mycelium Network

> Este documento reúne a arquitetura proposta e descrições dos componentes.
> Para resultados de testes e limites conhecidos, consulte [Validação](../VALIDACAO.md).
> O rótulo `0.2.0-Sovereign` abaixo identifica esta documentação; o `Cargo.toml`
> raiz e a [documentação completa](../DOCUMENTACAO_COMPLETA.md) usam outros rótulos.

> **Versão**: 0.2.0-Sovereign  
> **Classificação**: Documentação de Engenharia e Especificação Sistêmica  
> **Status**: documento de arquitetura; consulte Validação para o estado do projeto.

---

## 1. Visão geral

O Mycelium Network é um projeto em Rust para conectar nós em uma rede P2P,
compartilhar conteúdo e executar serviços distribuídos. Seus componentes usam
nomes inspirados em fungos: por exemplo, as hifas conectam nós e o Spore Bank
armazena conteúdo.

A arquitetura busca reduzir a dependência de infraestrutura centralizada. Os
nós usam identidades criptográficas, o conteúdo pode ser endereçado por hash
e o Sclerotium trata de dormência e retomada. Descoberta, disponibilidade e
privacidade dependem da configuração e das condições da rede; não há garantia
de tolerância total a falhas ou partições.

---

## 2. As Camadas do Organismo (L0 a L4)

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ CAMADA 4: APLICAÇÕES E EXPERIÊNCIA DO USUÁRIO (APPs)                        │
│   • Vitrine da Floresta (Hub Web Central)                                   │
│   • Mycelium Video (Streaming P2P em Chunks BLAKE3)                         │
│   • Mycelium Store (App Store Descentralizada & Emulação)                   │
│   • COSMIC CLI (Computação e Armazenamento Pós-Quântico)                    │
│   • ErgotOS & Console Singularity                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ CAMADA 3: THE LATTICE PIPELINE (COMPUTAÇÃO & ORQUESTRAÇÃO)                  │
│   • Giggs (Plots, DAG de commits, código soberano sem git)                  │
│   • TheField (Signals, ressonância, quóruns de execução)                    │
│   • Inertia (Vectors, compilação, testes, atestações assinadas)             │
│   • Vacuum (Chambers, voids, isolamento com Bubblewrap e cgroups)           │
│   • Plasma (Ions, nuvem de carga, órbitas, escalonamento elástico)          │
│   • Singularity (Event Horizon, proxy reverso, roteamento de órbitas)       │
├─────────────────────────────────────────────────────────────────────────────┤
│ CAMADA 2: PRIVACIDADE, SEGURANÇA E CRIPTOGRAFIA AVANÇADA                    │
│   • Veil Ω (Onion Routing pós-quântico de 3 saltos, Anti-SSRF, SOCKS5)     │
│   • Mycelium PQC (ML-KEM-768/1024 para troca de chaves pós-quântica)        │
│   • Mycelium ZKP (Provas de conhecimento zero, hardware binding, licenças)  │
│   • Entropy (Shamir Secret Sharing com meia-vida / GF(256))                 │
│   • Isotope (Anti-entropia, CRDT LWW sobre gossip de hifas)                 │
├─────────────────────────────────────────────────────────────────────────────┤
│ CAMADA 1: SUBSTRATO MICELIAL (REDES, DADOS & ECONOMIA)                      │
│   • Mycelium Hyphae (Transporte libp2p QUIC/TCP, Kademlia DHT, Gossipsub)   │
│   • Mycelium Pheromones (Identidade ed25519, trails, scents, alarmes)       │
│   • Mycelium Nutrients (Ledger metabólico: ATP, Enzymes, Resilience)        │
│   • Mycelium SporeBank (Armazenamento em disco + indexação DHT)             │
│   • Mycelium Nostr & Nostr-Transport (Bypass CGNAT via WSS outbound)        │
│   • Mycelium QEL (Quantum-resistant Erasure Layer, fragmentação K/N)        │
├─────────────────────────────────────────────────────────────────────────────┤
│ CAMADA 0: FISIOLOGIA FÍSICA & PORTADORAS (PHY / SCLEROTIUM)                 │
│   • Sclerotium (Estados biológicos: Sprouting, Alive, Dormant, Ghost, Dead) │
│   • Ghost Carrier (Ethernet WoL, Wi-Fi WoWLAN, Sub-GHz RF / LoRa, MCU UART) │
│   • Selective Wake (WakeToken anti-DoS / anti-vampire attacks via HMAC)     │
│   • GhostLease (Delegação criptográfica temporária a proxies vizinhos)      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Fluxo de Vida e Computação Ponta a Ponta

### 3.1. Publicação e Execução (The Lattice Pipeline)
1. **Sementeira (Sow)**: O desenvolvedor empacota arquivos em um `giggs::Plot`. Cada arquivo vira uma `Leaf` content-addressed pelo hash BLAKE3.
2. **Propagação (Gossip & DHT)**: O Plot é anunciado via Kademlia DHT (`spore/<ContentId>`) e replicado pelas hifas vizinhas.
3. **Sinal de Computação (Signal)**: Um `thefield::Signal` é emitido na rede solicitando build, teste ou processamento do Plot com um quórum de nós.
4. **Ressonância**: Nós que possuem recursos ociosos (`Resources { cpu, ram, storage, bandwidth }`) assinam e ressoam com o Signal.
5. **Execução Segura (Inertia & Vacuum)**: Quando o quórum fecha, o `inertia::Vector` executa o build/teste dentro de uma `vacuum::Chamber` isolada por **Bubblewrap** (`bwrap`), gerando uma atestação criptográfica assinada.
6. **Frutificação (Plasma & Singularity)**: O serviço vira um `plasma::Ion` e passa a ser roteado pelo `singularity::EventHorizon` na porta HTTP `:7474`.

### 3.2. Ciclo de Dormência e Despertar (Sclerotium)
1. O nó principal decide economizar energia ou o usuário fecha a tampa do notebook.
2. O nó gera e assina uma `GhostLease` conferindo permissões a proxies vizinhos (responder por CIDs replicados, acolher mensagens DTN Mailbox).
3. O computador entra em estado `DORMANT` (ACPI S3/S4) com a placa de rede ou MCU auxiliar escutando em baixa potência (1W a 50µW).
4. Quando uma requisição urgente chega, um vizinho envia um `ImpulsePacket` de 50 bytes contendo um `WakeToken` autenticado com HMAC e nonce inédito.
5. O hardware desperta (`ALIVE`), atende à demanda e pode voltar a hibernar.

---

## 4. O Sistema Imunológico e Econômico (Nutrient Cycling)

O Mycelium não utiliza moedas fiduciárias nem tokens inflacionários emitidos por mineradores industriais. O valor na rede é estritamente atrelado ao trabalho computacional e à oferta física:

| Nutriente | Moeda Bioquímica | Como é Ganho | Utilidade no Sistema |
|---|---|---|---|
| **ATP** | Energia celular | Executando Vectors de CPU do Inertia | Pagar por computação e prioridade de execução |
| **Enzymes** | Catalisador de acesso | Contribuindo memória RAM para Chambers | Acesso rápido a nós rápidos e banda sem fila |
| **Mycelia** | Direitos de espaço | Doando armazenamento em disco para o SporeBank | Direito a persistir dados na DHT global |
| **Spores** | Governança e sementes | Relaying de pacotes de rede e banda pública | Votação em quóruns e semeadura de repositórios |
| **Resilience** | Imunidade e saúde | Uptime estável e honestidade no protocolo | Imunidade a alarmes de banimento e evasão de churn |

---

## 5. Matriz de Conectividade e Membrana Fisiológica

Para garantir que nós residenciais consigam conversar com nós de data center sem intervenção manual de roteadores, o Mycelium adota a **Política de Membrana**:

```text
               ┌──────────────┐
               │  Esporocarp  │ (WAN Inbound verificado / Relay público)
               └──────▲───────┘
                      │ Relay Circuit v2
       ┌──────────────┴──────────────┐
       ▼                             ▼
┌──────────────┐              ┌──────────────┐
│   Floresta   │              │    Folha     │
│ (IPv6 Global │              │ (NAT/CGNAT   │
│  sem NAT)    │              │  Outbound)   │
└──────────────┘              └──────────────┘
```

- **Folha (NAT/CGNAT residencial)**: Estabelece túneis de saída via `QUIC`, `WebRTC ICE` ou `Nostr-Transport` (porta 443 WSS) até Esporocarpos.
- **Floresta (IPv6 global)**: Comunicação direta ponto-a-ponto sem NAT.
- **Esporocarp (Borda aberta)**: Nós voluntários que servem de relay comunitário e ganham crédito de **ATP** por gigabyte trafegado.
