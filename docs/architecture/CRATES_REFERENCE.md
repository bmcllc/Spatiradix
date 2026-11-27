# Referência de crates do Mycelium Network

> Esta referência descreve os componentes documentados aqui. Para a lista
> atual de pacotes, consulte o [`Cargo.toml`](../../Cargo.toml) do workspace.
> **Linguagem**: Rust (Edição 2021)  

---

## 1. Núcleo, Redes e Transporte (Substrato Básico)

### 1.1. `mycelium-core`
- **Caminho**: [`crates/mycelium-core`](../../crates/mycelium-core)
- **Papel**: Tipos primitivos compartilhados por todo o ecossistema.
- **Tipos Fundamentais**:
  - `NodeId(pub [u8; 32])`: Identificador canônico do nó, derivado via BLAKE3 da chave pública ed25519.
  - `ContentId(pub [u8; 32])`: Endereço content-addressed (prefixo `Qm...` em hex) usado por plots, arquivos e dados.
  - `Resources`: Estrutura de contribuição (`cpu_cores`, `ram_mib`, `storage_gib`, `bandwidth_mbps`).
  - `Nutrient`: Enum das 5 moedas bioquímicas (`Atp`, `Enzymes`, `Mycelia`, `Spores`, `Resilience`).
  - `Vitality`: Estado vital de um fruto (`Sprouting`, `Fruiting`, `Dormant`, `Decomposed`).
  - `Membrane`: Papel fisiológico de conectividade de rede (`Floresta`, `Raiz`, `Folha`, `Esporocarp`).
  - `trait FruitingBody`: Interface implementada por qualquer serviço que brota do micélio.

---

### 1.2. `mycelium-hyphae`
- **Caminho**: [`crates/mycelium-hyphae`](../../crates/mycelium-hyphae)
- **Papel**: Camada de rede e transporte vivo sobre `libp2p`.
- **Funcionalidades**:
  - Conexões ponto-a-ponto via **QUIC** (UDP) e **TCP + Noise + Yamux**.
  - Roteamento e busca de peers via **Kademlia DHT**.
  - Barramento de mensagens e fofoca em tempo real via **Gossipsub** (tópicos de feromônios e lattice).
  - Descoberta em rede local via **mDNS**.
  - **Relay Mesh (Circuit Relay v2)** para conectar nós atrás de NAT/CGNAT.
  - **Store-and-Forward / DTN Mailbox**: Armazém de mensagens e bundles tolerante a reboots e partições de rede (`DtnBundleStore`).
  - Suporte a **WebRTC ICE** (`webrtc-direct`).

---

### 1.3. `mycelium-pheromones`
- **Caminho**: [`crates/mycelium-pheromones`](../../crates/mycelium-pheromones)
- **Papel**: Reconhecimento químico e identidade descentralizada.
- **Funcionalidades**:
  - `Gland`: A glândula privada ed25519 do nó (`germinate()`, `from_seed()`, `sign_bytes()`).
  - `Pheromone`: Pacote de presença assinado contendo `trail` (histórico de trabalho), `scent` (reputação), `decay_secs` (evaporação temporal) e membrana.
  - Alarmes de onda química para notificação de peers maliciosos na malha.

---

### 1.4. `mycelium-nutrients`
- **Caminho**: [`crates/mycelium-nutrients`](../../crates/mycelium-nutrients)
- **Papel**: O ledger econômico metabólico da rede.
- **Funcionalidades**:
  - `Ledger`: Controle de saldos de nutrientes (`ATP`, `Enzymes`, `Mycelia`, `Spores`, `Resilience`).
  - `SignedTransfer`: transferências assinadas com verificação de nonce no ledger local. Isso, por si só, não prova que um débito foi confirmado em um estado comum entre recebedores.
  - Vouchers de liquidação e créditos automáticos por heartbeat e prestação de serviços.

---

### 1.5. `mycelium-sporebank`
- **Caminho**: [`crates/mycelium-sporebank`](../../crates/mycelium-sporebank)
- **Papel**: Persistência de dados content-addressed no disco do nó.
- **Funcionalidades**:
  - `SporeBank`: Armazena objetos `Plot` serializados em `{home}/sporebank/plots/{cid}.json`.
  - Indexação de chaves Kademlia DHT para busca global de conteúdos na rede.
  - Recuperação rápida (`recall`) e cache local.

---

### 1.6. `mycelium-node`
- **Caminho**: [`crates/mycelium-node`](../../crates/mycelium-node)
- **Papel**: O orquestrador central do nó (daemon do organismo).
- **Funcionalidades**:
  - `Organism`: Loop principal assíncrono que integra hifas, control socket, persistência e métricas.
  - Plano de controle via Unix Domain Socket (`mycelium.sock`) e JSON-RPC.
  - Servidor HTTP do Singularity Event Horizon (`:7474`).
  - Servidores dos ions nativos: `/src/` (navegador de código), `/store/` (lojinha de jogos), `/seeds/` (catálogo de peers) e `/vitrine/` (vitrine da floresta).

---

## 2. Portadoras Físicas, Dormência & Mídia

### 2.1. `mycelium-sclerotium`
- **Caminho**: [`crates/mycelium-sclerotium`](../../crates/mycelium-sclerotium)
- **Papel**: Protocolo de dormência profunda (Sclerotium) e portadora fantasma (Ghost Carrier).
- **Funcionalidades**:
  - Máquina de estados: `Sprouting -> Alive <-> Dormant <-> Ghost -> Dead`.
  - `GhostLease`: Delegação de presença para nós vizinhos sem compartilhar chaves privadas.
  - `WakeToken` e `ImpulsePacket`: autenticação de despertar com BLAKE3 keyed e pacote binário de 50 bytes.
  - `EthernetCarrier`: Despacho e recepção de Magic Packets Wake-on-LAN (WoL) com extensão SecureON.

---

### 2.2. `mycelium-media`
- **Caminho**: [`crates/mycelium-media`](../../crates/mycelium-media)
- **Papel**: Motor descentralizado para streaming de áudio e vídeo (Mycelium Video).
- **Funcionalidades**:
  - Fatiamento de vídeos em chunks de 2MB indexados por hashes BLAKE3.
  - `ChannelStore`: Gestão de canais descentralizados assinados por chaves ed25519/GhostID.
  - `PlaylistService`: Criação e versão de playlists imutáveis compartilháveis na malha.
  - `PinManager`: Fixação de vídeos no SporeBank local para evitar perda de dados.

---

### 2.3. `mycelium-store`
- **Caminho**: [`crates/mycelium-store`](../../crates/mycelium-store)
- **Papel**: App Store P2P de software legado, jogos e motores de emulação.
- **Funcionalidades**:
  - Detecção automática de capacidades do sistema host: **RetroArch, MAME, QEMU, WASM, Bubblewrap**.
  - Catálogo de spores de software (`SoftwareSpore`) com hashes de verificação de integridade.
  - Opções de execução com sandbox dependem do motor e da configuração; consulte a [auditoria](MACHINE_HUB_AUDITORIA.md) antes de executar conteúdo não confiável.

---

## 3. Privacidade, Anonimato & Pós-Quântica

### 3.1. `mycelium-veil`
- **Caminho**: [`crates/mycelium-veil`](../../crates/mycelium-veil)
- **Papel**: Rede de roteamento cebola (*onion routing*) pós-quântica VEIL Ω.
- **Funcionalidades**:
  - Roteamento cebola de três saltos (**Guard, Relay, Exit**) com **ML-KEM-1024 e ChaCha20-Poly1305**.
  - Servidor proxy **SOCKS5** local (`127.0.0.1:1080`).
  - Filtros **Anti-SSRF** no nó de egresso para redes privadas RFC 1918 e metadados.
  - Suporte a nós **Bridges** para evasão de censura estatal e bloqueios de IP.

---

### 3.2. `mycelium-pqc`
- **Caminho**: [`crates/mycelium-pqc`](../../crates/mycelium-pqc)
- **Papel**: Primitivas criptográficas pós-quânticas padronizadas (NIST / FIPS).
- **Funcionalidades**:
  - **ML-KEM-1024**: encapsulamento de chave pós-quântico.
  - A verificação de licenças ML-DSA-87 está no crate `mycelium-zkp`, não nesta API ML-KEM.

---

### 3.3. `mycelium-zkp`
- **Caminho**: [`crates/mycelium-zkp`](../../crates/mycelium-zkp)
- **Papel**: Provas de conhecimento zero, verificação de licenças e validação financeira.
- **Funcionalidades**:
  - Verificação de licenças de software **VOID-00** com vinculação a hardware seguro (`device_entropy`).
  - Validação e inspeção de invoices Lightning Network (**BOLT11**) para a economia de vouchers.

---

### 3.4. `mycelium-ghostid`
- **Caminho**: [`crates/mycelium-ghostid`](../../crates/mycelium-ghostid)
- **Papel**: Identidades efémeras secp256k1 compatíveis com Nostr (NIP-01 Schnorr).
- **Funcionalidades**:
  - Coleta de entropia do sistema e do ambiente (sem persistência em disco).
  - Assinaturas Schnorr efêmeras e decoerência programada de identidade.

---

### 3.5. `mycelium-qel`
- **Caminho**: [`crates/mycelium-qel`](../../crates/mycelium-qel)
- **Papel**: Quantum-resistant Erasure Layer (Camada de fragmentação e tolerância a desastres).
- **Funcionalidades**:
  - Fragmentação de arquivos em $N$ shards exigindo quórum de $K$ partes para reconstrução.
  - Indicações de transporte para os shards; um `TransportHint` não comprova que o canal correspondente está implementado ou foi usado.

---

### 3.6. `entropy`
- **Caminho**: [`crates/entropy`](../../crates/entropy)
- **Papel**: Cofre de segredos e Shamir Secret Sharing (SSS) sobre Galois Field $\text{GF}(256)$.
- **Funcionalidades**:
  - `Vault`: divisão de segredos em $M$-de-$N$ `Shade`s. `ChaosKey` limita o tempo de leitura do segredo reconstruído; veja os [limites de custódia](../pipeline/entropy.md).

---

### 3.7. `isotope`
- **Caminho**: [`crates/isotope`](../../crates/isotope)
- **Papel**: Estado distribuído com decaimento radioativo (CRDT Last-Write-Wins sobre gossip).
- **Funcionalidades**:
  - `Nucleus`: Armazena átomos de dados versionados com relógio LWW que se sincronizam via hifas.

---

## 4. O Pipeline de Computação "The Lattice"

### 4.1. `giggs`
- **Caminho**: [`crates/giggs`](../../crates/giggs)
- **Papel**: Forja soberana de código e DAG de plots.
- **Funcionalidades**:
  - `Plot`: Objeto imutável content-addressed que representa um commit/snapshot da árvore de código.
  - `Leaf`: Cada arquivo individual com caminho relativo e bytes de conteúdo fatiado.

---

### 4.2. `thefield`
- **Caminho**: [`crates/thefield`](../../crates/thefield)
- **Papel**: O campo de ressonância e coordenação de quórum.
- **Funcionalidades**:
  - `Signal`: Declaração pública de intenção de computação emitida na malha.
  - `Resonance`: Assinatura de nós que concordam em executar o pipeline quando o quórum for atingido.

---

### 4.3. `inertia`
- **Caminho**: [`crates/inertia`](../../crates/inertia)
- **Papel**: Motor de execução de compilação, testes e atestações criptográficas.
- **Funcionalidades**:
  - `Vector`: Instrução precisa de execução de build/teste em cima de um snapshot exato.
  - `SignedAttestation`: atestação assinada que permite conferir autoria e integridade; ela não prova que o executor agiu honestamente.

---

### 4.4. `vacuum`
- **Caminho**: [`crates/vacuum`](../../crates/vacuum)
- **Papel**: Camada de isolamento e execução segura de processos.
- **Funcionalidades**:
  - `Chamber`: O contêiner leve e isolado do Mycelium.
  - Suporte automático a **Bubblewrap** (`bwrap`), namespaces de Linux e limites de memória `RLIMIT_AS`.

---

### 4.5. `plasma`
- **Caminho**: [`crates/plasma`](../../crates/plasma)
- **Papel**: Nuvem elástica de serviços e balanceamento de carga.
- **Funcionalidades**:
  - `Ion`: Instância de serviço em execução com carga eletrostática (`Positive`, `Neutral`, `Negative`).
  - Dinâmica de repulsão e atração para escalonamento automático de réplicas entre nós da rede.

---

### 4.6. `singularity`
- **Caminho**: [`crates/singularity`](../../crates/singularity)
- **Papel**: O horizonte de eventos HTTP (gateway de entrada da internet tradicional).
- **Funcionalidades**:
  - `EventHorizon`: Reverse proxy HTTP na porta `:7474` que mapeia URLs `/{ion}/` até as Chambers vivas.
  - Rate limiting por IP, injeção de security headers e console de status.

---

## 5. Transportes Heterogêneos & Pontes

### 5.1. `mycelium-nostr` & `mycelium-nostr-transport`
- **Caminho**: [`crates/mycelium-nostr`](../../crates/mycelium-nostr) e [`crates/mycelium-nostr-transport`](../../crates/mycelium-nostr-transport)
- **Papel**: Túnel libp2p sobre relays Nostr (WSS outbound na porta 443).
- **Funcionalidades**: Permite a dois nós atrás de CGNAT/firewalls restritivos se conectarem sem abrir portas no roteador.

---

### 5.2. `mycelium-ipfs`
- **Caminho**: [`crates/mycelium-ipfs`](../../crates/mycelium-ipfs)
- **Papel**: Interoperabilidade com o ecossistema IPFS (blockstore local e CIDs).

---

### 5.3. `mycelium-tropical`
- **Caminho**: [`crates/mycelium-tropical`](../../crates/mycelium-tropical)
- **Papel**: Roteamento ótimo sobre álgebra tropical $(\min, +)$ para cálculo de menor custo e menor latência na malha.

---

### 5.4. `mycelium-distancebridge`
- **Caminho**: [`crates/mycelium-distancebridge`](../../crates/mycelium-distancebridge)
- **Papel**: Seleção de transportes a partir do contexto disponível; meios físicos como LoRa não são implementados por este crate.

---

## 6. CLI e Plataformas COSMIC

### 6.1. `cosmic-cli`
- **Caminho**: [`crates/cosmic-cli`](../../crates/cosmic-cli)
- **Papel**: Linha de comando para interação com a camada de computação e storage pós-quânticos COSMIC.

---

### 6.2. `platforms/cosmoplanck`
- **Caminho**: [`platforms/cosmoplanck`](../../platforms/cosmoplanck)
- **Papel**: Cliente REST de integração com a plataforma Planck.

---

### 6.3. `cli/mycelium-cli`
- **Caminho**: [`cli/mycelium-cli`](../../cli/mycelium-cli)
- **Papel**: O binário principal de usuário `mycelium`.
- **Comandos Principais**:
  - `sprout`, `daemon`, `status`, `shutdown` (Ciclo de vida do nó)
  - `sow`, `recall`, `signal`, `resonate`, `deploy` (The Lattice)
  - `repo publish`, `repo clone`, `repos` (Git e GitHub soberano)
  - `media publish`, `media pin`, `media pins` (Mycelium Video)
  - `channel create`, `channel publish`, `channel show` (Canais descentralizados)
  - `playlist create`, `playlist add` (Playlists)
  - `store list`, `store caps`, `store launch`, `store publish` (Mycelium Store)
  - `sclerotium hardware`, `sclerotium lease`, `sclerotium status`, `sclerotium wake` (Dormência e WoL)
  - `veil start`, `veil stop`, `veil status`, `veil descriptor` (Onion Routing VEIL Ω)
  - `license-verify`, `register-peer`, `bolt11` (ZKP e Economia)
