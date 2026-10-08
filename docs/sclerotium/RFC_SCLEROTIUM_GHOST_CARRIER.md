# RFC: Protocolo Sclerotium & Ghost Carrier

> **Status**: Proposto & Prototipado  
> **Crate**: [`mycelium-sclerotium`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-sclerotium)  
> **Camada**: Substrato L0 (Fisiologia & Portadora Física) / L1 (Delegação Criptográfica)  
> **Data**: Setembro de 2026  

---

## 1. Sumário Executivo: "Vale a pena a implementação disto?"

**Sim, absolutamente.** A introdução da dobradinha **Ghost Carrier** e **Protocolo Sclerotium** resolve o maior gargalo existencial de redes P2P descentralizadas: o **Dilema da Disponibilidade 24/7**.

Historicamente, redes como IPFS, BitTorrent e overlays DHT assumem tacitamente uma de duas realidades falhas:
1. *Ou os nós rodam em data centers (VPSs caros e centralizados) para manter 99.9% de uptime;*
2. *Ou nós residenciais (desktops, notebooks) que dormem ou desligam são marcados como "mortos/evaporados", degradando rotas DHT, perdendo pontuação de reputação (`Resilience`), e tornando seus conteúdos inacessíveis.*

No Mycelium Network, o **Sclerotium (Escleródio)** traduz com exatidão a estratégia biológica dos fungos reais: perante a escassez de recursos ou necessidade de repouso, o micélio condensa biomassa em estruturas endurecidas e dormentes (escleródios), preservando água, nutrientes e integridade genética sem consumir energia contínua. Quando um estímulo químico ou elétrico (**Impulse**) é detectado, o organismo desperta e retoma seu metabolismo completo.

---

## 2. Taxonomia Biológica Unificada

O ecossistema Mycelium consolida seus conceitos com total fidelidade biológica:

| Termo Fisiológico | Papel no Mycelium Network | Implementação Técnica |
|---|---|---|
| **Hypha** (Hifa) | Conexão ponto-a-ponto ativa | Sessão libp2p (QUIC / TCP + Noise + Yamux) |
| **Rhizomorph** (Rizomorfo) | Enlace de alta capacidade/agrupamento | Circuit Relay v2 + túneis multi-stream de alta vazão |
| **Sporocarp** (Esporocarpo) | Borda visível e alcançável da rede | Nó com IPv6 global/port-forward + Singularity Event Horizon |
| **Sclerotium** (Escleródio) | Nó em dormência profunda (cold/sleep) | Máquina principal em standby/suspenso + wake receiver ativo |
| **Ghost** (Fantasma) | Presença lógica delegada | Identidade temporária mantida por quórum via `GhostLease` |
| **Spore** (Esporo) | Conteúdo imutável e content-addressed | `Plot` com ContentId BLAKE3 indexado no Spore Bank |
| **Pheromone** (Feromônio) | Reconhecimento químico e identidade | Assinatura ed25519 (`Gland`) com decaimento temporal (`decay`) |
| **Impulse** (Impulso) | Sinal de disparo de baixa energia | Pacote binário de 50 bytes com `WakeToken` autenticado |
| **Mycelium** (Micélio) | Organismo vivo completo | O substrato inteiro operando em malha |

---

## 3. Os Quatro Estados do Nó

```text
               ┌─────────── germinação ───────────┐
               ▼                                  │
         ┌───────────┐                      ┌───────────┐
         │ SPROUTING │                      │   DEAD    │
         └─────┬─────┘                      └─────▲─────┘
               │ hifas enraizadas                 │ lease expirou
               ▼                                  │
         ┌───────────┐      suspensão       ┌─────┴─────┐
         │   ALIVE   │ ───────────────────► │  DORMANT  │
         │ (Fruiting)│ ◄─────────────────── │(Sclerotium│
         └─────┬─────┘       WakeToken      └─────┬─────┘
               │                                  │
               │ desligamento / sem rádio         │ sem standby
               ▼                                  ▼
         ┌──────────────────────────────────────────────┐
         │                    GHOST                     │
         │   (Presença lógica mantida por GhostLease)   │
         └──────────────────────────────────────────────┘
```

1. **ALIVE (Vivo / Frutificando)**:
   - CPU, RAM, GPU e interface de rede em operação plena.
   - Stack libp2p completo (gossipsub, Kademlia DHT, circuit relay).
   - Execução de Chambers do Vacuum e computação do Inertia.
2. **DORMANT (Dormente / Sclerotium)**:
   - CPU/GPU principal suspensa (Linux ACPI S3/suspend-to-RAM ou S4/suspend-to-disk).
   - O consumo cai de 150W para **1W a 3W** (standby da NIC Ethernet / Wi-Fi WoWLAN) ou **~50µW** (MCU sidecar LoRa/sub-GHz).
   - Receptor de wake ativo escutando a portadora Ghost Carrier.
   - Desperta sob demanda mediante recepção de um `ImpulsePacket` com `WakeToken` válido.
3. **GHOST (Fantasma)**:
   - Máquina totalmente desconectada da tomada ou sem sinal de rádio.
   - Membros vizinhos da malha mantêm uma **`GhostLease` assinada**.
   - Proxies respondem: *"Nó existe; está dormente; seus conteúdos CIDs [X, Y] estão nestas réplicas; guardo mensagens na Mailbox DTN para quando voltar"*.
   - **Nenhum proxy pode assinar como o nó nem gastar seus nutrientes.**
4. **DEAD (Decomposto)**:
   - A `GhostLease` expirou sem nenhuma prova de vida recente.
   - Recursos devolvidos ao substrato; feromônio evaporado.

---

## 4. Engenharia Criptográfica: `GhostLease`

A delegação é segura porque **não compartilha chaves privadas**. O nó original assina com sua `Gland` ed25519 uma declaração canônica delimitada por escopo e tempo:

```rust
pub struct GhostLease {
    pub origin_node_id: NodeId,
    pub origin_pubkey: [u8; 32],
    pub epoch: u64,
    pub valid_until: u64,
    pub nonce: u64,
    pub authorized_proxies: Vec<NodeId>,
    pub capabilities: Vec<LeaseCapability>,
    pub replicated_cids: Vec<ContentId>,
    pub wake_endpoints: Vec<WakeEndpoint>,
    pub signature: Vec<u8>,
}
```

### Capacidades Conferidas (`LeaseCapability`):
- `AdvertiseContent`: Autoriza o proxy a responder por CIDs replicados pertencentes ao nó dormente.
- `ReceiveMail`: Autoriza o proxy a acolher mensagens na Mailbox DTN em nome do nó dormente.
- `QueueJobs`: Autoriza o proxy a enfileirar execuções pendentes para entrega posterior.
- `RelayWake`: Autoriza o proxy a retransmitir o sinal de wake para os endpoints físicos do nó.

---

## 5. Proteção Anti-DoS: Despertar Seletivo com `WakeToken`

### O Perigo dos *Vampire Attacks* (Ataques de Negação de Sono)
Se qualquer pacote de rede acordasse o computador principal, um atacante poderia inundar o nó com transmissões contínuas, mantendo a CPU em pico de consumo e esgotando a bateria de um notebook em 40 minutos.

### O Modelo do `WakeToken`
Para acordar o nó, o requisitante precisa apresentar um token assinado/chaveado:

$$\text{WakeToken} = \text{BLAKE3}_{\text{keyed}}(\text{wake\_key}, \text{target} \parallel \text{requester} \parallel \text{epoch} \parallel \text{nonce} \parallel \text{reason})$$

A validação no receptor segue quatro barreiras estritas:
1. **Destino exato**: O token precisa ser explicitamente para o `NodeId` do alvo.
2. **Janela Temporal**: $|\text{epoch} - \text{now}| \le 300\text{s}$ (rejeita pacotes velhos ou no futuro distante).
3. **Cache de Nonce Anti-Replay**: Armazena nonces vistos recentemente; qualquer repetição do mesmo token é descartada instantaneamente.
4. **Verificação de Chave/MAC**: O receptor só emite o gatilho de ligar a placa-mãe se o MAC bater.

---

## 6. O Pacote de Impulso Binário (50 Bytes)

Para operar sobre portadoras analógicas, FSK, AFSK, LoRa ou sub-GHz com largura de banda mínima, o `ImpulsePacket` foi codificado em exatamente **50 bytes**:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  PREAMBLE: "MYCE" (4 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  VER (0x01)   |  CMD ('W')    |  REASON (u8)  | FLAGS (0x00)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                TARGET NODE PREFIX (8 bytes)                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|              REQUESTER NODE PREFIX (8 bytes)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    EPOCH (8 bytes, LE)                        |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    NONCE (8 bytes, LE)                        |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               AUTH MAC PREFIX (8 bytes)                       |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          CRC16-CCITT (2 bytes)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 7. Fases de Implementação e Realidade Física

### Fase 1: Software & Hardware Comercial (Já Funcional no Crate)
- **Wake-on-LAN (WoL)** via Linux `ethtool` / Netlink e sockets UDP broadcast.
- Magic Packet com extensão **SecureON** (chave de 6 bytes derivada do `WakeToken`).
- `GhostLease` criada, persistida em disco e compartilhada com vizinhos.
- Mailbox DTN acolhendo pacotes em nome do nó dormente.

### Fase 2: Cyber-Física / Dongle MCU Sidecar (Próximo Passo)
- Microcontrolador auxiliar de baixo custo (**ESP32-C3** ou **Raspberry Pi RP2040**).
- Conexão com transceiver sub-GHz (**SX1262 LoRa** a 915 MHz / 433 MHz ou **CC1101**).
- Pino GPIO conectado ao header de energia da placa-mãe (`PWR_BTN`) ou disparando WoL na LAN local.
- Consumo elétrico do receptor: **~15 µA a 5 mA** (pode ser mantido por anos em bateria CR2032 ou mini painel solar).

### Fase 3: Rádios de Despertar Integrados (Futuro)
- Adoção de módulos compatíveis com **IEEE 802.11ba WUR** conforme chegarem ao mercado comercial.

---

## 8. Conclusão da Avaliação

A implementação do **Sclerotium + Ghost Carrier** não é apenas vantajosa; ela é o diferencial que posiciona o Mycelium Network como uma verdadeira **rede viva e adaptativa**, onde o nó computacional imita a eficiência energética da natureza, sem sacrificar a identidade criptográfica nem a persistência distribuída de dados.
