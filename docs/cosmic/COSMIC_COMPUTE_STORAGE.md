# 🌌 COSMIC — Compute & Storage Pós-Quânticos sobre o Mycelium

> **Crates**: [`cosmic-cli`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/cosmic-cli), [`platforms/cosmoplanck`](file:///media/bruno/SAMBOOK/Mycelium%20Network/platforms/cosmoplanck), [`mycelium-qel`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-qel), [`mycelium-zkp`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-zkp)  
> **Camada**: L3 / L4 — Computação Verificável e Armazenamento em Shards  
> **Status**: Ativo  

---

## 1. O Princípio de Ouro do COSMIC

> *"A confiança sai do hardware e vai para a criptografia."*

No modelo de computação em nuvem tradicional, você confia na empresa dona do servidor (AWS, Google, Microsoft) para não bisbilhotar seus dados, não censurar suas rotinas e manter 99.9% de uptime. Se a máquina falhar ou o governo intimar a empresa, seu serviço morre.

O **COSMIC** inverte essa equação:
- Você **não confia em nenhuma máquina individual**.
- O storage é fragmentado matematicamente em **Shards K/N** (se você escolher 3 de 7, o arquivo é reconstruível a partir de quaisquer 3 partes, mas mesmo que um invasor capture 2 partes ele obtém **zero bits** de informação).
- O compute é **verificável**: você não confia no resultado de quem executou; a execução produz uma prova matemática de integridade (atestação criptográfica e provas formais).
- A identidade e permissões são garantidas por licenças criptográficas pós-quânticas **VOID-00 (ML-DSA-87)**.

---

## 2. A Comparação de Paradigmas

| Recurso Legado | Modelo Tradicional (VPS) | Modelo Soberano COSMIC | Mecanismo no Código |
|---|---|---|---|
| **Storage** | Disco SSD em 1 servidor | **Shards K/N Pós-Quânticos** multicanal | `mycelium-qel::fragment` + `reconstruct` |
| **Compute** | Processo rodando em 1 VM | **Compute Verificável** (recipe $\to$ proof) | `thefield::Signal` $\to$ `inertia::Vector` |
| **Identidade** | Usuário/SSH Key/Root | **GhostID portátil + Licença VOID-00** | `mycelium-ghostid` + `mycelium-zkp::license` |
| **Uptime** | Dependente de energia 24/7 | **K/N canais + transporte híbrido** | Nostr, IPFS, RelayMesh, LoRa, Proximity |
| **Monetização** | Cartão de crédito / Boleto | **Nutrient Ledger (ATP / Enzymes)** | `mycelium-nutrients::Ledger` |

---

## 3. Arquitetura em Três Níveis

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. CONTRATO CRIPTOGRÁFICO (O "SER")                                         │
│    • Identidade: GhostID efêmero ou estável derivado da entropia local      │
│    • Permissão: Licença VOID-00 pós-quântica (ML-DSA-87 + Device Binding)  │
│    • Política de Tolerância: QEL K/N (ex: 3 de 5 shards)                    │
├─────────────────────────────────────────────────────────────────────────────┤
│ 2. SEMÂNTICA & APIS COSMIC (O "QUÊ")                                        │
│    • cosmic put   → fragmenta dados em shards com erasure coding            │
│    • cosmic get   → busca qualquer quorum K de shards e reconstrói          │
│    • cosmic run   → despacha job com atestação de integridade               │
│    • cosmic auth  → valida dispositivo via hash de hardware seguro          │
├─────────────────────────────────────────────────────────────────────────────┤
│ 3. SUBSTRATO MYCELIUM (O "ONDE")                                            │
│    • Hifas libp2p + SporeBank + DHT de Zonas                                │
│    • Camada híbrida: Nostr Relays + IPFS Blockstore + LoRa                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. O Sistema de Fragmentação QEL (Quantum-resistant Erasure Layer)

O crate [`mycelium-qel`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-qel) divide qualquer arquivo ou segredo em $N$ pedaços, exigindo no mínimo $K$ pedaços para reconstrução:

$$\text{Arquivo Original} \xrightarrow{\text{QEL }(K, N)} \{ \text{Shard}_1, \text{Shard}_2, \dots, \text{Shard}_N \}$$

### Canais de Dispersão Híbrida:
Para que o dado sobreviva à destruição física de datacenters ou cortes de cabos submarinos, os shards são distribuídos por rotas heterogêneas:
1. **Shard 1 & 2**: Kademlia DHT e SporeBank de nós vizinhos locais (LAN/Wi-Fi).
2. **Shard 3**: Criptografado e publicado como evento efémero em relays **Nostr** via WebSockets (`wss://`).
3. **Shard 4**: Bloco content-addressed em gateways **IPFS** locais.
4. **Shard 5**: Enlace de rádio **LoRa sub-GHz** ou transporte físico via encontros DTN.

Mesmo que a internet convencional caia, bastam quaisquer $K$ fragmentos recuperados para remontar os dados intactos.

---

## 5. A Licença Pós-Quântica VOID-00 (ML-DSA-87)

O COSMIC integra no crate [`mycelium-zkp`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-zkp) a verificação de licenças digitais pós-quânticas:

- **Algoritmo**: **ML-DSA-87** (FIPS 204 Dilithium nível 5 — segurança equivalente a 256 bits pós-quânticos).
- **Tamanho da Chave Pública**: 2.592 bytes.
- **Tamanho da Assinatura**: 4.627 bytes.
- **Vinculação de Dispositivo (Device Binding)**: A licença combina o SKU do software com uma medida de entropia do hardware local (`device_entropy`).
- **Gate de Admissão Licenciada**: O nó daemon do Mycelium só admite e roteia tráfego para peers que possuam licenças válidas quando operando em modo de federação fechada ou corporativa.

---

## 6. Comandos da CLI `cosmic`

O binário `cosmic` (compilado a partir de `crates/cosmic-cli`) oferece a interface direta de usuário para a camada COSMIC:

```bash
# Fragmenta e armazena um arquivo com redundância 3 de 5 shards
cosmic put --file segredo.tar.gz --threshold 3 --total 5

# Reconstrói o arquivo buscando os fragmentos na malha híbrida
cosmic get --cid Qm... --output segredo-restaurado.tar.gz

# Executa computação verificável no cluster
cosmic run --recipe pipeline.json

# Inspeciona o estado da carteira GhostID e licenças VOID-00
cosmic status

# Valida uma licença pós-quântica ML-DSA-87
mycelium license-verify --vendor-key <HEX_2592B> --sku "ENTERPRISE-PRO" --signature <HEX_4627B>
```
