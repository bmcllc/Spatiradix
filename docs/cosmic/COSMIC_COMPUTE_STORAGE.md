# COSMIC: computação e armazenamento sobre o Mycelium

> **Crates**: [`cosmic-cli`](../../crates/cosmic-cli), [`platforms/cosmoplanck`](../../platforms/cosmoplanck), [`mycelium-qel`](../../crates/mycelium-qel), [`mycelium-zkp`](../../crates/mycelium-zkp)
> **Camada**: L3 / L4 — Computação Verificável e Armazenamento em Shards  
> **Status**: Ativo  

---

## 1. Visão geral

O COSMIC explora armazenamento fragmentado, computação verificável e identidade
portátil sobre o Mycelium. O QEL divide dados em N partes com limiar K; a
recuperação depende de partes suficientes estarem disponíveis. Uma atestação
assinada ajuda a verificar sua autoria e integridade, mas não prova, por si
só, que o executor foi honesto. O projeto também inclui licenças digitais
VOID-00 baseadas em ML-DSA-87.

Os mecanismos e canais descritos abaixo misturam implementação e propostas.
Consulte [Validação](../VALIDACAO.md) para o estado dos testes.

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

O crate [`mycelium-qel`](../../crates/mycelium-qel) divide qualquer arquivo ou segredo em $N$ pedaços, exigindo no mínimo $K$ pedaços para reconstrução:

$$\text{Arquivo Original} \xrightarrow{\text{QEL }(K, N)} \{ \text{Shard}_1, \text{Shard}_2, \dots, \text{Shard}_N \}$$

### Canais de dispersão híbrida

A arquitetura considera rotas diferentes para distribuir shards. A lista abaixo
ilustra a proposta; a disponibilidade de cada transporte depende da
implementação e da configuração:
1. **Shard 1 & 2**: Kademlia DHT e SporeBank de nós vizinhos locais (LAN/Wi-Fi).
2. **Shard 3**: Criptografado e publicado como evento efémero em relays **Nostr** via WebSockets (`wss://`).
3. **Shard 4**: Bloco content-addressed em gateways **IPFS** locais.
4. **Shard 5**: Enlace de rádio **LoRa sub-GHz** ou transporte físico via encontros DTN.

A reconstrução exige que pelo menos $K$ fragmentos válidos sejam recuperados.
Uma falha de rede pode impedir o acesso a eles.

---

## 5. A Licença Pós-Quântica VOID-00 (ML-DSA-87)

O COSMIC integra no crate [`mycelium-zkp`](../../crates/mycelium-zkp) a verificação de licenças digitais pós-quânticas:

- **Algoritmo**: **ML-DSA-87** (FIPS 204 Dilithium nível 5 — segurança equivalente a 256 bits pós-quânticos).
- **Tamanho da Chave Pública**: 2.592 bytes.
- **Tamanho da Assinatura**: 4.627 bytes.
- **Vinculação de Dispositivo (Device Binding)**: A licença combina o SKU do software com uma medida de entropia do hardware local (`device_entropy`).
- **Gate de Admissão Licenciada**: O nó daemon do Mycelium só admite e roteia tráfego para peers que possuam licenças válidas quando operando em modo de federação fechada ou corporativa.

---

## 6. Comandos da CLI `cosmic`

O binário `cosmic` (compilado a partir de `crates/cosmic-cli`) oferece a interface direta de usuário para a camada COSMIC:

```bash
# Fragmenta um arquivo em cinco partes, com limiar de três
cosmic put segredo.tar.gz --k 3 --n 5

# Substitua Qm... pelo ContentId completo retornado pelo comando anterior
cosmic get Qm... --out segredo-restaurado.tar.gz

# Executa uma receita local e grava a prova
cosmic run --recipe sha256 segredo.tar.gz --proof proof.json

# Mostra a identidade GhostID local, se já tiver sido criada
cosmic auth whoami

# Mostra os argumentos necessários para verificar uma licença
mycelium license-verify --help
```

Por padrão, `put` e `get` usam o armazenamento local do COSMIC. A opção
`--home` tenta publicar ou recuperar fragmentos por um daemon Mycelium.
