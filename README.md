# 🍄 Mycelium Network — O Substrato Vivo do The Lattice

> *"A floresta não é uma coleção de árvores. É uma rede subterrânea de fungos que alimenta, comunica e cura."*

Nuvem P2P viva em Rust: hifas (libp2p), feromônios, Spore Bank, e o fluxo Lattice ponta a ponta.

## 🧪 Estado de validação

- ✅ **Nível a (cumprido)** — o workspace compila e os testes locais passam, com artefatos reais (binários, capturas, logs) reproduzíveis nesta máquina.
- ❌ **Nível b (não cumprido)** — malha multi-nó em redes reais (física/ISP distintas) não foi executada nem registrada.
- ❌ **Nível c (não cumprido)** — sem validação por terceiros.
- ❌ **Nível d (não cumprido)** — sem implantação em produção; nenhum seed com inbound verificado existe em `seeds/mainnet.txt`.
- As seções abaixo descrevem o **escopo e a intenção** do projeto; onde há afirmação de prontidão, o número real está em [`docs/VALIDACAO.md`](docs/VALIDACAO.md).

## Quick start

```bash
# 1. Planta a semente (identidade + recursos em disco)
cargo run -p mycelium-cli --release -- --home /tmp/node-a sprout --contribute 2cpu,4gb,100gb

# 2. Desperta o daemon (Event Horizon HTTP em :7474)
cargo run -p mycelium-cli --release -- --home /tmp/node-a daemon --contribute 2cpu,4gb,100gb --horizon-port 7474

# 3. Noutro terminal — fluxo Lattice → Chamber viva
cargo run -p mycelium-cli --release -- --home /tmp/node-a sow --message "hello"
# anote o ContentId (Qm…)
cargo run -p mycelium-cli --release -- --home /tmp/node-a signal --plot Qm… --quorum 1 --ion webapp

# 4. Acesse o Ion pelo Singularity (proxy HTTP real)
curl -s http://127.0.0.1:7474/webapp/ | jq .
```

Demo automatizada do horizon: `./scripts/horizon-demo.sh`

Dois nós com bootstrap remoto:

```bash
# terminal A — seed na porta 4001
mycelium --home /tmp/a daemon --listen /ip4/0.0.0.0/tcp/4001

# terminal B
mycelium --home /tmp/b daemon --bootstrap /ip4/IP_DE_A/tcp/4001/p2p/PEERID_DE_A
```

Bootstrap além da LAN (catálogo HTTP + `/dnsaddr/`):

```bash
mycelium seeds fetch --url ./seeds/mainnet.example.txt
mycelium daemon --public-bootstrap --bootstrap-url https://seu.host/seeds.txt
# ou arquivo local:
mycelium daemon --seed-file ./seeds/mainnet.example.txt --listen /ip4/0.0.0.0/tcp/4001
```

Vacuum usa **bubblewrap** por padrão quando `bwrap` está no PATH; layers content-addressed em `{home}/layers/` e limites soft de RAM (`RLIMIT_AS`).

Rede só com seed book (sem mDNS / sem `--bootstrap` manual):

```bash
./scripts/seedbook-demo.sh
```

Demos: `./scripts/e2e-demo.sh` · `./scripts/horizon-demo.sh` · `./scripts/seedbook-demo.sh` · `./scripts/isotope-decay-demo.sh`

## CLI unificada `lattice` (Forja + Rede)

```bash
# Fase 1 — planta um nó (folha CGNAT por default; --sporocarp exige gate de prova)
./lattice plant

# Comando mágico: B.A.S.E. analisa o binário → Plot → Ion no Event Horizon
./lattice resurrect caminho/para/firmware.bin
# → http://127.0.0.1:7474/webapp/

# Passthrough: lattice base … (base-cli) e lattice daemon|sow|status… (mycelium-cli)
```

Requer binários compilados (`target/release/mycelium` e `Behavioral ASIC Synthesis Engine/target/release/base`) ou `LATTICE_MYCELIUM_BIN` / `LATTICE_BASE_BIN`. Home default: `LATTICE_HOME` ou `~/.local/share/mycelium`.

## Código-fonte pela rede (sem git, sem GitHub)

```bash
# Semeia um diretório inteiro (recursivo) com visibilidade
mycelium --home ~/n1 seed-code --path ./meu-app --name meu-app \
  --description "app beta" --ion webapp --visibility public   # public|private|reserved|archived|community

# Em outro nó, baixa o código (replica via gossip/SporePrint em segundos)
mycelium --home ~/n2 recall-code --plot Qm…            # extrai em ./meu-app (CWD do CLI)
mycelium --home ~/n2 recall-code --plot Qm… --output /tmp/x   # destino explícito

# privado: só o autor baixa; o conteúdo nunca trafega na rede
```

## Fluxo ponta a ponta

```
Giggs sow Plot → Spore Bank (disco + DHT) → gossip hifas
       → TheField Signal + quórum
       → Inertia Vectors (build/test/deploy)
       → Vacuum Chamber → Plasma Ion → Singularity Event Horizon
```

## Comandos CLI

| Comando | Função |
|---|---|
| `sprout` | Inicializa identidade/recursos sem subir rede |
| `daemon` | Organismo persistente (Ctrl-C ou `shutdown`) |
| `status` | Estado vivo (socket) ou offline (disco) |
| `sow` | Semeia Plot → Spore Bank + gossip/DHT (`--qel`/`--nostr`/`--ghost`) |
| `signal` | Emite Signal de pipeline no TheField |
| `resonate` | Contribui para o quórum de um Signal |
| `recall` | Lê Plot local; DHT ou `--qel --nostr` (relays) |
| `bootstrap` | Dial explícito a um peer remoto |
| `seeds list/add/fetch` | Seed book (bootstrap público) |
| `seeds catalog list/add/remove/export` | Catálogo estruturado de seeds públicas/privadas (`{home}/seeds/catalog.json`) + export para mainnet.txt |
| `isotope-put` / `isotope-get` | Estado Isotope (anel 4 + Decay pelas hifas) |
| `deploy` | One-shot: sow → signal → URL do Event Horizon |
| `store list/caps/launch/publish` | App Store / Steam P2P de software antigo e emulação (QEMU, MAME, RetroArch, WASM) |
| `repo publish/clone/list` | Distribuição de código soberana: publica a árvore como Plot multi-leaf (DHT + gossip) e reconstrói em qualquer nó — sem GitHub |
| `media publish/pin/pins` | Streaming e fixação de vídeos em chunks BLAKE3 de 2MB via enxame P2P (Mycelium Video) |
| `channel create/publish/show` | Gestão de canais descentralizados assinados por chave criptográfica |
| `playlist create/add` | Criação e versão de playlists portáteis e soberanas |
| `sclerotium hardware/lease/status/wake` | Protocolo Sclerotium: dormência profunda, GhostLease, Wake-on-LAN e WakeToken anti-DoS |
| `veil start/stop/status/descriptor` | Roteamento cebola pós-quântico VEIL Ω de 3 saltos (Guard/Relay/Exit), Anti-SSRF e SOCKS5 (:1080) |
| `shutdown` | Hiberna o daemon (estado fica em disco) |

## 📚 Documentação Técnica Completa

Para aprofundamento na engenharia do ecossistema, consulte os documentos dedicados:

- **[Arquitetura Geral Sistêmica](docs/architecture/ARQUITETURA_GERAL_SISTEMICA.md)**: Visão holística de todas as camadas de L0 a L4 e fluxos do organismo.
- **[Dicionário e Referência de Crates](docs/architecture/CRATES_REFERENCE.md)**: Guia exaustivo cobrindo todos os 30 crates e plataformas do monorepo.
- **[VEIL Ω — Roteamento Cebola Pós-Quântico](docs/veil/VEIL_ONION_ROUTING.md)**: Especificação da rede cebola de 3 saltos com ML-KEM-768 e isolamento Anti-SSRF.
- **[COSMIC — Compute & Storage Pós-Quânticos](docs/cosmic/COSMIC_COMPUTE_STORAGE.md)**: Fragmentação QEL K/N, atestações e licenças VOID-00 (ML-DSA-87).
- **[RFC Sclerotium & Ghost Carrier](docs/sclerotium/RFC_SCLEROTIUM_GHOST_CARRIER.md)**: Especificação de dormência biológica, GhostLease e despertar seletivo.
- **[Índice Completo de Documentação](docs/README.md)**: Catálogo organizado de todos os 45+ documentos técnicos.

## Crates do Monorepo

O projeto é modularizado em 30 crates e plataformas especializados:

| Crate | Camada | Papel |
|---|---|---|
| `mycelium-core` | L0 / L1 | Identificadores (`NodeId`, `ContentId`), recursos e interfaces vitais |
| `mycelium-hyphae` | L1 | libp2p QUIC/TCP, Kademlia DHT, gossipsub, relay mesh e DTN Mailbox |
| `mycelium-pheromones` | L1 | Identidade ed25519 (`Gland`), trails, scents e alarmes |
| `mycelium-nutrients` | L1 | Ledger de nutrientes: ATP, Enzymes, Mycelia, Spores, Resilience |
| `mycelium-sporebank` | L1 | Armazenamento de Plots content-addressed em disco e DHT |
| `mycelium-node` | L1 / L2 | Daemon persistente, Event Horizon HTTP (:7474), ions `/src`, `/store`, `/vitrine` |
| `mycelium-sclerotium` | L0 / L1 | Dormência biológica, GhostLease, Wake-on-LAN e WakeToken anti-vampire attacks |
| `mycelium-veil` | L2 | Rede cebola pós-quântica (ML-KEM-768), proxy SOCKS5, Anti-SSRF e bridges |
| `mycelium-media` | L4 | Motor de streaming de áudio/vídeo em chunks de 2MB BLAKE3 e canais |
| `mycelium-bank` | L4 | **Banco/corretora descentralizada**: carteira soberana PQC, ledger hash-encadeado, livro de ordens, pagamentos NFC P2P |
| `mycelium-store` | L4 | App Store P2P e motores de emulação (RetroArch, MAME, QEMU, WASM) |
| `mycelium-zkp` | L2 | Licenças pós-quânticas VOID-00 (ML-DSA-87) e validação Lightning BOLT11 |
| `cosmic-cli` | L3 / L4 | CLI para computação verificável e storage em shards QEL |
| `giggs` … `plasma` | L3 | Componentes de compilação, quórum, isolamento e balanceamento do The Lattice |
| `mycelium-cli` | CLI | O binário executável unificado `mycelium` |

## Persistência (`MYCELIUM_HOME` / `--home`)

```
gland.seed          identidade (PeerId estável)
ledger.json         nutrientes
resources.json      contribuição
organism.json       field, ions, métricas de hifas, bootstrap
nucleus.json        Isotope (átomos LWW)
layers/             Vacuum layers content-addressed
builds/             workbench do Inertia
sporebank/plots/    Plots content-addressed
listen_addrs.json   multiaddrs para bootstrap de pares
seeds.txt           seed book mesclado
mycelium.sock       plano de controle do daemon
```

## CGNAT / Vivo sem esporocarpo: Hybrid Theory (Nostr + QEL + ipfs local)

Outbound `wss://` (porta 443) + blockstore local — funciona atrás de firewall residencial:

```bash
mycelium sow --message "floresta" --hybrid
# noutro home (cola o Qm… completo):
mycelium --home /tmp/folha-b recall --plot Qm… --hybrid
./scripts/hybrid-demo.sh
```

Docs: [docs/network/nostr-qel.md](docs/network/nostr-qel.md) · voluntário mesh: [docs/network/candidatos.md](docs/network/candidatos.md) · ET-COSMIC bridge: [docs/cosmic/et-cosmic-bridge.md](docs/cosmic/et-cosmic-bridge.md) · feature CLI `nostr` (default).

## COSMIC — storage + compute + identidade pós-quânticos

Remodela o tríplice *VPS = compute + storage + uptime* em **contratos
criptográficos**: a confiança sai do hardware e vai pra criptografia.
Design completo em [docs/cosmic/cosmic-design.md](docs/cosmic/cosmic-design.md). Binário
`cosmic` (crate `cosmic-cli`):

```bash
# Storage QEL: fragmenta em shards pós-quânticos (3/7), multicanal.
# --home <nó> distribui os shards na malha Mycelium via Isotope (qualquer peer recupera).
cosmic put arquivo.bin --k 3 --n 7 --home ~/node-a
cosmic get Qm0d70b7c78873aafe911f4b5f9313502f5d9a3eb47aac0cdf0817fd2a6fb72140 --out recuperado.bin --home ~/node-b

# Compute verificável: receita determinística → proof re-provável (re-provm).
# --home <nó> publica proof + input na rede; cosmic verify <proof_id> recupera e re-executa.
cosmic run --recipe blake3 input.bin --proof proof.json --home ~/node-a
cosmic verify Qm0d70b7c78873… --home ~/node-b --id Qm0d70b7c78873…   # ✓ re-provm confere

# Identidade portátil: o mesmo --seed deriva a mesma identidade em QUALQUER OS/arch
cosmic auth spawn --seed 00010203… (e depois cosmic auth sign/verify)
```

Shards e identidade em `~/.cosmic` (ou `$COSMIC_HOME`).


## Fase tropical / PQC (port ET-COSMIC)

```bash
cargo test -p mycelium-tropical -p mycelium-pqc -p mycelium-distancebridge
```

Crates: `mycelium-tropical` (Max-Plus), `mycelium-pqc` (ML-KEM-1024), `mycelium-distancebridge` (seleção de transportes).

## Publicar um esporocarpo voluntário (zero VPS)

```bash
# De telemóvel 5G:
./scripts/probe-sporocarp.sh IP_PUBLICO 4001 telemovel-5g > proof.json

# No peer voluntário (não no CPE Vivo):
./scripts/verify-sporocarp.sh 4001 proof.json
MYCELIUM_REACHABLE=1 ./scripts/run-public-seed.sh
./scripts/export-seed.sh ~/.local/share/mycelium-seed >> seeds/mainnet.txt
```

24/7: `sudo MYCELIUM_REACHABLE=1 ./scripts/install-seed.sh`  
Docs: [docs/network/engenharia-reversa-bloqueio.md](docs/network/engenharia-reversa-bloqueio.md) ·
[docs/network/volunteer-sporocarp.md](docs/network/volunteer-sporocarp.md) ·
[docs/network/rizomorphs.md](docs/network/rizomorphs.md)

## 📜 Prova: site + assinatura sem hospedagem, sem domínio, sem VPS

```bash
bash scripts/prova-zero-infra.sh
```

O nó desta máquina é a hospedagem, o NodeId é o endereço (nenhum DNS) e a lease
ed25519 com `valid_until` é a assinatura do cliente — plano em
[docs/PROVA_ZERO_INFRA.md](docs/PROVA_ZERO_INFRA.md).

## 📚 Documentação Completa

- 🌟 **[Livro Mestre & Documentação Técnica Completa](docs/DOCUMENTACAO_COMPLETA.md)**: Manual definitivo cobrindo a arquitetura, VEIL Ω, COSMIC, Sclerotium e todos os 30 crates.
- 🗺️ **[Índice Geral de Documentos](docs/README.md)**: Mapa temático organizado por diretórios.
- 📦 **[Dicionário Exaustivo de Crates](docs/architecture/CRATES_REFERENCE.md)**: Referência técnica de cada crate do monorepo.
- 🧅 **[Protocolo VEIL Ω Onion Routing](docs/veil/VEIL_ONION_ROUTING.md)**: Roteamento pós-quântico de 3 saltos e proxy SOCKS5.
- 🪐 **[COSMIC Compute & QEL Storage](docs/cosmic/COSMIC_COMPUTE_STORAGE.md)**: Computação e armazenamento particionado K-de-N.
- 🍄 **[Sclerotium & Ghost Carrier](docs/sclerotium/RFC_SCLEROTIUM_GHOST_CARRIER.md)**: Hibernação biológica, WoL e despertar físico.

## Desenvolvimento

```bash
cargo build --workspace
cargo test --workspace
./scripts/e2e-demo.sh
```

## Licença

**GNU Affero General Public License v3.0** — veja [LICENSE](LICENSE).

Copyleft forte com cláusula de rede: quem distribuir ou oferecer o Mycelium
como serviço pela rede é obrigado a publicar o código-fonte das modificações.
Fork para lucrar sem devolver o código viola a licença.

> *"O futuro da computação não é construir castelos de silício. É plantar florestas de código."*
