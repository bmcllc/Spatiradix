# Spatiradix

O Spatiradix é uma rede ponto a ponto escrita em Rust. Ele conecta nós
com libp2p, armazena e compartilha conteúdo e oferece ferramentas para executar
serviços e distribuir código. Os componentes usam nomes inspirados em fungos:
as conexões são hifas, e o armazenamento de conteúdo é o Spore Bank.

O executável e os identificadores técnicos existentes continuam usando
`mycelium`, inclusive nos comandos e nas configurações mostrados abaixo.

Para localizar código e entender os limites entre componentes, consulte o
[guia de navegação do código](docs/architecture/NAVEGACAO_CODIGO.md).

## Comece por aqui

Estes comandos criam um nó local, iniciam o daemon e publicam uma mensagem.
Execute o daemon em um terminal separado e mantenha-o aberto para os passos
seguintes. Substitua `Qm…` pelo identificador completo retornado por `sow`.

```bash
# 1. Crie a identidade e registre os recursos em disco
cargo run -p mycelium-cli --release -- --home /tmp/node-a sprout --contribute 2cpu,4gb,100gb

# 2. Inicie o daemon (Event Horizon HTTP na porta 7474)
cargo run -p mycelium-cli --release -- --home /tmp/node-a daemon --contribute 2cpu,4gb,100gb --horizon-port 7474

# 3. Em outro terminal, publique a mensagem e inicie o fluxo
cargo run -p mycelium-cli --release -- --home /tmp/node-a sow --message "hello"
# anote o ContentId (Qm…)
cargo run -p mycelium-cli --release -- --home /tmp/node-a signal --plot Qm… --quorum 1 --ion webapp

# 4. Acesse o Ion pelo proxy HTTP Singularity
curl -s http://127.0.0.1:7474/webapp/ | jq .
```

Para executar a demonstração automatizada do Horizon, use `./scripts/horizon-demo.sh`.

Dois nós com bootstrap remoto:

```bash
# terminal A — seed na porta 4001
mycelium --home /tmp/a daemon --listen /ip4/0.0.0.0/tcp/4001

# terminal B
mycelium --home /tmp/b daemon --bootstrap /ip4/IP_DE_A/tcp/4001/p2p/PEERID_DE_A
```

Para conectar nós fora da rede local, use um catálogo HTTP, DNS ou um arquivo local:

```bash
mycelium seeds fetch --url ./seeds/mainnet.example.txt
mycelium daemon --public-bootstrap --bootstrap-url https://seu.host/seeds.txt
# ou arquivo local:
mycelium daemon --seed-file ./seeds/mainnet.example.txt --listen /ip4/0.0.0.0/tcp/4001
```

O Vacuum usa **bubblewrap** por padrão quando `bwrap` está no PATH. Suas camadas
ficam em `{home}/layers/`, endereçadas pelo conteúdo, e a RAM tem limites
soft via `RLIMIT_AS`.

Para experimentar uma rede que usa apenas o catálogo de seeds, sem mDNS ou
`--bootstrap` manual:

```bash
./scripts/seedbook-demo.sh
```

Outras demonstrações: `./scripts/e2e-demo.sh`, `./scripts/horizon-demo.sh`,
`./scripts/seedbook-demo.sh` e `./scripts/isotope-decay-demo.sh`.

[Demonstração local da Vitrine, da replicação P2P e do Root](docs/reports/demonstracao-2026-11-21.md)

## Spatiradix Habitat (Fase H0)

O daemon mantém um registro **local de manifestos de serviços assinados**, com
políticas `local`, `private` e `public`. Use `mycelium habitat register`, `list`
e `inspect`; o cadastro **não** replica, executa nem publica conteúdo.
Veja [Habitat — escopo, comandos e limites](docs/architecture/HABITAT_MVP.md).
A fase H2 adiciona um [teste de rota SOCKS5 via VEIL e medição de uso HTTP sem cobranças](docs/architecture/HABITAT_MYC_VEIL_H2.md).

## ARQ-Mint (QVP-2/ARQ adaptado à emissão PoUW)

O perfil ARQ experimental foi integrado ao `mycelium-mint`: modula a emissão
por diversidade de trabalho e concentração pseudônima, com quórum vinculado
à política em gênese. **Não converte scores em dinheiro e não foi ativado na
rede existente.** Consulte [ARQ-Mint privado](docs/architecture/ARQ_MINT_PRIVATE_POUW.md).

## Cameon (laboratório pós-quântico)

O crate experimental `mycelium-pqcripto` cifra mensagens privadas com ML-KEM-1024,
usa uma assinatura efêmera ML-DSA-87 e exige política de transporte sem fallback
inseguro. **Não é uma moeda transacionável**: gastos continuam bloqueados até
existirem consenso, provas PQ de saldo e conservação e nullifiers verificáveis.
O CUPP permite ao **comprador escolher Cameon para pagar a nota do vendedor**,
com valor exato, moeda, impostos e tarifas vinculados ao mandato assinado.
`payer_checkout` e `coverage` validam a admissão financeira em simulação
(risco ARQ + cobertura informada); **nenhuma liquidação, reserva ou débito
acontece**. A política antiga de 8 USDC é só um perfil comercial opcional.
Veja o [projeto Cameon e os critérios de implantação](docs/architecture/CAMEON_PQ_CHAMELEON.md).

## CLI unificada `lattice` (Forja + Rede)

```bash
# Crie um nó (folha atrás de CGNAT por padrão; --sporocarp exige prova)
./lattice plant

# Analise um binário com B.A.S.E. e publique o resultado no Event Horizon
./lattice resurrect caminho/para/firmware.bin
# → http://127.0.0.1:7474/webapp/

# lattice base … repassa comandos ao base-cli; daemon, sow e status ao mycelium-cli
```

É preciso compilar `target/release/mycelium` e
`Behavioral ASIC Synthesis Engine/target/release/base`, ou apontar para os
binários com `LATTICE_MYCELIUM_BIN` e `LATTICE_BASE_BIN`. O diretório de dados
usa `LATTICE_HOME` ou, por padrão, `~/.local/share/mycelium`.

## Código-fonte pela rede (sem git, sem GitHub)

```bash
# Semeia um diretório inteiro (recursivo) com visibilidade
mycelium --home ~/n1 seed-code --path ./meu-app --name meu-app \
  --description "app beta" --ion webapp --visibility public   # public|private|reserved|archived|community

# Em outro nó, baixe o código replicado via gossip/SporePrint
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
| `media publish/pin/pins` | Streaming e fixação de vídeos em chunks BLAKE3 de 2MB via enxame P2P (Spatiradix Video) |
| `rhizome ui/identity/post/story/video/chat-send/import-x/import-whatsapp` | Super-app social soberano (`/rhizome/`): YouTube/Reels, Instagram/Stories (Isotope), Facebook/Comunidades, X/Microblog e WhatsApp PQ E2EE (ML-KEM-1024 + DTN + Nostr) |
| `channel create/publish/show` | Gestão de canais descentralizados assinados por chave criptográfica |
| `playlist create/add` | Criação e versão de playlists portáteis e soberanas |
| `sclerotium hardware/lease/status/wake` | Protocolo Sclerotium: dormência profunda, GhostLease, Wake-on-LAN e WakeToken anti-DoS |
| `veil start/stop/status/descriptor` | Roteamento cebola pós-quântico VEIL Ω de 3 saltos (Guard/Relay/Exit), Anti-SSRF e SOCKS5 (:1080) |
| `shutdown` | Hiberna o daemon (estado fica em disco) |

## Documentação

Para entender o projeto ou encontrar detalhes de implementação, comece por estes documentos:

- **[Arquitetura geral](docs/architecture/ARQUITETURA_GERAL_SISTEMICA.md)**: camadas e fluxos do projeto.
- **[Referência de crates](docs/architecture/CRATES_REFERENCE.md)**: descrição dos componentes do repositório.
- **[VEIL Ω — Roteamento Cebola Pós-Quântico](docs/veil/VEIL_ONION_ROUTING.md)**: Especificação da rede cebola de 3 saltos com ML-KEM-768 e isolamento Anti-SSRF.
- **[COSMIC — Compute & Storage Pós-Quânticos](docs/cosmic/COSMIC_COMPUTE_STORAGE.md)**: Fragmentação QEL K/N, atestações e licenças VOID-00 (ML-DSA-87).
- **[RFC Sclerotium & Ghost Carrier](docs/sclerotium/RFC_SCLEROTIUM_GHOST_CARRIER.md)**: Especificação de dormência biológica, GhostLease e despertar seletivo.
- **[Índice de documentação](docs/README.md)**: documentos organizados por tema.
- **[Documentação completa](docs/DOCUMENTACAO_COMPLETA.md)**: visão abrangente da arquitetura e dos componentes.
- **[Rhizome](docs/architecture/RHIZOME_SUPERAPP.md)**: aplicação social e seus protocolos.
- **[Build Android](docs/architecture/ANDROID_SOVEREIGN_BUILD.md)**: geração de APK ARM64.

## Principais crates

O workspace reúne vários componentes. A tabela apresenta alguns deles; a lista
atual de membros está em [Cargo.toml](Cargo.toml).

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
| `mycelium-rhizome` | L4 | **Super-app social soberano (`/rhizome/`)**: YouTube/Reels, Stories (Isotope), Comunidades, Microblog/X, Chat PQ E2EE (ML-KEM-1024 + DTN) e bridges (Nostr, RSS, ActivityPub, importadores X/WhatsApp) |
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

## Conexão atrás de CGNAT (Nostr, QEL e IPFS local)

O modo híbrido usa conexões de saída `wss://` na porta 443 e armazenamento local
de blocos. Para experimentá-lo:

```bash
mycelium sow --message "floresta" --hybrid
# noutro home (cola o Qm… completo):
mycelium --home /tmp/folha-b recall --plot Qm… --hybrid
./scripts/hybrid-demo.sh
```

Docs: [docs/network/nostr-qel.md](docs/network/nostr-qel.md) · voluntário mesh: [docs/network/candidatos.md](docs/network/candidatos.md) · ET-COSMIC bridge: [docs/cosmic/et-cosmic-bridge.md](docs/cosmic/et-cosmic-bridge.md) · feature CLI `nostr` (default).

## COSMIC: armazenamento, computação e identidade

O COSMIC reúne ferramentas para armazenamento fragmentado, computação
verificável e identidade portátil. O projeto está descrito em
[cosmic-design.md](docs/cosmic/cosmic-design.md). Exemplos com o binário
`cosmic` (crate `cosmic-cli`):

```bash
# Storage QEL: fragmenta em shards pós-quânticos (3/7), multicanal.
# --home <nó> distribui os shards na malha Spatiradix via Isotope (qualquer peer recupera).
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

## Prova: site + assinatura sem hospedagem, sem domínio, sem VPS

```bash
bash scripts/prova-zero-infra.sh
```

O nó desta máquina é a hospedagem, o NodeId é o endereço (nenhum DNS) e a lease
ed25519 com `valid_until` é a assinatura do cliente — plano em
[docs/PROVA_ZERO_INFRA.md](docs/PROVA_ZERO_INFRA.md).

## Desenvolvimento

```bash
cargo build --workspace
cargo test --workspace
./scripts/e2e-demo.sh
```

## Licença

O Spatiradix está disponível sob a [GNU Affero General Public License versão 3
ou posterior (AGPL-3.0-or-later)](LICENSE). Componentes de terceiros e projetos
incorporados separadamente podem ter suas próprias licenças; consulte seus
respectivos avisos.
