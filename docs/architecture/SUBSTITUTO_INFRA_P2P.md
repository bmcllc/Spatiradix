# Substituto de VPS, hospedagem, domínio, git, Docker e servidores — Mycelium + MAPS

Data: 2026-10-17. Status: **plano de arquitetura**, nada aqui está implementado além do
que já existe no repo e está marcado como tal. O placar oficial continua sendo
[`docs/VALIDACAO.md`](../VALIDACAO.md) (nível a cumprido; b, c, d e E6 = 0/9).

Objetivo do usuário: **usar a pilha inteira sem o computador ligado, com mais de um nó**,
misturando o Mycelium com o framework MAPS
([pavrus117/ai-os-maps-guide](https://github.com/pavrus117/ai-os-maps-guide)).

---

## 0. O hardware necessário

"Sem o computador ligado" **não** significa "sem nenhum hardware ligado". Bytes e
processos só existem em máquinas que estão online. O que a descentralização troca é
*quem* liga a máquina:

| Modelo atual | Modelo Mycelium |
|---|---|
| 1 VPS alugado, 1 empresa, 1 cartão de crédito | N nós baratos/voluntários; qualquer um cai e o serviço continua |
| Você paga uptime | Uptime = soma das réplicas online (E1/E2) |

Para o cenário planejado aqui, a proposta considera **3 nós em locais e fontes
de energia diferentes**, com pelo menos 2 ligados e 1 alcançável de fora, por
conexão direta ou relay. Isso é uma hipótese operacional, não uma garantia de
disponibilidade. O notebook pode desligar enquanto outros nós assumem o serviço,
desde que a replicação e o acesso tenham sido configurados e validados.

Candidatos a nó sempre-ligado, do mais barato ao mais caro:

1. **Celular Android velho na tomada + Wi-Fi.** Já existe binário:
   `dist/mycelium-android-arm64` (NDK r30, Android 24+). Rodar via Termux com
   `termux-wake-lock`. Custo: ~R$ 0 (aparelho parado) + ~2–4 W.
2. **Raspberry Pi / TV box / mini-PC** (ARM ou x86, 3–10 W).
3. **Nó de amigo/comunidade** (pacto recíproco: eu pino o seu, você pina o meu — é o
   `seeds catalog` + pinning R≥3 da E1).
4. **Seed pago "sempre-ligado" de terceiro** — mesmo modelo do Radicle Garden
   (€4,99/mês por seed com replicação garantida). Não é autoridade: é só mais um
   detentor substituível. Isso é o produto nº 1 do
   [`PLANO_PRODUCAO_MONETIZACAO.md`](../PLANO_PRODUCAO_MONETIZACAO.md).

O problema do CGNAT Vivo (todo inbound ❌ em
[`mapa_cpe_vivo.md`](../network/mapa_cpe_vivo.md)) se resolve **sem VPS** pela
ordem da E3: QUIC direto → hole punching (DCUtR) → circuit relay v2 num nó
alcançável → transporte Nostr outbound `wss://:443` (já existe:
`mycelium-nostr-transport`, `--hybrid`). Celular em 5G + casa em CGNAT só conversam
se houver **pelo menos um** relay acessível — de um voluntário ou de um relay Nostr
público. Isso é dependência de terceiro *substituível*, não de servidor próprio.

---

## 1. Tabela de substituição

| Hoje | Substituto Mycelium | Já existe no código | Falta (etapa) | Referência externa |
|---|---|---|---|---|
| **VPS** (compute 24/7) | Ion rodando em Vacuum Chamber em ≥2 nós; migração `IonOffer → IonAccept → IonMigrate → IonReady` | `mycelium-node/organism.rs` (IonOffer/IonMigrate autenticado), `ion-migrate`, `vacuum` | failover real cross-host, estado persistente (E2) | Akash/Flux (mercado de compute) — modelo de lease, mas exigem token/cadeia |
| **Hospedagem** (arquivos/site) | Plot content-addressed no Spore Bank + pinning R≥3 + anti-entropy | `sporebank`, `seed-code`, anti-entropy por manifesto (E1.3 provado em loopback) | recibos de custódia, quota/GC, prova entre hosts (E1.2/E1.4) | nsite (NIP-5A): manifesto path→hash servido por gateways |
| **Domínio / DNS** | NodeId/PeerId é o endereço; Ion é o nome de serviço; alias humano opcional | `prova-zero-infra.sh` (NodeId no lugar do domínio), `/dnsaddr/` no bootstrap | **registro de nomes assinado** (ver §3.3) | Nostr NIP-05 / ENS / Handshake como *aliases*, nunca obrigatórios |
| **HTTPS para navegador comum** | gateway voluntário intercambiável → Event Horizon remoto via fluxo P2P | `singularity` (proxy, fallback de 3 réplicas) | túnel HTTP-sobre-libp2p até Chamber remota, 2 gateways (E4) | gateways nsite / IPFS |
| **.git / GitHub** | `repo publish/clone`, `seed-code/recall-code` (árvore → Plot multi-leaf) | `cli` `Repo`, `SeedRepo`, `RecallCode` | histórico/branches assinados, issues/patches | **Radicle** (git P2P maduro, 1.0, ~600 nós/semana) e NIP-34 — interoperar em vez de reinventar |
| **Docker** | Vacuum: bubblewrap + layers content-addressed + RLIMIT | `vacuum/process.rs`, `layers.rs` | cgroups reais, quotas fail-closed (E5.3); alvo **WASM** para portabilidade ARM/x86 | wasmtime/WASI 0.3 (preview) — sandbox por capability, roda igual em celular e PC |
| **Servidores / rede privada** (Tailscale do MAPS) | malha hyphae (Noise/QUIC) + VEIL para tráfego sensível; membrana private | `hyphae`, `veil`, `membrane.rs` | relay sem URL fixa (E3), teste CGNAT real | iroh 1.0 (dial por chave, hole punching em QUIC) como referência |
| **CI / cron do servidor** | Pulse distribuído (§2.3) + `inertia` (build/test/deploy) | `inertia`, `thefield` (Signal+quórum) | registro de rotinas replicado + eleição por lease | — |
| **Despertar máquina dormindo** | Sclerotium: GhostLease + WakeToken + WoL | `mycelium-sclerotium` (wake.rs, lease.rs) | WoL atravessando a malha até a LAN alvo | — |

---

## 2. MAPS reescrito em cima do Mycelium

O MAPS original depende de **um VPS (Hostinger) + Tailscale + git sync a cada 5 min**.
Aqui cada camada perde essas três dependências.

### 2.1 M — Memory (mapa de tudo, 2 saltos)

- Mantém as regras do MAPS: um arquivo-raiz ≤60 linhas que só aponta; um signpost por
  área ≤80 linhas com as seções fixas `Projects, State, Skills, Memory, Routines,
  Not here`; todo fato tem uma casa só; checador noturno com exit ≠ 0.
- **Mudança:** a pasta da memória é um **repo Mycelium** (`mycelium repo publish`),
  não um remoto git. Cada nó recebe o Plot por gossip/DHT e pina. O checador vira uma
  rotina Pulse (§2.3), roda em qualquer nó vivo.
- Conflito: arquivos de memória são *append-only* (regra 2 do MAPS), então a fusão é
  união de logs — evita o LWW do Isotope, que perde escrita concorrente (E2.2).

### 2.2 A — Agent (o mesmo agente em N máquinas)

- Original: notebook + 1 VPS. Aqui: **notebook + celular-nó + Pi/amigo**, todos com a
  mesma memória via Spore Bank.
- Rede privada: no lugar do Tailscale, a membrana `private` do hyphae (só PeerIds na
  allowlist) e firewall com **inbound fechado**; o tráfego sai por relay/Nostr.
- Mantém as travas do MAPS, que são boas e independem de infra:
  usuário sem privilégio; perfil de ferramentas que **nega enviar/compartilhar/
  apagar** (o máximo é deixar rascunho); login pelo fluxo oficial de setup-token da
  própria assinatura — nunca sessão copiada nem harness de terceiro.
- O agente roda como **Ion** num nó escolhido; se o nó cai, a lease expira e outro nó
  da lista assume (§2.3). Só um executa por vez.

### 2.3 P — Pulse (rotinas sem você)

Registro único (como no MAPS): `nome, agenda, nós elegíveis, prompt/skill, modelo,
esforço, ferramentas, max-turns, timeout, saída`. Diferenças:

- O registro vive no repo de memória e é replicado.
- **"Qual máquina roda"** deixa de ser fixo: cada execução pega uma **GhostLease**
  curta (`sclerotium::lease`, ed25519 + `valid_until`) anunciada no gossip. Quem
  segura a lease válida roda; os outros esperam. Lease vence sem heartbeat → outro
  nó elegível assume. Isso é eleição de líder por expiração, sem servidor.
- Cada execução anexa uma linha ao log (hora, nome, nó, turnos, custo, status) —
  também replicado. Os dois tetos do MAPS (diário + janela curta) são lidos desse
  log *global*, então três nós não triplicam o gasto.
- Nó dormindo e elegível: o Pulse pode mandar WakeToken (Sclerotium) antes.

### 2.4 S — Screen (painel que mostra e não guarda)

- Vira um Ion estático servido pelo **Event Horizon** (`/vitrine` já existe) de
  qualquer réplica. Lê só JSON que rotinas já escreveram; marca painel velho como
  *stale*; sem cookie/login/JS de terceiro.
- Acesso: nativo pela malha (sem navegador público) ou por gateway voluntário com
  HTTPS (E4). Nunca porta pública no nó doméstico.
- Botão "play" = gravar um pedido na fila replicada; quem tiver a lease executa.
- Os dados do "brain" (grafo) podem vir do `graphify-out/graph.json` que já existe.

---

## 3. Decisões de desenho

### 3.1 Não reinventar o que já é maduro
- **Git:** o `repo publish` atual distribui árvores, não histórico. Para colaboração
  real, interoperar com **Radicle** (Heartwood, git puro, NID por chave) — o Mycelium
  pode ser só mais um seed Radicle e transporte. Evita manter um git próprio.
- **Site estático:** espelhar o formato de manifesto do **nsite** (path → hash) no
  Plot permite que gateways Nostr existentes sirvam o mesmo site.

### 3.2 Contêiner: Vacuum agora, WASM depois
`bwrap` só existe em Linux; celular Android e Windows não têm. Para "qualquer nó roda
qualquer serviço" o formato portátil é **componente WASM** (wasmtime). Plano: Vacuum
aceita dois tipos de Chamber — `bwrap` (Linux, código nativo) e `wasm` (qualquer
arquitetura, capability-based). Ion declara qual precisa; a migração só oferta para
nós com a capacidade (`store caps` já lista motores).

### 3.3 Nomes sem DNS
Nome humano = registro assinado `{nome, PeerId/Ion, seq, valid_until}` publicado no
DHT e gossip; vale o maior `seq` assinado pela mesma chave. Alias externos
opcionais (NIP-05, ENS) apontam para o PeerId. Não resolve disputa de nome global —
por desenho, o nome é *local à chave* (como `npub`); isso é limite, não bug.

---

## 4. Fases e gates (ligados à E1–E6)

Cada fase só fecha com evidência medida entre **máquinas diferentes**, nunca loopback.

| Fase | Entrega | Gate de aceitação | Etapa |
|---|---|---|---|
| **F0 — 3 nós reais** | notebook + celular (binário android) + 1 nó sempre-ligado; 1 relay alcançável | `neighbor_ids` não-vazio nos 3; log de gossip cross-host; **desligar o notebook** e os outros 2 continuam conversando | T1–T3, E6 #1 |
| **F1 — Hospedagem** | site estático (Plot) pinado em R=3 | publicador desligado; `recall` + GET via Horizon nos outros 2 | E1, E6 #3/#4 |
| **F2 — Memória MAPS** | repo de memória replicado + checador noturno | editar no celular, ler no Pi sem o notebook | E1 |
| **F3 — Pulse distribuído** | registro + lease + log global + tetos | matar o nó que segura a lease no meio; outro assume em < 2× TTL; contagem de execuções não duplica | E2 |
| **F4 — Screen** | painel no Horizon, 2 gateways | derrubar 1 gateway, o outro serve | E4, E6 #6 |
| **F5 — VPS substituído** | Ion com estado migrando entre nós (Vacuum/WASM) | GET e escrita persistem após derrubar o host primário | E2, E5.3 |
| **F6 — Nomes + git** | registro de nomes assinado; ponte Radicle | clone por nome sem DNS; seed Radicle recebe push | — |

F0 é o bloqueio real (o mesmo de [`PLANO_PRODUCAO_MONETIZACAO.md`](../PLANO_PRODUCAO_MONETIZACAO.md)
§1): enquanto tudo for 1 máquina, nenhuma fase acima é verificável.

---

## 5. Riscos

- **Disponibilidade ≠ descentralização.** 3 nós domésticos na mesma queda de luz
  são 1 nó. Distribuir por endereço/energia.
- **Relay de terceiro** (Nostr público) pode limitar ou sumir — manter ≥2 e rotação (E3.2).
- **Celular:** Android mata processos em segundo plano; exige wake-lock, exclusão de
  otimização de bateria e carregador. Medir uptime real antes de contar como "sempre ligado".
- **Agente sem supervisão** em nó de terceiro: o perfil sem enviar/apagar e o teto de
  custo do Pulse são obrigatórios, não opcionais. Credenciais da assinatura só em nós
  seus — nunca em nó de amigo/voluntário.
- **Dados privados:** hoje Plots restritos não saem do nó (E0). Memória pessoal
  replicada exige a criptografia ponta a ponta da E5.2 antes de ir a nó alheio.

---

## 6. Fontes

- MAPS: <https://github.com/pavrus117/ai-os-maps-guide>
- Radicle (FAQ, números de abr/2026): <https://radicle.dev/faq> · Radicle Garden: <https://radicle.garden/>
- iroh 1.0 (dial por chave, hole punching): <https://pinggy.io/amp/blog/iroh_1_0_dial_keys_not_ips/>
- nsite / NIP-5A: <https://github.com/soveng/nsite> · <https://nips.4rs.nl/nips/5a>
- NIP-34 (git sobre Nostr, cliente n34): <https://rust-digger.code-maven.com/crates/n34>
- Compute descentralizado (Akash/Golem, APNet 2026): <https://akash.network/blog/akash-vs-the-grid/>
- WASM vs contêiner: <https://www.morphllm.com/comparisons/wasm-vs-docker>
