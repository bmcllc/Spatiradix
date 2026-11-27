# CandidateRelay — terceiro estado (kind 39401)

CandidateRelay ajuda nós atrás de CGNAT a descobrir pares usando Nostr, sem
anunciar que aceitam conexões de entrada como esporocarpos.

```text
/esporocarp      ⇔ MYCELIUM_REACHABLE   (permanente, proof.json)
/candidate-relay ⇔ Nostr outbound       (temporário, TTL ~5 min, sem proof)
/folha           ⇔ sem inbound público  (pode ter peers de saída)
```

## Problema

Uma folha atrás de CGNAT pode não receber conexões diretas. Sem um par
alcançável ou outro caminho de descoberta e transporte, ela pode permanecer
sem vizinhos. O modelo anterior descrevia esse caso como um ponto fixo do
operador Bellman `(Bφ)_i = sup_j(b_ij + φ_j)`.

O mailbox (`sow`/`recall --hybrid`, kind 31234) permite troca assíncrona.
Para uma conexão ativa entre duas folhas atrás de CGNAT, CandidateRelay oferece
um mecanismo de encontro por relays Nostr.

## Algoritmo (P0)

```text
Cada 30–300s (jitter):
  1. GhostID efémero (secp256k1 / Schnorr)
  2. Publicar kind 39401 (expires=now+300, backchannel=relay)
  3. Subscrever kinds=[39401] recentes
  4. Verificar sig + TTL; handshake com tag #p
  5. Derivar shared secret de sessão (binding P0)
  6. Prune expirados
```

Nenhuma referência à identidade permanente (`gland.seed` / PeerId).

## CLI

```bash
# Descoberta (kind 39401)
mycelium candidate
mycelium candidate --loop

# Sessão estável para mensagens (grava {home}/candidate.session)
mycelium candidate whoami

# Terminal A — escuta + re-anuncia
MYCELIUM_HOME=/tmp/cand-a mycelium candidate listen --loop

# Terminal B — substitua GHOST_A pela chave impressa no terminal A
MYCELIUM_HOME=/tmp/cand-b mycelium candidate send --to GHOST_A -m "ola da folha B"

# Novo GhostID
mycelium candidate reset
```

Duas sessões no mesmo computador precisam de diretórios `MYCELIUM_HOME`
distintos, pois cada uma mantém seu próprio `candidate.session`.

Métrica: `candidate_peers > 0` **não** promove a membrana a esporocarp.

## Kinds QEL (reserva)

| Kind | Nome |
|------|------|
| 39400 | QEL_PRESENCE |
| **39401** | **QEL_CANDIDATE_RELAY** (descoberta) |
| **39406** | **QEL_BACKCHANNEL** (NIP-44, tag `#p`) |
| 31234 | QEL_SHARD mailbox |

## Roadmap

| Prioridade | Item | Estado |
|------------|------|--------|
| P0 | Announce + discover + handshake | ✅ `mycelium candidate` |
| P0 | Backchannel cifrado bidirecional | ✅ `listen` / `send` (NIP-44) |
| P0 | Transporte libp2p sobre Nostr | ✅ `mycelium-nostr-transport` + `--nostr-transport` |
| P1 | Hole punching UDP (Ford 2005) | pendente |
| P2 | Keep-alive NAT | pendente |
| P3 | LoRa / SMS / DTN DistanceBridge | pendente |

Doc do transporte: [`nostr-transport.md`](nostr-transport.md).


## Riscos

1. **CGNAT simétrico UDP** — hole punching pode falhar; Nostr WSS é uma alternativa, com vazão dependente do relay.
2. **Bootstrapping frio** — primeira folha sozinha mantém ponto fixo; precisa de ≥2 folhas ou “esporocarpo verde” (IP público a publicar 39401 **sem** fingir `/esporocarp`).
3. **Latência do relay** — varia conforme o relay e a rota; compare relays disponíveis na região.

## Relação com esporocarpo voluntário

| | CandidateRelay | Esporocarpo |
|--|----------------|-------------|
| Proof inbound | Não | Sim (`proof.json`) |
| Membrana | permanece folha | `/esporocarp` |
| Uso | descoberta + backchannel Nostr | circuit relay libp2p |
| CGNAT Vivo | sim | não (folha) |

Ver [`invariante_membrana.md`](invariante_membrana.md), [`nostr-qel.md`](nostr-qel.md), [`volunteer-sporocarp.md`](volunteer-sporocarp.md).
