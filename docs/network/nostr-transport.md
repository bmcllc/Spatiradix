# Nostr Transport — libp2p sobre CandidateRelay

O transporte Nostr permite que uma folha atrás de CGNAT se conecte a pares
por relays Nostr públicos, sem anunciar um esporocarpo. A conexão depende de
relays disponíveis e de outros pares acessíveis.

## Princípio

O backchannel (kind 39406) é um canal bidirecional sobre conexões WSS de saída.
O crate `mycelium-nostr-transport` o expõe como um `Transport` libp2p; o
Swarm usa Noise e Yamux sobre esse transporte.

```text
Aplicação / Kademlia / GossipSub
        ↓
   Noise + Yamux   (stack libp2p)
        ↓
   NostrTransport  (AsyncRead/Write + seq/ACK)
        ↓
   kind 39401 descoberta + kind 39406 dados
        ↓
   wss://relay…   (outbound — CGNAT OK)
```

**Invariante intacto:** isto **não** é `/esporocarp`. Não anuncia relay circuit. Não exige `MYCELIUM_REACHABLE`.

## Multiaddr

Forma lógica: `/nostr/<relay>/<ghost_hex>`

Codificação usada aqui (não há multicodec `/nostr`):

```text
/unix/mycelium-nostr/<relay_url_hex>/<ghost_hex64>
```

Helpers: `encode_nostr_multiaddr` / `parse_nostr_multiaddr` / `listen_multiaddr`.

## Uso

```bash
# Build (default CLI já inclui nostr-transport)
cargo build -p mycelium-cli --release

# Folha/Floresta: Nostr transport liga-se sozinho (auto).
MYCELIUM_HOME=/tmp/folha-a mycelium daemon --no-mdns

# Forçar ON / OFF:
mycelium daemon --nostr-transport
mycelium daemon --no-nostr-transport

# Smoke dois homes:
./scripts/nostr-transport-smoke.sh
```

Env: `MYCELIUM_NOSTR_TRANSPORT=1` (força ON), `MYCELIUM_NOSTR_RELAY=wss://nos.lol`.

O GhostID é mantido em `{home}/candidate.session` (TTL de aproximadamente uma
hora). O nó anuncia novamente a cada 60 segundos; a descoberta descarta anúncios
expirados e prefere os que usam `listen:`.

## Limitações (MVP)

- Latência 200–400 ms via relay público
- Rate-limit dos relays — só controlo/gossip leve, não sync grande
- DCUtR / hole punch: fora deste MVP
- GhostID-por-pacote HD: fora deste MVP

## Relação com CandidateRelay CLI

| Comando | Papel |
|---------|--------|
| `mycelium candidate listen/send` | chat backchannel sem Swarm |
| `mycelium daemon` (folha/floresta) | mesh libp2p (`vizinhos`) via Nostr |

Ver [`candidate-relay.md`](candidate-relay.md).
