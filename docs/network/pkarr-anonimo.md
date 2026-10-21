# Pkarr anônimo — um nó, sem seed, sem DNS, sem VPS

Data: 2026-10-18. Crate: [`crates/mycelium-pkarr`](../../crates/mycelium-pkarr).
CLI: `mycelium pkarr {init,address,publish,resolve}`.
Nível de validação: **(a)**, mais uma evidência real: publicação e resolução
**via Tor** em 2 relays Pkarr públicos (2026-10-19, ver
[`testes-realidade.md`](../reports/testes-realidade.md)). Ainda não testado por
dentro de um circuito VEIL vivo.

Atende o gate **G1** de [`EVOLUCAO_2NOS_SOBERANA.md`](../architecture/EVOLUCAO_2NOS_SOBERANA.md),
adaptado a **um nó só e anônimo**: o nó fica encontrável por um endereço
`myc1…` sem revelar quem é nem onde está.

---

## 1. O que o desenho original vazava, e o que mudou

O roteiro original (§2.1 do EVOLUCAO_2NOS) publicava, sob a chave do nó
(`Gland`), os **multiaddrs com IP**, falando UDP direto com a Mainline DHT. Para
um nó anônimo isso entrega três coisas de uma vez:

1. **o IP** (no registro e no tráfego UDP com centenas de nós da DHT);
2. **a ligação** entre o registro e a identidade de rede do nó;
3. **a linha do tempo**, porque a mesma chave é republicada para sempre.

Este crate inverte as três:

| Ameaça | Defesa implementada | Onde |
|---|---|---|
| DHT ou relay liga os registros entre si e à identidade | chave **cegada por época** `A_e = H(A‖e)·A` (técnica do onion v3 do Tor); época de 24 h | `blind.rs` |
| Observador lê os endpoints | conteúdo cifrado em **XChaCha20-Poly1305**, chave HKDF do endereço e da época | `anon.rs` |
| Cifrado transplantado ou reaproveitado | AAD = chave da época ‖ timestamp | `anon.rs` |
| O tamanho denuncia quantos e quais endpoints | texto claro **acolchoado** a 700 B; todo pacote tem o mesmo tamanho (896 B) | `anon.rs` |
| O registro aponta para o IP | só endpoints **sem IP**: Nostr `wss://` com domínio, descritor VEIL, onion v3, ContentId; validados **ao publicar e ao resolver** | `anon.rs::validate` |
| O relay vê o IP de quem publica ou resolve | só sai por **SOCKS5 local** (VEIL `127.0.0.1:1080` ou Tor `9050`) com `socks5h` (DNS resolvido no proxy); proxy não-loopback é recusado; `HTTP_PROXY` do ambiente é ignorado; sem redirecionamento; só HTTPS; sem User-Agent | `relay.rs` |
| Quem conhece o endereço forja registro | assinar sob `A_e` exige o escalar mestre `a` | `blind.rs` |
| A chave do serviço liga o operador ao nó | identidade mestra **separada** do NodeId/`Gland` | `keystore.rs` |
| Chave roubada do disco por outro usuário | arquivo `0600` em diretório `0700`, criado com `create_new`; recusa na leitura se legível por outros, se for symlink ou se o dono for diferente | `keystore.rs` |
| Registro velho em cache | validade limitada à época seguinte; o resolvedor recusa épocas com mais de 1 de atraso e timestamps mais de 10 min no futuro | `anon.rs` |
| Precisão do relógio como impressão digital | timestamp arredondado para o segundo | `anon.rs::seal` |
| Parser de dados hostis | DNS escrito à mão com limites explícitos, laço de ponteiros limitado, nunca entra em pânico (há teste com lixo) | `dns.rs` |

**Modo privado** (`init --private`): o endereço passa a carregar um segredo de
32 B (`myc1<chave>.<segredo>`). Sem o segredo, nem quem descobriu a chave
mestra lê os endpoints. Funciona como a autorização de cliente do Tor.

### Por que relay HTTP e não a DHT direto

UDP não passa pelo SOCKS5 do VEIL nem do Tor, e falar com a DHT expõe o IP. O
relay Pkarr recebe o pacote **por dentro do circuito** e o grava na DHT. Ele vê
só a chave da época e o cifrado. O formato é o mesmo da DHT, então qualquer
relay Pkarr serve, e há teste provando que a implementação de referência aceita
o pacote.

---

## 2. Uso (um nó)

```bash
# 1. identidade (uma vez). Faça backup de ~/.mycelium/pkarr/
mycelium pkarr init --private
mycelium pkarr address          # → myc1…  (entregue só a quem deve achar o serviço)

# 2. com o VEIL rodando (SOCKS5 em 127.0.0.1:1080) ou o Tor (--socks 127.0.0.1:9050):
mycelium pkarr publish \
  --nostr-pubkey <64hex> --nostr-relay wss://nos.lol --nostr-relay wss://relay.damus.io \
  --every 1800                  # republica com jitter de ±20 %; troca de chave na virada da época

# 3. do outro lado (também via SOCKS5):
mycelium pkarr resolve 'myc1…'

# conferir sem rede:
mycelium pkarr publish --plot <cid> --dry-run
```

`--unsafe-direct` existe só para teste e avisa que revela o IP.

### Recebi o endereço, conectei

```bash
# no nó anônimo: publica o próprio endpoint Nostr (GhostID + relay do daemon)
mycelium pkarr publish --from-node --socks 127.0.0.1:9050 --every 1800
# em qualquer outro nó com daemon rodando:
mycelium pkarr connect 'myc1…' --socks 127.0.0.1:9050
```

`connect` resolve, decifra e envia `Request::DialNostr` ao daemon local para
cada relay anunciado. Prova (2026-10-21): par configurado em `wss://nostr.wine`,
nó anônimo em `wss://relay.primal.net`. O par ficou com 0 vizinhos até o
`connect`; o único dial no log dele foi o do endereço resolvido e a vizinhança
fechou em ~2 s. O nó anônimo seguiu sem conexão fora do Tor e sem UDP.

---

## 3. Evidência

`cargo test -p mycelium-pkarr` → **24/24**. `cargo clippy -p mycelium-pkarr --all-targets -- -D warnings` → 0.

- `reference_pkarr_accepts_our_anonymous_packet` e `we_accept_reference_pkarr_packet`: compatibilidade nos dois sentidos com `pkarr` 8.1.
- `observer_sees_neither_identity_nor_content`: a chave mestra e os endpoints não aparecem em nenhum byte do pacote, e a chave muda a cada época.
- `all_records_have_the_same_size`: um endpoint ou três dão o mesmo tamanho.
- `tampering_is_detected`: um bit trocado em qualquer posição amostrada é recusado.
- `other_identity_cannot_impersonate`, `private_mode_requires_access_secret`, `freshness_rules`.
- `ip_revealing_endpoints_are_refused`: IP v4/v6, `ws://`, `localhost`, `.local`, `.lan`, credencial na URL, query, onion v2 e multiaddr.
- `relay_traffic_goes_only_through_local_socks5h`: um SOCKS5 falso confirma que o cliente envia o **nome** (ATYP=3) e falha fechado.
- `dead_proxy_never_falls_back_to_direct`.
- Keystore: não sobrescreve e recusa arquivo com permissão `0644`.

Smoke da CLI (home temporário): `init --private` cria arquivos `0600`/`0700`;
relay `wss://1.2.3.4` é recusado; `--socks 8.8.8.8:1080` é recusado; com SOCKS
morto o comando falha sem tentar conexão direta; com chave `0644` a leitura é
recusada.

---

## 4. Não há "garantia total" — riscos residuais

Segurança total não existe. Abaixo estão os limites reais deste componente:

1. **O anonimato depende do circuito.** O crate garante só que nada sai fora do
   SOCKS5. Se o VEIL tiver falha, o IP vaza ali. O VEIL nunca foi validado na
   WAN nem auditado por terceiro (nível (b)/(c) não cumpridos, ver
   [`VALIDACAO.md`](../VALIDACAO.md)). Para anonimato forte hoje, o Tor
   (`--socks 127.0.0.1:9050`) é mais maduro.
2. **Adversário global passivo** pode correlacionar o horário das publicações
   com o tráfego do nó. O jitter reduz isso, mas não elimina.
3. **Quem tem o endereço lê os endpoints.** O endereço é a credencial. Vazou,
   rotacione com `init` em outro home e um novo endereço.
4. **Um nó = R=1.** Desligou o nó, o serviço some. O registro continua na DHT
   até expirar, mas aponta para algo morto. Anonimato não é disponibilidade.
5. **Relays podem censurar ou sumir.** Isso afeta a disponibilidade, não o
   sigilo. Configure 2 ou mais com `--relay`. Os padrões são públicos e
   substituíveis.
6. **A segurança do cegamento** se apoia no mesmo argumento do onion v3 do Tor
   (fator derivado por hash da chave e da época). A implementação foi revisada
   só pelo autor; não houve auditoria criptográfica externa.
7. **Endpoint comprometido**: malware no nó lê `master.key`. O crate protege
   contra outros usuários da máquina, não contra root nem contra o seu usuário.
8. **Os endpoints que você publica** precisam ser anônimos também: o nó deve
   conectar aos relays Nostr **pelo VEIL ou Tor**. Este crate valida o formato,
   não o caminho de rede do resto do sistema.

## 5. Próximos passos (para sair do nível (a))

- ~~Publicar e resolver por um circuito real até um relay público~~: feito via
  Tor em 2026-10-19. Falta repetir pelo VEIL.
- Integrar ao daemon: republicação automática e endpoint Nostr derivado do
  `GhostID` efêmero.
- Revisão externa da derivação de cegamento.

---

## 6. Nó anônimo: `mycelium daemon --anonymous`

O registro anônimo só serve se o nó também não vazar ao ser contatado. Por
isso o daemon ganhou um modo em que **todo** o tráfego de rede sai pelo SOCKS5
local.

```bash
mycelium daemon --anonymous                           # Tor em 127.0.0.1:9050 (padrão)
mycelium daemon --anonymous --anon-socks 127.0.0.1:1080   # SOCKS5 do VEIL
```

| Caminho de rede | Antes | No modo anônimo |
|---|---|---|
| WebSocket Nostr (transporte, CandidateRelay, RelayPool) | direto | só via SOCKS5, nome resolvido no proxy (`socks5h`), só `wss://`; sem fallback (`mycelium_nostr::net`) |
| Swarm libp2p | TCP + QUIC + DNS Cloudflare + mDNS | só o transporte Nostr (+ circuitos relay por cima dele); endereço IP **não tem transporte** para discar |
| Escuta | `0.0.0.0`/IPv6 global | nenhuma escuta em IP; só o endereço Nostr (GhostID + URL do relay) |
| Health check de seeds | TCP cru até cada seed | desligado |
| DuckDNS, sporocarp, relay server, UPnP | opcionais | recusados |
| Event Horizon e ions HTTP | loopback | loopback obrigatório (`MYCELIUM_HORIZON_BIND` não-loopback é erro) |

**Fail-closed:**
- O daemon não sobe se o SOCKS5 não responder ao handshake.
- Cada uma destas opções vira **erro**, não aviso: `--listen`,
  `--announce-ip`, `--public-bootstrap`, `--bootstrap-url`, `--relay`,
  `--sporocarp`, `--assume-reachable`, `--webrtc`, `--no-nostr-transport`,
  papel VEIL que aceita conexões e as variáveis `MYCELIUM_ANNOUNCE_IP*`,
  `MYCELIUM_DNS_SEEDS`, `MYCELIUM_REACHABLE` e `DUCKDNS_TOKEN`.
- O mDNS é sempre desligado.
- Relay Nostr padrão: `wss://relay.damus.io`, porque o `nos.lol` recusa saídas Tor.

**Evidência (2026-10-19, [`testes-realidade.md`](../reports/testes-realidade.md)):**
- Auditoria de sockets com `ss` durante 2,5–5 min de daemon real: a única conexão
  TCP externa foi para `127.0.0.1:9050`; nenhum socket UDP; todos os listeners em
  loopback.
- Testes `crates/mycelium-hyphae/tests/anonymous_mode.rs`: uma isca TCP local
  **nunca** recebe conexão quando o nó anônimo disca `/ip4`, `/ip6`, QUIC e `/dns4`
  para ela. O controle (nó direto) **recebe**, o que prova que a isca funciona.
  Opções que revelam IP são recusadas e o WebSocket segue o proxy do processo.

- **Troca de dados real pelo Tor (2026-10-19):** nó anônimo × nó comum no
  `wss://relay.primal.net` viraram vizinhos em < 30 s; um Plot foi do par ao nó
  anônimo e outro do nó anônimo ao par, com conteúdo íntegro dos dois lados.
  Durante a troca, `ss` não mostrou nenhuma conexão fora do Tor, nenhum UDP e
  nenhum listener fora de loopback. O `status` respondeu em 7 ms.

**Limites conhecidos:**
- Os dois nós estavam na **mesma máquina**. O relay e o Tor são reais, mas isso
  não conta como teste multi-host (nível (b)).
- Relays públicos ainda aplicam rate-limit: o damus respondeu `banned` uma vez
  durante o teste. O transporte agora agrupa quadros e recua, mas um relay pode
  bloquear mesmo assim. Use 2 ou mais relays que aceitem Tor.
- O GhostID do transporte Nostr é estável por home: liga as sessões entre si
  (não ao IP). Rotação é trabalho futuro.
- O VEIL como proxy deste modo não foi exercitado; o teste usou o Tor.
