# Mycelium Rhizome: aplicação social P2P (`/rhizome/`)

Status: implementação Fase 1 em `crates/mycelium-rhizome`, integrado ao daemon `mycelium-node` (`rhizome_ion`), ao Event Horizon `singularity` (`/rhizome/`), à interface web (`deploy/store-ui/rhizome.html`) e à CLI (`mycelium rhizome ...`).

Este documento descreve os componentes, mecanismos criptográficos e limites
registrados para a integração. Para o estado de validação do projeto, consulte
[Validação](../VALIDACAO.md).

---

## Arquitetura sobre a Infraestrutura do Spatiradix

O Rhizome reúne vídeo, publicações, stories, comunidades e mensagens cifradas.
Ele usa os seguintes componentes do Mycelium:

| Experiência | Primitivos Rhizome | Substrato Mycelium Utilizado |
|---|---|---|
| **Identidade Soberana** | `SovereignKeys`, `ProfileManifest` | `mycelium-pheromones` (`Gland` Ed25519 + `NodeId`), `mycelium-pkarr` (`myc1...` sem DNS), `mycelium-ghostid` (`GhostId` secp256k1/Nostr), `mycelium-pqc` (`ML-KEM-1024`) |
| **Vídeo & Reels (YouTube)** | `PostKind::Video`, `PostKind::Short`, upload chunked, player HTTP Range `206` | `mycelium-media` (`ingest_video`, chunks BLAKE3, `verify_chunk_integrity`, `ChannelStore`, `PlaylistManifest`, `PinManager`, `DiscoveryLens`) + `SporeBank` Plots |
| **Stories & Status 24h (IG/Zap)** | `StoryItem` com `expires_at` e poda automática | `isotope` (`Atom` em chave `rhizome/story/<node>/<id>`, replicação via `Envelope::AtomSync`) |
| **Feed, Fotos & Comunidades (IG/FB/X)** | `SocialPost`, `MediaAttachment`, `Comment`, `Reaction`, `FollowEdge`, `Community` | `giggs::Plot` + `mycelium-sporebank` + `mycelium-hyphae` (libp2p gossipsub `mycelium/lattice/v1` + Kademlia DHT + anti-entropy) |
| **Chat E2EE & Grupos (WhatsApp)** | `SealedChatEnvelope`, `GroupManifest`, `ChatReceipt` (`Sent`/`Delivered`/`Read`) | `mycelium-pqc` (`ML-KEM-1024` FIPS 203) + `XChaCha20-Poly1305` + `Envelope::Direct` → `mycelium-hyphae::DtnBundleStore` (entrega offline store-and-forward) + fallback `mycelium-nostr` NIP-44 |
| **Acesso Web & Gateway** | SPA offline zero-CDN (`rhizome.html`) + REST API + Range streaming | `singularity` Event Horizon (`http://127.0.0.1:7474/rhizome/`) |

---

## Garantias Criptográficas

1. **Autenticação Estrita Ed25519 (`verify_strict`)**:
   - Todo `ProfileManifest`, `SocialPost`, `StoryItem`, `Comment`, `Reaction`, `FollowEdge`, `Community`, `VideoManifest` (via `SyncEnvelope`), `SealedChatEnvelope`, `GroupManifest` e `ChatReceipt` é assinado com separação de domínio (`domain || 0x00 || payload`).
   - O `NodeId` declarado é sempre validado contra `NodeId::derive(ed25519_pubkey)`.
   - Objetos adulterados ou com assinatura inválida são rejeitados antes de persistir.
2. **Mensageria Pós-Quântica (E2EE 1:1 e Grupos)**:
   - **1:1**: encapsulamento `ML-KEM-1024` para a chave pública anunciada no `ProfileManifest` do destinatário → derivação de chave via `BLAKE3::derive_key` vinculada a remetente, destinatário e `msg_id` → `XChaCha20-Poly1305` com AAD → assinatura Ed25519 externa do remetente.
   - **Grupos**: chave simétrica de 32 bytes por época embrulhada individualmente por `ML-KEM-1024` + `XChaCha20-Poly1305` para cada membro.
   - **Fallback CGNAT**: conversão opcional para evento Nostr NIP-44 (`kind 39406`) assinado com Schnorr (`GhostId`).
3. **Integridade de Streaming de Vídeo**:
   - Cada fatia lida em `GET /rhizome/api/videos/{cid}/stream` (`206 Partial Content`) passa por `mycelium_media::verify_chunk_integrity` (BLAKE3) antes de ser entregue ao player HTML5.

---

## Retrocompatibilidade (X, WhatsApp & Protocolos Abertos)

- **Importador X / Twitter**: aceita `window.YTD.tweets.part0 = [...]` (`tweets.js` oficial do archive), arrays JSON e payloads `{ "data": [...] }` da API v2; reconstrói cadeias de threads (`reply_to`), preserva hashtags e re-assina localmente com proveniência `ExternalOrigin::XArchive`.
- **Importador WhatsApp (`.txt`)**: suporta formatos Android PT-BR/EU (`DD/MM/YYYY HH:MM - Nome: msg`), iOS (`[DD/MM/YYYY, HH:MM:SS] Nome: msg`) e US AM/PM, mensagens multilinhas, avisos de sistema e detecção de `<Mídia oculta>` / anexos (`.opus`, `.jpg`, `.mp4`).
- **Bridges Abertas Nativas**:
  - **Nostr**: exportação de posts para NIP-01 (`kind:1`), NIP-23 (`kind:30023`) e NIP-71 (`kind:34235`/`34236`) assinados por Schnorr real (`GhostId`), mais importação com verificação Schnorr real (`GhostId::verify_nostr_event`).
  - **RSS 2.0**: `GET /rhizome/feed.xml` (com `<enclosure>` para vídeos/fotos).
  - **ActivityPub JSON-LD**: `GET /rhizome/ap/actor` e `GET /rhizome/ap/outbox`.
- **Adaptadores Plugáveis Externos (`ExternalBridgeAdapter`)**:
  - `XApiV2Adapter` e `WhatsAppCloudAdapter` implementam geração de payload real e parser real de webhook do WhatsApp Cloud API (`POST /rhizome/api/bridges/whatsapp/webhook`).
  - **Limite honesto**: nenhum tráfego de saída é disparado automaticamente para servidores da X Corp ou da Meta sem credenciais explícitas (`MYCELIUM_X_API_TOKEN`, `MYCELIUM_WA_CLOUD_TOKEN`, `MYCELIUM_WA_PHONE_NUMBER_ID`) e despacho opt-in.

---

## Como Executar

```bash
# 1. Subir o daemon com Event Horizon na porta 7474
cargo run -p mycelium-cli -- --home /tmp/rhizome-a daemon --horizon-port 7474 --listen /ip4/0.0.0.0/tcp/4001

# 2. Abrir o Super-App no navegador
# http://127.0.0.1:7474/rhizome/

# 3. Comandos CLI equivalentes
mycelium --home /tmp/rhizome-a rhizome identity
mycelium --home /tmp/rhizome-a rhizome profile --handle bruno --name "Bruno" --bio "Nó soberano"
mycelium --home /tmp/rhizome-a rhizome post "Olá floresta! #Mycelium"
mycelium --home /tmp/rhizome-a rhizome story "Story efêmero 24h" --ttl-hours 24
mycelium --home /tmp/rhizome-a rhizome video ./demo.mp4 --title "Meu Vídeo P2P"
mycelium --home /tmp/rhizome-a rhizome chat-send --to <NODE_ID_B> "Oi pós-quântico!" --nostr-fallback
mycelium --home /tmp/rhizome-a rhizome import-x ./tweets.js
mycelium --home /tmp/rhizome-a rhizome import-whatsapp ./Conversa.txt --title "Família"
```

---

## Escopo Atual & Fusão MMP / MCP / MEP (Fase 2 + Android Soberano)

Além da Fase 1 completa acima, o Super-App nativo em `/rhizome/` e a CLI fundiram nativamente em Rust as capacidades do **Mycelium Video (MMP / MCP / MEP)** e o empacotamento Android soberano:

- **MMP (Video Engine & Shards)**:
  - Upload streaming em O(1) RAM (`prepare_video_ingest_from_file`), categorias `longform`, `short` (Reels 9:16 com navegação touch/teclado) e `doc`, capa customizada ou SVG offline em `GET /rhizome/api/videos/{cid}/thumbnail`.
  - Hidratação automática de manifestos e chunks legados em `.mycelium/sporebank/chunks/<cid>.bin` + `playlists/*.json`.
  - Recibos verificáveis `ShardReplicaReceipt` emitidos via `ProofOfStorage` (`GET /rhizome/api/videos/{cid}/details`, `POST /rhizome/api/videos/{cid}/pin`, `POST /rhizome/api/videos/{cid}/view`).
  - Gorjetas P2P reais com liquidação Schnorr no `Organism::ledger` (`POST /rhizome/api/videos/{cid}/tip`).
- **MCP (Mycelium Commons Protocol)**:
  - Projetos coletivos com orçamento aberto, marcos e validação estrita de contrato *split* somando exatamente 100% (`GET/POST /rhizome/api/commons`, `GET /rhizome/api/commons/{id}`, `POST /rhizome/api/commons/{id}/contribute`), replicados por assinatura Ed25519 na malha.
- **MEP, Enxame & Carteira Viva**:
  - Ponte direta por canal `oneshot` entre `rhizome_ion` e `Organism` expondo saldos reais do `Ledger`, transferências Schnorr (`GET /rhizome/api/wallet`, `POST /rhizome/api/wallet/transfer`), telemetria viva libp2p/Physarum + chunks/bytes retransmitidos (`GET /rhizome/api/swarm`, `POST /rhizome/api/swarm/config`), Lentes customizáveis (`GET/POST /rhizome/api/lenses`) e moderação local (`GET/POST /rhizome/api/moderation`).
  - CLI estendida: `mycelium rhizome video --doc --commons <id> --thumbnail <img.png> --replicas 3`, `commons-create`, `commons-list`, `commons-contribute`, `lens-list`, `lens-create`, `swarm`, `wallet`.
- **Android**: veja [ANDROID_SOVEREIGN_BUILD.md](ANDROID_SOVEREIGN_BUILD.md) e `scripts/build-android-sovereign.sh`.

---

## Fase 3 — Economia Unificada CPX, AEX World, VEIL Ω Proxy/VPN & Omnibridge Social (9 Redes)

Integrado diretamente ao ion `/rhizome/api/` (`crates/mycelium-node/src/ecosystem_ion.rs`) e à SPA offline (`deploy/store-ui/rhizome.html`):

1. **Moeda Unificada `CPX` + `mycelium-mint` como Reserva + GhostID × NFC × Bank × Pay × Wallet + Royalties (`mycelium-royalty`)**:
   - `mycelium-mint`: razão de lastro `DEFAULT_CPX_PER_MYC = 8` (`MonetaryPolicy::myc_reserve_to_cpx`, `MainnetMintEngine::cpx_reserve_status`).
   - `mycelium-bank`: `Asset::Cpx`, conta de reserva `reserve:mycelium-mint` (`settle_mint_reserve_to_cpx` bloqueia `MYC` na reserva e emite `8× CPX` com anti-replay por nullifier), derivação determinística **GhostID** em `SovereignWallet` (`derive_ghost_id`, `ghost_pubkey_xonly`, `verify_ghost_schnorr`), `NfcProof::create_with_ghostid` / `verify_with_ghostid`, e frame NFC Forum NDEF TNF=4 `NfcNdefFrame` (`mycelium.network:ghostpay` + URI `urn:mycelium:nfc:cpx:v1:`) embutindo envelopes CBOR BIP-340 de `mycelium-pay`.
   - `mycelium-royalty`: contratos `RoyaltyContract` assinados em Ed25519 com soma estrita `10_000 bps`, projeção `isotope::Atom` (`royalty/license/<content_id>`), taxa padrão de `500 bps` (5%) destinada à reserva e conservação inteira exata em `RoyaltyEngine::distribute_cpx`.
   - Gorjetas de vídeo (`POST /rhizome/api/videos/{cid}/tip`) com `asset_type: "cpx"` liquidam automaticamente pelo contrato de royalty se cadastrado, ou diretamente no `mycelium-bank`.
   - Endpoints: `GET /rhizome/api/finance`, `POST /rhizome/api/finance/mint-reserve`, `POST /rhizome/api/finance/transfer-cpx`, `POST /rhizome/api/finance/nfc/request`, `POST /rhizome/api/finance/nfc/tap`, `POST /rhizome/api/royalties/contract`, `POST /rhizome/api/royalties/payout`.
2. **Sessão AEX World & Cameon PX (`aex-mycelium-bridge/1.0.0`)**:
   - Integra a ponte criptográfica existente em `crates/mycelium-node/src/aex_bridge.rs` (GhostID efêmero RAM-only `ZeroizeOnDrop`, QEL fragment/reconstruct, Pedersen ZKP commit, DTN poll) + sonda HTTP configurável para o nó AEX World (`http://127.0.0.1:4173`) com ticker PAME e simulador Asset-to-Capital de Não-Alienação (`0%` transferência de propriedade).
   - Endpoints: `GET /rhizome/api/aex/status`, `POST /rhizome/api/aex/config`, `POST /rhizome/api/aex/simulate`, `POST /rhizome/api/aex/bridge`.
3. **VEIL Ω como Proxy / VPN Pós-Quântico (Local, Relays Remotos & `VpnService` + `tun2socks`)**:
   - Feature `veil` habilitada por padrão em `mycelium-node` e `mycelium-cli`.
   - Controle ao vivo via `/rhizome/api/veil/{status,start,stop,killswitch,test}`: suporta papéis `all`, `client`, `exit` e `relay` com descritores remotos de Guard/Middle/Exit e Trust Pins; sobe circuito telescópico ML-KEM-1024 real, servidor SOCKS5 RFC 1928 local (`socks5h://127.0.0.1:<porta>`), multiplexador L3 `tun2socks` puro em Rust (`crates/mycelium-veil/src/tunnel/tun2socks.rs` — IPv4/TCP/DNS-over-VEIL com Quad9/Cloudflare, zero Google DNS), Kill Switch fail-closed e teste real de handshake RFC 1928 (`0x05 0x00`).
   - No APK Android soberano (`v0.3.0`), `VeilVpnService` (`BIND_VPN_SERVICE`) captura o tráfego IPv4 do dispositivo via `VpnService.Builder` (excluindo `network.mycelium.rhizome` para evitar loop de roteamento) e o encaminha por socket loopback para o `TunBridgeServer` Rust.
   - **Limite honesto**: para alterar o IP público de saída, é necessário operar em papel `client` apontando para descritor(es) de nó `exit` remoto; no Android, a ativação da VPN global requer aprovação interativa do usuário no diálogo nativo `VpnService.prepare()`.
4. **Omnibridge Social (9 Redes: Instagram, Facebook, WhatsApp, X, Telegram, Reddit, YouTube, Twitch, TikTok)**:
   - Motor local em `crates/mycelium-rhizome/src/omnibridge.rs`: cofre local cifrado com `XChaCha20-Poly1305` (`omnibridge_vault.enc`, zero segredos em texto claro no disco), sincronizadores via APIs oficiais / feeds públicos oficiais (YouTube Atom, Reddit JSON, oEmbed oficial público para X e TikTok, Twitch Helix, Telegram Bot API, X API v2, Meta Graph API, TikTok Display API, WhatsApp Cloud API) com roteamento opcional pelo **VEIL Ω SOCKS5** (`socks5h://`), importadores de exports oficiais e vCard `.vcf`, detecção/lançamento nativo dos 9 apps via `<queries>` (`MyceliumNative.isAppInstalled` / `openSocialApp`), Share Target Android (`ACTION_SEND` `text/plain` e `text/x-vcard`) e importação opt-in da agenda Android via `READ_CONTACTS`.
   - **Limite honesto**: respeita integralmente o sandbox de aplicativos do Android e termos de autenticação — nunca burla CAPTCHAs nem acessa dados privados de outros apps sem credenciais/exports ou permissão explícita do próprio usuário.
   - Endpoints: `GET /rhizome/api/omnibridge/overview`, `POST /rhizome/api/omnibridge/connect`, `POST /rhizome/api/omnibridge/sync`, `POST /rhizome/api/omnibridge/import`, `GET /rhizome/api/omnibridge/directory`.
5. **Quórum Esporocarpo Multi-Nó (`mycelium-mint` P2P) & Unificação TheField (`/field/`)**:
   - `GET/POST /rhizome/api/finance/reserve-policy` e `POST /rhizome/api/finance/mint-claim` permitem operar a reserva `mycelium-mint` em quórum real multi-esporocarpo (`min_quorum >= 2`) via Gossipsub (`WorkClaim` → `SporocarpAttestation` → `MintEpochSettled`), drenando automaticamente os recibos liquidados para `8× CPX` no `mycelium-bank`.
   - **TheField** (`/field/`, `crates/mycelium-node/src/field_ion.rs`, `deploy/store-ui/field.html`, `mycelium field`) substituiu definitivamente o antigo Code Hub, unificando repositórios Git P2P (`RefStore`/`SporeBank` + Vacuum CI) e sinais vivos de ressonância (`thefield::Field` em `/field/api/signals`).

### Verificação registrada
- Validado em host Linux `x86_64` via testes unitários (`thefield`, `singularity`, `mycelium-veil` incluindo `tun2socks`, `mycelium-mint`, `mycelium-royalty`, `mycelium-bank`, `mycelium-pay`, `mycelium-rhizome`, `mycelium-hyphae`, `mycelium-android-forge`), testes de aceitação ao vivo (`crates/mycelium-node/tests/rhizome_p2p_acceptance.rs` e `crates/mycelium-node/tests/ecosystem_acceptance.rs` incluindo quórum 2-de-2 P2P + VEIL Exit/Client remoto + TheField), e validação cruzada em CPU ARM64 via `qemu-aarch64-static` + OpenSSL CMS/PKCS#7.
- Validado ao vivo em hardware físico **Moto G35 5G (Android 15 / API 35, `arm64-v8a`, `PAGESIZE=4096`)** na **`v0.3.0`** via `adb`: `adb install -r` (`Success`), `dex2oat64` (`dex2oat returned code 0`, 6 classes DEX verificadas), `dumpsys package` (`VeilVpnService`/`BIND_VPN_SERVICE`, `NDEF_DISCOVERED`, `ACTION_SEND`, `<queries>` das 9 redes, `NFC`, `READ_CONTACTS`), entrega ao vivo de `ACTION_SEND` via `singleTop`/`onNewIntent` com zero erros, e validação HTTP ao vivo de `/rhizome/`, `/field/`, `/field/api/signals`, `/hub/` (`404`), `/rhizome/api/finance/reserve-policy`, `/rhizome/api/veil/{start,test,stop}` (com `tun_bridge` L3 ativo) e `/rhizome/api/omnibridge/overview`.
