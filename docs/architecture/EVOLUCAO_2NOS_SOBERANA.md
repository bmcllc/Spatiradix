# Evolução soberana com 2 nós — P2P + Nostr + Web convencional sem infra própria

Data: 2026-10-17. Status: **desenho de arquitetura e roteiro**. Nada aqui está
provado além do que já existe no repo (nível **(a)**, loopback — ver
[`docs/VALIDACAO.md`](../VALIDACAO.md)). Complementa
[`SUBSTITUTO_INFRA_P2P.md`](SUBSTITUTO_INFRA_P2P.md), que mirava ≥3 nós; aqui o
alvo é **o mínimo viável: 2 nós seus**.

Fontes estudadas: repo Mycelium inteiro; pasta `/media/bruno/SAMBOOK/Alien Files`
(Protocolo de Malha Unificado AMP/CFA, ETΞRNET/VØID, PDC/Metal Math) e os
duplicados no Google Drive; pesquisa web (Pkarr/Mainline DHT, iroh, Nostr
Negentropy, Willow). A triagem anterior já está em
`research/ANALISE_ALIEN_FILES_MYCELIUM.md` (arquivo histórico, ausente da árvore atual).

---

## 0. A questão de infraestrutura

O plano investiga quais funções de infraestrutura podem ser prestadas por
serviços públicos existentes enquanto dois nós próprios guardam os dados e
executam os serviços. A proposta depende da disponibilidade desses serviços e
de validação entre máquinas e redes distintas.

Um VPS junta num só lugar cinco funções: *bootstrap/descoberta, nome (DNS),
retransmissão (relay), guarda-e-encaminha (quando o outro lado está offline) e
compute/armazenamento*. A tese deste documento: as quatro primeiras já existem
como **comuns públicos** que ninguém controla e que você não mantém. Só a quinta
(seus dados e seu compute) precisa de hardware seu — e aí bastam 2 nós.

| Função do VPS | Comum público que a substitui | Você mantém? | Confia nele? |
|---|---|---|---|
| Descoberta / bootstrap | **Mainline DHT** (~milhões de nós BitTorrent) | não | não (assinado) |
| Nome / DNS | **Pkarr** — registro DNS assinado sob chave pública, guardado na Mainline DHT | não | não (verifica a assinatura) |
| Relay / hole punching | relays libp2p/**iroh** públicos; relays **Nostr** públicos | não | não (cifrado ponta a ponta) |
| Guarda-e-encaminha (um lado offline) | **relay Nostr** público (store-and-forward) | não | não (cifrado, efêmero) |
| Compute + armazenamento (a verdade) | **os seus 2 nós** | sim | sim |

Os três primeiros comuns são **dobradiças substituíveis**: se um relay Nostr cai,
usa-se outro; se um nó DHT mente, a assinatura Pkarr denuncia. Nenhum é
"servidor" no sentido de autoridade. É exatamente o contrato da
`EVOLUCAO.md` ("seeds e relays são substituíveis"), agora
levado ao limite: **zero seeds próprios**.

---

## 1. Por que 2 nós bastam (e o que cada um faz)

Topologia mínima soberana:

```
  Nó A (notebook, intermitente)          Nó B (celular/Pi na tomada, 24/7-ish)
  - verdade quente, edição               - réplica pinada (R=2), sempre mais perto do "ligado"
  - publica Pkarr do serviço      ←→     - re-publica Pkarr quando A dorme
          \                               /
           \   (quando A e B não se veem direto: CGNAT) /
            → Mainline DHT (descoberta) + relay Nostr/iroh (rendezvous + store-and-forward) ←
```

- **A verdade vive nos 2 nós, replicada.** Um Plot pinado em A e B (R=2) sobrevive
  à queda de qualquer um — é a E1 do repo (`sporebank` + anti-entropy por
  manifesto, já provada em loopback na E1.3). Com só 2 detentores, R=2 é o teto:
  perdeu os dois ao mesmo tempo, perdeu o dado. Honestamente: 2 nós = 1 falha
  tolerada, não mais.
- **O "terceiro nó" é emprestado, não mantido.** Quando A está desligado, quem
  entrega o conteúdo a um visitante é B. Quando *os dois* estão atrás de CGNAT e
  não se enxergam, o encontro acontece via Mainline DHT + um relay público. O
  relay pode guardar mensagens para entrega posterior. Para proteger conteúdo
  sensível, a implementação precisa cifrá-lo antes do envio; a classificação
  `private`, por si só, não comprova criptografia ponta a ponta.
- **Celular velho como nó B.** Já há binário: [`dist/mycelium-android-arm64`](../../dist/mycelium-android-arm64)
  (Android 24+). Via Termux + `termux-wake-lock`, ~2–4 W. Não é "sempre ligado"
  garantido (Android mata background) — medir uptime real antes de prometer.

---

## 2. As três evoluções pedidas, com 2 nós

### 2.1 P2P — do bootstrap próprio ao bootstrap emprestado

Hoje o Mycelium precisa de um seed com inbound verificado (`seeds/mainnet.txt`,
hoje vazio) para o primeiro peering. **Isso é o que prende em "≥3 nós / VPS".**

Evolução: **descoberta via Mainline DHT + Pkarr**, eliminando o seed próprio.

- Cada nó publica na Mainline DHT, sob sua **chave pública** (a `Gland` ed25519 do
  `pheromones`, ou a `GhostID`), um registro assinado Pkarr com seus multiaddrs
  atuais (A/AAAA + um `SVCB` apontando ao Ion). Formato Pkarr: chave(32) +
  assinatura(64) + timestamp(8) + pacote DNS(≤1000 B), via BEP44 *mutable item*.
- Para achar o outro nó, resolve-se a chave na DHT e verifica-se a assinatura. Sem
  URL fixa, sem DNS, sem seed. A Mainline DHT faz o papel do "catálogo HTTP" da E3
  — só que é um comum de milhões de nós que já está no ar há 15+ anos.
- Freshness: registros Pkarr expiram em horas; re-publicar de hora em hora. Com 2
  nós, **B re-publica o registro de A quando A dorme** (é a dobradiça que mantém o
  serviço "encontrável" sem A ligado).
- Prioridade de transporte permanece a da E3: QUIC direto → hole punching (DCUtR,
  o `relay_mesh.rs`/`dcutr` já no `hyphae`) → relay público → Nostr WSS outbound
  (`mycelium-nostr-transport`, modo `--hybrid`, já existe).

Crate novo sugerido: `mycelium-pkarr` (ou feature em `hyphae`): publica/resolve
registros assinados na Mainline DHT. Reusa a identidade de `pheromones`/`ghostid`.

> **Atualização 2026-10-18:** `crates/mycelium-pkarr` foi implementado na variante
> **anônima de nó único**. Não publica multiaddrs com IP nem reusa a `Gland`: usa
> uma chave mestra separada, cegada por época, conteúdo cifrado e publicação via
> relay Pkarr só por SOCKS5 (VEIL/Tor). Ver
> [`docs/network/pkarr-anonimo.md`](../network/pkarr-anonimo.md). Nível (a): sem
> teste em relay público nem em circuito vivo.

### 2.2 Nostr — do transporte ao substrato de disponibilidade

O repo já usa Nostr como transporte (`mycelium-nostr`, `mycelium-nostr-transport`,
`--hybrid`, CandidateRelay). A evolução é tratar o relay Nostr como **o
guarda-e-encaminha que substitui o uptime do VPS**:

- **Caixa postal de disponibilidade.** Quando A publica/atualiza um Plot e B está
  offline (ou vice-versa), o delta vai cifrado para 2+ relays Nostr públicos como
  evento efêmero. O que volta online puxa e reconcilia. É a E1.3 (anti-entropy)
  estendida para "nenhum dos dois estava online ao mesmo tempo".
- **Reconciliação eficiente: Negentropy (NIP-77).** Em vez de reanunciar tudo, usa
  *range-based set reconciliation* — o nó manda um fingerprint do conjunto, o outro
  compara e só pede o que falta. É a **mesma família** do manifesto anti-entropy
  que o Mycelium já implementou (E1.3) e do set-reconciliation do Willow. Alinhar o
  formato do manifesto ao Negentropy deixa relays `strfry` servirem de dobradiça de
  sincronização sem código proprietário.
- **Rotação e pluralidade:** ≥2 relays independentes, rotação automática (E3.2).
  Nenhum relay é necessário ao protocolo nativo; quando A e B se veem direto, o
  Nostr nem entra.

Limite honesto: relay público pode limitar taxa, censurar por pubkey ou sumir. Por
isso ≥2 e por isso o conteúdo vai **sempre cifrado** (o relay é carteiro cego).

### 2.3 Web convencional — do gateway próprio ao nome Pkarr + gateway efêmero

Para um navegador comum (fora da malha) abrir o seu serviço **sem você hospedar
nada**:

- **Nome:** uma chave pública Pkarr é um TLD soberano de 52 caracteres
  (`<z-base-32>`). Resolvedores PKDNS públicos (ou a extensão/relay HTTP do Pkarr)
  traduzem isso para o endereço atual do seu Ion — o `SVCB`/`HTTPS` record aponta
  ao Event Horizon alcançável no momento (nó B, ou um gateway voluntário). É o
  substituto real do domínio: **o nome é a chave, e a chave é sua**.
- **HTTP(S):** o navegador não fala libp2p nem UDP-DHT. Então a borda web é:
  1. nativo na malha (sem navegador) — já funciona;
  2. um **gateway voluntário intercambiável** (E4) que faz HTTP→fluxo P2P
     autenticado até a Chamber (`singularity` já tem proxy + fallback de réplicas);
  3. para o caso pessoal "só eu e meus aparelhos", uma **rede privada** (ex.:
     Tailscale, como no MAPS) é o atalho honesto: seus 2 nós + seu navegador num
     overlay, inbound público fechado. Não é "web pública", é "minha web".
- O gateway/relay HTTP do Pkarr contorna o fato de que faixas de IP de nuvem são
  bloqueadas por nós da DHT e de que o browser não faz UDP.

A promessa "qualquer um no mundo abre pelo Chrome sem você manter nada" exige um
gateway público de terceiro (comum, substituível) — igual aos gateways nsite/IPFS.
Com só 2 nós e nenhum gateway, o acesso web é o seu círculo (rede privada) + a
malha nativa. Isso é um teto, e está dito.

---

## 3. "O futuro" — o que destes documentos entra e o que NÃO entra

Da pasta Alien Files e do Drive, o material **aproveitável** converge com o que a
pesquisa mostra ser o estado da arte:

| Ideia (Alien Files / AMP-CFA) | Equivalente real / no repo | Entra como |
|---|---|---|
| Identidade auto-soberana, chave = nome | Pkarr sob chave; `ghostid`/`pheromones` | **núcleo** da §2.1/§2.3 |
| CRDT + "merge = redução de entropia" | `isotope` (LWW) + anti-entropy E1.3; Negentropy/Willow | **núcleo** da §2.2 |
| Fragmentação QEL / Shamir, rotas disjuntas | `mycelium-qel`, `entropy` (Shamir), VEIL 3 saltos | privacidade opcional (E5.2) |
| Transporte multimodal (WebRTC/Nostr/BLE/LoRa) | `distancebridge`, `hyphae` (webrtc feat.), Nostr | roteiro E3; BLE/LoRa = futuro |
| Compute verificável pago por frame (STARK) | `cosmic-cli` (prova re-executável), `zkp` | pesquisa, não bloqueia 2 nós |
| PDC/Metal Math (ponto-fixo, bitwise, ECS) | — | otimizar o worker WASM em hardware fraco (celular) |
| Pagamento por assinatura sem servidor | `sclerotium::lease` + `prova-zero-infra.sh` | **já existe**, casa com Pkarr |

**O que NÃO entra, por decisão explícita de segurança** (e coerente com a triagem
anterior do repo): os componentes **ANIMUS / SYMBIONT** descritos no ETΞRNET/VØID —
auto-propagação oculta via dependências npm/pip/cargo, bootstrap escondido em
PDFs/imagens, execução em eBPF "abaixo do firewall", payload dormente em
firmware/LLM. Isso é desenho de **malware/supply-chain** e de instalação sem
consentimento. A rede aqui é **opt-in explícito**: um nó só existe porque alguém o
instalou e ligou de propósito. Propagação escondida está fora do escopo e não será
implementada. (As alegações de "lei física inquebrável", energia zero-point e
QKD/relativístico dos mesmos docs são narrativa, não engenharia executável — ficam
de fora como requisito, não como implementação.)

---

## 4. Roteiro (gates, ligados à E1–E6)

Cada gate mede entre **as 2 máquinas reais**, nunca loopback.

| Gate | Entrega | Aceitação (falsificável) | Base no repo |
|---|---|---|---|
| **G0 — 2 nós reais** | notebook (A) + celular/Pi (B); nenhum seed próprio | A e B se acham **só pela Mainline DHT/Pkarr**; `neighbor_ids` não-vazio; sem linha em `seeds/mainnet.txt` | E3, `hyphae` |
| **G1 — Pkarr** | `mycelium-pkarr`: publica/resolve registro assinado na DHT | resolver a chave de A de outra rede devolve os multiaddrs certos e a assinatura confere; B re-publica quando A cai | novo; reusa `ghostid` |
| **G2 — Disponibilidade sem uptime** | caixa postal Nostr (Negentropy) cifrada | A publica com B offline; B volta depois e reconcilia só o delta; conteúdo some do relay | E1.3 + `nostr-transport` |
| **G3 — Sobrevivência R=2** | Plot pinado em A e B | desligar A; visitante baixa de B via Pkarr+gateway; religar A e reconciliar | E1.5 (já provada em loopback) |
| **G4 — Nome → web** | nome Pkarr resolve para o Ion; acesso por rede privada e/ou 1 gateway | abrir o serviço pelo nome de 52-char num navegador na rede privada; derrubar o gateway e cair para acesso nativo | E4, `singularity` |
| **G5 — Pagamento** | assinatura via `sclerotium::lease` sobre o serviço Pkarr | lease válida → 200; vencida → 401; tudo sem servidor de contas | `prova-zero-infra.sh` (já existe) |

G0+G1 são o desbloqueio: provam que **2 nós + comuns públicos** substituem
seed/VPS/DNS. É o mesmo bloqueio de ambiente apontado no
[`PLANO_PRODUCAO_MONETIZACAO.md`](../PLANO_PRODUCAO_MONETIZACAO.md) (§1: sair do
loopback), agora sem exigir alugar VPS.

---

## 5. Riscos e limites (ditos, não escondidos)

- **R=2 tolera 1 falha, não 2.** Perdeu A e B juntos (roubo, enchente, formatação
  dupla), perdeu o dado. Controle dos nós não garante durabilidade. Um 3º detentor
  (amigo/comunidade, pinning recíproco) sobe para R=3 quando quiser.
- **Comuns públicos não são seus, mas também não são garantidos.** Mainline DHT é
  robusta por escala, mas BEP44 tem limite de tamanho e expiração; relays Nostr
  podem censurar por pubkey. Mitigação: pluralidade e rotação, conteúdo sempre
  cifrado, re-publicação periódica.
- **Celular como nó 24/7 é otimista.** Android suspende background; medir uptime
  real antes de contar com B como âncora.
- **Dados privados replicados exigem E5.2** (cripto ponta a ponta de layers/índice)
  antes de irem a relay ou a nó de terceiro. Hoje Plots restritos não saem do nó
  (E0) — bom para privacidade, mas então B não pode custodiar o privado de A sem a
  E5.2.
- **Opt-in é inegociável.** Nada de propagação automática (§3). Cada nó é instalado
  e ligado por uma pessoa.

---

## 6. Fontes

- Pkarr / Mainline DHT / PKDNS: <https://github.com/Pubky/pkarr> · <https://pubky.org/explore/technologies/pkdns.md> · <https://pubky.org/explore/technologies/mainline-dht.md>
- Nostr Negentropy (NIP-77, strfry): <https://github.com/hoytech/strfry/blob/master/docs/negentropy.md>
- Willow (set reconciliation, naming): <https://jzhao.xyz/thoughts/Willow-Protocol> · Earthstar: <https://nlnet.nl/project/Earthstar/interview.html>
- iroh 1.0 (dial por chave, hole punching em QUIC): <https://pinggy.io/amp/blog/iroh_1_0_dial_keys_not_ips/>
- Radicle (git P2P, referência de seed sempre-ligado pago e substituível): <https://radicle.dev/faq>
- Material interno estudado: `Alien Files/SECRET/Protocolo_de_Malha_Unificado.pdf` (AMP/CFA), `ETΞRNET.pdf`/`VOID*.pdf`, `Protocolo de Dinâmica Computacional 5.2` (Drive); triagem histórica em `research/ANALISE_ALIEN_FILES_MYCELIUM.md`.
