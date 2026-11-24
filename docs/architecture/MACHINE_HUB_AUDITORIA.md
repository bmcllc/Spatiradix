# 🍄 Auditoria de segurança — o código que o Machine Hub reutiliza

Data: 2026-10-22. Companheiro de [`MACHINE_HUB.md`](MACHINE_HUB.md).

**Método:** leitura estática do código nesta data. Nenhum exploit foi executado;
as cadeias abaixo foram montadas por leitura e estão marcadas assim.
**Escopo:** o que o Hub vai reutilizar ou expor — `mycelium-store`, os ions
`store` e `vitrine` do `mycelium-node`, o Event Horizon (`singularity`), refs do
`giggs`, `mycelium-nutrients`, `mycelium-bank` e a validação BOLT11 do
`mycelium-zkp`. O trilho de pagamento do `mycelium-economy` foi lido como
referência positiva, não auditado a fundo. Fora do escopo: `hyphae`, `veil`,
`pkarr`.

**Severidade:** *Crítica* = execução de código no host ou perda de receita sem
outra interação além de abrir um site ou link. *Alta* = o mesmo com uma
pré-condição a mais, ou integridade de pagamento/fornecimento. *Média* = dano
local ou limitado. *Latente* = inalcançável pela rede hoje, alcançável assim que
o Hub ingerir manifestos ou refs da rede — que é o plano.

---

## 1. Resumo

| ID | Sev. | Onde | O quê | Hoje |
|---|---|---|---|---|
| MH-01 | Crítica | `crates/mycelium-store/src/lib.rs:200` + `deploy/store-ui/game.html:224` | XSS refletido: o id da URL entra cru numa string JS | explorável |
| MH-02 | Crítica | `crates/mycelium-store/src/runner.rs:364` + `lib.rs:448` | QEMU em modo terminal usa `-serial mon:stdio` e a API escreve bytes crus no stdin: o monitor do QEMU fica na mão de quem chama a API | explorável (com QEMU instalado) |
| MH-03 | Alta | `crates/mycelium-store/src/lib.rs:129`, `:414`, `:424`; `crates/mycelium-node/src/lib.rs:197` | API de processos da store aberta sem token; o token só é gerado em nó relay; listar e ler saída de processo nunca exigem token | explorável |
| MH-04 | Alta | `crates/singularity/src/proxy.rs:397` | o fallback do horizon serve HTML de qualquer Plot público cuja mensagem contenha o nome do ion, sem a CSP `sandbox` do `/site/`; Plot público chega sozinho por gossip (`crates/mycelium-node/src/organism.rs:2148`) | explorável (uma navegação) |
| MH-05 | Alta | `crates/singularity/src/proxy.rs:147` | o horizon não confere `Host` nem `Origin`: DNS rebinding dá a qualquer site a mesma origem dos ions | explorável |
| MH-06 | Crítica · latente | `runner.rs:297`, `:302`, `:328`, `:369`; `qemu_builder.rs:97` | o manifesto controla argumentos de QEMU, RetroArch e MAME (`extra_args`, `libretro_core`, `qemu_config`) | catálogo só local → RCE ao instalar quando ingerir da rede |
| MH-07 | Alta · latente | `runner.rs:167`, `:282`, `:384`; `organism.rs:3850`, `:3902` | motor `Native` executa o conteúdo (`sh <arquivo>`); motor desconhecido vira `Native`; `sandbox` é ignorado; o bwrap monta `/` inteiro com rede | latente |
| MH-08 | Média | `lib.rs:371`, `:406`; `runner.rs:423`; `organism.rs:3854` | `main_binary_file` absoluto ou com `..` é aceito; temporário previsível em `/tmp`, gravado seguindo symlink | latente / local |
| MH-09 | Crítica (receita) | `crates/mycelium-node/src/vitrine_ion.rs:326` | a lease premium é aceita de qualquer emissor | explorável |
| MH-10 | Média (desenho) | `crates/mycelium-nutrients/src/lib.rs:458`; `crates/mycelium-zkp/src/bolt11.rs:89` | voucher é IOU autoassinado; a "validação BOLT11" só faz parse do invoice | por desenho |
| MH-11 | Média | `crates/mycelium-nutrients/src/lib.rs:430` | receber Equity/Royalty credita +10% de Resilience a si mesmo; auto-transferência cunha sem limite | local |
| MH-12 | Alta (pagamento) · latente | `crates/mycelium-bank/src/payments.rs:49`, `:120`; `identity.rs:89` | "Settled" só com assinatura; chave não ligada ao `from`; sem anti-replay; o KEM cifra para a própria chave do pagador | crate sem consumidor no workspace |
| MH-13 | Média · latente | `crates/mycelium-store/src/catalog.rs:182`, `:411` | ids globais sem dono; autor derivado do id; CIDs do seed não são dos bytes | latente |
| MH-14 | Alta · latente | `crates/giggs/src/lib.rs:91` | `compare_and_swap` não exige que o novo assinante seja o do ref atual | refs só locais hoje |

---

## 2. A cadeia crítica: abrir um site → comando no host

Montada por leitura; **não executada**. Pré-condições: nó desktop sem
`MYCELIUM_CONTROL_TOKEN` nem `control.token` (o padrão fora do modo relay —
MH-03), `qemu-system-i386` no `PATH`, Event Horizon na porta padrão 7474
(`cli/mycelium-cli/src/main.rs:55`).

1. O site faz uma navegação de topo para
   `http://127.0.0.1:7474/store/web/<payload>`. Navegação de topo não passa por
   CORS nem por `X-Frame-Options`.
2. O horizon repassa ao ion `store`; `serve_game_page` coloca o id já
   decodificado dentro de `const SPORE_ID = '…';` (MH-01). O script do atacante
   roda na origem do horizon, que é a mesma de todos os ions (store, s1, src,
   vitrine, hub).
3. O script faz `POST /store/api/store/spores/doom-1993/launch`. Sem token, a
   chamada é autorizada (MH-03). Os seeds MS-DOS recomendam QEMU
   (`catalog.rs:196`), lançado em modo terminal com
   `-nographic -serial mon:stdio` (`runner.rs:363`). Sem o WAD local o QEMU sobe
   na BIOS, e o lançamento dá certo assim mesmo.
4. O script faz `POST /store/api/store/processes/<id>/input` com `\u0001c`
   (Ctrl-A c alterna para o monitor) e um comando do monitor. O monitor do QEMU
   grava arquivos arbitrários do host (`pmemsave`, `dump-guest-memory`,
   `screendump`) e, nas versões que mantêm o transporte `exec:`, executa
   comandos (`migrate "exec:…"`). `GET …/output` devolve a resposta (MH-03).

Variante sem os passos 1–2: DNS rebinding (MH-05) entrega a mesma origem.

Qualquer um destes três consertos quebra a cadeia: escapar o id (MH-01), token
obrigatório (MH-03), `-monitor none` (MH-02). Os três devem entrar.

---

## 3. Achados

### MH-01 — XSS refletido na página de jogo da store
- **Onde:** `serve_game_page` faz `html.replace("__SPORE_ID__", &id)`
  (`crates/mycelium-store/src/lib.rs:200`) e o template tem
  `const SPORE_ID = '__SPORE_ID__';` (`deploy/store-ui/game.html:224`). O extrator
  `Path` do axum entrega o segmento já decodificado (`%27` vira `'`). O horizon
  não acrescenta CSP às respostas repassadas (`security_headers_gate`,
  `crates/singularity/src/proxy.rs:109`).
- **Importa para o Hub porque** a UI do Hub vai morar no mesmo horizon.
- **Correção mínima:** recusar com 404 id fora de `^[a-z0-9-]{1,64}$` e inserir
  com `serde_json::to_string(&id)` (string JS válida e escapada).

### MH-02 — monitor do QEMU exposto pela API de input
- **Onde:** modo terminal acrescenta `-nographic -serial mon:stdio`
  (`crates/mycelium-store/src/runner.rs:363`); `process_input_handler` escreve
  o texto recebido no stdin do filho (`lib.rs:448`), que é um pipe
  (`process.rs:186`).
- **Correção mínima:** `-display none -serial stdio -monitor none` no lugar de
  `-nographic -serial mon:stdio`.

### MH-03 — API de processos da store fail-open
- **Onde:** `is_authorized` devolve `true` quando não há token
  (`lib.rs:129`); o token só é gerado quando `enable_relay`
  (`crates/mycelium-node/src/lib.rs:197`). `list_processes_handler` (`lib.rs:414`)
  e `process_output_handler` (`lib.rs:424`) nunca pedem token, nem quando há um.
  A comparação do token não é em tempo constante.
- **Correção mínima:** gerar `control.token` (0600) sempre que faltar a variável
  de ambiente — o código de `lib.rs:197` já faz isso, só precisa sair do
  `if enable_relay` —; exigir token em todas as rotas de processo; comparar em
  tempo constante.

### MH-04 — fallback do horizon serve HTML da rede na origem privilegiada
- **Onde:** sem órbita para o ion, `proxy` varre o Spore Bank e devolve a
  primeira folha `.html` de qualquer Plot público cuja mensagem contenha o nome
  do ion (`crates/singularity/src/proxy.rs:397`), sem a CSP `sandbox` que o
  `/site/` aplica (`crates/singularity/src/gateway.rs:23`). Plot público
  recebido por gossip é absorvido e republicado automaticamente
  (`crates/mycelium-node/src/organism.rs:2148`). Um par remoto planta um Plot com
  mensagem `ion:qualquer-coisa` e um `index.html`; quem abrir
  `http://127.0.0.1:7474/qualquer-coisa/` roda o script dele com acesso a todos
  os ions.
- **Correção mínima:** trocar o corpo do fallback por um redirecionamento para
  `/site/<cid>/`, que já isola o conteúdo — ou remover o fallback.

### MH-05 — sem checagem de `Host`/`Origin` no horizon
- **Onde:** `serve_horizon` (`crates/singularity/src/proxy.rs:147`) não tem
  middleware de `Host`. Só o proxy remove o cabeçalho ao repassar
  (`proxy.rs:482`).
- **Correção mínima:** middleware que só aceita `Host` igual a
  `127.0.0.1:<porta>`, `localhost:<porta>`, `[::1]:<porta>` ou um nome
  configurado; em método que muda estado, exigir `Origin` igual ao host.

### MH-06 — manifesto controla argumentos de emuladores externos
- **Onde:** `extra_args` vai inteiro para RetroArch, MAME e QEMU
  (`runner.rs:302`, `:328`, `:369`; `qemu_builder.rs:97`); `libretro_core` vira
  `retroarch -L <valor>` (`runner.rs:297`), e `-L` aceita caminho de biblioteca
  — carregar um `.so` arbitrário é executar código; as strings de `qemu_config`
  viram `-M`, `-cpu`, `-vga` e `-device` sem lista branca.
- **Por que latente:** hoje o catálogo só recebe entradas do seed e de
  publicação local. O Hub vai ingerir manifestos da rede; nesse dia, instalar é
  executar.
- **Correção:** no Hub o manifesto é declarativo e não tem nenhum desses campos
  (`MACHINE_HUB.md` §4.2). Para os lançadores legados: remover `extra_args` do
  manifesto, aceitar `libretro_core` só como nome `[a-z0-9_]+` resolvido dentro
  dos diretórios de cores, lista branca para `qemu_config`.

### MH-07 — motor `Native` executa o conteúdo baixado
- **Onde:** `build_launch_command` devolve `sh <arquivo>` (`runner.rs:384`) e
  ignora o parâmetro `sandbox` (`runner.rs:282`); o `launch` nativo usa bwrap com
  `--ro-bind / /` e rede (`runner.rs:167`), o que lê todas as chaves e carteiras
  do usuário; `StoreLaunch` transforma motor desconhecido em `Native`
  (`organism.rs:3850`); `StorePublish` registra spores com `recommended: Native`
  (`organism.rs:3902`).
- **Correção:** tirar `Native` de qualquer caminho alimentado pela rede; motor
  desconhecido = erro; quando houver sandbox, usar a receita do `vacuum`
  (`crates/vacuum/src/process.rs:829`).

### MH-08 — caminhos
- **Onde:** `main_binary_file` é concatenado ao diretório da store sem validação
  (`lib.rs:371`, `organism.rs:3854`) — `Path::join` com caminho absoluto
  substitui a base. O temporário `mycelium-{id}-{ext}` em `/tmp` é previsível e
  `fs::write` segue symlink (`lib.rs:406`, `runner.rs:423`); `id` e `ext` não são
  sanitizados.
- **Correção mínima:** `main_binary_file` precisa ser um único componente, sem
  `/` nem `..`; temporário com nome aleatório, `create_new` e 0600 num diretório
  privado.

### MH-09 — assinatura premium aceita lease de qualquer chave
- **Onde:** `check_subscription` (`crates/mycelium-node/src/vitrine_ion.rs:326`)
  confere a capacidade `Subscriber`, a validade e a assinatura — mas a assinatura
  é conferida contra `origin_pubkey`, que vem na própria lease
  (`crates/mycelium-sclerotium/src/lease.rs:216`). Ninguém compara o emissor com
  a chave do operador. Qualquer pessoa gera uma chave, assina uma lease
  `Subscriber` válida até 2100 e lê `/vitrine/premium`. O próprio teste usa uma
  chave aleatória (`Gland::germinate()`, `vitrine_ion.rs:407`) e espera sucesso.
- **Correção mínima:** exigir `lease.origin_node_id == ` a `node_id` da Gland do
  operador (o CLI já a carrega com `NodeStore::open(home).load_or_create_gland()`);
  inverter o teste: lease de chave aleatória → recusada.

### MH-10 — voucher é IOU; "BOLT11 validado" não é pagamento
- **Onde:** `redeem_voucher` (`crates/mycelium-nutrients/src/lib.rs:458`)
  confere a assinatura do pagador e credita. O chamador confere `payee`
  (`organism.rs:2571`), e o emissor honesto debita a si mesmo
  (`organism.rs:2672`), mas o recebedor não tem como saber se o pagador tinha
  saldo: qualquer chave cunha vouchers. Com a feature `bolt11`, a checagem é
  `parse().is_ok()` (`crates/mycelium-zkp/src/bolt11.rs:89`). Invoice é pedido de
  pagamento; prova de pagamento é a preimagem.
- **Correção:** documental — corrigir o comentário "economia voucher autenticada
  por Lightning" e nunca liquidar compra com nutrients (`MACHINE_HUB.md` §6.1).

### MH-11 — Resilience cunhada no recebimento
- **Onde:** ao receber Equity ou Royalty, o próprio recebedor ganha +10% em
  Resilience (`crates/mycelium-nutrients/src/lib.rs:430`). O nó não recusa
  transferência para si mesmo (`organism.rs:1043`), então `from == to == eu`
  repetido cunha Resilience sem limite.
- **Correção mínima:** recusar `from == to`; tirar o royalty até existir um autor
  identificado para recebê-lo (hoje ele vai para quem recebeu).

### MH-12 — "Settled" sem liquidação no bank
- **Onde:** `receive_nfc_payment` devolve `PaymentStatus::Settled` depois de só
  conferir a assinatura (`crates/mycelium-bank/src/payments.rs:120`).
  `payer_pubkey` não é ligado a `intent.from`: o `account_id` é derivado da
  semente **privada** (`identity.rs:89`), então ninguém consegue conferi-lo a
  partir da chave pública. Não há registro de nonce (replay), nem saldo. O KEM é
  encapsulado para a chave do próprio pagador (`payments.rs:49`), e o recebedor
  não consegue decapsular — a "confidencialidade" não acontece.
- **Por que latente:** nenhum crate do workspace usa o `mycelium-bank`.
- **Correção:** não emitir `Settled` sem liquidação; derivar `account_id` da
  chave pública; registrar nonces; encapsular para o recebedor. Até lá o bank
  fica fora do Hub.

### MH-13 — sem identidade de publicador na store
- **Onde:** `publish_spore` grava `author = NodeId::derive(spore.id)`
  (`crates/mycelium-store/src/catalog.rs:411`): o autor é o nome, não uma chave.
  Ids são strings globais (chave de `HashMap`), então o segundo publicador com o
  mesmo id sobrescreve o primeiro. Os `content_id` do seed são hash de rótulos
  (`catalog.rs:182`).
- **Correção:** ids `<chave>/<slug>`, autor = chave real, CID sempre dos bytes.

### MH-14 — ref do `giggs` pode ser avançado por outra chave
- **Onde:** `compare_and_swap` (`crates/giggs/src/lib.rs:91`) confere a assinatura
  do novo update, o `previous` e a sequência — os três públicos — mas não exige
  que o assinante seja o mesmo do ref atual.
- **Por que latente:** hoje só o próprio nó escreve refs (`organism.rs:1017`).
  Quando o Hub aceitar canais vindos da rede, qualquer chave poderá apontar o
  `stable` de outro publicador para um manifesto malicioso.
- **Correção mínima:** aceitar o update só se o assinante for o do ref atual (ou,
  no primeiro update, se o repositório for a própria chave do assinante). Teste:
  update de outra chave com `previous` e sequência corretos → recusado.

---

## 4. O que já está certo e deve ficar

- `catalog_locked` + `validate()` fail-closed e escrita atômica do catálogo
  (`crates/mycelium-store/src/lib.rs:108`, `catalog.rs:477`).
- `/site/<cid>/` com CSP `sandbox` (origem opaca) e `normalize()` contra `..`
  (`crates/singularity/src/gateway.rs:23`, `:126`).
- `RefStore`: componentes validados, CAS, sequência monotônica, assinatura
  conferida na leitura.
- `vacuum`: bwrap fail-closed com namespaces, `--clearenv` e binds mínimos.
- `mycelium-economy`: âncora de confiança fixada, chave do verificador fora do
  alcance do chamador, releitura da cadeia, "uma tx, um settlement".
- Input de processo com teto de 8 KiB e mutex por pipe (sem deadlock), em
  `crates/mycelium-store/src/process.rs`.

---

## 5. Ameaças do Hub e o requisito que cada uma gera

| Ameaça | Requisito |
|---|---|
| Núcleo de terceiro malicioso | nunca no processo do Hub; sandbox sem rede, `$HOME` nem display; fora do Tier 1, só Referência (`MACHINE_HUB.md` D3, D4, §7.1) |
| ROM ou disco que explora bug de memória de um núcleo honesto | a mesma sandbox — por isso núcleo baixado roda isolado mesmo sendo Referência, no Tier 1 |
| Manifesto malicioso | manifesto só declarativo, validado na fronteira (sem argumentos, sem caminhos) |
| Par malicioso no gossip | conteúdo da rede é dado: nunca código nem HTML na origem privilegiada (MH-04); BLAKE3 conferido por chunk |
| Site malicioso (CSRF, rebinding, XSS) | ion `machines` com origem própria, token por sessão, `Host`/`Origin` conferidos, CSP sem script inline |
| Sequestro de canal ou rollback | assinante fixado + sequência monotônica (MH-14) |
| Chave de publicador roubada | chave fora do nó (pode ficar offline ou num Root); rotação assinada pela chave antiga; lista de revogação |
| Fraude de pagamento | valor único por pedido, uma tx um settlement, N confirmações, licença conferida com a chave do anúncio (MH-09) |
| Sybil em atestados e seeding | Referência exige lista de confiança; seeding só com recibo de comprador licenciado, com teto |
| Build adulterado | build reproduzível atestado por ≥ 2 builders |

---

## 6. Portões

- **Antes da etapa 2** (o Hub passa a ingerir manifestos e refs da rede):
  MH-01 a MH-08, MH-13 e MH-14 fechados, cada um com o teste que prova a
  correção.
- **Antes da etapa 4** (dinheiro): MH-09 fechado; MH-12 fechado ou o bank fora do
  caminho; MH-10 e MH-11 resolvidos ou documentados como "não é dinheiro".
- **Agora, independentemente do Hub:** MH-01, MH-02, MH-03 e MH-09 são
  exploráveis hoje e têm correção de poucas linhas.
