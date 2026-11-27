# Validação — Spatiradix

Este documento registra o que foi validado no projeto e quais evidências
ainda faltam. Os resultados pertencem às versões e aos ambientes identificados
em cada seção; eles não garantem que o estado atual seja o mesmo.

Números de linha citam o estado do working tree na data desta escrita.
`docs/reports/status.md` está sendo editado em paralelo; onde ele é citado,
procure também a string entre aspas, que é estável.

**Duas convenções de citação, para que ninguém siga a referência errada.**
Primeiro: onde uma seção descreve um defeito que já foi **corrigido** nesta
mesma rodada, a linha citada é a do estado **pré-correção** e isso está dito
no texto. É o caso da URL de RPC lida de `argv` e do construtor
`BaseUsdcVerifier::new`; as linhas atuais apontam para código diferente.
Segundo: onde uma seção anota que uma afirmação anterior **deixou de valer**,
a afirmação original é preservada e a correção vem em seguida. Nenhuma
afirmação deste documento foi apagada; as que caducaram estão marcadas como
caducadas, e é assim que devem ser lidas.

## Níveis de validação

### (a) Compila e passa testes localmente — SUSTENTADO

Este nível é real e o trabalho de engenharia é competente.

Evidência de artefato, em `docs/reports/P4_HOMOLOGATION_REPORT.md:15-17`:

| Item | Valor |
| --- | --- |
| Código homologado | `749106c55576dee7cfe28d9bfc863a3f53b3fa7f` |
| SHA-256 do binário | `5bb4c6ee6df47d37fd800c8187a48dc2f0068e878f057bc8c5d3a70c516cce0f` |
| Plataforma | Linux `6.12.107+deb13-amd64`, `x86_64` |

O mesmo documento traz, por cenário, tabelas PASS/FAIL, CIDs declarados por
cenário, digest de log e o cenário de rejeição de evidência adulterada — ou
seja, a cadeia de aceitação está implementada e exercitada, não só descrita.

Contagem auto-relatada em `docs/reports/status.md:148`
(`cargo test --workspace --release`): BASE **460/0**, Mycelium **130/0**,
clippy Mycelium 0 erros.

Limite honesto deste nível: a rede usada é loopback
(`docs/reports/P4_HOMOLOGATION_REPORT.md:18` — "Loopback apenas"). O nível (a)
prova correção local de protocolo e de harness de prova, não topologia.

### (b) Multi-nó em redes reais — NÃO SUSTENTADO

Todos os gates multi-nó do repositório fazem bind em loopback:

- `scripts/stress-prolonged.sh:74,88,89` — os nós escutam
  `/ip4/127.0.0.1/tcp/${PORTS[N]}` e fazem bootstrap no primeiro nó também em
  `127.0.0.1`. O resultado "5 nós / 44 réplicas / 1h" reportado em
  `docs/reports/status.md:196` é, portanto, **N processos, 1 máquina,
  0 redes**.
- `crates/mycelium-hyphae/tests/multihop_topology_acceptance.rs` — 13
  ocorrências de `/ip4/127.0.0.1/tcp/0`.
- `crates/mycelium-node/tests/community_service_survival_acceptance.rs:41,78`
  — idem.

A única execução em ambiente real é
`docs/reports/testes-realidade.md:3-15` (2026-07-30, "CGNAT real (Vivo) ↔ 5G").
Ela é desqualificada pela linha 23 do **mesmo arquivo**:

```
# Terminal 2 — 5G (mesmo notebook, rede diferente)
```

Uma máquina, duas redes, sobre um relay público de terceiro
(`wss://nos.lol`). Além disso, os dois endereços são IPv6 globais
(`2804:7f7:e03a:be::` e `2804:214:8857:b801::`), que **não atravessam CGNAT**:
CGNAT é um conceito de IPv4; IPv6 global não passa por NAT.

O mapeamento de alcançabilidade do próprio autor confirma a ausência de
inbound: `docs/network/mapa_cpe_vivo.md:30-33` marca `❌` em *Inbound WAN* para
IPv4 TCP 4001/443 e IPv6 TCP 4001/443, e
`docs/network/mapa_cpe_vivo.md:75-76` registra `reachable = false` e
`relay_server = false`.

### (c) Validação por terceiro — NÃO SUSTENTADO

Zero. Sem assinatura externa, sem tester/revisor/auditor nomeado de fora, sem
post em fórum ou issue, sem receipt on-chain.

- `docs/network/candidatos.md:47` lista apenas `TushiBook (Bruno)`; as demais
  linhas são "prospecto".
- O pedido de voluntário em `docs/network/pitch_voluntario.txt:11`
  ("é um favor técnico de 15 minutos") não recebeu resposta.
- Todo o histórico é de autoria única: `git log --format='%an' | sort -u`
  retorna exatamente `bmcc-DEV` e `bmcllc`.

A própria assinatura do relatório de homologação é auto-assinada e o texto
diz o que ela prova (`docs/reports/P4_END_TO_END_HOMOLOGATION.md:135-136`):
"a assinatura comprova quem produziu o relatório; ela não comprova,
isoladamente, que o executor foi honesto".

### (d) Deploy em produção — NÃO SUSTENTADO

- `dist/` contém um único artefato, `dist/mycelium-android-arm64`, binário
  Android de 20/jul — stale.
- Não existe nenhum arquivo `.log` versionado com medições de produção. O
  único log no repositório é `.mycelium/daemon.log` (6 KB, sessão local de
  desenvolvimento).
- `deploy/` são templates não executados; o próprio
  `docs/reports/release-0.1.0.md:50` os descreve como "pontos de partida
  operacionais".
- Nenhum nó vivo: `/home/bruno/.mycelium/state.json` contém apenas fixtures
  `seed-1`, `test-daemon`, `test-deploy`, `test-status`, todos com
  `neighbor_ids: []`.
- `seeds/mainnet.txt` tem **zero entradas ativas**. A única entrada está
  comentada, com o motivo "inbound TCP falhou em Jul/2026".
- O runbook de mainnet Base existe apenas na branch
  `feature/mycelium-base-rpc-pqc` (`docs/MYCELIUM_BASE_RPC.md`,
  `docs/MYCELIUM_BASE_RPC_OPERATIONS.md`). O diretório `.rpc-real/`, ao qual o
  runbook aponta, não existe. E
  `scripts/rpc-two-node-smoke.sh` (também só nessa branch) sobe um RPC Base
  **mock**: `ThreadingHTTPServer` em `127.0.0.1` (linhas 49 e 91).

## Baseline de remediação — verificado

Registro do que foi efetivamente executado nesta rodada de remediação, com o
código de saída de cada comando. Onde aparece "exit 0", a execução terminou com
sucesso. Ferramenta: `cargo 1.88.0` / `rustc 1.88.0`, agora fixados no
`rust-toolchain.toml` novo (canal `1.88.0`).

Esta seção corrige uma afirmação que este próprio documento fazia e que era
falsa: o código **não** havia sido compilado. Ele não acrescenta prova de rede,
de contraparte nem de produção. Os níveis (b), (c) e (d) e o placar E6 0/9
permanecem exatamente como estão acima e abaixo.

### Build

| Comando | Exit | Resultado |
| --- | --- | --- |
| `cargo check --workspace --locked` | 0 | workspace default verde |
| `cargo check --workspace --all-targets --locked` | 0 | idem + alvos de teste/bench/exemplo |
| `cargo check -p mycelium-node --all-targets --features veil --locked` | 0 | superfície veil compila |

### Testes

| Comando | Exit | Resultado |
| --- | --- | --- |
| `cargo test --workspace --locked --no-fail-fast` | 0 | **308 passed / 0 failed / 1 ignored**, em 68 binários de teste |
| o mesmo com `--features veil` | 0 | **315 passed / 0 failed / 1 ignored** |

O delta de **+7** é exatamente as três suítes veil que eram invisíveis. O
único teste ignorado é pré-existente e está documentado no próprio código:
`crates/mycelium-nostr/tests/mep_0_3_0_acceptance.rs:45`,
`#[ignore = "requer o SporeBank local com o Plot de aceitação"]`.

### O gate veil agora é real

Esta é a mudança mais importante desta rodada. As três suítes de aceitação de
segurança do veil **executam** sob `--features veil` e reportam **0 testes**
sob features default — `mycelium-node` declara `default = []`, então o build
default nunca as alcança:

| Suíte (`crates/mycelium-node/tests/`) | Testes | Resultado |
| --- | --- | --- |
| `veil_socks5_integration` | 1 | passed |
| `veil_data_path_security` | 2 | passed |
| `veil_p1_3_2_acceptance` | 4 | passed |

Antes desta rodada, essas ~918 linhas de teste de aceitação de segurança (930
linhas físicas nos três arquivos) **nunca tinham sido compiladas**, quanto mais
executadas. Compilar já é diferente de não compilar; executar ainda não é o
mesmo que provar. As duas ressalvas honestas estão no fim desta seção.

### Suítes por feature

| Comando | Exit | Resultado |
| --- | --- | --- |
| `cargo test -p mycelium-zkp --features range-proof,license,bolt11 --locked` | 0 | 15 passed |
| `cargo test -p mycelium-hyphae --features webrtc,nostr-transport,pqc-transport --locked` | 0 | 47 passed |

As **8 features** da matriz de CI compilam limpas. `webrtc` e `range-proof`
tinham previsão anotada de falha (`libp2p-webrtc` 0.9.0-alpha.1 experimental;
`bulletproofs` 4.0.0 / `merlin` 3.0.0 / `dalek-ng` 4.1.1) e **não** falharam.

Ressalva honesta: `webrtc` compila e não contribui com **nenhum** teste — a
suíte de `mycelium-hyphae` dá 43 testes unitários com e sem a feature.

### O crate órfão compila e os testes dele passam

`crates/mycelium-economy` (7.408 linhas) está fora de `[workspace]` — tem o
próprio `[workspace]` declarado no `Cargo.toml:9`. Resultado:
`cargo check --locked` exit 0, `cargo test --locked` exit 0, **58 passed na
primeira execução da história**.

O código é são. Contém 16 funções `validate_*` fail-closed, entre elas
`stale_state_fails_closed`, `closed_execution_gate_fails_closed`,
`autonomy_ledger_detects_tampering` e `tampered_receipt_hash_is_rejected`. O
defeito é de **processo**: 58 testes verdes rodam em **zero execuções de CI**
puramente por causa da linha `[workspace]`. Enquanto ele não entrar no
workspace, o placar de cobertura do CI é uma mentira por omissão.

> **Atualização — esta afirmação deixou de valer.** A tabela `[workspace]` foi
> removida em `crates/mycelium-economy/Cargo.toml:8-9` e o crate entrou em
> `Cargo.toml:34`. O parágrafo acima descreve o estado **medido antes** da
> integração e fica aqui como registro histórico, não como estado atual. O
> defeito de processo está corrigido; o que a integração **não** fez foi
> reexecutar a suíte do workspace inteiro, de modo que as contagens de 308/315
> abaixo descrevem a composição **anterior** do workspace. Ver "Rodada P0–P2:
> o ledger de autonomia, auditado" adiante.

### Clippy: inventário, não correção

| Comando | Exit | Avisos distintos |
| --- | --- | --- |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | **101** | 200 (features default) |
| o mesmo com `--features veil` | **101** | 216 |

Principais lints: `uninlined_format_args` 94, `useless_format` 36, `ptr_arg`
10, `io_other_error` 9, `redundant_closure` 5, `too_many_arguments` 4,
`collapsible_if` 4.

**Nada foi corrigido.** O passo de clippy com `-D warnings`, que é bloqueante em
CI, não pode passar ainda. Registado como dívida, não como verde.

> **Atualização — os números acima ficaram velhos, o veredicto não.** Medido
> depois de P3 e P5: **218 avisos distintos em 39 lints** (18 em
> `mycelium-economy`, 197 nos restantes crates); `uninlined_format_args` 101,
> `useless_format` 37, `ptr_arg` 10, `io_other_error` 9. Sai com **1** sob
> `-D warnings`. **Nada foi corrigido** — o bloqueio é idêntico, só cresceu
> +18 avisos. Detalhe em "Contagens e estado das execuções" na rodada P3–P5.

### CI continua vermelho

`.forgejo/workflows/validate.yml` tem **3 passos bloqueantes** em falha:

- **clippy** com `-D warnings` — falha acima, 200 avisos.
- **workspace tests** — falhavam antes desta rodada; estão verdes agora
  (308/0 e 315/0 com veil).
- **gate-b** (`community_service_survival_acceptance`) — ainda falha.

> **Atualização.** O bullet do clippy tem agora 218 avisos, não 200. O bullet
> dos workspace tests tem agora **491/0/1** e **498/0/1** com veil, não 308/0 e
> 315/0. O bullet do **gate-b continua em falha** — nada nesta rodada o tocou,
> porque tocar nele exigiria o que nenhuma tarefa de integridade de ledger pode
> fornecer: uma segunda máquina.

Defeito de projeto do próprio pipeline, independente do clippy: o job de
feature-matrix roda `cargo check`, **não** `cargo test`. Ou seja, mesmo depois
de ficar verde, a CI **compilaria** as suítes veil e nunca as **executaria**.
Um check verde sobre testes não roda é uma afirmação menor do que parece.

### Um bug real encontrado e corrigido nesta rodada

`spawn_bwrap`, em `crates/vacuum/src/process.rs`, resolvia o binário do nó
apenas a partir de `spec.mycelium_bin` mais quatro caminhos fixos, dois deles
relativos ao CWD. `cargo test` define o CWD como a raiz do pacote, então os
caminhos relativos à raiz do workspace não achavam nada. Corrigido com ordem de
resolução explícita — override explícito → `<root>/target/<profile>/mycelium`
→ `PATH` → caminhos legados de `/tmp` — ancorada numa raiz de workspace
derivada de `current_exe()`
(`crates/vacuum/src/process.rs:676-694`, `:723`), não do CWD.

Detalhe que merece ficar registrado: o `PATH` precisou vir **depois** do build
da raiz do workspace, não antes. Há um instal global obsoleto em
`/home/bruno/.local/bin/mycelium` (3 de ago) que não tem a rota `/status` nem o
header `x-chamber-pid` que o teste afirma — um binário velho no `PATH`
sombreando o build da própria árvore falhava em silêncio. São 7 testes
herméticos novos cobrindo a precedência.

### Correções fail-closed concluídas nesta rodada

- **`vacuum`** — `fail_closed` é default `true`; `bwrap` ausente devolve
  `IsolationUnavailable` em vez de gerar processo sem sandbox; `MYCELIUM_FAIL_CLOSED`
  é opt-**out** explícito.
- **`mycelium-zkp`** — `prove_range` / `verify_range` devolvem
  `Result<_, ZkpError>` com `RangeProofDisabled` em vez de entrarem em pânico
  via `unimplemented!()` no caminho default.
- **`mycelium-store` + `mycelium-node`** — o `Arc<Mutex<StoreCatalog>>`
  compartilhado ganhou `StoreCatalog::validate()` chamado em toda aquisição, em
  **6 sites no store** e **3 no daemon**; `CatalogError::Poisoned` recusa.
  `launch_spore_handler` (HTTP) e `StoreLaunch` (daemon) estão fail-closed
  ambos. Antes, a ponte HTTP era fail-closed e o daemon fail-**open** sobre o
  mesmo estado compartilhado — a mesma lacuna, dois portões, um aberto.
- **`mycelium-veil`** — `VeilError::Poisoned` adicionado; `route()` reestruturado
  para que `pipeline.process()` rode **antes** do lock de sessão, eliminando a
  única seção crítica com risco de pânico; `PoolTelemetry` consolida quatro
  mutexes em um só, para que o snapshot não possa mais rasgar.

### Duas ressalvas que não podem ser enterradas

1. **`active_layers == 0` é hoje uma tautologia.** `wired_layer_count()`
   (`crates/mycelium-veil/src/lib.rs:182`) devolve 0 porque
   `pipeline_on_data_path` é inicializado `false` em `lib.rs:162` e nunca é
   mutado para `true` em lugar nenhum da árvore — 3 menções no total:
   declaração, inicialização e leitura. Logo, a asserção em
   `veil_socks5_integration.rs:79` **não pode falhar hoje**. É uma armadilha de
   detonação para quem ligar o pipeline, não verificação independente. Um teste
   que só pode passar não é evidência.
2. **A Layer 0 executa em produção.** `start_session` (`lib.rs:206-210`) chama
   `l0.process(b"")` para derivar o MAC. Portanto "o pipeline não está no
   caminho de dados" é estritamente verdade **para o caminho de dados**, não
   para execução em geral. A frase mais fraca é a correta; a mais forte seria
   falsa.

### Aviso de disco

`/dev/sda2` está em **98%** com ~12 GB livres; `target/` ocupa **103 GB**.
Outros builds a frio são inseguros nesta máquina até que housekeeping seja
aplicado.

> **Atualização — resolvido.** Medido agora: `/dev/sda2` em **74%**, 109 GB
> livres. 104 GB foram devolvidos apagando o `target/debug` (103 GB, gitignored)
> e o `crates/mycelium-economy/target/` órfão (2,3 GB, verificado conter só
> artefatos de build). O `target/release/mycelium` foi preservado
> byte-idêntico: 39.606.560 bytes, mtime `2026-09-23 22:52:07` inalterado.
> Builds a frio voltaram a ser seguros nesta máquina. Nenhum ficheiro
> versionado foi tocado.

### O que esta rodada não mudou

Nada nesta rodada moveu a lacuna de topologia. Nenhuma máquina a mais, nenhuma
rede a mais, nenhum inbound verificado, nenhuma contraparte. O gate veil agora
rodar é **precondição para fechar a lacuna** — sem ele, qualquer falha em rede
real seria indistinguível de falha de código — e **não é progresso** no sentido
de se aproximar de (b), (c) ou (d). Tratar a execução local como meio caminho
para (b) seria exatamente o tipo de inferência que a seção "O que NÃO é prova"
abaixo recusa.

## Rodada P0–P2: o ledger de autonomia, auditado

O que vem a seguir não acrescenta nenhum host, nenhuma rede, nenhum inbound
verificado e nenhuma contraparte. São correções de verdade de código, todas
medidas e com código de saída. **Os níveis (b), (c) e (d) continuam NÃO
SUSTENTADOS, o placar E6 continua 0/9, e o valor externo liquidado continua
zero.** Nada nesta rodada é um passo em direção a (b), (c) ou (d), e nada
nela toca a afirmação de validade topológica deste documento.

O achado central desta rodada, porém, é o mais grave já registrado aqui, e
não é sobre rede: é sobre integridade.

### P0 — `mycelium-economy` deixou de ser órfão

`crates/mycelium-economy/Cargo.toml:8-9` carregava a sua própria tabela
`[workspace]` vazia. Ela foi removida, e o crate passou a constar de
`Cargo.toml:34` (`members`) e de `Cargo.toml:73` (`[workspace.dependencies]` —
inerte, por convenção: os outros 30 members têm lá entrada, e este crate
declara as suas dependências inline).

Efeito, que é o ponto inteiro: os **58 testes** do crate passaram a ser vistos
por `cargo test --workspace` **pela primeira vez**. Antes, 58 testes verdes
rodavam em **zero execuções de CI**, e a única causa era aquela linha. O job
de workspace tests (`.forgejo/workflows/validate.yml:62`) roda
`cargo test --workspace` e passa agora a alcançar este crate — mas a CI
continua vermelha por outros motivos, e o job em questão corre sem
`--no-fail-fast` e sem `--locked` (ver "Metodologia de medição").

A unificação de features do `reqwest` foi conferida **antes** de editar, não
depois: a raiz declara `default-features = false` com
`["http2","rustls-tls","stream","blocking"]` (`Cargo.toml:90`) e o crate
economy `["blocking","json","rustls-tls"]`
(`crates/mycelium-economy/Cargo.toml:21`). O resultado fundido é
**puramente aditivo** — `json` entra, nada sai, e o backend TLS é o mesmo nos
dois lados —, portanto nenhum outro crate podia quebrar por unificação de
features. Isso não é argumento: foi confirmado empiricamente pelo
`cargo check --workspace --all-targets --locked` verde descrito abaixo.

Diff do `Cargo.lock`: **+16 inserções, 0 remoções**. Quinze linhas são o
novo pacote `mycelium-economy` com as suas 9 dependências; a décima sexta é
uma correção de drift pré-existente — `"ed25519-dalek"` passou a constar nas
deps de `mycelium-core`, que o seu `Cargo.toml:14` já declarava
(`ed25519-dalek = { workspace = true }`) e o lockfile em HEAD omitia. Nenhuma
versão foi tocada; nenhuma linha saiu.

### O modelo de ameaça que não estava escrito

Uma auditoria somente-leitura da fronteira de confiança do ledger de autonomia
estabeleceu, com evidência, o seguinte. As citações de linha são do estado
**pré-P2** quando o próprio código já foi corrigido; onde isso acontece, está
dito.

**1. A fonte da verdade era escolhida por quem chamava.** O URL de RPC da Base
era lido de `argv[3]` nos comandos de cadeia
(`crates/mycelium-economy/src/bin/mycelium-economy.rs:384-387`, estado
pré-P2), com default `http://127.0.0.1:8546`. `BaseUsdcVerifier::new`
(`base_usdc.rs:73-94` hoje; era `:52-72`) aceitava **qualquer** endpoint
loopback.

**Consequência, e é a mais grave deste documento:** qualquer processo capaz de
fazer bind numa porta loopback podia conduzir o verificador legítimo a emitir
um `ExternalValueReceipt` com `proof_verified: true` **genuinamente**, sem
forjar nada, sem assinatura e sem tocar numa linha do código. Não era um
ataque a uma assinatura: era um ataque à **fonte**. Quem ganha a corrida pela
porta 8546 fica com autoridade económica real e, enquanto isso durar, todo o
trabalho de tornar o ledger à prova de forjamento é trabalho desperdiçado — a
verdade estava sob controlo do atacante.

**2. A cadeia de hash não tem âncora externa.** O hash commita o registro
inteiro (`autonomy.rs:307-315`, `computed_hash` hasheia a struct
re-serializada), mas a cadeia **não tem âncora externa, não tem assinatura, e
o seu génese é uma constante pública hardcoded**
(`autonomy.rs:23`, `AUTONOMY_GENESIS_HASH`). Ela detecta
modificação-sem-recomputação. Não detecta fabricação: quem escreve o ficheiro
recalcula a cadeia inteira, e o resultado é internamente consistente por
construção. Isto é uma limitação estrutural, não um defeito de implementação,
e continua válida depois de P1 e P2.

**3. A leitura da cadeia não volta a executar nada.**
`AutonomousEconomy::records()` (`autonomy.rs:332-379`) verifica sequência,
`prev_hash` e `record_hash`, e é isso. Ela **nunca** re-executa
`validate_external_value()` e **nunca** prova estado on-chain no momento da
leitura. Um `proof_verified: true` gravado por um caminho não verificado é lido
de volta como fait accompli.

**4. O elo mais fraco estava fora da cadeia.**
`s1-outcome-policy.json` — o ficheiro que fixa o endereço do executor contra o
qual o reconciliador valida (`s1_outcome.rs:249` carrega a policy, `:315-318`
rejeita qualquer `tx_to` que não seja o executor) — vive **fora** da cadeia,
**sem assinatura**, e é livremente sobrescrevível. Um pin de verdade que pode
ser trocado sem deixar rasto não é um pin.

**5. Não há endurecimento de permissões nem lock de ficheiro.** Os ficheiros
são criados por `fs::create_dir_all` + `OpenOptions` (`lib.rs:337,397,423,864`;
`autonomy.rs:324,949`; `reinvestment.rs:144,443`; `s1_outcome.rs:118,158`) sem
modo explícito e sem lock. Os ledgers herdam o umask — tipicamente `0644`.
Nota de precisão, feita **depois** de P2: um grep por `set_permissions` /
`PermissionsExt` / `flock` / `fs2` devolvia **zero** ocorrências na auditoria;
hoje devolve **três**, todas em código de teste
(`chain_provider.rs:454-455`, `rpc_test_server.rs:56-57`,
`base_usdc.rs:742-743`), e todas existem para *provocar* a recusa — modo
`0o777` num caso, `0o700` no fixture do servidor falso. Em código de produção
o resultado continua a ser zero: **não há `0700`/`0600`, não há `flock`**.

**6. Serde descarta chaves desconhecidas por omissão.** Um atacante podia
acrescentar chaves JSON arbitrárias ao ficheiro sem quebrar a cadeia. O
`deny_unknown_fields` (P1, abaixo) fecha isto, e o comentário de
`computed_hash` (`autonomy.rs:302-306`) passa a dizer o que é verdade: o hash
commita o registro **semântico canónico**, não os bytes persistidos.

**7. A falsificação foi demonstrada, não apenas argumentada.** Três registros
JSONL escritos à mão — `Agent` + `Opportunity` + `ExternalValue` — atingem
`level: "ARV4"` (`autonomy.rs:896-897`, que exige ≥ 2000 mUSD/dia numa janela
de 30 dias) e rendem **100 mUSD/dia de autoridade real de reinvestimento**
(`reinvestment.rs:68`, `max_daily_commitment_musd_micros = 100_000_000`) via
`reinvestment::decide` (`reinvestment.rs:152`) → `commit_job`
(`reinvestment.rs:267`) → o ledger legítimo `reinvestment-ledger.jsonl`
(`reinvestment.rs:149`). Dois bastam para fechar a janela de 30 dias. As
guardas de API — `validate_external_value`, a allowlist de classe interna, a
recusa de reuso de prova, `net = gross − cost` — são **todas** contornadas,
porque o atacante escreve o ficheiro diretamente e nenhuma delas é consultada
na leitura.

**A formulação correta, que este documento passa a adotar:** o objetivo não é
"tornar o ledger infalsificável" — isso é indecidível localmente, e nenhum
esquema criptográfico com a chave no mesmo `$HOME` muda o resultado, porque um
atacante do mesmo principal do processo possui essa chave. O objetivo é
**"tornar um ledger falsificado estruturalmente incapaz de produzir autoridade
económica"**. A frase a memorizar é `ledger ≠ authority`: um registro é uma
afirmação; a autoridade tem de ser re-derivada de evidência verificada a cada
leitura. P1 e P2 são passos reais nessa direção e **nenhum** dos dois chega lá.

### P1 — fronteira de liquidação tipada

Novo módulo `crates/mycelium-economy/src/boundary.rs`.

- `SyntheticAsset` (`:46`) e `RealAsset` (`:68`, campos privados, construtor
  validador em `:87` e allowlist `is_known()` em `:120`).
- `ControlDomain` (`:151`) é **Serialize-only, deliberadamente sem
  `Deserialize`** — nenhum JSON pode introduzir um domínio. O comentário no
  código diz o porquê: um domínio que se pode ler de um ficheiro é um domínio
  que um escritor pode afirmar, e afirmar `External` é precisamente a
  falsificação que este desenho remove.
- `BoundaryEvidence` (`:234`) é a única forma persistida e contém
  **endereços e hashes, nenhum campo de domínio**.
- `ControlledAddressRegistry` (`:160`), com `domain_of()` (`:214`), semeada
  a partir de `PaymentPolicy.payout_address` (`from_policy`, `:172`).
- `BoundaryCrossing` (`:385`) tem campos privados e **não** tem `Deserialize`;
  o seu único caminho de construção é `derive(&evidence, &registry)` (`:402`),
  que **não pode ser chamado sem um registry**. `CrossingKind` (`:288`) cobre as
  4 linhas invariantes.
- Um `SyntheticAsset` **não pode** aparecer num `BoundaryCrossing`, por
  sistema de tipos: o campo é `RealAsset` e nenhum construtor do módulo aceita
  um sintético. Registrado com honestidade: isto é uma **garantia de tipo**,
  não um teste de compile-fail `trybuild`; não existe tal harness no crate.
  Um teste que verifica por construção que a síntese não entra num crossing
  existe (`synthetic_asset_cannot_be_placed_in_a_crossing`, `:854`), mas o que
  ele prova é o comportamento em runtime, não um erro de compilação.
- `lib.rs:148` `settlement_asset: String` → `SettlementAsset`; `lib.rs:172`
  `counts_as_paid_demand` passou a exigir `is_real()`. A serialização continua a
  ser a mesma string plana ("USDC"), deliberadamente: `computed_hash` hasheia a
  struct re-serializada e um mapa aqui invalidaria todo hash já em disco.
- `deny_unknown_fields` nos envelopes de ledger confiados: `LedgerRecord`,
  `JobRequest`, `WorkReceipt`, `PaymentIntent`, `SettlementReceipt`,
  `PaymentPolicy` (`lib.rs:84,98,114,137,182,313`) e `AutonomyRecord`,
  `AutonomyPayload` e os payloads de autonomia (`autonomy.rs:48,63,103,128,197,
  278,292`). Só rejeita chaves extras; não muda a forma serializada.
- `validate_hash32` consolidada numa cópia só: pública em
  `base_usdc.rs:598`, com `s1_outcome.rs:642-646` a delegar. Comportamento
  idêntico.

### P2 — fonte de cadeia confiável

Novo módulo `crates/mycelium-economy/src/chain_provider.rs`. Toda a leitura de
cadeia passa por um único choke point, `base_usdc.rs:395 rpc_call`.

- O URL de RPC posicional foi **removido dos cinco comandos de cadeia**;
  passá-lo devolve `RPC_ARG_REMOVED` (`bin:87-92`, arms em `bin:294,299,306,317,
  455`). Comandos novos de provisionamento: `payment-policy-pin-provider`
  (`bin:280`) e `s1-outcome-policy-pin-provider` (`bin:441`).
- Ordem de resolução (`chain_provider.rs:260 resolve`, glue em `lib.rs:437`):
  1. `MYCELIUM_DEV_BASE_PROVIDER` (`chain_provider.rs:29`) — só
     dev/test; é o único caminho para HTTP loopback, e **toda** a verificação
     que ele permite sai marcada `provider_identity_verified: false`;
  2. pin de `chain_provider` na policy de pagamento (`lib.rs:326`);
  3. sem pin → `EconomyError::ProviderUnpinned` (`lib.rs:51`).
  **Sem endpoint default, sem fallback.**
- Um pin de policy **tem de ser um Unix domain socket**
  (`validate_policy_pin`, `chain_provider.rs:173`, que recusa loopback HTTP
  por não ter identidade verificável). A identidade é verificada com
  `std::os::unix::fs::{FileTypeExt, MetadataExt}` (`chain_provider.rs:21`) —
  `lstat` (recusa symlink), `is_socket()`, `mode & 0o022 == 0`,
  `uid ==` dono configurado — na construção **e antes de cada chamada**
  (`verify_socket_identity`, `chain_provider.rs:188`; `is_socket()` em `:204`,
  modo em `:210`). **Nenhuma dependência nova**: `Cargo.toml` intocado, e o
  transporte HTTP/1.1 + JSON-RPC sobre `UnixStream` foi escrito à mão
  (`base_usdc.rs:488`) porque o `reqwest` não fala socket unix.
- A allowlist de métodos read-only (`base_usdc.rs:395-410`, arms em `:399-405`)
  está **inalterada** e continua a bloquear `eth_sendRawTransaction`. Um teste
  novo também bloqueia `eth_sendTransaction`, `eth_signTransaction`,
  `personal_sendTransaction` e `eth_sign`, e afirma que **nenhum** request
  chegou ao provider. O crate permanece estruturalmente incapaz de transmitir.
- O comentário de fronteira em `base_usdc.rs:96-117` diz explicitamente o que
  isto **não** defende: um atacante com root, um atacante no mesmo principal do
  OS que consiga substituir o binário ou escrever a policy, um nó upstream
  Base comprometido, e o override de dev — que é não autenticado por
  construção e diz isso em cada registro de verificação.

### Verificação desta rodada

| Comando | Exit | Resultado |
| --- | --- | --- |
| `cargo test -p mycelium-economy --locked` | 0 | **130 passed / 0 failed** (124 lib + 6 integração CLI) |
| `cargo check --workspace --all-targets --locked` | 0 | 0 erros, 0 warnings |

Baseline do crate: 58. Delta: **+72 testes**. Confirmado por contagem de
atributos, sem depender do runner: `grep -rho '#\[test\]' crates/mycelium-economy/src/`
devolve **124**, e `tests/pinned_provider_cli.rs` tem **6**.

O que **não** foi medido: `cargo test --workspace` **não** foi reexecutado
depois de P0. As contagens de 308/0 e 315/0 da baseline de remediação
descrevem a composição do workspace **anterior** à entrada do crate economy;
com o crate dentro, o número de testes que o workspace executa é maior e
**não foi medido aqui**. Qualquer pessoa que leia "308" como o estado atual
do workspace está a ler um número velho.

Disco: **104 GB devolvidos**. Apagados o `target/debug` (103 GB, gitignored) e
o `crates/mycelium-economy/target/` órfão (2,3 GB, verificado conter apenas
artefatos de build). `target/release/mycelium` preservado byte-idêntico —
39.606.560 bytes, mtime `2026-09-23 22:52:07` inalterado. `/dev/sda2` de 99%
para 74%, 109 GB livres.

Estado depois da rodada, para quem for olhar: `target/` voltou a 8,1 GB e
`target/debug` a 2,0 GB, porque as execuções de verificação de P1 e P2
recompilaram o que era preciso. O que o housekeeping devolveu foi **folga**,
não um `target/` permanentemente vazio — e `crates/mycelium-economy/target/`
continua inexistente. Nada versionado foi tocado.

Sobre o caminho `~/.mycelium/economy/`: existe, e hoje tem **um** ficheiro,
`payment-policy.json` (228 bytes, `d28 set`, `-rw-rw-r--`). Nenhum
`*.jsonl` de ledger foi criado por esta rodada. O modo `0664` desse ficheiro é
em si uma ilustração do ponto 5 acima do modelo de ameaça.

### Metodologia de medição: como ler qualquer número de teste daqui para frente

Dois defeitos de método foram descobertos nesta rodada e **produziram um falso
verde**. Ambos valem para toda a leitura de números de teste deste projeto, e
por isso ficam registrados:

1. `cargo test` **para no primeiro binário de teste que falha** e não reporta
   as falhas depois dele. Uma contagem de "passou" tirada de uma execução sem
   `--no-fail-fast` é uma contagem do que veio antes da primeira falha.
2. Pipar a saída do cargo para `tee` reporta o **exit status do `tee`**, não o
   do cargo. `cargo test … | tee log.txt` reporta **0** mesmo quando o cargo
   sai com 101. Foi assim que um falso positivo foi produzido nesta rodada.

Portanto: `--no-fail-fast` e `${PIPESTATUS[0]}` são obrigatórios para uma
contagem em que se possa confiar. Vale notar que
`.forgejo/workflows/validate.yml:62` hoje corre `cargo test --workspace`
**sem** `--no-fail-fast` e **sem** `--locked` — o que significa que, quando
essa linha passar a ser verde, o número que ela mostra não é o número total de
testes do workspace. Isto é exatamente o tipo de número que a seção "O que
NÃO é prova" recusa.

### O que esta rodada **não** mudou

Nada aqui moveu a lacuna de topologia. Nenhuma máquina a mais, nenhuma rede a
mais, nenhum inbound verificado, nenhuma contraparte. Os níveis (b), (c) e (d)
e o placar E6 0/9 estão exatamente onde estavam, e o valor externo liquidado
continua **zero**.

### O que permanece aberto, e é muito

Isto é a parte desfavorável da rodada, e é maior do que o que foi fechado.

1. **O ataque de ledger falsificado continua vivo.** P1 removeu a capacidade de
   *afirmar* um domínio; **não** verifica evidência. Um processo que consiga
   escrever `~/.mycelium/economy/*.jsonl` ainda pode inventar endereços, hashes
   de transação e hashes de bloco e re-derivar um crossing a partir deles.
   Somado ao ponto 7 acima, o ataque real continua a dar autoridade
   económica. Só P3 (`VerifiedEconomyView`) faz a autoridade depender de
   evidência verificada em vez de bytes armazenados.

   > **Atualização — este item fechou, e a última frase é a razão de ter
   > fechado.** P3 existe, e a falsificação escrita à mão que rendia 100 mUSD/dia
   > de autoridade real agora para em `AttestationGap::ChainNotConfirmed`, porque
   > a transação que o receipt cita **não existe**. Isto vale para ARV, para RV e
   > para o orçamento de reinvestimento. O que P3 **não** fez foi tornar a cadeia
   > de hash autêntica: ela continua verificável contra si própria, o génese
   > continua a ser uma constante pública, e o item 2 desta lista continua
   > aberto — `record_external_value` ainda existe e ainda não consulta crossing
   > nenhum. O que mudou é o que essa abertura **consegue** fazer, e a diferença
   > é a diferença entre um número e autoridade.
2. **`record_external_value` (`autonomy.rs:565`) está inalterado e continua
   aberto.** Não consulta crossing nenhum, logo um valor lançado por ele não
   carrega evidência de fronteira. Só
   `record_external_value_with_crossing` (`autonomy.rs:664`) é o caminho
   tipado, e ele é opcional.

   > **Atualização — as linhas mudaram, o facto não.** Hoje
   > `autonomy.rs:686` e `autonomy.rs:785`. O caminho não tipado continua a
   > existir e continua opcional; o que mudou é que, quando existe um crossing
   > citado, o valor **não tipado** já não pode ser promovido: a vista re-deriva
   > o crossing contra o registry como ele está agora, e sem `proof_verified`
   > nenhuma.
3. **Um outflow nunca consegue lançar um receipt.** O crossing exige uma classe
   que crie valor, e a `validate_external_value` pré-existente recusa classes
   não criadoras quando `proof_verified`. Está testado e comentado
   (`crossing_rejects_a_class_it_does_not_justify`, `boundary.rs:1258`), não
   contornado. É deliberado por agora e é um **ponto de decisão**, não um
   detalhe.

   > **Atualização — continua aberto, e a linha mudou**
   > (`boundary.rs:1284`). P3 torna-o mais consequente sem o resolver: uma
   > **perda** externa continua não atestável, e portanto um ganho **não
   > atestado** e uma perda **não atestada** ficam ambos fora da base
   > reinvestível. Continua a ser uma decisão de desenho, não um bug.
   >
   > **Atualização — P4 não resolveu isto, e a frase que o segue tem de ser
   > lida com o pior dos dois valores.** P4 fechou uma assimetria **dentro** das
   > entradas — a receita estava sem assinatura e passou a estar assinada — mas a
   > assimetria **entre** entradas e saídas é a mesma. `BoundaryCrossing` deriva
   > `ExternalToControlled` como **+valor** e não existe um
   > `ControlledToExternal` = **−valor** simétrico, portanto uma perda externa
   > continua impossível de atestar, e `NEV = ΣVerifiedInflows −
   > ΣVerifiedOutflows` **não é ainda computável**. Isto é o **próximo item
   > concreto depois de P4** e está escrito como tal em "Próximo gate" e na
   > lista de carranças da rodada P4, item 11. O que P4 acrescenta é que a
   > assimetria passou de *um detalhe de desenho* a *um bloqueador nomeado*: sem
   > o lado das saídas, o `NEV` que este documento reporta como 0 é um 0
   > **incompleto**, não um 0 de economia medida.
4. **`with_verified_proof` (`boundary.rs:424`) não olha para o
   `provider_identity_verified` de P2.** Verifica `verified`, chain, token,
   amount, recipient, tx e block — e nada mais. Logo, um crossing pode ser
   fechado por prova vinda do override de dev. É uma linha; ninguém a
   escreveu.

   > **Atualização — continua exactamente como está.** `boundary.rs:424` não
   > mudou e continua sem olhar para `provider_identity_verified`. Mas o
   > caminho de autoridade de P3 **não depende só disto**: o quarto portão em
   > `verified_view.rs:772` recusa o mesmo verificador antes de a prova contar
   > para alguma coisa, e `provider_pinned()` já nem chega a construir a vista.
   > Logo a frase "é uma linha; ninguém a escreveu" descreve um facto e já não
   > descreve uma exposição no caminho que decide autoridade.
   >
   > **Atualização — a linha continua igual, e deixou de ser o único portão por
   > uma razão mais forte.** `boundary.rs:424` continua exactamente onde estava
   > e continua sem olhar para `provider_identity_verified`. Mas P4 **tornou esse
   > sinal obrigatório em todo o caminho de atestação**: existe agora um
   > `AttestationGap::ProviderIdentityUnverified` dedicado
   > (`verified_view.rs:222`) e um `SettlementGap::ProviderIdentityUnverified`
   > (`verified_view.rs:487`), e nenhum receipt nem settlement sem identidade de
   > provider verificada pelo kernel é contado. A consequência a registar com
   > honestidade é a contrária da que se poderia supor: **essa variante de
   > lacuna é hoje inalcançável pela API pública**, porque `provider_pinned`
   > recusa antes e o campo é imutável. É defesa em profundidade, não um caminho
   > vivo; nenhum teste a alcança e nenhum foi escrito para parecer que sim. Ver
   > a lista de carranças da rodada P4, item 5.
5. **S1 ainda não está ligado ao crossing.** `with_verified_proof` exige
   `receipt.proof_hash == crossing.tx_hash`, mas o adaptador S1 cita um hash de
   receipt S1, não um hash de transação Base. Precisa de decisão em P3 —
   acrescentar um campo a `ExternalValueReceipt` mudaria **todo** hash já
   armazenado.

   > **Atualização — decidido em P3, pela opção (a), e sem o custo previsto.**
   > `proof_hash` passou a ser o hash da transação Base
   > (`s1_outcome.rs:407`), `source_id` passou a ser
   > `s1-base:<tx>:<hash do receipt S1>` (`s1_outcome.rs:383-387`), e o
   > reconciliador emite `BoundaryEvidence` para a perna que já verificava
   > (`s1_outcome.rs:423`). **Nenhum campo novo em `ExternalValueReceipt`**, e
   > portanto **nenhum hash já armazenado** foi invalidado: mudam-se os
   > `record_hash` dos registros **novos**, nada em disco foi reescrito, e os
   > receipts S1 antigos continuam a deserializar — reportados como *unattested*,
   > com o motivo escrito.
6. **`amount_raw` é `u64`, não `u128`.** Um `u128` dentro do
   `AutonomyPayload` internamente taggeado pode ser escrito mas nunca lido de
   volta (o deserializador de conteúdo de enum taggeado do serde não suporta
   `u128`). Consistente com `BaseUsdcVerifier` já recusar transferências USDC
   acima de `u64::MAX`.
7. **Sem `0700`/`0600`, sem `flock`, sem âncora externa de cabeça.** Nenhum
   desses três derrota um atacante do mesmo principal; só uma âncora externa
   derrota.

   > **Atualização — 2 dos 3 entregues, e a ressalva final continua com a
   > força toda.** Hoje há `0700`/`0600` passados como argumento de modo de
   > `open(2)` e corrigidos activamente quando se encontra um modo lixado; há lock
   > exclusivo por sentinela `O_CREAT|O_EXCL` com vitalidade lida de `/proc`; e há
   > uma âncora de cabeça em ficheiro separado, verificada na leitura. **O que
   > não há** é `flock` — foi substituído pela sentinela, e a corrida residual
   > dela está declarada no código — e **não há âncora externa**, porque a
   > âncora em ficheiro separado é um **alarme** e o próprio doc do módulo
   > chama-lhe isso. A segunda frase deste item, "só uma âncora externa
   > derrota", **não foi tocada por P5** e é a afirmação que sobrevive a esta
   > rodada inteira.
8. **Nada foi commitado.** `crates/mycelium-economy/` continua untracked
   (`git status --porcelain` devolve `?? crates/mycelium-economy/`) e
   `docs/economy/` idem. Todo o trabalho medido acima vive em arquivos que um
   `git clean` apaga.

   > **Atualização — continua verdade, e agora vale para mais trabalho.** Nada
   > foi commitado nesta rodada também; a secção "Rodada P3 e P5" acima é
   > exactamente a mesma situação, com mais ~4.680 linhas a viver num
   > directório que um `git clean` apaga. O oposto de um registo é um registo
   > que sobrevive ao `git clean`, e este ainda não sobrevive.

> **Atualização — o item 1 e o item 5 deixaram de valer; o item 7
> parcialmente.** P3 fecha o ataque de ledger falsificado (ver "P3" na rodada
> P3–P5 abaixo) e decide a ligação de S1 ao crossing, com a opção (a) e sem
> campo novo em `ExternalValueReceipt`. P5 entrega `0700`/`0600` e um lock
> exclusivo, mas **não** `flock` e **não** âncora externa — e a própria
> documentação de código nomeia o substituto: uma âncora de cabeça em ficheiro
> separado, que é um **alarme** e não uma prova. O parágrafo acima fica como
> registo do estado antes de P3 e P5.

## Rodada P3 e P5: a autoridade passa a ser verificada, e o ledger a ser durável

O que vem a seguir também não acrescenta nenhum host, nenhuma rede, nenhum
inbound verificado e nenhuma contraparte. **Os níveis (b), (c) e (d) continuam
NÃO SUSTENTADOS e o placar E6 continua 0/9, sem uma única linha alterada na
secção de E6.** O valor externo liquidado continua **zero**. P3 e P5 são
correções de integridade de código, medidas e com código de saída; não são um
passo em direção a (b), (c) ou (d), e nada aqui toca a afirmação de validade
topológica deste documento.

São duas rodadas porque fecham duas coisas diferentes. **P3** é o passo que
torna `ledger ≠ authority` uma **propriedade do sistema de tipos** e não uma
promessa de leitura cuidadosa. **P5** é o passo que torna os mesmos ficheiros
privados, serializados e detetáveis quando algo corre mal.

### P3 — `VerifiedEconomyView`

Novo módulo `crates/mycelium-economy/src/verified_view.rs` (2.390 linhas). A
identidade de verificação está no doc do módulo, não num comentário lateral
(`verified_view.rs:7`, e o que é proibido em `:27`):

```text
TrustedNEV = VerifyChain(VerifyPolicy(DeriveBoundary(Evidence)))

FORBIDDEN: TrustedNEV = receipt.proof_verified
```

Isto é a mesma identidade que "Próximo gate" já anunciava, agora escrita no
código que a executa.

**Duas vistas.** `VerifiedEconomyView` (`verified_view.rs:424`) serve o ledger
de autonomia — ARV, NEV verificado, decisão de reinvestimento.
`VerifiedRevenueView` (`verified_view.rs:910`) serve o ledger de receita — RV e
demanda paga. O `ControlledAddressRegistry` e o verificador são **parâmetros de
construtor** (`verified_view.rs:425-428`, `:433-437`, `:450-454`), nunca lidos
do diretório: um registry é uma afirmação do operador sobre que endereços são
controlados, e lê-lo do disco seria devolver a P1 o que P1 tirou.

**O modo de confiança é um tipo distinto, não uma flag.** Esta é a diferença
que faz a propriedade valer:

- `TrustMode::Unverified` devolve `UnattestedNev` (`verified_view.rs:260`) — um
  tipo **sem `Deserialize`** e sem nenhum accessor que um predicado de promoção
  ou uma porta de orçamento possa aceitar. "Três receipts re-derivam e 5,0 mUSD
  é afirmado" e "5,0 mUSD é atestado" são frases diferentes, e só a segunda
  pode gastar dinheiro.
- Só `TrustMode::ProviderPinned` produz `VerifiedNev` (`verified_view.rs:286`):
  campos privados, sem `Deserialize`, **sem construtor público em lado nenhum do
  crate**. Existe **exatamente um** sítio de construção em todo o repositório —
  `verified_view.rs:507`, dentro de `verified_nev()`.
- `provider_pinned()` **recusa** construir com um endpoint que o kernel não
  identifica (`verified_view.rs:455-464`), pelo que o override de loopback de
  desenvolvimento nunca pode promover. Testado por
  `a_provider_without_a_kernel_identity_cannot_attest`
  (`verified_view.rs:2094`).
- Não existe flag para forçar o modo fraco. `TrustMode` é um enum com duas
  variantes; a única forma de obter um número acionável offline é não obtê-lo.

**Os caminhos económicos saíram das flags armazenadas para a vista.**
`arv_status` (`autonomy.rs:1033`), `summary` (`autonomy.rs:934`),
`rv_status` (`lib.rs:956`), `revenue_summary` (`lib.rs:900`) delegam agora na
vista. `reinvestment::decide` (`reinvestment.rs:245`) deixou de ser autoritativo e
passou a delegar em `decide_from_view` (`reinvestment.rs:261`); `commit_job`
(`reinvestment.rs:404`) faz o mesmo com `commit_job_from_view`
(`reinvestment.rs:421`), que recusa **antes** da aritmética. `decide` deixou de ser um caminho
autoritativo por construção: ele próprio monta uma vista `Unverified`
(`reinvestment.rs:252-254`) e delega. O nome antigo ficou, o contrato antigo
não.

Foi acrescentado `autonomy::revalidate_external_value`
(`autonomy.rs:1158`), que re-executa as regras de escrita **na leitura**,
incluindo o invariante `gross − cost` (`autonomy.rs:1171-1178`). A separação
foi deliberada e está escrita no doc: `validate_external_value` tem contrato
condicional no `proof_verified` armazenado, e um leitor que a chamasse herdava
essa dependência. Aqui `proof_verified` **não é consultado**; a pergunta é se o
registo é internamente consistente, não o que o escritor afirmou sobre ele. Por
isso um receipt escrito com a flag desligada conta se a evidência for genuína.

**Resultado da falsificação.** O ledger forjado passa a cadeia de hash, passa a
classe de valor, passa a re-validação e passa a derivação de fronteira. Falha em
`AttestationGap::ChainNotConfirmed` (`verified_view.rs:160`) — o receipt cita
uma transação que **não existe**. É este o teste a que a frase do documento
"tornar um ledger falsificado estruturalmente incapaz de produzir autoridade"
deixa de ser aspiracional: três registros JSONL escritos à mão rendem agora zero
autoridade, e o motivo é nomeado, não um erro de parse nem um zero silencioso.

**S1: decisão de ligação, opção (a).** O ponto de decisão que P0–P2 deixaram
aberto está decidido, e a decisão foi a que não custa um hash já em disco:

- `proof_hash` passa a ser o hash da transação Base, não o hash do receipt S1
  (`s1_outcome.rs:407`). A razão está no próprio código: `with_verified_proof`
  exige `proof_hash == crossing.tx_hash`, e um hash de receipt S1 não nomeia
  transação nenhuma sobre a qual um provider possa ser perguntado — um receipt
  que cita um nunca poderia ser re-derivado e nunca contaria.
- `source_id = s1-base:<tx>:<hash do receipt S1>` (`s1_outcome.rs:383-387`),
  pelo que o receipt S1 **continua citável** a partir do ledger sem campo novo.
- O reconciliador emite `BoundaryEvidence` para a perna executor→beneficiário
  que ele **já** verifica (`s1_outcome.rs:423`), e volta a fazer essa leitura
  pelo verificador tipado para que a prova tenha a forma que
  `with_verified_proof` exige (`s1_outcome.rs:417-421`).
- **Nenhum campo novo em `ExternalValueReceipt`.**

> **Consequência, e é uma consequência real:** o valor escrito em registros
> **novos** mudou, logo o `record_hash` de um registro novo difere do que um
> build anterior teria escrito. Nada em disco foi reescrito, e um receipt S1
> escrito antes desta mudança **continua a deserializar** — sai reportado como
> *unattested*, com o motivo escrito
> (`a_ledger_written_before_p3_still_deserializes_and_is_reported_as_unattested`,
> `verified_view.rs:2353`). Isto é o comportamento pretendido, e é
> também a prova de que a mudança não é destrutiva.

### P5 — durabilidade do ledger

Novo módulo `crates/mycelium-economy/src/durability.rs` (1.460 linhas). Só `std`:
sem `libc`, sem `fs2`, sem `nix` (`durability.rs:3-5`).

**Permissões.** `0700` em diretórios e `0600` em ficheiros são passados como o
**próprio argumento de modo de `open(2)`** (`OpenOptionsExt::mode`,
`durability.rs:249-251` e `:263-265`), não como um `set_permissions` posterior:
não existe janela legível entre criar e proteger. Modos pré-existentes
lixados são **corrigidos ativamente** e a correcção é **registada**
(`force_mode`, `durability.rs:154`), com a razão escrita no doc: recusar em vez
de corrigir deixaria toda a instalação existente sem abrir, porque raízes criadas por
versões anteriores são `0755` por construção. Toda a escrita de produção na raiz
da economia passa por `append_line` (`durability.rs:285`) ou
`write_private_atomic` (`durability.rs:314`).

**Locking.** Sentinela em `O_CREAT|O_EXCL` — `create_new(true)` é exactamente
isso — em `<root>/.locks/<name>.lock` (`durability.rs:59`, `:433`,
`LedgerLock` em `:495`). A vitalidade em caso de crash vem de `/proc`: o ficheiro
de lock guarda `<pid>:<ticks de arranque>`, e a obsolescência é decidida por o
processo estar **vivo**, lido de `/proc` — não pela idade do ficheiro
(`durability.rs:439-442`). O tempo de arranque e não apenas o pid, porque senão
um pid reciclado pareceria um titular vivo e o lock penduraria para sempre
(`durability.rs:444`). Um zombie conta como morto: o `/proc` existe mas ninguém
poderá responder. `ENOENT` é morte provada.

Duas regras que valem mais do que o mecanismo: um titular **lento** nunca é
declarado morto, e um lock cujo titular não pode ser estabelecido é **recusado,
nunca roubado por suposição**.

> **A alternativa foi implementada primeiro, e o teste do implementador provou
> que estava errada.** A primeira versão era um `UnixListener` em bind como
> mutex. O raciocínio está escrito em `durability.rs:448-467` e vale a pena
> repetir porque é um erro de modelo mental, não de implementação: a
> **vitalidade** de um socket (o descritor em escuta) e a sua **posse** (a
> entrada no diretório) são **dois objectos diferentes**, e o kernel deixa que
> sejam trocados entre duas syscalls. A sequência que o teste reproduziu:
>
> ```text
> A libera:      desliga o listener, remove a entrada
> R sonda:       connect() -> recusado, entrada já ausente  (sem inode obsoleto!)
> C faz bind:    tem sucesso no caminho agora livre          (C é o dono)
> R remove:      apaga o socket de C                         (R também é o dono)
> ```
>
> C e R julgam ambos possuir o lock. Sob 16 threads a sondar, isto correu cerca
> de **uma aquisição em oito**. A sentinela não tem este caminho, porque **a
> entrada É a reivindicação** e **É o registo de vitalidade**: `O_EXCL` ou vê a
> entrada ou cria-a, e as duas coisas não se entrelaçam. A vantagem genuína do
> socket — o kernel libertá-lo no crash sem política de obsolescência — o
> sentinela recebe da vitalidade por `/proc`, e `/proc` já era dependência da
> verificação de propriedade deste crate.

**Append atómico.** Um buffer, um `write_all`, a newline **no mesmo buffer**,
um `sync_data` (`durability.rs:293-297`). O que o formato anterior podia fazer
era intercalar um registo com os bytes de outro escritor a meio da estrutura; isto
estreita a janela de registro partido ao prefixo de **uma** linha.

**Linha final partida.** Recuperada **em voz alta**: truncada de volta à última
newline completa, com o fragmento e a contagem de bytes impressos
(`recover_torn_tail`, `durability.rs:345`), e o total acumulado persistido em
`HeadAnchor.discarded_bytes_total` (`durability.rs:795`, acumulado em `:840-843`)
para que o evento seja observável **a posteriori**. A justificação está escrita e
é a que importa: um registo incompleto nunca foi reconhecido como confirmado, mas
**saltar o fragmento em silêncio esconderia o evento**. O log e o contador
existem para que ninguém possa afirmar depois que não houve corte.

**Deteção de truncamento.** Um ficheiro `*-head.json` à parte, escrito depois de
cada append e verificado na leitura (`HeadAnchor`, `durability.rs:784`;
`verify_head_anchor`, `durability.rs:871`; suavizado em `autonomy.rs:433` e
`lib.rs:815`). Três recusas: âncora à frente do ledger (cauda truncada ou ficheiro
trocado por uma cópia mais antiga), âncora na mesma sequência com hash diferente
(ledger reescrito no lugar, não acrescentado), e âncora atrasada cuja sequência
já não hasheia para o valor ancorado.

> **Isto é um alarme, explicitamente não uma prova**, e o doc do módulo
> (`durability.rs:30-42`) diz antes de qualquer comentário deste ficheiro:
> `HeadAnchor` **não** é uma âncora externa. Vive no mesmo diretório, sob o mesmo
> uid, com as mesmas permissões que o ledger que protege — um atacante que
> escreve o ledger reescreve a âncora. É um *tripwire*, e o termo é o do próprio
> doc do módulo: deteta truncamento acidental, corrupção bit-a-bit e um ledger
> trocado por uma cópia mais velha. **Não** derrota um
> atacante do mesmo principal que consiga reescrever os dois ficheiros. Só uma
> âncora externa derrota: um contador selado em TPM, um segundo host, um quórum
> de assinaturas, ou um log de transparência publicado. Nenhum está disponível sem
> dependência externa **e** contraparte externa, e ambos estão fora do âmbito
> aqui. O corte para `reinvestment-ledger.jsonl` usa o campo
> `autonomy_head_hash` que já existia (`reinvestment.rs:112`, verificado em
> `reinvestment.rs:222`).

### Lacuna de cobertura fechada depois da verificação

Este é o registo que interessa, porque **não** é um item novo: é uma falha de
cobertura que sobreviveu à implementação e só apareceu numa passagem de
verificação independente, por leitura de código.

Havia teste de ledger forjado escrito à mão para o ARV
(`a_forged_ledger_passes_the_hash_chain_and_still_cannot_promote`,
`verified_view.rs:1531`) e para o orçamento de reinvestimento
(`a_forged_ledger_cannot_raise_the_reinvestment_budget`,
`verified_view.rs:1571`). **Não havia nenhum para `rv_status`.** O código
estava correcto — `rederive_settlement` prova ignorar
`payment_proof_verified`/`external_paid` — mas **não estava provado**, e
"está correcto" dito por quem leu o código não é um teste.

Foram acrescentados dois testes em `crates/mycelium-economy/src/verified_view.rs`,
na nova secção "1b. the same forgery, against the REVENUE ledger"
(`verified_view.rs:1648`):

- `a_forged_revenue_ledger_passes_the_hash_chain_and_still_cannot_promote`
  (`verified_view.rs:1872`)
- `a_forged_revenue_ledger_is_still_refused_when_a_provider_is_pinned`
  (`verified_view.rs:1982`)

Três decisões que valem registar, porque são o que separa um teste útil de um
teste decorativo:

1. **A cadeia falsificada é afirmada como válida, positivamente.** Sequência
   contígua desde 1, `prev_hash` ligado ao `record_hash` predecessor a partir do
   génese público, `record_hash` **recomputado independentemente** da função
   privada do crate (`revenue_computed_hash`, `verified_view.rs:1721`, faz o
   `blake3` a partir dos bytes do próprio registo), e
   `audit_ledger().valid == true` (`verified_view.rs:1886-1887`). Uma falsificação
   que falhasse a sua própria cadeia não provaria nada: a vista nunca a veria.
2. **A razão da falha é uma lacuna de atestação concreta**, não um erro de parse
   nem um nulo: `SettlementGap::NoPinnedProvider` offline
   (`verified_view.rs:1937-1940`), `SettlementGap::ChainNotConfirmed` com
   provider pinado. A evidência é uma **lista de valores** que nomeia um
   settlement, e o que não conta é negativo enquanto a mensagem de motivo lá
   está, por extenso.
3. **O controlo positivo já existia e foi referenciado, não duplicado**:
   `verified_external_settlement_promotes_rv0` (`lib.rs:1539`), que continua a
   ser a prova de que a vista não está apenas a recusar tudo.

**Prova que carrega peso:** duas mutações revertidas falham estes testes. Uma
que confiasse nos booleanos armazenados, e outra que partisse o `prev_hash`
forjado. Um teste que passa com a mutação também aplicada não é evidência de
nada.

### Propriedades de segurança verificadas

Verificadas por **leitura de código**, numa passagem independente. Cada linha
desta lista é uma afirmação sobre o código, não sobre a intenção:

- **Nenhum caminho económico lê `proof_verified`.**
  `counts_as_external_value` (`autonomy.rs:235`) continua no código, mas toda a
  sua cadeia de chamadas de produção está **morta**:
  `positive_external_value` (`autonomy.rs:242`) é chamada só por um teste
  (`autonomy.rs:1338`), e `counts_as_external_value` só por ela
  (`autonomy.rs:243`) e por um teste de fronteira (`boundary.rs:1217`).
  `counts_as_paid_demand` (`lib.rs:176`) é chamada em dois sítios, ambos dentro
  de `append_settlement` (`lib.rs:701` e `:725`) — o caminho de **escrita**, onde
  confiar no flag torna a validação **mais estrita**, não mais solta: um
  settlement externo tem de citar um intent de pagamento que existe, com bloco
  posterior à âncora, e o valor tem de bater exactamente com o preço do job.
  Todas as outras leituras de booleanos armazenados são restritivas — forçam
  `false`, rejeitam, ou alimentam deteção de replay. O caminho de autoridade são
  **quatro portões**, nenhum deles booleano (`verified_view.rs:674`, `:679`,
  `:688`, `:763`).
- **`VerifiedNev` exige um provider identificado pelo kernel.** Exactamente um
  sítio de construção em todo o repositório (`verified_view.rs:507`); exige um
  verificador; o verificador exige `provider_identity_verified()`
  (`verified_view.rs:455`), que só é verdadeiro para um Unix socket — HTTP
  loopback é `false`.
- **O crate continua incapaz de transmitir.** A allowlist de seis métodos
  read-only está **inalterada** (`base_usdc.rs:399-404`), `eth_sendRawTransaction`
  é rejeitado, e `verifier_cannot_broadcast_even_against_a_pinned_provider`
  (`base_usdc.rs:769`) afirma que cinco métodos de escrita são recusados **e que
  nenhum pedido chegou ao provider**.
- **O endpoint de RPC não é definível a partir de `argv`.** Os cinco comandos de
  cadeia devolvem `RPC_ARG_REMOVED`, e
  `rpc_endpoint_as_positional_argument_is_refused_everywhere`
  (`tests/pinned_provider_cli.rs:134`) faz bind de um `TcpListener` real, passa o
  URL dele como posicional extra aos cinco, e afirma que o listener **nunca
  recebeu uma conexão** (`tests/pinned_provider_cli.rs:181-184`).
- **Um ledger falsificado dá autoridade zero** — agora coberto para ARV, RV e o
  orçamento de reinvestimento.

### Contagens e estado das execuções

Todas medidas, com código de saída. Nenhuma contagem aqui foi tirada de um
commit message, de um `| tee`, ou de uma execução sem `--no-fail-fast`.

| Comando | Exit | Resultado |
| --- | --- | --- |
| `cargo test --workspace --locked --no-fail-fast` | 0 | **491 passed / 0 failed / 1 ignored**, em 74 binários |
| o mesmo com `--features veil` | 0 | **498 passed / 0 failed / 1 ignored** |
| `cargo test -p mycelium-economy --locked --no-fail-fast` | 0 | **185 passed** (163 lib + 10 `ledger_durability` + 6 `pinned_provider_cli` + 6 `verified_view_cli`) |
| `cargo check --workspace --all-targets --locked` | 0 | 0 erros |

> **Atualização — a tabela acima foi medida ANTES de P4 e não foi remedida
> depois.** Os **491** e os **498** de workspace, e os **185** do crate
> `mycelium-economy`, descrevem a composição **até** P4. P4 acrescentou **133**
> testes ao crate, que passou a **318**. `cargo test --workspace
> --locked --no-fail-fast` **não** foi reexecutado depois de P4, e portanto
> **nenhuma contagem de workspace pós-P4 é publicada neste documento**. Um
> número inventado aqui seria pior do que um número ausente: ver "Verificação
> desta rodada" na rodada P4, onde se diz explicitamente que a contagem de
> workspace pós-P4 **não foi medida**. As afirmações de fundo da tabela — que o
> `--no-fail-fast` é obrigatório, que o delta de veil é +7, que o único teste
> ignorado é o pré-existente — continuam verdadeiras.

O delta de veil é exactamente **+7** (1 + 2 + 4), as mesmas três suítes de antes.
O único teste ignorado continua a ser o pré-existente
(`crates/mycelium-nostr/tests/mep_0_3_0_acceptance.rs:45`).

Os **185** do crate foram reconferidos por contagem de atributos, sem depender do
runner: `#[test]` em `crates/mycelium-economy/src/` soma **163** (11 `autonomy`,
11 `base_usdc`, 31 `boundary`, 14 `chain_provider`, 19 `durability`, 23 `lib`,
5 `mupp_adapter`, 5 `reinvestment`, 4 `s1_adapter`, 9 `s1_outcome`, 4
`s1_perception_adapter`, 5 `scaling`, 5 `terr_research`, 17 `verified_view`), e
os três binários de integração somam 10 + 6 + 6. Bate certo. Era **58** em P0 e
**130** em P2.

Concorrência, sem flakes: **20/20** sequencial, **64/64** concorrente
sobre-subscrito, **25/25** entre processos, **8/8** entre processos para o
binário de durabilidade.

Disco: **97 GB livres**, `target/` com **20 GB**.

**Clippy continua vermelho, e piorou em número.** **218 avisos distintos em 39
lints** (18 em `mycelium-economy`, 197 noutros crates). Topo: `uninlined_format_args`
101, `useless_format` 37, `ptr_arg` 10, `io_other_error` 9. A CI corre
`-D warnings` e **não pode passar**. **Nada foi corrigido** — é dívida, não verde.

### Correções metodológicas

As duas primeiras já estão registadas em "Metodologia de medição" e valem para
toda a leitura de números deste documento; não são repetidas aqui. As duas
seguintes são **novas** e ambas são da mesma família, o que é a razão de esta
subsecção existir: *um gate que reporta sucesso sem ter feito nada é pior do
que um gate que falha.*

1. **`cargo test` sem `--no-fail-fast`** para no primeiro binário que falha e
   esconde os seguintes. Medido aqui: **23 dos 40 binários** ficavam por trás de
   uma falha. Já registado.
2. **`cargo … | tee log` reporta o status do `tee`.** Já registado; um falso
   verde foi produzido por via disso. `${PIPESTATUS[0]}` é obrigatório. Já
   registado.
3. **Um `FILTER` de teste errado é da mesma classe de bug — e é a mais
   traiçoeira das quatro, porque não dá sinal nenhum.**
   `cargo test … concurrent_appends` sai com **0** sem executar **zero**
   testes: o teste real chama-se
   `concurrent_cli_appends_produce_one_valid_chain_without_duplicate_sequence`
   (`tests/ledger_durability.rs:171`). Um job de CI keyed num filtro que não
   casa com nada é uma operação nula silenciosa que reporta sucesso. Isto muda a forma como
   **qualquer** gate de teste futuro tem de ser escrito: o gate tem de afirmar o
   número de testes executados, não apenas o código de saída.
4. **Um flake latente de execução paralela foi encontrado e corrigido.**
   `s1_adapter.rs` chaveava o seu fixture de `/tmp` **só pelo hash de conteúdo**,
   pelo que dois binários de teste concorrentes sobrescreviam o fixture um do
   outro — **6 de 36 suítes paralelas** falhavam. Corrigido incluindo o pid no
   nome (`s1_adapter.rs:263-267`, com o porquê escrito no comentário acima). Não
   afeta `cargo test`, que corre os binários sequencialmente, mas morderia
   qualquer runner de testes paralelo futuro.

### Carrancas que permanecem abertas — registadas, não corrigidas

Cada uma destas está documentada no código que a contém. Estão aqui porque um
placar que só lista o que foi fechado é uma peça de marketing.

1. **O lock não abrange os "já existe?" de quem chama.** O doc de `verify_head`
   do ledger de receita (`lib.rs:805-814`) diz que o lock cobre a integridade da
   cadeia mas **não** as verificações de duplicação que correm antes de `append`
   ser alcançado: dois
   chamadores podem passar ambos a verificação de duplicação de
   `append_settlement` e ambos acrescentar. Cada append continua
   individualmente bem formado e encadeado, portanto é uma corrida
   check-then-act de **regra de negócio**, não uma falha de integridade do
   ledger. Fechá-la significa manter o lock atravessando todos os caminhos
   públicos de escrita, incluindo `commit_job` — uma **mudança semântica**, não
   um remendo.
2. **A sentinela `O_CREAT|O_EXCL` tem uma corrida residual**, declarada em
   `durability.rs:474-488`: dois reclaimers podem ambos concluir que o lock de um
   titular **morto** está obsoleto, e o `unlink` do perdedor pode cair depois da
   reivindicação do vencedor. Exige um titular que morreu sem correr `Drop`, dois
   reclaimers simultâneos, e o `unlink` do perdedor a cair dentro da janela do
   vencedor. **Não ocorre entre titulares vivos.** Fechá-la exige lock advisory do
   kernel — `flock(2)` / `fcntl(F_SETLK)` — que exige uma dependência nova.
3. **`geteuid(3)` está contornado por `/proc/self` em Linux**
   (`durability.rs:112-115`); não há verificação de propriedade nos outros Unix.
4. **O caminho tipado de P3 só admite INFLOWS**, porque só
   `ExternalToControlled` é `Creating` (`boundary.rs:334-340`). Logo uma
   **perda** externa continua não atestável, e ambas — ganho não atestado e
   perda não atestada — ficam **fora da base**. Isto é deliberado por agora e é
   um **ponto de decisão**, não um detalhe.
5. **`counts_as_external_value` e `counts_as_paid_demand` continuam a ler
   booleanos armazenados**, mas nenhum caminho económico os chama; permanecem no
   caminho de escrita e nos diagnósticos, onde é o sítio certo para eles.
6. **Com um provider pinado, quem controla o socket identificado pelo kernel
   controla a verdade.** É o limite que P2 declarava, e P3 nem o desfaz nem a
   sua natureza altera: o que P3 garante é que **esta** fonte, e não um booleano
   gravado, é a fonte da autoridade.
7. **`SyntheticAsset` não poder aparecer num `BoundaryCrossing` continua a ser
   uma garantia de tipo, não um teste de compile-fail `trybuild`**, e não existe
   tal harness no crate. Registado duas vezes porque é o tipo de afirmação que
   alguém vai querer promover a título de teste.

### Correção de citações: P3 e P5 deslocaram linhas de P0–P2

O documento diz, no topo, que as citações de linha se referem ao working tree na
data da escrita. P3 e P5 acrescentaram ~4.680 linhas — dois módulos novos
(1.460 + 2.390) e dois binários de integração novos (480 + 350) — e
**empurraram** um número de citações já escritas. Nenhuma foi apagada; a tabela abaixo é a correção. As
afirmações de fundo continuam verdadeiras — o que mudou foi o endereço, não o
conteúdo.

| Citado em P0–P2 | Onde está agora | O que é |
| --- | --- | --- |
| `autonomy.rs:307-315` (`computed_hash`) | `autonomy.rs:357-362` | a mesma função |
| `autonomy.rs:23` (génese) | `autonomy.rs:23` | **inalterado** |
| `autonomy.rs:332-379` (`records()`) | `autonomy.rs:394-426` | |
| `autonomy.rs:565` (`record_external_value`) | `autonomy.rs:686` | |
| `autonomy.rs:664` (`…_with_crossing`) | `autonomy.rs:785` | |
| `autonomy.rs:896-897` (limiar ARV4) | `verified_view.rs:584-585` | a tabela de níveis passou para a vista |
| `reinvestment.rs:68` (100 mUSD/dia) | `reinvestment.rs:83` | valor em `:83`, campo em `:73` |
| `reinvestment.rs:152` (`decide`) | `reinvestment.rs:245` | |
| `reinvestment.rs:267` (`commit_job`) | `reinvestment.rs:404` | |
| `reinvestment.rs:149` (ledger) | `reinvestment.rs:182` | const em `:35` |
| `boundary.rs:1258` (`crossing_rejects_a_class…`) | `boundary.rs:1284` | |
| `boundary.rs:854` (`synthetic_asset_cannot…`) | `boundary.rs:854` | **inalterado** |
| `boundary.rs:424` (`with_verified_proof`) | `boundary.rs:424` | **inalterado** — e continua a não olhar para `provider_identity_verified`, tal como P0–P2 registou |
| `lib.rs:148` (`settlement_asset`) | `lib.rs:152` | |
| `lib.rs:172` (`counts_as_paid_demand`) | `lib.rs:176` | `is_real()` em `:184` |
| `lib.rs:84,98,114,137,182,313` (`deny_unknown_fields`) | `lib.rs:194,88,102,118,141,367` | por nome: `LedgerRecord`, `JobRequest`, `WorkReceipt`, `PaymentIntent`, `SettlementReceipt`, `PaymentPolicy` |
| `autonomy.rs:48,63,103,128,197,278,292` | `autonomy.rs:342,328,107,132,201,52,67` | conjunto actual: 52, 67, 107, 132, 201, 328, 342 |
| `base_usdc.rs:395-410` (allowlist) | `base_usdc.rs:395-410` | **inalterado**; arms em `:399-404` |
| `base_usdc.rs:598` (`validate_hash32`) | `base_usdc.rs:598` | **inalterado** |
| `chain_provider.rs:29,173,188,204,210,260` | iguais | **inalterado** |
| `lib.rs:437` (glue do `resolve`) | `lib.rs:508` | |
| `lib.rs:326` (pin na policy) | `lib.rs:508` | mesma chamada |
| `bin:87-92` (`RPC_ARG_REMOVED`) | `bin:190` | |
| `bin:294,299,306,317,455` (arms) | `bin:401,406,413,424,611` | os mesmos cinco comandos |
| `bin:280`, `bin:441` (comandos de pin) | `bin:387`, `bin:597` | |
| `s1_outcome.rs:76`, `:249`, `:315-318`, `:642-646` | `:85`, `:137`, `:315-317`, `:462-465` | |

### O que esta rodada **não** mudou

Nada aqui move a lacuna de topologia. Nenhuma máquina a mais, nenhuma rede a
mais, nenhum inbound verificado, nenhuma contraparte. Os níveis (b), (c) e (d)
e o placar E6 0/9 estão exatamente onde estavam, e o valor externo liquidado
continua **zero**.

E o que P3 **não** faz é o limite honesto desta rodada: ele torna a autoridade
depender de evidência verificada, e isso é tudo. Ele não adiciona um byte de
cadeia externa, não assina nada, e não muda o facto de que um atacante do mesmo
principal que consiga escrever `~/.mycelium/economy/` **e** reescrever a
âncora de cabeça continua dentro do alcance do ledger. A frase
`ledger ≠ authority` passou a ser uma propriedade do sistema de tipos; a
**âncora externa** continua fora do âmbito, e é ela que só uma fase futura
entrega.

## Rodada P4: política autenticada, receipts assinados, e a receita estava sem assinatura

O que vem a seguir também não acrescenta nenhum host, nenhuma rede, nenhum
inbound verificado e nenhuma contraparte. **Os níveis (b), (c) e (d) continuam
NÃO SUSTENTADOS e o placar E6 continua 0/9, sem uma única linha alterada na
secção de E6. NEV continua 0 e o valor externo criado continua 0.** P4 é
integidade e autoridade: liga uma **fonte de identidade externa** a tudo o que
até P3 re-derivava de evidência. Nenhum byte de valor foi criado aqui.

São três fases deliveries porque a primeira tentativa excedeu o tempo e foi
dividida: **P4a** (âncora pinada + política assinada), **P4b** (wrapper de
receipt autenticado), **P4c** (o lado da receita, que estava **sem
assinatura**), e **P4d**, que é uma correcção de CLI encontrada por P4c e que
sem ela tornaria P4b e P4c inalcançáveis pela linha de comando.

### P4a — âncora de confiança pinada e política assinada

Novo módulo `crates/mycelium-economy/src/policy_auth.rs` (3.018 linhas, 55
atributos `#[test]`).

**Dois papéis de chave, nunca uma chave para os dois.** `PolicyAuthorityKey`
(`policy_auth.rs:461`) assina políticas; `VerifierRuntimeKey`
(`policy_auth.rs:552`) assina atestações. O papel viaja **dentro do `KeyId`**,
não em metadata externa, para que não haja uma chave que assine política e
atestação com a mesma identidade.

**A âncora de confiança está fora do directório mutável da economia.**
`/etc/mycelium/trust/policy-authority.pub` é o caminho de pin por omissão
(`policy_auth.rs:99`). E neste host esse caminho **não é criável**: uid 1000 e
`mkdir: cannot create directory '/etc/mycelium': Permissão negada`; verificado
agora de forma independente, `/etc/mycelium` está **ausente** e o processo corre
como uid 1000. Logo o caminho é configurável e, na sua ausência ou face a uma
validação falhada, a política fica **UNATTESTED** e tudo falha fechado. **Não
há fallback para dentro de `~/.mycelium/economy/`** — esse directório é a
fronteira de entrada não confiável e o ledger de atestações vive lá.

> **Atualização — esta frase deixou de ser verdadeira em P4d, e é preciso
> dizer exactamente em que.** P4a eliminou o override *do pin sozinho* e o
> fallback para o directório mutável. P4d introduziu
> `MYCELIUM_TRUST_ROOT_DIR`, que desloca a **âncora de pin** — e a chave de
> assinatura, inseparavelmente. Portanto **hoje existe uma variável de ambiente
> que muda onde a âncora de confiança é lida**. A defesa que sobrevive é mais
> estreita e é a que está escrita: a variável move **as duas metades juntas**,
> nunca uma só; recusar por omissão é o default; e `trust_root_relocated`
> aparece em **todos** os relatórios de confiança em vez de ser inferido de um
> caminho. Isto é uma escalação de exposição declarada, não um
> desaparecimento dela — e o seu custo está registado na lista de carranças
> desta rodada, item 1.

**Validação em dois estágios.** `lstat` sobre o caminho (recusa symlink,
exige ficheiro regular, `mode & 0o022 == 0`, `uid ==` dono configurado, tecto de
256 bytes), depois `fstat` sobre o descritor aberto, re-verificando tipo, modo e
uid (`policy_auth.rs:1336-1339`). O segundo estágio fecha a corrida
`lstat`→`open` que `chain_provider` deixa aberta, porque `open(2)` **segue
symlinks**.

**A regra central é imposta e testada: a chave que autoriza uma política NÃO
está dentro da política.** `the_gland_trap_a_self_signed_policy_is_rejected`
(`policy_auth.rs:2188`) constrói uma política que embute uma pubkey e é
validamente assinada por essa mesma chave, e ela é recusada com
`AuthorityNotPinned` (`policy_auth.rs:172`). É a diferença para o padrão
`Gland` do próprio projecto: em `crates/mycelium-pheromones/src/lib.rs:149-151`,
`PheromoneBody` transporta `pub identity: [u8; 32]` — a chave pública do
emissor — **dentro do corpo assinado**, e portanto a chave verificadora viaja
com a mensagem que ela própria autentica. O teste do receptor continua a passar
em `mycelium-pheromones`; o que muda é que em `mycelium-economy` uma chave
assim **não autoriza nada**.

**O preimage é bytes determinísticos, nunca JSON.** `push_tagged`
(`policy_auth.rs:1624`) emite `LEN:u32be ‖ TAG ‖ LEN:u32be ‖ VALUE`, sob o
domínio `MYCELIUM-ECONOMY/POLICY/V1` (`policy_auth.rs:116`), com 10 secções
numa tabela de fonte única (`POLICY_PREIMAGE_FIELDS`,
`policy_auth.rs`, 10 entradas). A justificação está escrita no código e vale
por si: assinar uma forma serializada converte ordem de campos, espaços em
branco, campos desconhecidos e qualquer mudança futura de serializador em
**semântica criptográfica**. É testado com uma asserção de layout byte a byte,
com independência de ordem, com sensibilidade à ordem das secções e com um
teste de ambiguidade de concatenação por prefixo de comprimento.

**`controlled_registry_hash`** (`policy_auth.rs:720`) percorre o **conteúdo**
do registry — não uma contagem — e recolhe-o num `BTreeSet`, de modo que a
ordem de inserção não pode preservar o digest, sob o domínio
`MYCELIUM-ECONOMY/CONTROLLED-REGISTRY/V1` (`policy_auth.rs:119`). Mudar
qualquer endereço controlado invalida a política.
`provider_identity_hash` (`policy_auth.rs:802`) faz o mesmo sobre
`ProviderIdentityConstraints { transport, endpoint, socket_owner_uid }`
(`policy_auth.rs:748`) — logo uma política assinada para um Unix socket
verificado pelo kernel **não** pode ser satisfeita por uma porta TCP de
loopback que responda igualmente bem.

**Ordem de validação, 9 verificações**, documentada no próprio código
(`policy_auth.rs:1490-1499`): versão de schema → separação de papéis →
reconstrução do preimage → **a autoridade resolve-se a partir do pin** → a
assinatura verifica contra essa chave pinada → `chain_id` → `min_confirmations`
→ hash do registry vivo → hash de identidade do provider.

### P4b — wrapper de receipt autenticado

Novo módulo `crates/mycelium-economy/src/receipt_auth.rs` (1.802 linhas, 17
atributos `#[test]` próprios).

`AuthenticatedExternalValueReceipt { receipt, policy_hash, verifier_key_id,
attestation_hash, signature }` (`receipt_auth.rs:518`) — cinco campos privados,
sem construtor público, e **`verify()` não recebe parâmetro de chave**
(`receipt_auth.rs:590`): recebe um `&ValidatedOutcomePolicy` e chama
`trusted_verifier()` internamente. Um chamador não pode fornecer uma chave, não
pode oferecer uma `VerifierPublicKey` lida de uma política não validada, e não
pode sequer nomear o tipo `dalek`.

`VerifierPublicKey::verifying_key()` passou a `privado` em `policy_auth`; o
único `VerifyingKey` alcançável é `TrustedVerifierKey::verifying_key()`
(`pub(crate)`, `policy_auth.rs:1150`), e um `TrustedVerifierKey` tem
**exactamente um** construtor. A armadilha `Gland` um nível abaixo está fechada
e testada por
`the_verifying_key_is_not_reachable_outside_a_validated_policy`
(`receipt_auth.rs:1149`).

**Preimage da atestação:** domínio `MYCELIUM-ECONOMY/EXTERNAL-VALUE/V1`
(`receipt_auth.rs:110`), **13 secções**
(`ATTESTATION_PREIMAGE_FIELDS`, `receipt_auth.rs:290-303`), reusando o encoder de
P4a, para que uma assinatura de receipt e uma de política partilhem uma
disciplina só. Duas adições para além do óbvio:

- **`verifier_key_id`** — um receipt não pode ser re-assinado sob outra chave
  delegada.
- **`receipt_hash`** — `blake3` sobre **todos** os campos do receipt
  (`RECEIPT_HASH_FIELDS`, `receipt_auth.rs:192-206`). É isto que impede uma
  assinatura de ser reapontada para uma economia inflada.
- **`asset`** transporta o contrato **normalizado**, não o símbolo armazenado,
  porque `usdc` e `USDC` seriam de outro modo duas mensagens diferentes.

**`provider_identity_verified` passou a portão obrigatório.** P2 criou-o e
ninguém o consumia; P4 tornou-o obrigatório, com um
`AttestationGap::ProviderIdentityUnverified` dedicado
(`verified_view.rs:222`, emitido em `verified_view.rs:1104`).

**`policy_hash` liga o receipt à política:** `receipt.policy_hash ==
H(política validada corrente)`, senão unattested
(`AttestationGap::PolicyHashMismatch`, `verified_view.rs:214`). A história de
rotação de políticas está deliberadamente fora de âmbito — ver item 2 das
carranças desta rodada.

**A ordem de portões de P3 foi preservada, não substituída.** A identidade que
o código executa é agora
`VerifiedNev = VerifyChain(DeriveBoundary(VerifyReceiptSig(VerifyPolicy(Evidence))))`
(`verified_view.rs:7`) — a assinatura de receipt foi **inserida** entre
`VerifyPolicy` e `DeriveBoundary`, e não posta no lugar da leitura de cadeia. Uma
correcção de ordem merece registo: **a derivação da fronteira tem de vir ANTES
da leitura de cadeia**, porque `verify_transfer` consome o crossing derivado
`(tx, payee, amount)`. A string de identidade já o tinha nesta ordem; o código
tinha de o fazer. Dois testes de P3 foram **reforçados**, não afrouxados —
notadamente `a_forged_ledger_is_still_rejected_when_a_provider_is_pinned`
(`verified_view.rs:2373`), que passou a assinar a falsificação com a chave
**delegada** e continua a afirmar `ChainNotConfirmed`, para que a leitura de
cadeia permaneça o **único** predicado a falhar.

### P4c — a receita estava sem assinatura, e a assimetria está fechada

**Este foi o achado mais importante da rodada, e não é um detalhe de
engenharia.** P4b deixou `SettlementReceipt` por assinar: uma parte que conseguisse
escrever o ledger de receita **e** produzir uma transferência on-chain real do
tamanho certo para um endereço controlado podia lançar **RV0 que nenhum
verificador alguma vez atestou**. O lado da autonomia exigia assinatura; o lado
da receita não exigia. Essa assimetria era a lacuna.

Novo módulo `crates/mycelium-economy/src/settlement_auth.rs` (2.004 linhas, 15
atributos `#[test]`). `AuthenticatedSettlementReceipt` (`settlement_auth.rs:716`)
espelha o wrapper do receipt: cinco campos privados e um único construtor,
`VerifierRuntimeKey::attest_settlement(&ValidatedOutcomePolicy,
&SettlementReceipt, &PaymentIntent)` (`settlement_auth.rs:898`), que recusa a
menos que a chave que assina **seja** a chave a que a política validada
delegou. `verify()` não recebe chave.

Preimage: domínio `MYCELIUM-ECONOMY/SETTLEMENT/V1`
(`settlement_auth.rs:154`), **14 secções**, incluindo `anchor_block`,
`anchor_block_hash` e `settlement_hash` (digest canónico sobre os 15 campos do
receipt, `SETTLEMENT_HASH_FIELDS`, `settlement_auth.rs:259-274`).
**O formato de wire de `SettlementReceipt` está INALTERADO** — nenhum campo
novo — logo os ledgers antigos re-serializam byte a byte.

**A separação de domínios é provada, não afirmada.**
`a_settlement_signature_cannot_be_replayed_as_a_receipt_signature`
(`settlement_auth.rs:1365`) usa **a mesma chave e os mesmos factos de cadeia**
dos dois lados e mostra que os preimages diferem, que cada um transporta
apenas o seu domínio, que nenhuma assinatura verifica sobre a mensagem da outra
e que **re-rotular as secções do settlement sob o domínio do receipt continua a
falhar**.

`an_unsigned_settlement_with_a_real_transfer_does_not_reach_paid_demand`
(`verified_view.rs:4247`) é o teste de regressão: uma transferência **REAL**
servida pelo provider identificado pelo kernel, **por assinar**, dá PRE-RV0,
demanda paga 0, valor declarado 5,0, e a leitura de cadeia **nunca é alcançada**.
O controlo positivo corre no **mesmo fixture** a seguir, para que o braço
negativo não possa passar de forma vazia.

**A questão do AMOUNT foi decidida explicitamente:** a atestação **não**
afirma a relação de valores. Liga a **identidade** dos números (`amount_raw` = o
valor exacto on-chain do intent; `settlement_hash` = as figuras próprias do
ledger), **não** `net == on-chain`. A regra
`usd_equivalent_micros == intent.exact_amount_raw` permanece em
`rederive_settlement` como `AmountNotJustified`. O raciocínio, registado porque
é o tipo de decisão que alguém vai querer refazer: essa é uma predicado sobre
**dois registos de ledger que só o LEITOR pode ver**; aritmética dentro de uma
assinatura é aritmética que um **SIGNANTE** pode errar, e um bug do signante
torna-se uma regra de promoção.

**Seis testes pré-existentes tiveram de ser REPARADOS, não apenas
reeexecutados**, porque afirmavam promoção de RV0 a partir de settlements não
assinados. Registado com honestidade: apertar uma fronteira de confiança
invalida legitimamente testes que codificavam o comportamento antigo. Um deles
foi assinado especificamente para que a leitura de cadeia permanecesse o único
predicado em falha.

### P4d — a CLI não conseguia assinar, e a política não validava por ela

O implementador de P4c reportou, correctamente, que `settle-base-usdc` produzia
settlements **sempre** unattested: nenhum comando alcançava o caminho de
assinatura. A investigação encontrou uma metade **pior**: `load_outcome_policy`
(`bin/mycelium-economy.rs:91`) tinha `TrustStoreConfig::system_default()`
hardcoded, com o pin em `/etc/mycelium/trust` pertencente a uid 0 — não
criável e não configurável neste host —, portanto **nenhuma política de
resultado conseguia validar através da CLI**. Não era só a assinatura: todo o
modo de leitura `ProviderPinned` de P4b era **inalcançável pela CLI**.

Novo módulo `crates/mycelium-economy/src/verifier_key_store.rs` (778 linhas, 12
atributos `#[test]`) e novo teste de integração
`crates/mycelium-economy/tests/signing_cli.rs` (1.116 linhas, 13 testes).

**Uma única raiz de confiança segura as duas metades:** o pin da autoridade **e**
a chave de assinatura do verificador (`verifier-runtime.key`, modo `0400`, a
mesma gramática de três linhas). Por omissão `/etc/mycelium/trust` (uid 0) ou
`MYCELIUM_TRUST_ROOT_DIR` (`verifier_key_store.rs:88,91,101`). **Não podem ser
configuradas em separado** — um teste afirma que partilham um mesmo pai. O
raciocínio, registado porque é uma recusa de desenho e não uma escolha: uma
variável de ambiente ou um argumento de CLI **só para a chave** foi rejeitado
porque cria uma segunda âncora de confiança com o seu próprio ciclo de vida, e
um argumento é exactamente a forma que P4a removeu quando matou
`RPC_ARG_REMOVED`; reutilizar a área da política foi rejeitado porque
`~/.mycelium/economy/` **é** a fronteira de entrada não confiável e o ledger de
atestações vive lá. Ligar a chave ao pin significa que uma chave plantada em
qualquer caminho legível é **inerte** enquanto nenhuma política validada a
delegar — e isso exige substituir o pin **e** servir uma política assinada por
uma chave privada de autoridade que não está no repositório.

**Recusa por omissão:** sem opt-in, a assinatura recusa em `/etc/…`. Definir
`MYCELIUM_TRUST_ROOT_DIR` **é** o opt-in, e `trust_root_relocated` aparece em
todos os relatórios de confiança em vez de ser inferido de um caminho.

**Fluxo de dois passos, deliberado.** `settle-base-usdc` verifica e regista;
`settlement-attest` assina. Continuam auditáveis de forma independente
(ficheiros encadeados separados, timestamps separados — "verificado à segunda,
assinado à terça depois de uma rotação" é um evento normal), um provider
comprometido não consegue exercer a chave do operador, e uma chave em falta
deixa a confirmação de pagamento no ledger **não assinada, com o motivo** em vez
de a perder. `settle-base-usdc` devolve agora
`attestation: { signed: false, reason, next_command, signing_key }`
(`bin/mycelium-economy.rs:1605-1616`) para que o fluxo de dois passos seja
descobrível e não uma armadilha.

Comandos novos (`bin/mycelium-economy.rs:388-390`, dispatch em `:682-693`):
`settlement-attest SETTLEMENT_ID`, `receipt-attest SOURCE_ID` e
`verifier-key-show` (só leitura, **nunca** imprime bytes secrets). O
endereçamento é por **chave de ledger**, não por job, porque um job pode ter
vários settlements e ambiguidade não é aceitável.

**Fail-closed em três camadas.** `EconomyViews::signing_key()`
(`bin/mycelium-economy.rs:356`) é o único portão por que passam os dois comandos
que assinam: sem política validada devolve `Err` **antes de qualquer ficheiro
ser lido**. Uma verificação ao nível da biblioteca recusa uma chave que não é a
delegada, para que nenhum chamador a possa contornar. E a identidade do ficheiro
é absoluta, sem symlink, ficheiro regular, tecto de tamanho,
`mode & 0o077 == 0`, uid esperado, gramática exacta e papel fixado — com `lstat`
e depois `fstat` sobre o descritor aberto
(`verifier_key_store.rs:524`). `install` usa `create_new` e **nunca** roda a
chave no lugar.

### Verificação desta rodada

| Comando | Exit | Resultado |
| --- | --- | --- |
| `cargo test -p mycelium-economy --locked --no-fail-fast` | 0 | **318 passed** |
| `cargo check --workspace --all-targets --locked` | 0 | 0 erros, **0 warnings** |

Composição dos 318, reconferida por contagem de atributos e não só pelo runner:
**282** em `crates/mycelium-economy/src/` e **36** nos quatro binários de
integração (`tests/ledger_durability.rs` 10, `tests/pinned_provider_cli.rs` 6,
`tests/verified_view_cli.rs` 7, `tests/signing_cli.rs` 13). Delta do crate:
**185 → 318**, isto é **+133**, dos quais **99** em quatro módulos novos
(`policy_auth.rs` 55, `receipt_auth.rs` 17, `settlement_auth.rs` 15,
`verifier_key_store.rs` 12), **13** em `tests/signing_cli.rs` e **21**
distribuídos por módulos que já existiam (`verified_view.rs` +17, `lib.rs` +3,
`tests/verified_view_cli.rs` +1).

> **Nota sobre o `270 lib` que circula nesta rodada.** Esse número é a leitura
> **intermediária** da fase P4b, não a final. A contagem final de lib é **282**,
> e 282 + 36 = **318**. Quem citar `270 lib` junto com os números de integração
> finais está a misturar duas medições.

> **O que NÃO foi medido depois de P4, e por isso não é publicado aqui:** as
> contagens de workspace **491/0/1** e **498/0/1** da rodada P3/P5 foram medidas
> **antes** de P4 e **não** foram remedidas. Com 133 testes novos, elas não são
> o estado atual do workspace e este documento **não** as actualiza nem inventa
> um número novo. Um placar que publica uma contagem de workspace que sabe estar
> velha é exactamente o defeito que este documento recusa; a leitura correcta é:
> contagem do workspace = **não medida nesta rodada**; contagem do crate
> `mycelium-economy` = **318**, medida.

Disco: **~91 GB livres**.

**Clippy continua vermelho.** Nada nesta rodada o tocou. A dívida medida antes
(218 avisos em 39 lints) é o que se sabe; o passo `-D warnings` da CI
**não pode passar** e é o bloqueio concreto e nomeado da CI. Registado como
dívida, não como verde.

### Gate de CI que não pode passar por não correr nada

Novo `scripts/ci-test-gate.sh` (331 linhas), ligado tanto a `.woodpecker.yml`
como a `.forgejo/workflows/validate.yml`. Existe por causa de **três modos de
falso-verde verificados**, todos da mesma classe — o comando tem sucesso
enquanto aquilo que se queria verificar não aconteceu:

1. `cargo test` sem `--no-fail-fast` para no primeiro binário de teste que
   falha e esconde os seguintes; já registado em "Metodologia de medição", onde
   se mediu **23 dos 40 binários** por trás da falha.
2. Pipar a saída do cargo para `tee` reporta o **exit status do `tee`**;
   `${PIPESTATUS[0]}` é obrigatório.
3. **Um filtro de teste que não casa com nada sai com 0 tendo executado zero
   testes.** Demonstrado concretamente neste repositório:
   `cargo test … concurrent_appends` passa de forma vazia, porque o teste real
   chama-se `concurrent_cli_appends_produce_one_valid_chain_without_duplicate_sequence`
   (`tests/ledger_durability.rs:171`). Um job de CI keyed num filtro errado é uma
   operação nula silenciosa que reporta sucesso.

O gate obtém o status real do cargo por `PIPESTATUS`, acrescenta sempre
`--no-fail-fast` sem nunca o duplicar, detecta um **TOTAL** de zero testes
executados (exit 2, "VACUOUS PASS"), impõe um piso `--min-tests` opcional e
suporta `--expect-test` para afirmar que uma suite ou teste nomeado **realmente
executou** (exit 4).

> **Por que o zero é conferido no TOTAL e nunca por binário.** Existem
> componentes com zero teste legítimos, e isso foi verificado numa execução real:
> `unittests src/bin/mycelium-economy.rs` reporta honestamente `running 0 tests`
> ao lado de 185 outros que passaram. Um gate que reprovasse por binário seria
> reprovar a verdade.

Pisos por job: workspace **450** (medido 491), veil **450** com três
`--expect-test` para as suites do veil (medido 498, delta exactamente +7),
economy **170** (medido 185 e depois 318), gate-a **3**, gate-b **1**. Os pisos
são postos deliberadamente **abaixo** da medição: apanham perda catastrófica
sem oscilar.

**Nada foi enfraquecido.** Os 7 pipelines do Woodpecker e os 10 passos do
Forgejo mantiveram o seu estado bloqueante / `allow_failure`; `gate-a` e `gate-b`
continuam bloqueantes; feature-matrix e `fmt` continuam não bloqueantes; o par
`rust:slim` com `@master` e `toolchain: "1.88.0"` foi preservado — a troca de
`@stable` fora deliberada e já feita, porque `@stable` **ignora** o input de
toolchain. `--locked` foi acrescentado às invocações que não o tinham.

### Carrancas que permanecem abertas — registadas, não corrigidas

Cada uma está documentada no código que a contém. Um placar que só lista o que
foi fechado é uma peça de marketing.

1. **Uma raiz de confiança relocalizada é um directório que o principal
   invocante controla.** Quem conseguir escrever nela pode substituir o pin **e**
   a chave de assinatura e servir uma política auto-assinada, e a CLI assina
   para essa pessoa. **Não é uma classe nova** — o lado de leitura tem a
   exposição idêntica desde P4a — mas prender a chave **privada** ao mesmo
   directório **alarga o que uma substituição bem sucedida compra**.
2. **Sem história de rotação de políticas.** Um receipt ou settlement emitido
   sob a política A é recusado sob a política B, **permanentemente** (rotação
   está fora de âmbito por desenho, `policy_auth.rs` e
   `AttestationGap::PolicyHashMismatch`). Não há lista de revogação nem marca de
   água alta de `policy_version`. Uma política previamente válida continua aceite
   enquanto corresponder ao registry e ao provider vivos.
3. **Substituição do pin e do binário pelo mesmo principal está fora do modelo
   de ameaça fechado** — documentada em `policy_auth.rs`, não defendida.
4. **Sem protecção de rollback** nos ledgers de atestação: um atacante que
   consiga escrever o ledger **e** a sua âncora de cabeça reescreve a história.
   Só uma âncora externa — TPM, segundo host, quórum, log de transparência —
   fecha isso, e nenhuma está disponível sem dependência externa **e**
   contraparte externa.
5. **`AttestationGap::ProviderIdentityUnverified` é hoje INALCANÇÁVEL pela API
   pública.** `provider_pinned` recusa antes, e o campo é imutável. É defesa em
   profundidade, não um caminho vivo; **nenhum teste o alcança e nenhum foi
   falsificado para parecer que sim.**
6. **`AttestationReplayed` só pára duplicados dentro de uma leitura.** Nada liga
   uma atestação a uma sequência de ledger, portanto um registo atestado
   duplicado promove **uma vez por arranque de processo**.
7. **`AttestationIndex::build` salta em silêncio uma atestação cujo receipt
   embutido não seja digerível** — reportada como *não assinada* em vez de
   *malformada*, um diagnóstico mais grosseiro.
8. **Uma chave de assinatura delegada pode assinar qualquer coisa sobre a
   evidência que lhe é entregue**, incluindo uma transação fabricada. **Por
   desenho** — a leitura de cadeia é o portão que prova que o verificador leu
   mesmo a cadeia. A assinatura prova proveniência, não
   existência.
9. **`anchor_block_hash` está ligado, não é o hash do bloco CONFIRMADO.** Ligar
   o confirmado exigiria mover o portão de assinatura para depois da leitura de
   cadeia e quebrar a paridade com a sequência de autonomia. A altura é
   re-verificada contra o provider no momento da leitura.
10. **Nem `SettlementReceipt` nem `PaymentIntent` registam um pagador.** Qualquer
    pessoa pode pagar o endereço controlado — igualmente verdade antes deste
    trabalho.
11. **A assimetria que P4c fechou era só de ENTRADAS.**
    `BoundaryCrossing` deriva `ExternalToControlled` como +valor, mas ainda não
    existe um `ControlledToExternal` = −valor simétrico, portanto **uma perda
    externa continua impossível de atestar**.     `NEV = ΣVerifiedInflows −
    ΣVerifiedOutflows` **não é ainda computável**. Este é o próximo item
    concreto depois de P4, e está escrito como tal em "Próximo gate".

    > **Atualização — este item deixou de ser verdade, e é a falsificação mais
    > substancial que P4.5 produziu.** A afirmação acima descreve o estado
    > **até** P4.5 e fica aqui como registo. Hoje, `BoundaryDirection` tem os
    > **dois** sentidos (`boundary.rs:335-340`), `ControlledToExternal` deriva
    > `−valor`, e `NEV = ΣVerifiedInflows − ΣVerifiedOutflows` **é computável**:
    > o arbitrage de dois sinais soma `80_000` micros e promove
    > (`settlement.rs:1841-1949`). Duas ressalvas, e nenhuma delas é
    > atenuação: (a) a soma só existe **sobre uma operação completa**, decidida
    > contra uma enumeração da cadeia — uma perna isolada não produz número
    > nenhum; (b) **nenhuma operação real de produção é hoje promotevel**,
    > porque toda transacção real na Base queima gas e uma operação com gas não
    > tem valor comparável sem evidência de preço (carranca 1 da rodada P4.5).
    > Portanto a simetria deixou de ser o item bloqueante **e** continua a não
    > ser o item seguinte: o item seguinte é o outro, o preço.

### Correção de citações: P4 deslocou linhas de P3/P5 (e uma de P3 ficou errada)

O documento diz, no topo, que as citações de linha se referem ao working tree na
data da escrita. P4 acrescenta ~9.049 linhas — quatro módulos novos (3.018 +
1.802 + 2.004 + 778), um binário de integração novo (1.116) e um script de CI
(331) — e **empurrou** citações já escritas. Nenhuma foi apagada; a tabela é a
correção. As afirmações de fundo continuam verdadeiras — o que mudou foi o
endereço, não o conteúdo.

**Uma citação de P3 ficou errada por substance, não por deslocamento**, e é a
primeira a corrigir:

| Citado em P3 | Onde está agora | O que é |
| --- | --- | --- |
| `TrustedNEV = VerifyChain(VerifyPolicy(DeriveBoundary(Evidence)))` (blocoquoted na secção P3) | `VerifiedNev = VerifyChain(DeriveBoundary(VerifyReceiptSig(VerifyPolicy(Evidence))))` (`verified_view.rs:7`) | **a identidade ganhou um passo** — `VerifyReceiptSig` foi inserido por P4b **entre** `VerifyPolicy` e `DeriveBoundary`. Não é uma reordenação: a assinatura de receipt é uma etapa nova, e a leitura de cadeia **continua a ser o passo mais externo**, o que é o que a propriedade de P3 exige. O blocoquoted antigo acima fica como registo do estado até P4b |

> **Atualização — o blocoquoted da secção P3 que reproduz a identidade de
> verificação ficou desatualizado por P4b, e é corrigido aqui em vez de ser
> apagado.** O texto original ("`TrustedNEV = VerifyChain(VerifyPolicy(
> DeriveBoundary(Evidence)))`") descrevia o estado **até** P4b. O que o código
> executa hoje é o da tabela acima, e a frase "Isto é a mesma identidade que
> 'Próximo gate' já anunciava" continua a ser verdade no que structuralmente
> importa — `VerifyPolicy` deixou de ser uma palavra por escrever.

Deslocamentos verificados:

| Citado em P3/P5 | Onde está agora | O que é |
| --- | --- | --- |
| `verified_view.rs:424` (`VerifiedEconomyView`) | `verified_view.rs:655` | |
| `verified_view.rs:910` (`VerifiedRevenueView`) | `verified_view.rs:1473` | |
| `verified_view.rs:260` (`UnattestedNev`) | `verified_view.rs:385` (construção em `:786`) | |
| `verified_view.rs:286` (`VerifiedNev` sob `ProviderPinned`) | `verified_view.rs:412` (construção em `:762`) | |
| `verified_view.rs:455` (`provider_identity_verified` no gate) | `verified_view.rs:444` | `provider_pinned` passou a `:691` |
| `verified_view.rs:455-464` (recusa de endpoint sem identidade) | `verified_view.rs:691-710` | |
| `verified_view.rs:507` (único sítio de construção de `VerifiedNev`) | `verified_view.rs:762` | continua a ser **um só**, como P3 afirmou |
| `verified_view.rs:160` (`ChainNotConfirmed`) | `verified_view.rs:233` | `SettlementGap::ChainNotConfirmed` em `:488` |
| `verified_view.rs:674,679,688,763` (os quatro portões) | `verified_view.rs:740-770` (`verified_nev`) | os quatro portões **continuam quatro**; o quinto, `VerifyReceiptSig`, foi acrescentado por P4b |
| `verified_view.rs:772` (quarto portão, na nota de actualização de P0–P2) | `verified_view.rs:748-756` | a recusa por falta de política validada |
| `verified_view.rs:763-807` (leitura de cadeia) | `verified_view.rs:740-775` | |
| `verified_view.rs:1531`, `:1571` (falsificação ARV / orçamento) | `verified_view.rs:2294`, `verified_view.rs:2246` | |
| `verified_view.rs:1648` (secção "1b") | `verified_view.rs:2629` | |
| `verified_view.rs:1872`, `:1982` (falsificação RV) | `verified_view.rs:2665`, `verified_view.rs:2780` | |
| `verified_view.rs:2094` (`a_provider_without_a_kernel_identity…`) | `verified_view.rs:2936` | |
| `verified_view.rs:2353` (ledger pré-P3 ainda desserializa) | `verified_view.rs:3235` | |
| `autonomy.rs:394-426` (`records()`) | `autonomy.rs:485-517` | |
| `autonomy.rs:686` (`record_external_value`) | `autonomy.rs:777` | |
| `autonomy.rs:785` (`…_with_crossing`) | `autonomy.rs:1021` | |
| `autonomy.rs:934` (`summary`) | `autonomy.rs:1170` | |
| `autonomy.rs:1033` (`arv_status`) | `autonomy.rs:1269` | |
| `autonomy.rs:1158` (`revalidate_external_value`) | `autonomy.rs:1394` | invariante `gross − cost` em `:1407-1413`, não `:1171-1178` |
| `lib.rs:900` (`revenue_summary`) | `lib.rs:904` | |
| `lib.rs:956` (`rv_status`) | `lib.rs:960` | |
| `reinvestment.rs:245,261,404,421` | iguais | **inalterado** |
| `boundary.rs:151,160,234,288,385,424,854,1284` | iguais | **inalterado** — `with_verified_proof` continua em `:424` |
| `s1_outcome.rs:85,137,315-317,462-465` | iguais | **inalterado** |
| `bin:190` (`RPC_ARG_REMOVED`) | `bin:429` | arms em `:652,653,658,661,669,672` |
| `bin:387`, `bin:597` (comandos de pin) | `bin:626`, `bin:864` | |
| `s1_adapter.rs:263-267` (pid no fixture) | inalterado | |

### O que esta rodada **não** mudou

Nada aqui move a lacuna de topologia. Nenhuma máquina a mais, nenhuma rede a
mais, nenhum inbound verificado, nenhuma contraparte.

**Estado a registar sem atenuação: NEV = 0 · valor externo criado = 0 · E6 =
0/9 · níveis (b), (c) e (d) NÃO SUSTENTADOS.** Cada porção de-integridade
obtida em P0–P4 é **integridade e autoridade, não geração económica**. P4 liga
uma identidade externa a uma política e a atestações; **não cria valor, não
liquida valor, e não aproxima `ARV0` de passar** — passar exige valor externo
atestado, e a atestação que P4 tornou obrigatória é precisamente a que nenhum
ledger local consegue fabricar.

E o limite honesto desta rodada, escrito com o mesmo spirit de "não é âncora
externa" que P5 levava: **uma assinatura de verificador não é uma âncora
externa.** O ledger de atestações vive em `~/.mycelium/economy/`, sob o mesmo
uid que o pode reescrever; a chave é delegável por uma política que o pin
autoriza; e a política é aceite enquanto corresponder ao registry e ao provider
vivos, sem lista de revogação. P4 fecha *quem pode falar*, não *o que se pode
reescrever depois de falado*.

## Rodada P4.5: simetria de fronteira, identidade canónica de evento, e o custo nativo que este build não converte

O que vem a seguir também não acrescenta nenhum host, nenhuma rede, nenhum
inbound verificado e nenhuma contraparte. **Os níveis (b), (c) e (d) continuam
NÃO SUSTENTADOS e o placar E6 continua 0/9, sem uma única caixa marcada na
secção de E6. NEV = 0 e valor externo criado = 0.** Todo o P0–P4.5 é
**integridade e autoridade, não geração económica**: P4.5 torna a subtração
`inflows − outflows` *expressável e auditável*, e continua a não criar um único
micros de valor externo. É uma distinção que esta secção repete porque é
frequentemente o ponto em que um placar começa a mentir: a partir de P4.5c o
crate **consegue** somar uma perna de saída e uma de entrada, e **não o faz** —
somá-las exige uma operação **completa**, e nenhuma operação completa foi
produzida por um ledger real deste host.

Cinco entregas, e a ordem não é cosmética:

- **P4.5a** (`boundary_delta.rs`, 2.050 linhas) — `BoundaryDirection` nos dois
  sentidos, com o sinal derivado, e a promoção de uma perna isolada
  **estruturalmente impossível**.
- **P4.5b** (`event_id.rs`, 1.890 linhas) — identidade canónica do facto
  externo, e **idempotência económica** no lado da autonomia.
- **P4.5c** (`settlement.rs`, 3.196 linhas) — agregação por transacção,
  completude julgada contra uma enumeração da cadeia, e o predicado de promoção
  a viver só no settlement completo.
- **P4.5d** — custo nativo verificado, em wei, **sem conversão ETH/USD
  nenhuma**.
- **P4.5e** — a lacuna de desduplicação do lado da receita, que P4.5b reportou
  e não fechou.

O crate passou de 7.408 linhas (medição da baseline de remediação) para
**36.924** em `src/`, e de 318 para **390** testes.

### P4.5a — direcção de fronteira nos dois sentidos, derivada e não afirmada

`BoundaryDirection {ExternalToControlled, ControlledToExternal}`
(`boundary.rs:335`) é **Serialize-only**: o `derive` é
`#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]` (`boundary.rs:333`) e
**não há `Deserialize`** — a mesma disciplina, e pela mesma razão, que
`ControlDomain` (`boundary.rs:149-154`), cuja doc diz que um domínio que se
pode reler de um ficheiro é um domínio que um escritor pode afirmar.

**Um único caminho de construção em todo o crate**, e é uma cadeia de três
setas documentada em `boundary.rs:314-331`:

```text
BoundaryCrossing::derive(&evidence, &registry)        // lookup ao registry
  -> BoundaryCrossing::boundary_leg()                  // lê (from, to) derivados
    -> BoundaryLeg::of(ControlDomain, ControlDomain)   // PRIVADO (boundary.rs:427)
```

`BoundaryLeg::of` é privado ao módulo, portanto nenhum outro módulo do crate
constrói uma direcção a partir de dois domínios que inventou. O sinal vem de
`BoundaryDirection::sign()` (`boundary.rs:356-361`), que devolve `+1` / `−1`, e
que é **o único multiplicador de sinal em todo o crate**. `sign()` não recebe
montante e não devolve número: quem quiser um sinal sem magnitude chama
`nev_sign()` (`boundary.rs:346-351`), que devolve o enum fechado `NevSign` —
`ExternalToControlled → Positive`, `ControlledToExternal → Negative` — e portanto
não há nada ali para somar.

**O sinal nunca vem de JSON, e isso é testado em vez de descrito.**
`the_sign_cannot_be_supplied_or_overridden_by_a_caller`
(`boundary_delta.rs:894`) e
`boundary_direction_cannot_be_introduced_by_deserialization`
(`boundary_delta.rs:961`) fixam-no. O segundo teste é o que torna a primeira
afirmação verificável em vez de retórica: um bloco JSON não pode virar
`BoundaryDirection`.

**`External → External` é `BoundaryLeg::OutsidePerimeter` com
`nev_sign() == None`, e NÃO `Some(Zero)`.** `BoundaryLeg::nev_sign()`
(`boundary.rs:471-479`) dá `Some(NevSign::Zero)` para `InternalTransfer` e
`None` para `OutsidePerimeter`, e o raciocínio está escrito na própria função e
vale a pena ser repetido, porque é o tipo de decisão que um placar tem de
transportar sem a simplificar: **uma transferência interna É uma linha da tabela
de NEV que lê zero** (um endereço controlado participou, mesmo que o valor não
tenha saído do perímetro) **; uma transferência sem nenhum extremo controlado
está FORA da tabela.** Devolver `Zero` para as duas deixaria um caller somar uma
não-travessia num total e ler o resultado como "isto aconteceu e não valia
nada" — uma afirmação que ninguém neste crate consegue sustentar.
`external_to_external_is_outside_the_perimeter_not_a_zero_profit_crossing`
(`boundary_delta.rs:1067`) fixa a diferença, e
`every_domain_pair_maps_to_exactly_one_leg` (`boundary_delta.rs:1110`) fixa que
os quatro pares dão exactamente uma linha.

**A promoção isolada é estruturalmente impossível, e por cinco caminhos
independentes da forma do tipo** — não por uma flag de run-time e não por um
comentário:

1. `signed_amount_micros` é **`pub(crate)`** (`boundary_delta.rs:613-616`, com
   o accessor de duas linhas a explicar porquê): um caller fora do crate não
   obtém uma magnitude para somar. Não é "não deve" — não pode.
2. O tipo não tem `promotes()`, `is_positive()` nem `nev_musd()`. A única
   superfície pública devolve `asset()`, `direction()`, `event_id()`,
   `evidence_hash()`, `policy_hash()` e `nev_sign()` — e `nev_sign()` é um
   facto sobre a direcção, não um veredicto.
3. **Não tem `Deserialize`** (`#[derive(Debug, Clone, Serialize)]`,
   `boundary_delta.rs:488`), logo um blob descodificado não pode ser
   reconvertido em perna.
4. O **único construtor público** é `from_crossing(&BoundaryCrossing,
   &ValidatedOutcomePolicy)` (`boundary_delta.rs:522-525`). Não existe
   construtor que aceite um inteiro, e portanto nada se torna perna por
   *afirmar* que o é.
5. **Nada do módulo é alcançável a partir de `VerifiedEconomyView`.** Verificado
   por grep: `boundary_delta` não é importado em `verified_view.rs`; o único
   consumidor de `VerifiedBoundaryDelta` em todo o repositório é
   `settlement.rs` (`:395`, `:1365`, `:1470`).

O predicado que decide alguma coisa vive em `SettlementAuthority::is_positive`
(`settlement.rs:993`), alcançável apenas por `VerifiedSettlement::promote`
(`settlement.rs:909`), alcançável apenas por `assemble` a devolver `Complete`.

`a_lone_delta_cannot_promote` (`boundary_delta.rs:1767`) caminha por todas as
superfícies de promoção do crate — `verified_nev`, `arv_status`,
`unattested_nev`, `autonomy_summary` — nos **dois** modos de confiança, com um
ledger real, com o crossing gravado, com a política validada e com um provider
identificado pelo kernel. É a prova da afirmação, e está no teste, não na doc.

**A decisão de desenho que importa registar, porque é contra-intuitiva e porque
o seu erro seria silencioso:** acrescentar a perna negativa de forma ingénua
**teria sido mais perigoso do que o desenho só-de-entradas.** O caso mínimo é o
arbitrage:

```text
executor controlado -> pool     100.00 USDC   (saída, tem de ser −)
pool                -> executor 100.08 USDC   (entrada, tem de ser +)
```

A operação vale `+0.08`. Promover **qualquer** das pernas isoladamente produz um
resultado falso, e o primeiro deles é um falso **lucro** de magnitude suficiente
para financiar orçamento real: `+100.08` com nenhum `−100.00` à vista. Sob o
desenho só-de-entradas esse erro **não é expressável**, porque promover a
entrada é tudo o que o desenho sabe fazer e a entrada aconteceu mesmo. No
momento em que os dois sentidos existem, a promoção de uma travessia isolada
deixa de ser sound — e por isso a prioridade de P4.5a foi tornar o isolamento
**impossível**, não tornar as pernas promovíveis.
`both_legs_of_an_arbitrage_sum_to_the_real_profit_and_promote_nothing`
(`boundary_delta.rs:1821`) é o parágrafo anterior em forma de teste: soma as
duas pernas (−100.00 + 100.08 = `80_000` micros), afirma que esse `net` é um
`i128` nu que não é `VerifiedNev` nem entrada de promoção nenhuma, e depois
percorre as quatro superfícies de promoção com as duas pernas gravadas.

**Um delta zero ou mal assinado é um ERRO TIPADO, não um `debug_assert`.**
`BoundaryDeltaError::ZeroAmount` e `::SignMismatch` (`boundary_delta.rs:196-207`)
existem como braços próprios e valem em build de release — a justificação está
na doc do módulo (`boundary_delta.rs:83-85`): um `debug_assert` é estritamente
mais fraco, porque desaparece exactamente onde a entrada é controlada por um
atacante. Uma única implementação, `check_signed_amount`
(`boundary_delta.rs:299-318`), é partilhada pelo produtor (`signed_micros`,
`boundary_delta.rs:266-292`) e pelo consumidor (`from_signed_amount`,
`boundary_delta.rs:581-598`), de modo a não poderem divergir: uma
implementação, dois sítios de chamada, zero deriva.

**Um custo de gas não é expressável como delta `ControlledToExternal`, e isso é
estrutural, não convenção.** Todo o caminho para um delta começa num
`BoundaryEvidence` (dois endereços distintos, activo identificado, montante não
nulo, hashes de transacção e bloco bem formados) mais um
`BaseUsdcVerification` que descreve **aquele** ERC-20 transfer. Uma taxa de gas
não tem log `Transfer` para o qual apontar uma prova, é queimada por um
protocolo ou paga a um validador, e pode nunca tocar num endereço controlado —
logo não há travessia a derivar.
`an_external_cost_cannot_be_expressed_as_a_controlled_to_external_delta`
(`boundary_delta.rs:1898`) fixa a costura: um montante de "tamanho de taxa" é um
transferimento diferente (recusado), e a serialização de um delta não contém
`gas`, `fee`, `external_cost`, `cost`, `gas_used` nem `gas_price`.

### P4.5b — identidade canónica de evento e idempotência económica no lado da autonomia

```
ExternalEventId = H( "MYCELIUM-ECONOMY/EVENT-ID/V1", schema_version, chain_id,
                     tx_hash, log_index, asset, from_address, to_address,
                     amount_raw )
```

Oito secções, tabela de fonte única `EVENT_ID_FIELDS`
(`event_id.rs:479-488`), codificador `preimage` (`event_id.rs:505-540`) a
reutilizar o `push_tagged` de P4a — nunca uma struct serializada, porque uma
codificação auto-descritiva promoveria ordem de campos, espaços em branco e
formatação de números à identidade de um facto económico. A tabela é conferida
contra o codificador em run-time (`check_layout`, `event_id.rs:550-570`), e a
ausência das secções proibidas é **afirmada como teste** contra a tabela
(`event_id.rs:1184`). Ausentes por construção: `sequence`, timestamps,
`source_id`, `opportunity_id`, `verifier_id`, `policy_hash`, digests de receipt,
caminho e `record_hash`.

**`log_index` é OBRIGATÓRIO.** Um provider que confirma uma transferência sem
dizer qual log casou não estabeleceu um evento, e o leitor reporta
`EventIdError::LogIndexUnknown` em vez de contar — nunca um índice inventado
nem um `0` por omissão. `from_confirmed_transfer` é onde essa regra vive, e
`a_confirmed_transfer_with_no_log_index_is_not_counted`
(`verified_view.rs:5965`) fixa-a. O raciocínio está escrito no teste e vale
por si: preencher o índice com zero deixaria este evento ser arquivado sob a
identidade de outro log, o que é pior do que recusá-lo.

Existe um segundo domínio, `NATIVE_GAS_EVENT_ID_DOMAIN =
"MYCELIUM-ECONOMY/NATIVE-GAS-EVENT-ID/V1"` (`event_id.rs:106`), para que um
pagamento de gas **não possa colidir** com uma transferência de token na mesma
transacção. E `NATIVE_CURRENCY` (`event_id.rs:121`) é a palavra zero reservada
que substitui `asset`/`from`/`to` num facto nativo, em vez de um endereço de
contrato fabricado.

**A reformulação da protecção contra replay** é o conteúdo de fundo deste
sub-passo. O desenho anterior ligava a assinatura a uma **SEQUÊNCIA** do
ledger, e isso era errado por duas razões independentes: tornava a evidência
externa dependente da sua **posição num ficheiro local** — misturando dois
domínios que o projecto separou deliberadamente, porque prova de existência não
deve depender de onde alguém a guardou — e tornava o efeito **por leitura**, de
modo que um registo duplicado promovia **uma vez por arranque de processo**. A
identidade correcta é um digest canónico do **facto externo**.

**Três preocupações, mantidas distintas** (`event_id.rs:854-892`; a tabela ali
é explícita):

| preocupação | onde vive | se for ignorada |
| --- | --- | --- |
| a mesma linha foi acrescentada duas vezes | problema de **armazenamento**, recusado pelo caminho de escrita sob o lock | o ficheiro cresce; nada está errado ainda |
| a mesma **atestação** é reivindicada por dois registos | problema de **proveniência**, `AttestationGap::AttestationReplayed` | uma assinatura avalizaria dois lançamentos |
| o mesmo **facto externo** é lançado duas vezes | o problema **económico**, e o único que pode inflar um total | o NEV é contado duas vezes por uma transferência |

A primeira é higiene e não é autoridade: um ledger que *fisicamente contenha*
uma duplicata — escrita por um fork, restaurada de uma cópia, acrescentada à
mão — ainda não pode dobrar a contagem, e nenhuma disciplina de escrita o pode
prometer. A segunda é defesa em profundidade sobre o ledger de atestações e é
reportada à parte, porque uma atestação duplicada e um evento duplicado são
diagnósticos diferentes com correcções diferentes.

**`CountedEvents` (`event_id.rs:893-937`) não pode ser contornado.** É um
`HashSet<ExternalEventId>` mais um `BTreeMap` de relatório, criado **dentro**
de `receipt_evidence()` (`verified_view.rs:1003`) e destruído à saída. Três
factos fecham a porta: é o **único produtor** de `ReceiptEvidence`; `assess_receipt`
é **privada** (`verified_view.rs:1184`) e é a **única** escritora de
`counted = true`; e o conjunto é uma **local**, sem parâmetro de construtor e
sem campo — portanto "já contado" é **recalculado do ledger em cada leitura**,
que é a razão de um reinício de processo re-derivar a mesma resposta. `claim()`
(`event_id.rs:905-915`) é o mecanismo: `seen` **é** a autoridade, e
`first_counted_at` existe só para o relatório poder nomear o registo que detém
o crédito — é escrito na mesma chamada e nunca é consultado para a decisão, logo
não há caminho em que os dois discordem.
`the_duplicate_is_still_not_counted_after_the_view_is_rebuilt`
(`verified_view.rs:5658`) reabre o directório três vezes, como um processo novo o
faria, e afirma que as três leituras concordam: 5.000.000 micros, 1 recibo, o
mesmo diagnóstico.

**Duas variantes novas de gap separam os casos**, e o texto de cada uma nomeia o
que um relatório de replay não consegue nomear:

- `AttestationReplayed` (`verified_view.rs:214`) — uma assinatura reivindicada
  duas vezes. Falha de **proveniência**.
- `ExternalEventAlreadyCounted { event_id, first_counted_at_sequence }`
  (`verified_view.rs:227-231`) — **duas assinaturas perfeitas sobre o mesmo
  facto**. Falha **económica**. O texto nomeia o id **e** a sequência que
  detém a contagem (`:318-325`), coisas que um relatório de replay não tem como
  produzir.

`a_replayed_attestation_and_a_repeated_event_are_told_apart`
(`verified_view.rs:5786`) prova que as duas não colidem.

### P4.5c — agregação do settlement, e onde mora o predicado de promoção

`OperationId = H("MYCELIUM-ECONOMY/OPERATION-ID/V1", schema_version, chain_id,
tx_hash)` — três secções, `OPERATION_ID_FIELDS` (`settlement.rs:155-159`),
campo **privado** (`settlement.rs:252-254`), **sem `Deserialize`**, e **um**
construtor a partir de um `TransactionLogScan` (`settlement.rs:258`). O caller
fornece **scans, nunca um id** — e a decisão de agrupamento é tomada em
`assemble` (`settlement.rs:1082-1099`), não pelo caller.

**Uma transacção = uma operação, e o agrupamento multi-transacção é RECUSADO**
(`SettlementError::CrossTransaction`), não dividido. O raciocínio é o argumento
central deste sub-passo e é o mais importante dos cinco: **uma transacção é a
maior unidade pela qual a cadeia responde** — todos os logs que emitiu
aconteceram, ou nenhum aconteceu — logo é a única forma de agrupamento com
evidência atrás. Duas transacções não têm essa evidência, e agrupá-las é uma
escolha do operador feita **a posteriori**, que é exactamente como se fabrica um
líquido lucrativo: registar a entrada e escolher uma janela que exclua a saída
perdedora. E dividir seria **pior** do que não fazer nada, porque cada metade
voltaria como um settlement **completo**, e a metade perdedora voltaria como uma
operação completa de `−100.08`.
`an_operation_spanning_two_transactions_is_refused` (`settlement.rs:2595`)
fixa-o, e a doc do próprio teste nomeia o motivo (`settlement.rs:2586-2593`).

**O predicado de promoção vive em `SettlementAuthority`** (`settlement.rs:950`),
alcançável só por `VerifiedSettlement::promote` (`settlement.rs:909`),
alcançável só por `assemble` a devolver `Complete` (`settlement.rs:1249`). Uma
perna carrega o seu sinal e **não sabe nada sobre se os seus irmãos existem**,
pelo que qualquer predicado de dinheiro sobre uma perna estaria errado por
construção — é o que P4.5a fez impossível e P4.5c torna desnecessário.

**A completude é julgada contra uma ENUMERAÇÃO DA CADEIA, não contra a evidência
guardada por este nó.** Este é o ponto que mais importa reter, porque é o que
separa um settlement de uma tautologia: uma operação montada apenas a partir das
linhas de evidência que este nó tem seria **completa por construção** — e o que
lhe faltaria seria exactamente as pernas que ninguém escreveu. O mecanismo é
`TransactionLogScan.exhaustive` (`base_usdc.rs:120`, `:169`), que é `false`
quando pelo menos um log não pôde ser classificado; e a lista de pernas vem do
`receipt.logs` da cadeia (`base_usdc.rs:649-652`), com
`exhaustive = unclassified.is_empty()` (`base_usdc.rs:746`). A evidência
guardada entra **depois**, em `establish_leg` (`settlement.rs:1360-1478`), onde
a ausência de uma linha para um log enumerado é `LegState::Absent`. A
classificação é estrita para `Transfer` não identificado, amount ilegível ou
acima de `u64`, ou `Transfer` com menos de três topics (`base_usdc.rs:670-698`) —
ver a carrança 2.

**Três estados de incompletude, serializados com tags explícitas, e
deliberadamente não colapsados** (`SettlementIncompleteness`,
`settlement.rs:617-648`, tag `state`): `Absent` (a cadeia enumerou-o, não há
evidência guardada — o dinheiro moveu-se, o montante é desconhecido),
`Unattested` (chain-confirmado **e** evidência detida, mas sem política
validada — real e não ligado), `Unconfirmed` (evidência detida, a leitura de
cadeia não a liga a esse log), mais `scan_not_exhaustive`. As três são
distinguíveis **sem parsear prosa**:
`the_three_incompleteness_states_are_distinguishable_in_the_report`
(`settlement.rs:2285`) afirma que cada uma tem nome próprio, que cada uma
serializa a sua própria tag, e que `absent` e `unattested` têm palavras
diferentes. `IncompleteSettlement` tem, sim, duas colunas numéricas
(`confirmed_inflow_micros`, `confirmed_outflow_micros`, `settlement.rs:789-795`),
e elas chamam-se `confirmed_*` precisamente para não poderem ser lidas como a
operação.

**`MissingRequiredEconomicEvidence ⇒ NoSpendAuthority` é imposta pela AUSÊNCIA
de um método.** `IncompleteSettlement::net_delta_micros()` existe e devolve
**permanentemente `None`** (`settlement.rs:806-808`) — presente para que um
caller que tente receba `None` em vez de um erro de compilação, e para que a
*forma* da recusa faça parte da API pública. E não há `promote`, nem qualquer
caminho para um `SettlementAuthority`. Nunca "falta uma saída → assumir zero".
`either_leg_on_its_own_promotes_nothing` (`settlement.rs:1962`) afirma
`incomplete.net_delta_micros() == None` para as duas direcções isoladas, e
`a_leg_with_no_validated_policy_is_unattested_not_zero` (`settlement.rs:2049`) e
`a_leg_the_chain_will_not_bind_is_unconfirmed_not_zero` (`settlement.rs:2107`)
afirmam as outras duas.

**Duas reconciliações feitas, e ambas é um facto registado que deixou de ser
verdade:**

1. `UncanonicalEventId`, o *placeholder* de P4.5a — criado porque dois agentes
   concorrentes não conseguiam confirmar o tipo um do outro — foi **substituído**
   pelo `ExternalEventId` real. O tipo hoje não existe em lado nenhum do código;
   as três ocorrências restantes da string são três notas que **nomeiam a
   remoção** (`boundary_delta.rs:121`, `:634`, `:1527`). Duas identidades de
   evento num crate é exactamente como "temporário" se torna estrutural, e o
   tipo real existe agora para a substituir.
2. `evidence_hash` **já não contém `chain_confirmed`**. A tabela tem oito secções
   e `chain_confirmed` não está nenhuma (`boundary_delta.rs:326-335`), o que é
   **afirmado** em `the_evidence_digest_names_the_transfer_and_nothing_else`
   (`boundary_delta.rs:2030-2048`) e em
   `the_evidence_digest_cannot_be_re_pointed` (`boundary_delta.rs:1444-1453`).
   A razão está escrita e merece ser repetida: com `chain_confirmed` dentro, uma
   transferência tinha **dois** digests de evidência — um para "registada" e um
   para "confirmada" — e o segundo não é um facto diferente, é um **estágio
   posterior de aprendizagem do mesmo facto**. Uma chave de identidade que muda
   quando o nó aprende qualquer coisa conta estágios de conhecimento, não factos,
   e um conjunto de desduplicação indexado por ela teria contado a perna duas
   vezes. O estado de confirmação continua a ser gravado e continua a ser
   vinculativo — `from_crossing` recusa um crossing sem prova
   (`ChainUnconfirmed`, `boundary_delta.rs:530-532`) — só deixou de ser uma
   identidade. **Uma expectativa de teste de P4.5a estava errada e foi
   reescrita**; é a reconciliação acima que a torna falsa, e o teste reescrito é
   o que está citado.

### P4.5d — custo nativo verificado, e a consequência honesta de o reportar

`VerifiedNativeGasCost` (`settlement.rs:506-517`) com `gas_used`,
`effective_gas_price_wei`, `l1_fee_wei`, derivando

```text
cost_wei = gas_used × effective_gas_price_wei + l1_fee_wei
```

com aritmética **verificada**: `checked_mul` seguido de `checked_add`, e
overflow é `SettlementError::NetOutOfRange`, nunca um número envolvido
(`settlement.rs:537-542`) — porque uma taxa envolvida seria dinheiro grátis.
`an_overflowed_native_cost_is_refused_rather_than_wrapped`
(`settlement.rs:3098`) fixa-o. A identidade é um `ExternalEventId` sob
`NATIVE_GAS_EVENT_ID_DOMAIN`, e `asset`/`from`/`to` recebem a `NATIVE_CURRENCY` —
palavra zero reservada, não um contrato de token fabricado
(`settlement.rs:543-552`).

**Reportado como DUAS quantidades separadas:** `token_net_delta_micros()`
(`settlement.rs:873`) e `total_native_cost_wei()` (`settlement.rs:879`). O termo
de custo externo é deliberadamente **não** subtraído do primeiro: subtrair wei
de micros seria um erro de categoria. `comparable_net_value_micros()`
(`settlement.rs:897-902`) é `None` sempre que valor nativo se mexeu, e `promote()`
devolve então `SettlementError::NoComparableNetValue`. Não existe conversão
ETH→USD em lado nenhum do crate — verificado por grep, e o resultado está em
"Propriedades de segurança verificadas", item (f).

**A consequência honesta, e é significativa: nesta build, NENHUMA operação que
gaste gas pode promover.** Na Base, qualquer transacção real queima gas, portanto
em produção isto não promoveria nada. O fixture de arbitrage reporta
`gasUsed: 0x0` **de propósito**, e o comentário no fixture diz exactamente isso
(`settlement.rs:1703-1708`): é o que exercita o caminho de promoção, e um segundo
teste cobre a outra metade. O par é o estado honesto deste build — promove uma
operação sem custo e recusa promover uma que queimou gas que não consegue
precificar. Fechar isto exige uma **fonte de evidência de preço em que se possa
confiar** — uma observação de oracle assinada ou uma segunda atestação assinada
por política — e **não** uma constante.

### P4.5e — a lacuna de desduplicação do lado da receita, que P4.5b reportou

`settlement_evidence()` (`verified_view.rs:1869`) constrói um `CountedEvents`
por leitura, com o mesmo código e a mesma justificação do lado da autonomia. A
identidade do pagamento é reivindicada **depois** da assinatura e **depois** da
leitura de cadeia (`verified_view.rs:2115-2179`), e o corpo diz porquê: um
registo que não é comprovadamente a liquidação de um pagamento real **não tem
pagamento nenhum para ser duplicado de**, e recusá-lo ali reportaria a falha
errada. Gap: `SettlementGap::SettlementEventAlreadyCounted { event_id,
first_counted_at_sequence }` (`verified_view.rs:663-667`).

**Provas.** `a_duplicated_settlement_is_counted_once_in_paid_demand`
(`verified_view.rs:6223`) estabelece a pré-condição em vez de a assumir: dois
registos, `settlement_id` diferente, `settled_at_unix` diferente, **dois
`settlement_hash` distintos** (`:6247-6251`), **duas atestações genuínas**
(`:6252-6257`) — e depois 5.0 e não 10.0. O caso estreito que o relatório de
lacuna nomeou é
`a_duplicate_settlement_differing_only_in_settled_at_is_still_one_event`
(`verified_view.rs:6326`): **treze campos idênticos** — `schema_version`,
`job_id`, `work_receipt_id`, `mode`, `settlement_asset`,
`settled_amount_micros`, `usd_equivalent_micros`, `payment_intent_id`,
`payment_block_number`, `payment_proof_hash`, `payment_proof_verified`,
`external_paid`, `internal_work` (`:6337-6355`) —, dois `settlement_hash`
distintos, duas assinaturas genuinamente distintas, **uma identidade**, **5.0 e
não 10.0** (`:6364`). Nem a guarda de replay de atestação nem uma comparação
byte a byte podem vê-lo: só a identidade do facto externo pode, e pode.
`the_duplicate_settlement_is_still_not_counted_after_the_view_is_rebuilt`
(`verified_view.rs:6381`) fecha o caso do reinício de processo do lado da
receita também.

**O pagamento precisou do seu próprio preimage** (`SETTLEMENT_EVENT_ID_DOMAIN =
"MYCELIUM-ECONOMY/SETTLEMENT-EVENT-ID/V1"`, `event_id.rs:663`), com uma tabela
de **sete linhas** — `schema_version`, `chain_id`, `tx_hash`, `log_index`,
`asset`, `to_address`, `amount_raw` (`event_id.rs:676-684`), ou seja **seis
factos** mais a versão de schema. A razão é precisa e vale por si:
`ExternalEventFact` liga `from_address`, e **nada na leitura de receita
estabelece o pagador** — `BaseUsdcVerification` reporta o destinatário, o token
e o montante, e o pagador não é lido por lado nenhum (`event_id.rs:640-660`).
Inventar um pagador **poria um facto fabricado dentro de um digest** — e um
digest de um facto fabricado é um digest de nada, e seria **estável**, o que é
pior do que aleatório. E `(chain_id, tx_hash, log_index)` já nomeia um log numa
cadeia, portanto o preimage menor é o **mais verdadeiro**, não o mais fraco:
omite um campo porque esse campo é desconhecido aqui, não porque foi esquecido.
`the_settlement_payment_preimage_names_only_what_the_revenue_read_established`
(`verified_view.rs:6586`) fixa a tabela, afirma que `from_address` não está
nela, e separa os três domínios uns dos outros.

### Verificação desta rodada

Todas as execuções com `cargo 1.88.0` / `rustc 1.88.0`, sempre `--locked`,
sequenciais, com `${PIPESTATUS[0]}` e sempre `--no-fail-fast`.

| Comando | Exit | Resultado |
| --- | --- | --- |
| `cargo test -p mycelium-economy --locked --no-fail-fast` | 0 | **390 passed / 0 failed** |
| `cargo test --workspace --locked --no-fail-fast` | 0 | **698 passed / 0 failed / 0 ignored**, em 39 binários com testes |
| `cargo test --workspace --features veil --locked --no-fail-fast` | 0 | **705 passed / 0 failed** |
| `cargo check --workspace --all-targets --locked` | 0 | verde |
| `cargo clippy --workspace --all-targets --locked` | 0 | **232 avisos distintos em 41 lints** |

Composição dos 390, reconferida por contagem de atributos e não só pelo runner:
**354** em `crates/mycelium-economy/src/` e **36** nos quatro binários de
integração (`tests/ledger_durability.rs` 10, `tests/pinned_provider_cli.rs` 6,
`tests/signing_cli.rs` 13, `tests/verified_view_cli.rs` 7). 354 + 36 = 390, e
os dois caminhos concordam. Delta do crate contra P4: **318 → 390**, isto é
**+72**, dos quais **57** em três módulos novos (`boundary_delta.rs` 20,
`event_id.rs` 16, `settlement.rs` 21) e os restantes 15 distribuídos por
`verified_view.rs`, `base_usdc.rs` e `boundary.rs`. Era **58** em P0.

**O delta veil é exactamente +7**, e é o mesmo trio de sempre, com os mesmos
números: `veil_data_path_security` +2, `veil_p1_3_2_acceptance` +4,
`veil_socks5_integration` +1 (de 0 para 1/2/4). Nada mais no workspace se moveu
com a feature, e é isso que a afirmação "delta exactamente +7" quer dizer.

**Ressalva honesta sobre o `cargo check`.** A execução do workspace saiu em
0.29 s, servida pelo cache de fingerprints, e portanto **não** é uma medição de
compilação nova — do mesmo modo que um `cargo check` verde sobre cache não é
prova de nada. Para não publicar um zero de avisos que não foi medido,
`cargo check -p mycelium-economy --all-targets --locked` foi repetido num
`CARGO_TARGET_DIR` limpo (compilação a frio real, 17.61 s): **exit 0, 0
avisos**, e o directório temporário foi removido depois. Disco: **~91 GB livres**,
inalterado.

**Clippy: 232 avisos distintos em 41 lints**, e o passo `-D warnings` da CI **não
pode passar**. Nada foi corrigido — o enunciado desta tarefa é explicitamente
"não corrigir". Topo: `uninlined_format_args` **181**, `useless_format` **73**,
`ptr_arg` **20**, `io_other_error` **18**, `redundant_closure` **10**,
`too_many_arguments` **8**, `collapsible_if` **8**, `op_ref` 6,
`bool_assert_comparison` 6, `clone_on_copy` 6. Os números vêm da aritmética do
próprio cargo (414 diagnósticos emitidos em 36 alvos, 182 deles marcados como
duplicados por alvo); a contagem por sítios únicos de código-fonte no log dá 230,
e a diferença de dois é de alvos que o cargo não deduplicou. Concentração:
`crates/mycelium-node/src/organism.rs` 64 sítios,
`cli/mycelium-cli/src/main.rs` 52, `crates/mycelium-hyphae/src/lib.rs` 17, e
**7 em `crates/mycelium-economy/src/verified_view.rs` + 5 em `event_id.rs` + 3
em `settlement_auth.rs` + 2 em `boundary.rs` + 2 em `receipt_auth.rs`**. Ou
seja: **a dívida de clippy desta rodada é quase toda pré-existente e de outros
crates.**

### Propriedades de segurança verificadas

Todas por leitura do código, com citação. Nenhuma por inferência a partir de um
nome de teste.

| # | Propriedade | Veredicto | Evidência |
| --- | --- | --- | --- |
| a | Promoção isolada impossível; o predicado vive só no settlement completo | **CONFIRMADA** | `boundary_delta.rs:613-616` (`pub(crate)`, sem accessor público de montante), `:488` (sem `Deserialize`), `:522-525` (único construtor público, sem inteiro), `:299-318` (zero/erro de sinal tipado, partilhado por duas chamadas); `settlement.rs:909-934` (`promote` só em `VerifiedSettlement`), `:1249-1258` (`Complete` só quando `reasons` está vazio), `:993-995` (o predicado); `verified_view.rs:1184` (`assess_receipt` privada), `:496-547` (`from_settlement_authorities` só aceita `SettlementAuthority`); grep confirma que `boundary_delta` não é importado por `verified_view.rs` e que `VerifiedBoundaryDelta` só é usado em `settlement.rs`; teste: `boundary_delta.rs:1767` |
| b | Ambos os sentidos derivados, sinal não fornecido pelo caller, `BoundaryDirection` sem `Deserialize` | **CONFIRMADA** | `boundary.rs:333-340` (derive sem `Deserialize`), `:427-442` (`BoundaryLeg::of` privado, único construtor), `:450-455` (`direction()` → `None` para as duas não-travessias), `:356-361` (`sign()`, único multiplicador); `boundary_delta.rs:526-537` (o sinal é aplicado dentro de `from_crossing`, nunca recebido), `:581-598`; testes: `boundary_delta.rs:894`, `:961`, `:862`, `:878`, `:1110` |
| c | O caso do arbitrage é aritmeticamente certo nos dois sentidos | **CONFIRMADA** | As duas pernas → `settlement.rs:1841-1949`: inflows 100.080.000, outflows 100.000.000, `token_net_delta_micros() == 80_000` ("oito cêntimos, não cem e não cento e oito"), `promote` → `nev_musd_micros() == 80_000`, `is_positive()`, e chega a um `VerifiedNev` com 2 pernas. Cada perna sozinha → `settlement.rs:1962-2035`: `incomplete.net_delta_micros() == None`, `!is_complete()`, `missing_states() == ["absent"]`, as **duas** pernas reportadas, a perna ausente com a direcção que falta, e `assert_no_promotion_route` a percorrer todas as superfícies. As duas direcções são testadas porque a assimetria é o risco: só-entrada dá um falso **lucro**, só-saída dá um número errado |
| d | Settlement incompleto ⇒ sem autoridade de gasto; `Absent` / `Unattested` / `Unconfirmed` distinguíveis, não colapsados a zero | **CONFIRMADA** | `settlement.rs:806-808` (`net_delta_micros()` é permanentemente `None`; os únicos números públicos do tipo são as duas colunas `confirmed_*` de `:789-795`), e ausência de `promote` e de qualquer produtor de `SettlementAuthority` em `IncompleteSettlement`; `settlement.rs:617-648` (quatro variantes com tag `state`), `:1280-1289` (`incompleteness_for` escolhe a variante pelo estado, nunca colapsa), `:1460-1468` (sem política → `Unattested`), `:1403-1411` (sem linha guardada → `Absent`); testes: `settlement.rs:2285`, `:2049`, `:2107`, `:1962` |
| e | Idempotência económica nos **dois** lados, incluindo duplicado que só difere em `settled_at_unix` | **CONFIRMADA** | Autonomia: `event_id.rs:893-937` (`CountedEvents` + `claim`), `verified_view.rs:1003` (criado dentro de `receipt_evidence`), `:1430-1459` (a identidade é construída da evidência **re-derivada** mais o log index lido, e a reivindicação é o **último** portão antes de `counted = true`), `:210-231` (as duas variantes de gap separadas). Receita: `verified_view.rs:1869` (o segundo `CountedEvents`), `:2115-2179` (portão 12, **depois** da assinatura e **depois** da leitura de cadeia), `:663-667` (`SettlementEventAlreadyCounted`). Testes: `verified_view.rs:6326` (treze campos idênticos, dois `settlement_hash`, duas assinaturas, uma identidade, 5.0), `:6223` (5.0 e não 10.0), `:5658` e `:6381` (o resultado sobrevive a três reconstruções), `:5460`, `:5554` |
| f | Nenhum preço ETH/USD presumido | **CONFIRMADA** | Nenhuma taxa, fonte de preço nem conversão existe no crate. Todas as ocorrências de "price" em `crates/mycelium-economy/src/` são ou `effectiveGasPrice`/`gasPrice` lidos do receipt (`base_usdc.rs:724-729`), ou `max_price_musd_micros`, que é o **tecto de lançamento de um job** (`lib.rs:103`, `lib.rs:733`) e nada tem a ver com câmbio, ou documentação que afirma a ausência. `VerifiedNativeGasCost` não tem campo USD, nem parâmetro `eth_usd`, nem taxa (`settlement.rs:498-505`, `:596-600`); o custo é reportado em wei ao lado do delta em micros e os dois nunca são somados (`settlement.rs:873-881`); e `comparable_net_value_micros()` devolve `None` quando valor nativo se mexeu (`settlement.rs:897-902`) |
| g | A completude é decidida contra uma enumeração da cadeia, não contra a evidência deste nó | **CONFIRMADA** | `TransactionLogScan.exhaustive` (`base_usdc.rs:120`, `:169`), calculado como `unclassified.is_empty()` sobre o `receipt.logs` da cadeia (`base_usdc.rs:649-652`, `:746`); `assemble` recusa tratar um scan não-exaustivo como completo (`settlement.rs:1107-1111`); o conjunto de pernas é o do scan (`settlement.rs:1113`), e a evidência guardada só é procurada **depois**, dentro de `establish_leg` (`settlement.rs:1399-1411`), onde a falta é `Absent`. `same_transfer` (`settlement.rs:1485-1499`) exclui deliberadamente o `block_hash` do emparelhamento, para que um bloco mal registado seja `Unconfirmed` e não `Absent` |
| h | `evidence_hash` já não contém `chain_confirmed`, e `UncanonicalEventId` não existe | **CONFIRMADA** | Tabela de oito secções sem `chain_confirmed` (`boundary_delta.rs:326-335`), afirmada por `assert!(!tags.contains(&"chain_confirmed"))` (`boundary_delta.rs:2047`) e pelo teste de re-pointing (`boundary_delta.rs:1444-1453`); o estado continua a ser vinculativo por `ChainUnconfirmed` (`boundary_delta.rs:530-532`). `UncanonicalEventId`: **zero ocorrências de tipo** em todo o repositório — as três únicas menções da string são notas que nomeiam a remoção (`boundary_delta.rs:121`, `:634`, `:1527`) |

### Carranças que permanecem abertas — registadas, não corrigidas

Todas as nove, por ordem de gravidade. Nenhuma foi fechada nesta rodada.

1. **Nenhuma operação com gas pode promover.** É o maior limite funcional de
   todo o build, e é directo: `comparable_net_value_micros()` é `None` sempre
   que valor nativo se mexeu, e na Base **toda** transacção real queima gas. O
   fixture de arbitrage reporta `gasUsed: 0x0` para exercitar o caminho de
   promoção (`settlement.rs:1703-1712`). Fechar exige evidência de preço em que
   se possa confiar — observação de oracle assinada ou segunda atestação
   assinada por política —, **não** uma constante.
2. **A completude só é tão boa quanto a classificação de logs.** A classificação
   é estrita para `Transfer` não identificado, `Transfer` com amount ilegível ou
   acima de `u64`, e `Transfer` com menos de três topics
   (`base_usdc.rs:670-698`), e é **laxa** para eventos que não sejam `Transfer` —
   são saltados sem entrar em `unclassified` (`base_usdc.rs:662-664`). Um
   receipt real de arbitrage contém dezenas de logs, pelo que a operação pode
   reportar **completa** onde talvez devesse dizer que não tem a certeza — o
   caso concreto é **uma perna WETH dentro de uma rota multi-activo**, que não é
   `Transfer` de USDC e por isso não bloqueia. **Decisão de julgamento, não
   omissão**, e registada como tal.
3. **A identidade da operação não é estável através de um revert-and-retry, e
   não há tratamento de reorg.** `OperationId` liga `chain_id` e `tx_hash`
   (`settlement.rs:155-159`); uma tentativa refeita é outra transacção, logo
   outra operação, e o par original continua lá. É **a mesma exposição que P4b
   já tinha para receipts**, estendida a settlements.
4. **Um terceiro domínio de preimage.** `SETTLEMENT_EVENT_ID_DOMAIN` tem, por
   desenho, um conjunto de linhas diferente — `from_address` não está lá, porque
   a leitura de receita não estabelece o pagador (`event_id.rs:640-684`). É
   separado por domínio e fixado por teste (`verified_view.rs:6586-6619`), mas
   **é um terceiro vocabulário** num crate cuja força é precisamente que cada
   digest tem exactamente um significado documentado. A mitigação é a separação
   por domínio; o custo é a contagem de vocabulários.
5. **O agrupamento por transacção é um limite deliberado.** Uma operação
   economicamente única que a cadeia reparta por duas transacções é **recusada**
   (`CrossTransaction`). Hoje é a resposta correcta, fail-closed; para uma
   estratégia cross-transaction é a resposta errada. Registado como limite, e
   não como bug.
6. **`SettlementAuthority` é cunhável por qualquer pessoa que consiga montar um
   settlement completo.** As três pré-condições são as mesmas de um receipt
   (provider identificado pelo kernel, política validada, evidência guardada que
   casa com uma enumeração da cadeia), portanto isto é **paridade** e não um
   buraco novo. Mas **não há tecto de autoridades por operação**, e a prevenção
   de replay do lado do caller é o `CountedEvents` **do lado do receipt** — o
   lado do settlement não tem um.
7. **O modo `Unverified` não consegue calcular uma identidade de evento** — o
   log index vem da leitura de cadeia, que o modo offline não faz. Logo
   `unattested_nev` **conta em dobro** um facto — e isto é afirmado, não
   escondido: `verified_view.rs:5955` afirma 10.000.000 para dois registos. Esse
   número **não é insumo de autoridade** — é por isso que o campo se chama
   `claimed_*` e não `net_*` — **mas é um diagnóstico que um operador pode ler
   mal**, e um placar honesto diz as duas coisas.
8. **Um provider que omita `logIndex` recusa agora contar essa transferência.**
   Fail-closed e discutivelmente correcto — o facto é innomeável sem índice, e
   duas transferências idênticas numa transacção são indistinguíveis sem ele — mas
   é **uma recusa nova contra uma cadeia real**. Um
   `eth_getTransactionReceipt` conforme inclui `logIndex`, pelo que não deve
   disparar em produção. **Não pôde ser verificado contra um nó vivo**, e fica
   assim escrito.
9. **O conjunto de eventos contados é por leitura:** memória O(n) e uma
   inserção de hash por registo contado em **cada** chamada a `arv_status` /
   `autonomy_summary`. Não há índice persistido. A propriedade é comprada por
   **recomputação**, e é o preço explícito de não haver estado por esquecer entre
   arranques.

### Postura da raiz de confiança: dois modos, não "inseguro vs seguro"

Isto fica registado porque a distinção é rotineiramente colapsada num eixo único
que não descreve nada.

- **Modo Developer/Owner** — a raiz de confiança é controlada pelo **mesmo uid**
  do processo. Defende contra **falsificação do ledger** e contra **acidentes**:
  o pin, a chave de assinatura, a política e o ledger de atestações são coerentes
  entre si e uma escrita acidental é detectada. **Não** protege contra
  **comprometimento do uid**: quem obtém o uid obtém a raiz.
- **Modo Hardened** — a raiz de confiança vive **fora do domínio do processo**:
  propriedade de root, verificador dedicado, TPM, ou um host externo.

São **dois modos**, não um eixo "inseguro vs seguro". O que P4d entregou
(`verifier_key_store.rs` + `tests/signing_cli.rs`) é a **âncora de pin e a chave
de assinatura configuráveis inseparavelmente** — a variável de ambiente move
**as duas metades juntas**, nunca uma só — com `trust_root_relocated` a aparecer
em **todos** os relatórios de confiança em vez de ser inferido de um caminho. O
que P4.5 **não** faz é mover a raiz para fora do domínio do processo: isso
continua a exigir uma dependência externa **e** uma contraparte externa, que é
a mesma barreira que P5 encontrou para a âncora de cabeça e que nenhuma fase até
P4.5 levantou.

**`PolicyHighWaterMark { version, policy_hash }`, diferido para mais tarde.** A
carranca 2 da rodada P4 regista que não há lista de revogação nem marca de água
alta de `policy_version`. O desenho diferido carrega **os dois campos**, e a
regra que o justifica é a que faz este deferimento não ser um esquecimento: **um
`highest_policy_version` nu é insuficiente**, porque **um único número pode, por
bug operacional, corresponder a hashes diferentes** — duas políticas com a mesma
versão, um pin trocado, um rollback parcial — e um leitor que confiasse só no
número aceitaria a política errada com a confiança certa. Um par
`(version, policy_hash)` torna essa colisão detectável, porque o hash discorda.
Nada disto foi implementado nesta rodada e nada disto é medido.

### O que esta rodada **não** mudou

Nada aqui move a lacuna de topologia. Nenhuma máquina a mais, nenhuma rede a
mais, nenhum inbound verificado, nenhuma contraparte.

**Estado a registar sem atenuação: NEV = 0 · valor externo criado = 0 · E6 = 0/9
· níveis (b), (c) e (d) NÃO SUSTENTADOS.** Cada porção de integridade obtida em
P0–P4.5 é **integridade e autoridade, não geração económica**. P4.5c torna
`inflows − outflows` computável **e auditável** — que é o que P4 deixou
explicitamente por fazer — e não aproxima `ARV0` de passar por um milímetro:
passar exige valor externo atestado, e a operação que o atestaria tem de ser
completa **e** promotevel, e hoje nenhuma operação real é promotevel (carranca 1).

E o limite honesto que P4.5 impõe a si próprio, no mesmo spirit de "não é âncora
externa" que P4 e P5 levaram: **uma identidade canónica de facto externo não é
uma âncora externa.** `ExternalEventId` prova que dois observadores estão a falar
da mesma transferência, e nada mais — não carrega autoridade, não é âncora, e o
ledger que o faz sobreviver continua sob o mesmo uid. A propriedade que P4.5b
comprou é real e é estreita: **um facto externo, por muito registado que seja,
conta uma vez.** Isso fecha a dupla contagem. Não fecha quem pode escrever.

## Critérios de aceitação do projeto (E6) — 0/9

Estes são os critérios do próprio projeto
(`EVOLUCAO.md:69-79`), transcritos sem atenuação. Nenhum está satisfeito.

- [ ] **3+ nós em máquinas diferentes** — bloqueado por (b): todo nó em
  loopback, uma única máquina. Nenhuma porta 4001 com inbound verificado.
- [ ] **Nenhuma dependência obrigatória de URL fixa para bootstrap após
  peering inicial** — `seeds/mainnet.txt` vazio de entradas ativas; nenhum
  seed público verificável existe para peers novos.
- [ ] **Conteúdo replicado com prova de posse e persistência** — sem réplica
  entre máquinas distintas; prova de posse existe, persistência distribuída
  não foi observada fora de um host.
- [ ] **Publicador offline e serviço disponível por 2+ réplicas** — sem duas
  réplicas em hosts distintos; `neighbor_ids: []` em todos os nós registrados.
- [ ] **Perda de um relay não interrompe a malha além do reconexão
  configurada** — nunca testado com kill de relay; o teste de sobrevivência
  (`community_service_survival_acceptance.rs`) opera com dois peers em
  `127.0.0.1`.
- [ ] **Dois gateways independentes servem o mesmo Ion** — smoke test de dois
  nós existe, mas contra RPC mock e loopback
  (`scripts/rpc-two-node-smoke.sh`, branch `feature/...`).
- [ ] **Teste com internet residencial CGNAT, com tráfego de saída e relays
  voluntários** — o relay voluntário nunca aconteceu; a saída usou relay
  público de terceiro `wss://nos.lol`, e os endereços eram IPv6 global.
- [ ] **Código de terceiros isolado sob quotas reais, com testes
  adversariais** — `fail_closed` agora é o default e `bwrap` ausente retorna
  `IsolationUnavailable` (correção desta rodada), mas não há execução sob
  quotas de cgroup medidas nem battery adversarial de terceiros.
- [ ] **Logs e medições de uptime, latência p95, tempo de recuperação e
  disponibilidade de réplicas** — inexistente. Zero logs de produção, zero
  séries temporais.

O 0/9 é a situação desde o commit `a6cc5c7` (2026-09-21), intocado pelos 74
commits posteriores na branch `feature/mycelium-base-rpc-pqc`.

**A rodada P0–P2 não move este placar, e a razão vale mais que o número.**
Nenhum dos nove critérios é satisfeito por integração de workspace, por
tipagem de fronteira ou por pin de provider. Todos os nove são, um a um,
critérios sobre máquinas distintas, réplicas fora de um host, clientes
independentes, tráfego de saída real e séries temporais de produção — e nada
disso foi criado, publicado, medido ou witnessed nesta rodada. A integração do
`mycelium-economy` no workspace foi, ela própria, chamada de "oito, com
qualidade de teste zero"; o critério 8 fala em isolamento de **terceiros** sob
quotas **reais** com bateria **adversarial de terceiros**, e continua por
marcar. O valor externo liquidado é zero, e `ARV0` ainda não passa.

> **Atualização — P3, P5 e P4 também não move este placar, e nenhuma das nove
> caixas da lista acima foi marcada.** Nenhum dos nove critérios é satisfeito por
> assinatura de política, por atestação de receipt ou por assinatura de
> settlement. Todos os nove continuam a ser, um a um, critérios sobre máquinas
> distintas, réplicas fora de um host, clientes independentes, tráfego de saída
> real e séries temporais de produção. **NEV = 0 · valor externo criado = 0 ·
> E6 = 0/9**, e a frase que importa mais é a última: **cada porção de
> integridade obtida em P0–P4 é integridade e autoridade, não geração
> económica.** Uma política autenticada não move o critério 1; uma atestação
> assinada não move o critério 9. O que P4 fez foi tornar mais difícil que um
> ledger local seja acreditado — o que é condição **necessária** para o dia em
> que houver algo real a atestar, e não um passo em direcção a esse dia.

> **Atualização — P4.5 também não move este placar, e nenhuma das nove caixas
> da lista acima foi marcada.** Nenhum dos nove critérios é satisfeito por
> direcção de fronteira, por identidade de evento, por agregação de settlement
> ou por custo nativo verificado. Os nove continuam a ser, um a um, critérios
> sobre máquinas distintas, réplicas fora de um host, clientes independentes,
> tráfego de saída real e séries temporais de produção. **NEV = 0 · valor externo
> criado = 0 · E6 = 0/9**, e a frase que decide o registo desta rodada é a de
> sempre, com uma clause acrescentada: **cada porção de integridade obtida em
> P0–P4.5 é integridade e autoridade, não geração económica.** P4.5c tornou
> `inflows − outflows` computável e auditável — não move o critério 1, e
> aproximou `ARV0` de zero, porque nenhuma operação real deste host é
> promotevel: a carranca 1 da rodada P4.5 é precisamente que nenhuma operação
> **com gas** pode promover, e na Base toda transacção real queima gas.

## O que NÃO é prova

Itens que já foram tomados por validação neste projeto:

- **Multi-nó em loopback**: N processos, 1 máquina, 0 redes.
- **Servidor RPC mock** (`ThreadingHTTPServer`): prova o parser, não a chain.
- **Assinatura auto-assinada**: prova integridade do artefato local, não a
  honestidade de quem o executou — o próprio
  `docs/reports/P4_END_TO_END_HOMOLOGATION.md:135-136` diz exatamente isso.
- **IPv6 global (`2804:...`) apresentado como CGNAT**: IPv6 global não
  atravessa NAT.
- **Feature que só existe sob `cargo --features` não-default**: código não
  compilado não é código validado. *(O princípio permanece. A instância
  específica do veil deixou de se aplicar: desde a baseline de remediação as
  três suítes `veil_*` compilam e executam — 7 testes, todos verdes — sob
  `--features veil`. Ainda assim, `webrtc` compila e não contribui com nenhum
  teste, e a matriz de CI apenas faz `cargo check`: continuam sendo verdadeiras
  as duas frases seguintes.)*
- **Arquivo de teste cujos testes estão todos atrás de
  `#[cfg(feature = ...)]`**: não roda, logo não valida.
- **Contagem de testes citada em commit message**, sem comando e saída
  anexados.
- **Contagem de testes vinda de `cargo test … | tee log`**: reporta o exit
  status do `tee`, não o do cargo, e produz um verde falso. E sem
  `--no-fail-fast`, o cargo para no primeiro binário de teste que falha e
  esconde as falhas seguintes. Registado em detalhe em "Metodologia de
  medição".
- **Cadeia de hash apresentada como autenticidade.** `autonomy.rs:307-315`
  commita o registro inteiro, mas a cadeia não tem âncora externa, não tem
  assinatura e o génese é uma constante pública hardcoded
  (`autonomy.rs:23`). Detecta modificação-sem-recomputação; não detecta
  fabricação. Um ledger consistente consigo próprio pode ter sido escrito
  inteiro por um atacante.
- **`proof_verified: true` apresentado como prova de pagamento.** É um
  booleano persistido num ficheiro local, e a auditoria mostrou que ele pode
  ser obtido **sem forjar nada**, simplesmente conduzindo o verificador
  legítimo a falar com um endpoint escolhido pelo atacante. Enquanto a fonte da
  verdade for escolhível por quem chama, a assinatura do resto do trabalho é
  decorativa.
  *(Actualizado em P3: as três condições acima deixaram de ser suficientes,
  porque o booleano deixou de ser um insumo de autoridade. P2 fechou a segunda
  — a fonte deixou de ser escolhível por quem chama — e P3 fechou a primeira e a
  terceira, por via de tipos: `VerifiedNev` tem exactamente um sítio de construção
  no repositório, exige um provider identificado pelo kernel, e nenhum caminho
  económico lhe dá entrada. O booleano continua a ser legível em disco e em
  `autonomy-audit`, e continua a ser tudo o que é: um diagnóstico. Isto
  **reduz** a lista de coisas que seriam erro de raciocínio; não a apaga, porque
  `proof_verified` continua a ser um booleano persistido num ficheiro local.)*
- **Endpoint loopback apresentado como confine de segurança.** Loopback é um
  guard de transporte contra acesso remoto acidental num verificador read-only.
  Não é uma identidade: qualquer processo na máquina pode fazer bind na porta.
  P2 substituiu-o por um pin de Unix socket verificado pelo kernel, o que é
  estritamente mais forte — e o comentário em `base_usdc.rs:96-117` continua a
  dizer, corretamente, que nem isso derrota um atacante do mesmo principal.
- **Domaino de controlo ASSERTIDO num payload JSON.** `ControlDomain`
  (`boundary.rs:151`) é Serialize-only **de propósito**: um domínio que se pode
  ler de um ficheiro é um domínio que um escritor pode afirmar. `BoundaryEvidence`
  (`:234`) não tem campo de domínio, e o domínio só sai de um lookup contra um
  registry (`boundary.rs:214`). Isto não é estilo: é a correcção directa da
  falsificação.
- **Garantia de tipo lida como teste de compilação.** Que um
  `SyntheticAsset` não possa entrar num `BoundaryCrossing` é uma propriedade do
  sistema de tipos, não um `trybuild` compile-fail — não existe tal harness no
  crate. A afirmação correcta é "o compilador recusa"; a afirmação mais fraca e
  ainda verdadeira é "existe um teste que confirma em runtime". As duas coisas
  estão registadas em P1.
- **Assinatura de verificador apresentada como autenticidade** *(registado em
  P4)*. P4 liga uma política assinada por uma autoridade **pinada fora de
  banda** a receipts e settlements assinados pela chave que essa política
  delegou, e isso é um avanço real e verificável. Não é âncora externa, e é
  exactamente o mesmo raciocínio que o doc de `durability.rs:30-42` aplica ao
  `HeadAnchor`. Concretamente: o ledger de atestações vive em
  `~/.mycelium/economy/`, **sob o mesmo uid que o pode reescrever**; uma chave
  plantada em qualquer caminho legível é inerte, mas **qualquer** política que o
  pin autorize pode delegar a essa chave; **não há histórico de rotação nem lista
  de revogação**, logo uma política revogada continua aceite enquanto
  corresponder ao registry e ao provider vivos; e uma chave delegada **pode
  assinar qualquer coisa** sobre a evidência que lhe é entregue, incluindo uma
  transação fabricada — por desenho, porque a leitura de cadeia é o portão que
  prova que o verificador leu a cadeia. A frase exacta: **a assinatura prova
  proveniência, não existência, e não prova que ninguém reescreva o livro
  depois de o ter assinado.**
- **Trust root relocalizado apresentado como o default.** `MYCELIUM_TRUST_ROOT_DIR`
  é o opt-in explícito e o seu custo está nomeado no relatório de confiança, mas
  um trust root apontado para um directório que o principal invocante controla é
  um trust root desse principal. `/etc/mycelium/trust` (uid 0) não é criável
  neste host, e **é por isso que a assinatura recusa por omissão** — recusa não
  como omissão de implementação, mas como fail-closed.

## Contradições pendentes de reconciliação

1. **Status WAN do Veil.**
   `docs/veil/VEIL_ONION_ROUTING.md:5` diz "Status: Ativo / Homologado WAN";
   `docs/veil/VEIL_P12_WAN_FIELD_VALIDATION.md:1` diz "Homologação WAN física
   (pendente)". O segundo documento se autodesqualifica — "não é um certificado
   de segurança nem um resultado de campo" — e lista bloqueadores não
   corrigidos: os papéis `relay` e `exit` assinam `0.0.0.0:9050/9051`
   (endereço de escuta, não anunciável) como endpoint
   (`crates/mycelium-node/src/organism.rs`); e
   `VeilHopRouter::new()` usa `GhostId::spawn_quick(...)`, de modo que a
   identidade do nó muda silenciosamente a cada restart, o que invalida
   qualquer pin durável.

2. **Contagens de teste divergentes em `docs/reports/status.md`.** Quatro
   números diferentes para a mesma suíte:
   - `"137 passed, 0 failed"` (linha 15)
   - `"460 testes, 0 falhas"` (linha 18, contexto B.A.S.E.)
   - `"Mycelium **130/0**"` (linha 148)
   - `"Workspace default → **136/0**"` (linha 157)

   Contagem medida na árvore: 364 atributos de teste
   (`#[test]`/`#[tokio::test]`) em 92 arquivos, mais 10 arquivos de integração
   em `crates/*/tests/` totalizando 2.788 linhas. Nenhuma contagem publicada
   bate com isso, porque as seções misturam workspace BASE, workspace
   Mycelium, features não-default e arquivos `scratch_*` removidos.
   Primeira contagem medida na árvore e reproduzível, vinda da baseline de
   remediação: **308 passed / 0 failed / 1 ignored** no workspace default e
   **315 / 0 / 1** com `--features veil`. Nenhum dos quatro números acima
   continua valendo como estado atual.

   **Nova medição, depois de P0** (escopo explícito, para ser reproduzível:
   `grep -rE '#\[(tokio::)?test\]' --include='*.rs' crates/ platforms/ cli/`)
   → **456 atributos de teste em 96 arquivos**, mais **11 arquivos** de
   integração em `crates/*/tests/` totalizando **3.123 linhas** (eram 10 /
   2.788; o arquivo novo é `crates/mycelium-economy/tests/pinned_provider_cli.rs`).
   Estas duas contagens **não são diretamente comparáveis** às de 364/92/10/2.788:
   o escopo do comando antigo não está registrado em lugar nenhum, logo o
   delta não pode ser atribuído com honestidade. O que é comparável e é
   verificável: o crate `mycelium-economy` tem hoje 124 atributos `#[test]` em
   `src/` e 6 em `tests/`, ou seja 130, e ele passou a contar para
   `cargo test --workspace`.
   Os 308/0 e 315/0 da baseline **não** são o estado atual do workspace: o
   workspace passou a executar mais testes e **a execução completa não foi
   remedida**. E repare-se na coincidência que não deve ser confundida:
   `"Mycelium **130/0**"` em `status.md:148` e o `130 passed` medido em
   `mycelium-economy` são números iguais com escopos completamente diferentes.

   > **Atualização em P4 — este item continua exactamente tão aberto como
   > estava, e a situação piorou em magnitude.** A reconciliação de P0-P2 subiu
   > o número do crate para 130 e, depois, P3/P5 para 185; **P4 voltou a
   > subi-lo para 318**. Ao mesmo tempo, a contagem de workspace mais recente
   > publicada neste documento — **491/0/1** e **498/0/1** — foi medida **antes
   > de P4** e **não** foi remedida. Portanto, hoje: contagem do crate
   > `mycelium-economy` = **318** (medida, reconferida por atributos);
   > contagem de workspace = **não medida depois de P4**. Os quatro números de
   > `status.md` continuam a não bater com nada, e **nenhum número de workspace
   > pós-P4 é inventado aqui** para tapar o buraco. A lição desta lista é a
   > mesma das três rodadas anteriores: um placar com um número velho é um
   > registro desatualizado pode induzir a uma conclusão errada.

   > **Atualização em P4.5 — a contagem de workspace deixou de ser "não
   > medida" e foi medida, e os quatro números de `status.md` continuam errados
   > por uma margem maior.** Workspace: **698 / 0 / 0** no default e **705 / 0**
   > com `--features veil`, em 39 binários com testes. Crate
   > `mycelium-economy`: **390** (354 lib + 36 integração), reconferido por
   > contagem de atributos. Os **318** acima descrevem o estado **até** P4.5.
   > Os quatro números de `status.md` (137, 460, 130, 136) estão agora errados
   > por um factor de 3 a 5, e `docs/reports/status.md` **continua por
   > reconciliar** — este documento não edita esse ficheiro.

3. **`docs/reports/status.md` é um diário, não um relatório.** A seção
   "Concluído nesta sessão" aparece cinco vezes (linhas 124, 211, 255, 280,
   312) e existem dois blocos de roadmap — "## Roadmap" (linha 110) e "###
   Próximos passos sugeridos" (linha 203) — ambos quase inteiramente
   checkmarked. Um roadmap com tudo marcado não é um roadmap: não há
   trabalho restante listado.

4. **Duplicata byte-idêntica.** `EVOLUCAO.md` e `PLANO_EVOLUCAO_MYCELIUM.md`
   têm os mesmos 8.322 bytes.

5. **`EVOLUCAO.md` descreve outro repositório.** Abre, em "Escopo real deste
   pacote", com "O arquivo fornecido contém somente `crates/`; **não** contém
   o `Cargo.toml` raiz" — falso para a árvore atual. É uma nota de passagem de
   mão para um tarball externo. O commit `1b262b9`
   ("chore: remover diretorios legados obsoletos") descompactou/apagou a árvore
   e deixou `mycelium-evolucao-crates.tar.gz` versionado.

6. **Criptografia declarada ≠ criptografia implementada.** README afirma
   ML-KEM-768 (`README.md:125,143`); o código só tem `MlKem1024`
   (`crates/mycelium-pqc/src/lib.rs:7,43`). X25519 é descrito em três
   documentos (`docs/architecture/CRATES_REFERENCE.md`,
   `docs/veil/VEIL_ONION_ROUTING.md`, `crates/mycelium-pqc/README.md`), mas
   nenhum crate `x25519` aparece em qualquer `Cargo.toml` do workspace.

7. **Três versões conflitantes.**
   `docs/architecture/ARQUITETURA_GERAL_SISTEMICA.md:3,5` — `0.2.0-Sovereign`
   e "Status: Ativo / Em Produção"; `Cargo.toml:37` — `version = "0.1.0"`;
   `docs/DOCUMENTACAO_COMPLETA.md:4` — `0.1.0-alpha`.

8. **Links quebrados em `docs/README.md`.** Na seção COSMIC (linhas 41-44),
   dois dos três links omitem o prefixo `cosmic/` e portanto não resolvem a
   partir de `docs/`: `cosmic-design.md` e `cosmic-bridge.md`, que existem
   apenas como `docs/cosmic/cosmic-design.md` e
   `docs/cosmic/et-cosmic-bridge.md`. O terceiro link está correto.

9. **Rótulos de commit mais fortes que o texto.** Na branch
   `feature/mycelium-base-rpc-pqc`, o commit `c8d9c7c`
   ("docs(rpc): mark P1/P2 homologated and use scoped regression gate") removeu
   de `docs/MYCELIUM_BASE_RPC.md` o requisito "Não declarar a malha RPC
   operacional até P1-P3 estarem integrados e testados em pelo menos dois
   hosts reais" e o substituiu por um smoke em loopback contra servidor mock.
   A documentação continued honesta; o rótulo no commit ficou mais forte que a
   evidência.

10. **O pin de verdade do reconciliador S1 vive fora da cadeia de hash, sem
    assinatura.** `s1-outcome-policy.json` (`s1_outcome.rs:76`) fixa o
    endereço do executor contra o qual cada reconciliação é validada
    (`s1_outcome.rs:249` carrega, `:315-318` recusa qualquer `tx_to`
    diferente). O ficheiro não é comitado na cadeia, não é assinado e é
    sobrescrevível por quem tem escrita no `$HOME`. Um pin que pode ser trocado
    sem deixar rasto na cadeia não é um pin. P2 trata isto ao nível do
    **provider** (pin de Unix socket verificado pelo kernel); o **pin de
    política** continua por tratar, e é o item 2 de "O que permanece aberto"
    que lhe dá a prioridade correcta.

    > **Atualização — este item estava certo, e P4 é a fase que o fecha. A
    > frase "o pin de política continua por tratar" deixou de valer; a análise
    > de fundo permanece, e as citações de linha abaixo deslocaram-se.** O pin
    > da política de resultado passou a ser **assinado** por uma
    > `PolicyAuthorityKey` cuja chave pública tem de resolver a partir de
    > `/etc/mycelium/trust/policy-authority.pub`, **fora do directório mutável
    > da economia** (`policy_auth.rs:99`), com validação de identidade em dois
    > estágios (`lstat`, depois `fstat` sobre o descritor aberto, porque
    > `open(2)` segue symlinks). E a regra central é imposta e testada: **a chave
    > que autoriza uma política não está dentro da política** —
    > `the_gland_trap_a_self_signed_policy_is_rejected` (`policy_auth.rs:2188`)
    > recusa com `AuthorityNotPinned`. Um pin que pode ser trocado sem deixar
    > rasto continua a não ser um pin; o que mudou é que a troca passou a exigir
    > substituir também o pin fora do `$HOME` **e** servir uma política assinada
    > por uma chave privada de autoridade que não está no repositório.
    >
    > **O que P4 não fechou, e é o que fica deste item:** sem rotação de
    > políticas e sem lista de revogação, uma política previamente válida
    > continua aceite enquanto corresponder ao registry e ao provider vivos
    > (item 2 das carranças de P4); e o pin de **provider** de P2 é uma exposição
    > separada que P4 não desfaz — quem controla o socket identificado pelo
    > kernel controla a verdade. As citações deste item
    > (`s1_outcome.rs:76`, `:249`, `:315-318`) estão em `:85`, `:137`, `:315-317`
    > na árvore actual; ver a tabela de correcção de citações da rodada P4.

11. **O ledger de autonomia continua sem qualquer verificação de leitura.**
    `AutonomousEconomy::records()` (`autonomy.rs:332-379`) verifica sequência,
    `prev_hash` e `record_hash` — e é isso. Não re-executa
    `validate_external_value()` e não prova estado on-chain. Combinado com o
    facto de `record_external_value` (`autonomy.rs:565`) continuar a ser um
    caminho aberto e não tipado, a cadeia é verificável contra **si própria** e
    nada mais. Está registrado como limitação estrutural em "O modelo de
    ameaça que não estava escrito", e não como bug a corrigir: ser indecidível
    localmente não é uma falha de implementação.

    > **Atualização — este item deixou de valer tal como está escrito, e é
    > preciso ser exacto sobre o que mudou e o que não mudou.** A frase
    > "`records()` … é isso" **continua verdadeira**: `records()`
    > (`autonomy.rs:394-426`) ainda verifica só sequência, `prev_hash` e
    > `record_hash`, mais a recuperação da cauda partida e a âncora de cabeça —
    > e continua a **não** re-executar a validação e a **não** provar estado
    > on-chain. O que mudou é que essa limitação deixou de ser a **última linha**:
    > P3addediu uma camada acima que faz as duas coisas, e nenhum caller
    > económico pode ficar por ela. `revalidate_external_value`
    > (`autonomy.rs:1158`) re-executa as regras de escrita na leitura, incluindo
    > `gross − cost`, sem consultar o `proof_verified` armazenado; e
    > `VerifiedEconomyView` acrescenta a leitura de cadeia atrás de um provider
    > identificado pelo kernel. **O que continua exactamente igual** é a
    > limitação de fundo: a cadeia continua verificável contra **si própria** e
    > nada mais; a prova on-chain continua a depender de uma fonte externa; e
    > `record_external_value` (`autonomy.rs:686`) continua a ser um caminho
    > aberto e não tipado, ao lado de `record_external_value_with_crossing`
    > (`autonomy.rs:785`) que é o caminho tipado e que continua **opcional**.
    > Ver também a nota à limitação estrutural correspondente em "O modelo de
    > ameaça que não estava escrito", ponto 3, que se mantém de pé.
    >
    > **Actualização em P4 — o mesmo limite estrutural, nas mesmas palavras.**
    > As citações desta nota deslocaram-se para `autonomy.rs:485-517`
    > (`records()`), `:777` (`record_external_value`), `:1021`
    > (`…_with_crossing`) e `:1394` (`revalidate_external_value`, com o
    > invariante `gross − cost` em `:1407-1413`). **O fundo não mudou:** a
    > cadeia continua verificável contra si própria e nada mais; o génese
    > continua a ser uma constante pública; e `record_external_value` continua a
    > ser um caminho aberto e **opcional**. O que P4 acrescenta por cima disto é
    > uma assinatura de autoridade que exige uma identidade **externa**, e é
    > precisamente por isso que esta limitação não desapareceu: um atacante do
    > mesmo principal continua a poder escrever o ficheiro — o que P4 impede é
    > que a sua escrita **conte**.

12. **Contagem de testes do workspace sem reexecução após P0.** Ver item 2
    acima: o crate entrou no workspace, mas `cargo test --workspace` não foi
    remedido, logo nenhuma contagem do workspace na árvore atual está publicada
    neste documento. Um documento de placar que só tem números velhos para a
    suíte que acabou de crescer de 58 para 130 testes é, ele próprio, um item
    desta lista.

    > **Atualização — fechado.** `cargo test --workspace --locked
    > --no-fail-fast` foi reexecutado: exit 0, **491 passed / 0 failed / 1
    > ignored** em 74 binários; com `--features veil`, exit 0, **498 / 0 / 1**.
    > A contagem do crate `mycelium-economy` é **185** (163 lib + 10
    > `ledger_durability` + 6 `pinned_provider_cli` + 6 `verified_view_cli`),
    > reconferida por contagem de atributos e não só pelo runner. Item 2 acima
    > deixa de ser um item e passa a ser história.
    >
    > **Actualização em P4 — este item reabre, e a reabertura é o registo
    > honesto.** O "fechado" acima era verdade **até** P4. P4 acrescentou **133**
    > testes ao crate `mycelium-economy`, que passou de **185** a **318**, e
    > `cargo test --workspace --locked --no-fail-fast` **não** foi reexecutado
    > depois disso. Logo: **contagem de workspace pós-P4 = não medida**, e este
    > documento deliberadamente **não** publica um número para ela. O item
    > reabre pelo mesmo motivo pelo qual existiu da primeira vez: um documento
    > de placar que só tem números velhos para a suíte que acabou de crescer de
    > 185 para 318 é, ele próprio, um item desta lista. O que **é** medido e
    > publicado é a contagem do crate (282 lib + 36 integração = **318**),
    > reconferida por contagem de atributos.

## Status da telemetria e do isolamento (corrigido nesta rodada)

Correções feitas em código nesta rodada, registradas aqui para que o leitor
não as encontre inesperadas:

- **`mycelium-veil`** — `VeilStatus.active_layers` reportava um `7` fixo
  (hardcoded) enquanto a `LayerPipeline` (`crates/mycelium-veil/src/layers/`,
  1.134 linhas em 8 módulos) é exercitada apenas por testes: o tráfego usa
  `crates/mycelium-veil/src/planes/live.rs` + `bridge.rs`. Passa a reportar a
  contagem realmente conectada (0) e `layers/mod.rs` ganhou um banner de
  status. O módulo é mantido de propósito, não é lixo.
- **`mycelium-zkp`** — `range_proof::prove_range` / `verify_range` faziam
  `panic!` via `unimplemented!()` no build default, exatamente no caminho que
  `mycelium-veil` compila. Agora retornam `Result<_, ZkpError>` com
  `RangeProofDisabled`.
- **`mycelium-store` / `mycelium-veil`** — `std::sync::Mutex.lock().unwrap()`
  em handlers async ( envenenamento por pânico derrubava o handler) trocado
  por tolerante: `unwrap_or_else(|e| e.into_inner())`.
- **`vacuum`** — `fail_closed` agora é default `true`; `bwrap` ausente
  retorna `VacuumError::IsolationUnavailable` em vez de silenciosamente gerar
  processo sem sandbox. `MYCELIUM_FAIL_CLOSED=0` passou a ser opt-out
  explícito e logado em `warn` (`crates/vacuum/src/process.rs:42-56`).
- **CI / toolchain** — `rust-toolchain.toml` fixado em `1.88.0`, o piso
  medido do grafo resolvido (`time 0.3.53` é a restrição vinculante). Adicionado
  pipeline de feature-matrix porque `cargo test --workspace` sozinho nunca
  compila os caminhos veil/license/bolt11/nostr/pqc — há 111 blocos
  `#[cfg(feature = ...)]` em `crates/` (127 incluindo `cli/`), e os três
  arquivos de aceitação do veil em `crates/mycelium-node/tests/`
  (`veil_data_path_security.rs`, `veil_p1_3_2_acceptance.rs`,
  `veil_socks5_integration.rs` — 930 linhas) estão inteiros atrás de
  `#[cfg(feature = "veil")]`. Desde a baseline de remediação esses três
  arquivos **compilam e executam** (1 + 2 + 4 testes, todos verdes) sob
  `--features veil`; ver "Baseline de remediação — verificado" acima.
- **`mycelium-store` + `mycelium-node`** (esta rodada) — sobre o mesmo
  `Arc<Mutex<StoreCatalog>>` que ficou tolerante a envenenamento no bullet
  anterior, os dois caminhos de aquisição passaram a ser fail-closed: o
  recovery tolerante permanece onde o estado não é fronteira de segurança
  (wrappers de handler), mas `launch_spore_handler` (HTTP) e `StoreLaunch`
  (daemon) agora chamam `StoreCatalog::validate()` em toda aquisição — 6 sites
  no store, 3 no daemon — e `CatalogError::Poisoned` recusa. A correção
  anterior e esta são complementares, não em conflito.
- **`mycelium-veil`** (esta rodada) — `VeilError::Poisoned` adicionado;
  `route()` reestruturado para rodar `pipeline.process()` antes do lock de
  sessão, eliminando a única seção crítica com risco de pânico; `PoolTelemetry`
  consolida quatro mutexes em um, para que o snapshot não possa rasgar.
- **`vacuum`** (esta rodada) — `spawn_bwrap` resolvia o binário do nó por
  `spec.mycelium_bin` mais quatro caminhos fixos, dois relativos ao CWD, e
  `cargo test` define o CWD como a raiz do pacote: os caminhos relativos à
  raiz do workspace não achavam nada. Ordem de resolução explícita e âncora em
  `current_exe()` em vez de CWD. 7 testes herméticos novos cobrem a
  precedência, incluindo o caso de um binário obsoleto no `PATH`
  (`/home/bruno/.local/bin/mycelium`) que sombreava o build da árvore em
  silêncio.

Feature-matrix: **executado localmente nesta rodada**, e verde — as 8 features
compilam limpas, incluindo `webrtc` e `range-proof`, que tinham previsão
anotada de falha. Isso muda o que o pipeline mede, não o quanto ele bloqueia.

Ressalva mantida: o pipeline de feature-matrix continua sendo
`allow_failure: true` (`.woodpecker.yml:88-90`) e `continue-on-error: true`
(`.forgejo/workflows/validate.yml`). Ele **reporta, não bloqueia**. Verde nesse
pipeline ainda não é gate.

Ressalva nova, e ela é séria: mesmo quando o feature-matrix ficar verde, o job
da CI roda `cargo check`, **não** `cargo test`. Ele passaria a *compilar* as
suítes veil e continuaria **sem executá-las**. Para que a baseline de remediação
seja sustenta por CI, o job precisa rodar `cargo test --features veil`.

`/dev/sda2` em 98% com ~12 GB livres e `target/` em 103 GB limitam builds a
frio futuros.

> **Atualização — resolvido.** `/dev/sda2` está em 74%, 109 GB livres; 104 GB
> devolvidos. Ver "Verificação desta rodada" na seção "Rodada P0–P2".
>
> > **Nova medição, depois de P3 e P5:** `/dev/sda2` em **77%**, **97 GB
> > livres**, e `target/` com **20 GB** (as execuções de verificação desta rodada
> > voltaram a compilar o que era preciso). A folga que o housekeeping devolveu é
> > **folga**, não um `target/` permanentemente vazio: é assim que se deve ler o
> > número. Build a frio continua a ser seguro nesta máquina; o que deixou de ser
> > verdade é que haja 109 GB.

Nenhuma dessas correções muda os níveis (b), (c) ou (d). Elas fecham lacunas de
verdade de código; a lacuna de topologia continua inteira.

## Próximo gate: de (a) para (b)

Ordem concreta. Não é nova arquitetura; é execução.

1. ~~**Build com `--all-features` e deixar verde.**~~ **FEITO.**
   `cargo check --workspace --all-targets --locked` e o sweep `veil` saíram
   com exit 0; as ~918 linhas de aceitação do veil em
   `crates/mycelium-node/tests/` executaram de fato (7 testes, verdes) sob
   `--features veil`. A saída está registrada em "Baseline de remediação —
   verificado".
2. **Clippy em `-D warnings` verde.** Hoje 200 avisos distintos (216 com
   `veil`), `cargo clippy --workspace --all-targets --locked -- -D warnings`
   sai com 101. Enquanto este passo é bloqueante em
   `.forgejo/workflows/validate.yml`, o job não pode passar. É dívida puramente
   mecânica — o topo da lista (`uninlined_format_args` 94, `useless_format` 36)
   é um commit de formatação.

   > **Atualização — o número subiu e o bloqueio é o mesmo.** Medido depois de
   > P3 e P5: **218 avisos distintos em 39 lints**, dos quais 18 em
   > `mycelium-economy` e 197 nos restantes crates. Topo: `uninlined_format_args`
   > **101**, `useless_format` **37**, `ptr_arg` 10, `io_other_error` 9.
   > Continua a sair com **1** sob `-D warnings`, continua bloqueado em
   > `.forgejo/workflows/validate.yml`, e **nada foi corrigido**.
   >
   > Isto é, hoje, **o bloqueio concreto e nomeado** da CI. A afirmação acima
   > continua exacta no que estruturalmente importa — dívida mecânica, não
   > dívida de desenho — mas o número que ela dá ficou velho em +18 avisos.
   >
   > **Nova medição, depois de P4.5: 232 avisos distintos em 41 lints.** Foi
   > remedido, não estimado: 414 diagnósticos emitidos em 36 alvos, 182 deles
   > marcados como duplicados pelo próprio cargo. Topo: `uninlined_format_args`
   > **181**, `useless_format` **73**, `ptr_arg` **20**, `io_other_error` **18**,
   > `redundant_closure` **10**, `too_many_arguments` **8**, `collapsible_if`
   > **8**. **Nada foi corrigido.** A concentração diz o que a dívida é: 64
   > sítios em `crates/mycelium-node/src/organism.rs`, 52 em
   > `cli/mycelium-cli/src/main.rs`, 17 em `crates/mycelium-hyphae/src/lib.rs` —
   > e, dentro de `mycelium-economy`, 7 em `verified_view.rs`, 5 em
   > `event_id.rs`, 3 em `settlement_auth.rs`, 2 em `boundary.rs`, 2 em
   > `receipt_auth.rs`. A dívida de clippy que P4.5 introduziu é, portanto,
   > quase toda **pré-existente e de outros crates**, e o bloqueio é o mesmo
   > que era: o passo `-D warnings` da CI não passa.
3. **Fazer a CI *executar* as suítes veil, não apenas compilá-las.** O
   feature-matrix faz `cargo check`. Enquanto isso não virar `cargo test`, a
   baseline de remediação é um fato local e não uma garantia reproduzível — e
   uma regressão em segurança só apareceria depois de um merge.

   > **Atualização em P4 — executam agora, e continuam a não bloquear.** Existe
   > um passo de veil que corre
   > `./scripts/ci-test-gate.sh "veil acceptance suites" --min-tests 450
   > --expect-test veil_socks5_integration --expect-test
   > veil_data_path_security --expect-test veil_p1_3_2_acceptance --workspace
   > --features veil --locked` em **ambos** os ficheiros de CI
   > (`.woodpecker.yml:159`, `.forgejo/workflows/validate.yml:156`), e ele é um
   > `cargo test --workspace --features veil` a sério — as três suites de aceitação
   > **executam**, e os três `--expect-test` afirmam que executaram de facto.
   > Portanto a primeira frase deste item ("fazer a CI *executar*") está
   > **cumprida**. **A ressalva que decide o item continua intacta:** o passo
   > vive dentro do pipeline `feature-matrix`, que é `allow_failure: true` no
   > Woodpecker e `continue-on-error` no Forgejo. Verde ali **reporta, não
   > bloqueia**. Uma regressão de segurança nas suites veil continua a poder
   > passar um merge. Promover esse pipeline a bloqueante continua por fazer, e
   > é a razão de o gate existir sem estar ligado a um portão.
4. ~~**`mycelium-economy` dentro de `[workspace]`.**~~ **FEITO (P0).**
   Texto original deste item, preservado: "Hoje são 58 testes verdes em zero
   execuções de CI, por causa da linha `[workspace]` em
   `crates/mycelium-economy/Cargo.toml:9`. O código compila e passa; só o
   registro de execução está errado." Isso descreveu o estado **até** P0. A
   tabela `[workspace]` foi removida de
   `crates/mycelium-economy/Cargo.toml:8-9` e o crate entrou em `Cargo.toml:34`;
   os 58 testes passaram a ser vistos por `cargo test --workspace` e, com P1 e
   P2, são **130** (124 lib + 6 integração CLI),
   `cargo test -p mycelium-economy --locked` exit 0, `Cargo.lock` diff
   **+16/0**.

   > **Atualização — o número do crate subiu outra vez.** Com P3 e P5 são
   > **185** (163 lib + 10 `ledger_durability` + 6 `pinned_provider_cli` + 6
   > `verified_view_cli`), e `cargo test --workspace --locked --no-fail-fast`
   > mede **491 passed / 0 failed / 1 ignored** em 74 binários. Os 130 acima
   > descrevem o estado **até** P3.
   >
   > **Atualização em P4 — o número subiu outra vez, e o número de workspace
   > ficou velho pela segunda vez.** Com P4 o crate é **318** (282 lib + 10
   > `ledger_durability` + 6 `pinned_provider_cli` + 7 `verified_view_cli` + 13
   > `signing_cli`), `cargo test -p mycelium-economy --locked --no-fail-fast`
   > exit 0. Os **491** acima **não** foram remedidos depois de P4 e descrevem o
   > estado **até** P4; a contagem de workspace pós-P4 é **não medida** e não é
   > publicada. O `Cargo.lock` também não é o de P0: o crate declara hoje
   > `ed25519-dalek.workspace = true`
   > (`crates/mycelium-economy/Cargo.toml:23`) e o lockfile lista-o entre as suas
   > dependências, que já não são as nove de P0. O número exacto do diff de
   > lockfile de P4 **não foi medido** e não é publicado aqui.
   >
   > **Atualização em P4.5 — a contagem de workspace deixou de ser "não
   > medida", e foi remedida como deve ser.** Os **318** acima descrevem o
   > estado **até** P4.5, e os **491** que lhes antecedem descrevem o estado
   > **até** P4. Medido agora, com `--locked --no-fail-fast` e
   > `${PIPESTATUS[0]}`:
   >
   > | Comando | Exit | Resultado |
   > | --- | --- | --- |
   > | `cargo test -p mycelium-economy --locked --no-fail-fast` | 0 | **390** (354 lib + 36 integração) |
   > | `cargo test --workspace --locked --no-fail-fast` | 0 | **698 / 0 / 0 ignorados**, em 39 binários com testes |
   > | `cargo test --workspace --features veil --locked --no-fail-fast` | 0 | **705 / 0** — delta exactamente **+7** |
   >
   > A composição dos 390 foi reconferida por contagem de atributos de teste e
   > não só pelo runner: 354 em `src/`, mais 10 + 6 + 13 + 7 nos quatro
   > binários de integração. Os dois caminhos concordam. Delta do crate contra
   > P4: **318 → 390**, isto é **+72**, dos quais 57 em três módulos novos
   > (`boundary_delta.rs` 20, `event_id.rs` 16, `settlement.rs` 21).
   >
   > O item 4 está **cumprido desde P0** e o número acima é a medição
   > corrente. O item, nesse sentido, fecha; o que **não** fecha é o registo de
   > execução: o piso do gate (`--min-tests 170` para o crate) é
   > deliberadamente abaixo da medição, e a execução que este placar publica é
   > local, não um artefacto de CI.
5. **gate-b verde** (`community_service_survival_acceptance`), terceiro passo
   bloqueante ainda em falha em `.forgejo/workflows/validate.yml`.
6. **Uma entrada ativa em `seeds/mainnet.txt`**, a partir de um host com
   inbound verificado (`./scripts/verify-sporocarp.sh`). Hoje: zero.
7. **Dois nós, duas máquinas físicas, ISPs diferentes.** Medir uptime, latência
   p95 e tempo de recuperação, e anexar os logs.
8. **Quatro nós; matar um relay** e medir se a malha sobrevive e por quanto
   tempo.
9. **E6 itens 1, 3, 4, 6 e 9** — o subconjunto mensurável — assinados com uma
   chave de contraparte.

Os itens 2 a 5 são hygiene de CI e não movem o placar em nada. Os itens 6 a 9
são os únicos que mexem em (b), (c) e (d). Nenhum item desta lista, e nenhuma
execução local, substitui host físico.

### Em paralelo, e acima de tudo isso: a sequência de integridade P3–P7

A lista acima é o caminho para (b). Esta é o caminho para **o ledger deixar de
ser uma afirmação**. Ela não substitui a anterior e não a antecipa: são
independentes, e ambas são necessárias. A ordem é a acordada, e a razão de
ser P3 primeiro é direta: enquanto ARV, RV, NEV e reinvestimento puderem ser
derivados de um booleano armazenado, nenhuma das outras cinco fases importa.

**Estado da sequência depois de P3 e P5: a ordem restante é P4 → P6 → P7**, e
depois dela o trabalho físico de E6, que nada em P0–P5 toca nem se aproxima de
tocar. "Independentes" não quer dizer "uma espera pela outra": quer dizer que
nenhuma das duas substitui a outra. Um ledger incontestável num host só continua
a ser um ledger num host só.

> **Atualização — P4 está entregue, e a frase acima passou de "ordem
> restante" a "ordem preenchida".** O estado real da sequência é **P3 feito, P5
> feito, P4 feito**; a ordem restante passou a ser **P6 → P7**, e depois dela o
> trabalho físico de E6. A observação do parágrafo acima **não** deixou de
> valer: um ledger agora autenticado num host só continua a ser um ledger num
> host só. P4 tornou a afirmação mais difícil de falsificar; não a tornou
> verificável por fora.

> **Atualização em P4.5 — a ordem restante passa a ser P6 → P7, e a frase "P4
> também não é a fase que vem a seguir" fica resolvida pelo lado que
> importava.** P4.5 entregou a **simetria entrada/saída**, que era o item
> concreto que P4 tinha deixado escrito como anterior a P6, e portanto a ordem
> preenchida é **P3, P5, P4, P4.5** e a ordem restante é **P6 → P7**, seguida do
> trabalho físico de E6. A observação que o parágrafo acima faz continua inteira
> e vale para P4.5 como valeu para P3, P5 e P4: um ledger cuja identidade de
> evento é canónica **num host só** continua a ser um ledger num host só. O que
> P4.5 comprou é a correcção de um erro aritmético real — uma perna isolada
> podia promover um falso lucro — e uma identidade de facto externo, que é o que
> impede que um facto se conte duas vezes. Nenhuma das duas é verificação
> externa.

1. ~~**P3 — `VerifiedEconomyView`.**~~ **FEITO.** Texto original deste item,
   preservado: "ARV, RV, NEV e a decisão de reinvestimento têm de **re-derivar
   de evidência verificada** a cada leitura, para que nenhum booleano gravado
   conceda autoridade. É o item que fecha o ataque de ledger falsificado, que
   continua vivo. Requer resolver os dois pontos de decisão abertos: o outflow que
   nunca lança receipt (`boundary.rs:1258`) e a ligação de S1 ao crossing
   (`with_verified_proof` exige `receipt.proof_hash == crossing.tx_hash`, e o
   adaptador S1 cita um hash de receipt S1). O último tem custo: acrescentar um
   campo a `ExternalValueReceipt` muda **todo** hash já armazenado." Isso
   descreveu o estado **até** P3. Entregou-se em
   `crates/mycelium-economy/src/verified_view.rs`; o ataque de ledger falsificado
   está fechado para ARV, RV e o orçamento de reinvestimento; a ligação de S1
   foi pela **opção (a)**, sem campo novo; e o custo do hash já armazenado não
   foi pago — mudaram-se os `record_hash` dos registros **novos**, e nada em disco
   foi reescrito. O ponto do outflow **não** foi resolvido e continua um **ponto
   de decisão** aberto, não uma omissão.
2. ~~**P4 — política e receipts autenticados.**~~ **FEITO.** Texto original
   deste item, preservado: "Chave de verificador pinada, política assinada,
   `policy_hash` dentro do receipt. Registado explicitamente para não ser mal
   entendido: isto **não** é uma chave auto-descrita do tipo `Gland`. Uma chave
   que se descreve a si mesma e vive no mesmo `$HOME` não é uma fonte de
   identidade — é o mesmo atacante com um campo a mais. **A chave de
   verificador pinada não viaja dentro do corpo assinado.**" Isso descreveu o
   estado **até** P4. Entregou-se em quatro fases:
   - **P4a** (`policy_auth.rs`) — dois papéis de chave, âncora pinada em
     `/etc/mycelium/trust/policy-authority.pub`, validação `lstat` + `fstat`,
     preimage em bytes determinísticos sob `MYCELIUM-ECONOMY/POLICY/V1`, e a
     regra central **testada**: a chave que autoriza uma política não está
     dentro da política.
   - **P4b** (`receipt_auth.rs`) — `AuthenticatedExternalValueReceipt` com
     cinco campos privados e `verify()` **sem parâmetro de chave**; o
     `VerifyingKey` mais próximo do exterior é `pub(crate)` e pertence a um
     `TrustedVerifierKey` com um único construtor; `verifier_key_id` e
     `receipt_hash` no preimage.
   - **P4c** (`settlement_auth.rs`) — **a receita estava sem assinatura**, e essa
     era a assimetria real: autonomia exigia assinatura, receita não. Fechada,
     com separação de domínios provada e com o `SettlementReceipt` **sem
     campo novo**, para que os ledgers antigos re-serializem byte a byte.
   - **P4d** (`verifier_key_store.rs` + `tests/signing_cli.rs`) — sem isto, nada
     do resto era alcançável pela CLI: `load_outcome_policy` tinha o pin
     hardcoded em `/etc/mycelium/trust` (uid 0, não criável neste host) e
     **nenhuma política validava pela CLI**. Uma raiz de confiança segura agora
     as duas metades — pin e chave — e não podem ser configuradas em separado.
   O aviso do item original sobre `Gland` foi honrado e testado, e a diferença
   em relação ao padrão `Gland` do próprio projecto está nomeada com citação:
   `PheromoneBody` (`crates/mycelium-pheromones/src/lib.rs:149-151`) transporta
   `identity: [u8; 32]` dentro do corpo assinado.
3. ~~**P5 — durabilidade do ledger.**~~ **FEITO, com uma ressalva que é o
   próprio item.** Permissões `0700`/`0600`, deteção de truncamento e lock
   exclusivo foram entregues em `crates/mycelium-economy/src/durability.rs`. Mas o
   itemoriginal prometia **`flock`** e **uma âncora externa de cabeça**, e nenhuma
   das duas foi entregue, porque nenhuma das duas é o que este código faz:
   - **`flock` foi substituído** por uma sentinela `O_CREAT|O_EXCL` com vitalidade
     lida de `/proc`. A alternativa `UnixListener` foi implementada primeiro e o
     teste do implementador provou-a errada — a vitalidade de um socket e a sua
     posse são objectos diferentes e o kernel trocá-los-á entre syscalls. O que
     falta é o **lock advisory do kernel**, e ele exige uma dependência nova.
   - **A âncora externa de cabeça não foi entregue, e não é um bug: é
     impossível localmente.** O que existe é uma âncora em ficheiro separado, que
     o próprio doc do módulo chama *alarme, não prova*, porque vive sob o mesmo
     uid e o mesmo diretório que o ledger que protege. Um contador selado em
     TPM, um segundo host, um quórum de assinaturas ou um log de transparência
     publicado exigem **dependência externa e contraparte externa**, ambos fora
     do âmbito.
   A honestidade do item original — "as três primeiras não derrotam um atacante
   do mesmo principal; só a âncora externa derrota" — **mantém-se inteira**, e
   agora está escrita no código com o mesmo spirit: as três primeiras não
   derrotam; só a externa derrota; e a externa não foi feita.
4. **P6 — máquina de estados `NO_EDGE` e rotação de `OpportunityClass`.**
   > **Pré-condição que P4 deixou escrita, e que é mais concreta do que
   > "quando houver tempo":** o próximo item de P4 não é P6, é a **simetria
   > entrada/saída**. `BoundaryCrossing` deriva `ExternalToControlled` como
   > +valor e não existe `ControlledToExternal` = −valor, portanto uma perda
   > externa continua impossível de atestar e
   > `NEV = ΣVerifiedInflows − ΣVerifiedOutflows` **não é computável**. Sem
   > isso, qualquer `SearchHealth` vectorizado por `OpportunityClass` seria
   > calculado sobre metade da realidade económica. Isto deve preceder P6, ou
   > ser absorvido por ela — mas não pode ser pulado, e é a razão de a lista de
   > carranças de P4 o marcar como "próximo item concreto".
   >
   > **Atualização em P4.5 — a pré-condição foi cumprida, e P6 fica desbloqueado
   > numa base que antes não existia.** A simetria entrada/saída está entregue
   > (`boundary.rs:335-340` com os dois sentidos, sinal derivado em
   > `boundary.rs:356-361`; agregação em `settlement.rs`), e
   > `NEV = ΣVerifiedInflows − ΣVerifiedOutflows` é computável sobre uma
   > operação **completa**. A afirmação do texto original acima — que qualquer
   > `SearchHealth` vectorizado por `OpportunityClass` seria calculado sobre
   > metade da realidade económica — **deixou de valer, e é corrigida aqui em vez
   > de ser apagada**.
   >
   > E o que P4.5 acrescenta a este item é mais do que a subtração: o sistema
   > passou a distinguir **`NO_COMPLETE_SETTLEMENT` de `NEGATIVE_NEV`**, porque
   > uma operação incompleta *não tem* líquido e uma operação completa negativa
   > tem líquido negativo, e antes de P4.5 as duas condições eram o mesmo zero.
   > `SearchHealth` precisa exactamente dessa distinção, e sem ela o vector
   > mediria "nada a fazer" sem distinguir "não li o suficiente" de "li e o
   > mercado não paga". É essa a base sobre a qual P6 passa a ser o próximo
   > item — com a ressalva honesta de que hoje **nenhuma operação real é
   > promotevel** (carranca 1 da rodada P4.5), pelo que o que P6 vai vectorizar
   > é, para já, sobretudo o caminho de recusa.
5. **P7 — Synthetic Ledger.** Continua diferido, e a razão de continuar diferido
   ficou mais específica depois de P3: `ConversionEfficiency` **não tem
   denominador** antes de existir valor externo medido, e P3 não criou valor
   externo — criou avia de o confirmar.

   > **Atualização — P4 não mudou esta razão; tornou-a mais dura.** P4 também
   > não criou valor externo — criou **via para confirmar que o valor é real**.
   > `ConversionEfficiency` continua sem denominador, e a assinatura de
   > atestação não é um denominador: é uma condição para que o denominador
   > possa um dia existir. O diferimento de P7 mantém-se.

**A identidade de verificação acordada** é
`TrustedNEV = VerifyChain(VerifyPolicy(DeriveBoundary(Evidence)))`. Cada
palavra conta, e a ordem conta mais:

- `DeriveBoundary(Evidence)` — o domínio é **derivado** por lookup contra um
  registry, nunca afirmado por quem escreve (P1, já feito).
- `VerifyPolicy(...)` — a política que fixa a fonte é ela própria verificada,
  não um ficheiro sobrescrevível (P4, pendente).
- `VerifyChain(...)` — o estado on-chain é provado no momento da leitura, e
  não lido de volta de um registo (P3, **feito**: o quarto portão em
  `verified_view.rs:763-807`).

> **Atualização — `VerifyPolicy` deixou de estar pendente, e a identidade ganhou
> um passo pelo caminho.** A identidade escrita no código hoje é
> `VerifiedNev = VerifyChain(DeriveBoundary(VerifyReceiptSig(VerifyPolicy(Evidence))))`
> (`verified_view.rs:7`): P4b **acrescentou** `VerifyReceiptSig` entre
> `VerifyPolicy` e `DeriveBoundary`, sem reordenar o resto — a leitura de cadeia
> continua o passo mais externo, que é a propriedade que P3 comprou. A citação
> `verified_view.rs:763-807` deslocou-se para `verified_view.rs:740-775`; ver a
> tabela de correcção de citações da rodada P4. Uma correção de ordem que vale
> registo: **a derivação da fronteira tem de vir antes da leitura de cadeia**,
> porque `verify_transfer` consome o crossing derivado `(tx, payee, amount)`.

E o que esta identidade **não** é, dito de forma tão explícita quanto o resto
deste documento: **nunca é `receipt.proof_verified`**. Esse é um booleano
persistido, escrito por um caminho que aceita um endpoint escolhido por quem
chama. Usá-lo como identidade de verificação é exatamente o que a auditoria
demonstrou ser falsificável com três linhas de JSON.

**Nota de progresso, dita com o registo inteiro à vista:** `DeriveBoundary` e
`VerifyChain` estão feitas; falta `VerifyPolicy`. Uma identidade com o passo do
meio em falta não é a identidade acordada — é uma versão mais fraca dela, e o que
falta é precisamente a parte que exige uma **identidade de fora**. É por isso que
**P4 é o próximo item da sequência**, e não P6.

> **Atualização — esta nota de progresso deixou de valer e é substituída pelo
> que se segue; o texto original fica acima como registo do estado até P4.** As três
> palavras estão feitas: `DeriveBoundary` (P1), `VerifyPolicy` (P4a/P4d) e
> `VerifyChain` (P3), com `VerifyReceiptSig` (P4b) e a assinatura de settlement
> (P4c) por cima. **A identidade acordada já não tem nenhum passo por
> escrever.** E a conclusão do parágrafo acima inverteu-se por uma razão que é
> bom deixar explícita: P4 **também não é** a fase que vem a seguir. A fase que
> vem a seguir é a **simetria entrada/saída** — sem `ControlledToExternal` = −valor,
> `NEV = ΣVerifiedInflows − ΣVerifiedOutflows` não é computável e qualquer número
> de `NEV` que este documento publique está a medir metade do que diz medir.
> Depois dela: **P6 → P7**, e depois o trabalho físico de E6, que nada em P0–P4
> toca nem se aproxima de tocar.
>
> E o limite que P4 impôs à própria victoria, porque um placar honesto tem de o
> dizer no dia em que ganha: **uma assinatura de verificador não é uma âncora
> externa.** Não há rotação de políticas, não há revogação, não há protecção de
> rollback, e o ledger de atestações vive sob o mesmo uid que o pode reescrever.
> A palavra `VerifyPolicy` deixou de ser uma palavra por escrever — **não** passou
> a ser uma palavra que nada pode desmontar.

---

O nível (a) é real e a engenharia é competente: há binário com SHA-256 pinado
por commit, tabelas PASS/FAIL por cenário, CIDs, rejeição de evidência
adulterada e um harness de prova que se recusa a aceitar artefato modificado.
A distância até (b), (c) e (d) não é conceitual — nenhuma ideia nova é
requerida. É mecânica: dois hosts, um seed com inbound real, um contador
externo e um killer de relay com cronômetro. O que falta não é saber como
fazer; é o tempo de máquina e de contraparte. Até que isso exista, o placar
honesto é 1/4, com 0/9 nos critérios do próprio projeto.

E a segunda distância, que a auditoria desta rodada abriu e que não é
mecânica: entre um ledger que **afirma** e um ledger cuja autoridade é
**verificada**. Ela hoje é de um item só e é bem nomeado —
`VerifiedEconomyView` —, mas esse item depende de todos os outros cinco. O
placar honesto continua 1/4 e 0/9. Uma auditoria que encontra um ataque real e
construtivo não é progresso em (b), (c) ou (d), e tratá-la como se fosse seria
exatamente o tipo de inferência que a seção "O que NÃO é prova" recusa.

> **Atualização — dois dos cinco itens já não estão por fazer, e o parágrafo
> acima é a fotografia de antes.** `VerifiedEconomyView` **e** a durabilidade do
> ledger estão entregues e medidas (ver "Rodada P3 e P5"); com elas, o ataque de
> ledger falsificado rende **zero** autoridade em ARV, RV e reinvestimento, e o
> `record_hash` é gravado sob `0600` num directório `0700` com lock exclusivo e
> âncora de cabeça verificada na leitura. Dependem agora **três** fases — P4,
> P6, P7 — em vez de cinco, e a ordem restante é **P4 → P6 → P7**, porque a
> palavra `VerifyPolicy` da identidade continua a ser a única por escrever.
>
> Duas coisas que esta actualização **não** toca, e é o que interessa reter:
> o **placar continua 1/4 e 0/9**, e a **âncora externa continua por fazer**.
> Fechar o ataque de falsificação e fechar a lacuna de topologia são duas
> perguntas diferentes, e P3 e P5 responderam à primeira. A segunda — dois hosts,
> um seed com inbound real, um contador externo, um killer de relay com
> cronômetro — está exactamente onde estava, e o valor externo liquidado
> continua **zero**. `ARV0` continua por passar: passar exige valor externo
> **atestado**, e a atestação que P3 tornou obrigatória é precisamente a que
> nenhum ledger local consegue fabricar.

> **Atualização — P4 fecha a palavra que faltava, e o placar não se mexe de um
> milímetro.** `VerifyPolicy` foi entregue em `policy_auth.rs` (âncora pinada em
> `/etc/mycelium/trust`, política assinada, a chave autorizadora **fora** do
> corpo assinado) e `VerifyReceiptSig` foi acrescentado por P4b, com
> `settlement_auth.rs` a fechar a lacuna mais séria de todas — a receita estava
> sem assinatura. Das cinco fases, **quatro estão feitas** (P1, P3, P4, P5) e
> dependem agora **duas** — P6 e P7 — mais o item de simetria
> entrada/saída que P4 deixou escrito e que precede ambas. As duas frases do
> parágrafo original que **continuam verdadeiras sem alteração nenhuma**, e que
> são as que interessam reter: o **placar continua 1/4 e 0/9**, e a **âncora
> externa continua por fazer**. Fechar o ataque de falsificação e fechar a
> lacuna de topologia são duas perguntas diferentes; P3, P5 e P4 responderam à
> primeira e **não tocaram na segunda** — dois hosts, um seed com inbound real,
> um contador externo e um killer de relay com cronômetro estão exactamente onde
> estavam.
>
> E o estado a registar sem atenuação, porque é o número que este documento
> existe para não distorcer: **NEV = 0 · valor externo criado = 0 · E6 = 0/9 ·
> níveis (b), (c) e (d) NÃO SUSTENTADOS.** Cada porção de integridade obtida
> em P0–P4 é **integridade e autoridade, não geração económica**. P4 tornou mais
> difícil que um ledger local seja acreditado; isso é condição necessária para
> o dia em que houver algo real a atestar, e **não** é um passo em direcção a esse
> dia. A frase que fecha esta rodada é a mesma que fechava a anterior, e ela não
> envelheceu: `ledger ≠ authority` deixou de ser uma promessa de leitura
> cuidadosa, e **continua a não ser uma âncora externa**.

> **Atualização — P4.5 fecha a palavra que faltava à aritmética, e o placar
> continua 1/4 e 0/9 sem um milímetro de movimento.** Desde P4, o crate sabia
> somar **entradas** e não sabia somar uma **saída**; `NEV = ΣVerifiedInflows −
> ΣVerifiedOutflows` não era computável, e o próprio documento o registava como
> o próximo item concreto. P4.5a deu ao tipo a segunda direcção com o sinal
> derivado do registry, P4.5c fez a agregação — recusando tanto a promoção de
> uma perna isolada quanto o agrupamento de duas transacções — e o arbitrage de
> dois sinais promote `+0.08`, que é o seu lucro real e não `+100.08`. **As três
> frases deste documento que continuam verdadeiras sem alteração nenhuma** são,
> como sempre, as três do fim: o **placar continua 1/4 e 0/9**, a **âncora
> externa continua por fazer**, e **`NEV = 0 · valor externo criado = 0`**. Cada
> porção de integridade obtida em P0–P4.5 é **integridade e autoridade, não
> geração económica** — e P4.5 é a demonstração mais afiada disso que o
> documento contém, porque é a primeira rodada em que o crate fica **capaz** de
> publicar um número de `NEV` e escolhe não o publicar para nenhuma operação que
> não seja completa e promotevel. E é por isso que a próxima coisa a fazer não é
> um número: é uma **fonte de evidência de preço** que permita promoting uma
> operação que queimou gas, sem a qual nenhuma transacção real na Base pode
> promover. `ledger ≠ authority` continua a ser o estado, e a frase que fecha
> esta rodada é a mesma que fechava as três anteriores: uma identidade canónica
> de facto externo **não** é uma âncora externa.
