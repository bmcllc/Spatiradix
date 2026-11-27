# Fonte de renda cripto autônoma, soberana e capital-zero — usando o Spatiradix

Data: 2026-10-03. **Revisão 2** — inclui 3 testes ao vivo executados em 2026-10-03 que corrigem
a Revisão 1 em um erro de **1000×** na economia de gas.
Base: auditoria de `crates/` (108k LOC), `crates/mycelium-economy/` (62k LOC),
`S1-BPF-source-update old/` (motor de arb), `docs/VALIDACAO.md` (3.220 linhas).

---

## 0. Resultado dos testes

**Pergunta testada:** como iniciar sem capital inicial?
**Resultado da amostra:** o custo estimado de uma tentativa foi de cerca de
**US$ 0,0054 em ETH** nas condições medidas em 3 de outubro de 2026. Taxas,
preço do ETH, disponibilidade de serviços e execução mudam; esse valor não é
uma garantia de custo ou de viabilidade futura.

| Pedido | Veredito | Realidade medida |
|---|---|---|
| **Capital do zero** | ✅ **LITERAL** | Arbitragem com flash loan usa **zero capital de trade** (o USDC é emprestado e devolvido na mesma tx). O único custo é gas: **US$ 0,0054** por tentativa (1 tx) ou **US$ 0,0094** (2 tx). Um faucet público entrega ~USDC 1 de ETH na Base mainnet, uma vez por endereço, sem capital. |
| **Zero intervenção humana** | ✅ **Sim, com 3 exceções** | A decisão de trade é 100% autônoma. **Não** inclui: (a) o deploy único do executor, (b) declaração tributária no Brasil, (c) recuperação de chave comprometida. |
| **Escalável** | ⚠️ A estrutura sim, o MEV não | Arbitragem em mempool público decai para zero — todo searcher vê a mesma opportunity. |
| **Soberana** | ✅ **Sim, e é vantagem** | Sem KYC, sem CEX. Na Base, soberania converte-se em vantagem de latência (blocos de 200ms). |

**Correção da Revisão 1:** a estimativa anterior de cerca de 150 USDC para gas
continha um erro de escala de 1000×. A amostra abaixo encontrou custos menores,
mas transações ainda exigem pagamento de taxas ou um patrocinador.

> Os testes registrados não encontraram oportunidade nas três classes que o
> scanner avaliou. O resultado não prova ausência de oportunidades em todos
> os mercados; custos, infraestrutura e riscos também afetam a viabilidade.

---

## 1. OS TRÊS TESTES EXECUTADOS (2026-10-03)

### TESTE A — Economia real de gas na Base

| Medição | Valor | Fonte |
|---|---|---|
| `baseFeePerGas` | **5.000.000 wei (0,005 gwei), PINADO** | 13 amostras / 52 s de tempo de cadeia: min = mediana = max, **1 valor distinto** |
| `gasPrice` | 6.000.000 wei (0,006 gwei) | `eth_gasPrice` |
| `maxPriorityFeePerGas` | 1.000.000 wei | `eth_maxPriorityFeePerGas` |
| Variação do base fee em 60 s | **0 mudanças, fator 1,0×** | Sem risco de deriva de float |
| ETH/USDC | **US$ 2.687,15** | Chainlink `0x71041…bb70` `latestRoundData` |
| Fee de dados L1 | ~1,5e9 wei = **US$ 0,000004** | `l1Fee` nos receipts (`baseFee()=0`, Fjord) |
| **Gas real, tx atômica de 2 swaps v4** | **mediana 332.217** (n=77) | `gasUsed` de receipts reais, 150 blocos |
| Gas, 1 swap v4 | mediana 142.925 (n=107) | idem |
| Distribuição v4 completa | p25 116k · p50 154k · p75 557k · p90 1,13M · max 2,65M | 305 tx / 401 eventos |

**Custo por tentativa, a ETH = US$ 2.687,15:**

| Caminho | Gas | Wei | USDC |
|---|---|---|---|
| 1 tx (arb atômico de 2 swaps) | 332.217 | 1.993.302.000.000 | **US$ 0,00536** |
| 2 tx (policy + execution) | 582.217 | 3.493.302.000.000 | **US$ 0,00939** |
| Modelo conservador do próprio S1 | 600.000 (+120% margem + L1) | 4.365.296.503.332 | **US$ 0,01173** |

**Float necessário:**

| Float de ETH | Tentativas (1 tx) | Tentativas (2 tx) |
|---|---|---|
| **US$ 0,10** | 18 | **10** |
| **US$ 1,00** | 186 | 106 |
| US$ 10,00 | 1.866 | 1.065 |

**Erro da Revisão 1, corrigido:** eu li `modeledTxCostUSDC: 12900` como 12,90 USDC. O campo é em
**micro-USDC** (6 decimais), confirmado por `sovereign_edge.py:117-126` `wei_to_usdc()`. O valor real
é **US$ 0,0117**. A conta da Revisão 1 (26 USDC/tentativa, 150 USDC de float) estava errada por 1000×.

### TESTE B — Existe caminho on-chain para gas zero na Base?

**Não. É um fato de protocolo, não um bug.**

Uma transação com `value == 0` de um remetente com `balance == 0` **nunca pode ser incluída**: o
gas é debitado na admissão, e o flash loan só é creditado durante a execução. A circularidade é
inquebrável — nenhum executor pode pagá-lo, porque pagá-lo exigiria já estar executando.

Verificações no código S1:
- `operation.py:288` — `require(eth_getBalance(sender) >= cost, "ETH insuficiente para taxas")`
- `runner.py:748-749` — mesma checagem, com `max_transaction_cost_wei`
- `operation.py:274, 306, 331` — todas as tx construídas com `value = 0x0`
- `S1FlashExecutor.sol` e `S1SharedExecutor.sol` **não têm `receive()` nem `fallback()`** →
  `S1SharedExecutor.sol:284 rescueETH()` é **código morto inalcançável**

**O que foi testado ao vivo:**

| Mecanismo | Vivo na Base hoje? | Permite conta com 0 ETH? | Evidência |
|---|---|---|---|
| **MEV-Share** (searcher não paga gas) | ❌ **só Ethereum L1** | — | `relay.flashbots.net eth_chainId` → `0x1`; SSE stream mostra WETH `0x1f98…f984` (L1), e `0x28c6c062…` = Binance hot wallet |
| **Titan Sponsored Bundles** (builder paga o gas) | ❌ **só Ethereum L1** | — | `titanbuilder.xyz`: *"We are a neutral block builder on **Ethereum**"*; `rpc.titanbuilder.xyz` não existe; `llms.txt` sem menção a Base |
| **Builder de terceiro / sequenciador** | ❌ não existe | — | `docs.base.org`: *"Base currently operates with a **single active sequencer**"*. Sem mercado de proponentes |
| **Base Builder Rewards** | ❌ futuro | — | `docs.base.org/apps/builder-codes`: *"unlocking rewards **as the program expands**"* |
| **Paymaster público (`paymaster.base.org`)** | ⚠️ serviço vivo, mainnet **allowlist-gated** | **desconhecido** | Mainnet v0.6 → `"sender not allowed"`; v0.7 → `"no paymaster found"`. Sepolia responde de verdade |
| **CDP Paymaster** (até US$ 15k em créditos, Base mainnet) | ✅ | **SIM**, via smart account ERC-4337 | `docs.cdp.coinbase.com/paymaster/introduction/welcome` |
| **EntryPoint v0.7 na Base** | ✅ instalado | não paga sozinho | `eth_getCode(0x0000000071727De22E5E9d8BAf0edAc6f37da032)` → 16.035 bytes; usado em ~7 tx AA por bloco |
| **`S1SharedExecutor.executeSponsored`** (`sol:124-173`) | ✅ contrato existe | **só se um patrocinador offered** | 3ª parte paga o gas e divide o lucro — exige contraparte经济学amente motivada. Não é serviço público |
| **Flashblocks 200ms** | ✅ | ❌ é latência, não elimina gas | `docs.base.org/base-chain/flashblocks/overview` |
| **Faucets** | — | — | `ethfaucet.com` (BringID): ~USDC 1 de ETH **mainnet**, ZK-proof, 1× por endereço. QuickNode/Alchemy exigem ≥0,001 ETH na L1 |

**Veredito:** a Base não tem nenhum mecanismo de gas-DFA-compartilhado. Todo o gênese de MEV
(sponsored bundles, MEV-share, builder nets) é **Ethereum L1**. O único caminho real na Base é
**CDP Paymaster** (crédito de gas), e ele exige converter o executor em smart account ERC-4337 —
complicado por `S1FlashExecutor.sol:172 executeAaveV3` ser `onlyOwner`.

### TESTE C — O instrumento de medição funciona de graça? E o que ele encontra?

**Sim, funciona, e é grátis.** Mas encontrou **nada**.

**Blockers de infraestrutura (todos-free, todos reais):**
1. `discover.py:233` → `operation.cast_executable()` → **`cast não encontrado`**. O script morre sem
   o Foundry instalado. Precisa só de `cast sig` e `cast calldata` (encoding ABI offline).
2. `sovereign-edge-scan.py:208` → `re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}/?")` →
   **`EDGE_SCAN_REQUIRES_LOCAL_MYCELIUM_RPC`**. O flag `--allow-non-authoritative-endpoint` relaxa
   **só a checagem de identidade (linha 219), não esta**. Não há combinação de flags que rode em RPC público.
3. `operation.py:95` default `BASE_RPC_URL=https://mainnet.base.org` → **rejeita o batch path inteiro**:
   medido `quoted 0, quote_failures 10`. Usar `base-mainnet.public.blastapi.io`.
4. `discover.py:341` — `require(len(sys.argv)==2)`: **só aceita um path de config.** Não existe `--amount`.
5. `s1_triangle_sweep.py:63` — **código morto estrutural** (ver §1.C.3).

**Capacidade de RPC grátis medida (não citada de docs):**

| Endpoint | 1 thread | 8 threads, batch 64 |
|---|---|---|
| `base-mainnet.public.blastapi.io` | 2,7 req/s | **19,7 req/s, 406 eth_call/s, 0 erros** |
| `base-rpc.publicnode.com` | 2,9 req/s | 1,2 req/s, **24 HTTP429** (conta por `eth_call`, não por request) |
| `mainnet.base.org` | 2,1 req/s | `-32016 "over rate limit"` |

Custo por ciclo: **7 requests HTTP, 21 `eth_call`, 2,36 s, 10 observações.**

**Sustentável em 30 dias a US$ 0:** o limite é o **block time (2 s)**, não o orçamento RPC.
Com 2 endpoints rotacionados: **1 ciclo por bloco = 1,296.000 ciclos = 13 milhões de observações
em 30 dias**, com 35% de folga. **Nenhum node pago é necessário.**

---

## 2. DADOS DE MERCADO NOVOS (medidos hoje, nunca antes medidos)

### 2.1 Arbitragem 2-hop v4 hookless — **10 de 10 negativas**, degradação super-linear

Bloco 52.140.603. `aave_flashloan_premium_total_bps = 5`.

| Entrada USDC | fee1→fee2 | Saída USDC | Edge bruto | Após prêmio 5 bps |
|---:|---|---:|---:|---:|
| 10 | 500→3000 | 9,942274 | −0,057726 | **−0,062726** |
| 10 | 3000→500 | 9,933693 | −0,066307 | −0,071307 |
| 25 | 500→3000 | 24,777911 | −0,222089 | **−0,234589** |
| 50 | 500→3000 | 49,298727 | −0,701273 | −0,726273 |
| 100 | 500→3000 | 97,584912 | −2,415088 | −2,465088 |
| 250 | 500→3000 | 234,862435 | −15,137565 | **−15,262565** |
| 250 | 3000→500 | 232,660474 | −17,339526 | −17,464526 |

**0 de 10 positivas.** A perda cresce **super-linearmente** com o tamanho: −0,58% a 10 USDC →
**−6,05% a 250 USDC**. O edge exigido era USDC 0,002; o melhor observado é −0,0627 —
**31× o lucro exigido do lado errado.** Confirmado em dois endpoints independentes (blastapi e
publicnode), bloco fixado, **resultado byte-idêntico**. Ciclo de 5 voltas / 50 observações em 90 s:
```
REASON HISTOGRAM: {"NEGATIVE_TOKEN_EDGE": 50, "POSITIVE_BUT_BELOW_MIN_PROFIT": 0, "CLEARS_MIN_PROFIT": 0}
```

**Este espaço está morto. Não rode mais.**

### 2.2 Cross-venue v4 ↔ Aerodrome — **8 de 8 negativas**

Bloco 52.139.530, 5 USDC. `positive_token_edges: 0`.

| Direção | Pool | v4 fee | Saída | Edge |
|---|---|---:|---:|---:|
| Aerodrome→v4 | WETH volatile | 500 | 4,988462 | **−0,014038** |
| Aerodrome→v4 | WETH volatile | 3000 | 4,978728 | −0,023772 |
| v4→Aerodrome | WETH volatile | 500 | 4,964931 | −0,037569 |
| v4→Aerodrome | WETH volatile | 3000 | 4,956038 | −0,046462 |

Melhor caso **−28 bps**; exigido **+20 bps**. Gap de **48 bps na direção errada**, e **abre** com tamanho.
⚠️ **Só 5 USDC foi testado** — esta é a lacuna real (ver §4).

### 2.3 O espaço de pools é MENOR do que o scanner assume — 3 defeitos de código

Medido no bloco 52.139.507, com `0x6190b2b0 = UnexpectedRevertBytes(bytes)` confirmado no 4byte.directory:

| Par | fee tiers que existem | Observe |
|---|---|---|
| USDC↔WETH | **só 500 e 3000** | 100 e 10000 **revertem** |
| USDC↔GHO | 100 e 500 (25 USDC → 25,0117 GHO) | 3000 efetivamente vazio (→ 0,000845 GHO) |
| **WETH↔GHO** | **NENHUM** | **as 8 pernas reverteram** |

**Consequências:**
1. **`s1_triangle_sweep.py` é código morto permanente.** Seus únicos 2 caminhos
   (`USDC→WETH→GHO→USDC`, `USDC→GHO→WETH→USDC`, linha 63) exigem um pool v4 WETH/GHO que **não existe
   na Base**. 16/16 QUOTE_FAIL, para sempre. É um defeito de configuração, não uma descoberta de mercado.
2. 8 dos QUOTE_FAILs do cross-venue são os tiers 100/10000 inexistentes do v4.
3. **GHO é `VENUE_UNAVAILABLE` no Aerodrome** (`AERODROME_QUOTE_INVALID`) — metade da matriz
   cross-venue pretendida não existe.

### 2.4 Liquidações Aave V3 Base — classe nova, custo zero, **vale nada**

37.305 borrowers enumerados · 5.069 com dívida aberta · **19 liquidáveis** (bloco 52.141.085, 19,9 s).
Oracles: WETH US$ 2.687,15 · wstETH US$ 3.346,79 · AAVE US$ 180,29 · USDC US$ 0,999979.

| conta | HF | dívida USDC | close | `debtToCover` | bônus | bruto | **líquido** |
|---|---:|---:|---:|---:|---:|---:|---:|
| `0x1f1e61b1…d8a6b` | 0,9983 | 0,127724 | 100% | 0,127724 | 7,5% | 0,009579 | **+0,003130** |
| `0xfd1474b8…a3d1` | 0,9653 | 0,083571 | 100% | 0,083571 | **10%** | 0,008357 | **+0,001908** |
| `0x26eb287c…a987` | 0,9879 | 0,106641 | 100% | 0,106641 | 7,5% | 0,007998 | **+0,001549** |
| outros 16 | 0,80–0,997 | ≤ 0,0546 | — | — | 0–7,5% | — | **todos negativos** |

**Melhor oportunidade em todo o livro Aave V3 da Base agora: +US$ 0,0031.**
3 de 19 marginalmente lucrativos; **16 de 19 líquidos negativos.**
Break-even exige ~USDC 0,09–0,13 de dívida coberta; a maior posição é USDC 0,13 — **exatamente no ponto
de equilíbrio.** Atividade é alta em contagem (**3.455 liquidações / 175 dias ≈ 19,7/dia**) mas
**minúscula em tamanho** — a mediana das contas tem ~10 centavos de dívida.

⚠️ `gasUsed` de um liquidator real **não pôde ser medido** (0 liquidações nos últimos 5.000 blocos).
Os US$ 0,006449 usam 400.000 gas — estimativa defensável como p60–p70 das tx atômicas de 2 swaps
v4 medidas, mas **não é medição de liquidator**. Não substituído por chute.

---

## 3. O QUE ISSO MUDA NO PLANO

### 3.1 Corrigido: capital e gas saem da lista de riscos

| Item | Revisão 1 (errado) | Revisão 2 (medido) |
|---|---|---|
| Custo por tentativa | US$ 26 | **US$ 0,0094** |
| Float para começar | US$ 150 | **US$ 0,10** (≈10 tentativas) |
| Risco de deriva de gas | não avaliado | **zero** — base fee pinado em 0,005 gwei |
| Edge exigido pelo gas | dominante | **0,1 bps** a 1.000 USDC de notional |
| Anuidade de node RPC | ~US$ 50–150/mês | **US$ 0** — 13 M observações/30 dias grátis |

**O custo real deicomparar esta estratégia agora é ~US$ 0,10 de gas + tempo.**

### 3.2 Corrigido: a exit criterion da Fase 1 está mal enunciada

A Fase 1 da Revisão 1 previa 30 dias procurando edge positivo. Os testes mostram que o instrumento
**já está rodando há 5 ciclos e retorna 50/50 negativo**, e que 2 das 3 classes que ele alcança
(2-hop v4, cross-venue a 5 USDC) estão **definitivamente falsificadas**.

> **Fase 1 deve ser reenunciada como um teste de falsificação de graça, não como uma caça ao edge.**
> Rodar 30 dias para coletar 13 milhões de observações negativas sobre um espaço já morto é
> desperdício. A Fase 1 deve primeiro consertar os 3 defeitos de código da §2.3 e então medir
> **apenas o espaço que ainda não foi medido**.

### 3.3 Mantido: os thresholds absolutos continuam defeituosos

`discover.py:251-254` — `min_net_profit_usdc_raw` é **absoluto**, não proporcional.

| Notional | `edge-policy.example.json` (USDC 1,00) | shadow configs (USDC 2,01) |
|---:|---:|---:|
| 10 USDC | **1000 bps** | **2010 bps** |
| 1.000 USDC | 10 bps | 20,1 bps |
| 100.000 USDC | **0,1 bps** | 0,2 bps |

Swing de **1000×** sem mudar nenhuma config. Um trade de edge 100 bps planos é rejeitado a 10 USDC e
aceito a 1.000 USDC.

**Mas note:** a observação `quoted_gross_profit` **não é afetada** — `discover.py:305` é `out - amount`
bruto, registrado na linha 303-307 **antes** do filtro da linha 308. Então **o −0,0627 é medição
real**, não artefato. Zerar todos os thresholds não muda nada. Os thresholds só importam para o
**sweep de tamanho** — que é exatamente o que ainda falta rodar.

### 3.4 O split de unidade 1000× no ledger — confirmado como BUG

Inventário completo de conversões de escala em `crates/mycelium-economy/`:

| Divisor | Sites | Significado |
|---|---|---|
| `/ 1_000_000` (→ USD) | **~25 sites** em `verified_view.rs`, `autonomy.rs`, `reinvestment.rs`, `terr_research.rs`, `lib.rs`, `bin/` | "mUSD" = USD |
| `/ 1000` (→ milli) | **`nev_tier.rs:793, 807, 820, 832` — os únicos 4 do crate inteiro** | "mUSD" = milli-USD |

`nev_tier.rs` se contradiz em 10 linhas: `:84` diz *"10 mUSD/day = 10,000 micros"* (mUSD = micro),
`:793` divide por 1000 e rotula "mUSD/day" (mUSD = milli). Não há documentação de escala dupla em lugar
nenhum — `grep -i "torch|cash"` → 0 hits; a escada NEV não aparece em **nenhum** `.md` do repo.

**Prova por absurdo (a mesma em ambos os lados da correção):**
- `nev_tier_tests.rs:643-667` — 16.000.000 micros (**US$ 16/mês**) declarado suficiente para
  "self-fund" contra custo operacional de US$ 10/mês, atingindo **NEV4 com US$ 60/mês**.
- `reinvestment.rs` pode comprometer até **US$ 100/dia = US$ 3.000/mês**.
  → **Overspend de 50×.** Nenhuma operação real roda com cobertura de custo de 1,6×.
- Na leitura em USD: NEV3 exige US$ 500/dia = US$ 15.000/mês contra baseline de US$ 10/mês
  (trivialmente satisfeito), NEV4 exige US$ 2.000/dia = US$ 60.000/mês, e o reinvestimento de 20%
  sobre base investível de US$ 59.990 = US$ 11.998 acumulado. **Todos os números fecham.**

**Correção (Fase 0.6):** multiplicar `NEV1..NEV4_DAILY_AVG_MICROS` por 1000
(`nev_tier.rs:84-93` → `10_000_000 / 100_000_000 / 500_000_000 / 2_000_000_000`) e trocar os quatro
`/1000` por `/1_000_000`. NEV passa a ser o espelho correto de ARV.
**A correção hoje é barata porque a escada não tem nenhuma chamada de produção** — nenhuma das duas
leituras jamais afetou um número visível a operador.

### 3.5 NEV0–NEV4: o que é, e por que NÃO é a métrica do plano

Investigado a fundo. Veredito: **instrumento de medição, sem chamada de produção, e não monetizável
por construção.**

**É uma taxa, não um saldo.** `NevTier` é um enum sobre `daily_average_nev_micros`, recalculado do zero
a cada `evaluate()` (`nev_tier.rs:922`). Não existe tipo de detentor — `NevBalance`, `nev_amount`,
`total_nev` → **0 ocorrências no repo inteiro**. `VerifiedNev` (`verified_view.rs:461-479`) tem
`nev_musd_micros`, `receipts`, `provider`, `provider_identity_verified`, `policy_hash` — **nenhum campo
de dono**. `NevEconomicEventRecord` (`nev_durable.rs:107-134`) idem. **Não se gasta uma taxa.**

**Zero chamadas de produção, zero superfície de CLI.** `nev_tier` / `nev_durable` / `nev0` são
referenciados apenas por `lib.rs:48,59,62` (`pub mod`) e por `tests/nev_tier_tests.rs:30-31` +
`tests/cqr_economic_bridge_tests.rs:29-33`. `rg` nas 2.044 linhas de `bin/mycelium-economy.rs` →
**0 hits**. Não existe `nev-status`. **O binário sequer consegue imprimir o nível NEV.**
O binário expõe `arv-status`, `rv-status`, `revenue`, `autonomy-status`, `reinvestment-status`,
`economy-dashboard` — e o dashboard emite apenas `rv`, `arv`, `terr`, `reinvestment`.

**NEV4 é inalcançável em produção.** Só `OpportunityClass::Arbitrage` recebe a capability
`RealOpportunityClass` (`nev_tier.rs:255-259`). O segundo construtor é `#[cfg(test)]`
(`nev_tier.rs:113-117`). NEV4 exige `active_real_classes_count >= 2` (`nev_tier.rs:824-826`).
Máximo real = **1**. NEV4 é código morto por construção.

**`highest_ever_verified_tier` não é durável.** `rebuild` reseta para `PreNev0`
(`nev_tier.rs:562-563, 615`) e re-deriva no próximo `evaluate`. Nada persiste a marca d'água.

**NEV é mais rigoroso que ARV num ponto que importa:** exige **30 de 30 dias UTC observados**
(`nev_tier.rs:738-751`), não apenas 30 dias decorridos como ARV (`verified_view.rs:1050`).
*"an unobserved day is an unknown day, not a zero day"* (`:40-69`).
E tem um teste que prova: 30 eventos em 30 dias distintos, US$ 3/mês de líquido → **ainda NEV0**,
com `"missing 30 of 30"` (`nev_tier.rs:1572-1609`).
→ **Implica 30 dias completos e consecutivos de ciclos rodando antes de qualquer afirmação de
autossuficiência.** Isso é uma boa propriedade; o plano devehonrá-la mesmo usando ARV como métrica.

**O que a escada NEV tem de aproveitável:** o conceito de **NEV3 "self-funded"**
(`nev_tier.rs:811-821`) é o **único lugar em qualquer das escadas que fala de autossuficiência**:
`total_net_nev_micros >= monthly_operating_cost_micros` (neto dos últimos 30 dias cobre o custo
operacional mensal). Exposto como `NevTierStatus.operational_self_funding_healthy`.
**Adotar esse predicado, sobre ARV.** É a métrica correta para este plano, e ela é mais honesta que
"quanto ganhou" — responde "cobre o próprio custo?".

**Por que NÃO usar NEV como métrica do plano:** não está ligado, não é imprimível, e seu teto
(NEV4) é código morto. **Usar ARV** — `arv-status`, `economy-dashboard`, e é o que `reinvestment.rs`
lê. E sobre ARV, aplicar o predicado de autossuficiência do NEV3.

**Por que NÃO tentar monetizar NEV:** é **erro de categoria**, não problema de design. Um token de NEV
seria uma *claim sobre fluxo futuro incerto* — ou seja, um valor mobiliário. Isso violaria os
invariantes #10/#11/#13 do `crates/mycelium-economy/README.md:15-30` (o único número acionável é um
`VerifiedNev` que nenhum outro código constrói; o adaptador Base é read-only e pinado) e esbarraria em
`nev_tier.rs:38` (*"No synthetic, mock, or internal issuance can promote any tier"*) e em
`nev0.rs:216-220` `CostBasis::ModeledProfit` (*"a model is a hypothesis, and a hypothesis about profit
is the single most reliable way to manufacture a positive NEV"*).
**Os 14 invariantes estão funcionando.** Torna-se estruturalmente impossível converter uma medição em
pretensão sobre dinheiro — esse é o design correto, não uma falha.

**Nutrientes (ATP/Enzymes/Mycelia/Spores/Resilience): pior ainda.** `Ledger` tem `balances`, `transfers`,
`SignedTransfer`, `seen_nonces` e `redeemed` — mas `redeemed` resgata um **Voucher assinado**
(`nutrients/lib.rs:456-484`), que é um *claim interno de serviço já prestado*. Não troca nada.
O campo BOLT11 no voucher é só um parse bech32 (`mycelium-zkp/src/bolt11.rs:89-91`) e o único emissor
de produção o monta como `None` (`organism.rs:2417`). E a oferta é **ilimitada por construção**:
`pledge()` (`nutrients/lib.rs:310-336`) cria ATP a partir de núcleos de CPU **declarados num JSON**,
rodando automático de `organism.rs:318-324`. O ATP de um estranho se cria digitando um número maior.
Sem escassez não há preço possível. `docs/architecture/ARQUITETURA_GERAL_SISTEMICA.md:93-97` confirma:
cada nutriente é **prioridade de recurso**, não dinheiro. `docs/cosmic/COSMIC_COMPUTE_STORAGE.md:31`
posiciona o ledger como **alternativa ao** dinheiro, nunca como fonte dele.

**O fluxo de dinheiro está invertido — e isso é o insight de design:**
> NEV não é a renda. NEV é a **auditoria** da renda que chegou por fio externo.
> `s1_outcome.rs:322-326` exige `tx.from == sponsor`, um endereço que você não controla.
> O USDC chega na sua carteira porque um terceiro enviou, não porque o sistema pagou.
> `mycelium-economy` contribui com **medição de zero intervenção** e **capacidade de renda zero**.
> A camada de medição está **abaixo** do dinheiro, não acima.

---

## 4. PROCEDO EXATO: COMO INICIAR SEM CAPITAL INICIAL

Isto é a resposta direta à pergunta, e todo passo é medido.

### Passo 0 — Commitar (US$ 0, 10 min)
56% do código não está versionado (§7). Sem isso, tudo abaixo pode ser perdido.

### Passo 1 — Instalar Foundry (US$ 0, ~1 min)
`discover.py:233` chama `cast`. Sem ele **nenhum scanner roda**.

### Passo 2 — Obter o gas (US$ 0, US$ 0 de capital)
`ethfaucet.com` → ~USDC 1 de ETH **mainnet** Base, ZK-proof, 1× por endereço.
Ou: pedir aprovação no **CDP Paymaster** (até US$ 15k de crédito, Base mainnet) e rodar o executor
como smart account ERC-4337 — o que elimina o gas, não só o reduz.
**US$ 1 de ETH = 106 tentativas de 2 tx.** É o suficiente para começar e para toda a Fase 1.

### Passo 3 — Escolher o endpoint (US$ 0)
`BASE_RPC_URL=https://base-mainnet.public.blastapi.io` (19,7 req/s, 406 eth_call/s, 0 erros).
**Nunca** usar `mainnet.base.org` (rejeita o batch path) nem `publicnode` para batch
(conta por `eth_call` → 429 imediato). Rotacionar blastapi + publicnode dá 35% de folga.

### Passo 4 — Rodar a medição (US$ 0)
```bash
cd "S1-BPF-source-update old/scripts"
BASE_RPC_URL=https://base-mainnet.public.blastapi.io \
S1_DISCOVERY_RPC_URL=https://base-rpc.publicnode.com \
python3 discover.py ../config/edge-policy.example.json
```
Custo: **7 requests, 21 `eth_call`, 2,36 s, 10 observações.** Rodar 1× por bloco (2 s) = 43.200
observações-sets/dia. **`sovereign-edge-scan.py` NÃO funciona** — gate de loopback na linha 208.

### Passo 5 — Onde olhar (nesta ordem, e não antes)
1. **Consertar §2.3** — o espaço de pools é menor do que o scanner assume. Sem isso, medir classes mortas.
2. **Cross-venue em notional maior** — **é a maior lacuna real**. Só 5 USDC foi medido
   (−28 bps, e piora com tamanho — mas Aerodrome volatile tem spread próprio; 5 USDC não prova
   1.000 USDC). Rodar 25 / 100 / 1.000 / 10.000 USDC. Com thresholds em bps.
3. **Liquididações** — mecanismo real (HF cruzando), 19,7/dia. Mas hoje é poeira: o break-even é
   USDC 0,09 de dívida. **Só vale quando as posições crescerem.** Reavaliar em mercado de alta.
4. **Flashblocks** — o único moat true. Nenhum feed conectado ainda.

### Passo 6 — Se e somente se o edge aparecer
Deploy do `S1SharedExecutor` **pausado** (ação humana única) → verify → pin do runtime hash →
despausar → primeiro `ExternalValueReceipt` → A10 fecha → ARV0.

---

## 5. FASES REVISADAS

```
FASE 0   2 dias   US$0     [R1 0.1-0.7] + instalar foundry + consertar o gate
                             loopback de sovereign-edge-scan.py + BASE_RPC_URL default
                             + corrigir pools inexistentes (fee tiers) + triagem do WETH/GHO morto
                             ↓ gate: suíte verde
FASE 1R  5-10d    US$0     falsificação dirigida: cross-venue em notional grande com thresholds
                             em bps. NÃO 30 dias no espaço morto.
                             ↓ GATE GO/NO-GO  ← decisão real
         ├─ NO-GO → parar. Custou US$ 0,10.
         └─ GO
FASE 2   4-6sem  US$0     Flashblocks 200ms + mesh P2P de intenções + custódia HSM
FASE 3   4-5sem  US$0     supervisor systemd + métricas Prometheus + truth sweep
                             + watchdog de ETH + oracle Chainlink no ledger
FASE 4   1sem    ~US$0,10 deploy PAUSADO → verify → pin → despause → A10 fecha → ARV0
FASE 5   contínuo         anuidade de infra P2P sobre a mesma régua de atestação
```

**Perda máxima total: ~US$ 0,10 de gas + 10 dias.** Não há capital de trade em risco porque flash
loan não tem. Este é o argumento honesto para tentar — e o custo de descobrir que não funciona.

---

## 6. O QUE "ZERO INTERVENÇÃO HUMANA" NÃO PODE INCLUIR

1. **Tributário (Brasil, obrigatório).** Toda operação é fato gerador. Declaração mensal de
   criptoativos à Receita Federal, ganho de capital na venda (IN 2.500/1996), DARF. Lucro de
   arbitragem é ganho de capital. **Não existe botão.** O que dá para construir: ledger de custo
   de aquisição FIFO + razão realizado-vs-modelado, exportável no fechamento do período.
   Não existe em nenhum dos dois repositórios — é a lacuna mais concreta.
2. **Recuperação de chave.** Se o keystore vazar, um humano move fundos.
3. **O deploy do executor** (1 ação, 1 vez).

---

## 7. O QUE OS TESTES NÃO MUDARAM

O risco existencial do repositório é intocado e continua sendo o item #1:
```
153 caminhos alterados. NÃO versionados:
  crates/mycelium-economy/   ← 66.269 linhas = 56% de todo o Rust do repo
  docs/VALIDACAO.md          ← o registro de validação inteiro
  scripts/ci-test-gate.sh    ← ambos os CIs chamam; sem ele, CI não roda em clone novo
  rust-toolchain.toml        ← o pin de toolchain de que o CI depende
```
Um `git clean` destrói mais da metade do codebase e 100% do registro de validação.

---

## 8. O QUE EU NÃO RECOMENDO

- **Não caçar edge por mais 30 dias no espaço já falsificado.** 50/50 negativo em 90 s é resposta.
- **Não ligar o executor.** US$ 0,0054 de temptação por tentativa, mas as 8+10+8 medições
  de hoje foram negativas. Ligar primeiro = queimar gas para confirmar o que o scanner já disse.
- **Não rebaixar thresholds para "ver passar".** O projeto escreveu essa regra e a obedeceu
  corretamente uma vez (*"Thresholds were not lowered to change this, and must not be."*).
- **Não construir LLM no gating de trade.** `mycelium-economy` tem zero código de inferência e
  **não deveria ganhar.** Decisão determinística + fail-closed é o que torna o sistema auditável.
- **Não tentar monetizar NEV, nem os nutrientes ATP.** NEV é uma taxa sem detentor
  (`NevBalance`/`nev_amount`/`total_nev` → 0 ocorrências); sem dono não há gasto, logo não há resgate.
  Monetorizá-lo seria um valor mobiliário sobre fluxo futuro e violaria os invariantes #10/#11/#13 do
  `crates/mycelium-economy/README.md`. Os nutrientes têm oferta ilimitada por construção
  (`nutrients/lib.rs:310-336` a partir de CPU declarada num JSON), logo não têm preço possível.
  **Os 14 invariantes estão fazendo o trabalho deles.**
- **Não usar NEV0–NEV4 como métrica de sucesso.** Zero chamadas de produção, zero CLI — o binário não
  consegue imprimir o nível. E NEV4 exige 2 classes REAIS, mas só `Arbitrage` existe em produção
  (`nev_tier.rs:113-117, 255-259, 824-826`): **é código morto**. Usar **ARV** (`arv-status`,
  `economy-dashboard`), que está ligado, e aplicar por cima o predicado de autossuficiência do NEV3
  (`neto 30d >= custo operacional mensal`) — que é o único lugar em qualquer das escadas que fala de
  autossuficiência.
- **Não perseguir CEX.** Você pediu soberania e a resposta é a mesma: MEV-Share e Titan são
  **L1-only**, e CEX introduziria KYC. A soberania **não é o handicap aqui** — o handicap é
  que a Base não tem builder net. A mitigação é latência própria (Flashblocks), não CEX.
- **Não pursue as 4 classes em paralelo.** Cross-venue em notional grande primeiro (única lacuna
  real), depois liquidações (reavaliar em alta), depois Flashblocks.

---

## 9. APÊNDICE — Índice de evidências

| Afirmação | Fonte |
|---|---|
| base fee pinado em 0,005 gwei | 13 amostras `eth_getBlockByNumber`, min=mediana=max, 1 valor distinto |
| ETH = US$ 2.687,15 | Chainlink `0x71041…bb70` `latestRoundData` na Base |
| Gas real tx 2-swap v4: mediana 332.217 | `gasUsed` de 77 receipts, 150 blocos |
| `modeledTxCostUSDC: 12900` = US$ 0,0129 | `sovereign_edge.py:117-126` `wei_to_usdc()` → 6 decimais |
| Custo 2 tx = US$ 0,00939 | (332.217+250.000) × 6.000.000 wei × US$ 2.687,15 |
| `balance(sender) >= cost` obrigatório | `operation.py:288`, `runner.py:748-749` |
| `rescueETH` inalcançável | `S1SharedExecutor.sol:284`; nenhum `receive()`/`fallback()` nos contratos |
| MEV-Share é L1-only | `relay.flashbots.net eth_chainId` → `0x1`; WETH L1 no stream |
| Titan é L1-only | `titanbuilder.xyz` *"builder on Ethereum"*; `llms.txt` sem Base |
| Base tem sequenciador único | `docs.base.org` *"single active sequencer"* |
| Paymaster mainnet allowlist-gated | `paymaster.base.org` mainnet v0.6 → `"sender not allowed"` |
| CDP Paymaster: até US$ 15k, Base mainnet | `docs.cdp.coinbase.com/paymaster/introduction/welcome` |
| EntryPoint v0.7 instalado (16.035 bytes) | `eth_getCode(0x0000000071727De22E5E9d8BAf0edAc6f37da032)` |
| `ethfaucet.com` dá ~USDC 1 mainnet, 1×/endereço | BringID, ZK-proof, L2s suportados |
| `discover.py` exige `cast` | `discover.py:233` → `operation.py:31-47` |
| `sovereign-edge-scan.py` travado em loopback | `sovereign-edge-scan.py:208`; flag na linha 219 não levanta |
| `mainnet.base.org` rejeita o batch path | medido `quoted 0, quote_failures 10` |
| blastapi 19,7 req/s, 0 erros | medido, 8 threads batch 64 |
| 2-hop v4: 0/10 positivas, −0,58% a −6,05% | bloco 52.140.603, medido hoje |
| Cross-venue: 0/8 positivas, melhor −28 bps | bloco 52.139.530, 5 USDC |
| WETH↔GHO **não existe** na Base | 8/8 pernas revertem, bloco 52.139.507 |
| `s1_triangle_sweep.py` morto permanente | `s1_triangle_sweep.py:63` exige pool inexistente |
| 19 liquidáveis, melhor +US$ 0,0031 | 37.305 borrowers, bloco 52.141.085 |
| 3.455 liquidações / 175 dias ≈ 19,7/dia | enumeração de 175 dias |
| `gasUsed` de liquidator não medido | 0 eventos em 5.000 blocos — declarado como estimativa |
| Split de unidade 1000× no ledger | `nev_tier.rs:793,807,820,832` (os **únicos 4** `/1000` do crate) vs ~25 sites `/1e6` |
| NEV contradiz a si mesmo | `nev_tier.rs:84` "10 mUSD = 10.000 micros" vs `:793` `/1000` rotulado "mUSD/day" |
| NEV1..NEV4 reais | **US$ 0,01 / 0,10 / 0,50 / 2,00 por dia** (`nev_tier.rs:84-93`; 1e6 micros = US$1) |
| ARV1..ARV4 reais | **US$ 10 / 100 / 500 / 2.000 por dia** (`verified_view.rs:1051-1066`) |
| Bug do split: prova por absurdo | `nev_tier_tests.rs:643-667` (US$16/mês = "self-funded") vs `reinvestment.rs:84` (cap US$100/dia) → overspend 50× |
| NEV é taxa, não saldo | `nev_tier.rs:922` recalcula do zero; `NevBalance`/`nev_amount`/`total_nev` → 0 hits |
| `VerifiedNev` não tem dono | `verified_view.rs:461-479` — 5 campos, nenhum é endereço |
| NEV sem chamadas de produção | `lib.rs:48,59,62` + 2 test files; `rg` no binário de 2.044 linhas → 0 hits; sem `nev-status` |
| **NEV4 inalcançável** | só `Arbitrage` recebe `RealOpportunityClass` (`nev_tier.rs:255-259`); 2º construtor é `#[cfg(test)]` (`:113-117`); NEV4 exige ≥2 (`:824-826`) |
| `highest_ever` não durável | `nev_tier.rs:562-563, 615` — `rebuild` reseta para `PreNev0` |
| NEV exige 30/30 dias observados | `nev_tier.rs:738-751`; teste `:1572-1609` — 30 eventos/30 dias, US$3/mês → ainda NEV0 |
| Única métrica de autossuficiência | `nev_tier.rs:811-821` NEV3 `self_funding` → `operational_self_funding_healthy` (`:855-856`) |
| NEV não é monetizável | `resolution.rs:390-392` *"economic claim, not a budget"*; `nev0.rs:73-80` *"has no method that returns a budget"* |
| Invariantes que impedem monetizar | `crates/mycelium-economy/README.md:15-30` #10/#11/#13; `nev_tier.rs:38`; `nev0.rs:216-220` |
| `redeemed` dos nutrientes resgata voucher, não cripto | `nutrients/lib.rs:456-484`; BOLT11 é parse bech32 (`mycelium-zkp/src/bolt11.rs:89-91`), emissor de produção monta `None` (`organism.rs:2417`) |
| Oferta ATP ilimitada por construção | `nutrients/lib.rs:310-336` `pledge()` de CPU declarada; roda de `organism.rs:318-324` |
| Nutriente = prioridade, não dinheiro | `docs/architecture/ARQUITETURA_GERAL_SISTEMICA.md:93-97`; `docs/cosmic/COSMIC_COMPUTE_STORAGE.md:31` |
| Dinheiro chega de fora, não do sistema | `s1_outcome.rs:322-326` exige `tx.from == sponsor` (endereço que você não controla) |
| 56% do código não versionado | `git status` — `crates/mycelium-economy/` untracked, 66.269 linhas |
| `NEV = 0 · E6 = 0/9` | `docs/VALIDACAO.md:3191` |
| "Ainda não está liberado para dinheiro real" | `S1-BPF-source-update old/VALIDACAO.md:9` |

## Revisão cbBTC / hooks v4 — 2026-10-04

Esta revisão substitui interpretações anteriores de preço, validade dos hooks e descoberta Aero nesta investigação. Os registros citados eram `research/cbbtc/README.md` e `research/cbbtc/latest.json`, que não estão na árvore atual, além de `scripts/audit_cbbtc.py`.

1. USDC tem 6 decimais e cbBTC canônico tem 8; o tick −67461 representa aproximadamente US$85.044,75 por cbBTC. A interpretação próxima de US$117 era erro de escala, não evidência de token falso.
2. Usar Aero `getPool` na fábrica correta, Slipstream com tick spacing e FactoryRegistry para fábricas aprovadas. Conferir token0/token1, factory e parâmetro. Uma fábrica extra exige quoter compatível; o quoter principal não representa automaticamente seus pools.
3. Validar hooks pelos 14 bits de permissões e relação callback/return delta, sem mínimo numérico de endereço. Validar bits não prova comportamento econômico; taxa dinâmica exige hook não zero. Decodificar protocolFee no bit184 e lpFee no bit208.
4. Medir atividade com Swap logs. Cotar os dois pools alvo nos dois sentidos, em 25/100/1.000/10.000 USDC, incluindo WETH, no mesmo bloco. A busca registrada não é exaustiva.
5. HOOK-REBATE = NO (nenhum rebate demonstrado). CROSS-VENUE = INCONCLUSIVE enquanto não existir simulação atômica com consumo, settlement, repayment e lucro líquido comprovados. Cotações independentes positivas seriam candidatas para simulação, não receita.
6. Para uma candidata, simular o executor completo em fork do bloco fixado. Exigir `finalBalance > initialBalance + minProfit`, contabilizar gas/tip e buffers em USDC e garantir repayment. Só após evidência reproduzível discutir operação; nenhuma transação foi autorizada ou enviada nesta revisão.

O próximo passo depende da evidência: candidatas brutas positivas seguem para simulação completa; uma amostra negativa mantém a busca aberta somente nas lacunas declaradas. Não repetir o censo de milhões de pools nem usar a heurística `complete_fill` como prova de lucro ou inviabilidade.

Resultado no bloco 52.172.168: 46 pools externos, 3.844 cotações e 3.240 rotas cotadas, sem margem bruta positiva nos quatro tamanhos e dois sentidos de ambos os pools v4. A melhor retorna 24,993445 USDC para 25 USDC de entrada (−2,622 bps), antes de custos. Logs confirmam 1 Swap no pool fixo e 9 no dinâmico na janela de 2.000 blocos. A retomada resolveu limites RPC e quoters das fábricas extras; permanecem 184 chamadas com revert e enumeração limitada. CROSS-VENUE continua INCONCLUSIVE; nenhuma candidata positiva seguiu para simulação atômica e nenhuma transação foi enviada. Evidências e tabela por tamanho/sentido estão no relatório da auditoria.
