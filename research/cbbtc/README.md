# Auditoria cbBTC na Base — 4 de outubro de 2026

Auditoria somente de leitura. Nenhuma transação foi enviada. O JSON registra um único bloco para descoberta, estado e cotações; resultados não representam lucro executável.

## Correções implementadas

- Identidade por endereço canônico: USDC `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`, cbBTC `0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf`. Decimais conferidos na cadeia: 6 e 8. Para token0 USDC/token1 cbBTC, preço humano cbBTC/USDC = preço bruto × 10^(6−8); seu inverso dá USDC/cbBTC. O tick −67461 corresponde a aproximadamente US$85.044,75, não US$117.
- Aero Classic: descoberta por `getPool`, com sobrecargas bool/uint24 e fábrica `0x420DD381b31aEf6683db6B902084cB0FFECe40Da`. Slipstream usa `getPool(address,address,int24)` e tick spacing. Cada pool é conferido por tokens, fábrica e parâmetro; fábricas são lidas do FactoryRegistry.
- Quoters V3/Slipstream só são usados quando sua fábrica corresponde à do pool. Pools de outras fábricas ficam sem cotação compatível, com erro explícito.
- Hooks: permissões nos 14 bits baixos, coerência dos callbacks que retornam delta e exceção da taxa dinâmica. Não existe requisito de magnitude do endereço ≥ 2^64. Bits válidos não provam a implementação ou a existência de rebate.
- Slot0 v4: tick a partir do bit160, protocolFee do bit184, lpFee do bit208. Taxa dinâmica da chave não é a taxa efetivamente aplicada.
- Atividade é medida por logs Swap; variação de preço não substitui evidência de negociação.
- Quatro tamanhos: 25, 100, 1.000 e 10.000 USDC, dois sentidos, rotas diretas e via WETH. O indicador gross_bps é bruto e vem de cotações independentes.

## Limites e critério de decisão

HOOK-REBATE = NO no sentido de ausência de rebate demonstrado; não é prova de inexistência de rebates em todos os hooks. CROSS-VENUE = INCONCLUSIVE até uma execução atômica demonstrar saldo final superior ao inicial, com repayment, gas, tip e buffers contabilizados. O V4Quoter fornece amountOut e gasEstimate; não demonstra aqui consumo integral do input nem lucro do executor. Não usar uma heurística complete_fill para descartar ou aprovar rotas.

A enumeração de fee tiers e tick spacings é limitada e está registrada em coverage. Erros de ABI, RPC e fábricas sem quoter compatível permanecem visíveis. Portanto, ausência de rota positiva nesta amostra não exclui oportunidades fora dela. Não foi refeito o censo amplo de milhões de pools.

## Resultado da rodada

Bloco fixado **52.172.168**, hash `0xa9981f494828347fb0b57dfbf44db5e787f8e40a5eb8042593259880677a0508`. Foram descobertos 46 pools externos (14 V3, 4 Classic, 28 Slipstream) e enumerados 249 caminhos diretos ou via WETH. A rodada terminou com **3.844 cotações e 3.240 rotas cotadas**, nenhuma com margem bruta positiva.

A melhor rota compra no v4 de taxa fixa e vende no pool `0x9d14ff91ae2c6e3d1a760542248b6c7f206894b0`: **25 USDC → 24,993445 USDC**, margem **−2,622 bps**, antes de gas, tip, repayment e buffers. Nenhuma candidata seguiu para simulação atômica.

“Fixo” identifica o pool `0x64f978…bbb96` (LP fee 3000); “dinâmico”, `0xdfb253…80ab6` (LP fee observada 450). Comprar/vender refere-se à perna cbBTC no v4. A contagem abaixo registra rotas com retorno de cotação; não comprova consumo integral do input.

| USDC de entrada | Pool v4 | Sentido no v4 | Rotas cotadas | Melhor margem bruta (bps) |
|---:|---|---|---:|---:|
| 25 | Fixo | Comprar | 194 | -2.622000 |
| 25 | Fixo | Vender | 211 | -60.113200 |
| 25 | Dinâmico | Comprar | 194 | -8.426800 |
| 25 | Dinâmico | Vender | 211 | -4.606800 |
| 100 | Fixo | Comprar | 194 | -4.271000 |
| 100 | Fixo | Vender | 211 | -61.738500 |
| 100 | Dinâmico | Comprar | 194 | -11.527100 |
| 100 | Dinâmico | Vender | 211 | -7.049900 |
| 1000 | Fixo | Comprar | 194 | -26.649640 |
| 1000 | Fixo | Vender | 211 | -83.218650 |
| 1000 | Dinâmico | Comprar | 194 | -49.253130 |
| 1000 | Dinâmico | Vender | 211 | -41.802350 |
| 10000 | Fixo | Comprar | 194 | -238.741248 |
| 10000 | Fixo | Vender | 211 | -293.496367 |
| 10000 | Dinâmico | Comprar | 194 | -783.215180 |
| 10000 | Dinâmico | Vender | 211 | -589.970838 |

A janela de atividade de 52.170.169 a 52.172.168 tem quatro trechos completos por pool: **1 Swap no fixo e 9 no dinâmico**. Respostas bem-sucedidas preservadas no histórico RPC recuperaram essa evidência após falhas na retomada.

A retomada resolveu os limites do RPC e adicionou os quoters das duas fábricas Slipstream extras, com `factory()` conferido no bloco fixado. Das 3.984 combinações enumeradas, 3.240 retornaram cotação (810 por tamanho). Permanecem 184 chamadas com revert: 108 “Unexpected error” e 76 SPL. As 60 falhas de descoberta são reverts de sondagem e estão preservadas. Falhas de chamadas não equivalem a rotas únicas. Erros anteriores permanecem em `previous_errors`; cotações anteriores bem-sucedidas foram reaproveitadas no mesmo bloco.

**HOOK-REBATE = NO (nenhum rebate demonstrado); CROSS-VENUE = INCONCLUSIVE.** Nenhuma das rotas cotadas justifica simulação atômica por margem bruta positiva. As lacunas restantes são os reverts e a enumeração limitada de taxas/tick spacings; não há evidência para declarar inviabilidade global. `completed=true` significa que a rodada terminou, não que a cobertura foi exaustiva.

## Reprodução

Dependência Python: pycryptodomex. Executar da raiz do projeto:

```bash
rtk proxy python3 scripts/audit_cbbtc.py --resume --rpc https://base-mainnet.g.alchemy.com/public --request-interval 0.2
rtk proxy python3 -m unittest discover -s scripts -p test_audit_cbbtc.py
```

latest.json contém estado, pools, cotações, rotas, erros e respostas RPC. completed=true identifica uma rodada terminada. Checkpoints anteriores ao término são parciais.

## Fontes primárias

- [Coinbase: endereço cbBTC](https://www.coinbase.com/en-br/cbbtc).
- [Uniswap Hooks.sol: permissões e validade](https://raw.githubusercontent.com/Uniswap/v4-core/main/src/libraries/Hooks.sol).
- [Uniswap StateLibrary: layout do estado](https://raw.githubusercontent.com/Uniswap/v4-core/main/src/libraries/StateLibrary.sol).
- [Uniswap V4Quoter: retorno da cotação](https://raw.githubusercontent.com/Uniswap/v4-periphery/main/src/lens/V4Quoter.sol).
- [Slipstream IQuoterV2: ABI](https://raw.githubusercontent.com/aerodrome-finance/slipstream/main/contracts/periphery/interfaces/IQuoterV2.sol).
- [Aerodrome FactoryRegistry](https://raw.githubusercontent.com/aerodrome-finance/contracts/main/contracts/factories/FactoryRegistry.sol).

- [Slipstream: deployments e quoters por fábrica](https://github.com/aerodrome-finance/slipstream#deployments).
