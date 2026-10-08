# Mycelium AEM-ECO v0.1 — cripto por utilidade comprovada, sem mineração agressiva

Data: 2026-10-07. **Escopo atual: projeto arquitetural e avaliador offline SHADOW. Não há token novo emitido, transação enviada, preço sustentado, rendimento comprovado ou automação financeira habilitada.**

## Objetivo

Reduzir CPU/GPU, aquecimento, capital em risco e intervenções rotineiras, preservando NEV, NO_EDGE e a fronteira contábil já testada. Ganhar um token, emitir MYC, vender trabalho e receber USDC são eventos diferentes e DEVEM ter contabilidades diferentes. Melhorar utilidade pode aumentar demanda legítima por MYC; nenhum software garante valorização de preço.

## Evidência do repositório (verificada por inspeção)

- `crates/mycelium-economy/src/discovery.rs`: NO_EDGE de arbitragem não prova ausência global de receitas; o módulo atualmente reconhece classes não implementadas. Nunca reduzir limiar mínimo de lucro para forçar execução.
- `crates/mycelium-economy/src/verified_view.rs` e `reinvestment.rs`: NEV com autoridade apenas após leitura independente de cadeia/política/limite; simulação, saldos internos e flags de recebimento não autorizam investimento.
- `crates/mycelium-economy/README.md`: a liquidação USDC é verificada em provider pinado; não existe assinador nem método de broadcast neste crate. Preservar essa separação.
- `apps/mycelium-next`: já possui fila SQLite, limites térmicos 75 °C / retomada 70 °C, estado MUPP obrigatório, idempotência, diário, verificação de artefatos. Não criar segundo daemon para duplicar tais recursos.
- `crates/mycelium-bot/src/main.rs` permanece um protótipo de registro aleatório de trades, com `temperature_ok()` sempre true. **Não autorizar trades, não usá-lo como executor e não supor proteção térmica.**
- Leitura pontual em 2026-10-07 durante inspeção: CPU Package 80 °C; acima do teto de execução local de 75 °C. Esta leitura é pontual e exige nova medição antes de qualquer trabalho, mesmo que o projeto seja retomado depois.

## Arquitetura escolhida

```text
             MYCELIUM AEM-ECO — 1 NOTEBOOK
  serviços externos / clientes / protocolos reais
                        |
              oportunidade ou job
                        |
             S1 + discovery existente
                /               \
          NO_EDGE              candidato
            |                     |
  rotate suportado/backoff  simulação / checagem
            |                     |
    COLD_DISCOVERY       prova do trabalho/COSMIC/CQR
            |                     |
    mínimo CPU + sono      aceitação e pagamento
                                  |
                  VerifiedEconomyView (Rust existente)
                                  |
                        NEV comprovado > 0?
                          /            \
                        não            sim
                         |              |
                      reserva      ReinvestmentController
                         |              |
                        NO      orçamento limitado para
                    COMMITMENT    serviço/trabalho real
                                        |
                                crescimento condicionado
                                à demanda e temperatura

  Controle fora da cadeia: MUPP físico + cgroups + auditoria
  Emissão MYC (futuro): consenso + recibos únicos + política de emissão
  Executor on-chain (futuro): assinatura separada com limites explícitos
```

## Fonte de renda com menor consumo

1. PRIORIDADE 1 — Serviços verificáveis cobrados em USDC: verificação de artefatos, compute CQR, armazenamento/retrieval, tarefas de agentes com resultado comprovável; demanda pagante precisa ser descoberta, não inventada.
2. PRIORIDADE 2 — Recompensas de protocolos externos que paguem por tarefa, solver, keeper ou operação útil; checar taxas e aceitação no fechamento, primeiro em SHADOW.
3. PRIORIDADE 3 — Arbitragem Base, apenas quando `RobustNetAfterAllCosts > 0`, simulação exata, autorização separada e saldo de gas real. `NO_EDGE(Arbitrage)` leva a backoff/rotação, não a trades forçados.
4. RECOMPENSAS MYC internas: apenas créditos de contribuição. Não são USDC, receita externa ou prova de preço. Emissão futura deve ocorrer somente em uma chain com consenso funcional e defesa Sybil.

## Emissão MYC com pouco hardware

Não tentar produzir BTC com zero gasto de hashes. Projetar `Proof-of-Verified-Service` **como política de recompensa**, não como substituto de consenso. Um pagamento externo reconhecido por recibo independente ou uma tarefa útil com prova validada pode tornar-se elegível a MYC, sujeito a:
- Identificador de job/recibo único, gasto único, assinatura independente, deduplicação, bloqueio de auto-pagamento e de circularidade entre contas controladas.
- Verificador reproduzível, reputação com proteção Sybil, contestação/slashing quando aplicável e limite global de emissão. O teto de 1.000 MYC/dia das simulações anteriores é apenas candidato de parametrização, NÃO criação executada.
- Consenso BFT/PoS real e política anti-partição antes de a recompensa ser irreversível; não confundir um ledger JSON local com blockchain.
- Atribuir custo marginal de eletricidade, falha, fraude, rede, wear e liquidez, mesmo quando o número ainda for `unknown`.

## Bots e valorização

Bots permitidos: encontrar jobs, verificar provas, reconciliar USDC/recibos, rotear capacidade, detectar fraude e explorar oportunidades economicamente independentes.

Bots NÃO permitidos no AEM: wash trading, self-match, ordens fictícias, spoofing, volume circular, pump coordenado, promessas de aumento do preço, transações próprias registradas como receita. Não programar compra automática de MYC só para mover cotação. Demanda legítima se constrói com serviços úteis, precificados e pagos por usuários/protocolos externos.

Reinvestimento: usar **somente** os valores `VerifiedNev` do Rust existente, com provider realmente pinado, após reservas, cap diário, risco e gate térmico. Nenhum número em JSON de entrada do SHADOW confere autoridade financeira.

## Consumo e modo autônomo

- Padrão: GPU off; sensores leves; nenhuma varredura contínua; um worker no máximo *após* liberação e baseline. Não fixar watts ou lucro sem medição.
- Sob calor >=75 °C, sensor ausente/obsoleto/futuro ou MUPP negado: não executar tarefas.
- Uma vez bloqueado por calor, liberar somente com leitura válida <=70 °C e MUPP permitindo. O gate efetivo continua no `mycelium-next`; o SHADOW apenas aconselha.
- `NO_EDGE`: backoff exponencial com teto de 1 h. Rotacionar somente para classe com adapter real; seis classes declaradas ainda não garantem seis adapters.
- Processos de percepção e cópias de dados devem ter TTL e cota; não rodar pesquisas, treino de IA ou provas repetidas para “fabricar” NEV.
- Recursos quando houver carga: cgroup CPU/IO/memória e fila única, a ser adicionado ao executor real depois da validação térmica.

## Artefatos novos, sem interferir na base

`apps/mycelium-next/aem_shadow.py` contém uma função pura de decisão com relógio/sensor/MUPP, histerese, NO_EDGE, backoff e recomendação de modo.

`apps/mycelium-next/test_aem_shadow.py` testa relógio futuro, sensor ausente, calor, histerese, MUPP negado, NO_EDGE, classes não suportadas, entradas contraditórias e **nenhuma autoridade de emissão/trading/reinvestimento**.

**O módulo está isolado e não é chamado pela fila ou pela rede; só emite recomendações JSON.** Não usar sua saída como autorização. Antes de integrar, provar todas as invariantes com testes e a saída genuína dos sensores/MUPP e sem contornar o Rust `verified_view`.

Uso apenas quando houver condição térmica segura para testes locais:

```sh
cd '/media/bruno/SAMBOOK/Mycelium Network'
python3 -m unittest discover -s apps/mycelium-next -p test_aem_shadow.py -v
```

Não ligar `mycelium-bot` para negociação; não adicionar cron/daemon novo sem validação.

## Gates de entrega

- G0 (feito): inspecionar os componentes e produzir política SHADOW sem permissões financeiras.
- G1: testes isolados, integração de sensores/MUPP e medições úteis com hardware seguro.
- G2: job CQR real aceito por mecanismo de verificação, métricas e custo reproduzível.
- G3: pelo menos um cliente/protocolo externo aceita um resultado e liquida um pagamento verdadeiro; NEV positivo após todos os custos.
- G4: cobrança/recebimento automatizados com chaves separadas e recuperação de falhas; limites autorizados de tesouraria e compliance.
- G5: somente após consenso auditado e defesa anti-Sybil, estudar distribuição/emissão MYC e mecanismos de liquidez baseados em utilidade.

## Indicadores obrigatórios

```text
sensor_age_s, max_package_temp_c, mupp_state, allowed_jobs
useful_jobs_accepted, paid_jobs_settled, cost_per_validated_job
external_verified_inflows, external_verified_outflows, verified_NEV
NO_EDGE_by_class, coverage_by_class, cold_backoff_seconds
MYC_issued_on_consensus, real_token_demand, circulating_supply
unknown_energy_cost, unknown_external_revenue (nunca tratar como 0 medido)
```

## Limite econômico

`MYC_price` NÃO decorre da emissão. Sem compradores reais, não há liquidez executável garantida; com bots comprando de si próprios não existe receita nova. A única fórmula de sustentabilidade é `recebimentos_externos_reconciliados - saídas_externas_reconciliadas - custos_reais > 0`. Simulações da tokenomics 4X são hipóteses, não receitas. Qualquer operação comercial no Brasil requer avaliar a regulamentação aplicável de prestadores/serviços de ativos virtuais e obrigações fiscais.
