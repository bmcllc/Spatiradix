# AEM-ECO v0.2 — receber cripto por serviços leves, com custo e calor limitados

Continuação de [AEM-ECO v0.1](AEM_ECO_V01.md) e da proposta S1-MEM. A evolução é trocar a busca de ocupação máxima da máquina pela seleção de **trabalho útil, pequeno e pago por clientes externos**. O bot pode ficar ocioso. Sem demanda ou margem suficiente, executar menos é a decisão econômica correta.

Não há computação sem dissipação de calor nem mecanismo que garanta valorização de um token. O objetivo é limitar o consumo adicional e obter receita verificável em cripto, sem depender de mineração PoW na CPU/GPU. Demanda e preço de mercado continuam externos ao sistema.

## 1. Modelo mais barato

Usar um processo local, uma fila e no máximo um trabalho por vez. Os agentes Sensor, Descoberta, Cotação, Verificador e Contabilidade são funções lógicas; não exigem cinco máquinas ou cinco modelos de IA rodando continuamente. Preferir eventos e regras determinísticas a consultas repetidas ou inferência pesada.

Priorizar propostas de serviços pequenos: verificar hashes e manifestos, conferir um resultado limitado, produzir um recibo de entrega ou manter um artefato pequeno solicitado pelo cliente. Uma tarefa interna ou uma operação que qualquer cliente realiza gratuitamente não comprova demanda. Cada serviço precisa de cliente, contrato de aceitação e adaptador implementado antes de entrar na fila real.

O pagamento proposto é em USDC; MYC pode representar crédito interno de uso. Emitir MYC, pagar a si mesmo ou simular receita não gera renda externa nem NEV realizado. USDC é o ativo de cotação deste protótipo, sem promessa de estabilidade de preço ou ausência de risco do emissor/rede.

Evitar PoW local, GPU, múltiplos workers e descoberta contínua por polling curto. Não transferir carga para a nuvem sem incluir cobrança, rede, armazenamento e disponibilidade no custo. A máquina ligada enquanto espera também tem custo: o modo econômico precisa considerar desligamento/suspensão quando compatível com o serviço.

## 2. Fórmula de admissão

Para cada proposta, todos os valores monetários usam **inteiros em micro-USDC** (1 USDC = 1.000.000 unidades):

```text
C_superior = energia + liquidação + RPC + armazenamento + desgaste
Exposição  = C_superior + reserva_de_risco
P_inferior = pagamento_inferior - Exposição

Proposta viável ⇔ P_inferior ≥ margem_mínima_fixa > 0
                  e Exposição ≤ teto_por_trabalho
                  e Exposição ≤ teto_diário - gasto - já_reservado
```

`P_inferior` é previsão condicionada às estimativas fornecidas; **não é VerifiedNev**. Uma declaração de financiamento não prova que o cliente pode pagar. A reserva de risco reduz a margem prevista e a exposição disponível, mas não vira despesa realizada automaticamente. A margem mínima não diminui após NO_EDGE.

Cada componente de custo deve estar presente. `null` significa desconhecido e bloqueia a admissão econômica; `0` é uma declaração explícita, que ainda precisa ser justificada. A fórmula não permite tratar falta de medição como energia grátis. Taxas de liquidação precisam incluir os custos pertinentes de entrega, falha, retry e recebimento, com limites conservadores; etapas ausentes invalidam a previsão.

Para energia, quando houver um limite superior medido de consumo atribuível ao trabalho:

```text
energia_micro_USDC = ceil(joules_superiores × tarifa_micro_USDC_por_kWh / 3.600.000)
```

Temperatura não mede joules. Uma tarifa em BRL exige conversão explícita e conservadora para USDC, com origem e validade; não se pode somar BRL e USDC. A medição deve abranger execução, verificação, rede e custos atribuíveis. Consumo de espera/descoberta e despesas fixas entram também na avaliação do período; não desaparecem porque uma proposta individual parece lucrativa.

**Exemplo exclusivamente sintético:** pagamento de 1 USDC, custo superior de 0,10 USDC e reserva de 0,05 USDC produzem previsão de 0,85 USDC. Isso não demonstra que esse cliente, preço ou serviço existe. O avaliador não procura clientes, mede energia ou recebe pagamento.

## 3. NEV realizado e NO_EDGE têm papéis distintos

**NEV:** o resultado econômico comprovado por evidências válidas. O caminho Rust existente usa `VerifiedNev`, construído por autoridades e verificações próprias; um JSON com `proof_verified=true` ou uma previsão positiva não substitui esse caminho.

É necessário declarar o escopo contábil. Um NEV que já desconta gas não deve ter o mesmo gas descontado novamente. Para avaliar o negócio no período, reconciliar receitas externas liquidadas, perdas e despesas efetivas com identificadores únicos, incluindo energia de espera/descoberta, RPC, armazenamento e desgaste. Não selecionar apenas operações vencedoras. Essa reconciliação operacional completa ainda precisa ser implementada e ligada às evidências reais.

**NO_EDGE:** esperar ou abandonar uma proposta quando o ganho líquido não supera o piso. O bot não deve compensar a falta de margem aumentando potência, risco, emissão ou alavancagem. O estado NO_EDGE da descoberta atual cobre arbitragem suportada; não comprova ausência de oportunidades em todas as classes.

`NO_EDGE_QUOTE`, introduzido aqui, avalia apenas uma cotação. Não altera o NO_EDGE da descoberta nem sua memória. Um coordenador futuro poderá reagendar uma classe após rejeições, preservando esses escopos e registrando a origem de cada conclusão.

O controlador shadow existente usa espera de **60, 120, 240… até 3.600 segundos** quando observa NO_EDGE. Trocar de classe só faz sentido com adaptador implementado e orçamento próprio. Não inventar suporte a compute/storage/keeper porque há um nome no enum.

## 4. Perfil térmico proposto

| Regra | Comportamento |
|---|---|
| GPU | Desligada para estes serviços; proposta que exige GPU é recusada |
| Concorrência | Um trabalho; verificar consumo agregado dos subprocessos |
| CPU | Propor teto médio de 20% de **um** núcleo, com quota aplicada pelo executor |
| Duração | Até 10 segundos totais de CPU e 30 segundos de parede por proposta; limites podem ser menores |
| Faixa desejada | Começar pequeno e reduzir/pausar entre 60–65 °C, conforme medição do equipamento |
| Guarda atual | Bloqueia em ≥75 °C; após bloqueio só libera em ≤70 °C |
| Evidências | Sensores e S1-MUPP atuais e válidos; ausentes, futuros ou vencidos bloqueiam |

Os limites de CPU/parede da cotação são estimativas, não um sandbox. A quota de 20% e a faixa suave de 60–65 °C são propostas **a implementar no executor**; não foram aplicadas ao sistema. O corte 75/70 °C é uma regra operacional existente, não uma garantia térmica do fabricante. Atraso de amostragem e outros programas podem gerar picos.

As simulações anteriores com ocupação de 90–95% não provam um ótimo real nem servem para este perfil de baixo consumo. Não aumentar carga para reproduzir um ganho simulado. Os registros do projeto já mostram picos de compilação; este incremento usa Python e testes curtos, sem iniciar compilação ou trabalho científico.

## 5. Bots com rotina autônoma limitada

```text
Sensores + S1-MUPP → verificar guarda
                              ↓
             descobrir somente classes implementadas
                              ↓
          obter cotação + evidência de cliente/financiamento
                              ↓
             calcular margem e consultar orçamento
                       ↓                  ↓
                   sem margem          elegível
                       ↓                  ↓
                   esperar       validar tudo independentemente
                                          ↓
                              reservar orçamento atomicamente
                                          ↓
                               executar trabalho limitado
                                          ↓
                           verificar entrega + receber liquidação
                                          ↓
                          registrar resultado completo comprovado
```

Em uso real, reservar orçamento e impedir duplicação precisam acontecer atomicamente no armazenamento persistente, inclusive após reinício e na troca do dia UTC. O executor revalida sensores/MUPP antes de trabalhar e entregar; um conselho shadow antigo não autoriza nada. Se o custo real ultrapassa a estimativa, parar e revisar a classe, preservando a perda na contabilidade.

Depois de configuração inicial e validação, a rotina pode dispensar aprovação humana por tarefa dentro de limites previamente definidos. Mudanças de ativo, rede, permissões, modelo de risco ou tetos exigem revisão da política. Falhas de sensores, pagamentos, clientes ou refrigeração podem demandar manutenção; autonomia não elimina essas dependências.

Para futura liquidação, usar credenciais restritas ao contrato/rede necessários e teto financeiro; não entregar ao bot uma carteira principal sem limites. Reinvestimento futuro deve exigir NEV comprovado, reserva operacional e sua própria política, nunca apenas a previsão desta cotação.

## 6. Como isso pode sustentar valor

O ciclo economicamente defensável é **cliente externo → serviço útil → entrega aceita → pagamento liquidado → reputação e demanda recorrente**. Bots ajudam a reduzir custo e falhas. Se MYC tiver uma utilidade comprovada e política sustentável, maior demanda por essa utilidade pode influenciar seu valor; isso não garante valorização, liquidez ou renda mensal.

Não usar wash trading, volume artificial, auto-pagamentos ou compras circulares como evidência de valor. Não emitir recompensa sem receita e chamá-la de lucro. A mineração proposta é prestação de serviço remunerada em cripto, não criação gratuita de moedas.

Arbitragem/MEV não é o caminho inicial recomendado para este equipamento: a documentação do Ethereum descreve busca automatizada competitiva e disputa por taxas, que reduz margens. [Ethereum: MEV](https://ethereum.org/en/developers/docs/mev/).

Flash loan também não elimina custos: o Aave exige devolução com a taxa aplicável na mesma transação; a taxa é governável e deve ser consultada no protocolo, não fixada por suposição. Esse mecanismo não fornece clientes nem lucro por si só. [Aave: flash loans](https://aave.com/docs/aave-v3/guides/flash-loans).

## 7. O que existe nesta versão

| Peça | Situação |
|---|---|
| `aem_shadow.py` e `aem_bridge.py` | Conselho passivo já ligado à guarda local; sem autoridade financeira |
| `aem_economics.py` | Novo avaliador offline de cotação, custos, recursos e orçamento |
| `test_aem_economics.py` | Testes sintéticos de limites e bloqueios; não acessam hardware/carteira |
| Ligação cotação → fila real | Ainda não implementada |
| Medição de joules e contabilidade operacional completa | Ainda não implementada |
| Demanda paga/receita real → bridge | Não conectada; não confundir com campos declarados |
| Adaptadores de serviços leves | Propostas; precisam de implementação e comprador real |
| Execução financeira, mint ou reinvestimento | Não ativados |

O avaliador recebe JSON de até 64 KiB com `quote`, `policy`, `budget`, `observation` e opcionalmente `memory`. Valores duplicados, tipos ambíguos e números não finitos são recusados. As declarações de cliente, financiamento e adaptador permanecem **não confiáveis**. Um orçamento fornecido por JSON não é a reserva persistente do executor.

Mesmo `READY_FOR_VERIFICATION_SHADOW` significa apenas “previsão apta para verificação”. Toda saída mantém `verified_nev=null` e `execution_authorized`, `trade_authorized`, `mint_authorized`, `reinvestment_authorized` em `false`. Não há rede, carteira, assinatura, medição de energia ou criação de tarefa nesse módulo. Ele não modifica o `Engine.gate()`.

Regressão local leve, a partir da raiz do projeto:

```bash
rtk proxy python3 -m unittest discover -s apps/mycelium-next -p 'test_*.py'
```

Validação em 2026-10-07: **99 testes PASS em 0,406 s**, incluindo 20 testes novos de cotação econômica. Sensores reais lidos depois da regressão mostraram CPU Package em **49 °C**; é uma amostra sem carga produtiva, não uma prova de temperatura futura. Confirmada a ausência de `/tmp/s1-mupp-state.json` e de `target/debug/mycelium-cqr-worker`. Nenhuma compilação real, tarefa produtiva ou operação financeira foi iniciada nesta evolução.

## 8. Critérios antes de sair do shadow

1. Identificar e validar o produtor S1-MUPP genuíno; preservar bloqueios. Os últimos registros do projeto apontam arquivo ausente e worker CQR ainda não produzido. Não fabricar evidência de liberação.
2. Medir custo energético e comportamento térmico de um serviço mínimo, contabilizando também a espera. Validar a quota de CPU no executor antes de carga contínua.
3. Implementar um adaptador com aceitação verificável e conseguir um cliente externo com pagamento comprovável. Produzir uma entrega pequena e reconciliar o pagamento real, taxas, energia e perdas.
4. Validar reserva atômica, deduplicação, recuperação após falhas, teto por tarefa/dia e parada por sensor/financiamento inválido. Só então ligar rotina autônoma de execução dentro da política.

Até esses critérios serem satisfeitos, esta é uma evolução de projeto e um avaliador offline: não demonstra mineração lucrativa, trabalho pago disponível ou valorização automática.
