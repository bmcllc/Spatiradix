# Mycelium-ECO soberano: trabalho útil e liquidação local

**Estado: proposta de arquitetura, baseada na inspeção do repositório em
2026-10-08. O circuito descrito abaixo ainda não está implementado nem ativado.**

## Objetivo e limite econômico

A proposta é operar sem internet, exchange, RPC público, assinatura de API,
custodiante ou modelo de IA remoto. Identidade, tarefas, verificação,
armazenamento, políticas e liquidação ficariam no computador do operador;
outros equipamentos poderiam participar pela LAN. Energia, hardware e
manutenção continuam necessários.

O produto econômico inicial é um **crédito local de direito a serviço**. Ele
representa uma obrigação limitada de entregar um serviço especificado, e não
BTC, USDC, preço em reais ou promessa de valorização. Assinar um saldo não cria
compradores, capacidade física nem renda. Entre bots do mesmo proprietário,
transferências apenas redistribuem orçamento; o ganho possível é o serviço
entregue e a economia de recursos comprovada.

Bitcoin, por exemplo, aceita blocos segundo as regras da sua rede e exige prova
de trabalho. Por consequência, um saldo criado neste livro local não se torna
BTC da rede Bitcoin. Ver [Bitcoin Developer Guide — Block Chain](https://developer.bitcoin.org/devguide/block_chain.html).

## Base existente e lacunas

Ver a [revisão das lacunas de implementação](MYCELIUM_ECO_SOBERANO_LACUNAS.md)
para evidências no código, bloqueios atuais e ordem de entrega.

| Componente | O que existe | O que falta para este circuito |
| --- | --- | --- |
| Mycelium / identidade | Identidades, assinaturas e transporte local/P2P | Restringir participantes, serviços e autoridade de liquidação ao domínio local |
| SporeBank | Armazenamento endereçado por conteúdo | Serviço de backup/cache contratado, manifesto de backup, restauração e medição do resultado |
| Nutrients | Saldos locais, transferências e vouchers | Reserva de orçamento/capacidade e liquidação atômica em um estado autorizado comum |
| Mycelium-ECO | Separação entre trabalho interno e receita externa | Ordens locais e benefícios físicos com tipos próprios |
| Supervisor ECO | Espera, deduplicação de relatórios e gates físicos | Produtor local, executor de serviço e liquidante local; o supervisor atual só descobre oportunidades |

Em [mycelium-nutrients](../../crates/mycelium-nutrients/src/lib.rs), `pledge`,
`heartbeat` e `compute_reward` recebem recursos ou contadores do chamador.
Esses métodos, isoladamente, não provam entrega ou disponibilidade.
`redeem_voucher` verifica assinatura e replay no recebedor, mas não consulta um
estado comum que comprove o débito definitivo do pagador. Identidade e
anti-replay local não resolvem gasto duplicado entre recebedores diferentes.

Por isso, os nutrientes atuais não devem ser promovidos automaticamente a
saldo resgatável deste novo circuito. A migração exige origem e reserva
verificadas, sem alteração silenciosa de saldos existentes.

## Primeiro serviço: backup deduplicado e restaurável

Começar por uma tarefa com utilidade verificável e escopo pequeno:

1. O operador define uma vez os diretórios permitidos, destino de backup,
   retenção, orçamento e limites físicos. Os dados de origem são somente leitura.
2. Um bot detecta alterações nesses diretórios e cria uma ordem local de backup.
   Não gera arquivos artificiais para fabricar demanda.
3. Um executor usa armazenamento por conteúdo, reaproveitando blocos já
   presentes. Trabalha em lotes pequenos e interrompíveis.
4. Um verificador separado do executor confere conteúdo, manifesto e
   restauração. Na primeira versão, cada backup precisa de restauração integral
   verificada antes de ser aceito. Hash sozinho não comprova recuperabilidade.
5. A liquidação transfere o preço reservado do orçamento da ordem para o
   executor, uma única vez. Nenhum crédito novo nasce de contar operações.
6. A medição compara a cópia de referência especificada na ordem com todo o
   espaço físico atribuível ao backup, incluindo índices e manifesto. Economia
   negativa é registrada como custo, não escondida como sucesso econômico.

Isso pode reduzir o tamanho de um backup novo. Não significa que o disco de
origem foi liberado: o circuito não apaga originais. Uma cópia no mesmo disco
também não protege contra falha desse disco. Redundância exige outro suporte,
que pode continuar inteiramente local.

Depois, o mesmo protocolo pode atender cache de resultados determinísticos e
indexação local. Um cache só contabiliza processamento evitado em uma consulta
real, com entradas e versão do serviço correspondentes. Não remunera o bot por
produzir consultas repetidas para si próprio.

## Créditos, capacidade e liquidação

### Emissão limitada

- Cada crédito identifica domínio, serviço, unidade, provedor e validade.
  Unidades de armazenamento e de processamento não são somadas como se fossem
  uma mesma moeda.
- Uma emissão é uma alocação explícita da política inicial, vinculada a uma
  reserva de serviço e a um limite total. A capacidade disponível precisa ser
  medida, com margem para uso do proprietário, falhas e limites térmicos.
- Direitos emitidos e ainda válidos não podem superar a reserva correspondente.
  Trabalho entregue, uptime, número de bots e CPU declarada não autorizam emissão.
- Transferências conservam o total de créditos. Resgate e expiração retiram
  direitos conforme regras previamente fixadas; não produzem créditos de volta
  automaticamente.
- Falta de capacidade bloqueia novas emissões/ordens. Uma falha física não pode
  ser resolvida inventando lastro ou apagando obrigações já assumidas.

O limite evita prometer o mesmo recurso várias vezes; não torna hardware futuro
infalível. Inicialmente, esses créditos são contabilidade de serviço dentro do
domínio confiável do operador. Sua aceitação fora dele dependeria de outras
pessoas ou sistemas, algo que este projeto não pressupõe.

### Um estado autorizado, sem mineração por hashes

Para um computador ou uma LAN sob o mesmo operador, usar **um liquidante local
com um único escritor**, diário persistente e transações atômicas. Ele autentica
ordens e mantém saldos, reservas, emissões e recibos. Os workers não escrevem
seus próprios saldos. Não há necessidade de PoW para esse modelo de confiança.

Cada ordem vincula `domain_id`, `job_id`, pagador, executor, versão/hash da
política, entradas, preço, unidade, reserva, geração do executor e validade.
Assinaturas atribuem responsabilidade; o verificador confere a entrega.

```text
necessidade local autorizada
    -> ordem assinada
    -> reserva atômica de orçamento e capacidade
    -> gate físico -> execução limitada
    -> verificação do resultado
    -> débito + crédito + recibo, na mesma transação
    -> medição de benefício local
```

O banco rejeita `job_id`/recibo repetido e saldo insuficiente. Confirmação ao
worker só acontece depois do commit durável. Reinício durante execução ou
liquidação exige conciliação; uma geração antiga do worker não pode confirmar
uma ordem já encerrada. Expiração, cancelamento e liberação de reserva têm
transições definidas na política, sem liberar e pagar a mesma reserva.

Uma partição da LAN impede liquidação final até reconexão ao liquidante.
Resultados podem ficar pendentes; nós desconectados não criam saldos definitivos
por conta própria. Sincronizar pelo maior saldo ou timestamp não é consenso de
pagamento. Se o futuro exigir operadores mutuamente desconfiados, será preciso
outro protocolo e outro modelo de segurança. Replicar máquinas do mesmo dono
não cria demanda independente nem proteção contra esse dono.

O liquidante é uma autoridade local, portanto o MVP é centralizado dentro desse
domínio. Comprometimento do host/chave é risco de confiança. Um diário com hashes
ajuda a auditar, mas não impede o administrador de substituir todo o histórico;
checkpoints guardados em outro suporte local ajudam a detectar essa substituição.

## Benefício local, NEV e NO_EDGE

Manter três medidas distintas:

| Medida | Significado |
| --- | --- |
| Créditos locais | Direitos/obrigações de serviço e distribuição do orçamento |
| Benefício local verificado | Resultado entregue e economia física, quando medida |
| `VerifiedNev` / `PaidDemand` | Valor externo com as provas exigidas pelo ECO existente |

Os recibos deste circuito são `internal_work=true`. Não promovem RV/ARV, não
criam `VerifiedNev` e não financiam reinvestimento externo. O caminho atual de
Base/USDC conserva todas as exigências de liquidação e de provider autenticado.

A decisão local usa limites por recurso, e não uma soma arbitrária de bytes,
joules, tempo e reputação. Para cada serviço, a política define utilidade mínima,
orçamento de CPU/I/O/disco, prazo e condição de verificação. Energia e desgaste
sem medição ficam desconhecidos; não são tratados como zero. Benefícios futuros
estimados não são benefícios já realizados.

Sem necessidade autorizada ou sem vantagem suficiente, o bot entra em espera.
Isso aplica o princípio de `NO_EDGE` ao trabalho local; não libera o gate
financeiro existente. Despesa inicial de backup pode ser autorizada pelo
orçamento de manutenção por sua utilidade, sem fingir que é lucro.

## Autonomia com limites físicos

Após configuração inicial, bots podem detectar alterações, contratar dentro de
cotas, executar, verificar, liquidar, auditar e esperar sem aprovação por tarefa.
Eles não podem ampliar orçamento, emitir fora da política ou alterar regras
para transformar perdas em ganhos.

Reutilizar os gates térmicos/MUPP existentes, com bloqueio por sensor ausente ou
obsoleto. Aplicar os limites também ao produtor local, verificador e workers;
os limites atuais do subprocesso de descoberta não cobrem automaticamente essas
novas etapas. Usar um worker inicial, evitar GPU, limitar CPU/I/O e espaçar lotes,
calibrando com o equipamento real. Nenhum limite de software garante calor zero.

Executar com usuário sem privilégios, acesso mínimo aos diretórios e ao banco,
autenticação de workers e permissões privadas para chaves. O perfil offline não
usa DNS público, RPC, APIs ou downloads de modelos. Queda do liquidante, sensor
inválido, disco cheio ou inconsistência de estado bloqueiam novas ordens até
recuperação segura.

## Critérios antes de ativar

1. Completar um backup real pequeno com internet indisponível e verificar a
   restauração, sem alterar arquivos de origem.
2. Mostrar separadamente créditos, espaço usado/economizado e custos observados;
   receita externa permanece sem promoção.
3. Repetir ordem/recibo, interromper antes/depois do commit e reiniciar: nenhum
   pagamento duplicado, saldo negativo ou reserva reutilizada.
4. Desconectar um worker: nenhuma liquidação definitiva baseada apenas em seu
   saldo declarado ou voucher.
5. Com sensor obsoleto, disco cheio ou orçamento esgotado, parar automaticamente.
   Sem mudanças nos dados e sem ordens pendentes, permanecer ocioso.
6. Auditar conservação dos créditos, limites de emissão e reservas de serviço.

Esses são critérios para a implementação futura, não testes já aprovados. As
alterações Rust anteriores do supervisor ainda precisam de compilação e testes
em condições térmicas seguras. Este documento não ativa serviços, emite ativos
ou modifica os ledgers existentes.

Referências locais: [economia autônoma](AUTONOMOUS_BOT_ECONOMY.md),
[RV0](RV0_REVENUE_VALIDATION.md),
[supervisor ECO](../../apps/mycelium-next/README.md#supervisor-nativo-mycelium-eco)
e [SporeBank](../../crates/mycelium-sporebank/README.md).
