# O que falta para o Mycelium-ECO soberano

**Revisão de 2026-10-08. Há componentes aproveitáveis, mas ainda não há um
circuito completo de serviço, verificação e liquidação local.**

Escopo: inspeção do código e leituras pontuais de arquivos/sensores. Não foram
executados builds, testes de carga, bots, transferências ou novos serviços nesta
revisão. Os critérios abaixo são trabalho pendente, não resultados aprovados.
Esta revisão não substitui uma auditoria completa de segurança.

Referência de arquitetura: [Mycelium-ECO soberano](MYCELIUM_ECO_SOBERANO.md).

## Base que já existe

| Componente | Evidência no código | Reaproveitamento e limite |
| --- | --- | --- |
| Identidade e transporte Mycelium | [node](../../crates/mycelium-node/src/organism.rs) | Autenticação e comunicação; ainda é preciso limitar o domínio e os caminhos de saída do novo serviço. |
| Armazenamento por conteúdo | [SporeBank](../../crates/mycelium-sporebank/src/lib.rs), `deposit`, `atomic_write` | Já há persistência com arquivo temporário, sincronização e rename. Isso não constitui, sozinho, um backup restaurável de diretórios. |
| Fila durável e deduplicação | [Mycelium Next](../../apps/mycelium-next/mycelium_next.py), `submit`, `run_once` | SQLite, chave idempotente e tratamento de execução incerta. Classes atuais: `backend_health`, `artifact_verify`, `cqr_c0`. |
| Verificação de artefato | [backend](../../apps/mycelium-next/mycelium_backend.py), `task_leaves`, `verify_task` | Manifesto, tamanho e SHA-256 de um artefato limitado a 128 KiB. Falta o contrato de backup de múltiplos arquivos e restauração integral. |
| Registro econômico | [LocalEconomy](../../crates/mycelium-economy/src/lib.rs), `append_job`, `append_work`, `append_settlement` | Já registra ordens, trabalho e liquidação, com verificações e deduplicação. Não encontrei o banco de orçamento e capacidade da proposta soberana. |
| Separação de receita externa | [economy](../../crates/mycelium-economy/src/lib.rs), `internal_work`, `is_external_paid` | Trabalho interno não deve virar receita externa ou `VerifiedNev`. Preservar essa fronteira. |
| Gates físicos | [Next](../../apps/mycelium-next/mycelium_next.py), `gate`; [S1](../../apps/mycelium-next/s1_gate.py), `evaluate` | Sensores reais, histerese e bloqueio por estado ausente/inválido/antigo. Precisam cobrir todas as etapas novas. |
| Supervisor ECO | [supervisor](../../apps/mycelium-next/eco_supervisor.py), `NativeRunner`, `EcoSupervisor` | Descoberta limitada e deduplicação de relatórios; os comandos permitidos são discovery/status/dashboard, sem execução de serviços ou pagamentos. |

O caminho mais curto é ampliar essa base com um serviço pequeno. Criar outro
loop que apenas imprime operações não resolve a falta do circuito econômico.

## Bloqueios atuais e prioridades

### P0 — proteção física real e estado S1 disponível

O [bot Rust](../../crates/mycelium-bot/src/main.rs), linhas 7–10, tem
`temperature_ok()` retornando sempre `true`. As linhas 25–34 sorteiam uma
quantidade e um destino, registram uma mensagem e deixam o envio comentado.
Esse bot é um protótipo; suas mensagens não comprovam trades ou recebimentos.

Reaproveitar os gates reais do Next, eliminando o placeholder no caminho do novo
worker. Aplicar a proteção ao produtor, executor e verificador, com limites de
CPU, I/O, disco e tamanho dos lotes. A configuração deve ser validada para o
hardware; os valores atuais de pausa/retomada de 75/70 °C não garantem calor zero.

Na leitura desta revisão, `/tmp/s1-mupp-state.json` estava ausente. O gate S1
exige estado genuíno com idade máxima de cinco segundos; portanto, esse requisito
continua bloqueando execução. Falta identificar e integrar o produtor local
desse estado, sem preencher evidência artificialmente nem remover o gate.

A maior leitura térmica pontual foi **58,05 °C**. Ela não demonstra segurança sob
carga. O [README do Next](../../apps/mycelium-next/README.md) registra picos
anteriores e builds interrompidos; a validação Rust continua pendente em
condições adequadas.

### P0 — demanda local e serviço de backup completo

Falta um produtor que transforme alterações reais em diretórios autorizados em
ordens de serviço. A fila existente recebe tarefas explícitas; o supervisor
consome relatórios já produzidos. Não encontrei o produtor automático de backup
da proposta. O caminho de relatório do exemplo,
`apps/mycelium-next/var/s1-search-report.json`, também estava ausente; isso não
exclui a existência de outra configuração.

Definir uma política inicial com origem somente leitura, destino, retenção,
cotas, identidades autorizadas e condição de aceitação. Para proteção contra
falha do disco, o destino precisa estar em outro suporte, que pode ser local.

Implementar blocos deduplicados, manifesto de diretórios e restauração integral
para um destino de verificação separado. Definir tratamento de links,
permissões, arquivos em alteração e retenção; não remover blocos ainda usados
por backups válidos. O verificador deve rejeitar conteúdo ausente ou corrompido
e confirmar a restauração antes de autorizar pagamento. Os originais não são
apagados nem modificados.

### P0 — reserva e liquidação local atômica

Falta um estado autorizado comum para contas, orçamento, capacidade reservada e
recibos. O `LocalEconomy` existente é uma base de registro, mas seus modos atuais
são `Simulated` e `External`; registrar um recibo não equivale à transação de
créditos de serviço descrita na proposta.

Em [Nutrients](../../crates/mycelium-nutrients/src/lib.rs), `redeem_voucher`
verifica assinatura e replay no ledger recebedor, depois credita o saldo. Essa
função não comprova débito definitivo e reserva em um banco comum. `pledge`,
`heartbeat` e `compute_reward` também aceitam recursos/contadores do chamador,
sem comprovar por si só a entrega de serviço.

Implementar um liquidante local com um único escritor e transações duráveis:

1. Validar domínio, política, entradas, preço, unidade, executor e validade da ordem.
2. Reservar orçamento e capacidade sem prometer o mesmo recurso duas vezes.
3. Aceitar apenas a entrega verificada correspondente à ordem e à geração ativa.
4. Confirmar débito, crédito, consumo/liberação de reserva e recibo na mesma transação.
5. Rejeitar replay, saldo insuficiente, valores fora dos limites e overflow;
   confirmar ao worker somente depois do commit.

Separar crédito de serviço de nutrientes antigos e de valores em USD. A emissão
inicial deve ter limite explícito e capacidade reservada; transferências
conservam o total, e resgate/expiração seguem a política. Não converter saldos
antigos automaticamente nem emitir por uptime ou contagem de operações.

### P0 — recuperação automática dentro da política

Next e supervisor já colocam operações incertas em `needs_reconciliation`.
Isso evita repetição cega, mas ainda não encontrei recuperação automática para
o novo serviço e suas reservas. Autonomia exige resolver os casos comprováveis
sem aprovação por tarefa.

Definir transições de reserva, execução, verificação, commit, cancelamento e
expiração. Após reinício, consultar artefatos e estado autoritativo antes de
retomar ou liberar reserva. Usar geração do executor para recusar confirmações
antigas. Se não houver evidência suficiente, manter a operação pendente e
bloquear a ação dependente; nunca inventar sucesso para manter o bot ativo.

Na LAN, um worker sem contato com o liquidante pode conservar um resultado
pendente, mas não criar saldo final. Recuperação não deve repetir pagamento já
confirmado nem liberar uma reserva que também será paga.

### P0 — caminho privado e perfil offline verificável

O backend atual usa `repo_publish` para artefatos públicos. Em
[Organism](../../crates/mycelium-node/src/organism.rs),
`publish_repo_ref_expected` exige Plot público e tenta distribuir seu conteúdo
pela DHT e lattice. Não reutilizar esse caminho para arquivos privados de backup.

Usar armazenamento privado local e, se houver LAN, transporte autenticado
restrito aos participantes autorizados. Definir acesso mínimo aos diretórios,
permissões de chaves, proteção dos dados no suporte e um perfil que não dependa
de DNS público, RPC, APIs ou downloads. A existência de armazenamento privado no
SporeBank ajuda, mas o caminho completo do serviço ainda precisa ser integrado
e verificado offline.

### P1 — medição e operação contínua

Faltam métricas do serviço real: bytes de origem, cópia de referência, espaço
físico atribuível ao backup incluindo índices/manifestos, duração e custo
observado. Energia não medida deve continuar desconhecida. Deduplicação que
aumenta o espaço usado deve aparecer como custo.

Exibir separadamente créditos, benefício físico e receita externa. Sem demanda
autorizada ou orçamento, entrar em espera (`NO_EDGE` local), sem fabricar
consultas ou arquivos para aumentar contadores.

Depois da aceitação do circuito, preparar inicialização automática, reinício
limitado, recuperação de chaves/estado, checkpoints em outro suporte local e
registros de falhas. A configuração inicial substitui decisões humanas por
tarefa; não elimina manutenção física.

## Ordem prática de implementação

1. Resolver a integração S1 e a validação física; manter bloqueio até haver
   estado genuíno e condições adequadas.
2. Implementar política, ordens tipadas e banco transacional de créditos,
   orçamento e reservas, separado da receita externa.
3. Acrescentar um único worker de backup privado, limitado e interrompível,
   com restauração verificada antes da liquidação.
4. Conectar produtor de alterações reais, recuperação após reinício e métricas.
5. Validar o ciclo offline e somente então habilitar operação contínua.

O primeiro marco é **um backup pequeno real, restaurado e verificado, com uma
única transferência de crédito reservado e nenhum arquivo de origem alterado**.
Escalar bots antes disso multiplica componentes sem comprovar entrega.

## Evidência necessária para aceitar o marco

| Cenário | Resultado exigido |
| --- | --- |
| Internet indisponível | Detectar alteração, executar backup privado, restaurar, verificar e liquidar localmente. |
| Ordem ou recibo repetido | Uma única liquidação; saldos e reservas conservados. |
| Interrupção antes/depois do commit | Recuperação consistente, sem pagamento duplicado ou reserva liberada e paga. |
| Bloco ausente/corrompido | Restauração rejeitada e nenhum pagamento por entrega inválida. |
| Sensor ausente/antigo, disco cheio ou orçamento insuficiente | Bloqueio automático sem inventar capacidade ou receita. |
| Worker antigo ou LAN interrompida | Nenhuma confirmação indevida ou saldo definitivo fora da autoridade. |
| Dados sem mudanças e fila vazia | Espera, sem produzir demanda artificial. |
| Capacidade e créditos | Emissão dentro do limite reservado e auditoria de conservação. |
| Métricas | Benefício físico separado dos créditos; trabalho interno não promovido a receita externa. |

O resultado soberano possível é serviço entregue e benefício local comprovado.
Créditos criados dentro desse domínio não são recebimentos de BTC/USDC nem
comprovam valorização externa. Bots do mesmo proprietário redistribuem o
orçamento disponível; não criam um pagador independente.
