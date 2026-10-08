# Três prioridades locais — Mycelium Network

Escopo atualizado em 2026-10-04 por instrução direta do usuário: focar tudo localmente na infraestrutura Mycelium Network. A busca de pagador externo deixa de ser requisito dessas três prioridades. O documento anexado permanece contexto, não autorização independente.

## 1. Controle térmico e redução de repetições improdutivas

Estado: em andamento.

Reutilizar S1-MUPP, seu adaptador e o controle de buscas existente. Verificar sensores ausentes, dados obsoletos, sobretemperatura, cooldown, recuperação e backoff. Preservar alterações preexistentes e evitar testes de estresse desnecessários.

Avanço: corrigido o adaptador Rust para bloquear margem térmica quando o timestamp do sensor está no futuro. Adicionado teste de bloqueio e recuperação quando o relógio alcança o timestamp. Validação: `cargo test -p mycelium-economy mupp_adapter --lib` passou os 6 testes do adaptador. A auditoria e integração dos demais casos continuam pendentes.

## 2. Executar e validar uma tarefa local

Estado: pendente de integração e execução demonstrável.

Aproveitar o núcleo CQR existente para uma classe de tarefa computacional local, com entrada reproduzível, resultado persistido e critérios objetivos de aceitação. Verificar o caminho de execução e proteção térmica antes de apresentar a tarefa como concluída. Não depender de serviços externos para concluir esse escopo.

## 3. Medir os resultados locais

Estado: pendente.

Registrar duração, aceitação e recursos por tarefa, com unidades e proveniência. Energia e custo devem permanecer desconhecidos quando não medidos. Créditos internos e benchmarks não são receita recebida. Preservar os requisitos existentes de verificação de pagamentos.

## Continuidade

O acompanhamento automático foi atualizado para essas três prioridades locais. Registrar aqui testes, evidências e impedimentos a cada avanço relevante. Avisar quando as três estiverem comprovadamente concluídas, houver falha material ou ação indispensável do usuário. Não iniciar crescimento ou reinvestimento automático.

A auditoria cbBTC anterior permanece em research/cbbtc/README.md e não conta como conclusão deste escopo.

## Registro — 2026-10-04, acompanhamento local

- Corrigida uma aprovação indevida no validador CQR: a frequência antes era considerada válida apenas por ser positiva, com erro fixado em zero. Agora o operador de forças calcula a frequência do modo periódico e compara com a solução analítica em rad/s, usando as tolerâncias do job. Isso verifica dispersão do operador, não convergência de trajetória nem física experimental.
- Antes da adição do teste negativo de contorno não periódico, `rtk cargo test -p mycelium-economy --test cqr_kernel_tests` passou 23 testes. O novo teste negativo ainda não foi executado.
- `rtk cargo test -p mycelium-economy discovery --lib` terminou com 85 aprovados e 2 falhas: expectativas antigas de freshness para timestamps futuros. Ajustados os testes para exigir bloqueio no adaptador e usar horário preciso no caso fracionário. Revalidação pendente.
- Falha material térmica: `sensors -j` registrou CPU Package id 0 = 94 °C e Core 5 = 94 °C, acima do teto de execução CQR de 75 °C. Leitura pontual do hardware, em graus Celsius; não é temperatura simulada. Suspendidos novos testes e execução de tarefa neste acompanhamento. Estado `/tmp/s1-mupp-state.json` ausente. Não substituir sensores reais por fakes para declarar execução local concluída.
- Ainda não há tarefa real aceita nem métricas persistidas por tarefa. Energia (J/kWh), custo monetário e receita recebida permanecem desconhecidos/não medidos; nenhum crédito interno foi contado como receita. As três prioridades permanecem abertas. A automação continua ativa para retomar quando houver condições térmicas seguras, sem repetições de carga enquanto a condição persistir.

### Verificação térmica — 2026-10-04T19:59:56.793097+00:00

CPU Package id 0: 94.0 °C, acima do teto local de 75 °C. Execução e testes com carga continuam suspensos; nenhuma tarefa aceita foi acrescentada. Evidência: `research/evidence/thermal-20261004T195956Z.json` (leitura real de `sensors -j`, unidade °C). As três prioridades permanecem abertas; energia e custo continuam desconhecidos. Automação permanece ativa.

### Verificação térmica — 2026-10-04T21:00:05.747567+00:00

CPU Package id 0: 96.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261004T210005Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-04T22:00:36.011996+00:00

CPU Package id 0: 95.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261004T220036Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-04T23:02:06.445509+00:00

CPU Package id 0: 95.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261004T230206Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T00:02:06.556488+00:00

CPU Package id 0: 95.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T000206Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T01:02:37.251952+00:00

CPU Package id 0: 96.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T010237Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T02:02:35.317496+00:00

CPU Package id 0: 80.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T020235Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T03:04:05.265890+00:00

CPU Package id 0: 93.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T030405Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T04:04:35.738832+00:00

CPU Package id 0: 93.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T040435Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T05:05:05.171471+00:00

CPU Package id 0: 95.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T050505Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T06:05:05.765297+00:00

CPU Package id 0: 93.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T060505Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T07:05:07.640413+00:00

CPU Package id 0: 92.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T070507Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T08:05:06.894642+00:00

CPU Package id 0: 88.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T080506Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T09:05:40.373544+00:00

CPU Package id 0: 92.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T090540Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T10:07:11.481720+00:00

CPU Package id 0: 95.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T100711Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T11:06:38.855458+00:00

CPU Package id 0: 95.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T110638Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Nova tentativa solicitada — 2026-10-05T11:27:05.699929+00:00

CPU Package id 0: 95.0 °C; acima do teto local de 75 °C. Validação com carga permanece bloqueada. Evidência: `research/evidence/thermal-20261005T112705Z.json`, leitura real de `sensors -j`, unidade °C. Nenhuma tarefa aceita; energia e custo desconhecidos. Três prioridades ainda abertas.

### Verificação térmica — 2026-10-05T12:09:41.054206+00:00

CPU Package id 0: 95.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T120941Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T13:07:37.601272+00:00

CPU Package id 0: 90.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T130737Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T14:08:37.859072+00:00

CPU Package id 0: 95.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T140837Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T15:10:12.658159+00:00

CPU Package id 0: 93.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T151012Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T16:10:12.086913+00:00

CPU Package id 0: 92.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T161012Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T17:11:16.636255+00:00 UTC

CPU Package id 0: 84.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T171116Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T18:09:33.557614+00:00 UTC

CPU Package id 0: 83.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T180933Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T19:11:05.103541+00:00 UTC

CPU Package id 0: 86.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T191105Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T20:11:02.598085+00:00 UTC

CPU Package id 0: 83.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T201102Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T21:16:43.177433+00:00 UTC

CPU Package id 0: 85.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T211643Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.

### Verificação térmica — 2026-10-05T22:14:07.047538+00:00 UTC

CPU Package id 0: 92.0 °C; execução bloqueada pelo teto local de 75 °C ou ausência de leitura válida. Sem repetir testes com carga enquanto persiste o impedimento. Evidência real: `research/evidence/thermal-20261005T221407Z.json`, proveniência `sensors -j`. Nenhuma tarefa aceita acrescentada; energia e custo desconhecidos. Três prioridades abertas, automação ativa.


### 2026-10-05T23:56:00.260966+00:00 — protótipo Mycelium Next

Nova base isolada em `apps/mycelium-next`, com fila SQLite persistente, deduplicação, limite de tentativas, recuperação de interrupções, painel local e proteção térmica automática. Plano detalhado em `research/PLANO_MYCELIUM_NEXT.md`; instruções em `apps/mycelium-next/README.md`. Alterações preexistentes preservadas.

Validação: 14 testes unitários passaram; smoke HTTP real retornou 200 para painel/API, 403 para Host inválido e encerramento limpo (código 0). Temperaturas reais e disponibilidade do socket registradas em `research/evidence/mycelium-next-20261005T235600Z.json`. Gate real: `cooldown`; máximo: 94.05 °C. Backend disponível: False. Energia (J) e custo permanecem desconhecidos por ausência de medição.

As três prioridades originais continuam ABERTAS: o novo gate ainda precisa ser integrado ao S1-MUPP; não houve execução e aceitação de tarefa produtiva pelo backend; faltam métricas de uma execução produtiva. O teste de saúde não representa mineração, pagamento ou receita recebida. Wallet e chain são capacidades planejadas, sem assinatura, transferência ou consenso implementados. Nenhum crescimento ou reinvestimento automático foi iniciado; automação original mantida ativa.


### 2026-10-06T12:15:26Z — integração S1-MUPP e repositório nativo

A versão local em `apps/mycelium-next` passou a exigir estado S1-MUPP válido, recente e com autorização para executar. Estado ausente, inválido ou vencido bloqueia a execução. A leitura térmica considera os sensores válidos, bloqueia a partir de 75 °C e só libera após resfriamento até 70 °C. A autorização é verificada novamente antes de publicar. Bloqueios de segurança não consomem tentativas de tarefa.

A classe auxiliar `artifact_verify` publica conteúdo público de até 128 KiB pelo socket autenticado do Mycelium, lê o conteúdo pelo repositório nativo, valida manifesto, tamanho e SHA-256 e publica um recibo que também é lido e validado. Ela não substitui a execução CQR exigida por este plano, nem comprova integração produtiva com Sporebank/Cosmic ou pagamento recebido. CIDs confirmados são persistidos para recuperação. Uma publicação cuja confirmação ficou incerta exige reconciliação e não é repetida automaticamente; a mesma proteção cobre interrupção durante a mutação.

**Testes:** `rtk proxy python3 -m unittest -v test_mycelium_next.py`, executado em `apps/mycelium-next`: 30 testes passaram em 0,118 s, saída 0. Cobertura inclui socket Unix isolado, validação e corrupção de artefatos, recuperação dos CIDs, confirmação incerta sem duplicar publicação, conflito de conteúdo na chave de deduplicação e bloqueio seguro sem consumir tentativas. O backend e os estados S1 desses testes são sintéticos; esses resultados não constituem execução produtiva no backend real.

**Verificação real:** evidência em [mycelium-next-20261006T121526Z.json](evidence/mycelium-next-20261006T121526Z.json). A maior leitura foi 95,05 °C, com caminhos dos sensores e horários registrados no JSON; o gate retornou bloqueado. `/tmp/s1-mupp-state.json` estava ausente (`FileNotFoundError`) e o socket padrão Mycelium recusou a conexão (`ConnectionRefusedError`). A inspeção usou estado temporário isolado e operações de leitura; não executou a fila real, não iniciou o backend, não compilou Rust e não gerou carga produtiva adicional.

- **Prioridade 1 — ABERTA:** integração e bloqueios locais implementados e testados; faltam estado operacional S1-MUPP e comprovação da proteção na infraestrutura real. O leitor S1 não controla, por si só, outros processos do backend.
- **Prioridade 2 — ABERTA:** falta execução e aceitação de uma tarefa CQR real pela infraestrutura Mycelium. A classe auxiliar de artefatos não encerra esse requisito.
- **Prioridade 3 — ABERTA:** o registro local oferece duração em ms, tempo de CPU em ms, memória em KiB e razão de aceitação com proveniência; faltam medições de tarefa produtiva real. CPU pode incluir atividade compartilhada do painel; memória representa o pico do processo no Linux, não memória exclusiva por tarefa. Pendências e reconciliações são excluídas do denominador de aceitação. Energia em J permanece desconhecida (`null`) e custo permanece desconhecido quando não medidos.

Nenhuma receita recebida foi demonstrada. Créditos internos e testes não são receita. Wallet, chain, stablecoins e Lightning continuam como desenvolvimento planejado, sem movimentação financeira. Não foram usados serviços externos nem iniciado crescimento ou reinvestimento automático. A automação `concluir-tr-s-prioridades-mycelium` permanece ATIVA porque as três prioridades ainda estão abertas.


### 2026-10-06 — Triagem local de Alien Files

A pedido do usuário, foi concluída uma análise de referências em `/media/bruno/SAMBOOK/Alien Files/`: inventário filtrado de 880 arquivos/699 PDFs, extração de 12 PDFs, leitura seletiva e inspeção estática de código. Relatório: [ANALISE_ALIEN_FILES_MYCELIUM.md](</media/bruno/SAMBOOK/Mycelium Network/research/ANALISE_ALIEN_FILES_MYCELIUM.md>). Evidência com SHA-256, páginas e limites de cobertura: [alien-files-triagem-20261006.json](</media/bruno/SAMBOOK/Mycelium Network/research/evidence/alien-files-triagem-20261006.json>). Originais preservados; nenhum código Alien executado.

Achados prioritários: proposta de CRDT/DAG/recibos do protocolo de malha; modelos de proveniência de ancient-sky-reconstruction; exemplos numéricos como candidatos condicionais a validação. Wallet, chain, stablecoin e Lightning operacionais não foram demonstrados pelo material examinado. As três prioridades continuam abertas: esta análise não comprova controle térmico real, CQR aceito pelo backend ou métricas produtivas. Energia/custo não medidos; nenhuma receita comprovada.

### 2026-10-07 — AEM-ECO: ponte passiva e regressão local (sem execução econômica)

- Integração nova: `apps/mycelium-next/aem_bridge.py`; reusa a saída já validada de `Engine.gate()` sem criar daemon, sem leitura extra de sensor, sem substituir S1-MUPP e sem autorizar tarefas. Persistência do estado SHADOW na tabela SQLite `settings`. `status` e painel exibem somente aconselhamento e telemetria.
- O `aem_shadow.py` mantém lógica NO_EDGE/backoff para futuro adapter, mas o bridge real ainda não importa `DiscoveryReport` ou `VerifiedNev`: nunca inventa sinal de sucesso, receita ou ausência global de oportunidades.
- Testes com sensores sintéticos: `python3 -m unittest discover -s apps/mycelium-next -p 'test_*.py' -q` → 53 testes aprovados em 0,119 s; apenas testes leves, sem backend, wallet, assinatura ou mineração.
- Medição real pontual de segurança após os testes: CPU Package id 0 = **94 °C** (coretemp via `sensors`); `/tmp/s1-mupp-state.json` **ausente**. Permanece BLOQUEADO por temperatura e S1 indisponível. A lista instantânea de processos indicou `headroom` entre os que mais usaram CPU; não comprova a causa do aquecimento, nem autoriza interromper outros processos.
- **Prioridades 1–3 permanecem abertas**: a política de bloqueio e os testes estão integrados, mas controle físico integrado ao gerador legítimo de estado S1-MUPP, execução CQR real e métricas aceitas dependem de máquina fria e autorização real. NEV, custo de energia, receita e capacidade produtiva continuam sem medição. Nenhuma emissão ou transação foi iniciada.

### 2026-10-07 — Headroom encerrado e AEM preflight incorporado

- Processo identificado: `/home/bruno/.local/bin/headroom proxy --port 8787`, PID 902172, usuário bruno. SIGTERM enviado e saída confirmada por `pgrep -a -x headroom`; socket TCP 127.0.0.1:8787 ficou sem listener. Nenhuma unit systemd com nome headroom foi encontrada. Aplicativo e configurações preservados.
- Implementado `Engine.preflight()` e novo CLI `preflight` em `apps/mycelium-next/mycelium_next.py`: chama somente `gate()` e `status()`, sem enfileirar, executar ou pagar tarefas. Retorna capacidades CQR/financeiras indisponíveis em vez de inventar valor externo.
- Testes integrados: `python3 -m unittest discover -s apps/mycelium-next -p 'test_*.py' -q` → **56 testes aprovados, 0 falhas, 0,120 segundo**. Inclui que preflight com calor não altera estado nem tentativas das tarefas pendentes.
- Uma leitura `preflight` real com diretório SQLite temporário e isolado retornou `maximum_celsius=94.0`, `reason=cooldown`, `s1_reason=s1_unavailable_or_invalid`, `allowed=false`, `aem_state=THERMAL_LOCK`, `cqr_connected=false`, `financial_enabled=false`. Resultado: **BLOQUEADO**, tarefa CQR real permanece pendente. Energia, custo e receita continuam desconhecidos; nenhum trabalho de usuário foi iniciado.
- Outro processo, `grep` em `/media/bruno/SAMBOOK/SteamLibrary/steamapps`, aparecia consumindo CPU; não foi encerrado, pois o pedido de encerramento foi especificamente do headroom.

### 2026-10-07 — CQR-C0 native worker staged; compilation aborted on thermal ceiling

- SteamLibrary recursive `grep` PID 1869614 identified and terminated by SIGTERM at user's instruction; `headroom` remains off. CPU package fell from 92 °C to 64 °C and subsequently 58 °C on point measurements, consistent with major load reduction but not proof of sole causation.
- New bounded CQR worker Rust source `crates/mycelium-economy/src/bin/mycelium-cqr-worker.rs` and Cargo target; resource limits via `libc::setrlimit(RLIMIT_CPU/RLIMIT_AS)`, 64 KiB stdin, 64 oscillator C0 only, MUPP and physical sensor checks before/mid/after via existing CQR thermal watchdog, reproducibility and known-answer verification. `--make-sample-job` creates a digest-correct local sample without executing CQR.
- New Python bridge `apps/mycelium-next/cqr_runner.py`, explicit `cqr_c0` submission in `mycelium_next.py`, `submit-cqr --key --job-file` CLI, and protected dispatch. No auto submission, finance, chain transactions, signing or token issuance. Reports are local scientific results, never VerifiedNev.
- Regression suite: **67 tests Python PASS**, 0 failures, 0.184 seconds (including mocks, NOT physics execution).
- Attempted `cargo build --offline -p mycelium-economy --bin mycelium-cqr-worker -j 1` with priority reduction and active 75 °C guard. CPU package spiked to **89 °C**, watchdog sent SIGTERM to Cargo process group, exit **143**. Subsequent inspection: no `cargo`/`rustc` process, `target/debug/mycelium-cqr-worker` **missing**. Later thermal probe 81 °C despite no Rust processes. **Native compilation/validation pending; no real CQR benchmark performed.**
- S1-MUPP producer absent (`/tmp/s1-mupp-state.json` missing). Block live work. Next gates: diagnose abnormal heat under small load, establish genuine S1 producer, compile only with safe temperatures, perform first actual CQR scientific computation, then inspect third-party settlement and verified external value separately.

### 2026-10-07 — Segurança de sensores e integridade científica (AEM/CQR)

- CPU sem compilação oscilou entre 63 °C, 80 °C, 91 °C e 82 °C. `sensors` apresentou 91 °C no máximo em uma verificação real `preflight`; MUPP permaneceu indisponível, `allowed=false`, binário nativo ausente. Nenhum kernel real foi executado.
- `temperatures()` do Mycelium Next agora inclui `/sys/class/hwmon/hwmon*/temp*_input` em adição às thermal zones, preservando falha fechada com erros de leitura. Testes ACPI vs hwmon (CPU muito mais quente) + falha de sensor adicionados.
- Auditoria CQR revelou algoritmo efetivo único `VelocityVerlet` com precisão `f64`, sem implementação de `RungeKutta4` ou `Float32` selecionável. Contrato Python/Rust restringido a C0 64 osciladores, Velocity Verlet, Float64 strict, contorno periódico e suíte implementada. Testes dos campos não implementados foram ampliados.
- Verificação leve: 69 testes Python PASS; `cargo metadata --offline --no-deps` identificou o target e dependências, mas NÃO compilou o worker. S1 BPF/Cognitive Hypervisor buscas rasas não revelaram produtor MUPP legítimo. Não criar flag fake, não ignorar ausência.
- Pendências: examinar hardware térmico e ventoinhas, identificar produtor S1-MUPP real, compilar worker em ambiente estável, testes Rust e primeiro CQR real com prestação de contas separada de pagamento externo verificável.

### 2026-10-07 — Nova tentativa de build CQR: guarda térmico confirmou recusa segura

- Novo `apps/mycelium-next/guarded_cqr_build.py`: executa compilação Rust offline com apenas um job, afinidade a um único CPU, `nice -n 19`, duty cycle ~18% (0,08 s ativo/0,36 s parado), leituras reais de `coretemp` e thermal zones, abortando com `SIGCONT`/`SIGTERM` do grupo de processos se o máximo atingir 75 °C; exige <=70 °C na partida. Timeout máximo 150s. Não executa CQR, nem muda S1 ou emite cripto.
- Primeira invocação: temperatura inicial 79 °C, abortada ANTES de iniciar Cargo.
- Segunda invocação: temperatura inicial 68 °C, compilação iniciada, máximo 77 °C em 1,2 s, encerrada imediatamente por `thermal_abort` (exit 3). Log em `/tmp/mycelium-cqr-guarded-build.log` registra apenas `Compiling mycelium-economy...`, sem diagnóstico de erro de código. Não há executável `target/debug/mycelium-cqr-worker` e não restaram processos Cargo/rustc. Sensor após cancelamento 64 °C. O problema de hardware/carga permanece impeditivo.
- Criado `test_guarded_cqr_build.py` com 4 testes sintéticos, sem invocar Cargo. Regressão completa: **73 testes PASS** em 0,127 s. `/tmp/s1-mupp-state.json` continua ausente.
- Recomenda-se inspecionar refrigeração/ventoinhas, poeira, contato e pasta térmica e repetir apenas quando as temperaturas puderem permanecer estáveis sob compilação; não burlar os limites.

### 2026-10-07 — Repetição solicitada da compilação CQR

- Leitura preliminar: CPU Package 61 °C, sem `cargo`/`rustc` ativos.
- Invocação real de `guarded_cqr_build.py`: o sensor agregado já marcava **75,0 °C na própria pré-verificação**, ultrapassando o máximo de **70 °C para partida**.
- Resultado: `REFUSED`, código de saída 3; **Cargo não iniciou**, não gerou `target/debug/mycelium-cqr-worker`, sem processos de build remanescentes. O log antigo em `/tmp/mycelium-cqr-guarded-build.log` é da tentativa anterior, não de novo build.
- MUPP genuíno ausente. O hardware oscila termicamente mesmo em carga baixa; evitar novas tentativas repetidas sem corrigir a refrigeração.

### 2026-10-07 — Diagnóstico de baseline e suspeita de Turbo Boost (somente leitura)

- Perfil real da máquina: `powerprofilesctl get = power-saver`; Intel `no_turbo = 0` (Turbo Boost ativo), `scaling_max_freq=4400000` kHz, base `2600000` kHz e `max_perf_pct=100`. O usuário comum não tinha permissão de escrita nos limites sysfs. `thermald` inativo. Nenhuma dessas opções foi modificada.
- Criados `thermal_diagnostic.py` e `test_thermal_diagnostic.py` (4 testes adicionais) para coleta de curto prazo sem carga artificial, com leitura de coretemp, thermal zones, CPU0 MHz, validade e erros de sensor. Evidência: `research/evidence/cqr-thermal-baseline-20261007.json`.
- 12 amostras reais/0,25 s; 12/12 sensores válidos; CPU package mínimo 54 °C, mediana 55 °C, máximo 55 °C; CPU0 1032,961–1477,528 MHz, zero amostras >=75 °C. A ausência de compilação durante o intervalo é essencial: isso **não demonstra** capacidade térmica para compilar Rust. Não foi testado controle de Turbo ou alteração do sistema.
- Novo `preflight` isolado: máximo 55,05 °C, mas `allowed=false`, `s1_unavailable_or_invalid`, binário CQR ausente e finanças desligadas. Nenhuma execução/mint/pagamento.
- Regressão de Python **77 testes PASS**, zero falhas. Próximos gates continuam: hardware térmico estável sob compilação e controlador S1-MUPP de origem autêntica; compilar e validar worker sem violar o teto, depois executar CQR real e verificar recompensa externa separadamente.

### 2026-10-07 — Controle de Turbo temporário preparado, não aplicado

- Coleta real inicial: CPU package 51 °C, `intel_pstate/no_turbo=0` (Turbo Boost ativo), ausência de `cargo`/`rustc`, estado S1-MUPP ausente, CQR worker não compilado.
- Tentativa de consultar privilégios: `sudo -n true` recusado (sem autorização não interativa), e controle `no_turbo` não gravável como usuário bruno. Para não contornar privilégios nem expor senha, **nenhum ajuste do hardware foi realizado**.
- Criado `apps/mycelium-next/build_cqr_turbo_off.sh` para execução interativa local com `sudo -v`: preserva estado original, ativa `no_turbo=1` temporariamente, inicia o processo Python que limita a compilação e restaura estado original com traps e verificação; comando `--check` não usa sudo nem muda configuração.
- Validação sem privilégios: `bash -n` PASS, `--check` PASS, leitura `no_turbo=0` preservada; 77 testes Python PASS (0,359 s), temperatura 51 °C, sem processo de compilação e sem binário.
- Pendente: usuário autenticar execução local no terminal real; somente depois registrar temperaturas de compilação, binário nativo e testes Rust. Continuar bloqueando CQR real até que MUPP genuíno esteja presente, fresco e autorize trabalho.

### 2026-10-07 — Turbo-off sob carga resolveu pico térmico; limite de tempo era insuficiente

- Usuário executou `build_cqr_turbo_off.sh` com autenticação local: `no_turbo` original 0, transitoriamente 1, restauração final `no_turbo=0` confirmada. CPU 52 °C no início e máximo 52 °C nos 150,1 s de execução.
- Interrompida exclusivamente por `time_budget_abort`, não por temperatura ou erro Rust; log inspecionado e contém apenas início da compilação de `mycelium-economy v0.1.0`. Não foi criado o binário Rust. Observação: não se pode concluir compilação correta apenas por ausência de erros.
- O antigo duty cycle de 0,08 s ativo / 0,36 s parado (=18,2%) oferecia pouco tempo de CPU no limite total de 150 s. Ajustado para duty cycle térmico adaptativo (60% abaixo de 62 °C, 38% em 62–66 °C, 20% em 66–70 °C) e teto de 900 s; pausa preventiva acima de 70 °C até recuperar para 65 °C e abort >=75 °C. Permanecem 1 CPU, `-j1`, `nice -n19`, modo offline e sem S1 artificial.
- Validação após mudança: **79 testes Python PASS**, incluindo alarme térmico simulado com finalização do grupo, mais `bash -n` e `--check`. Estado final observado: CPU 51 °C, Turbo originalmente 0, `cargo`/`rustc` sem processos ativos. **A nova versão ainda não foi testada em compilação real.**
- Próximo gate: operador executar novamente o wrapper com autenticação local e anexar log completo, saída de progresso, confirmação de restauração do Turbo e hash/build do executável. Após isso, rodar testes nativos CQR com segurança real; S1-MUPP permanece pendente e execução de jobs continua bloqueada.
