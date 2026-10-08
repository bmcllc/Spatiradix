# Mycelium Next — protótipo local

Uma base pequena para operar pelo Mycelium existente, com fila persistente e painel local. Requer Linux e Python 3; não instala dependências.

```bash
cd "/media/bruno/SAMBOOK/Mycelium Network"
rtk proxy python3 apps/mycelium-next/mycelium_next.py submit --key health-001
rtk proxy python3 apps/mycelium-next/mycelium_next.py start
```

Abra http://127.0.0.1:8787. Sem `--eco-config`, `start` processa a fila a cada 30 segundos; não cria tarefas automaticamente. Com essa opção, também acompanha relatórios externos pelo [supervisor nativo Mycelium-ECO](#supervisor-nativo-mycelium-eco). `backend_health` consulta a saúde do backend. `artifact_verify` publica um arquivo explicitamente público pelo repositório nativo Mycelium, lê seu conteúdo de volta, verifica tamanho e SHA-256 e publica um recibo verificável. Essa classe ainda não substitui a execução CQR exigida pelas prioridades, nem representa mineração ou pagamento.

Outros comandos:

```bash
rtk proxy python3 apps/mycelium-next/mycelium_next.py status
rtk proxy python3 apps/mycelium-next/mycelium_next.py run-once
rtk proxy python3 apps/mycelium-next/mycelium_next.py verify-journal
rtk proxy python3 -m unittest discover -s apps/mycelium-next -v
```

Opções globais `--state` e `--socket` devem preceder o comando. O socket padrão é `~/.local/share/mycelium/mycelium.sock`; a autenticação usa `MYCELIUM_CONTROL_TOKEN` ou `control.token` ao lado do socket. O estado fica em `apps/mycelium-next/var`, com diretório privado e SQLite.

Para enfileirar um artefato, use `submit-artifact --key IDENTIFICADOR --public-file CAMINHO`. O arquivo deve ser público: o repositório pode disponibilizá-lo aos pares. O limite é 128 KiB. `import-task --key IDENTIFICADOR --cid CID` valida um manifesto já publicado; o CID deve conter 64 dígitos hexadecimais, com prefixo `Qm` opcional. O manifesto vincula nome, tamanho e SHA-256 ao conteúdo recebido.

## Implementado

- Fila persistente, submissão idempotente, um executor por diretório de estado, recuperação após interrupção, três tentativas no máximo e espera crescente.
- Proteção automática: bloqueia a partir de 75 °C, retoma até 70 °C; sensor ausente, inválido ou antigo também bloqueia. Exige ainda estado S1-MUPP válido, recente e autorizando execução em `/tmp/s1-mupp-state.json`. Revalida antes de cada publicação. Bloqueio não consome tentativas, e mudanças de motivo ficam no diário. Os limites precisam ser validados para o hardware.
- Consulta ao backend com prazo e validação da resposta; painel somente leitura, limitado ao loopback e com verificação de Host.
- Publicação e leitura pelo socket nativo, com limites de mensagem, conteúdo e prazo. Guarda os CIDs confirmados para recuperar a tarefa sem republicar. Se a confirmação de uma publicação for incerta, a tarefa exige conciliação e não é repetida automaticamente.
- Registro de duração em ms, CPU do processo em ms, pico de memória em KiB e proveniência. A aceitação usa tarefas aceitas e rejeitadas; pendências e conciliações ficam fora desse denominador. Energia em J e custo ficam desconhecidos quando não medidos.
- Diário com hashes encadeados e verificação local. Não é consenso de blockchain nem prova de imutabilidade: sem checkpoint independente, remoção do final ou reescrita integral não é detectável.

## Limites desta versão

A proteção controla somente este executor. Lê a autorização do guardião S1-MUPP, mas não controla a temperatura nem a carga de outros processos, inclusive o backend existente. Estado S1-MUPP ausente ou antigo bloqueia a execução; não crie um estado simulado para liberar operação real. CPU pertence ao processo compartilhado com o painel; memória é o pico do processo durante sua vida, não o consumo isolado de cada tarefa.

Wallet, assinatura, saldos, chain, stablecoin e Lightning estão apresentados como capacidades planejadas; não estão implementados. O painel não deve ser usado como carteira. Não há receita recebida comprovada, crescimento automático ou reinvestimento. Os 30 testes usam sensores e estado S1-MUPP simulados; parte deles exercita um servidor temporário de socket Unix. Comprovam o comportamento do protótipo, sem comprovar uma execução produtiva no backend real.

Na verificação de 6 de outubro de 2026, um sensor marcou 95,05 °C, o estado S1-MUPP estava ausente e o socket real recusou a conexão. As três prioridades permanecem abertas. Evidência: `research/evidence/mycelium-next-20261006T121526Z.json`.

O roteiro de implementação está em `research/PLANO_MYCELIUM_NEXT.md`. Preserve os avisos e a licença AGPL-3.0 aplicáveis ao código reaproveitado do projeto.

## AEM-ECO — integração passiva (2026-10-07)

O código `aem_bridge.py` reaproveita o resultado da mesma amostra real de `Engine.gate()` sem chamar sensores duas vezes, sem criar daemon, sem reconfigurar MUPP e sem alterar o caminho de autorização de `run_once()`. A cada chamada do gate, armazena recomendação SHADOW e memória térmica na tabela `settings` já existente. O estado aparece sob `aem_eco` no JSON do comando `status`, na API `/api/status` e no cartão **AEM-ECO (somente observação)** do painel.

Estados possíveis: `LOW_POWER_DISCOVERY` (recomendação, não job), `THERMAL_LOCK`, `MUPP_LOCK`, `SENSOR_LOCK` e `STALE_TELEMETRY`. O controlador puro `aem_shadow.py` já reconhece `NO_EDGE`/`COLD_DISCOVERY` com backoff, porém **a ponte ainda não está conectada ao DiscoveryReport/VerifiedNev do Rust**: indica explicitamente `not_connected_to_discovery`/`not_connected_to_verified_view`. Não alterar isso inserindo dados sintéticos. Em caso de estado S1 ausente, vencido, não autorizado ou temperatura acima do limite, continua bloqueado. Um status antigo é marcado como obsoleto após 30 s.

Essa integração NÃO executa automação financeira, NÃO fornece autorização de mineração, NÃO assina transações, NÃO altera emissão MYC e NÃO declara receita. Os campos financeiros ficam explicitamente sem autoridade. A fonte de decisão financeira continua `mycelium-economy::verified_view`, com provider pinado e cadeia verificada, e o executor externo não foi conectado.

Testes sintéticos leves:

```bash
python3 -m unittest discover -s apps/mycelium-next -p 'test_aem*.py' -v
```

O gate existente do Mycelium Next permanece a proteção real; o SHADOW não o substitui. **Em 7/10/2026, CPU Package chegou a 95 °C e o arquivo real /tmp/s1-mupp-state.json estava ausente.** Não iniciar jobs nem testes sob carga até obter leituras seguras e um S1-MUPP genuíno. O próximo gate é executar e aceitar uma tarefa CQR verdadeira com métricas completas — ainda não demonstrado.

## Pré-verificação de segurança AEM (2026-10-07)

O comando abaixo faz **uma** leitura térmica real e uma validação do estado S1-MUPP, registra a transição de segurança em um SQLite local e emite diagnóstico estruturado. Não consome tarefa, não inicializa backend, não cria wallet, não emite MYC nem faz rede:

```sh
cd '/media/bruno/SAMBOOK/Mycelium Network'
python3 apps/mycelium-next/mycelium_next.py preflight
```

`preflight` usa o mesmo gate de `run_once` mas **não chama `run_once`**. A resposta inclui `can_execute_existing_jobs`, `cqr_backend.connected` (false até existir adaptador produtivo), `aem_eco` e `financial_execution.enabled` (false). Mesmo que os sensores e o S1 autorizem trabalho, essa resposta NÃO autoriza emissão, trades nem reinvestimento.

Teste de regressão em 2026-10-07: **56/56 testes** Python. Pré-verificação real em estado isolado: temperatura máxima 94 °C, reason=`cooldown`, S1=`s1_unavailable_or_invalid`, `can_execute_existing_jobs=false`, `cqr_backend.connected=false`, `financial_execution.enabled=false`. `headroom proxy --port 8787` foi encerrado por SIGTERM e porta 8787 liberada. O aquecimento persistiu; não iniciar trabalho produtivo.

## CQR-C0 explícito — fila protegida (2026-10-07)

Arquivos novos: `cqr_runner.py`, `test_cqr_runner.py`, `crates/mycelium-economy/src/bin/mycelium-cqr-worker.rs`. Registro Cargo do binário `mycelium-cqr-worker` e dependência Linux `libc` para `RLIMIT_CPU`/`RLIMIT_AS`. O novo job `cqr_c0` aceita SOMENTE um JSON explícito `{"spec": CqrJobSpec, "initial_state": PhaseSpacePoint}`, até 64 KiB, CQR-C0, 64 osciladores, 1–5000 passos, limites máximos 10s CPU/30s por execução/512 MiB, teto térmico de até 75 °C. A fila SQLite continua idempotente, sob `Engine.gate()`, `S1-MUPP` e mutex; o Rust também revalida MUPP e sensores independentemente antes e após suas execuções. O subprocesso possui timeout externo, stdout limitado e sem execução via shell. A medição de CPU do filho Rust é discriminada em `child_cpu_ms` (RUSAGE_CHILDREN).

Somente depois de **compilação bem-sucedida e demonstração de S1-MUPP genuíno, fresco e autorizando execução**, gerar um exemplo com hash correto sem executar o kernel:

```bash
cd '/media/bruno/SAMBOOK/Mycelium Network'
cargo build --offline -p mycelium-economy --bin mycelium-cqr-worker -j 1
./target/debug/mycelium-cqr-worker --make-sample-job > /tmp/cqr-c0-sample.json
python3 apps/mycelium-next/mycelium_next.py submit-cqr --key cqr-c0-sample-1 --job-file /tmp/cqr-c0-sample.json
# O supervisor já tem `start` ou pode fazer `run-once`; NUNCA utilizar antes de preflight seguro.
python3 apps/mycelium-next/mycelium_next.py preflight
```

**NÃO executar esses comandos nesta máquina no estado atual.** Em 2026-10-07, tentativa de compilação Rust com `nice -n 19`, `-j1`, guarda de hardware >=75 °C elevou instantaneamente Package CPU para 89 °C; o guarda abortou o build (exit=143), nenhum `cargo`/`rustc` permaneceu ativo e nenhum novo executável foi produzido. O estado obrigatório `/tmp/s1-mupp-state.json` ainda estava ausente.

**Gate não demonstrado:** só existem testes Python com mocks sintéticos, não uma execução CQR real, nem verificação criptográfica externa por um terceiro. O hash de resultado e as validações locais NÃO representam um `VerifiedNev`, uma recompensa MYC, receita paga, contrato externo ou prova de consenso. O CLI nativo imprime digest de resultado, relatório físico e as flags `received_revenue=false`/`verified_nev=null`. Para renda real ainda faltam demanda paga, entrega verificável por terceiros e liquidação externa autenticada. A fonte de estado S1-MUPP também não possui mecanismo de autenticação adicional neste protótipo: não tratá-la como confiança criptográfica por si só.

## Gate térmico consolidado e ABI CQR estrita — 2026-10-07

`temperatures()` passou a agregar **todas as zonas em /sys/class/thermal/thermal_zone*/temp e os sensores hwmon em /sys/class/hwmon/hwmon*/temp*_input**. O `Engine.gate()` já valida idade, erros, tipo e validade dos valores, usando o **máximo entre sensores**; nenhum sensor inacessível é substituído por zero. Exemplo real de divergência: `x86_pkg_temp` e `coretemp` podem não ser iguais num instante. Dois testes novos simulam o cenário ACPI frio/hwmon CPU quente e falha de leitura hwmon. Resultado da regressão: **69 testes OK**.

A inspeção de `cqr/oscillators.rs` revelou que o kernel efetivamente executa `VelocityVerlet::step()` em `f64` (sem dispatch de integrador ou precisão). Para não assinar um relato científico enganoso, o novo worker nativo e o `cqr_runner.py` exigem **estritamente** o contrato implementado: `schema_version=1`, `model_id=coupled_oscillators_64`, `model_version=1.0.0`, `integrator_spec=velocity_verlet`, `precision_policy=float64_strict`, `periodic_boundary=true`, `expected_observables=[energy]`, `validation_suite=[symplectic_conservation]`. Modos futuros só entram quando houver implementação e validação independente.

`cargo metadata --offline --no-deps` confirmou que o Cargo reconhece o alvo `mycelium-cqr-worker` e dependência `libc`; `rustfmt --check` validou a sintaxe superficial/formatação. Isso **não substitui** compilação nem o teste Rust em hardware. Nenhuma emissão, recompensa, NEV ou transação foi criada.

O produtor S1-MUPP genuíno continua não identificado na busca delimitada dos diretórios `S1 BPF/s1`, `S1 BPF/scripts` e `S1 Cognitive Hypervisor/systemone`; `/tmp/s1-mupp-state.json` permanece ausente. Não gerar essa evidência artificialmente, não mudar para fallback permissivo e não iniciar kernel científico/compilação sob picos acima de 75 °C. A última observação durante a revisão variou entre ~63 °C e ~91 °C sem tarefas CQR, indicando necessidade de investigar refrigeração.

## Compilação com guarda térmica (2026-10-07)

`python3 apps/mycelium-next/guarded_cqr_build.py` é uma tentativa **estritamente supervisionada** de compilar o worker CQR-C0 Rust. O programa lê sensores reais `coretemp` + thermal zones, exige início até 70 °C e interrompe todo o grupo de processos Cargo/rustc se o máximo atingir 75 °C. Restringe a apenas um núcleo, prioridade baixa, duty cycle (0,08 s execução/0,36 s pausa) e até 150 segundos. Não pode executar tarefas CQR nem pagar, emitir ou assinar nada. O log da compilação fica em `/tmp/mycelium-cqr-guarded-build.log`.

**Resultado real desta tentativa:** primeira invocação recusada com 79 °C, sem compilação; segunda, iniciada a 68 °C, abortada a 77 °C após 1,2 s. O executável **não foi produzido** e não restaram processos `cargo`/`rustc`. Quatro testes adicionais da guarda (mocks, sem compilação real): 73 testes Python PASS. O equipamento está com picos térmicos incompatíveis com a execução pesada; inspecionar refrigeração antes de outra compilação.

## Diagnóstico térmico sem carga (2026-10-07)

Ferramenta de leitura sem efeitos de execução: `apps/mycelium-next/thermal_diagnostic.py`. Ela coleta termometria de `coretemp` + todos os sensores existentes via `temperatures()`, lê apenas a frequência de CPU0 e preserva origem, timestamp, contagem de erros e medidas com unidades. Não liga ventoinhas, não altera frequência ou energia, não executa CQR, não substitui S1-MUPP e não concede autoridade financeira.

```bash
cd '/media/bruno/SAMBOOK/Mycelium Network'
python3 apps/mycelium-next/thermal_diagnostic.py --samples 12 --interval 0.25 --output research/evidence/cqr-thermal-baseline-20261007.json
```

Evidência real, 12 amostras, sensores válidos 12/12: CPU Package mínimo **54 °C**, mediana **55 °C**, máximo **55 °C**; frequência de CPU0 entre **1032,961 e 1477,528 MHz**; nenhuma amostra >=75 °C. Dados correspondem à máquina **sem compilação**; não inferir temperaturas seguras quando `rustc` estiver ativo. Sistema já estava no perfil `power-saver`, embora `intel_pstate/no_turbo=0` (Turbo Boost ativo) e teto de frequência de CPU0 fosse 4,4 GHz, acima da base 2,6 GHz. Controles `no_turbo` e `max_perf_pct` não estão graváveis pelo usuário comum; **nenhuma configuração foi alterada**. `thermald` estava inativo; não há leitura de ventoinha `fan*_input` identificada nessa inspeção. As informações são indicativas e não comprovam defeito mecânico ou causalidade única.

O `preflight` feito logo depois, em SQLite isolado, registrou máximo real **55,05 °C** e `allowed=false`, motivo **s1_unavailable_or_invalid**, porque `/tmp/s1-mupp-state.json` continua ausente. Também reportou `cqr_binary_available=false` e `financial_execution.enabled=false`. Regressão Python: **77 testes PASS**. Não repetir compilação em loop nem contornar sensores. Investigar dissipação e ventoinhas, e validar a necessidade de limite temporário de Turbo com o administrador antes de retomar compilação.

## Compilação com Turbo Boost temporariamente desativado — autorização local necessária (2026-10-07)

Criado `apps/mycelium-next/build_cqr_turbo_off.sh`. Esse é um invólucro para o guarda térmico já existente. O usuário deve executá-lo em seu **próprio terminal interativo**, **sem `sudo` antes do `bash`**:

```bash
cd '/media/bruno/SAMBOOK/Mycelium Network'
bash apps/mycelium-next/build_cqr_turbo_off.sh --check
bash apps/mycelium-next/build_cqr_turbo_off.sh
```

O programa solicita autorização por `sudo -v` antes de alterar o único controle root `/sys/devices/system/cpu/intel_pstate/no_turbo`; memoriza o valor original, ativa `no_turbo=1`, verifica o estado e invoca `guarded_cqr_build.py` como **usuário normal**. Traps `EXIT`/`INT`/`TERM`/`HUP` tentam restaurar **exatamente o valor anterior** e verificam a leitura. A compilação continua restrita a uma CPU, baixo duty-cycle, tempo máximo de 150 segundos, partida <=70 °C e abort >=75 °C; nenhuma tarefa CQR, operação financeira, emissão ou alteração de S1-MUPP é executada.

Aviso: nenhuma rotina de limpeza de processo pode garantir restauração após `SIGKILL`, queda de energia ou falha grave do sistema. O script imprime alerta e comando manual se uma tentativa de restaurar falhar. Não usá-lo em terminal propenso a interrupção ou sem acesso local de recuperação. No teste remoto, `sudo -n true` **não era autorizado** e o controle sysfs não era gravável; portanto **não houve tentativa efetiva de alterar Turbo**. `bash -n` e `--check` passaram, `no_turbo` permaneceu **0**, CPU marcou **51 °C**, nenhuma compilação foi iniciada e o novo executável permanece **ausente**. A regressão Python teve **77 testes PASS**. Para restauração manual à configuração observada hoje: `echo 0 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo` (somente quando necessário e sob autorização local).

## Compilação Turbo-off com duty cycle adaptativo (2026-10-07)

O operador realizou uma compilação real com `bash apps/mycelium-next/build_cqr_turbo_off.sh`. O sistema confirmou `no_turbo=1` durante a execução, amostrou **52 °C na entrada e 52 °C de máximo**, encerrou o trabalho apenas por `time_budget_abort` após **150,1 s** e restaurou `no_turbo=0` com êxito. O log `/tmp/mycelium-cqr-guarded-build.log` continha só `Compiling mycelium-economy v0.1.0 (...)`; **nenhum erro de código foi registrado, mas o compilador não finalizou**. `target/debug/mycelium-cqr-worker` permanece ausente.

O supervisor `guarded_cqr_build.py` foi ajustado **após** essa execução para um teto de **900 s**, mantendo o corte térmico em **75 °C**, exigindo partida de no máximo **70 °C**, um núcleo, baixa prioridade, execução offline e sem operações financeiras. O duty cycle passa a ser adaptativo: abaixo de 62 °C usa 0,12 s ativo/0,08 s parado (60%); de 62 °C a menos de 66 °C usa 0,10/0,16 (38%); de 66 °C a menos de 70 °C usa 0,06/0,24 (20%). Ao atingir **70 °C**, o worker para e só recomeça após resfriar para **65 °C ou menos**. Amostragem nas pausas de até 0,05 s, mensagens de progresso a cada aproximadamente 30 s. Se atingir 75 °C ou faltar sensor, o grupo privado de compilação é encerrado sem retry automático.

A modificação foi validada **sem repetir compilação**: `79/79` testes Python PASS em 0,420 s; inclui teste de `SIGTERM` simulado quando sensor informa 76 °C. `bash -n` e o modo `--check` passaram; Turbo Boost permaneceu em 0 e a temperatura real na validação foi 51 °C. Para nova tentativa, repetir **no terminal local**, nunca executar como root:

```bash
cd '/media/bruno/SAMBOOK/Mycelium Network'
bash apps/mycelium-next/build_cqr_turbo_off.sh
```

O usuário deverá autenticar com `sudo` no seu próprio terminal. A restauração é verificada no final. Uma compilação aprovada não dispensa origem S1-MUPP legítima nem autorização do `Engine.gate()` para executar trabalho CQR real. Nenhuma operação de pagamento, emissão ou verificação NEV faz parte deste processo.

## AEM-ECO v0.2 — cotação econômica offline

[A proposta v0.2](../../research/AEM_ECO_V02.md) prioriza serviços pequenos pagos por clientes externos, GPU desligada e espera quando não há margem. `aem_economics.py` calcula uma previsão conservadora em micro-USDC com cinco componentes de custo, reserva de risco, piso de lucro, limites de recursos e exposição por trabalho/dia. Custo desconhecido, orçamento vencido ou guarda shadow bloqueada impedem avanço.

O módulo é **isolado da fila real**: lê uma proposta JSON offline de até 64 KiB e emite conselho `SHADOW_QUOTE`. Não mede energia, reserva orçamento, acessa carteira ou executa serviço. Declarações de financiamento/adaptador e orçamento JSON não são provas. Mesmo uma cotação elegível mantém todas as autorizações falsas e `verified_nev=null`; o bridge passivo existente continua sem receita/demanda real conectada.

Regressão leve, sem compilação ou sensores reais:

```bash
rtk proxy python3 -m unittest discover -s apps/mycelium-next -p 'test_*.py'
```

## Supervisor nativo Mycelium-ECO

`eco_supervisor.py` conecta o ciclo do Mycelium Next ao motor `discovery` do Mycelium-ECO. É uma opção explícita de `start`: avalia relatórios externos novos, conserva a espera de `NO_EDGE`/`NegativeNev` e mantém o histórico em SQLite entre reinícios. Não produz esses relatórios nem implementa execução financeira ou recebimento. Nenhum serviço foi ativado nesta implementação.

Comece por uma cópia de [eco-config.example.json](eco-config.example.json) e configure uma fonte real. Caminhos relativos são resolvidos a partir do arquivo de configuração. `source_report` deve apontar para o formato aceito pelo `S1ShadowEvidenceAdapter` nativo, atualizado por um produtor externo; um JSON arbitrário não constitui uma oportunidade. `mupp_state` deve vir do guardião S1-MUPP real. O exemplo usa `estimated_job_cost_musd_micros=10000` apenas para ilustrar a unidade: substitua pela estimativa medida; não é medição de energia nem orçamento mensal.

O binário precisa incluir o novo campo `scheduler` dos comandos `discovery-status` e `discovery-run`. Um binário antigo gera `NATIVE_UPGRADE_REQUIRED` e não inicia a descoberta. **O Rust alterado ainda não foi compilado nem testado**; faça essa validação em equipamento com condições térmicas seguras antes de habilitar o ciclo. As tentativas anteriores nesta máquina apresentaram picos de até 95 °C.

Depois dessas condições, uma passagem isolada ou o acompanhamento contínuo usam:

```bash
rtk proxy python3 apps/mycelium-next/mycelium_next.py --state /tmp/mycelium-eco-check eco-run-once --config apps/mycelium-next/eco-config.json
rtk proxy python3 apps/mycelium-next/mycelium_next.py start --eco-config apps/mycelium-next/eco-config.json
```

O loop verifica a fila e o ECO a cada 30 segundos; o intervalo configurado e os prazos nativos podem adiar a chamada seguinte. A espera nativa usa tempo Unix, com 60 segundos por ciclo de espera, sem aumentar buscas, cobertura ou resoluções. Esperas antigas baseadas em ciclos são migradas uma vez e persistidas. Relatórios devem ter até 128 KiB, JSON estrito e idade dentro do limite configurado (30 segundos no exemplo). O digest do conteúdo normalizado impede consumir novamente o mesmo relatório, mesmo que só mudem espaços ou a ordem das chaves. Uma execução interrompida ou com confirmação incerta exige conciliação e bloqueia repetição automática.

Cada subprocesso nativo fica em um núcleo, com prioridade baixa, limite de CPU de 2 segundos (limite rígido de 3), memória virtual de 256 MiB, saída de 256 KiB e prazo de 15 segundos para descoberta ou 5 para consultas. O supervisor revalida temperatura, S1-MUPP e cancelamento durante a execução. A partir de 75 °C bloqueia; só retoma até 70 °C. Falta de sensor ou de MUPP válido e recente também bloqueia. Esses limites reduzem trabalho e interrompem este executor; não garantem ausência de calor nem controlam outros processos.

O cartão **Mycelium-ECO** e `mycelium_eco` no status exibem o estado da descoberta. Demanda externa paga só aparece após o dashboard nativo confirmar provider pinado, identidade verificada, resultados validados e invariantes de receita preservados. A medida é cumulativa e não representa saldo de carteira, lucro nem previsão de valorização. Sem essa comprovação, fica desconhecida. Mesmo consultas nativas podem inicializar a identidade privada do `LocalEconomy` em `native_home`; use um diretório dedicado.

Validação Python: **122 testes passaram**, usando fontes, gates e respostas nativas sintéticas; alguns exercitam subprocessos locais pequenos. A checagem isolada com sensores reais retornou `GATE_BLOCKED` por `s1_unavailable_or_invalid`, sem criar estado nativo. A análise de sintaxe Rust com `rustfmt` e do JavaScript com `node --check` passou; isso não substitui compilação ou testes Rust. Essas verificações cobrem limites, esperas, deduplicação e recuperação, sem comprovar rentabilidade, recebimento ou execução produtiva no motor Rust. Para chegar ao recebimento autônomo ainda faltam o produtor real de oportunidades, um serviço contratado com margem verificada e liquidação autenticada.
