# Mycelium Network — plano privado, local e capital-zero

**Data:** 10 de novembro de 2026  
**Estado:** proposta de implementação; este documento não declara funcionalidades novas como concluídas.  
**Diretório do projeto:** /media/bruno/SAMBOOK/Mycelium Network/  
**Decisões do operador:** rede privada somente do proprietário; início em um computador; economia cripto interna.

## 1. Definição do projeto

O Mycelium será, nesta etapa, uma infraestrutura privada de automação e serviços locais, controlada por um único operador e executada no TushiBook. O Laya será a interface de gerenciamento dos agentes; os componentes Rust/Python já existentes no Mycelium continuarão responsáveis por identidade, armazenamento, fila, execução, validação e registros.

O objetivo não é criar uma rede pública, vender capacidade de terceiros ou simular mineração. É fazer o computador executar trabalho útil sobre dados e arquivos autorizados pelo proprietário, registrar resultados verificáveis e distribuir créditos internos entre os agentes que contribuíram.

**Capital-zero significa não contratar infraestrutura, serviços pagos, tráfego publicitário, domínio, VPS, APIs comerciais ou equipamentos novos para iniciar.** Não significa custo econômico literalmente zero: energia, conexão já existente, manutenção e desgaste do computador continuam existindo. Como esses custos ainda não estão medidos, devem aparecer como desconhecidos, nunca como zero presumido.

### Decisões fixas desta versão

- Propriedade e controle: um único proprietário; nenhum participante externo.
- Topologia inicial: um computador, um nó Mycelium, vários processos/agentes locais.
- Rede: modo privado local; sem bootstrap público, mDNS, relay externo, seed público ou portas de entrada expostas.
- Dados: somente arquivos, metadados e conteúdo cuja utilização foi autorizada pelo proprietário.
- Economia: unidade interna MYC, com recibos assinados e histórico verificável localmente.
- Liquidação: nenhuma emissão pública, exchange, bridge, custódia de terceiros ou promessa de conversão nesta etapa.
- IA: processamento local como padrão; o agente deve continuar funcional sem uma API de IA externa.

## 2. O que “economia cripto interna” significa aqui

MYC será inicialmente uma **unidade privada de contabilidade criptográfica**, não uma criptomoeda pública. Os eventos do ledger serão assinados e encadeados por hashes; os saldos serão derivados desses eventos. Isso oferece integridade verificável e autoria dos lançamentos, mas não cria consenso distribuído, mercado, liquidez, lastro financeiro ou resistência à alteração por um administrador que controle integralmente o computador.

MYC não terá preço em BRL/USD, não será anunciado como investimento, não será resgatável por dinheiro e não será transferível para carteiras externas. Um saldo MYC representa apenas contribuição/recurso reconhecido dentro da instalação privada do Mycelium.

A palavra “cripto” nesta fase descreve o uso de criptografia para identidade, assinatura, integridade e prevenção de replay. **Não chamar o ledger local de blockchain ou de moeda descentralizada.**

### Separação obrigatória de registros

1. **Nutrients (ATP, Enzymes, Mycelia, Spores, Resilience):** indicadores de recursos e metabolismo já existentes. Não são dinheiro.
2. **MYC interno:** créditos privados concedidos por tarefas locais aceitas, sujeitos às regras deste documento. Não são receita.
3. **RV/NEV e receita externa:** permanecem no domínio do mycelium-economy e só podem refletir pagamento externo real e verificado. Trabalho próprio, emissão MYC, testes e transferências entre carteiras controladas pelo proprietário nunca promovem receita externa.

Não misturar os três saldos nem converter automaticamente um em outro.

## 3. Arquitetura-alvo de um único computador

    Proprietário
       |
       v
    Laya local — painel e gestão de agentes
       |
       v
    Adaptador Laya ↔ Mycelium (localhost autenticado)
       |
       v
    Mycelium Next — fila SQLite persistente e supervisor
       |
       +------> Workers locais (Relay / Metadata / Hybrid)
       |                    |
       |                    v
       |              resultados e métricas
       v
    mycelium-node — daemon e socket Unix autenticado
       |
       +------> SporeBank / Content IDs / armazenamento local
       +------> índices e metadados privados
       +------> ledger MYC local e recibos assinados
       |
       v
    Relatório local: tarefas, recursos, integridade e saldos

### Regras de rede

- O daemon e o adaptador devem aceitar somente conexões locais nesta fase.
- Preferir Unix Domain Socket para plano de controle entre processos.
- Quando HTTP local for necessário para o Laya, bind exclusivo em 127.0.0.1, autenticação e validação de Host.
- Desativar descoberta mDNS, bootstrap remoto, publicação de seeds e relays públicos no perfil privado.
- Não encaminhar portas do roteador, não abrir Event Horizon à Internet e não instalar túnel público.
- Os módulos libp2p existentes podem permanecer no workspace, mas o perfil privado não deve discar nem aceitar peers externos.
- Falha em provar o isolamento de rede bloqueia a ativação do perfil.

A instalação será um **nó único com vários workers locais**, não uma malha P2P multi-host. O uso de bibliotecas P2P no código não altera essa classificação.

## 4. Responsabilidade de cada componente existente

| Componente | Uso nesta versão | Decisão |
|---|---|---|
| Laya | Configurar, iniciar, pausar e observar agentes | Interface local; não substitui o runtime |
| apps/mycelium-next | Fila SQLite, tentativas, recuperação e painel | Reutilizar; manter supervisor térmico |
| mycelium-node | Daemon, socket local, Event Horizon e integração do nó | Reutilizar em perfil privado |
| mycelium-bot | Processo worker | Substituir o placeholder antes de qualquer execução |
| mycelium-core | NodeId, ContentId e tipos comuns | Reutilizar |
| mycelium-pheromones / keyring | Identidade e gestão de chaves | Auditar APIs e armazenamento antes de integrar |
| mycelium-sporebank | Objetos content-addressed locais | Reutilizar para entradas/resultados aprovados |
| mycelium-nutrients | Recursos e créditos metabólicos | Manter separado de MYC |
| mycelium-economy | Revenue ledger, RV/NEV e provas externas | Preservar; não usar para fabricar demanda interna |
| mycelium-store / media | Catálogos e mídia locais | Deixar para etapa posterior |
| mycelium-veil / PQC | Transporte privado avançado | Não ativar agora; não é requisito do MVP |

Não introduzir NATS, PostgreSQL, Kubernetes, Docker, VPS ou uma blockchain nesta fase. O scheduler SQLite e os sockets locais existentes são suficientes para o primeiro fluxo. Não duplicar filas nem criar um segundo daemon se a função já existir em Mycelium Next ou mycelium-node.

### Laya e o runtime

Laya será o plano de controle dos agentes: configuração, escolha do perfil, início/parada, inspeção de tarefas e leitura de relatórios. A execução real permanece em workers controlados pelo Mycelium.

Criar um adaptador estreito, local e autenticado. O adaptador deverá:
- aceitar somente comandos de uma allowlist;
- encaminhar tarefas ao scheduler existente;
- consultar estado e métricas sem permissões de escrita financeira;
- validar payload, tamanho, prazo, caminho de arquivos e identidade da tarefa;
- falhar fechado quando o daemon, o supervisor ou o estado de autorização estiver indisponível.

Se a integração direta do Laya exigir um gateway HTTP, mantê-lo em loopback. Não expor a API do Laya, n8n ou Mycelium à rede externa. Modelos locais via Ollama podem ser opcionais para classificação e extração; a validação dos resultados deve ser determinística e independente do modelo.

## 5. Perfis de workers

### Metadata Worker — prioridade inicial

Trabalha exclusivamente sobre diretórios explicitamente autorizados. Primeiras tarefas: inventariar arquivos, extrair metadados locais, normalizar formatos, calcular BLAKE3, detectar duplicatas e construir índices privados. Não enviar nomes, conteúdo, caminhos ou identificadores para terceiros.

Cada tarefa recebe um manifesto com:
- task_id estável e chave idempotente;
- caminho raiz permitido e política de acesso;
- hash de entrada e versão do transformador;
- limites de tamanho, CPU, memória e tempo;
- esquema de saída e critérios de aceitação;
- hash do resultado, relatório e decisão do validador.

### Relay Worker — escopo local limitado

No primeiro estágio, “relay” significa mover blocos entre componentes/processos locais, ou entre áreas autorizadas do próprio nó. Não vender largura de banda, não gerar tráfego artificial, não criar loops de retransmissão e não atuar como proxy público.

A transferência só pode compor métricas quando o destinatário local confirmar a integridade e a conclusão. Bytes de heartbeat, descoberta, retry ou controle não geram MYC.

### Hybrid Worker

Combina indexação e transporte local. Deve reutilizar os handlers existentes em vez de criar uma nova implementação paralela. A fila define o tipo de trabalho; o worker não pode inventar tarefas para creditar a própria carteira.

### O que não executar

- Trades aleatórios, arbitragem, mineração de moedas externas ou staking.
- Cliques, impressões, visitas ou tráfego publicitário artificiais.
- Geração de tarefas pelos próprios workers para produzir créditos.
- Downloads de dados sem licença, coleta de dados pessoais sem finalidade/autorização ou crawling não solicitado.
- Execução de código arbitrário fornecido por conteúdo indexado.
- GPU/LLM pesado ou compilação prolongada sem pré-verificação térmica válida.

## 6. Ledger privado MYC

### Modelo proposto

Criar um módulo de ledger interno isolado do revenue ledger. A implementação deve primeiro auditar o que pode ser reaproveitado de mycelium-nutrients (vouchers Ed25519, nonce e proteção contra replay) e mycelium-economy (encadeamento BLAKE3, validação ao ler e gravação durável). Não reutilizar diretamente o tipo Nutrient como se fosse dinheiro.

Cada evento MYC deve conter, no mínimo:
- schema_version e domain separator;
- sequence monotônica e event_id idempotente;
- previous_hash e event_hash BLAKE3;
- identidade do proprietário emissor e identidade do worker beneficiário;
- task_id, classe de tarefa e versão do worker;
- hashes de entrada/saída e prova de aceitação;
- métricas medidas com unidade e proveniência;
- valor MYC, motivo, nonce e timestamp;
- assinatura Ed25519 de chave autorizada.

Os saldos devem ser recalculados a partir do diário validado; não confiar num saldo editável armazenado em separado. Movimentações entre carteiras exigem lançamentos equilibrados de débito/crédito, nonce único e assinatura autorizada. A escrita deve ser serializada, atômica e idempotente. Falha de assinatura, lacuna de sequência, hash inválido, replay ou schema desconhecido bloqueia novos créditos.

### Política de emissão interna

- Uma carteira de autoridade pertence ao proprietário; cada worker recebe identidade derivada e permissões mínimas.
- Workers não possuem permissão de cunhar MYC, alterar regras, aprovar seu próprio resultado ou liberar pagamentos.
- O scheduler cria tarefas; o worker executa; o validador independente aceita/rejeita; somente o emissor autorizado registra o crédito.
- MYC é concedido por trabalho útil aceito, nunca por uptime isolado, heartbeat, número bruto de pacotes ou volume duplicado.
- Definir orçamento máximo de emissão por tarefa e por dia antes de ativar recompensas.
- Rejeições, tentativas, duplicatas e tarefas internas de saúde não geram MYC.
- Créditos podem ser consumidos futuramente para prioridade, quota ou serviços locais. Essa utilidade deve ser implementada e testada antes de chamar o token de funcional.
- Exportação ou cópia do ledger é backup, não prova de consenso nem de saldo resgatável.

Uma regra de cálculo inicial pode ser determinística: classe de tarefa × unidades aceitas × fator de qualidade, limitada pelo orçamento da tarefa. Os pesos só serão definidos depois de medir o baseline; não inventar cotação BRL, custo de energia ou valor de mercado para MYC.

### Segurança das chaves

- Não ler, imprimir, copiar ou incluir no Git seeds, vaults, tokens ou chaves existentes.
- Auditar mycelium-keyring e permissões dos arquivos antes de decidir onde guardar a chave de emissão.
- Nunca entregar a chave do proprietário aos workers ou ao Laya.
- O Laya solicita uma operação ao serviço local de assinatura; não recebe material secreto.
- O serviço de assinatura valida política, task_id, recibo e limite diário antes de assinar.
- Backup cifrado da chave e recuperação devem ser documentados antes de emissão real de MYC.

### Limite de confiança

Um ledger local hash-encadeado detecta alterações acidentais e inconsistências, mas o administrador/root que controla o host pode reescrever o diretório e recalcular toda a cadeia. Sem um segundo domínio de confiança, testemunha externa ou checkpoint independente, não alegar imutabilidade adversarial. Esse limite é intencional no modo de um único computador.

## 7. Proteção operacional e térmica

O histórico do projeto registra bloqueios térmicos e ausência de estado S1-MUPP válido em verificações anteriores. Esses registros são históricos, não uma leitura da temperatura atual. A operação produtiva só poderá iniciar após uma pré-verificação real e recente.

Regras obrigatórias:
- Reutilizar o Engine.gate / Mycelium Next e o supervisor S1-MUPP existente.
- Sensor ausente, inválido ou desatualizado, estado S1 ausente/inválido ou gate negado = bloqueio.
- Não criar estado S1 sintético, não reduzir o limite térmico para “passar” e não contornar o supervisor.
- Usar o máximo entre sensores válidos, histerese e cooldown já definidos pelo guardião; validar esses valores contra o hardware antes de confiar neles.
- CPU, memória, duração, tamanho de entrada/saída e tentativas têm limites rígidos.
- Persistir estados queued, blocked, running, validated, rejected e failed; reinício não duplica execução ou crédito.
- Começar com uma única tarefa leve e concorrência 1. Aumentar somente após evidência de estabilidade.
- Energia/custo desconhecidos permanecem null; não declarar rentabilidade com base em throughput apenas.

## 8. Etapas de implementação e gates de aceite

### P0 — Preservar o estado atual (sem mudanças de código)

1. Confirmar branch, status, diff rastreado e lista de untracked.
2. Criar um registro de baseline e, antes de qualquer refatoração, um patch externo das alterações rastreadas. Fazer backup seletivo dos novos arquivos de trabalho sem copiar .mycelium, vaults, seeds, chaves ou artefatos secretos.
3. Não executar reset, clean, checkout destrutivo, stash automático, rebase ou commit.
4. Manter Cargo.lock, crates novos, modificações e arquivos não rastreados exatamente como estão.
5. Registrar a nova documentação em arquivo independente.

**Aceite:** o diff pré-existente continua intacto; a única nova alteração desta tarefa é este documento.

### P1 — Perfil privado local

1. Criar uma configuração nomeada private_single_host em local não versionado, com defaults seguros.
2. Bind apenas em loopback ou socket Unix; desativar mDNS, bootstrap externo, relay, seed público e descoberta remota.
3. Definir raízes de dados permitidas e credenciais locais.
4. Testar que o daemon inicia, responde localmente e não abre listener em interface externa.
5. Documentar como parar e reiniciar o daemon sem perder a fila.

**Aceite:** serviços essenciais funcionam localmente; nenhuma conexão/porta externa é necessária; nenhuma seed pública é publicada.

### P2 — Contrato de tarefa e supervisor

1. Reutilizar SQLite e a fila de apps/mycelium-next.
2. Definir schemas versionados para metadata_index, local_transfer e local_maintenance.
3. Adicionar idempotency key, deadlines, limites e estados recuperáveis.
4. Ligar o scheduler ao daemon pelo socket autenticado.
5. Fazer preflight real do sensor e S1-MUPP; falha fecha a execução.

**Aceite:** uma tarefa leve persiste após restart, não duplica efeitos e é bloqueada por gate inválido.

### P3 — Laya Adapter

1. Descobrir e documentar a API/eventos da versão do Laya instalada.
2. Implementar somente health, submit_task, pause_worker, resume_worker, task_status e report.
3. Autenticar localmente; allowlist de comandos; payload e tamanho limitados.
4. Laya não acessa wallet, seed, vault ou arquivo interno do ledger diretamente.
5. Adicionar modo CLI de contingência para o caso de Laya indisponível.

**Aceite:** Laya envia uma tarefa local e mostra estado/resultado; não existe listener público nem acesso a segredos.

### P4 — Workers reais

1. Substituir o loop aleatório em crates/mycelium-bot/src/main.rs por um runtime orientado a tarefas.
2. Remover simulação de trade e função térmica placeholder; consumir o gate real.
3. Implementar primeiro Metadata Worker para um diretório de teste autorizado.
4. Implementar Local Transfer após o contrato de metadados passar.
5. Implementar Hybrid apenas como composição dos dois handlers.
6. Validar resultados por hash, esquema e repetição determinística quando aplicável.

**Aceite:** resultado reproduzível, verificável, com métricas reais e sem comunicação externa.

### P5 — Ledger MYC privado

1. Fazer auditoria de API e testes dos módulos mycelium-nutrients, mycelium-economy e mycelium-keyring.
2. Criar ledger interno isolado, com eventos assinados, sequência, nonce e hash-chain.
3. Derivar saldos do diário; adicionar auditoria e recuperação.
4. Conectar emissão somente ao caminho tarefa aceita → recibo validado → autorização do proprietário.
5. Separar claramente MYC, Nutrients e RV/NEV.
6. Começar em modo dry-run; depois habilitar créditos locais limitados, sem transação externa.

**Aceite:** assinatura inválida, replay, adulteração, emissão fora do limite e crédito por tarefa rejeitada são recusados.

### P6 — Painel e operação diária

1. Exibir workers ativos, fila, tarefas, bloqueios, CPU, memória e temperatura.
2. Exibir saldo MYC com aviso “crédito interno sem valor monetário”.
3. Exibir histórico de emissão/consumo e resultado da auditoria do ledger.
4. Exportar relatório local com hashes e métricas.
5. Implementar pausa geral e parada limpa.

**Aceite:** o proprietário consegue inspecionar, pausar, auditar e recuperar a instalação sem depender de serviço externo.

### P7 — Fechamento do MVP

Só marcar MVP concluído quando todos estes itens tiverem evidência:
- nó e Laya operando na mesma máquina;
- perfil privado sem listener externo;
- tarefa de metadados real concluída e validada;
- transferência local validada, se habilitada;
- worker bloqueado quando S1/temperatura não autoriza;
- restart sem perda, duplicação ou crédito duplicado;
- ledger MYC íntegro e assinatura verificável;
- relatório mostra custo/energia desconhecidos quando não medidos;
- nenhuma emissão ou pagamento externo ocorreu;
- testes e logs reproduzíveis anexados a docs/reports.

## 9. Estrutura sugerida de arquivos

Preservar os módulos existentes e acrescentar apenas o mínimo necessário, após auditoria:

- docs/architecture/PLANO_MYCELIUM_PRIVADO_CAPITAL_ZERO.md — este plano.
- config/private-single-host.example.toml — exemplo sem segredos, versionável.
- config/private-single-host.toml — configuração real, fora do Git.
- apps/mycelium-next — scheduler/fila existente; evoluir por mudanças pequenas.
- crates/mycelium-bot/src — runtime e handlers de tarefas, removendo placeholders.
- crates/mycelium-private-economy/ — considerar novo crate apenas se a auditoria confirmar que o ledger MYC não cabe sem contaminar Nutrients ou Revenue Ledger.
- docs/reports/private-single-host/ — relatórios de testes, sem chaves ou dados pessoais.

Não criar o novo crate antes da auditoria. O código econômico atual tem invariantes fortes para proteger receita externa; mantê-los intactos é prioridade.

## 10. Critérios explícitos de “capital-zero”

### Permitido no início

- Computador, disco, sistema operacional e conexão já disponíveis.
- Rust/Python e ferramentas já instaladas.
- SQLite, bibliotecas open-source e modelos locais existentes.
- Nó local, workers locais, armazenamento nos discos já disponíveis.
- MYC interno não resgatável e sem cotação externa.

### Fora do escopo inicial

- VPS, domínio, CDN paga, gateway pago, tráfego comprado ou publicidade.
- API comercial de IA, serviço externo de armazenamento ou banco gerenciado.
- Compra de hardware, token público, listagem em exchange, liquidez ou market making.
- Mineração/staking de criptoativos externos.
- Abrir a rede para terceiros ou prometer disponibilidade 24/7.
- Receber/guardar cripto de terceiros, operar exchange ou custodiar fundos.

Se uma etapa exigir um custo inevitável, parar no gate correspondente, estimar e apresentar a decisão ao proprietário. Não ativar cobrança, assinatura, emissão ou compra automaticamente.

## 11. Riscos e limites aceitos

| Risco | Tratamento |
|---|---|
| Falha do único computador | Backups locais e exportações verificadas; indisponibilidade enquanto estiver desligado |
| Perda de chave | Backup cifrado e recuperação testada antes de emitir MYC |
| Root reescreve ledger | Declarar limite; hash-chain não é consenso independente |
| Worker gera atividade inútil | Só tarefas criadas pelo proprietário e resultados aceitos recebem crédito |
| Laya indisponível | CLI e scheduler continuam independentes |
| Modelo de IA alucina | Validador determinístico; LLM nunca decide sozinho emissão |
| Calor ou falta de sensor | Fail-closed pelo supervisor existente |
| Vazamento de dados | Escopo local autorizado, sem telemetria externa e sem publicação de conteúdo privado |

## 12. Estado inicial e preservação do Git

Snapshot observado antes de criar este documento:
- Branch: feat/mycelium-pkarr.
- Alterações rastreadas: 19 arquivos modificados.
- Alterações staged: 0.
- Arquivos não rastreados: 31.
- Diff rastreado: 976 inserções e 495 remoções.
- Há alterações existentes em Cargo.toml/Cargo.lock, CLI, mycelium-bot, mycelium-economy, mycelium-pqc, mycelium-root, mycelium-zkp e outros componentes.

Este plano não autoriza descartar, normalizar ou reformatar essas alterações. Não assumir que arquivos untracked são descartáveis. Não ler nem copiar conteúdo de seeds, vaults, wallets ou segredos para snapshots. Qualquer refatoração futura deve ser feita sobre a branch existente, em mudanças pequenas, com diff revisado antes de editar e testes direcionados depois.

## 13. Ordem de execução recomendada

1. P0 — preservar o estado e confirmar baseline.
2. P1 — configurar modo privado de um único host.
3. P2 — validar fila, tarefa e supervisor.
4. P3 — conectar Laya localmente.
5. P4 — substituir o bot placeholder pelo Metadata Worker real.
6. P5 — construir MYC como ledger interno assinado, em dry-run primeiro.
7. P6 — painel e auditoria.
8. P7 — comprovar os critérios do MVP.

**Primeira entrega técnica recomendada:** Metadata Worker local + fila persistente + recibo validado. É a menor fatia que comprova utilidade real sem depender de capital, internet pública, token externo ou hardware novo.

**Definição de sucesso:** o TushiBook executa tarefas autorizadas sobre dados próprios; Laya coordena os bots; o Mycelium persiste e valida resultados; MYC registra créditos internos auditáveis; e toda a instalação permanece privada, pausável e controlada pelo proprietário.
