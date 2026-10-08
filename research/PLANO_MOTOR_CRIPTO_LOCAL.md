# Plano de continuidade do motor local Mycelium

Data: 2026-10-05. Documento de planejamento; não comprova execução, receita ou conclusão das três prioridades. Não autoriza negociação real, emissão de token, crescimento ou reinvestimento automático.

## Objetivo e limites

Construir um motor local que executa tarefas úteis, valida entregas e registra custos e resultados verificáveis. Receber cripto por serviço, minerar uma rede e emitir um token são operações diferentes. A infraestrutura atual ainda não demonstra receita recebida. Créditos internos e benchmarks não são receita.

Bots podem reduzir desperdício, executar tarefas e controlar riscos. Não asseguram valorização. Demanda por utilidade pode sustentar valor; emissão, volume artificial ou compra coordenada não comprovam demanda. Excluir wash trading, spoofing, pump e promessas de rendimento.

## Estado de partida

Segundo research/PRIORIDADES_TRABALHO_PAGO.md, último registro em 2026-10-05T22:14:07.047538 UTC: CPU 92 °C, acima do limite local de 75 °C; evidência research/evidence/thermal-20261005T221407Z.json. É uma leitura histórica, não temperatura atual. As três prioridades permanecem abertas. Energia e custo monetário não medidos continuam desconhecidos.

## 1. Desbloquear a operação com segurança térmica

Revalidar sensores reais e o gate S1-MUPP. Investigar consumo dos processos e sua propriedade antes de interrompê-los. Não aumentar carga enquanto houver bloqueio térmico. Ausência de sensor, estado vencido, timestamp futuro, aquecimento e fase insegura impedem trabalho.

Usar histerese, período mínimo de recuperação e amostras válidas consecutivas. Cada tarefa terá prazo, teto de tentativas e backoff persistente. Trabalho bloqueado aguarda mudança de estado; não repete benchmark improdutivo. Não elevar o limite térmico para obter aprovação.

Saída: evidências de bloqueio por calor, sensor ausente, estado vencido/futuro e retomada segura; testes do adapter e discovery pertinentes aprovados. Registrar condições e resultados no arquivo de prioridades.

## 2. Executar uma classe de tarefa local existente

Começar pelo CQR existente: tarefa determinística pequena, entrada versionada, limites de duração e memória, execução sob proteção térmica e validação independente. Persistir entrada, versão do código, resultado, hashes e decisão de aceitação. Repetir somente quando necessário para verificar determinismo ou uma mudança relevante.

A validação de dispersão do operador de força não comprova, isoladamente, convergência da trajetória ou fidelidade experimental. Acrescentar critérios adequados à entrega, incluindo conservação, tolerâncias e rejeição de resultado inválido. Um benchmark aceito ainda não é um serviço comprado.

Saída: ao menos uma execução real aceita, rejeições esperadas verificadas e pacote de evidências reproduzível, sem serviço externo.

## 3. Instrumentar duração, aceitação e recursos

Registrar por execução: identificador; timestamps UTC; duração monotônica em ms; CPU em ms quando medida; pico de memória em bytes ou MiB com conversão explícita; temperatura em °C com caminho do sensor; tentativas; motivo de bloqueio/rejeição; versão e origem de cada medição.

Taxa de aceitação = tarefas aceitas / tarefas efetivamente validadas, com janela e denominador. Separar tentativas de tarefas únicas. Energia em Wh somente com medição e escopo conhecidos; leitura RAPL, se disponível, não equivale automaticamente ao consumo total da máquina. Custo monetário depende de energia, tarifa e demais despesas medidas. Valores desconhecidos serão null com motivo, nunca zero inventado.

Saída: relatório local derivado dos registros brutos e conciliação entre fila, execuções e decisões. Concluir estas três prioridades antes de avaliar escala.

## 4. Organizar os bots locais

| Bot | Responsabilidade | Limite obrigatório |
| --- | --- | --- |
| Supervisor térmico | Autorizar ou bloquear trabalho | Falha fechada; prevalece sobre todos os workers |
| Orquestrador | Fila, prioridades, deduplicação e tentativas | Concorrência e orçamento limitados; backoff persistente |
| Worker | Executar a classe CQR autorizada | Deadline e limites de recursos efetivos |
| Validador | Aceitar ou rejeitar com critérios registrados | Separar produção e validação; não aprovar apenas por conclusão |
| Medidor | Coletar recursos e resultados | Unidades, proveniência e desconhecidos explícitos |
| Auditor | Conciliar registros e gerar relatório | Não transformar crédito interno em recebimento |

Preferir módulos da infraestrutura existente. Cada função pode começar no mesmo processo; não há necessidade de seis daemons. Uma fila persistente e estados queued, blocked, running, validated, rejected e failed precisam ter transições recuperáveis após reinício. Usar identidade estável da tarefa e escrita atômica; evitar efeitos duplicados.

Saída: reinício sem perda de tarefas, falha de worker sem duplicação, interrupção térmica registrada e fila sem repetição ilimitada.

## 5. Medir capacidade e escalar em etapas

Estabelecer baseline com um worker. Medir tarefas aceitas/hora, latência mediana e p95, memória, temperatura, falhas e tempo bloqueado. Aumentar concorrência em pequenos passos somente após janela sustentada segura e revisão dos resultados. Encerrar a etapa se a eficiência cair, houver calor excessivo ou regressão de validação.

Definir metas numéricas depois do baseline. Escala relevante é trabalho útil aceito por unidade de recurso, não quantidade de bots. Distribuição entre outras máquinas locais será uma etapa posterior, com autorização e inventário dos recursos, validação equivalente e orçamento global. Não comprar equipamento nem crescer automaticamente.

Saída: curva observada de capacidade versus recursos, configuração estável escolhida e limites de operação documentados. Não existe evidência atual para prometer alta escala nesta máquina.

## 6. Separar geração de receita e operação financeira

Rota preferencial para estudo posterior: cobrar por entregas úteis verificadas e permitir pagamento em cripto. Ainda exige demanda real, oferta definida, critérios de entrega e comprovação de pagamento. Descoberta de clientes e serviços externos ficam fora do escopo local atual.

Mineração exige escolher uma rede e algoritmo, medir hardware/energia e considerar dificuldade e remuneração observadas. Staking exige capital, regras específicas da rede e avaliação de penalidades. Nenhuma destas alternativas é implementada ou presumida rentável neste plano. Emitir token não gera receita automaticamente e não é necessário para o motor funcionar.

Uma integração financeira futura deverá começar em simulação: separar saldo interno, recebimento confirmado, tarifas e despesas; modelar falhas e reconciliação. Transações reais precisam de escopo específico, limites e gestão de chaves. Bots de tesouraria/liquidez só entram se houver finalidade legítima e aprovação dessa operação; sem trades artificiais, sem promessa de elevar preço e sem reinvestimento automático.

Saída: viabilidade baseada em recebimentos reais menos despesas conhecidas. Resultado indeterminado se faltarem medições; nenhum prazo de retorno financeiro pode ser deduzido dos benchmarks.

## Ordem imediata

1. Verificar condições térmicas sem iniciar carga e resolver a causa do bloqueio dentro do escopo autorizado.
2. Finalizar proteção e testes pendentes; executar e validar uma tarefa CQR sob condição segura.
3. Persistir e conferir métricas e evidências; só então declarar as três prioridades concluídas e desativar a automação correspondente.
4. Implementar/revisar fila e bots necessários; medir baseline e elaborar proposta concreta de escala para revisão.

## Referências de contexto

- Ethereum staking: https://ethereum.org/staking/ — recompensas, requisitos e riscos específicos da rede.
- CFTC, pump-and-dump em moedas virtuais: https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/beware_virtual_currency_pump_dump.html

Estas referências não são dependências da execução local.
