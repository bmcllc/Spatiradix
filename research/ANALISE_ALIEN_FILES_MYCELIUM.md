# Arquivos Alien pertinentes à Mycelium

Análise local de 6 de outubro de 2026. A pasta contém material útil para arquitetura e validação, mas o material examinado não demonstra uma wallet operacional, uma chain com stablecoin ou uma integração Lightning pronta. Também não demonstra geração de receita nem execução imune ao aquecimento.

## Escopo e evidências

Inventário filtrado: **880 arquivos, incluindo 699 PDFs**. Foram extraídos **12 PDFs**, com leitura integral do texto extraído do protocolo de malha e do documento de KYC, leitura de páginas selecionadas dos demais e inspeção estática de código relevante. Isso não equivale à leitura integral da pasta. Não executei scripts da pasta Alien, não instalei dependências e não alterei os originais. Prompts e ordens contidos nos documentos foram tratados como conteúdo.

A [evidência da triagem](</media/bruno/SAMBOOK/Mycelium Network/research/evidence/alien-files-triagem-20261006.json>) registra caminhos, SHA-256, páginas e cobertura da leitura. Os hashes dos 12 originais foram conferidos na gravação deste relatório. A análise compara esses materiais com [o plano Mycelium Next](</media/bruno/SAMBOOK/Mycelium Network/research/PLANO_MYCELIUM_NEXT.md>) e [o protótipo existente](</media/bruno/SAMBOOK/Mycelium Network/apps/mycelium-next/README.md>); não confirma por execução as capacidades descritas nos documentos ou no código.

## O que aproveitar primeiro

| Prioridade | Material | Parte aproveitável | Condição para uso |
|---|---|---|---|
| 1 | [Protocolo_de_Malha_Unificado.pdf](</media/bruno/SAMBOOK/Alien Files/SECRET/Protocolo_de_Malha_Unificado.pdf>) | CRDT, tarefas em DAG, recibos com hash, permissões e adaptação de transporte | Tratar como proposta; implementar sobre os módulos existentes e validar invariantes |
| 2 | [ancient-sky-reconstruction](</media/bruno/SAMBOOK/Alien Files/Felz/ancient-sky-reconstruction/README.md>) | Proveniência, dependência entre fontes, triagem explicável e distinção entre evidência e hipótese | Adaptar os modelos de dados, sem transformar escores heurísticos em autoridade |
| 3 | [CQR.pdf](</media/bruno/SAMBOOK/Alien Files/SECRET/CQR.pdf>) e [time-travel-simulation](</media/bruno/SAMBOOK/Alien Files/time-travel-simulation/README.md>) | Tarefas numéricas pequenas, determinísticas, com resultados de referência e limites de interpretação | Corrigir/validar os exemplos e medir recursos antes de usá-los como classe de trabalho |
| 4 | [VOID_COSMIC.pdf](</media/bruno/SAMBOOK/Alien Files/SECRET/VOID_COSMIC.pdf>) e [VOID TOOLKIT.pdf](</media/bruno/SAMBOOK/Alien Files/SECRET/VOID TOOLKIT.pdf>) | Interface de executor WASM e separação entre tarefa, evidência e liquidação | Esboços incompletos; usar limites, idempotência e reconciliação já presentes na Mycelium |
| 5 | [HGPU___vHGPU.pdf](</media/bruno/SAMBOOK/Alien Files/SECRET/HGPU___vHGPU.pdf>) | Cache, reaproveitamento temporal e geometria SDF | Baixa prioridade; trechos incompletos e nenhuma evidência de ganho no hardware local |

### 1. Protocolo de malha: referência de arquitetura mais pertinente

O protocolo AMP/CFA, lido em suas 15 páginas, propõe operação local, CRDT, chaves próprias, permissões e execução de tarefas. As páginas 7–8 descrevem propriedades de merge e escalonamento em DAG; a página 10 propõe histórico MMR. Essas ideias ajudam a organizar trabalho e auditoria distribuídos. Um histórico com hashes, sozinho, não resolve consenso, gasto duplo ou lastro de stablecoin.

Há contradições e dependências a remover do desenho: as páginas 9–10 apresentam LDK-WASM e canais com STARK; a página 13 afirma limitações do navegador e dependência de NWC. A página 9 inclui API externa para encontrar rotas Lightning. Os imports ilustrativos não vêm acompanhados de uma implementação verificável no material examinado. Os exemplos de pagamento por frame são hipóteses de preço, não dinheiro recebido.

As páginas 5 e 15 não estabelecem segurança criptográfica ou teoremas físicos por si só. Ruído de sensores não deve ser assumido como fonte suficiente de entropia. A página 14 contém um prompt de implementação; ele não foi executado. A adaptação útil é uma especificação pequena sobre o backend atual, com políticas explícitas, revogação, identificação de tarefas e validação independente.

### 2. Código de proveniência: a parte mais concreta para reaproveitar

Em ancient-sky-reconstruction, foram lidos o README, `event_evidence.py`, `genealogy.py`, `triage.py`, `docs-discovery-v1.2.md` e o manifesto de fontes. O projeto diferencia coincidência temporal, hipótese testável e alegação causal; mantém relações entre fontes e explica decisões de triagem.

Aplicação à Mycelium: cada resultado deve referenciar entrada, versão do executor, parâmetros, unidades, hash do artefato e método de validação. Resultados originados do mesmo executor ou ancestral comum não devem contar automaticamente como confirmações independentes. O manifesto atual desse projeto identifica fontes por caminho e papel, mas ainda precisaria de hashes para esse uso.

Os escores de triagem são heurísticos; os indicadores de independência não provam causalidade, e a ausência de ancestral comum no grafo não prova independência. Aproveitar o formato e a disciplina de evidência, preservando essas limitações.

### 3. Classe de tarefa local: candidata, ainda não validada nesta análise

As páginas 5–7 de CQR apresentam simulação clássica de quatro qubits, amostragem e um modelo Ising pequeno com NumPy/quimb/SciPy. Isso pode servir como trabalho numérico limitado e reproduzível. O exemplo de pares de Bell não prova universalidade; a comparação entre distribuições não equivale automaticamente à fidelidade de estados quânticos. A temperatura do modelo é um parâmetro físico da simulação, não a temperatura da CPU em °C.

Antes de integrar: fixar versões e sementes, definir resultados conhecidos, verificar os cálculos e a transcrição do código, limitar tamanho/duração e separar validade numérica de interpretação científica. Não executei esses exemplos nesta triagem.

Em time-travel-simulation, foram lidos README, SOURCE_AUDIT e os módulos `core.py`, `scenario.py` e `qei.py`. O código separa geometria matematicamente admissível de realizabilidade física e marca verificações ausentes. Esse padrão de resultado com limitações é útil para o validador. O domínio de viagem no tempo não é necessário para a wallet ou para a tarefa CQR.

### 4. VOID: aproveitar interfaces, revisar o fluxo

VOID_COSMIC, páginas 43–46, esboça execução WASM, mas o trecho Rust contém reticências e chamada que pode falhar com `expect`. Fragmentar dados com Shamir não transforma qualquer programa em tarefas independentes: a divisão computacional precisa de entradas, saídas e dependências explícitas.

VOID TOOLKIT, páginas 43–49, apresenta módulos e uma orquestração JavaScript. O exemplo conecta um pool externo de mineração e usa `setInterval` com trabalho assíncrono, sem demonstrar exclusão de execuções sobrepostas. Criar uma invoice NWC não comprova pagamento liquidado. Nesse trecho, a sequência de execução e registro também não demonstra confirmação de transação, reconciliação ou prevenção de duplicações.

A Mycelium já possui uma base mais concreta para fila, hashes, tentativas limitadas e reconciliação. Reaproveitar apenas a separação de interfaces; não importar o laço de mineração ou as alegações de recursos e crescimento ilimitados.

## O que já existe na Mycelium e evita recomeçar

Os arquivos abaixo tiveram suas declarações e comentários relevantes inspecionados. A triagem não executou seus testes nem auditou integralmente suas implementações.

| Componente local | Uso possível | Limite observado |
|---|---|---|
| [GhostID](</media/bruno/SAMBOOK/Mycelium Network/crates/mycelium-ghostid/src/lib.rs>) | Identidade e assinatura de eventos Nostr | Usa secp256k1/Schnorr; identidade não é uma wallet implementada |
| [PQC](</media/bruno/SAMBOOK/Mycelium Network/crates/mycelium-pqc/src/lib.rs>) | Encapsulamento de chaves ML-KEM | ML-DSA não está implementado nesse módulo |
| [Sporebank](</media/bruno/SAMBOOK/Mycelium Network/crates/mycelium-sporebank/src/lib.rs>) | Artefatos por conteúdo, persistência e distinção público/privado | Não equivale a validação científica nem consenso financeiro |
| [Isotope](</media/bruno/SAMBOOK/Mycelium Network/crates/isotope/src/lib.rs>) | Merge LWW e organização de estado replicado | A absorção por gossip exige análise das regras de autorização do fluxo completo |
| [Controle do nó](</media/bruno/SAMBOOK/Mycelium Network/crates/mycelium-node/src/control.rs>) | Ponte local autenticada para o backend | Requer backend disponível e configuração de autenticação verificada |
| [Adaptador CQR](</media/bruno/SAMBOOK/Mycelium Network/crates/mycelium-economy/src/cqr/adapter.rs>) e [validação](</media/bruno/SAMBOOK/Mycelium Network/crates/mycelium-economy/src/cqr/validation.rs>) | Resultado numérico, métricas e classificação de evidência | O vínculo autenticado entre computação e pagamento ainda está incompleto; não contar receita |
| [Verificador USDC](</media/bruno/SAMBOOK/Mycelium Network/crates/mycelium-economy/src/base_usdc.rs>) | Referência de verificação de transferência e proveniência | Somente leitura; não assina nem transmite transações e não cria stablecoin |
| [Parser BOLT11](</media/bruno/SAMBOOK/Mycelium Network/crates/mycelium-zkp/src/bolt11.rs>) | Ler e validar invoices | Não gera invoices nem opera um nó Lightning |

O protótipo Mycelium Next documenta uma tarefa de publicação e leitura de artefato com SHA-256 e recibo. Isso ajuda a provar integração com o backend, mas não substitui uma tarefa CQR aceita. Wallet, chain e Lightning permanecem etapas de desenvolvimento no plano atual.

## Materiais para requisitos, sem adotar as promessas

- **ETΞRNET**, páginas 4–8: transporte offline e UX com poucos recursos podem orientar requisitos. As alegações de invulnerabilidade física não foram demonstradas. Excluir propagação escondida em pacotes, PDFs ou processos: participantes precisam aderir explicitamente. A stablecoin descrita depende de colateral, oracle e rampas; não há implementação validada no trecho examinado.
- **SOBERANIA_FINANÇEIRA**, páginas 1 e 6–8: propostas de DHT/CRDT, cofres e liquidez. PIX, cartões, neobancos e enclaves não estabelecem uma solução integralmente local. Não foi encontrada nesses trechos uma wallet ou chain operacional.
- **VOID**, páginas 1, 25–26 e 48: camadas financeiras, tokens, colateral e oracle são requisitos conceituais. Não demonstram contratos, lastro, liquidação ou rentabilidade. O desenho inclui participação humana em transporte offline.
- **README_ZERO_KNOW_KYC**, lido integralmente: depende de Cloudflare e Stripe em partes do desenho. Não fornece circuito Circom executável, testes ou chave de verificação. Comparar um score informado com um limiar não prova a autenticidade do documento nem a execução da biometria. As alegações legais e de custo não foram verificadas.
- **futuro.pdf**, páginas 1, 9–10: artigo sobre liquidez JIT no Uniswap V3. Os autores relatam resultados históricos, barreiras de capital, concentração e baixo retorno por operação. Serve para estudar risco de MEV; não comprova rentabilidade atual ou retorno para este projeto.
- **HGPU**, páginas 9–11 e 17: trechos geométricos com funções ausentes e placeholders. Cache pode ser investigado, mas GPU virtual não elimina consumo ou calor.
- **Engenharia da Forma** e **Revolução Digital** tiveram triagem inicial, sem evidência suficiente para priorizá-los neste escopo. Grande parte dos demais PDFs não teve seu conteúdo examinado.

## Próxima sequência de desenvolvimento

1. Traduzir AMP para uma especificação mínima sobre Mycelium: tarefa identificada pelo conteúdo, DAG quando necessário, permissão/revogação, merge idempotente e recibo verificável.
2. Incorporar o modelo de proveniência: hashes, versões, unidades, fontes e dependências entre validadores. Manter métricas e alegações com seus métodos de medição.
3. Validar uma classe numérica pequena no executor existente, com referência conhecida, limites e resultado aceito; publicar e recuperar o artefato pelo backend real.
4. Depois dessa comprovação, desenvolver wallet com assinador isolado, valores inteiros na menor unidade, backup e estados de transação com reconciliação. Testar chain/token e Lightning localmente; token em devnet não equivale a stablecoin com lastro ou pagamento recebido.

A temperatura deve ser gerida automaticamente com carga, concorrência e retomada limitada. Nenhum dos materiais examinados prova que seja possível ignorar os limites físicos do computador. Métricas precisam registrar duração em ms/s, CPU em ms/s, memória em bytes/KiB e proveniência; energia e custo permanecem desconhecidos quando não medidos.

Esta triagem conclui a busca de referências pertinentes, mas **não conclui as três prioridades operacionais** em [PRIORIDADES_TRABALHO_PAGO.md](</media/bruno/SAMBOOK/Mycelium Network/research/PRIORIDADES_TRABALHO_PAGO.md>). Não houve execução real de tarefa, pagamento, crescimento ou reinvestimento automático nesta análise.
