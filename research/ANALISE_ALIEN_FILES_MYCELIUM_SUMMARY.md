# Análise de Alien Files – Mycelium

## Escopo
- 880 arquivos, 699 PDFs.
- 12 PDFs extraídos e lidos parcialmente.
- Nenhum script executado; apenas inspeção estática.

## Materiais mais úteis
| # | Documento | Uso recomendado |
|---|-----------|-----------------|
| 1 | **Protocolo_de_Malha_Unificado.pdf** | Base arquitetural: CRDT/DAG, recibos hash, permissões, transporte multimodal. Não contém implementação completa de Lightning ou pagamentos. |
| 2 | **ancient‑sky‑reconstruction** (repo) | Modelo de proveniência: hashes, versões, unidades, fontes. Adaptar para registrar evidências de tarefas locais. |
| 3 | **CQR.pdf** / **time‑travel‑simulation** | Classe de tarefa numérica pequena (qubits, Ising). Servir como caso de teste CQR a ser integrado ao executor. |
| 4 | **VOID COSMIC / VOID TOOLKIT** | Ideia de separação de interfaces (WASM + orquestração JS). Reusar apenas o conceito de interface, não o código incompleto. |
| 5 | **HGPU___vHGPU.pdf** | Cache e geometria SDF – baixa prioridade, sem implementação prática. |

## Componentes Mycelium já existentes que podem ser reaproveitados
- **GhostID** – identidade e assinatura Nostr.
- **PQC** – encapsulamento de chaves ML‑KEM.
- **Sporebank** – armazenamento de artefatos via DHT.
- **Isotope** – CRDT LWW para sharding de chave‑valor.
- **mycelium‑node/control.rs** – ponte autenticada ao backend.
- **cqr/adapter.rs & validation.rs** – validação de resultados numéricos (ainda incompletos).
- **base_usdc.rs** – leitura de recibos BOLT11 (não gera invoices).

## Prioridades locais (arquivo `PRIORIDADES_TRABALHO_PAGO.md`)
1. **Controle térmico** – bloqueio acima de 75 °C já implementado; falta integração com guardião S1‑MUPP real.
2. **Executar e validar tarefa CQR** – adaptar o adaptador CQR ao executor `mycelium‑next` e criar um teste com cálculo simples (ex.: Ising do CQR.pdf).
3. **Medição de resultados** – registro de duração, CPU/memória e proveniência já presente; energia e custo ainda não medidos.

## Estado atual (06‑10‑2026 14:38)
- Temperaturas de CPU entre 87 °C e 96 °C → execução bloqueada.
- Estado S1‑MUPP ausente (`/tmp/s1-mupp-state.json`).
- Backend Mycelium indisponível (conexão recusada).
- 30 testes unitários do protótipo `mycelium‑next` passaram; nenhum teste de tarefa produtiva concluído.

## Próximos passos recomendados
1. **Restaurar/gerar estado S1‑MUPP válido** para permitir que o executor ultrapasse o bloqueio térmico (ou ajustar temporariamente o limite para testes).
2. **Integrar o adaptador CQR** (`crates/mycelium‑economy/src/cqr`) ao executor de `mycelium‑next` e criar um caso de teste que execute um cálculo simples (ex.: simulação Ising do CQR.pdf) com entrada reproduzível e verificação de recibo.
3. **Instrumentar medição de energia** (ex.: `powermetrics` ou leitura de `/sys/class/powercap`) para preencher o campo “energia (J)” nas métricas de tarefa.
4. **Mapear especificações AMP/CFA** para APIs existentes (`GhostID`, `Isotope`, `Sporebank`). Documentar como os “receipts hashados”, “merge como redução de entropia” e “permissões verificáveis” serão implementados.
5. **Atualizar documentação** – incluir um resumo executivo (este arquivo) e instruções de como reproduzir a análise de Alien Files.

## Conclusão
A análise fornece referências arquiteturais (AMP/CFA) e modelos de proveniência que podem ser incorporados ao código existente. As três prioridades locais permanecem abertas; a ação mais urgente é restaurar o estado S1‑MUPP e validar uma tarefa CQR para avançar nas metas de execução e medição.
