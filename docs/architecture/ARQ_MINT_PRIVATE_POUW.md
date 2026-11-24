# ARQ-Mint — perfil QVP-2/ARQ para emissão PoUW

Data-base: 2026-11-21. Estado: P0 experimental, testado localmente.
Escopo: crates/mycelium-mint/src/arq.rs e src/engine.rs.

## Princípio

O QVP-2/ARQ fornecido pelo autor é um modelo adaptativo de avaliação
de criptoativos e risco. Adaptamos somente mecanismos defensivos à
emissão PoUW. O score de mercado original NÃO é uma cotação de Cameon,
nem gera moeda fiduciária, crédito, liquidez ou valorização.

Prioridades: privacidade no protocolo de emissão, dados agregados,
múltiplos validadores, sem cadastro civil exigido pelo ARQ, anti-replay,
emissão limitada e verificável por consenso.

## Correspondência das seis camadas

| Camada QVP-2/ARQ | Adaptação ARQ-Mint | Estado |
|---|---|---|
| 0. DataOps | WorkClaim verificado e proteção contra replay no lote; sem API de preços ou ID civil | Parcial; fontes independentes e resistência Sybil ainda insuficientes |
| 1. O/D/F/T/R | Contagem agregada de trabalho, diversidade e concentração | Parcial; não há demanda econômica, fluxo financeiro nem regressão ortogonal |
| 2. Regime | Healthy, Stressed, Halted por agregados da época | Implementado; não é o HMM macro do documento |
| 3. Score | Health score 10000/2500/0 bps por regime | Simplificado; não há atualização bayesiana nem rank IC |
| 4. Execução | Cap de emissão por época e por produtor existente, ARQ reduz limite | Implementado parcialmente; não calcula slippage |
| 5. Risco | Bloqueio sem trabalho, redução em concentração e falta de diversidade | Parcial; eventos externos e risco de mercado não entram no consenso |

## Regras matemáticas e política inicial

ArqMintPolicy::default:
- Healthy exige 2 categorias de PoUW, 2 produtores pseudônimos,
  concentração máxima de 80% no maior produtor; orçamento até 100%.
- Stressed: há trabalho, mas há concentração ou diversidade
  insuficiente; orçamento até 25%.
- Halted: lote sem trabalho, orçamento zero.

orçamento_ARQ = piso(orçamento_monetário * multiplicador_bps / 10000)

A política original de emissão máxima, halving, replay e cap por nó
permanece. O ARQ só reduz o orçamento; nunca o aumenta.
Percentuais são escolhas de laboratório; não foram obtidos de backtest.

## Ativação e quórum

Nova rede ARQ deve usar MainnetMintEngine::genesis_arq() e
ArqMintPolicy::default() ou uma política validada específica.
O hash de gênese inclui hashes da política monetária inteira e da
política ARQ. Cada lote usa engine.compute_arq_batch_root(&claims),
cuja saída incorpora:
- hash do lote PoUW original;
- hash da política monetária original (suprimento, halving, pesos etc.);
- hash da política ARQ de governança;
- decisão determinística e orçamento calculado.

Validadores verificam claims e assinam esse ARQ root com
SporocarpAttestation::sign(). A emissão ocorre exclusivamente com
engine.settle_epoch_arq(&claims, &attestations).

Assinaturas de lote legado não podem ativar uma época ARQ.
O método antigo settle_epoch rejeita uso quando a política ARQ
estiver fixada na gênese. O caminho legado permanece compatível.
Não ativamos esse perfil na mainnet existente nem migramos MYC/Cameon.

## Privacidade concreta e o que ainda não está feito

A saída ArqMintDecision contém apenas contagens e valores agregados;
não inclui dados civis, destinatários bancários ou notas de compra.

Mas a estrutura WorkClaim ainda inclui IDs pseudônimos do produtor
e da contraparte, identificadores do trabalho e assinaturas Ed25519.
MintReceipt ainda divulga beneficiário e quantia e carrega o blinding
Pedersen. Isso NÃO é anonimato criptográfico de ponta a ponta.

Os validadores atuais pertencem a um HashMap conhecido em gênese.
O sistema tem quórum distribuído, mas não rede permissionless pronta.
IDs diferentes podem pertencer à mesma pessoa: concentração por
NodeId não é prova de resistência Sybil. Claims assinados também
podem conter quantidade de trabalho exagerada por duas partes em
conluio; é preciso prova verificável de execução real.

Para privacidade e anonimato fortes ainda são necessários:
- commitments de saldo e gasto sem expor valores ou vínculo de
  entrada/saída;
- ZKP de autorização e conservação, nullifiers não correlacionáveis;
- autenticação e provas pós-quânticas auditadas;
- consenso de rede resistente a Sybil, sem conjunto fixo de confiança;
- mitigação contra correlação temporal de rede e tráfego VEIL/MIX.

Sem fontes de dinheiro externo, a emissão PoUW não banca pagamentos
em BRL, USD ou outra moeda, mesmo que Cameon seja uma unidade
universal de autorização de compras.

## Próximas fases

P1: prova de trabalho útil realmente verificável, sem contadores
infláveis por conluio.
P2: DataOps com agregados point-in-time e validação por múltiplos nós.
P3: sinais O/D/F/T/R economicamente verificáveis e estimativa de regime
com dados determinísticos, comprometidos na crônica de consenso.
P4: testnet de consenso aberto + spend shielded pós-quântico.
P5: motor de tesouraria QVP-2/ARQ separado do consenso, com fonte
de liquidez real e validação walk-forward, para financiar CUPP.

Verificação:
  cargo test -p mycelium-mint --offline --lib
  cargo clippy -p mycelium-mint --offline --no-deps -- -D warnings
