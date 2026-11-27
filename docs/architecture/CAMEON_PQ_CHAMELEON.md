# Cameon: arquitetura e limites do experimento

Data-base: 2026-11-21

## CUPP — Cameon Universal Purchasing Power (P0.3, somente simulação)

Na proposta CUPP, o comprador escolhe pagar com Cameon e informa quantas
unidades deseja usar. A nota fiscal ou invoice define o valor e a moeda que o
vendedor deve receber; o desenho não exige que ele possua Cameon. Esse fluxo
está em simulação e ainda não efetua o pagamento.

O valor externo de Cameon não é definido por preço de mercado, mas isso NÃO
confere poder de compra ilimitado. A diferença entre qualquer valor recebido
pelo vendedor e o que o pagador aportou exige cobertura real da tesouraria,
subsídios, receita ou crédito contratado. ARQ não cria moedas fiduciárias.

### Arquivos e interfaces executadas

- crates/mycelium-pqcripto/src/payer_checkout.rs: PayerMandate assinado com
  ML-DSA-87 inclui ID e compromissos do recebedor/invoice, saldo máximo a
  debitar em Cameon, moeda/rail, preço exato, tributos inclusos, adicionais,
  taxas e validade. Assinatura demonstra INTENÇÃO, não saldo nem titularidade.
- PreparedPayerCheckout nunca marca operação como liquidada.
- crates/mycelium-pqcripto/src/coverage.rs: prepare_cupp_coverage()
  avalia matematicamente saldo Cameon REPORTADO, financiamento na MESMA
  moeda do vendedor e quantidade necessária a reservar. Exige duas fontes
  de observação independentes e registro com até 60 segundos.
- ArqRiskSignals: kill switches, slippage, limite de perda/risco e alerta de
  drift persistente (>30% por dois meses); o sinal NÃO é auditoria bancária.
- Operações propostas podem assumir 1 Cameon consumido com um pão de
  R$ 1,00 ou uma compra de US$ 25,00, mas cada compra tem sua despesa real
  própria e precisa de cobertura específica. Nenhuma reserva é realizada.

### Relação com o documento QVP-2/ARQ fornecido

O arquivo QVP-2/ARQ organiza camadas: DataOps point-in-time, fatores de
oferta/demanda/fluxo/tendência/risco, regime macro, scoring adaptativo,
execução com liquidez/custos, risco e kill switch. Seu score 0–100 é
RANKING relativo de criptoativos, não equivalência em USD/BRL e não
evidência de caixa. O módulo CUPP aproveita suas regras defensivas:
fonte múltipla e recente, limites de liquidez, custos de execução, risco
de cauda e interrupções. NÃO implementa HMM, scoring, histórico de preços,
backtesting ou otimização de carteira da ARQ; isso seria um projeto separado
de tesouraria com dados reais e governança de risco.

### PENDÊNCIAS CRÍTICAS — nenhuma resolvida por este P0.3

1. Adquirir e autenticar acesso de um PSP/banco com autorização para debitar
   saldo externo e confirmar liquidação da moeda do vendedor.
2. Implementar ledger Cameon com saldo verificado, consenso, reserva
   transacional, idempotência persistente e prevenção de gasto duplo.
3. Conectar tesouraria real com saldos segregados por moeda,
   reconciliação e reservas atômicas para pagamentos concorrentes.
4. Integrar verificação independente de dados de tesouraria, proveniência
   da liquidez, limite de exposição e aprovação explícita por comprador.
5. Aplicar impostos conforme a jurisdição/transação. Tributo incluso no
   preço é parte do valor ao vendedor e NÃO deve ser somado duas vezes;
   tributo adicional e tarifa vêm além do preço do vendedor se aplicáveis.
6. Somente então autorizar liquidação via instituição Pix, SWIFT ou BRICS
   conforme adaptador legítimo e confirmar os comprovantes externos.

Teste local offline: cargo test -p mycelium-pqcripto --offline --lib.
O resultado é PLANEJAMENTO/ADMISSÃO, não pagamento, lastro, lucro ou
conversão monetária.

## Histórico P0.2: preço contextual — SUPERADO pelo CUPP P0.3

Este desenho antigo de propostas assinadas por provedores está mantido
apenas para compatibilidade de laboratório. No CUPP a ordem parte do
COMPRADOR e a moeda/valor são definidos pela invoice do vendedor.


Cameon NÃO possui valor externo universal. O mesmo saldo nativo pode ter
preços expressos diferentes conforme o acordo de cada transação:
- uma loja pode aceitar 1 Cameon por uma mercadoria de 20 BRL;
- outro provedor pode aceitar 1 Cameon por 42,50 BRL;
- uma ordem distinta pode denominar a mesma quantidade em BTC ou EUR.

Esses valores não são somáveis, automaticamente conversíveis entre si ou
saldos efetivos de moeda externa. Cada valor é uma oferta contextual, cujo
signatário precisa ser conhecido e cuja liquidação precisa ser provada.
"Pode assumir qualquer valor" = valor contratual parametrizável; NÃO é
poder de compra infinito ou dinheiro efetivamente criado.

Implementação em crates/mycelium-pqcripto/src/chameleon.rs:
- DestinationKind e Destination: representação Cameon, fiduciária ou cripto,
  sempre com rede explícita para ativos cripto e precisão identificada.
- PaymentRail: Cameon, Pix (somente BRL), Swift, BricsDcms,
  CryptoNetwork. Isto é roteamento de instruções, não acesso às redes.
- ContextualQuote: preço variável por transação; ML-DSA-87 assina
  valor Cameon, valor de recebimento, moeda, rede, trilho, custos,
  compromisso do destinatário, provedor, invoice e janela temporal.
- PreparedInstruction: proposta validada cujo settled = false.
- Verificação exige chave pública do prestador obtida de fonte confiável.
- Não existe qualquer conversão ou movimentação de saldo aqui.
- A oferta não é escrow nem garantia de contraparte; o usuário não deve
  pagar até haver um mecanismo de liquidação atômica/reversão.

O antigo perfil valuation.rs 1 CAMEON = 8 USDC é apenas UMA forma
voluntária de cotar no comércio, não a paridade protocolar ou o valor da
unidade Cameon. Usar outros valores é permitido desde que explicitamente
propostos, aceitos e executados de verdade.

## Perfil comercial opcional: 1 CAMEON = 8 USDC (P0.1)

O crate mycelium-pqcripto define uma cotação interna imutável e verificável:
- CAMEON_MICROS = 1_000_000;
- TARGET_USDC_MICROS_PER_CAMEON = 8_000_000;
- TARGET_USDC_PER_CAMEON = 8;
- CameonPrice::for_cameon(...) calcula preços inteiros com overflow recusado;
- CameonPrice::for_usdc_target(...) calcula quantidade Cameon com
  arredondamento para cima.

MerchantAcceptance::issue(...) permite a um comerciante ADERIR VOLUNTARIAMENTE
ao preço e assinar uma oferta individual usando ML-DSA-87 (FIPS 204).
MerchantAcceptance::verify(...) exige chave pública previamente autenticada,
compromissos do pedido/comerciante, chain-id e validade de até 15 minutos.
Essa oferta é uma aceitação comercial; não transfere valores nem cria USDC.

ReportedReserveCoverage calcula a necessidade teórica de reservas:
  USDC_micros = CAMEON_micros * 8
e desconta a liquidez já comprometida. Os números reportados não são prova
de posse da reserva ou capacidade de resgate. É obrigatório um processo
independente de confirmação de reservas finais e operacionalmente disponíveis,
e contratos que autorizem a liquidação.

Para tornar "8 USDC" pagáveis FORA do Mycelium, cada pagamento deve:
1. obter proposta comercial executável para Cameon/USDC de formador de
   mercado, com preço e vencimento assinados;
2. verificar capacidade de entregar USDC e liquidez de destino;
3. permitir ao usuário aceitar valor/taxas e autorizar gasto real;
4. transferir Cameon com consenso e prova de não duplo gasto;
5. realizar conversão pelo provedor com confirmação irreversível;
6. pagar via PSP Pix, instituição SWIFT ou participante BRICS/PSP;
7. emitir recibo somente com confirmação de liquidação externa.

Os componentes 1-7 acima NÃO estão operacionais; o ativo ainda não tem
paridade de mercado. A implementação P0.1 faz apenas:
política de preço, aceitação assinada, cálculo de cobertura reportada.

A política de 8 USDC NÃO deriva do preço legado de MYC; Cameon é novo
ativo, com suprimento, custódia e registro próprios a desenhar.

Estado: proposta de arquitetura + núcleo experimental P0
Nome: Cameon. Ticker a definir; NÃO converter automaticamente o ativo legado MYC
em Cameon sem plano explícito de migração, reconciliação e consentimento.

## 1. Missão e limites

Cameon é proposto como um ativo nativo soberano, com pagamentos privados
entre participantes e gateways de saída para moedas reais e redes financeiras.

"Camaleão" significa:
- mudar endereço/chave de sessão entre transações;
- selecionar transporte VEIL/MIX segundo requisitos mensuráveis;
- codificar uma ordem de pagamento num formato exigido pelo trilho de destino;
- manter privacidade minimizando dados coletados e separando identidades por contexto.

NÃO significa:
- 100% de anonimato demonstrado em todas as condições;
- assumir silenciosamente a identidade de outra moeda ou instituição;
- transformar bytes de Cameon em dólares, reais ou liquidez;
- dispensar requisitos de identificação em instituição financeira;
- criar valor ou rendimento automaticamente a partir da emissão.

MODELO DE PRIVACIDADE
- Privado nativo: objetivo de ocultar remetente, recebedor, valor e grafo de
  transações da audiência pública, com notas criptográficas blindadas.
- Venda interna: comerciante enxerga os dados necessários para entregar o
  produto; a rede não deve divulgar desnecessariamente esses dados.
- Saída fiduciária: PSP/banco e destinatário conhecem as informações que o
  trilho exige; VEIL só pode reduzir vazamento na rede de transporte.
- Ataques considerados: análise global de tráfego, correlação temporal,
  nós Sybil, controle de relay/exit, registros do provedor de câmbio, replay,
  gastos duplos, falhas de chave e adversário quântico futuro.
- Metadados temporais, tráfego e vinculação por serviços externos devem
  ser auditados antes de qualquer declaração comercial de anonimato.

## 2. Crates e responsabilidade técnica

Cameon Core (novo):
- mycelium-pqcripto: envelopes privados, ML-DSA efêmero, política de
  transporte e interface de transações que falha fechada.
- mycelium-pqc: ML-KEM-1024; verificar vetores e implementações FIPS.
- mycelium-zkp: hoje tem Pedersen/Bulletproofs sobre curvas elípticas;
  isso NÃO é prova de saldo pós-quântica. Criar provador/verificador
  apropriado (ex.: sistema baseado em hashes/STARK com avaliação formal).
- mycelium-keyring: domínios separados para endereço por pagamento,
  material KEM/assinatura e recuperação em 24 palavras. Não compartilhar
  seed de outro ativo sem mapeamento formal e auditoria.
- mycelium-ghostid: identidades efêmeras para mensageria; não é prova
  de propriedade dos valores.

Consenso, armazenamento e mensagens:
- mycelium-mint: reaproveitar a lógica de limites de emissão e PoUW;
  NÃO usar uma declaração local de trabalho como prova de dinheiro,
  consenso ou valorização. Cameon exige registro global de nullifiers,
  conservação de valor e estado de emissão próprio.
- mycelium-nutrients: vouchers de serviço; separados de moeda liquidada.
- mycelium-sporebank, giggs, mycelium-ipfs, mycelium-qel: somente
  blobs cifrados, compromissos e estado público estritamente necessário.
- mycelium-sclerotium: durabilidade de estado criptográfico com controle
  de rollback, sem armazenar valores e destinatários em texto claro.
- mycelium-hyphae, mycelium-nostr, mycelium-distancebridge: malha
  de transporte/desbravamento. Roteamento não equivale a anonimato.

Pagamento, privacidade, custódia e economia:
- mycelium-veil: LIVE e MIX, kill-switch sem fallback direto; verificar
  circuitos e camadas em tráfego de produção. Atualmente as sete camadas
  do LayerPipeline são declaradas NÃO ligadas ao caminho real.
- mycelium-pay: SDK de checkout, consentimento e recibo assinado.
  Seu perfil híbrido existente inclui ECDH clássico; o Cameon exige
  perfil PQ-only antes de afirmar criptografia inteiramente PQ.
- mycelium-bank: carteira e registro financeiro com reconciliação.
  Seu ledger atual é local-first; não substitui consenso global. O fluxo
  NFC antigo marca settled após validar assinatura, sem creditar o ledger:
  bloquear esse caminho em produção até haver transferência atômica.
- mycelium-economy: tarifas de serviços, mercado, demanda e orçamentos.
- mycelium-meta-gateway: mensagens Pix/BRICS/SWIFT e rotas de PSP,
  isoladas das regras de titularidade de Cameon.
- mycelium-root: recuperação de segredos offline e custódia pessoal.

## 3. Pipeline interno Cameon

Pedido comercial -> Mycelium-Pay confirma preço e beneficiário ->
carteira cria endereço de recebimento descartável ->
geração de nota blindada e provas PQ verificáveis ->
controle de conservação de valor / nullifiers únicos por consenso ->
transporte VEIL/MIX sem fallback direto ->
finalidade no consenso e atualização no Mycelium-Bank ->
recibo para comerciante, com mínimos dados necessários.

A fase atual NÃO implementa a linha inteira: somente envelope criptográfico,
autenticação efêmera de sessão e seleção de política de rota.
A função require_verified_shielded_spend() devolve erro de propósito.

BLOQUEADORES CRIPTOGRÁFICOS:
- prova pós-quântica verificável de saldo/soma das entradas e saídas;
- proof of membership/ownership que não revele qual nota foi consumida;
- nullifier não vinculável mas globalmente exclusivo;
- parâmetros de segurança, test vectors, reversões, fees, range proofs;
- robustez frente a adversários quantum e vazamentos de metadados;
- modelo de consenso e finalidade que não dependa de um nó privado.

## 4. Caminho externo e o Meta-Gateway

Mycelium-Pay -> cotação no Meta-Gateway ->
transação real de Cameon com finalidade ->
contraparte autorizada fornece liquidez / converte Cameon ->
PSP ou prestador autorizado recebe a moeda necessária ->
Pix, SWIFT ou participante DCMS encaminha e confirma ->
recibo final com reconciliação e auditoria.

FSM proposta:
DRAFT -> QUOTED -> USER_AUTHORIZED -> FUNDS_RESERVED ->
ONRAMP_OFFRAMP_ACCEPTED -> EXTERNAL_SUBMITTED ->
EXTERNAL_CONFIRMED -> SETTLED.
Em falha: CANCELED, FAILED, REFUND_PENDING, REFUNDED.
Nenhuma transição para SETTLED pode resultar apenas de criação de
mensagem, assinatura, prova KEM, evento de webhook não autenticado
ou referência de mercado fornecida pelo próprio usuário.

A referência anterior "1 MYC = 8 USDC" não se aplica
automaticamente a Cameon. Caso deseje preço-alvo de 8 USDC por Cameon,
será apenas uma política indicativa até que um formador de mercado
ou instituição ofereça cotação executável com liquidez comprovada.
Não converter por multiplicação 8 sem contraparte. Se houver promessa
de resgate, verificar reservas e obrigações reais, inclusive risco
de contraparte, câmbio, custos, pagamentos pendentes e auditoria.

TRILHOS:
- PIX: ler QR/BR Code, validar campos, txid, CRC, cobrança JSON,
  callbacks e regras de início. Integração real somente via PSP
  participante/contrato; não equivale ao acesso direto ao SPI/DICT.
- BRICS DCMS: configurar nós, chaves, acordos bilaterais, limites por
  moeda, intenções e roteamento; não executar pagamentos em rede real
  sem contraparte/permissão e capacidade de liquidação.
- SWIFT: priorizar ISO 20022 CBPR+ e FINplus, endereço estruturado/
  híbrido em 2026, BIC/campos exigidos, regras CSP/CSCF e
  instituição autorizada. Não depender de MT103 antigo como base única.

A criação de implementações independentes conforme documentos públicos
não fornece código-fonte, acesso à rede ou credenciais de terceiros.

## 5. Política de auto-investimento

Cameon Mint = emissão controlada e validação de trabalho/consenso.
Mint NÃO é um fundo, corretora nem fonte automática de rendimentos.

Uma estratégia de investimento deve ser módulo independente do Bank,
com consentimento granular, limites por ativo, proteção de fundos de
clientes, relatório de risco, saques e desativação fácil.
Nunca aplicar investimento automático ao saldo livre sem autorização
explícita. Nunca registrar rendimento estimado como saldo liquidado.
Uma reserva prometida para resgate imediato não pode ser arriscada
sem contabilizar redução da liquidez/risco de perdas.

## 6. Fonte documental e implementações permitidas

Documentos fornecidos na conversa:
1) II_ManualdePadroesparaIniciacaodoPix.pdf — páginas 12–16:
   QR estático, txid, CRC16, QR dinâmico e payload JSON.
2) BRICS-Pay-Strategic-Vision-en.pdf — páginas 5–7:
   gateways nacionais, parceiros, diagramas e redes DCMS.
3) CSP_decision_tree_v2022_v1.1_20220615.pdf — páginas 1–4:
   arquitetura SWIFT, interface de comunicações e ownership.
4) stdsmx_rcmdn_impl_iso_20022_msg_best_prac.pdf — páginas 3–5:
   escolha de versão, autorização de participantes e validação.

Referências externas complementares:
- BCB, API Pix: https://github.com/bacen/pix-api
- BCB, normas: https://www.bcb.gov.br/estabilidadefinanceira/pix-normas
- DCMS User Manual: https://docs.brics-pay.com/BRICS_DCMS_User_manual.pdf
- SWIFT, CBPR+ 2026:
  https://www.swift.com/standards/iso-20022/iso-20022-financial-institutions-focus-payments-instructions
- BCB, Resolução nº 520 (prestadores de serviços de ativos virtuais):
  https://www.bcb.gov.br/estabilidadefinanceira/exibenormativo?numero=520&tipo=Resolu%C3%A7%C3%A3o+BCB

Manuais e visão estratégica não equivalem à especificação completa de
conectividade, autorização de rede, governança ou acesso a ambientes
financeiros de produção.

## 7. Critérios de aprovação, por ordem

P0 (entregue parcialmente, exclusivamente laboratório):
- envelope ML-KEM + XChaCha20 de tamanho fixo com testes de adulteração;
- prova efêmera ML-DSA de sessão, sem afirmar ser autorizacão de gasto;
- política VEIL/MIX sem fallback direto, e gasto explicitamente bloqueado.
- Nenhuma chave nem valor informado em logs públicos.

P1 (não entregue): formato canônico Cameon, assinaturas PQ de autorização,
provas de conservação, nullifier/UTXO blindado, teste de gasto duplo,
reorganização e recuperações sob múltiplos nós independentes.

P2 (não entregue): LIVE/MIX integrado de ponta a ponta, medição de
correlação entre IP/endereço/tempo/destinatário, ataques de replay,
testes de stress, randomização de horários/padding.

P3 (não entregue): SDK merchant Cameon sobre mycelium-pay, checkout
blindado, recibos e mycelium-bank sincronizado com consenso real.

P4 (não entregue): emuladores Pix/BRICS/SWIFT a partir das especificações,
com vetores; conectores regulados com PSPs e câmbio autorizado,
reservas verificáveis, idempotência, cancelamento e estorno.

P5 (não entregue): exame independente de segurança, modelagem de
adversários, auditoria de oferta/reserva/risco, pentests, conformidade
local e pilotos pequenos com provedores licenciados.

Não usar "primeira" ou "totalmente anônima" como afirmação pública sem
pesquisa de anterioridade e auditorias em redes reais.
