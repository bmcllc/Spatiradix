# Mycelium Habitat × MYC × VEIL — H2

Data: 2026-11-21. Integração local, sem commit nem push.

## Transporte privado verificado

Novo módulo: crates/mycelium-meta-gateway/src/veil_egress.rs

O VeilEgress recebe um SOCKS5 loopback e abre uma conexão TCP ao domínio
público, porta 443, usando ATYP=03 (DNS remoto). Não resolve o endereço
do destinatário na máquina local, não usa proxy remoto não confiável,
não aceita IP literal ou nomes reservados e NÃO FAZ FALLBACK DIRETO.
O tempo máximo do handshake é 5 segundos.

O control socket do daemon expõe GatewayVeilProbe, disponível apenas
com --features veil e com o serviço VEIL ativado. A CLI:

    mycelium gateway veil-probe --host psp.exemplo-bancario.com

O retorno positivo indica SOMENTE sucesso de SOCKS CONNECT.
TLS/mTLS, identidade do PSP/banco, anonimato, execução e liquidação
financeira NÃO foram demonstrados. Os adaptadores Pix/SWIFT/BRICS
continuam criando mensagens preparadas, sem transmissão real.

## Medição observada de serviços

O Event Horizon mantém o contador existente de requisições tentadas
para scaling do Plasma. A camada adicionada separadamente registra
as respostas 2xx cujo corpo foi lido integralmente do upstream.
Resposta 500, erro de upstream e corpo incompleto não entram nesse
contador. Isso NÃO garante que o cliente tenha recebido tudo.

O daemon agrega dados por nome de Ion em memória, sem identificação
de pagador, e consulta os contadores atuais sem interromper o scaling.
A consulta requer manifesto Habitat local com nome correspondente.

Com manifesto registrado e Ion de mesmo nome acessível por /ion/...:

    mycelium habitat usage nome-do-ion
    mycelium habitat usage nome-do-ion --estimate-myc-micros-per-response 10000

A estimativa opcional de 10000 micros significa 0,010000 MYC por
resposta. A referência contábil é 1 MYC = 8 USDC, mas o preço é
fornecido pelo operador, não negociado com um pagador. NÃO há
cobrança, voucher, receita, saldo ou direito de resgate.

Limitações: vínculo por nome não autentica a aplicação executora;
somente HTTP do proxy de Ion é observado; não conta /site/,
acesso direto, GPU ou tráfego P2P. A telemetria se perde no
reinício; os contadores não constituem prova independente de
serviço entregue.

## Verificação feita

- Meta-Gateway, all-features: 26/26 testes aprovados.
- Meta-Gateway, no-default-features: 17/17 testes aprovados.
- Singularity, habitat_delivery: 1/1 teste HTTP em loopback.
- cargo check de mycelium-node e mycelium-cli: aprovado.
- cargo check de mycelium-node com a feature veil: aprovado.
- Nenhuma integração com banco/PSP externo foi testada.

## Próximos gates

1. Autenticar a ligação manifesto Habitat -> Ion e executor.
2. Vincular preço MYC a proposta assinada e aceite por consumidor.
3. Prova de entrega independente e prevenção de replay.
4. Persistência cifrada de medições, sem dados pessoais desnecessários.
5. TLS/mTLS e verificação de PSP sobre o SOCKS5 para operações reais,
   com política anti-SSRF e testes de vazamento entre dois hosts.
6. Só reconhecer receita após lançamento real do ledger, nunca por
   declaração unilateral ou referência econômica de 8 USDC.

Política de emissão e o restante dos crates foram preservados.
