# Spatiradix — transição do laboratório para P2P Mainnet

**Data:** 10 de novembro de 2026  
**Escopo desta transição:** Mycelium P2P Mainnet, não uma blockchain própria.  
**Estado:** plano de lançamento; nenhuma seed foi publicada, porta aberta ou transação enviada durante esta auditoria.

## 1. Decisão de terminologia

Na auditoria de 10 de novembro de 2026, não foi encontrado no workspace um
perfil formal chamado testnet, devnet ou localnet, nem uma opção `--testnet`.
As referências a Testnet no código examinado pertenciam ao parser de invoices
BOLT11/Lightning. As referências relevantes a mainnet tratavam do catálogo
público de seeds e dos scripts de bootstrap.

Logo, o estado atual é melhor descrito como **workspace e harness local de desenvolvimento, com recursos de rede implementados, mas sem mainnet P2P operacional comprovada**. A transição não é uma troca de flag: é uma sequência de gates de identidade, configuração, bootstrap, conectividade real, segurança e operação.

### Três coisas que não devem ser confundidas

1. **P2P Mainnet:** rede de produção de nós Mycelium, com descoberta, QUIC/TCP, Kademlia, Gossipsub, relay, armazenamento e protocolos compatíveis.
2. **MYC interno:** créditos/ledger privado. Não é token on-chain nem moeda com consenso distribuído.
3. **Blockchain Mainnet:** cadeia própria com genesis, blocos, mempool, consenso Sybil-resistant, validadores, finality/fork-choice, regras de emissão e clientes independentes. Esse motor não foi encontrado no workspace atual.

Este plano assume o item 1. Ele **não** declara ou cria uma blockchain própria. Uma futura mainnet monetária exige projeto, ameaça, protocolo e auditoria separados.

## 2. Evidência observada na auditoria

### Rede P2P existente

O workspace já contém mycelium-hyphae baseado em libp2p, com TCP/QUIC, Noise/Yamux, Kademlia, Gossipsub, mDNS e relay. mycelium-node integra o daemon persistente, socket de controle e Event Horizon. mycelium-sporebank oferece armazenamento content-addressed; o catálogo de seeds tem merge e health-check.

### Bloqueios de lançamento

- seeds/mainnet.txt declara **zero entradas ativas**. O endereço histórico está comentado porque inbound TCP falhou em julho de 2026.
- docs/VALIDACAO.md classifica o nível local de compilação/testes como sustentado, mas multi-host real, terceiro independente e deploy de produção continuam não sustentados; E6 permanece 0/9 na evidência consultada.
- docs/network/prova-2-maquinas.md diz que os dois papéis foram ensaiados na mesma máquina em 21/10/2026; a prova com duas máquinas físicas distintas ainda precisa ser executada.
- deploy/ contém templates; não representa implantação de produção. O binário Android em dist/ é identificado nos docs como antigo.
- mycelium-hyphae/src/seeds.rs define um catálogo HTTP público padrão no GitHub. Isso é um ponto de descoberta centralizado/substituível e deve ser uma opção explicitamente documentada, não uma autoridade de rede.
- A rede residencial anteriormente medida está atrás de CGNAT/firewall e não conseguiu inbound. Não assumir que o TushiBook pode ser seed público sem uma nova prova externa.

### Não é uma blockchain própria

- mycelium-bank contém contas, ordens, pagamentos e ledger local bank-ledger.jsonl com hash BLAKE3. Seu adaptador NullTransport não conecta peers.
- mycelium-economy tem ledgers locais e verificação de liquidação Base/USDC (chain ID 8453); isso é integração a uma blockchain externa, não produção de blocos Mycelium.
- mycelium-veil::ConsensusLayer implementa ordenação causal/anti-replay com timestamp, sequência e hash; não é consenso de blocos, eleição de validadores ou finalização de transações.
- Não foram encontrados símbolos implementados de mempool, block producer, block header, validator set ou fork choice no scan de fontes e documentação efetuado.

## 3. O que muda em relação à decisão de rede privada de um computador

Uma P2P Mainnet pública substitui a decisão anterior de “rede privada somente minha, um computador”. São objetivos incompatíveis no nível de topologia:
- um computador pode operar um nó local de produção, mas não prova uma rede P2P pública;
- mainnet pública requer peers físicos independentes, pelo menos um peer alcançável para bootstrap inicial e teste a partir de outra rede;
- o proprietário pode continuar controlando a governança e suas próprias chaves, mas peers externos passam a participar do transporte e armazenamento.

Se a intenção final continuar sendo rede privada e exclusiva do proprietário, o nome correto é **private production network**, não uma mainnet pública. Neste plano, o alvo é explicitamente P2P Mainnet pública porque é o significado de seeds/mainnet.txt e dos runbooks existentes.

## 4. Arquitetura-alvo de P2P Mainnet v1

    mycelium-cli / client
           |
    Network Profile (mainnet)
           |
    Identity + protocol compatibility
           |
    SeedBook / discovery
           |
    libp2p Swarm
      | TCP/QUIC
      | Kademlia DHT
      | Gossipsub
      | Relay Circuit v2 / hole punching
           |
    Peers independentes
           |
    SporeBank / Plot / ContentId / pinning
           |
    Receipts / audit / observability

### Separação test/lab e produção

Antes de chamar uma rede de mainnet, introduzir um perfil de rede explícito, versionado e validado. O perfil deve definir:
- network name e network ID fixo;
- protocolo mínimo/máximo e capabilities aceitas;
- namespace/tag de tópicos Gossipsub e chaves DHT;
- política de bootstrap e de confiança de seeds;
- política de conteúdo público/privado e de pinning;
- limites de mensagens, conexões, armazenamento e tráfego;
- regras de atualização e compatibilidade.

O perfil de produção deve falhar fechado em valores ausentes ou conflitantes. Não basta renomear um arquivo testnet para mainnet. Não reutilizar IDs/chaves de fixtures de teste como identidade de seed de produção. Test fixtures e endereços de teste nunca devem entrar no catálogo público.

Não fixar um endereço IP ou PeerId antes de uma prova real de reachability. Catálogo público deve conter somente seeds cuja identidade e inbound foram verificados pelo procedimento existente.

### Bootstrapping

- Manter mais de uma fonte de descoberta substituível: arquivo local, catálogo HTTP assinado ou autenticado, DNS TXT quando configurado e peers já conhecidos.
- O seed de bootstrap não deve ganhar autoridade sobre conteúdo, saldo, identidade ou política de clientes.
- A rede não pode aceitar uma seed apenas porque ela aparece em um arquivo; validar Multiaddr, PeerId, assinatura/identidade e health.
- Para Mainnet v1, começar com um seed publicamente alcançável e pelo menos um segundo peer independente para teste. Antes de anunciar resiliência, adicionar uma segunda seed independente.
- Remover dependências obrigatórias de IP/URL fixos em etapas futuras; não declarar bootstrap totalmente descentralizado enquanto o primeiro encontro depender de um único catálogo.

### O que não ativar por padrão

- Não publicar conteúdos privados do SporeBank, diretórios pessoais ou metadados sensíveis.
- Não expor Event Horizon (:7474) à Internet apenas para fazer a rede funcionar.
- Não habilitar relay server ou --assume-reachable sem inbound provado.
- Não transformar tráfego de controle, gossip, heartbeat ou replicação sem demanda em recompensa econômica.
- Não ativar carteira, emissão pública, market-making, staking ou pagamento automático.

## 5. Gates técnicos de lançamento

### M0 — Congelar o alvo e preservar o workspace

- Confirmar que o alvo é P2P Mainnet pública.
- Definir network ID, protocol version, tópicos e DHT namespaces em RFC separado.
- Guardar baseline do Git e preservar todos os diffs existentes.
- Não rebase, reset, clean, stash ou commit automático.
- Segredos, gland.seed, vault, wallets e credenciais não entram em relatório nem Git.

**Aceite:** escopo, threat model e compatibilidade de rede documentados; working tree preexistente intacto.

### M1 — Perfil de produção e isolamento

- Implementar mainnet como perfil explícito e separado das fixtures locais.
- Fazer testes de incompatibilidade: nó de teste não deve entrar na rede de produção por acidente.
- Usar identidade de produção nova, criada e mantida no host do proprietário.
- Separar diretórios de estado, catálogos, logs e ledger entre laboratório e produção.
- Definir política para atualizações incompatíveis e rollback de binário (não de estado sem migração).

**Aceite:** nenhum fixture/test peer é aceito; o perfil reporta exatamente sua rede, versão e PeerId.

### M2 — Seed com inbound comprovado

- Identificar um peer voluntário/segundo dispositivo que possa operar como seed.
- Iniciar daemon em portas definidas apenas após revisar firewall, bind e anúncio de endereços.
- Rodar scripts/verify-sporocarp.sh a partir de uma rede externa, como 4G/5G ou outra conexão independente.
- Conferir TCP e UDP conforme transports habilitados; registrar PeerId e multiaddrs realmente alcançáveis.
- Somente após sucesso executar export do seed para catálogo de produção.
- Nunca usar o antigo IP comentado como seed funcional.

**Aceite:** prova externa atual, identificável e reproduzível; o seed não é declarado vivo por configuração ou IPv6 isolado.

### M3 — Duas máquinas físicas e redes independentes

Executar scripts/prova-2-maquinas.sh com duas máquinas físicas diferentes ou adaptar o teste para o harness equivalente:
- A e B devem ter fingerprints de máquina distintos.
- A rede de B deve ser diferente da rede de A.
- B começa sem vizinhos, conecta pelo bootstrap e comprova peer autenticado.
- Publicar um Plot público de teste em A e recuperar em B verificando ContentId e hash.
- Desligar A; confirmar se B ainda consegue servir o conteúdo quando houver réplica válida.
- Reiniciar ambos; conferir persistência de identidade, seed book e recuperação.
- Capturar logs, horário UTC, versões, PeerIds e resultados; remover IPs privados/segredos de relatórios públicos.

**Aceite:** vizinho real em cada lado, transferência cross-host, reinício e teste de sobrevivência reproduzíveis. Dois processos na mesma máquina não fecham este gate.

### M4 — Malha, armazenamento e recuperação

- Testar Kademlia DHT e Gossipsub entre hosts.
- Reproduzir pinning e prova de posse; desired/verified/available não podem ser confundidos.
- Validar anti-entropy e replicação com o publicador offline.
- Testar perda de seed/relay e reconexão por outra rota.
- Confirmar GC/quota sem remover objetos ainda pinados.
- Testar CGNAT usando transports realmente disponíveis; simulador de LAN não comprova NAT traversal de ISP.
- Testar conteúdo privado: não pode ser absorvido, anunciado ou entregue em claro.

**Aceite:** critérios de sobrevivência/replicação medidos, quotas e privacidade verificadas.

### M5 — Segurança e governança operacional

- Revisar autenticação de anúncios, heartbeats, migrações, tarefas e recibos com vínculo entre chave pública e PeerId.
- Revisar rate limiting, quotas por peer, tamanho de mensagens, timeouts, DoS, Sybil e abuso de relay/storage.
- Executar fuzz/property tests nos parsers de Multiaddr, manifesto, gossip e protocolo de controle.
- Confirmar que código de terceiros não é executado sem sandbox e limites reais de recursos.
- Fazer secret scan e revisão de supply chain antes de release.
- Documentar revogação/rotação de seed, identidade e chaves de assinatura.
- Revisar licença e atribuição dos componentes; preservar AGPL-3.0 e notices aplicáveis.

**Aceite:** relatório de ameaça e testes adversariais; falhas críticas corrigidas; nenhuma chave ou credencial em artifacts.

### M6 — Release e observabilidade

- Criar artefatos de release reproduzíveis para Linux x86_64 primeiro.
- Gerar SHA-256/BLAKE3, SBOM, versão de protocolo, changelog e instruções de atualização.
- Assinar manifestos de release com chave de release separada da identidade diária do nó.
- Medir uptime, latência p50/p95, reconexão, falhas de gossip, peers únicos, réplica e uso de disco.
- Configurar backup e recuperação de estado; confirmar restauração em diretório limpo.
- Usar os templates deploy/prometheus depois de revisão; a existência do template não conta como deploy.
- Publicar changelog de Mainnet v1 somente após os gates M0–M6.

**Aceite:** binário identificado e verificável, telemetria por janela sustentada, recuperação testada e operador capaz de pausar/atualizar.

### M7 — Economia e MYC

P2P Mainnet não implica token mainnet. Para a primeira versão:
- preservar mycelium-nutrients como recurso/contabilidade de nutrientes;
- manter MYC como crédito interno separado, se o módulo privado for implementado;
- preservar mycelium-economy e as invariantes de RV/NEV;
- não considerar emissão MYC, tráfego de teste ou trabalho do próprio operador receita externa;
- não ativar negociação, transferência de valor público, custódia ou promessa de conversão.

Uma futura blockchain MYC exigirá RFC separada para:
1. genesis state e chain ID;
2. formato de bloco e transação canônica;
3. mempool e validação determinística;
4. consenso e modelo de adversário/Sybil;
5. validadores, finality, reorg e recuperação;
6. emissão, taxas, governança e migrações;
7. wallet, RPC, explorer, auditoria e segurança econômica;
8. testnet pública independente, ataque adversarial e auditoria antes de mainnet.

Não chamar a camada causal anti-replay do VEIL nem o ledger JSONL de mycelium-bank de consenso blockchain.

## 6. Primeiro lançamento recomendado

### P2P Mainnet v1 — escopo conservador

- Uma implementação Linux x86_64.
- Um operador de release e chaves sob controle do proprietário.
- Um seed com reachability externa comprovada e um segundo peer físico independente.
- TCP/QUIC e descoberta libp2p já implementados; habilitar somente transports efetivamente testados.
- Apenas compartilhamento de Plots explicitamente públicos.
- Sem token público, sem liquidação on-chain própria, sem marketplace aberto de terceiros e sem SLA 24/7.
- Catálogo público pode servir como bootstrap, mas deve ser tratado como mecanismo substituível, não fonte de autoridade.

### Métricas mínimas de lançamento

- 2 máquinas e 2 redes fisicamente distintas;
- PeerIds autenticados e neighbor_ids reais;
- 1 publicação/recuperação cross-host;
- 1 teste do origin offline com réplica verificada;
- 1 restart em cada host;
- nenhuma publicação de conteúdo privado;
- nenhuma chave ou dado pessoal vazado;
- logs e relatório versionados, sem segredos.

Para declarar uma malha resiliente e descentralizada, exigir 3 ou mais operadores/hosts e pelo menos duas fontes independentes de bootstrap/relay. O MVP de dois hosts é uma prova de conectividade, não alta disponibilidade.

## 7. Sequência concreta de execução

1. **Confirmar o alvo:** P2P Mainnet pública. Se a intenção for continuar exclusivamente privado, parar aqui e usar o perfil private production, não catálogo público.
2. **M0:** registrar baseline Git e revisar network profile/protocol IDs sem editar o working tree existente.
3. **M1:** implementar isolamento test/prod em alteração pequena e com testes de regressão.
4. **M2:** conseguir um segundo host/rede voluntário e provar inbound. Sem isso, não existe seed pública verificável; não simular.
5. **M3:** executar prova de dois hosts.
6. **M4–M5:** testar storage, failover, CGNAT, privacidade e segurança.
7. **M6:** produzir release assinada e monitorada.
8. **M7:** manter a economia separada; só projetar blockchain própria depois de uma decisão específica.

## 8. Itens explicitamente não autorizados por este plano

- Não adicionar, descomentar ou publicar IP/PeerId na lista de seeds sem prova.
- Não alterar o roteador, firewall ou CGNAT automaticamente.
- Não abrir Event Horizon na Internet.
- Não expor a API local do Laya/n8n.
- Não criar wallet, assinar ou broadcastar transação.
- Não modificar saldos, emitir MYC público ou migrar ledgers.
- Não apagar histórico, logs, chaves, vault ou catálogo.
- Não resetar, limpar, reformatar, fazer stash ou commit de alterações preexistentes.
- Não anunciar mainnet/produção enquanto os gates não tiverem evidência.

## 9. Estado de Git a preservar

O snapshot observado durante a auditoria anterior desta sessão estava na branch feat/mycelium-pkarr, com 19 arquivos rastreados modificados, nenhum staged e 32 caminhos não rastreados após a criação do plano privado. O número de arquivos não rastreados inclui documentos criados durante esta sessão e pode mudar com novas notas; sempre consultar git status antes de editar.

Esta transição deve adicionar documentação isolada primeiro. Alterações de protocolo/configuração devem ser pequenas, revisadas e testadas, sem descartar nenhum arquivo preexistente.

**Resultado esperado:** uma rede P2P Mycelium de produção, publicamente acessível e verificável, com os limites e a segurança documentados. Isto não equivale a uma blockchain MYC nem a um token mainnet.
