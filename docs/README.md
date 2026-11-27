# Documentação do Spatiradix

Aqui você encontra guias de uso, arquitetura, protocolos, modelos de ameaça e
relatórios de testes do Spatiradix.

Para uma visão ampla, comece pela [documentação completa](DOCUMENTACAO_COMPLETA.md).
Para saber o que já foi testado e quais limites permanecem, consulte
[Validação](VALIDACAO.md): documentos de projeto também descrevem propostas.

Para começar pelo código, consulte o [guia de navegação](architecture/NAVEGACAO_CODIGO.md).

---

## Onde encontrar cada assunto

```text
docs/
├── architecture/  → Arquitetura, referência de crates, protocolos e glossário
├── veil/          → VEIL Ω: roteamento, especificações e modelo de ameaça
├── cosmic/        → Computação e armazenamento COSMIC
├── sclerotium/    → Dormência, Wake-on-LAN e Ghost Carrier
├── network/       → Membranas, NAT, relays, seeds e transporte híbrido
├── pipeline/      → The Lattice, nutrientes, entropia e métricas
└── reports/       → Relatórios de testes e histórico do projeto
```

---

## Documentos por assunto

### Arquitetura e fundamentos (`docs/architecture/`)
- **[`ARQUITETURA_GERAL_SISTEMICA.md`](architecture/ARQUITETURA_GERAL_SISTEMICA.md)**: Camadas, fluxos do The Lattice, economia e política de membrana.
- **[`CRATES_REFERENCE.md`](architecture/CRATES_REFERENCE.md)**: Papéis, tipos e dependências dos crates; confira a lista atual no `Cargo.toml` raiz.
- **[`SUBSTITUTO_INFRA_P2P.md`](architecture/SUBSTITUTO_INFRA_P2P.md)**: Plano para substituir VPS, hospedagem, domínio, git, Docker e servidores pela malha, integrando o framework MAPS (memória, agente, rotinas, painel) em N nós.
- **[`EVOLUCAO_2NOS_SOBERANA.md`](architecture/EVOLUCAO_2NOS_SOBERANA.md)**: Evolução de P2P, Nostr e web convencional para o mínimo de 2 nós, pegando emprestados os comuns públicos (Mainline DHT/Pkarr, relays Nostr/iroh) no lugar de seed/VPS/DNS próprios; inclui a triagem do que entra e do que não entra da pasta Alien Files.
- **[`MACHINE_HUB.md`](architecture/MACHINE_HUB.md)**: Desenho do Mycelium Machine Hub — núcleo nativo de simulação (contrato por quadro, perfil libretro, host isolado sem VM), SDK e níveis de fidelidade, integração com store/giggs/nostr/economy, modelo econômico com liquidação verificável e decisões de compatibilidade.
- **[`MACHINE_HUB_AUDITORIA.md`](architecture/MACHINE_HUB_AUDITORIA.md)**: Auditoria de segurança do código que o Hub reutiliza (store, Event Horizon, vitrine, giggs, nutrients, bank), com a cadeia "abrir um site → comando no host" e os portões por etapa.
- **[`architecture.md`](architecture/architecture.md)**: Visão histórica do daemon e suas chambers.
- **[`protocol.md`](architecture/protocol.md)**: Formatos binário e JSON dos envelopes transmitidos pelas hifas.
- **[`glossary.md`](architecture/glossary.md)**: Termos de micologia usados no projeto e seus significados no código.

### Root (`docs/root/`)
- **[`ROOT.md`](root/ROOT.md)**: Cofre cifrado K-de-N espalhado pelos seus meios físicos (pendrive, SD, celular, HD), Reed-Solomon + chave Shamir, sincronização por contato, montável como pendrive (`mycelium root`).

### Privacidade e roteamento cebola (`docs/veil/`)
- **[`VEIL_ONION_ROUTING.md`](veil/VEIL_ONION_ROUTING.md)**: Roteamento cebola de três saltos com ML-KEM-1024, proxy SOCKS5 e filtros Anti-SSRF.
- **[`VEIL_OMEGA_SPEC.md`](veil/VEIL_OMEGA_SPEC.md)**: Especificação formal do protocolo de transporte e encriptação de camadas do Veil.
- **[`THREAT_MODEL.md`](veil/THREAT_MODEL.md)**: Análise contra adversários com visão global de tráfego, nós espiões e correlação estatística.
- **[`VEIL_P12_WAN_FIELD_VALIDATION.md`](veil/VEIL_P12_WAN_FIELD_VALIDATION.md)** e **[`veil-homologacao-wan.md`](veil/veil-homologacao-wan.md)**: Roteiros e critérios para a validação WAN, ainda pendente nos registros.

### Computação e armazenamento (`docs/cosmic/`)
- **[`COSMIC_COMPUTE_STORAGE.md`](cosmic/COSMIC_COMPUTE_STORAGE.md)**: Proposta de computação e armazenamento com contratos criptográficos.
- **[`cosmic-design.md`](cosmic/cosmic-design.md)**: Fragmentação de dados em shards K/N e computação verificável.
- **[`et-cosmic-bridge.md`](cosmic/et-cosmic-bridge.md)**: Conexão com o núcleo conceitual `void_core`.

### Dormência e portadoras (`docs/sclerotium/`)
- **[`RFC_SCLEROTIUM_GHOST_CARRIER.md`](sclerotium/RFC_SCLEROTIUM_GHOST_CARRIER.md)**: Especificação da máquina de estados (`Alive -> Dormant -> Ghost -> Dead`), leases criptográficas delegadas e despertar seletivo com `WakeToken`.
- **[`live_vs_dtn.md`](sclerotium/live_vs_dtn.md)**: Diferenças entre o controle em tempo real e o armazenamento tolerante a atraso (DTN).

### Rede, hifas, NAT e membranas (`docs/network/`)
- **[`matriz_membranas.md`](network/matriz_membranas.md)** e **[`invariante_membrana.md`](network/invariante_membrana.md)**: Regras que regem os nós Folha, Floresta, Raiz e Esporocarp.
- **[`volunteer-sporocarp.md`](network/volunteer-sporocarp.md)**: Instruções para operadores que desejam doar banda e ganhar nutrientes ATP como relay público.
- **[`nostr-transport.md`](network/nostr-transport.md)**: Uso de conexões WSS de saída e relays Nostr para conectar nós.
- **[`pkarr-anonimo.md`](network/pkarr-anonimo.md)**: Descoberta anônima de um nó sem seed, DNS ou VPS (`mycelium-pkarr`): chave cegada por época, registro cifrado e acolchoado, publicação só via SOCKS5 do VEIL/Tor; inclui modelo de ameaça e riscos residuais.
- **[`nostr-qel.md`](network/nostr-qel.md)**: Integração de fragmentação QEL com transporte Nostr.
- **[`candidatos.md`](network/candidatos.md)**, **[`candidate-relay.md`](network/candidate-relay.md)** e **[`candidatos.state.json`](network/candidatos.state.json)**: Gestão de candidatos a relay na rede mesh.
- **[`mapa_cpe_vivo.md`](network/mapa_cpe_vivo.md)** e **[`engenharia-reversa-bloqueio.md`](network/engenharia-reversa-bloqueio.md)**: Comportamento de CPEs residenciais e análise de bloqueios de operadoras.
- **[`ops-seed.md`](network/ops-seed.md)** e **[`pitch_voluntario.txt`](network/pitch_voluntario.txt)**: Procedimentos operacionais e manifesto para voluntários.
- **[`rizomorphs.md`](network/rizomorphs.md)** e **[`sporocarp-cdn.md`](network/sporocarp-cdn.md)**: Canais de alta capacidade e CDN distribuída.

### The Lattice e computação (`docs/pipeline/`)
- **[`SEED-CODE.md`](pipeline/SEED-CODE.md)**: Como publicar repositórios no SporeBank e reconstruí-los em qualquer máquina sem usar Git ou GitHub.
- **[`nutrient-ledger.md`](pipeline/nutrient-ledger.md)**: O modelo econômico de incentivos computacionais.
- **[`plasma-ion-migration.md`](pipeline/plasma-ion-migration.md)**: Como serviços migram dinamicamente entre nós baseados em carga eletrostática.
- **[`entropy.md`](pipeline/entropy.md)**: Implementação do cofre Shamir Secret Sharing para segredos com tempo de expiração.
- **[`pqc.md`](pipeline/pqc.md)**: Operações ML-KEM-1024 e transporte PQC das hifas.
- **[`prometheus.md`](pipeline/prometheus.md)**: Métricas exportadas pelo endpoint `/metrics` do Event Horizon.
- **[`ergotos.md`](pipeline/ergotos.md)**: Console e orquestração ErgotOS.
- **[`microeasy-ecosystem.md`](pipeline/microeasy-ecosystem.md)**: Ecossistema de integração de jogos e software.

### Relatórios de testes e homologação (`docs/reports/`)
- **[`status.md`](reports/status.md)**: O registro vivo do progresso de engenharia ao longo de todas as fases do projeto.
- **[`release-0.1.0.md`](reports/release-0.1.0.md)**: Checklist e notas de release v0.1.0.
- **[`testes-realidade.md`](reports/testes-realidade.md)**: Bateria de testes em condições adversas.
- **[`P4_END_TO_END_HOMOLOGATION.md`](reports/P4_END_TO_END_HOMOLOGATION.md)** e **[`P4_HOMOLOGATION_REPORT.md`](reports/P4_HOMOLOGATION_REPORT.md)**: Auditoria da Fase 4.
- **[`P5_MICROEASY_INTEGRATION.md`](reports/P5_MICROEASY_INTEGRATION.md)**: Integração da suíte MicroEasy Fase 5.
- **[`INTEGRACAO_INTEGRAL_P1_3_2.md`](reports/INTEGRACAO_INTEGRAL_P1_3_2.md)**: Relatório de homologação dos subsistemas integrados.
