# ErgotOS

O nome vem de *Claviceps purpurea*, um fungo que cresce no centeio.

## Visão

O ErgotOS é uma proposta de ambiente acessível pelo navegador para executar
serviços e software de diferentes máquinas, incluindo computadores, consoles
e dispositivos móveis. O plano também inclui ferramentas para interagir com
hardware físico. As metas abaixo não são garantias de compatibilidade ou de
controle sobre qualquer dispositivo.

## Componentes relacionados

| Pilar | Onde vive hoje |
|---|---|
| Interface no navegador | Event Horizon `/{ion}/`; o shell ErgotOS em `/console` é uma meta |
| Software de máquinas legadas | REVENANT: `lattice resurrect firmware.bin` e Forja |
| Análise de hardware | B.A.S.E. e specterprobe |
| Uso de recursos | Vouchers ATP e Inertia |
| Criptografia pós-quântica e fase tropical | ET-COSMIC: `mycelium-pqc`, `mycelium-tropical` |
| Estado que te segue | GhostID + Nucleus + Spore Bank (sessão itinerante) |

## Constelação Mycelium Network

- **ERGOT** — proposta de ambiente sobre o Mycelium.
- **RIZOMORFO** — camada de transporte que reúne Nostr transport, QEL,
  CandidateRelay e DistanceBridge para conectar nós em diferentes redes.
- **REVENANT** — fluxo proposto para analisar firmware, ROM ou ISO com
  B.A.S.E. e produzir um Plot e um Ion executável.
- **B.A.S.E.** = a Forja (Behavioral ASIC Synthesis Engine): descobrir,
  destravar e controlar hardware/software
- **specterprobe** = instrumento de sondagem/destravamento físico da Forja
  (`Behavioral ASIC Synthesis Engine/specterprobe/`) — entra no capítulo
  REVENANT quando o aparelho desbloquear
- **ET-COSMIC** = ponte PQC/tropical (ML-KEM-1024, max-plus) portada para os
  crates `mycelium-pqc` / `mycelium-tropical` / `mycelium-distancebridge`

## Próximos passos propostos

1. **Shell ErgotOS no `/console`**: desktop no navegador — Ions vivos de toda
   a rede (Growth Zones/Direct), terminal web → socket de controle, arquivos
   via Spore Bank, janelas = Ions
2. **Cápsulas de máquina**: Ions com emuladores (QEMU/RetroArch headless como
   layers Vacuum) — console/mobile/pad nativo dentro do micélio
3. **Índice global de Ions**: diretório pesquisável "o que está vivo agora"
4. **SDK Ergot**: empacotar qualquer software como Ion declarativo (Void +
   layers + manifest)
5. **Reputação anti-Sybil** para a economia aguentar escala
