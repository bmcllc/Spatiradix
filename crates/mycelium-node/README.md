# 🍄 `mycelium-node` — O Daemon e Organismo Completo

O orquestrador do nó Mycelium: inicializa a identidade química, hifas de rede P2P, banco de esporos, ledger de nutrientes, túneis VEIL, servidor HTTP Event Horizon e Vitrine da Floresta.

---

## 🎯 Arquitetura do Organismo

O `mycelium-node` unifica todas as peças do monorepo em uma entidade biológica executável:
- **`Organism`**:
  - Instância viva que gerencia o ciclo de vida dos módulos através do trait `FruitingBody`.
  - Configura portas padrão:
    - `:4001`: Conexões P2P `libp2p` (TCP / QUIC / WebRTC).
    - `:7474`: Event Horizon HTTP & Console Web / Vitrine Iônica.
    - `:9050`: Proxy local SOCKS5 anônimo (VEIL Ω).
- **Console Web e Vitrine da Floresta**:
  - Interface interativa embarcada para monitoramento do nó em tempo real:
    - `/console`: Painel de controle, logs de hifas e saldo de nutrientes.
    - `/vitrine`: Vitrine da Floresta exibindo o ecossistema sovereign (Mycelium Video, MicroEasy Studio, Git Soberano, Hospedagem P2P).
