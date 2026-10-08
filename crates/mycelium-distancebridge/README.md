# 🌉 `mycelium-distancebridge` — Transporte Multi-Canal e Pontes Fantasma

Camada L2 de transporte fantasma resiliente a censura, com agregação de múltiplos canais físicos e chaveamento dinâmico de conexões.

---

## 🎯 Capacidades

- **Multi-Caminho (Multi-Path)**:
  - Envio e recepção de tráfego fragmentado por múltiplos canais simultâneos (Wi-Fi, Ethernet, celular, relays).
- **Detecção e Evasão de Bloqueios**:
  - Monitoramento contínuo de perda de pacotes e tempos de ida e volta (RTT).
  - Comutação transparente sem interrupção de sessões na ocorrência de censura por DPI (Deep Packet Inspection).
