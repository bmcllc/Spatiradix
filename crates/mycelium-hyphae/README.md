# 🕸️ `mycelium-hyphae` — Malha Viva P2P e Transporte

Camada de conectividade e transporte viva baseada em `libp2p`, orquestrando hifas de comunicação em redes heterogêneas e adversariais.

---

## 🎯 Funcionalidades de Rede

- **Multi-Transporte**:
  - **QUIC (UDP)**: Conexões de baixíssima latência com multiplexação nativa de streams e criptografia TLS 1.3 embutida.
  - **TCP + Noise + Yamux**: Transporte confiável com cifragem Noise XX e multiplexação Yamux.
  - **WebRTC Direct**: Conectividade direta de navegadores e ambientes com restrições UDP/TCP.
- **Descoberta e Roteamento**:
  - **Kademlia DHT**: Espaço métrico XOR para localização de provedores de conteúdo e nós vizinhos.
  - **Gossipsub v1.2**: Propagação epidêmica de mensagens em tempo real (feromônios químicos e anúncios de estado).
  - **mDNS**: Descoberta sem configuração em redes locais (LAN).
- **Travessia de NAT e Relays**:
  - **Circuit Relay v2**: Comunicação indireta segura para nós atrás de CGNAT ou firewalls restritivos.
  - **AutoNAT**: Diagnóstico autônomo da capacidade de receber conexões externas.
- **Tolerância a Atrasos e Desconexões (DTN)**:
  - `DtnBundleStore`: Armazenamento persistente em disco (RocksDB / Sled) no padrão Store-and-Forward para nós intermitentes.
