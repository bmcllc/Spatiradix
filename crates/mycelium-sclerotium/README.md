# 🍄 `mycelium-sclerotium` — Estado Dormente e Ghost Carrier

Camada fisiológica de hibernação biológica, delegação criptográfica de presença e despertar seletivo por hardware (Wake-on-LAN / Wake-Up Radio).

---

## 🎯 Conceito Biológico

Na natureza, um **escleródio** (*sclerotium*) é uma estrutura fúngica compacta e dormente, capaz de sobreviver em condições hostis com gasto metabólico nulo, pronta para germinar quando as condições ambientais voltarem a ser favoráveis.

No Spatiradix, `mycelium-sclerotium` permite que nós físicos economizem 100% de energia da CPU principal sem desaparecerem da topologia lógica da rede P2P:
- **`LIVE`**: Máquina ligada, CPU/RAM ativas, processando tráfego e armazenamento.
- **`DORMANT`**: CPU suspensa/desligada; receptor de rádio/NIC aguarda `WakeToken` autenticado via Wake-on-LAN ou rádio de despertar (Ghost Carrier / 802.11ba).
- **`GHOST`**: Nós parceiros vizinhos mantêm uma `GhostLease` assinada, respondendo consultas de presença, guardando mensagens em caixas postais DTN e encaminhando pulsos de despertar sob demanda.
- **`DEAD`**: `GhostLease` expirada sem renovação criptográfica.

---

## 📦 Estrutura dos Módulos

- [`src/state.rs`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-sclerotium/src/state.rs): Máquina de estados finitos (`NodeVitalityState`: Live, Dormant, Ghost, Dead).
- [`src/lease.rs`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-sclerotium/src/lease.rs): Estrutura `GhostLease` com delegação de autoridade criptográfica ed25519 e verificação de expiração.
- [`src/wake.rs`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-sclerotium/src/wake.rs): Geração e validação de `WakeToken` seguro contra ataques de negação de serviço (DoS/Replay) e pacotes mágicos WoL.
- [`src/carrier.rs`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-sclerotium/src/carrier.rs): Enquadramento e modulação de pulsos analógicos de baixo consumo (*Ghost Carrier Frame*).
- [`src/proxy.rs`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-sclerotium/src/proxy.rs): Agente procurador (*Ghost Proxy*) mantido por peers para responder no lugar de nós dormentes.

---

## 🛠️ CLI Integrada

```bash
# Inspecionar capacidades de hardware (WoL / ethtool)
mycelium sclerotium hardware

# Gerar uma Ghost Lease para delegação a vizinhos
mycelium sclerotium lease --ttl 86400

# Consultar status do nó local
mycelium sclerotium status

# Despertar nó dormente autorizado
mycelium sclerotium wake --mac 00:11:22:33:44:55 --reason 1
```
