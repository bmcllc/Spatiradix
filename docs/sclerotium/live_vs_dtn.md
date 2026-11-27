# Rede em tempo real e armazenamento tolerante a atraso

## Rede em tempo real

Estas funções dependem de uma sessão ativa entre os nós:

| Função | Live? | Motivo |
|--------|-------|--------|
| mDNS LAN | sim | descoberta local |
| dial / identify | sim | handshake |
| relay circuit | sim | sessão stateful |
| `status` / control socket | sim | plano de controlo |
| Horizon local | sim | proxy local |
| gossipsub | sim/semi | propagação rápida |
| DHT query | sim/semi | lookup |
| WebRTC ICE | sim | negociação |

## DTN e armazenamento para encaminhamento posterior

Os itens abaixo podem ser armazenados para entrega ou sincronização posterior:

| Função | DTN? | Motivo |
|--------|------|--------|
| Plots Giggs | ✅ | content-addressed |
| `sow` / `recall` | ✅ | propagação eventual |
| Signals TheField | ✅ | quórum pode ser async |
| Isotope atoms | ✅ | LWW eventual |
| Vacuum layers | ✅ | content-addressed |
| mailbox DHT | ✅ | desenhado para isso |
| Entropy secrets | ⚠️ | preferir meia-vida, não persistir |

## Separação

```text
LIVE  = vizinhos, relay, dial, ICE, status, horizon
DTN   = Plots, Signals, Isotope, artifacts, mailbox
```

Sem um terceiro par alcançável, a comunicação pode depender de encontros em
rede local para troca posterior; o bootstrap pela WAN pode falhar.
