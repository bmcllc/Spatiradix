# Operar uma seed ou esporocarpo voluntário

Uma seed pública pode rodar em uma máquina voluntária, desde que sua porta de
entrada esteja acessível e seja verificada a partir de outra rede. Nós atrás
de CGNAT ou firewall podem operar como folhas. Veja os guias de
[esporocarpo voluntário](volunteer-sporocarp.md) e [membranas](rizomorphs.md).

## Fluxo rápido (voluntário)

Substitua `IP_PUBLICO`, `IPV4` e `IPV6` pelos endereços do candidato antes de
executar os comandos. Use apenas os endereços correspondentes à sua configuração.

```bash
# 1) No peer: port-forward TCP(+UDP) 4001, daemon a escutar 0.0.0.0
# 2) De outra rede (ex.: 5G), gere a prova:
./scripts/probe-sporocarp.sh IP_PUBLICO 4001 telemovel-5g > proof.json

# 3) Copie proof.json para o candidato e verifique lá:
./scripts/verify-sporocarp.sh 4001 proof.json

# 4) Somente se a verificação passar:
MYCELIUM_REACHABLE=1 ./scripts/run-public-seed.sh
# ou 24/7:
sudo MYCELIUM_REACHABLE=1 ./scripts/install-seed.sh \
  --announce-ip IPV4 --announce-ip6 IPV6

# 5) Exporte a linha /esporocarp para seeds/mainnet.txt ou DuckDNS TXT
./scripts/export-seed.sh ~/.local/share/mycelium-seed
```

## Sporocarp manual

```bash
export MYCELIUM_HOME=/var/lib/mycelium-seed
export MYCELIUM_REACHABLE=1
export MYCELIUM_ANNOUNCE_IP6=$(curl -6 -s ifconfig.co)   # se IPv6 inbound ok
# ou IPv4 com port-forward:
# export MYCELIUM_ANNOUNCE_IP=$(curl -4 -s ifconfig.co)
export DUCKDNS_TOKEN=seu-token          # opcional
export DUCKDNS_DOMAIN=meuspores
export MYCELIUM_CONTROL_TOKEN=$(openssl rand -hex 16)

mycelium sprout --contribute 2cpu,4gb,100gb
mycelium daemon \
  --listen /ip6/::/tcp/4001 \
  --listen /ip4/0.0.0.0/tcp/4001 \
  --assume-reachable \
  --sporocarp \
  --no-mdns \
  --horizon-port 7474 \
  --contribute 2cpu,4gb,100gb
```

Com `--sporocarp` + reachable:

- membrana **esporocarp** + relay server (circuit v2)
- anúncio mesh `/mycelium/relay-mesh/v1` (só se `wan_reach`)
- publish DuckDNS TXT com `/esporocarp` (se `DUCKDNS_*`)

## Folhas (casa / 5G)

```bash
mycelium daemon --seed-file ./seeds/mainnet.txt --no-mdns
# ou: --public-bootstrap  (DNS TXT Spore Bank)
```

Folhas priorizam `/esporocarp`. Não dialam `/folha`.

## Catálogo

- **DNS:** DuckDNS TXT do voluntário  
- **HTTP/git:** `seeds/mainnet.txt` via `--public-bootstrap` / `--seed-file`

## Verificação de acesso

Verifique o acesso de entrada antes de anunciar o esporocarpo. Ter um endereço
IPv6 na interface não prova que ele é alcançável pela internet.
