# Candidatos a esporocarpo voluntário

Um candidato está pronto quando tem endereço público, passa na sonda TCP
externa e `verify-sporocarp.sh` termina com código zero.

**Hybrid Theory:** sem verde, a folha já tem mesh leve via **Nostr transport**
(`vizinhos` sobre WSS, auto em `folha`/`floresta`). O voluntário desbloqueia
**mesh live** (circuit relay, baixa latência).

## Procedimento com o pipeline

```bash
# O que falta agora (checklist):
./scripts/volunteer-pipeline.sh next

# 0) Neste PC (candidato?): CGNAT?
./scripts/volunteer-pipeline.sh cgnat-check

# 1) Outreach — pitch no clipboard + marca estado
./scripts/volunteer-pipeline.sh pitch "Amigo fibra"

# 2) No VOLUNTÁRIO (depois do port-forward): abre listen para o probe
./scripts/volunteer-pipeline.sh prep-listen

# 3) No telemóvel 5G:
./scripts/volunteer-pipeline.sh probe <IP_PUBLICO>
# → gera proof.json

# 4) No PC do VOLUNTÁRIO (com proof.json):
./scripts/volunteer-pipeline.sh onboard proof.json
# → verify + seed + export → seeds/mainnet.txt

# 5) Na FOLHA (Bruno / TushiBook):
./scripts/volunteer-pipeline.sh folha-attach '/ip4/…/tcp/4001/p2p/…/esporocarp'
# → seed book + restart + espera vizinhos>=1

# Estado
./scripts/volunteer-pipeline.sh status
./scripts/volunteer-pipeline.sh mark "Amigo fibra" "verde"
```

O estado fica em [`candidatos.state.json`](candidatos.state.json), atualizado
pelos comandos `pitch` e `mark`.

## Tabela (manual / referência)

| Nome | Contacto | ISP | IPv4 público? | IPv6 aberto? | Port-forward? | Máquina | Estado |
|------|----------|-----|---------------|--------------|---------------|---------|--------|
| TushiBook (Bruno) | — | Vivo CGNAT | não (WAN≠LAN) | ICMP ok / TCP drop | não | casa | **folha** — Nostr transport |
| Amigo fibra | | | ? | ? | ? | PC | prospecto — próximo pitch |
| Uni / lab | | | ? | ? | ? | servidor | prospecto |
| Familiar | | | ? | ? | ? | NAS/PC | prospecto |
| Hackerspace | | | ? | ? | ? | rack | prospecto |

## Participação do voluntário

É preciso entrar em contato com o voluntário e configurar a porta no roteador.
O pipeline reúne os comandos para sondar, verificar, exportar a seed e conectar
a folha; acompanhe os resultados antes de avançar.

Pitch: [`pitch_voluntario.txt`](pitch_voluntario.txt) · Ops: [`volunteer-sporocarp.md`](volunteer-sporocarp.md) · Nostr mesh: [`nostr-transport.md`](nostr-transport.md) · Demo hybrid: `./scripts/hybrid-demo.sh`
