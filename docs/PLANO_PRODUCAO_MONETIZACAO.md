# Plano de produção e monetização (open-core)

> **Princípio.** O substrato Mycelium (rede, DHT, spore bank, economia,
> identidade) fica **AGPL-3.0 e mantido pela comunidade**. A receita vem de
> **camadas construídas por cima** — disponibilidade, conveniência, interfaces e
> trilhos — nunca de fechar o core. Este documento é um roteiro; não é uma
> declaração de prontidão. Onde não há evidência, está escrito "não medido".

Estado de validação atual (fonte única: [`docs/VALIDACAO.md`](VALIDACAO.md)):
nível **(a)** cumprido (compila + testes locais, **loopback**); **(b)** multi-host,
**(c)** terceiro e **(d)** produção **não cumpridos**; **E6 = 0/9**.

## 1. Os dois bloqueios reais (de ambiente, não de código)

1. **Térmico.** A máquina local oscila **87–96 °C** sob carga
   (`research/evidence/thermal-*.json`); o build do worker CQR foi abortado pelo
   próprio guardião térmico várias vezes. Compute pesado **não** é confiável
   aqui.
2. **Segundo host.** Todo gate do repositório faz bind em `127.0.0.1`. Enquanto
   for "1 máquina, 0 redes", nenhum critério de produção é atingível por mais
   código que se escreva.

Consequência: **produção = sair do loopback.** E isso é exatamente o que casa
com "a comunidade mantém": o comum precisa rodar em máquinas de terceiros.

## 2. Gates de teste para produção (T0–T7)

Do barato ao caro. Cada linha tem **evidência exigida** — sem ela, não se avança.

| # | Ação | Custo | Destrava | Evidência |
|---|------|-------|----------|-----------|
| **T0** | Resolver o térmico (ventoinha/pasta) **ou** mover compute para VPS | ~US$ 0 | as 3 prioridades locais + worker CQR | temperatura estável sob build (`research/evidence/`) |
| **T1** | **2–3 VPS** em datacenters distintos | ~US$ 10–40/mês | (b), E6 #1/#3/#4 | `neighbor_ids` não-vazio em cada nó; log de gossipsub cross-host |
| **T2** | **1 seed real** com inbound TCP 4001 verificado | US$ 0 (só o VPS) | E6 #2, bootstrap sem URL fixa | linha `/esporocarp` em `seeds/mainnet.txt` + saída de `verify-sporocarp.sh` |
| **T3** | Rodar as provas que já existem **entre hosts** | US$ 0 | (b) de verdade | `recall` cross-host; sobrevivência com publicador morto; anti-entropy entre hosts |
| **T4** | **Cliente independente** (não o nosso CLI) + ≤1 relay de terceiro | baixo | (c), E6 #6 | log do cliente externo; recibo |
| **T5** | **Recibo assinado on-chain** (Base) de uma custódia/settlement | gas mínimo | (c), E6 #3 | tx hash + `mycelium-economy` `verify-base-usdc` |
| **T6** | **Bateria adversarial** sob quota/GC + secret-scan no CI | baixo | E6 #8 | relatório com limites e falhas; CI com `gitleaks`/`trufflehog` |
| **T7** | **Métricas de produção**: uptime, latência p95, recuperação, réplicas | US$ 0 (Prometheus já existe) | (d), E6 #9 | série temporal + dashboards |

**Atalho eficiente:** **T1+T2+T3 numa tarde de VPS** move (b) e boa parte do E6
sem escrever código novo.

## 3. O que construir *por cima* (menu, ranqueado por aderência ao que já existe)

| # | Produto | Reusa | Como cobra | Prontidão |
|---|---------|-------|------------|-----------|
| 1 | **Disponibilidade gerenciada do comum** (nós/gateways/relays *always-on* com SLA; malha comunitária é best-effort) | `hyphae`, `singularity` (Horizon + `/metrics`), `veil` | assinatura mensal por nós/região | média |
| 2 | **Vitrine/loja soberana por assinatura** (criador publica sem hospedagem/domínio/VPS) | `vitrine_ion`, `sclerotium::lease`, `mycelium-media`, `mycelium-store` | por loja/assinante (USDC/Base + lease) | **alta** (MVP já provado) |
| 3 | **Backup verificável como serviço** (dedup + restaurável + recibo de custódia) | `cosmic-cli`, `entropy` (Shamir), `sporebank` | por GB/mês | média |
| 4 | **Marketplace com take-rate** (retro-jogos/ROMs, vídeo, apps) | `mycelium-store`, `mycelium-media`, `nutrients` | taxa por distribuição paga | média |
| 5 | **Observabilidade/SLA para operadores de nó** | `deploy/prometheus`, `/metrics` | plano de painel/alertas | alta (infra pronta) |
| 6 | **Trilho de recibos/liquidação** (billing verificável por prova, como API) | `mycelium-economy` (67k LOC: `verified_view`, `settlement`, `receipt_auth`) | API/uso | média |
| 7 | **VEIL Ω para empresas** (transporte PQC anti-censura + SOCKS5) | `mycelium-veil` | contrato de suporte/integração | média |
| 8 | **Identidade/PQC portátil** (login/mensagem pós-quântica) | `ghostid`, `pqc` | por assento | baixa |

Regra de ouro: **nada de receita inventada.** Créditos internos (MYC, mUSD, ATP)
e testes **não** são receita recebida — o próprio `PLANO_MYCELIUM_NEXT.md`
estabelece isso. Só conta valor **liquidado e observável** (recibo on-chain,
saldo de cliente).

## 4. Runbook — primeiro host real (T1+T2+T3), reusando o que já existe

### T1 — subir 2 VPS

- Portas: **TCP+UDP 4001** (libp2p), **7474** (Event Horizon) se exposto.
- Firewall: liberar 4001 TCP **e** UDP; IPv6 se disponível.
- Build: `cargo build --release -p mycelium-cli` → `target/release/mycelium`.

### T2 — publicar o seed com inbound verificado

```bash
# 1) No VPS (host A):
target/release/mycelium --home /var/lib/mycelium-seed sprout --contribute 2cpu,4gb,50gb
# 2) De OUTRA rede (seu laptop / host B):
./scripts/verify-sporocarp.sh IP_PUBLICO_A 4001
# 3) Só se ok, no host A:
MYCELIUM_REACHABLE=1 ./scripts/run-public-seed.sh        # ou scripts/install-seed.sh (24/7)
# 4) Exportar a linha e registrar:
./scripts/export-seed.sh /var/lib/mycelium-seed >> seeds/mainnet.txt
```

Formato da linha (ver `seeds/mainnet.example.txt`):
`/ip4/IP/tcp/4001/p2p/<PeerId>/esporocarp`.

### T3 — provar a malha entre hosts (o que hoje só roda em loopback)

```bash
# no host B: entra na malha pelo seed, sem mDNS
target/release/mycelium --home /tmp/node-b daemon \
  --seed-file ./seeds/mainnet.txt --no-mdns

# no host A: publica
target/release/mycelium --home /var/lib/mycelium-seed \
  sow --message "MULTIHOST-OK" --path app.rs --content 'fn main(){}'

# no host B: recupera pela rede (não local)
target/release/mycelium --home /tmp/node-b recall --plot <CID>

# sobrevivência: matar A (kill -9) e repetir o recall em B → deve continuar.
```

Os scripts `scripts/prova-sobrevivencia.sh` e `scripts/prova-anti-entropy.sh`
já provam esse comportamento em loopback; o passo T3 é **reexecutá-lo entre
hosts** — é a única diferença entre o que existe e o que o E6 pede.

### Verificação do gate T3

- `neighbor_ids` não-vazio em A e B (não mais `[]`).
- `recall` em B retorna o conteúdo **com A desligado**.
- Registrar evidência (log + CID + horário) em `docs/reports/testes-realidade.md`.

## 5. Ordem de prioridade (recomendação)

1. **T1+T2+T3** — destrava (b) e ~4/9 do E6 sem código novo.
2. **Produto #2 (vitrine/assinatura)** — o mais próximo de vendável; reusa o MVP
   `prova-zero-infra.sh`.
3. **Produto #6 (trilho de recibos)** — só depois, para que receita seja
   **verificável**, não crédito interno.

## 6. O que NÃO fazer

- **Não** marcar E6 sem evidência externa (host distinto, cliente distinto,
  séries temporais).
- **Não** contar crédito interno/teste como receita.
- **Não** adicionar feature nova de E1.x em loopback esperando que "produção
  venha depois" — o gargalo é host, não código.
- **Não** subir compute pesado local enquanto o térmico não estiver resolvido.

---

## Apêndice — E6 (0/9) → teste que fecha cada item

| Critério E6 | Fechado por |
|---|---|
| 1. 3+ nós em máquinas diferentes | T1 |
| 2. Bootstrap sem URL fixa após peering inicial | T2 |
| 3. Réplica com prova de posse + persistência | T1+T3 |
| 4. Publicador offline, serviço por 2+ réplicas | T3 |
| 5. Queda de relay com reconexão configurada | T3 (+ T4) |
| 6. Dois gateways independentes servem o mesmo Ion | T4 |
| 7. CGNAT residencial com relays voluntários | T1+T2 (Nostr/`veil`) |
| 8. Terceiros isolados sob quota real + adversarial | T6 |
| 9. Logs/séries: uptime, p95, recuperação, réplicas | T7 |
