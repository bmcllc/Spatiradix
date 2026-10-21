# Prova em 2 máquinas reais

Script: [`scripts/prova-2-maquinas.sh`](../../scripts/prova-2-maquinas.sh).
Fecha a lacuna "tudo rodou numa máquina só". Ensaiado nesta máquina em
2026-10-21 (os dois papéis passaram); falta rodar em **duas máquinas**.

## Pré-requisitos

| | Máquina A (anônima) | Máquina B (visitante) |
|---|---|---|
| Rede | qualquer (pode ser CGNAT) | **outra** rede (4G do celular roteado, casa de alguém) |
| Tor | obrigatório (`sudo apt install tor`) | opcional |
| Binário | `cargo build -p mycelium-cli` | mesmo binário (copie `target/debug/mycelium` ou compile) |

Android: o `dist/mycelium-android-arm64` é de julho e **não** tem `pkarr`,
`--anonymous` nem o gateway. No Termux: `pkg install rust tor git`, clone o repo e
`cargo build --release -p mycelium-cli` (demora). Ou use um segundo PC/notebook.

## Passos

```bash
# A
bash scripts/prova-2-maquinas.sh anon
# copie a linha que ele imprime e rode em B:
bash scripts/prova-2-maquinas.sh visitante 'myc1…' prova-xxxxxxxx
```

## O que conta como aprovado

- `relatorio-visitante.txt`: `vizinhos antes do connect=0`, `depois=1` e `PASSOU … nonce`.
- `relatorio-anon.txt`: todas as linhas com `tcp_fora_do_tor=0 udp=0`.
- Os dois relatórios com `máquina=` **diferentes** (hash do machine-id, sem IP).

Cole os dois relatórios em [`docs/reports/testes-realidade.md`](../reports/testes-realidade.md).
