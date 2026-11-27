# Prova em 2 máquinas reais

Script: [`scripts/prova-2-maquinas.sh`](../../scripts/prova-2-maquinas.sh).
O procedimento foi ensaiado em uma máquina em 21 de outubro de 2026, com os
dois papéis aprovados. Ainda falta executá-lo em **duas máquinas** para testar
a conexão entre redes distintas.

## Pré-requisitos

| | Máquina A (anônima) | Máquina B (visitante) |
|---|---|---|
| Rede | qualquer (pode ser CGNAT) | **outra** rede (4G do celular roteado, casa de alguém) |
| Tor | obrigatório (`sudo apt install tor`) | opcional |
| Binário | `cargo build -p mycelium-cli` | mesmo binário (copie `target/debug/mycelium` ou compile) |

Na data do ensaio, o binário `dist/mycelium-android-arm64` disponível era de
julho e não tinha `pkarr`, `--anonymous` nem o gateway. No Termux, instale
`rust`, `tor` e `git`, clone o repositório e execute
`cargo build --release -p mycelium-cli`. A compilação pode demorar; outra
opção é usar um segundo computador.

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
