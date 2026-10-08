# Prova zero-infra: site + serviço por assinatura sem hospedagem, sem domínio, sem VPS

Data: 2026-10-08. Runnable: `bash scripts/prova-zero-infra.sh` (sai 0 só se todas as
afirmações abaixo passarem).

## 1. Tese

Um site e um serviço por assinatura podem existir **sem contrato de hospedagem, sem domínio
registrado e sem VPS**. O que ocupa o lugar dos três:

| Recurso usual | Substituto aqui | Onde está no código |
|---|---|---|
| Hospedagem (Vercel/AWS/VPS) | um nó Mycelium rodando nesta máquina (`mycelium daemon`) | `scripts/prova-zero-infra.sh` §3 |
| Domínio (DNS) | identidade: NodeId de 64 hex + `IP:porta` do Event Horizon | `sclerotium status` → `NodeId Local` |
| Banco de usuários / sessões | lease de assinatura: JSON assinado ed25519 com `valid_until` | `crates/mycelium-sclerotium/src/lease.rs` |
| Checkout próprio | pagamento fora do servidor (USDC na Base) + ledger anti double-spend | `mycelium sub issue`, `mycelium-economy verify-base-usdc` |

Nada disso é anúncio: o script mede cada afirmação com HTTP status e exit codes.

## 2. O que foi construído

1. `crates/mycelium-sclerotium/src/lease.rs` — capacidade `LeaseCapability::Subscriber`
   (id 5) na lease já existente, que já traz assinatura ed25519, expiração, nonce e
   identidade derivada da chave.
2. `crates/mycelium-node/src/vitrine_ion.rs` — gate no Event Horizon:
   - `GET /vitrine/api/subscription` → plano público (preço, período, endereço de recebimento);
   - `GET /vitrine/premium` → **401** sem lease, **200** com lease válida;
   - só mensagens fixas na resposta de erro (nenhum texto do cliente vira HTML).
3. `cli/mycelium-cli` — `mycelium sub plan | issue | verify`.
4. `deploy/store-ui/premium.html` — landing do assinante (cola a lease, entra).
5. `scripts/prova-zero-infra.sh` — a prova executável.

## 3. Fluxo de assinatura

```
emissor                              assinante
  mycelium sub plan --usdc 5 --days 30 --recipient 0x…
      └─ publicado em /vitrine/api/subscription
                                    paga USDC na Base para o endereço do plano
  mycelium-economy verify-base-usdc TX ENDEREÇO VALOR     (RPC público, read-only)
  mycelium sub issue --subscriber <NodeId> --payment-tx TX
      └─ lease JSON compacto assinada ed25519 (validade = período pago)
                                    entrega o arquivo / cola no site
                                      └─ GET /vitrine/premium com a lease → 200
```

- **Uma tx gera exatamente uma lease**: o hash da tx entra em
  `{home}/premium/payments.jsonl`; reuso é recusado.
- **O período é a assinatura**: `valid_until` da lease. Vencida → 401.
- **A credencial é a própria assinatura**: sem conta, senha, cookie ou sessão.

## 4. Critérios falsificáveis (o que o script mede)

- [x] Nó no ar em `127.0.0.1:<porta do horizon>/health` (7474 por padrão; se ocupada, o nó cai para porta efémera e o script usa a porta real) sem qualquer configuração de DNS ou host contratado.
- [x] Site público responde 200 em `/vitrine/`.
- [x] Identidade do serviço é o NodeId (64 hex), não um domínio.
- [x] Plano de assinatura publicado e lido pelo próprio site.
- [x] `/vitrine/premium` → **401** sem lease.
- [x] `sub verify` → exit 0 para lease válida, exit ≠ 0 para vencida e para adulterada.
- [x] Lease válida → **200** e entrega o conteúdo; funciona via `X-Subscription-Lease` e
      via `Authorization: Bearer`.
- [x] Mesma tx emitida 2× → recusada (anti double-spend).
- [x] Lease com validade no passado → **401** "assinatura expirada".
- [x] Lease com `valid_until` esticado sem re-quebrar a assinatura → **401**.
- [ ] **Não provado aqui:** leitura a partir de outra máquina (2 hosts reais, CGNAT), queda
      de um relay, gateway voluntário com HTTPS para navegador fora da malha, revogação
      parcial de lease. São os critérios da Etapa E6 em [`EVOLUCAO.md`](../EVOLUCAO.md);
      nenhum deles é exigido para a tese "sem hospedagem/domínio/VPS", mas nenhum foi
      medido por este script.

## 5. Limites declarados (teto desta versão)

- **Lease é bearer**: quem possui o arquivo usa. Revogação = reemissão/espera do vencimento.
  Upgrade: desafio-assinatura com o NodeId do portador + revogação por nonce.
- **Pagamento verificado pelo emissor**: `sub issue` exige o hash da tx e o registra, mas não
  consulta a chain (o verificador on-chain já existe em `mycelium-economy verify-base-usdc` e
  aceita só RPC local). Automação exige um RPC local ou canal de pagamento com webhook.
- **Ledger em arquivo sem lock**: dois `sub issue` concorrentes com a mesma tx poderiam
  emitir duas leases. Um emissor, por vez, está fora do risco.
- **HTTP sem TLS próprio** no Event Horizon: atrás de um gateway voluntário (Etapa E4) o
  navegador fala HTTPS; na malha nativa o transporte já é o do nó.
- `--valid-until` aceita o passado de propósito: é o que permite provar expiração ao vivo e
  é poder do emissor (ele tem a chave).

## 6. Comandos

```bash
bash scripts/prova-zero-infra.sh          # a prova inteira (compila uma vez)
cargo test -p mycelium-sclerotium -p mycelium-node   # unitários do gate e da capacidade

# operação real, no seu nó:
mycelium sub plan --usdc 5 --days 30 --recipient 0xSEU_ENDERECO
mycelium-economy --home <nó> verify-base-usdc 0xTX 0xSEU_ENDERECO 5
mycelium sub issue --subscriber <NodeId do cliente> --payment-tx 0xTX --payment-verified
```
