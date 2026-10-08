#!/usr/bin/env bash
# =============================================================================
# 🍄 PROVA ZERO-INFRA — site + serviço por assinatura sem hospedagem, sem
# domínio e sem VPS.
#
# O que é demonstrado, em um comando:
#   1. site público servido por um nó rodando nesta máquina (endereço = IP:porta
#      do nó; nenhum DNS, nenhum host contratado);
#   2. plano de assinatura publicado pelo próprio site (/vitrine/api/subscription);
#   3. conteúdo premium bloqueado (401) para quem não tem lease;
#   4. lease emitida após o pagamento (uma tx = uma lease, ledger anti
#      double-spend) e liberando o conteúdo (200);
#   5. lease expirada e lease adulterada voltam a ser negadas (401);
#   6. verificação offline da lease com `mycelium sub verify` (exit 0/1).
#
# Uso:  bash scripts/prova-zero-infra.sh   (ou ./scripts/prova-zero-infra.sh)
# Saída: tabela PASS/FAIL; exit 0 só se tudo passar.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug/mycelium"
PUB_HOME="/tmp/prova-zero-infra-publicador"
SUB_HOME="/tmp/prova-zero-infra-assinante"
PORT="${PROVA_PORT:-7474}"
BASE="http://127.0.0.1:${PORT}"
DAEMON_LOG="/tmp/prova-zero-infra-daemon.log"
DAEMON_PID=""

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); echo "  ✅ $1"; }
bad()  { FAIL=$((FAIL + 1)); echo "  ❌ $1"; }

cleanup() {
  if [ -n "$DAEMON_PID" ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

http_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@" || echo "000"; }
body()      { curl -s --max-time 10 "$@" || true; }

echo "== 1/6 Compilando o nó (única dependência: Rust local) =="
cargo build -p mycelium-cli --manifest-path "$ROOT/Cargo.toml"

rm -rf "$PUB_HOME" "$SUB_HOME" "$DAEMON_LOG"
mkdir -p "$PUB_HOME/premium"

echo "== 2/6 Publicador: identidade + site + plano =="
"$BIN" --home "$PUB_HOME" sprout --contribute 2cpu,2gb,10gb >/dev/null

cat > "$PUB_HOME/premium/content.html" <<'EOF'
<!doctype html><meta charset="utf-8"><title>Premium</title>
<h1>Conteúdo premium</h1>
<p>MARKER-CONTEUDO-PREMIUM-OK</p>
EOF

# Endereço de recebimento de exemplo (USDC na Base). Na produção, o seu.
"$BIN" --home "$PUB_HOME" sub plan \
  --usdc 5 --days 30 \
  --recipient 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913

echo "== 3/6 Subindo o nó (Event Horizon na porta ${PORT}) =="
"$BIN" --home "$PUB_HOME" daemon --horizon-port "$PORT" --no-mdns \
  > "$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

# A porta REAL vem do log: se $PORT estiver ocupada por outro processo (ex.:
# um nó antigo ainda vivo), o horizon cai para porta efémera — curiar a porta
# pedida responderia o nó errado e a prova inteira mentiria.
HORIZON_PORT=""
for _ in $(seq 1 60); do
  HORIZON_PORT=$(grep -a 'event horizon escutando' "$DAEMON_LOG" 2>/dev/null \
    | grep -ao '127\.0\.0\.1:[0-9]*' | head -1 | cut -d: -f2 || true)
  [ -n "$HORIZON_PORT" ] && break
  sleep 1
done
if [ -z "$HORIZON_PORT" ]; then
  bad "nó não abriu o horizon; ver $DAEMON_LOG"; tail -5 "$DAEMON_LOG"; exit 1
fi
if [ "$HORIZON_PORT" != "$PORT" ]; then
  echo "  ⚠️  porta ${PORT} ocupada por outro processo — horizon real em ${HORIZON_PORT}"
fi
PORT="$HORIZON_PORT"; BASE="http://127.0.0.1:${PORT}"

if [ "$(http_code "$BASE/health")" = "200" ]; then
  ok "nó no ar em $BASE/health (sem VPS: é esta máquina)"
else
  bad "nó subiu mas /health não respondeu; ver $DAEMON_LOG"; exit 1
fi

NODE_ID="$("$BIN" --home "$PUB_HOME" sclerotium status 2>/dev/null | awk -F': ' '/NodeId Local/{print $2}' | tr -d '[:space:]' || true)"
if echo "$NODE_ID" | grep -Eq '^[0-9a-f]{64}$'; then
  ok "identidade pública do nó = $NODE_ID (é ela, não um domínio, que endereça o serviço)"
else
  bad "NodeId do publicador não obtido (got: '$NODE_ID')"
fi

echo "== 4/6 Site público e plano =="
if [ "$(http_code "$BASE/vitrine/")" = "200" ]; then
  ok "site público em $BASE/vitrine/ — nenhum DNS, nenhum host contratado"
else
  bad "site público não respondeu 200"
fi
if body "$BASE/vitrine/api/subscription" | grep -q '"price_usdc"'; then
  ok "plano de assinatura publicado pelo próprio site (/vitrine/api/subscription)"
else
  bad "plano de assinatura ausente"
fi
if [ "$(http_code "$BASE/vitrine/premium")" = "401" ]; then
  ok "conteúdo premium bloqueado sem lease (401)"
else
  bad "conteúdo premium deveria responder 401 sem lease"
fi

echo "== 5/6 Assinante: pagamento -> lease -> acesso =="
"$BIN" --home "$SUB_HOME" sprout --contribute 1cpu,1gb,1gb >/dev/null
SUB_ID="$("$BIN" --home "$SUB_HOME" sclerotium status 2>/dev/null | awk -F': ' '/NodeId Local/{print $2}' | tr -d '[:space:]' || true)"
if echo "$SUB_ID" | grep -Eq '^[0-9a-f]{64}$'; then
  ok "identidade do assinante = $SUB_ID"
else
  bad "NodeId do assinante não obtido (got: '$SUB_ID')"
fi

# 1º pagamento (hash sintático; na produção o emissor roda antes:
# mycelium-economy --home <pub> verify-base-usdc TX RECIPIENTE VALOR)
TX1="0x1111111111111111111111111111111111111111111111111111111111111111"
LEASE_OK="$PUB_HOME/premium/leases/assinante-1.json"
if "$BIN" --home "$PUB_HOME" sub issue --subscriber "$SUB_ID" --payment-tx "$TX1" \
     --out "$LEASE_OK" >/dev/null; then
  ok "lease emitida para o pagamento $TX1"
else
  bad "emissão da lease falhou"
fi
if "$BIN" --home "$PUB_HOME" sub verify --lease "$LEASE_OK" --subscriber "$SUB_ID" >/dev/null 2>&1; then
  ok "verificação offline da lease: exit 0"
else
  bad "sub verify recusou uma lease recém-emitida"
fi

if [ "$(http_code -H "X-Subscription-Lease: $(cat "$LEASE_OK")" "$BASE/vitrine/premium")" = "200" ]; then
  ok "assinante acessa o premium (200) com a lease no header"
else
  bad "premium não abriu com lease válida"
fi
if body -H "X-Subscription-Lease: $(cat "$LEASE_OK")" "$BASE/vitrine/premium" | grep -q "MARKER-CONTEUDO-PREMIUM-OK"; then
  ok "conteúdo premium entregue"
else
  bad "conteúdo premium não bateu com o publicado"
fi
if [ "$(http_code -H "Authorization: Bearer $(cat "$LEASE_OK")" "$BASE/vitrine/premium")" = "200" ]; then
  ok "formato alternativo Authorization: Bearer também é aceito"
else
  bad "Authorization: Bearer não foi aceito"
fi

if "$BIN" --home "$PUB_HOME" sub issue --subscriber "$SUB_ID" --payment-tx "$TX1" >/dev/null 2>&1; then
  bad "mesma tx aceita duas vezes (double-spend no ledger de pagamentos)"
else
  ok "reuso da tx $TX1 recusado — uma tx gera exatamente uma lease"
fi

TX2="0x2222222222222222222222222222222222222222222222222222222222222222"
LEASE_EXPIRED="$PUB_HOME/premium/leases/assinante-expirada.json"
PAST=$(( $(date +%s) - 10 ))
if "$BIN" --home "$PUB_HOME" sub issue --subscriber "$SUB_ID" --payment-tx "$TX2" \
     --valid-until "$PAST" --out "$LEASE_EXPIRED" >/dev/null; then
  ok "lease com validade no passado emitida (para provar expiração ao vivo)"
else
  bad "emissão da lease expirada falhou"
fi
if "$BIN" --home "$PUB_HOME" sub verify --lease "$LEASE_EXPIRED" >/dev/null 2>&1; then
  bad "sub verify aceitou lease expirada"
else
  ok "sub verify recusa lease expirada (exit != 0)"
fi
if body -H "X-Subscription-Lease: $(cat "$LEASE_EXPIRED")" "$BASE/vitrine/premium" | grep -q "assinatura expirada"; then
  ok "gate responde 401 'assinatura expirada' para lease vencida"
else
  bad "gate não expirou a lease vencida"
fi

# Lease adulterada: estica a validade sem poder re-quebrar a assinatura ed25519.
LEASE_TAMPER="/tmp/prova-zero-infra-lease-adulterada.json"
sed 's/"valid_until":[0-9]*/"valid_until":9999999999/' "$LEASE_OK" > "$LEASE_TAMPER"
if "$BIN" --home "$PUB_HOME" sub verify --lease "$LEASE_TAMPER" >/dev/null 2>&1; then
  bad "sub verify aceitou lease adulterada"
else
  ok "lease adulterada recusada pela assinatura ed25519"
fi
if [ "$(http_code -H "X-Subscription-Lease: $(cat "$LEASE_TAMPER")" "$BASE/vitrine/premium")" = "401" ]; then
  ok "gate responde 401 para lease adulterada"
else
  bad "gate abriu para lease adulterada"
fi

echo
echo "=================================================================="
echo " RESULTADO: ${PASS} PASS · ${FAIL} FAIL"
echo " Endereço do site : $BASE/vitrine/   (sem domínio)"
echo " Plano            : $BASE/vitrine/api/subscription"
echo " Premium          : $BASE/vitrine/premium (401 sem lease)"
echo " Identidade do nó : $NODE_ID"
echo " Custo de infra   : US\$ 0,00 — sem hospedagem, sem domínio, sem VPS"
echo "=================================================================="
[ "$FAIL" -eq 0 ]
