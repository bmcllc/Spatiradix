#!/usr/bin/env bash
# =============================================================================
# 🍄 PROVA SOBREVIVÊNCIA — o conteúdo sobrevive à morte do publicador.
#
# Criterio E1.5/E2.5 de EVOLUCAO.md, validado em malha real (3 nós, loopback):
#   1. nó A publica (sow) um plot;
#   2. réplicas B e C recebem os BYTES via gossip (SporePrint -> absorb_public)
#      e comprovam o conteúdo no SporeBank local;
#   3. A é DERRUBADO (kill -9);
#   4. B e C continuam servindo o plot do banco local, sem consultar A.
#
# O que isso prova (e o que não):
#   ✓ replicação de plot público entre pares e retenção local dos bytes;
#   ✓ disponibilidade do conteúdo com o publicador offline.
#   ✗ NÃO prova persistência após restart das réplicas (E2.5 completo);
#   ✗ NÃO prova pinning R>=3 com recibos nem anti-entropy (E1.1-E1.4);
#   ✗ NÃO prova CGNAT/multi-host (loopback apenas).
#
# Uso:  bash scripts/prova-sobrevivencia.sh
# Saída: tabela PASS/FAIL; exit 0 só se tudo passar.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug/mycelium"
BASE_PORT=18800          # porta base da malha (evita colidir com 7474/prova-zero)
HORIZON_BASE=18900
MARKER="SOBREVIVENCIA-MARKER-OK"

A_HOME="/tmp/prova-sobr-a"; B_HOME="/tmp/prova-sobr-b"; C_HOME="/tmp/prova-sobr-c"
A_LOG="/tmp/prova-sobr-a.log"; B_LOG="/tmp/prova-sobr-b.log"; C_LOG="/tmp/prova-sobr-c.log"
A_PID="" B_PID="" C_PID=""

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ✅ $1"; }
bad() { FAIL=$((FAIL+1)); echo "  ❌ $1"; }

cleanup() {
  for pid in "$A_PID" "$B_PID" "$C_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

# recall: exit 0 e imprime a mensagem se o plot está no bank LOCAL do nó.
recall_ok() { # $1=home $2=cid
  "$BIN" --home "$1" recall --plot "$2" 2>/dev/null | grep -q "$MARKER"
}
status_plots() { # $1=home -> nº de plots no bank
  "$BIN" --home "$1" status 2>/dev/null | awk '/plots/{print $2; exit}'
}

echo "== 1/5 Compilando o nó =="
cargo build -p mycelium-cli --manifest-path "$ROOT/Cargo.toml"

rm -rf "$A_HOME" "$B_HOME" "$C_HOME" "$A_LOG" "$B_LOG" "$C_LOG"
for h in "$A_HOME" "$B_HOME" "$C_HOME"; do mkdir -p "$h"; done

echo "== 2/5 Subindo a malha (A seed + B,C réplicas) =="
"$BIN" --home "$A_HOME" sprout --contribute 2cpu,4gb,50gb >/dev/null
"$BIN" --home "$B_HOME" sprout --contribute 1cpu,2gb,25gb >/dev/null
"$BIN" --home "$C_HOME" sprout --contribute 1cpu,2gb,25gb >/dev/null

A_PORT=$BASE_PORT; B_PORT=$((BASE_PORT+1)); C_PORT=$((BASE_PORT+2))
RUST_LOG=info "$BIN" --home "$A_HOME" daemon --contribute 2cpu,4gb,50gb \
  --horizon-port "$HORIZON_BASE" --no-mdns \
  --listen "/ip4/127.0.0.1/tcp/$A_PORT" >"$A_LOG" 2>&1 &
A_PID=$!

# espera o A ter socket + peer id
A_PEER=""
for _ in $(seq 1 60); do
  [ -S "$A_HOME/mycelium.sock" ] && A_PEER=$(grep -oE '12D3Koo[A-Za-z0-9]+' "$A_LOG" | head -1) && [ -n "$A_PEER" ] && break
  sleep 0.5
done
if [ -z "$A_PEER" ]; then bad "nó A (seed) não subiu; ver $A_LOG"; tail -5 "$A_LOG"; exit 1; fi
ok "nó A (publicador/seed) no ar, PeerId ${A_PEER:0:20}…"

BOOT="/ip4/127.0.0.1/tcp/$A_PORT/p2p/$A_PEER"
RUST_LOG=info "$BIN" --home "$B_HOME" daemon --contribute 1cpu,2gb,25gb \
  --horizon-port $((HORIZON_BASE+1)) --no-mdns \
  --listen "/ip4/127.0.0.1/tcp/$B_PORT" --bootstrap "$BOOT" >"$B_LOG" 2>&1 &
B_PID=$!
RUST_LOG=info "$BIN" --home "$C_HOME" daemon --contribute 1cpu,2gb,25gb \
  --horizon-port $((HORIZON_BASE+2)) --no-mdns \
  --listen "/ip4/127.0.0.1/tcp/$C_PORT" --bootstrap "$BOOT" >"$C_LOG" 2>&1 &
C_PID=$!

for _ in $(seq 1 60); do
  [ -S "$B_HOME/mycelium.sock" ] && [ -S "$C_HOME/mycelium.sock" ] && break
  sleep 0.5
done
if [ -S "$B_HOME/mycelium.sock" ] && [ -S "$C_HOME/mycelium.sock" ]; then
  ok "réplicas B e C conectadas ao seed A"
else
  bad "réplicas não subiram; ver $B_LOG / $C_LOG"; exit 1
fi
sleep 3   # deixa a lattice estabilizar antes de publicar

echo "== 3/5 A publica; B e C replicam =="
SOW_OUT=$("$BIN" --home "$A_HOME" sow --message "$MARKER" --path "app.rs" --content 'fn main(){ println!("sobrevive"); }' 2>&1) || {
  bad "sow falhou: $SOW_OUT"; exit 1; }
# o CLI imprime "plot semeado: Qm..." (prefixo minúsculo)
CID=$(echo "$SOW_OUT" | grep -oE 'Qm[0-9a-f]{40,}' | head -1 || true)
if [ -z "$CID" ]; then bad "sow não devolveu CID: $SOW_OUT"; exit 1; fi
ok "A publicou plot $CID"

# espera a propagação (gossip) encher o bank de B e C
replicated=0
for _ in $(seq 1 30); do
  if recall_ok "$B_HOME" "$CID" && recall_ok "$C_HOME" "$CID"; then replicated=1; break; fi
  sleep 1
done
if [ "$replicated" = "1" ]; then
  ok "B e C replicaram o conteúdo (recall local acha o MARKER)"
else
  bad "B/C não replicaram dentro da janela (B=$(status_plots "$B_HOME") C=$(status_plots "$C_HOME") plots)"
fi

echo "== 4/5 Derrubando o publicador A =="
kill -9 "$A_PID" 2>/dev/null || true
wait "$A_PID" 2>/dev/null || true
A_PID=""
# confirma que A está morto: socket some / recall falha
sleep 1
if "$BIN" --home "$A_HOME" status >/dev/null 2>&1; then
  bad "A ainda responde após kill -9 (teste inválido)"; exit 1
else
  ok "publicador A está morto (kill -9)"
fi

echo "== 5/5 B e C servem com A offline (banco local) =="
if recall_ok "$B_HOME" "$CID"; then
  ok "B serve o conteúdo com A morto (banco local)"
else
  bad "B perdeu o conteúdo com A morto"
fi
if recall_ok "$C_HOME" "$CID"; then
  ok "C serve o conteúdo com A morto (banco local)"
else
  bad "C perdeu o conteúdo com A morto"
fi

echo
echo "=================================================================="
echo " RESULTADO: ${PASS} PASS · ${FAIL} FAIL"
echo " Plot publicado : $CID (marker: $MARKER)"
echo " Topologia      : A(seed) -> B,C  |  A morto no passo 4"
echo " Escopo         : replicação de plot público + retenção local (E1.5)"
echo " Fora do escopo : anti-entropy/pinning R>=3, restart das réplicas, CGNAT"
echo "=================================================================="
[ "$FAIL" -eq 0 ]
