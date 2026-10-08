#!/usr/bin/env bash
# =============================================================================
# 🍄 PROVA ANTI-ENTROPY — reconciliação periódica + repin sem publicador (E1.3)
#
# Critério E1.3 de EVOLUCAO.md, validado em malha real (loopback):
#   Cenário 1 — reconciliação por MANIFESTO:
#     H detém um plot e anuncia os IDs (manifesto) SEM push de bytes; o nó
#     passivo Y aprende o ContentId pelo manifesto e o puxa do DHT sozinho.
#   Cenário 2 — detecção de detentor OFFLINE + repin:
#     P publica e mantém cópias em B e C. C cai (kill -9); P detecta a queda
#     pelo índice de detentores e dispara repin — recompondo cópias nos nós
#     vivos, sem depender do publicador.
#
# O que isso prova (e o que não):
#   ✓ anti-entropy dirigida por manifesto de IDs (pull do que falta);
#   ✓ detecção de peer offline e repin automático de cópias.
#   ✗ NÃO prova reconexão após queda de relay (depende de E3, multi-host/CGNAT).
#
# Uso:  bash scripts/prova-anti-entropy.sh
# Saída: tabela PASS/FAIL; exit 0 só se tudo passar.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug/mycelium"
BASE_PORT=19100
HORIZON_BASE=19200
MARKER="ANTIENTROPY-MARKER-OK"

H_HOME="/tmp/ae-h"; Y_HOME="/tmp/ae-y"
P_HOME="/tmp/ae-p"; B_HOME="/tmp/ae-b"; C_HOME="/tmp/ae-c"; E_HOME="/tmp/ae-e"
H_LOG="/tmp/ae-h.log"; Y_LOG="/tmp/ae-y.log"
P_LOG="/tmp/ae-p.log"; B_LOG="/tmp/ae-b.log"; C_LOG="/tmp/ae-c.log"; E_LOG="/tmp/ae-e.log"
H_PID=""; Y_PID=""; P_PID=""; B_PID=""; C_PID=""; E_PID=""

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ✅ $1"; }
bad() { FAIL=$((FAIL+1)); echo "  ❌ $1"; }

cleanup() {
  for pid in "$H_PID" "$Y_PID" "$P_PID" "$B_PID" "$C_PID" "$E_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

# recall: exit 0 e imprime a mensagem se o plot está no bank LOCAL do nó.
recall_ok() { # $1=home $2=cid
  "$BIN" --home "$1" recall --plot "$2" 2>/dev/null | grep -q "$MARKER"
}
status_plots() { # $1=home -> nº de plots no bank
  "$BIN" --home "$1" status 2>/dev/null | awk '/plots/{print $3; exit}'
}
wait_sock() { # $1=home $2=log -> espera o control socket
  for _ in $(seq 1 60); do [ -S "$1/mycelium.sock" ] && return 0; sleep 0.5; done
  return 1
}
peer_of() { grep -oE '12D3Koo[A-Za-z0-9]+' "$1" | head -1; }

echo "== 1/2 Compilando o nó =="
cargo build -p mycelium-cli --manifest-path "$ROOT/Cargo.toml"

rm -rf "$H_HOME" "$Y_HOME" "$P_HOME" "$B_HOME" "$C_HOME" "$E_HOME" \
       "$H_LOG" "$Y_LOG" "$P_LOG" "$B_LOG" "$C_LOG" "$E_LOG"
for h in "$H_HOME" "$Y_HOME" "$P_HOME" "$B_HOME" "$C_HOME" "$E_HOME"; do mkdir -p "$h"; done

# =============================================================================
echo "== Cenário 1/2: manifesto anti-entropy puxa o que falta (E1.3) =="
H_PORT=$BASE_PORT
"$BIN" --home "$H_HOME" sprout --contribute 1cpu,1gb,10gb >/dev/null
# H anuncia por MANIFESTO apenas (PUSH=0): não envia os bytes, só os IDs.
RUST_LOG=info,mycelium_node=debug MYCELIUM_ANTI_ENTROPY_SECS=3 MYCELIUM_ANTI_ENTROPY_PUSH=0 \
  "$BIN" --home "$H_HOME" daemon --contribute 1cpu,1gb,10gb \
  --horizon-port "$HORIZON_BASE" --no-mdns \
  --listen "/ip4/127.0.0.1/tcp/$H_PORT" >"$H_LOG" 2>&1 &
H_PID=$!
if ! wait_sock "$H_HOME"; then bad "H não subiu; ver $H_LOG"; exit 1; fi
H_PEER=$(peer_of "$H_LOG")
ok "H no ar só-anúncio (PUSH=0), PeerId ${H_PEER:0:18}…"

SOW=$("$BIN" --home "$H_HOME" sow --message "$MARKER" --path "app.rs" --content 'fn main(){}' 2>&1) || {
  bad "sow falhou: $SOW"; exit 1; }
CID=$(echo "$SOW" | grep -oE 'Qm[0-9a-f]{40,}' | head -1 || true)
if [ -z "$CID" ]; then bad "sow não devolveu CID: $SOW"; exit 1; fi
ok "H publicou plot $CID"

# Y entra passivo: nunca consulta o usuário; deve aprender o CID pelo manifesto.
"$BIN" --home "$Y_HOME" sprout --contribute 1cpu,1gb,10gb >/dev/null
RUST_LOG=info,mycelium_node=debug "$BIN" --home "$Y_HOME" daemon --contribute 1cpu,1gb,10gb \
  --horizon-port $((HORIZON_BASE+1)) --no-mdns \
  --listen "/ip4/127.0.0.1/tcp/$((BASE_PORT+1))" \
  --bootstrap "/ip4/127.0.0.1/tcp/$H_PORT/p2p/$H_PEER" >"$Y_LOG" 2>&1 &
Y_PID=$!
if ! wait_sock "$Y_HOME"; then bad "Y não subiu; ver $Y_LOG"; exit 1; fi

manifest_pull=0
for _ in $(seq 1 30); do
  grep -q 'manifesto revelou plots ausentes' "$Y_LOG" && { manifest_pull=1; break; }
  sleep 1
done
if [ "$manifest_pull" = "1" ]; then
  ok "Y aprendeu o ContentId pelo manifesto e disparou pull DHT (sem push de bytes)"
else
  bad "Y não registrou pull dirigido por manifesto (ver $Y_LOG)"
fi

got=0
for _ in $(seq 1 20); do [ "$(status_plots "$Y_HOME")" -gt 0 ] 2>/dev/null && { got=1; break; }; sleep 1; done
if [ "$got" = "1" ] && recall_ok "$Y_HOME" "$CID"; then
  ok "Y passou a deter o plot sozinho (reconciliação por manifesto)"
else
  bad "Y não absorveu o plot (bank=$(status_plots "$Y_HOME") plots)"
fi

# =============================================================================
echo "== Cenário 2/2: detecção de detentor offline + repin (E1.3) =="
P_PORT=$((BASE_PORT+2)); B_PORT=$((BASE_PORT+3)); C_PORT=$((BASE_PORT+4)); E_PORT=$((BASE_PORT+5))
"$BIN" --home "$P_HOME" sprout --contribute 1cpu,1gb,10gb >/dev/null
RUST_LOG=info,mycelium_node=debug MYCELIUM_ANTI_ENTROPY_SECS=4 \
  "$BIN" --home "$P_HOME" daemon --contribute 1cpu,1gb,10gb \
  --horizon-port $((HORIZON_BASE+2)) --no-mdns \
  --listen "/ip4/127.0.0.1/tcp/$P_PORT" >"$P_LOG" 2>&1 &
P_PID=$!
if ! wait_sock "$P_HOME"; then bad "P não subiu; ver $P_LOG"; exit 1; fi
P_PEER=$(peer_of "$P_LOG")
BOOT_P="/ip4/127.0.0.1/tcp/$P_PORT/p2p/$P_PEER"

SOW2=$("$BIN" --home "$P_HOME" sow --message "$MARKER" --path "app.rs" --content 'fn main(){}' 2>&1) || {
  bad "sow P falhou: $SOW2"; exit 1; }
CID2=$(echo "$SOW2" | grep -oE 'Qm[0-9a-f]{40,}' | head -1 || true)
if [ -z "$CID2" ]; then bad "sow P não devolveu CID: $SOW2"; exit 1; fi
ok "P publicou plot $CID2"

"$BIN" --home "$B_HOME" sprout --contribute 1cpu,1gb,10gb >/dev/null
"$BIN" --home "$C_HOME" sprout --contribute 1cpu,1gb,10gb >/dev/null
RUST_LOG=info,mycelium_node=debug MYCELIUM_ANTI_ENTROPY_SECS=4 \
  "$BIN" --home "$B_HOME" daemon --contribute 1cpu,1gb,10gb \
  --horizon-port $((HORIZON_BASE+3)) --no-mdns \
  --listen "/ip4/127.0.0.1/tcp/$B_PORT" --bootstrap "$BOOT_P" >"$B_LOG" 2>&1 &
B_PID=$!
RUST_LOG=info,mycelium_node=debug MYCELIUM_ANTI_ENTROPY_SECS=4 \
  "$BIN" --home "$C_HOME" daemon --contribute 1cpu,1gb,10gb \
  --horizon-port $((HORIZON_BASE+4)) --no-mdns \
  --listen "/ip4/127.0.0.1/tcp/$C_PORT" --bootstrap "$BOOT_P" >"$C_LOG" 2>&1 &
C_PID=$!
if ! wait_sock "$B_HOME" || ! wait_sock "$C_HOME"; then bad "B/C não subiram"; exit 1; fi

repl=0
for _ in $(seq 1 30); do recall_ok "$B_HOME" "$CID2" && recall_ok "$C_HOME" "$CID2" && { repl=1; break; }; sleep 1; done
if [ "$repl" = "1" ]; then ok "B e C detêm o plot (2 detentores além de P)"
else bad "B/C não replicaram (B=$(status_plots "$B_HOME") C=$(status_plots "$C_HOME"))"; fi

# Deixa os manifestos de B e C chegarem a P (>= 2 ticks de 4s) para P indexar
# ambos como detentores.
sleep 10

kill -9 "$C_PID" 2>/dev/null || true
wait "$C_PID" 2>/dev/null || true
C_PID=""
ok "detentor C derrubado (kill -9)"

repin=0
for _ in $(seq 1 15); do
  grep -q 'detentor offline' "$P_LOG" && { repin=1; break; }
  sleep 1
done
if [ "$repin" = "1" ]; then
  ok "P detectou o detentor offline e disparou repin (ver $P_LOG)"
else
  bad "P não registrou repin após a queda de C (ver $P_LOG)"
fi

# E entra após a queda; o conteúdo deve seguir disponível em >= 2 nós (B, E).
"$BIN" --home "$E_HOME" sprout --contribute 1cpu,1gb,10gb >/dev/null
RUST_LOG=info,mycelium_node=debug MYCELIUM_ANTI_ENTROPY_SECS=4 \
  "$BIN" --home "$E_HOME" daemon --contribute 1cpu,1gb,10gb \
  --horizon-port $((HORIZON_BASE+5)) --no-mdns \
  --listen "/ip4/127.0.0.1/tcp/$E_PORT" --bootstrap "$BOOT_P" >"$E_LOG" 2>&1 &
E_PID=$!
if ! wait_sock "$E_HOME"; then
  bad "E não subiu; ver $E_LOG"
else
  got_e=0
  for _ in $(seq 1 20); do recall_ok "$E_HOME" "$CID2" && { got_e=1; break; }; sleep 1; done
  if [ "$got_e" = "1" ] && recall_ok "$B_HOME" "$CID2"; then
    ok "após C cair, o plot segue em B e chega a E (cópias recompostas sem o publicador)"
  else
    bad "cópias não recompostas (B=$(status_plots "$B_HOME") E=$(status_plots "$E_HOME"))"
  fi
fi

echo
echo "=================================================================="
echo " RESULTADO: ${PASS} PASS · ${FAIL} FAIL"
echo " Cenário 1 : manifesto H(${CID:0:14}…) -> pull DHT por Y (sem push)"
echo " Cenário 2 : P publica -> B,C ; C morre -> repin em P ; E recompleta"
echo " Escopo    : anti-entropy por manifesto + detecção offline/repin (E1.3)"
echo " Fora      : reconexão de relay / multi-host (depende de E3)"
echo "=================================================================="
[ "$FAIL" -eq 0 ]
