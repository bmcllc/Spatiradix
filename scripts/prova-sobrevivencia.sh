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
#   ✓ recuperação de late-joiner via DHT (pull sob demanda, E1.3);
#   ✓ re-anúncio PERIÓDICO proativo por detentor, sem o publicador (push, E1.3).
#   ✗ NÃO prova persistência após restart das réplicas (E2.5 completo);
#   ✗ NÃO prova pinning R>=3 com recibos nem GC/quota (E1.1-E1.4);
#   ✗ NÃO prova CGNAT/multi-host (loopback apenas).
#
# Uso:  bash scripts/prova-sobrevivencia.sh
# Saída: tabela PASS/FAIL; exit 0 só se tudo passar.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${MYCELIUM_BIN:-$ROOT/target/debug/mycelium}"
BASE_PORT=18800          # porta base da malha (evita colidir com 7474/prova-zero)
HORIZON_BASE=18900
MARKER="SOBREVIVENCIA-MARKER-OK"

WORK="$(mktemp -d /tmp/prova-sobr.XXXXXXXX)"
A_HOME="$WORK/a"; B_HOME="$WORK/b"; C_HOME="$WORK/c"; D_HOME="$WORK/d"; E_HOME="$WORK/e"; P_HOME="$WORK/p"
A_LOG="$WORK/a.log"; B_LOG="$WORK/b.log"; C_LOG="$WORK/c.log"; D_LOG="$WORK/d.log"; E_LOG="$WORK/e.log"; P_LOG="$WORK/p.log"
A_PID=""; B_PID=""; C_PID=""; D_PID=""; E_PID=""; P_PID=""

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ✅ $1"; }
bad() { FAIL=$((FAIL+1)); echo "  ❌ $1"; }

cleanup() {
  for pid in "$A_PID" "$B_PID" "$C_PID" "$D_PID" "$E_PID" "$P_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  printf 'Diretório da prova e logs: %s\n' "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Confere a cópia no SporeBank sem disparar uma consulta DHT.
recall_ok() { # $1=home $2=cid
  grep -Fq "$MARKER" "$1/sporebank/plots/${2#Qm}.json" 2>/dev/null
}
status_plots() { # $1=home -> nº de plots no bank
  "$BIN" --home "$1" status 2>/dev/null | awk '/plots/{print $3; exit}'
}

echo "== 1/7 Preparando o binário =="
if [ -z "${MYCELIUM_BIN:-}" ]; then
  cargo build --locked -p mycelium-cli --manifest-path "$ROOT/Cargo.toml"
fi
[ -x "$BIN" ] || { bad "binário inválido: $BIN"; exit 1; }

for h in "$A_HOME" "$B_HOME" "$C_HOME"; do mkdir -p "$h"; done

echo "== 2/7 Subindo a malha (A seed + B,C réplicas) =="
"$BIN" --home "$A_HOME" sprout --contribute 2cpu,4gb,50gb >/dev/null
"$BIN" --home "$B_HOME" sprout --contribute 1cpu,2gb,25gb >/dev/null
"$BIN" --home "$C_HOME" sprout --contribute 1cpu,2gb,25gb >/dev/null

A_PORT=$BASE_PORT; B_PORT=$((BASE_PORT+1)); C_PORT=$((BASE_PORT+2))
RUST_LOG=info "$BIN" --home "$A_HOME" daemon --contribute 2cpu,4gb,50gb \
  --horizon-port "$HORIZON_BASE" --no-mdns --no-nostr-transport \
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
# Malha base com anti-entropy DESLIGADA: isola o pull (fase 6). O push proativo
# é provado à parte por um nó P dedicado (fase 7).
RUST_LOG=info MYCELIUM_ANTI_ENTROPY_SECS=86400 "$BIN" --home "$B_HOME" daemon --contribute 1cpu,2gb,25gb \
  --horizon-port $((HORIZON_BASE+1)) --no-mdns --no-nostr-transport \
  --listen "/ip4/127.0.0.1/tcp/$B_PORT" --bootstrap "$BOOT" >"$B_LOG" 2>&1 &
B_PID=$!
RUST_LOG=info MYCELIUM_ANTI_ENTROPY_SECS=86400 "$BIN" --home "$C_HOME" daemon --contribute 1cpu,2gb,25gb \
  --horizon-port $((HORIZON_BASE+2)) --no-mdns --no-nostr-transport \
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
# PeerIds de B e C (vivos após a morte de A). D alimenta-se de C (pull DHT);
# E alimenta-se de B (push proativo).
B_PEER=$(grep -oE '12D3Koo[A-Za-z0-9]+' "$B_LOG" | head -1)
C_PEER=$(grep -oE '12D3Koo[A-Za-z0-9]+' "$C_LOG" | head -1)
sleep 3   # deixa a lattice estabilizar antes de publicar

echo "== 3/7 A publica; B e C replicam =="
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
  ok "B e C replicaram o conteúdo (verificado no SporeBank em disco)"
else
  bad "B/C não replicaram dentro da janela (B=$(status_plots "$B_HOME") C=$(status_plots "$C_HOME") plots)"
fi

echo "== 4/7 Derrubando o publicador A =="
kill -KILL "$A_PID" || { bad "publicador A já estava offline"; exit 1; }
wait "$A_PID" 2>/dev/null || true
A_PID=""
ok "publicador A encerrado (SIGKILL)"

echo "== 5/7 B e C servem com A offline (banco local) =="
if recall_ok "$B_HOME" "$CID" &&
  "$BIN" --home "$B_HOME" recall --plot "$CID" | grep -F "$MARKER" >/dev/null; then
  ok "B serve o conteúdo com A morto (banco local)"
else
  bad "B perdeu o conteúdo com A morto"
fi
if recall_ok "$C_HOME" "$CID" &&
  "$BIN" --home "$C_HOME" recall --plot "$CID" | grep -F "$MARKER" >/dev/null; then
  ok "C serve o conteúdo com A morto (banco local)"
else
  bad "C perdeu o conteúdo com A morto"
fi

echo "== 6/7 Late-joiner D recupera via DHT (anti-entropy pull, E1.3) =="
# D entra DEPOIS da morte de A, nunca viu o gossip. Bootstrap no C — que está com
# o re-anúncio DESLIGADO, para isolar o caminho pull: recall ausente dispara
# dht_get -> C responde (guardou o record) -> resultado validado (público+hash)
# e absorvido no bank local de D.
BOOT_C="/ip4/127.0.0.1/tcp/$C_PORT/p2p/$C_PEER"
"$BIN" --home "$D_HOME" sprout --contribute 1cpu,1gb,10gb >/dev/null
RUST_LOG=info "$BIN" --home "$D_HOME" daemon --contribute 1cpu,1gb,10gb \
  --horizon-port $((HORIZON_BASE+3)) --no-mdns --no-nostr-transport \
  --listen "/ip4/127.0.0.1/tcp/$((BASE_PORT+3))" --bootstrap "$BOOT_C" >"$D_LOG" 2>&1 &
D_PID=$!
for _ in $(seq 1 60); do [ -S "$D_HOME/mycelium.sock" ] && break; sleep 0.5; done
if [ ! -S "$D_HOME/mycelium.sock" ]; then
  bad "late-joiner D não subiu; ver $D_LOG"
else
  ok "D entrou atrasado (após morte de A), bootstrap no C (sem push)"
  # Detecta se D já recebeu via re-anúncio (push) antes de qualquer consulta.
  D_ALREADY=0
  if recall_ok "$D_HOME" "$CID"; then D_ALREADY=1; fi
  # consulta DHT (recall ausente dispara dht_get) até o plot ser absorvido
  recovered=0
  for _ in $(seq 1 45); do
    "$BIN" --home "$D_HOME" recall --plot "$CID" >/dev/null 2>&1 || true
    if recall_ok "$D_HOME" "$CID"; then recovered=1; break; fi
    sleep 1
  done
  if [ "$recovered" != "1" ]; then
    bad "D não recuperou via DHT (record indisponível ou recall não baixa)"
  elif [ "$D_ALREADY" = "1" ]; then
    ok "D recebeu o conteúdo via re-anúncio antes de consultar (push proativo)"
  else
    ok "D recuperou via consulta DHT, sem ter sido alcançado pelo push (pull)"
  fi
fi

echo "== 7/7 Anti-entropy PROATIVA: E entra mudo e replica sozinho (E1.3) =="
# P é um mero detentor (não o publicador): entra com anti-entropy LIGADA (5s),
# puxa o plot do DHT e passa a REPUBLICÁ-LO periodicamente no lattice. E entra
# depois, NUNCA consulta nada, e o bank deve encher sozinho pelo re-anúncio de P
# — provando replicação proativa (push) sem depender do publicador A.
BOOT_C="/ip4/127.0.0.1/tcp/$C_PORT/p2p/$C_PEER"
"$BIN" --home "$P_HOME" sprout --contribute 1cpu,1gb,10gb >/dev/null
RUST_LOG=info,mycelium_node=debug MYCELIUM_ANTI_ENTROPY_SECS=5 "$BIN" --home "$P_HOME" daemon --contribute 1cpu,1gb,10gb \
  --horizon-port $((HORIZON_BASE+4)) --no-mdns --no-nostr-transport \
  --listen "/ip4/127.0.0.1/tcp/$((BASE_PORT+4))" --bootstrap "$BOOT_C" >"$P_LOG" 2>&1 &
P_PID=$!
for _ in $(seq 1 60); do [ -S "$P_HOME/mycelium.sock" ] && break; sleep 0.5; done
if [ ! -S "$P_HOME/mycelium.sock" ]; then
  bad "republicador P não subiu; ver $P_LOG"
else
  # P puxa o plot sob demanda (recall -> dht_get) e passa a ser detentor.
  for _ in $(seq 1 30); do
    "$BIN" --home "$P_HOME" recall --plot "$CID" >/dev/null 2>&1 || true
    recall_ok "$P_HOME" "$CID" && break
    sleep 1
  done
  if ! recall_ok "$P_HOME" "$CID"; then
    bad "P não conseguiu puxar o plot para republicá-lo; ver $P_LOG"
  else
    ok "detentor P puxou o plot do DHT e passou a republicá-lo (anti-entropy 5s)"
    sleep 4  # deixa qualquer anúncio pontual do pull passar antes de E entrar
    "$BIN" --home "$E_HOME" sprout --contribute 1cpu,1gb,10gb >/dev/null
    RUST_LOG=info "$BIN" --home "$E_HOME" daemon --contribute 1cpu,1gb,10gb \
      --horizon-port $((HORIZON_BASE+5)) --no-mdns --no-nostr-transport \
      --listen "/ip4/127.0.0.1/tcp/$((BASE_PORT+5))" --bootstrap "/ip4/127.0.0.1/tcp/$((BASE_PORT+4))/p2p/$(grep -oE '12D3Koo[A-Za-z0-9]+' "$P_LOG" | head -1)" >"$E_LOG" 2>&1 &
    E_PID=$!
    for _ in $(seq 1 60); do [ -S "$E_HOME/mycelium.sock" ] && break; sleep 0.5; done
    if [ ! -S "$E_HOME/mycelium.sock" ]; then
      bad "nó E não subiu; ver $E_LOG"
    else
      ok "E entrou após a morte de A (bootstrap no detentor P), sem consultar nada"
      # E é novo e NUNCA consulta: qualquer plot > 0 prova recebimento proativo.
      proactive=0
      for _ in $(seq 1 40); do
        # só observa o status; nenhum recall é disparado por nós
        if [ "$(status_plots "$E_HOME")" -gt 0 ] 2>/dev/null; then proactive=1; break; fi
        sleep 1
      done
      if [ "$proactive" = "1" ] && recall_ok "$E_HOME" "$CID"; then
        ok "E replicou o conteúdo sozinho (anti-entropy proativa; sem consulta)"
      else
        bad "E não recebeu o re-anúncio proativo (bank=$(status_plots "$E_HOME") plots)"
      fi
      # Prova direta: o tick periódico de P realmente republicou (>= 2 vezes).
      # E costuma receber rápido; espera o tick repetir para provar periodicidade.
      P_REANNOUNCED=0
      for _ in $(seq 1 12); do
        P_REANNOUNCED=$(grep -c 'anti-entropy: esporos públicos re-anunciados' "$P_LOG" 2>/dev/null || echo 0)
        [ "${P_REANNOUNCED:-0}" -ge 2 ] && break
        sleep 1
      done
      if [ "${P_REANNOUNCED:-0}" -ge 2 ]; then
        ok "tick periódico de P republicou o esporo ${P_REANNOUNCED}× (prova direta do re-anúncio)"
      else
        bad "P não registrou re-anúncio periódico suficiente (${P_REANNOUNCED:-0}×)"
      fi
    fi
  fi
fi

echo
echo "=================================================================="
echo " RESULTADO: ${PASS} PASS · ${FAIL} FAIL"
echo " Plot publicado : $CID (marker: $MARKER)"
echo " Topologia      : A(seed) -> B,C | A morto (4) | D pull via DHT (6) | P push<->E passivo (7)"
echo " Escopo         : replicação pública + retenção local (E1.5)"
echo "                : recuperação sob demanda via DHT (E1.3 pull)"
echo "                : re-anúncio periódico proativo por detentor (E1.3 push)"
echo " Fora do escopo : pinning R>=3 com recibos, restart das réplicas, CGNAT"
echo "=================================================================="
[ "$FAIL" -eq 0 ]
