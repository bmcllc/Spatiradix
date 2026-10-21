#!/usr/bin/env bash
# Prova em 2 máquinas reais: nó anônimo (A) × visitante (B), sem seed/DNS/VPS.
#
#   Máquina A (Tor rodando em 127.0.0.1:9050):
#     bash scripts/prova-2-maquinas.sh anon
#   → imprime um endereço myc1… e um NONCE; deixa rodando.
#
#   Máquina B (outra rede, ex.: celular roteando 4G para um notebook):
#     bash scripts/prova-2-maquinas.sh visitante 'myc1…' NONCE
#
# Cada lado grava um relatório em $PROVA_HOME/relatorio-<papel>.txt.
# Nada de IP é gravado: a distinção entre máquinas é o hash do machine-id.
set -euo pipefail

ROLE="${1:-}"
# Binário mais novo entre release e debug (um release antigo não tem `pkarr`).
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${MYCELIUM_BIN:-$(ls -t "$ROOT_DIR/target/release/mycelium" "$ROOT_DIR/target/debug/mycelium" 2>/dev/null | head -1)}"
[ -x "${BIN:-}" ] || { echo "binário mycelium não encontrado (cargo build -p mycelium-cli)"; exit 1; }
"$BIN" pkarr --help >/dev/null 2>&1 || { echo "$BIN não tem 'pkarr': recompile (cargo build -p mycelium-cli)"; exit 1; }
PROVA_HOME="${PROVA_HOME:-$HOME/.mycelium-prova-$ROLE}"
TOR="${TOR_SOCKS:-127.0.0.1:9050}"
RELAY_A="${RELAY_A:-wss://relay.primal.net}"
RELAY_B="${RELAY_B:-wss://nostr.wine}"
HORIZON="${HORIZON_PORT:-17500}"
mkdir -p "$PROVA_HOME"
REPORT="$PROVA_HOME/relatorio-$ROLE.txt"

log() { echo "[$(date -u +%FT%TZ)] $*" | tee -a "$REPORT"; }
mid() { (cat /etc/machine-id 2>/dev/null || hostname) | sha256sum | cut -c1-16; }
neighbors() { "$BIN" --home "$PROVA_HOME/node" status 2>/dev/null | grep -oE 'vizinhos +: [0-9]+' | grep -oE '[0-9]+$' || echo 0; }

: > "$REPORT"
log "papel=$ROLE máquina=$(mid) binário=$("$BIN" --version 2>/dev/null || echo '?')"

case "$ROLE" in
anon)
    curl -s --max-time 40 --socks5-hostname "$TOR" https://check.torproject.org/api/ip | grep -q '"IsTor":true' \
        || { log "FALHA: Tor não responde em $TOR"; exit 1; }
    log "Tor ok em $TOR"
    "$BIN" --home "$PROVA_HOME/node" daemon --anonymous --anon-socks "$TOR" \
        --nostr-relay "$RELAY_A" --horizon-port "$HORIZON" >"$PROVA_HOME/daemon.log" 2>&1 &
    DAEMON=$!
    trap 'kill $DAEMON 2>/dev/null' EXIT
    sleep 20
    [ -f "$PROVA_HOME/node/pkarr/master.key" ] || "$BIN" --home "$PROVA_HOME/node" pkarr init >/dev/null
    NONCE="prova-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    SITE="$PROVA_HOME/site"; mkdir -p "$SITE"
    printf '<!doctype html><meta charset=utf-8><title>prova</title><h1>%s</h1>\n' "$NONCE" > "$SITE/index.html"
    CID=$("$BIN" --home "$PROVA_HOME/node" seed-code --path "$SITE" --name prova --description prova 2>&1 \
        | grep -oE 'Qm[0-9a-f]{64}' | tail -1)
    log "site publicado cid=$CID"
    "$BIN" --home "$PROVA_HOME/node" pkarr publish --from-node --plot "${CID#Qm}" --socks "$TOR" | tee -a "$REPORT"
    ADDR=$("$BIN" --home "$PROVA_HOME/node" pkarr address)
    echo
    echo "=================================================================="
    echo " Na máquina B rode:"
    echo "   bash scripts/prova-2-maquinas.sh visitante '$ADDR' $NONCE"
    echo "=================================================================="
    log "endereço=$ADDR nonce=$NONCE"
    # Auditoria contínua: nenhuma conexão fora do Tor, nenhum UDP.
    while kill -0 "$DAEMON" 2>/dev/null; do
        PID=$(pgrep -f "home $PROVA_HOME/node daemon" | head -1 || true)
        [ -n "$PID" ] || break
        out=$(ss -tnp 2>/dev/null | grep "pid=$PID," | grep -v "$TOR" | grep -vc '127.0.0.1:.*127.0.0.1' || true)
        udp=$(ss -unap 2>/dev/null | grep -c "pid=$PID," || true)
        log "vizinhos=$(neighbors) tcp_fora_do_tor=$out udp=$udp"
        [ "$out" = 0 ] && [ "$udp" = 0 ] || log "ALERTA: tráfego fora do Tor"
        "$BIN" --home "$PROVA_HOME/node" pkarr publish --from-node --plot "${CID#Qm}" --socks "$TOR" >/dev/null 2>&1 || true
        sleep 60
    done
    ;;
visitante)
    ADDR="${2:?endereço myc1… obrigatório}"; NONCE="${3:?NONCE obrigatório}"
    "$BIN" --home "$PROVA_HOME/node" daemon --no-mdns --nostr-transport \
        --nostr-relay "$RELAY_B" --horizon-port "$HORIZON" >"$PROVA_HOME/daemon.log" 2>&1 &
    DAEMON=$!
    trap 'kill $DAEMON 2>/dev/null' EXIT
    sleep 20
    log "vizinhos antes do connect=$(neighbors)"
    SOCKS_ARGS=(--unsafe-direct)
    curl -s --max-time 20 --socks5-hostname "$TOR" https://check.torproject.org/api/ip >/dev/null 2>&1 \
        && SOCKS_ARGS=(--socks "$TOR")
    "$BIN" --home "$PROVA_HOME/node" pkarr connect "$ADDR" "${SOCKS_ARGS[@]}" | tee -a "$REPORT"
    for _ in $(seq 1 40); do [ "$(neighbors)" -ge 1 ] && break; sleep 5; done
    log "vizinhos depois do connect=$(neighbors)"
    [ "$(neighbors)" -ge 1 ] || { log "FALHA: não conectou"; exit 1; }
    OK=""
    for _ in $(seq 1 30); do
        body=$(curl -s "http://127.0.0.1:$HORIZON/myc/$ADDR/" || true)
        if echo "$body" | grep -q "$NONCE"; then OK=1; break; fi
        sleep 5
    done
    if [ -n "$OK" ]; then
        log "PASSOU: site do nó anônimo servido pelo gateway local com o nonce $NONCE"
    else
        log "FALHA: nonce não chegou pelo gateway"; exit 1
    fi
    ;;
*)
    echo "uso: $0 anon | visitante 'myc1…' NONCE"; exit 2 ;;
esac
