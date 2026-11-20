#!/usr/bin/env bash
# Demo ponta a ponta do motor de emissão mainnet (mycelium-mint, 1 MYC = 8 USDC)
# com 2 nós reais conectados via bootstrap TCP/libp2p e liquidação pelo Gossipsub.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${MYCELIUM_BIN:-$ROOT/target/debug/mycelium}"

if [ ! -x "$BIN" ]; then
  echo "[mint-demo] compilando mycelium-cli..."
  (cd "$ROOT" && cargo build -p mycelium-cli)
fi

WORK_DIR="$(mktemp -d /tmp/mycelium-mint-2nodes.XXXXXX)"
NODE_A="$WORK_DIR/node-a"
NODE_B="$WORK_DIR/node-b"
mkdir -p "$NODE_A" "$NODE_B"

PIDA=""
PIDB=""
cleanup() {
  [ -n "$PIDB" ] && kill "$PIDB" 2>/dev/null || true
  [ -n "$PIDA" ] && kill "$PIDA" 2>/dev/null || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

echo "[mint-demo] subindo node-a (esporocarpo + --mint-mainnet)..."
"$BIN" --home "$NODE_A" daemon --sporocarp --mint-mainnet --assume-reachable --no-mdns \
  --listen /ip4/127.0.0.1/tcp/14101 > "$NODE_A/daemon.log" 2>&1 &
PIDA=$!

for _ in $(seq 1 40); do
  [ -S "$NODE_A/mycelium.sock" ] && [ -f "$NODE_A/mint_state.json" ] && break
  sleep 0.25
done

PEER_A=$("$BIN" --home "$NODE_A" status | awk '/PeerId/ {print $NF}')
ADDR_A="/ip4/127.0.0.1/tcp/14101/p2p/$PEER_A"
echo "[mint-demo] node-a pronto: $ADDR_A"

# Compartilha o mesmo gênesis mint_state.json com o nó produtor (sem --sporocarp)
cp "$NODE_A/mint_state.json" "$NODE_B/mint_state.json"

echo "[mint-demo] subindo node-b (produtor) conectado a node-a..."
"$BIN" --home "$NODE_B" daemon --no-mdns --listen /ip4/127.0.0.1/tcp/14102 \
  --bootstrap "$ADDR_A" > "$NODE_B/daemon.log" 2>&1 &
PIDB=$!

for _ in $(seq 1 40); do
  [ -S "$NODE_B/mycelium.sock" ] && break
  sleep 0.25
done
sleep 2.5

echo "[mint-demo] node-b submetendo WorkClaim via Gossipsub..."
"$BIN" --home "$NODE_B" mint claim \
  --work-id 3333333333333333333333333333333333333333333333333333333333333333 \
  --kind compute --units 25 --epoch 0 \
  --counterparty-seed 4444444444444444444444444444444444444444444444444444444444444444 \
  --hashcash-bits 12

sleep 2.0

echo "=== NODE-A (esporocarpo) ==="
STATUS_A=$("$BIN" --home "$NODE_A" mint status)
echo "$STATUS_A"

echo "=== NODE-B (produtor) ==="
STATUS_B=$("$BIN" --home "$NODE_B" mint status)
echo "$STATUS_B"

echo "$STATUS_A" | grep -q "época atual  : 1"
echo "$STATUS_B" | grep -q "época atual  : 1"
echo "$STATUS_A" | grep -q "2.50000000 / 21000000.00000000 MYC"
echo "$STATUS_B" | grep -q "1 MYC = 8 USDC (total ≈ 20.00 USDC)"
grep -q "mainnet-mint:epoch=0:" "$NODE_B/ledger.json"

echo "[mint-demo] OK — emissão mainnet liquidada e creditada via Gossipsub!"
