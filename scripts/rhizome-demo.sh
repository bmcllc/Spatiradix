#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Demo ao vivo (2 nós P2P locais) do Mycelium Rhizome:
# - Nó A: http://127.0.0.1:7474/rhizome/
# - Nó B: http://127.0.0.1:7475/rhizome/
# Conectados via libp2p TCP local, sincronizando perfis (com chaves ML-KEM-1024),
# feed, stories (Isotope), vídeos BLAKE3 e chat E2EE pós-quântico (DTN).
# ==============================================================================

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${MYCELIUM_BIN:-$ROOT/target/debug/mycelium}"
WORK="$(mktemp -d /tmp/mycelium-rhizome-demo.XXXXXXXX)"
HOME_A="$WORK/node-a"
HOME_B="$WORK/node-b"
PID_A=""
PID_B=""

cleanup() {
  for p in "$PID_A" "$PID_B"; do
    if [[ -n "$p" ]]; then
      kill "$p" 2>/dev/null || true
      wait "$p" 2>/dev/null || true
    fi
  done
  printf '\nLogs e estado da demo em: %s\n' "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "=================================================================="
echo "🌿 INICIANDO DEMO 2 NÓS — MYCELIUM RHIZOME SUPER-APP P2P"
echo "=================================================================="

if [[ -z "${MYCELIUM_BIN:-}" ]]; then
  echo "[1/5] Compilando mycelium-cli..."
  cargo build --offline -p mycelium-cli --manifest-path "$ROOT/Cargo.toml"
fi

mkdir -p "$HOME_A" "$HOME_B"

echo "[2/5] Configurando perfis soberanos (Gland Ed25519 + PKARR + Nostr + ML-KEM-1024)..."
"$BIN" --home "$HOME_A" rhizome profile --handle bruno --name "Bruno Floresta" --bio "Canal soberano no Mycelium Rhizome (Nó A)"
"$BIN" --home "$HOME_B" rhizome profile --handle alice --name "Alice Mesh" --bio "Nó réplica e parceira P2P (Nó B)"

echo "[3/5] Subindo Nó A (Event Horizon :7474)..."
RUST_LOG=info "$BIN" --home "$HOME_A" daemon --horizon-port 7474 \
  --listen /ip4/127.0.0.1/tcp/0 --no-mdns --no-nostr-transport >"$WORK/node-a.log" 2>&1 &
PID_A=$!

for _ in {1..40}; do
  if [[ -f "$HOME_A/listen_addrs.json" ]] && curl -fsS --max-time 2 http://127.0.0.1:7474/rhizome/api/overview >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

ADDR_A=$(python3 -c 'import json,sys; addrs=json.load(open(sys.argv[1])); print(next(a for a in addrs if "/tcp/" in a and "/quic" not in a))' "$HOME_A/listen_addrs.json")

echo "[4/5] Subindo Nó B (Event Horizon :7475) conectado ao Nó A ($ADDR_A)..."
RUST_LOG=info "$BIN" --home "$HOME_B" daemon --horizon-port 7475 \
  --listen /ip4/127.0.0.1/tcp/0 --bootstrap "$ADDR_A" --no-mdns --no-nostr-transport >"$WORK/node-b.log" 2>&1 &
PID_B=$!

for _ in {1..40}; do
  if curl -fsS --max-time 2 http://127.0.0.1:7475/rhizome/api/overview >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

echo "[5/5] Publicando post inaugural e story efêmero no Nó A..."
"$BIN" --home "$HOME_A" rhizome post "Bem-vindo ao Mycelium Rhizome! Vídeo BLAKE3, Stories Isotope, Microblog X e Chat Pós-Quântico ML-KEM-1024 rodando 100% P2P. #Mycelium #Rhizome"
"$BIN" --home "$HOME_A" rhizome story "Story efêmero 24h via Isotope AtomSync!" --ttl-hours 24
"$BIN" --home "$HOME_A" rhizome sync >/dev/null 2>&1 || true
"$BIN" --home "$HOME_B" rhizome sync >/dev/null 2>&1 || true

echo ""
echo "=================================================================="
echo "✅ MYCELIUM RHIZOME ATIVO (2 NÓS CONECTADOS VIA LIBP2P)"
echo "   👉 Nó A (@bruno): http://127.0.0.1:7474/rhizome/"
echo "   👉 Nó B (@alice): http://127.0.0.1:7475/rhizome/"
echo "   📡 RSS 2.0 Nó A : http://127.0.0.1:7474/rhizome/feed.xml"
echo "   🌐 ActivityPub  : http://127.0.0.1:7474/rhizome/ap/actor"
echo "   Pressione Ctrl+C para encerrar os dois nós."
echo "=================================================================="
wait
