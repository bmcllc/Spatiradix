#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Demo local da Vitrine e do Event Horizon.
# Cria um canal, uma playlist e uma credencial Sclerotium de teste.
# Verifica publicação, clonagem e leitura HTTP de um repositório de exemplo.
# ==============================================================================

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${MYCELIUM_BIN:-$ROOT/target/debug/mycelium}"
WORK="$(mktemp -d /tmp/mycelium-showcase.XXXXXXXX)"
DEMO_HOME="$WORK/node"
DAEMON_LOG="$WORK/daemon.log"
DAEMON_PID=""

cleanup() {
  if [[ -n "$DAEMON_PID" ]]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  printf 'Diretório da demonstração e logs: %s\n' "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "=================================================================="
echo "🍄 INICIANDO DEMO DA VITRINE SOBERANA Spatiradix"
echo "=================================================================="

# 1. Compilação
echo "[1/7] Verificando binários..."
if [[ -z "${MYCELIUM_BIN:-}" ]]; then
  cargo build --locked -p mycelium-cli --manifest-path "$ROOT/Cargo.toml"
fi

# Prepara diretório de demo limpo
mkdir -p "$DEMO_HOME"

# 2. Germinação da semente (Identidade + Recursos)
echo "[2/7] Germinando semente do nó..."
"$BIN" --home "$DEMO_HOME" sprout --contribute 2cpu,4gb,50gb

# 3. Teste do Pilar 5: Sclerotium & Ghost Carrier
echo "[3/7] Gerando uma credencial Sclerotium de teste..."
"$BIN" --home "$DEMO_HOME" sclerotium lease --ttl-minutes 720 --mac 02:00:00:00:00:01 >/dev/null

# 4. Teste do Pilar 3: Mycelium Video (Canais e Playlists)
echo "[4/7] Configurando Canal e Playlist no Mycelium Video..."
"$BIN" --home "$DEMO_HOME" channel create "floresta-soberana" "Floresta Digital TV" --bio "Canal P2P sem censura"
"$BIN" --home "$DEMO_HOME" playlist create "Documentários P2P" --description "Vídeos da rede descentralizada"

# 5. Inicialização do Daemon e Event Horizon
echo "[5/7] Iniciando o Event Horizon local..."
RUST_LOG=info "$BIN" --home "$DEMO_HOME" daemon --horizon-port 0 \
  --listen /ip4/127.0.0.1/tcp/0 --no-mdns --no-nostr-transport >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

echo "Aguardando inicialização do Event Horizon..."
BASE=""
for _ in {1..30}; do
  BASE=$(sed -nE 's/.*event horizon escutando.*(127\.0\.0\.1:[0-9]+).*/http:\/\/\1/p' "$DAEMON_LOG" | tail -1)
  if [[ -n "$BASE" ]] && curl -fsS --max-time 2 "$BASE/health" >/dev/null 2>&1; then
    break
  fi
  BASE=""
  kill -0 "$DAEMON_PID" 2>/dev/null || break
  sleep 1
done
[[ -n "$BASE" ]] || { echo "Event Horizon indisponível. Veja $DAEMON_LOG." >&2; exit 1; }

# 6. Publicação e leitura na Forja
echo "[6/7] Publicando Repositório Soberano no SporeBank..."
TMP_REPO="$WORK/sample-repo"
mkdir -p "$TMP_REPO/src"
cat << 'EOF' > "$TMP_REPO/README.md"
# Meu App Soberano
Publicado em um nó local da Spatiradix.
EOF
cat << 'EOF' > "$TMP_REPO/src/main.rs"
fn main() {
    println!("Olá da Floresta P2P!");
}
EOF

PUBLICATION=$("$BIN" --home "$DEMO_HOME" repo publish --repository "meu-app-soberano" --message "v1.0.0" --dir "$TMP_REPO")
CID=$(sed -nE 's/.*ContentId[[:space:]]*: (Qm[0-9a-f]{64}).*/\1/p' <<<"$PUBLICATION")
[[ -n "$CID" ]] || { echo "Publicação sem ContentId." >&2; exit 1; }
curl -fsS --max-time 5 "$BASE/vitrine/api/repos" | grep -F "$CID" >/dev/null
"$BIN" --home "$DEMO_HOME" repo clone --cid "$CID" --dest "$WORK/clone" >/dev/null
cmp "$TMP_REPO/README.md" "$WORK/clone/README.md"
cmp "$TMP_REPO/src/main.rs" "$WORK/clone/src/main.rs"
curl -fsS --max-time 5 "$BASE/src/$CID/README.md" -o "$WORK/README.http.md"
cmp "$TMP_REPO/README.md" "$WORK/README.http.md"
printf 'Repositório conferido após clonagem e acesso HTTP: %s/src/%s\n' "$BASE" "$CID"

# 7. Teste do Pilar 4: Mycelium Store & Emulação
echo "[7/7] Detectando capacidades de emulação da Mycelium Store..."
"$BIN" --home "$DEMO_HOME" store caps || true

for route in /vitrine/ /vitrine/api/overview /src/ "/src/$CID" /store/ /seeds/ /console; do
  if ! curl -fsSL --max-time 5 "$BASE$route" >/dev/null; then
    printf 'Falha ao validar %s\n' "$BASE$route" >&2
    exit 1
  fi
done

echo ""
echo "=================================================================="
echo "🌟 A VITRINE ESTÁ DISPONÍVEL NOS SEGUINTES ENDPOINTS:"
echo "=================================================================="
echo "  🍄 Vitrine da Floresta : $BASE/vitrine/"
echo "  🐙 Forja de Código     : $BASE/src/"
echo "  🕹️ Mycelium Store      : $BASE/store/"
echo "  🌱 Catálogo de Seeds   : $BASE/seeds/"
echo "  📊 Console             : $BASE/console"
echo "=================================================================="
echo ""

echo ""
echo "Demo executada com sucesso! Pressione Ctrl+C para encerrar o daemon."
wait $DAEMON_PID
