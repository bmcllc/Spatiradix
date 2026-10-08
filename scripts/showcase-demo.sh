#!/usr/bin/env bash
set -e

# ==============================================================================
# 🍄 MYCELIUM NETWORK — DEMO DA VITRINE SOBERANA
# Mostra os 4 Pilares da Nuvem Descentralizada:
# 1. 🌐 Hospedagem Web Descentralizada (Adeus AWS/Vercel)
# 2. 🐙 Forja Soberana de Código (Substituto de Git e GitHub)
# 3. 📺 Mycelium Video (Concorrente Descentralizado do YouTube)
# 4. 🕹️ MicroEasy Studio & Mycelium Store (Lojinha e Jogos Retrô)
# 5. 🌱 Sclerotium & Ghost Carrier (Dormência Biológica e Wake-on-LAN)
# ==============================================================================

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug/mycelium"
DEMO_HOME="/tmp/mycelium-showcase-node"

echo "=================================================================="
echo "🍄 INICIANDO DEMO DA VITRINE SOBERANA MYCELIUM NETWORK"
echo "=================================================================="

# 1. Compilação
echo "[1/7] Verificando binários..."
cargo build -p mycelium-cli

# Prepara diretório de demo limpo
mkdir -p "$DEMO_HOME"

# 2. Germinação da semente (Identidade + Recursos)
echo "[2/7] Germinando semente do nó..."
"$BIN" --home "$DEMO_HOME" sprout --contribute 2cpu,4gb,50gb

# 3. Teste do Pilar 5: Sclerotium & Ghost Carrier
echo "[3/7] Testando Protocolo Sclerotium (Dormência e Wake)..."
"$BIN" --home "$DEMO_HOME" sclerotium hardware
"$BIN" --home "$DEMO_HOME" sclerotium lease --ttl-minutes 720

# 4. Teste do Pilar 3: Mycelium Video (Canais e Playlists)
echo "[4/7] Configurando Canal e Playlist no Mycelium Video..."
"$BIN" --home "$DEMO_HOME" channel create "floresta-soberana" "Floresta Digital TV" --bio "Canal P2P sem censura"
"$BIN" --home "$DEMO_HOME" playlist create "Documentários P2P" --description "Vídeos da rede descentralizada"

# 5. Teste do Pilar 2: Substituto de Git e GitHub (Forja de Código)
echo "[5/7] Publicando Repositório Soberano no SporeBank..."
TMP_REPO="/tmp/mycelium-sample-repo"
mkdir -p "$TMP_REPO/src"
cat << 'EOF' > "$TMP_REPO/README.md"
# Meu App Soberano
Publicado na Mycelium Network sem GitHub!
EOF
cat << 'EOF' > "$TMP_REPO/src/main.rs"
fn main() {
    println!("Olá da Floresta P2P!");
}
EOF

"$BIN" --home "$DEMO_HOME" repo publish --repository "meu-app-soberano" --message "v1.0.0" "$TMP_REPO"

# 6. Teste do Pilar 4: Mycelium Store & Emulação
echo "[6/7] Detectando capacidades de emulação da Mycelium Store..."
"$BIN" --home "$DEMO_HOME" store caps || true

# 7. Inicialização do Daemon e Event Horizon
echo "[7/7] Despertando Event Horizon na porta 7474..."
echo "Subindo daemon em background..."
"$BIN" --home "$DEMO_HOME" daemon --horizon-port 7474 --no-mdns &
DAEMON_PID=$!

trap "echo 'Encerrando daemon...'; kill $DAEMON_PID 2>/dev/null || true; exit 0" INT TERM EXIT

echo "Aguardando inicialização do Event Horizon..."
for i in {1..30}; do
  if curl -s http://127.0.0.1:7474/health >/dev/null 2>&1; then
    echo "✅ Event Horizon online em http://127.0.0.1:7474/"
    break
  fi
  sleep 1
done

echo ""
echo "=================================================================="
echo "🌟 A VITRINE ESTÁ DISPONÍVEL NOS SEGUINTES ENDPOINTS:"
echo "=================================================================="
echo "  🍄 Vitrine da Floresta (UI Completa) : http://127.0.0.1:7474/vitrine/"
echo "  🌐 API de Overview dos 4 Pilares     : http://127.0.0.1:7474/vitrine/api/overview"
echo "  🐙 Forja de Código (Git / GitHub)    : http://127.0.0.1:7474/src/"
echo "  🕹️ Lojinha de Jogos & Emulação       : http://127.0.0.1:7474/store/"
echo "  🌱 Catálogo de Seeds                 : http://127.0.0.1:7474/seeds/"
echo "  📊 Console do Singularity             : http://127.0.0.1:7474/console"
echo "=================================================================="
echo ""

# Consulta rápida da API da Vitrine
echo "Consultando API da Vitrine em tempo real:"
curl -s http://127.0.0.1:7474/vitrine/api/overview | jq . || curl -s http://127.0.0.1:7474/vitrine/api/overview

echo ""
echo "Demo executada com sucesso! Pressione Ctrl+C para encerrar o daemon."
wait $DAEMON_PID
