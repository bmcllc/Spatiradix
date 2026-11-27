#!/usr/bin/env bash
set -e

# ==============================================================================
# 🍄 Spatiradix — COMMUNITY LAUNCHER
# Lançador integrado da Nuvem Soberana para a Comunidade
# ==============================================================================

ROOT="$(cd "$(dirname "$0")" && pwd)"
MYCELIUM_HOME="${MYCELIUM_HOME:-$ROOT/.mycelium}"
BIN="$ROOT/target/release/mycelium"

echo "========================================================================"
echo "🍄 Spatiradix — ECOSSISTEMA SOBERANO (COMUNIDADE)"
echo "========================================================================"

# Verifica ou compila o binário de release
if [ ! -f "$BIN" ]; then
    echo "[*] Compilando binário de produção (mycelium release)..."
    cargo build --release -p mycelium-cli
fi

# Inicializa o nó se ainda não existir
if [ ! -f "$MYCELIUM_HOME/gland.seed" ]; then
    echo "[*] Germinando identidade soberana do nó..."
    "$BIN" --home "$MYCELIUM_HOME" sprout --contribute 2cpu,4gb,50gb
fi

# Sobe o daemon com Event Horizon
echo "[*] Despertando Event Horizon e camada de hifas..."
"$BIN" --home "$MYCELIUM_HOME" daemon --horizon-port 7474 &
DAEMON_PID=$!

trap "echo 'Encerrando ecossistema...'; kill $DAEMON_PID 2>/dev/null || true; exit 0" INT TERM EXIT

# Aguarda Event Horizon ficar online
for i in {1..20}; do
    if curl -s http://127.0.0.1:7474/health >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo ""
echo "========================================================================"
echo "🌟 ECOSSISTEMA OPERACIONAL — PRONTO PARA USO PELA COMUNIDADE"
echo "========================================================================"
echo ""
echo "  🍄 Vitrine da Floresta (Hub Central) : http://127.0.0.1:7474/vitrine/"
echo "  🐙 Forja Soberana (Git / GitHub P2P) : http://127.0.0.1:7474/src/"
echo "  🕹️ Mycelium Store (App Store & Jogos) : http://127.0.0.1:7474/store/"
echo "  🌐 Singularity Console               : http://127.0.0.1:7474/console"
echo "  🌱 Catálogo de Seeds / Mesh          : http://127.0.0.1:7474/seeds/"
echo ""
echo "------------------------------------------------------------------------"
echo "📺 Mycelium Video (YouTube Concorrente):"
echo "   Para rodar a interface completa:"
echo "   cd \"$ROOT/../Mycelium Video/Mycelium Video\" && npm run dev"
echo "   Acesso: http://localhost:3000"
echo ""
echo "🕹️ MicroEasy Studio LITE (SDK de Jogos & Emulação):"
echo "   Para rodar o estúdio completo:"
echo "   cd \"$ROOT/../MicroEasy Studio LITE/microeasy-studio-p5-integration\" && npm run dev"
echo "   Acesso: http://localhost:3001"
echo "========================================================================"
echo ""
echo "Pressione Ctrl+C para encerrar o daemon."
wait $DAEMON_PID
