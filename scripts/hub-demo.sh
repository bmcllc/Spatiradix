#!/usr/bin/env bash
# Demonstração end-to-end do Mycelium Code Hub (Git Soberano)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=========================================================="
echo "🍄 Mycelium Code Hub — Demonstração da Forja Soberana"
echo "=========================================================="

HOME_DIR=$(mktemp -d -t mycelium-hub-demo-XXXXXX)
trap 'rm -rf "$HOME_DIR"' EXIT

echo "📁 Usando home temporário: $HOME_DIR"

# 1. Sprout
echo "🌱 1. Plantando semente de nó..."
cargo run -p mycelium-cli -- --home "$HOME_DIR" sprout --contribute 2cpu,4gb,50gb >/dev/null

# 2. Inicia daemon em background
echo "🚀 2. Inicializando daemon com Event Horizon em :7474..."
cargo run -p mycelium-cli -- --home "$HOME_DIR" daemon --contribute 2cpu,4gb,50gb --horizon-port 7474 > "$HOME_DIR/daemon.log" 2>&1 &
DAEMON_PID=$!
trap 'kill -9 $DAEMON_PID 2>/dev/null || true; rm -rf "$HOME_DIR"' EXIT

# Aguarda daemon subir
sleep 3

# 3. Cria um projeto demo
PROJECT_DIR=$(mktemp -d -t mycelium-sample-repo-XXXXXX)
mkdir -p "$PROJECT_DIR/src"
cat << 'EOF' > "$PROJECT_DIR/src/main.rs"
// Mycelium Sovereign Sample App
fn main() {
    println!("Olá da floresta Mycelium!");
}
EOF

cat << 'EOF' > "$PROJECT_DIR/README.md"
# Projeto Soberano de Demonstração
Este projeto foi publicado diretamente na rede Mycelium, sem passar pelo GitHub.
Todos os commits são Plots imutáveis endereçados por BLAKE3.
EOF

echo "📦 3. Publicando repositório 'meu-projeto' na rede..."
cargo run -p mycelium-cli -- --home "$HOME_DIR" repo publish \
  --dir "$PROJECT_DIR" \
  --repository "meu-projeto" \
  --branch "main" \
  --message "feat: commit inicial soberano"

# 4. Testa a API do Hub
echo "🔍 4. Verificando API do Code Hub em http://127.0.0.1:7474/hub/api/repos..."
curl -s http://127.0.0.1:7474/hub/api/repos | jq .

echo
echo "🎉 Code Hub pronto!"
echo "Acesse a interface no navegador: http://127.0.0.1:7474/hub/"
