#!/usr/bin/env bash
# Demonstração end-to-end do TheField (Forja Soberana Git P2P & Signals)
set -e

DEMO_DIR="/tmp/mycelium-field-demo"
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR/meu-app-soberano/src"

echo "🌌 TheField — Demonstração da Forja Soberana de Código & Signals"
echo "----------------------------------------------------------------"

cat << 'EOF' > "$DEMO_DIR/meu-app-soberano/README.md"
# Meu App Soberano no TheField

Este repositório está versionado em blocos BLAKE3 distribuídos pela malha Mycelium, com colaboração por Signals no TheField.
EOF

cat << 'EOF' > "$DEMO_DIR/meu-app-soberano/src/main.rs"
fn main() {
    println!("Olá do TheField (Git Soberano P2P)!");
}
EOF

echo "📦 1. Compilando CLI Mycelium..."
cargo build -p mycelium-cli --quiet

BIN="./target/debug/mycelium"

echo "🚀 2. Publicando repositório 'meu-app-soberano' na malha local..."
$BIN repo publish \
  --dir "$DEMO_DIR/meu-app-soberano" \
  --repository "meu-app-soberano" \
  --branch "main" \
  --message "feat: inicialização do repositório no TheField"

echo "🔍 3. Verificando API do TheField em http://127.0.0.1:7474/field/api/repos..."
curl -s http://127.0.0.1:7474/field/api/repos | jq . || true

echo ""
echo "🎉 TheField pronto!"
echo "Acesse a interface no navegador: http://127.0.0.1:7474/field/"
