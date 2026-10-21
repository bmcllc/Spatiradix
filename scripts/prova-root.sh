#!/usr/bin/env bash
# Prova do Root: 3 "pendrives" (pastas), K=2, montado como pasta via FUSE.
# Sai 0 só se todas as afirmações passarem. Uso: bash scripts/prova-root.sh
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
B="${MYCELIUM_BIN:-$ROOT_DIR/target/debug/mycelium}"
W="$(mktemp -d)"
trap 'fusermount3 -u "$W/mnt" 2>/dev/null || true; rm -rf "$W"' EXIT
cd "$W"
ok() { echo "✔ $*"; }

"$B" root init --k 2 --label prova pendrive sdcard hd >/dev/null
mkdir -p dados/docs
echo "lista de compras" > dados/docs/lista.txt
head -c 3000000 /dev/urandom > dados/video.bin
"$B" root put pendrive sdcard -- dados >/dev/null
ok "gravado com 2 de 3 raízes (hd ausente)"

"$B" root get sdcard hd -- dados/video.bin v1 >/dev/null && cmp -s v1 dados/video.bin
ok "sdcard + hd (hd nunca viu a escrita) leem o vídeo íntegro"
"$B" root get pendrive hd -- dados/video.bin v2 >/dev/null && cmp -s v2 dados/video.bin
ok "pendrive + hd leem o vídeo íntegro"

if "$B" root ls pendrive >/dev/null 2>&1; then echo "✘ 1 raiz abriu"; exit 1; fi
ok "1 raiz sozinha não abre"
if grep -rqa "lista de compras" pendrive sdcard hd || grep -rqa "lista.txt" pendrive sdcard hd; then
    echo "✘ texto claro numa raiz"; exit 1
fi
ok "nenhuma raiz contém conteúdo ou nome em claro"

mkdir mnt
"$B" root mount pendrive hd -- mnt >/dev/null 2>&1 &
for _ in $(seq 1 50); do mountpoint -q mnt && break; sleep 0.1; done
mountpoint -q mnt
cmp -s mnt/dados/video.bin dados/video.bin
ok "montado: vídeo lido pela pasta íntegro"
printf 'um\n' > mnt/nota.txt
mkdir mnt/fotos
mv mnt/nota.txt mnt/fotos/nota.txt
printf 'dois\n' >> mnt/fotos/nota.txt
cp dados/video.bin mnt/fotos/copia.bin
rm mnt/dados/docs/lista.txt
fusermount3 -u mnt
ok "escrita, mkdir, mv, append, cp e rm pela pasta"

[ "$("$B" root get sdcard hd -- fotos/nota.txt /dev/stdout 2>/dev/null | head -2)" = "$(printf 'um\ndois')" ]
"$B" root get sdcard pendrive -- fotos/copia.bin c >/dev/null && cmp -s c dados/video.bin
if "$B" root get sdcard hd -- dados/docs/lista.txt x >/dev/null 2>&1; then echo "✘ rm não persistiu"; exit 1; fi
ok "depois de desmontar, outro par de raízes vê as mudanças"

rm -rf sdcard
"$B" root heal pendrive hd --replace 2 --into sdcard-novo >/dev/null
"$B" root get sdcard-novo hd -- fotos/copia.bin h >/dev/null && cmp -s h dados/video.bin
ok "raiz perdida recriada num meio novo"
echo "PROVA ROOT: PASSOU"
