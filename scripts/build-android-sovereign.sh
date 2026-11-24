#!/usr/bin/env bash
# ==============================================================================
# Build 100% Soberano para Android ARM64 (Zero Google SDK/NDK, Zero Gradle, Zero Termux)
# Compila daemon estático (aarch64-unknown-linux-musl) + Forja APK assinado (v1+v2) em Rust puro
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOV_DIR="$ROOT_DIR/.android-sovereign"
SYSROOT="$SOV_DIR/musl-sysroot"
BIN_DIR="$SOV_DIR/bin"
DIST_DIR="$ROOT_DIR/dist"
KEY_FILE="$SOV_DIR/mycelium-release.p256.key"
MUSL_VER="1.2.5"
MUSL_TARBALL="$SOV_DIR/musl-${MUSL_VER}.tar.gz"

echo "[1/7] Verificando ferramentas soberanas no host (rustup, clang, lld, qemu-aarch64-static, openssl)..."
for tool in rustup cargo make curl tar qemu-aarch64-static openssl readelf file; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ERRO: ferramenta obrigatória ausente: $tool" >&2
    exit 1
  fi
done

CLANG_BIN="$(command -v clang || command -v clang-19)"
LLD_BIN="$(command -v ld.lld || command -v ld.lld-19 || command -v lld)"
AR_BIN="$(command -v llvm-ar || command -v ar)"
RANLIB_BIN="$(command -v llvm-ranlib || command -v ranlib)"
STRIP_BIN="$(command -v llvm-strip || true)"

mkdir -p "$SOV_DIR" "$SYSROOT" "$BIN_DIR" "$DIST_DIR"

echo "[2/7] Garantindo target Rust aarch64-unknown-linux-musl..."
if ! rustup target list --installed | grep -qx "aarch64-unknown-linux-musl"; then
  rustup target add aarch64-unknown-linux-musl
fi

echo "[3/7] Garantindo headers MIT do musl libc ${MUSL_VER} (sem Google NDK / Bionic)..."
if [[ ! -f "$SYSROOT/include/stdio.h" ]] || [[ ! -f "$SYSROOT/include/bits/syscall.h" ]]; then
  if [[ ! -f "$MUSL_TARBALL" ]]; then
    curl -fsSL "https://musl.libc.org/releases/musl-${MUSL_VER}.tar.gz" -o "$MUSL_TARBALL"
  fi
  TMP_MUSL="$(mktemp -d)"
  tar -xzf "$MUSL_TARBALL" -C "$TMP_MUSL"
  make -C "$TMP_MUSL/musl-${MUSL_VER}" ARCH=aarch64 prefix="$TMP_MUSL/out" install-headers
  mkdir -p "$SYSROOT"
  rm -rf "$SYSROOT/include"
  cp -a "$TMP_MUSL/out/include" "$SYSROOT/include"
  rm -rf "$TMP_MUSL"
fi

cat > "$BIN_DIR/aarch64-musl-cc" <<EOF
#!/usr/bin/env bash
exec "$CLANG_BIN" --target=aarch64-linux-musl -isystem "$SYSROOT/include" "\$@"
EOF
chmod +x "$BIN_DIR/aarch64-musl-cc"

cat > "$BIN_DIR/aarch64-musl-ld" <<EOF
#!/usr/bin/env bash
exec "$LLD_BIN" -m aarch64linux "\$@"
EOF
chmod +x "$BIN_DIR/aarch64-musl-ld"

echo "[4/7] Compilando mycelium CLI/Daemon estático ARM64 (aarch64-unknown-linux-musl)..."
(
  cd "$ROOT_DIR"
  export CC_aarch64_unknown_linux_musl="$BIN_DIR/aarch64-musl-cc"
  export AR_aarch64_unknown_linux_musl="$AR_BIN"
  export RANLIB_aarch64_unknown_linux_musl="$RANLIB_BIN"
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$BIN_DIR/aarch64-musl-ld"
  export RUSTFLAGS="-C target-feature=+crt-static ${RUSTFLAGS:-}"
  cargo build --release --target aarch64-unknown-linux-musl -p mycelium-cli --bin mycelium
)

ARM64_OUT="$DIST_DIR/mycelium-android-arm64-musl"
cp "$ROOT_DIR/target/aarch64-unknown-linux-musl/release/mycelium" "$ARM64_OUT"
if [[ -n "$STRIP_BIN" ]]; then
  "$STRIP_BIN" --strip-debug "$ARM64_OUT" || true
fi
chmod +x "$ARM64_OUT"

echo "[5/7] Auditando ELF64 AArch64 estático..."
FILE_DESC="$(file "$ARM64_OUT")"
echo "  • file: $FILE_DESC"
if [[ "$FILE_DESC" != *"ARM aarch64"* ]] || [[ "$FILE_DESC" != *"statically linked"* ]]; then
  echo "ERRO: binário não é ARM aarch64 estático: $FILE_DESC" >&2
  exit 1
fi
if readelf -l "$ARM64_OUT" | grep -q "INTERP"; then
  echo "ERRO: binário contém PT_INTERP (dependência de linker dinâmico)!" >&2
  exit 1
fi
echo "  • readelf -l: zero INTERP confirmado (100% estático)"

echo "[6/7] Smoke test real em CPU ARM64 via qemu-aarch64-static..."
QEMU_HOME="$(mktemp -d)"
trap 'rm -rf "$QEMU_HOME"' EXIT
ID_OUT="$(MYCELIUM_ANDROID=1 MYCELIUM_HOME="$QEMU_HOME" qemu-aarch64-static "$ARM64_OUT" --home "$QEMU_HOME" rhizome identity)"
echo "$ID_OUT" | sed 's/^/  | /'
if ! echo "$ID_OUT" | grep -q "Gland NodeId"; then
  echo "ERRO: falha no smoke test qemu-aarch64-static (rhizome identity)" >&2
  exit 1
fi
POST_OUT="$(MYCELIUM_ANDROID=1 MYCELIUM_HOME="$QEMU_HOME" qemu-aarch64-static "$ARM64_OUT" --home "$QEMU_HOME" rhizome post "Teste soberano ARM64 via musl+QEMU")"
echo "$POST_OUT" | sed 's/^/  | /'
if ! echo "$POST_OUT" | grep -q "Post publicado"; then
  echo "ERRO: falha no smoke test qemu-aarch64-static (rhizome post)" >&2
  exit 1
fi

echo "[7/7] Forjando e assinando (v1 JAR/PKCS#7 + v2 Merkle ECDSA-P256) APK soberano..."
APK_OUT="$DIST_DIR/mycelium-rhizome-android-arm64.apk"
(
  cd "$ROOT_DIR"
  cargo run --release -p mycelium-android-forge -- build \
    --daemon "$ARM64_OUT" \
    --output "$APK_OUT" \
    --key "$KEY_FILE" \
    --version-code 3 \
    --version-name "0.3.0"
  cargo run --release -p mycelium-android-forge -- verify "$APK_OUT"
)

echo "  • Validando META-INF/CERT.EC & CERT.SF com OpenSSL independente..."
TMP_SIG="$(mktemp -d)"
python3 - <<PY
import zipfile
with zipfile.ZipFile("$APK_OUT", "r") as z:
    open("$TMP_SIG/CERT.EC", "wb").write(z.read("META-INF/CERT.EC"))
    open("$TMP_SIG/CERT.SF", "wb").write(z.read("META-INF/CERT.SF"))
PY
openssl pkcs7 -inform DER -in "$TMP_SIG/CERT.EC" -print_certs -noout
openssl cms -verify -inform DER -in "$TMP_SIG/CERT.EC" -content "$TMP_SIG/CERT.SF" -noverify -out /dev/null
rm -rf "$TMP_SIG"

ls -lh "$ARM64_OUT" "$APK_OUT"
echo "[✅ SUCESSO] Build Android 100% soberano concluído (verificado em host + qemu-aarch64-static + OpenSSL)!"
