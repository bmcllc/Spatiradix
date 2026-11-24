# Build 100% Soberano para Android ARM64 (Zero Google, Zero Termux, Zero SDK/NDK/Gradle)

Este documento descreve a adaptação nativa do **Mycelium Network / Rhizome** para Android `arm64-v8a` executável diretamente via APK assinado, sem Termux, sem Google Play Services, sem Android SDK/NDK/Gradle e sem DNS/STUN da Google.

---

## 1. Arquitetura do Binário e do APK

1. **Daemon Nativo Estático (`aarch64-unknown-linux-musl`)**:
   - Compilado com `cargo` / `rustc`, `clang --target=aarch64-linux-musl`, `lld`/`llvm-ar` e apenas os headers licenciados sob MIT do `musl-1.2.5` (`.android-sovereign/musl-sysroot/include`), com `RUSTFLAGS="-C target-feature=+crt-static"`.
   - zero dependência de `/system/bin/linker64` ou da Bionic do Android (`readelf -l` confirma zero `PT_INTERP`).
2. **Sem Dependências Google em Tempo de Execução**:
   - **DNS sem `/etc/resolv.conf`** (`mycelium-hyphae/src/seeds.rs` e `mycelium-nostr/src/net.rs`): quando `/etc/resolv.conf` inexiste (padrão no sandbox Android sem root), a resolução DNS usa exclusivamente `Quad9` e `Cloudflare` (`ResolverConfig::quad9()` + `ResolverConfig::cloudflare()`), removendo integralmente `ResolverConfig::default()` (`8.8.8.8`).
   - **STUN WebRTC ICE** (`mycelium-hyphae/src/webrtc_ice.rs`): removido `stun.l.google.com:19302`, mantendo apenas servidores independentes (Cloudflare, Nextcloud, Sipgate).
   - **Home resiliente no Android** (`cli/mycelium-cli/src/main.rs`): `resolve_home` respeita `MYCELIUM_HOME`, `ProjectDirs`, `$HOME/.mycelium` e `.mycelium`.
   - **Telemetria de dispositivo**: com `MYCELIUM_ANDROID=1`, `mycelium-node` identifica o nó como `"mobile"` nos recibos `ShardReplicaReceipt` e `/rhizome/api/swarm`.
3. **Forjador APK em Rust Puro (`crates/mycelium-android-forge`) — `v0.3.0`**:
   - Compila `AndroidManifest.xml` (AXML com pool UTF-16LE e atributos ordenados por Resource ID crescente, `minSdkVersion="26"`, `targetSdkVersion="34"`, `extractNativeLibs="true"`, `usesCleartextTraffic="true"`, permissões `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC`, `POST_NOTIFICATIONS`, `NFC` e `READ_CONTACTS` opt-in em runtime; bloco `<queries>` explícito para os 9 aplicativos sociais; `intent-filter` de `ACTION_NDEF_DISCOVERED` para `scheme="urn"` e `ACTION_SEND` Share Target para `text/plain` e `text/x-vcard`; e `<service android:name="network.mycelium.rhizome.VeilVpnService" android:permission="android.permission.BIND_VPN_SERVICE"/>`, mais flag opcional `--debuggable` desligada por padrão).
   - O daemon estático `libmycelium_daemon.so` embarca nativamente `veil` (proxy SOCKS5 ML-KEM-1024 + servidor L3 `tun2socks` puro em Rust + relays remotos `all`/`client`/`exit`/`relay`), `mycelium-bank` + `mycelium-pay` + `mycelium-royalty` + `mycelium-mint` (economia CPX + quórum esporocarpo multi-nó via Gossipsub + NFC GhostID), `aex-mycelium-bridge/1.0.0`, o cofre cifrado Omnibridge Social (9 redes + oEmbed público X/TikTok) e o **TheField** (`/field/`, unificando repositórios Git P2P e sinais vivos de ressonância; o legado Code Hub foi removido).
   - Gera `resources.arsc` (`0x7f`: `drawable/ic_launcher` e `string/app_name`), ícone PNG 192×192 RGBA e `classes.dex` (DEX v035 com `map_list` completo, anotações `@android.webkit.JavascriptInterface`, strings `MUTF-8` com ordenação UTF-16 e 6 classes Dalvik: `RhizomeWebViewClient`, `MyceliumService`, `VeilTunWorker`, `VeilVpnService`, `MyceliumBridge` e `MainActivity`).
   - O `MyceliumService` inicia `<nativeLibraryDir>/libmycelium_daemon.so --home <filesDir>/mycelium daemon --horizon-port 7474` com `MYCELIUM_ANDROID=1` e redirecionamento de saída para `<filesDir>/mycelium/daemon.log`, enquanto a `MainActivity` abre o `WebView` em `http://127.0.0.1:7474/rhizome/` expondo `window.MyceliumNative` (hardware `NfcAdapter` foreground dispatch + escrita `Ndef.writeNdefMessage`, controle nativo da `VeilVpnService` com Quad9 `9.9.9.9` e `addDisallowedApplication("network.mycelium.rhizome")`, detecção/lançamento dos 9 apps via `<queries>` e importação opt-in da agenda Android em vCard via `READ_CONTACTS`).
   - **Resiliência no sandbox Android 11–15 (`untrusted_app`)**: `mycelium-hyphae` (`substrate_behaviour`) degrada graciosamente quando `libp2p-mdns` (`if-watch` `NETLINK_ROUTE`) retorna `Permission denied (os error 13)`, mantendo TCP/QUIC loopback, transporte Nostr WSS e descoberta via seeds/relays plenamente ativos.
   - Empacota `resources.arsc` alinhado em 4 bytes e `lib/arm64-v8a/libmycelium_daemon.so` stored sem compressão e alinhado em **4096 bytes**.
   - Assina com **dupla assinatura criptográfica ECDSA P-256**:
     - **APK Signature Scheme v1** (`META-INF/MANIFEST.MF`, `CERT.SF`, `CERT.EC` CMS/PKCS#7 DER).
     - **APK Signature Scheme v2** (`APK Sig Block 42`, ID `0x7109871a`, Merkle root SHA-256 em chunks de 1 MiB).

---

## 2. Como Gerar e Verificar

```bash
bash scripts/build-android-sovereign.sh
```

Saídas em `dist/`:
- `dist/mycelium-android-arm64-musl` — binário ELF64 ARM64 estático.
- `dist/mycelium-rhizome-android-arm64.apk` — APK Android `arm64-v8a` assinado (v1+v2).

Comandos individuais do forjador:
```bash
cargo run --release -p mycelium-android-forge -- build \
  --daemon dist/mycelium-android-arm64-musl \
  --output dist/mycelium-rhizome-android-arm64.apk \
  --key .android-sovereign/mycelium-release.p256.key

cargo run --release -p mycelium-android-forge -- verify \
  dist/mycelium-rhizome-android-arm64.apk
```

---

## 3. Limites Honestos de Verificação (Doutrina da Honestidade)

| Camada Verificada | Ambiente de Execução | Escopo |
|---|---|---|
| Compilação `aarch64-unknown-linux-musl` + auditoria ELF (`file`, `readelf -l`) | Host Linux `x86_64` | Binário ARM64 estático sem `PT_INTERP` |
| Execução real `rhizome identity` e `rhizome post` | Emulação CPU ARM64 (`qemu-aarch64-static`) com `MYCELIUM_ANDROID=1` | Geração real de chaves/post em espaço de usuário ARM64 musl |
| Verificador DEX v035 (`verify_dex`, 6 classes + `@JavascriptInterface`), ZIP 4KB, v1/v2 e detecção de adulteração | Host Linux `x86_64` (`cargo test -p mycelium-android-forge`) | Validação estrutural e criptográfica independente |
| Assinatura CMS/PKCS#7 (`META-INF/CERT.EC` + `CERT.SF`) | OpenSSL independente (`openssl pkcs7` / `openssl cms -verify`) | Validação PKCS#7 DER fora do código Rust |
| Instalação, ART (`dex2oat64`), UI `WebView`, ponte `MyceliumNative` e daemon P2P nativo em hardware físico (`v0.3.0`) | **Moto G35 5G físico (`ZF524W2ZZL`, Android 15 / API 35, `arm64-v8a`, `PAGESIZE=4096`)** via USB/ADB | `adb install -r` (`Success`, `versionCode=3`, `versionName=0.3.0`), `ApkSignatureVerifier` v1+v2 OK, `cmd package compile -m verify -f` → `dex2oat returned code 0` (`base.odex` 30 672 bytes verificado, zero `VerifyError` nas 6 classes DEX), `dumpsys package` confirmando `VeilVpnService` (`BIND_VPN_SERVICE`), `ACTION_NDEF_DISCOVERED`, `ACTION_SEND` (`text/plain`, `text/x-vcard`), `queriesPackages` (9 redes), `NFC` (`granted=true`) e `READ_CONTACTS`; `MainActivity` (`LaunchState: COLD`, 872 ms) + `libmycelium_daemon.so` ativos sob `u0_a451`; entrega ao vivo de `ACTION_SEND` via `singleTop`/`onNewIntent` sem erros em `AndroidRuntime:E`/`chromium:E`; HTTP local validado em `/rhizome/` (`200`, 217 606 bytes), `/field/` (`200`, 29 747 bytes), `POST/GET /field/api/signals`, `/hub/` (`404` removido), `/rhizome/api/finance/reserve-policy`, `/rhizome/api/veil/start` (SOCKS5 + `tun_bridge` L3 ativo) + `/api/veil/test` (`0x05 0x00`, 1 ms) + `/api/veil/stop` e `/rhizome/api/omnibridge/overview` (9 redes) |
