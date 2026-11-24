use clap::{Parser, Subcommand};
use mycelium_android_forge::{build_sovereign_apk, verify_apk_file, ApkBuildConfig};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "mycelium-android-forge")]
#[command(about = "Forjador 100% soberano em Rust puro de APK Android ARM64 (v1+v2), zero Google SDK/NDK/Gradle")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Empacota o binário ARM64 estático em um APK Android ARM64 assinado (v1+v2).
    Build {
        #[arg(long)]
        daemon: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long, default_value_t = 1)]
        version_code: u32,
        #[arg(long, default_value = "0.1.0")]
        version_name: String,
        #[arg(long, default_value_t = false)]
        debuggable: bool,
    },
    /// Verifica independentemente assinaturas v1+v2, alinhamento ZIP e DEX v035 de um APK.
    Verify { apk: PathBuf },
}

fn main() {
    let cli = Cli::parse();
    let res = match cli.command {
        Cmd::Build {
            daemon,
            output,
            key,
            version_code,
            version_name,
            debuggable,
        } => build_sovereign_apk(ApkBuildConfig {
            daemon_path: &daemon,
            output_apk: &output,
            key_path: key.as_deref(),
            version_code,
            version_name: &version_name,
            debuggable,
        })
        .map(|rep| {
            println!(
                "[📱 Mycelium Android Forge] APK gerado e verificado: {}",
                output.display()
            );
            println!("    • v1 JAR+PKCS#7 : {} arquivos assinados", rep.v1_manifest_entries);
            println!("    • v2 Merkle SHA : {}", rep.v2_chunk_digest_hex);
            println!("    • Cert SPKI SHA : {}", rep.spki_sha256_hex);
            println!(
                "    • Alinhamento   : resources.arsc @{} (%4=0) · .so @{} (%4096=0)",
                rep.arsc_data_offset, rep.native_lib_data_offset
            );
        }),
        Cmd::Verify { apk } => verify_apk_file(&apk).map(|rep| {
            println!("[✅ Verificação Independente OK] {}", apk.display());
            println!("    • v1 entradas  : {}", rep.v1_manifest_entries);
            println!("    • v2 digest    : {}", rep.v2_chunk_digest_hex);
            println!("    • Cert SPKI    : {}", rep.spki_sha256_hex);
            println!(
                "    • Alinhamento  : resources.arsc @{} · .so @{}",
                rep.arsc_data_offset, rep.native_lib_data_offset
            );
        }),
    };

    if let Err(e) = res {
        eprintln!("[✗ mycelium-android-forge] {e}");
        std::process::exit(1);
    }
}
