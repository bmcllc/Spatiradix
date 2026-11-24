pub mod apk_zip;
pub mod arsc;
pub mod asn1;
pub mod axml;
pub mod dex;
pub mod icon;
pub mod signer;

use apk_zip::ZipEntryInput;
use arsc::encode_resources_arsc;
use axml::encode_android_manifest;
use dex::{compile_classes_dex, verify_dex};
use icon::generate_launcher_icon_png;
use signer::{build_and_sign_apk, load_or_create_signing_key, verify_apk, SignerError, VerificationReport};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ForgeError {
    #[error("daemon binário não encontrado ou vazio em {0}")]
    MissingDaemon(String),
    #[error("DEX inválido: {0}")]
    Dex(#[from] dex::DexError),
    #[error("assinador/verificador APK: {0}")]
    Signer(#[from] SignerError),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
}

pub struct ApkBuildConfig<'a> {
    pub daemon_path: &'a Path,
    pub output_apk: &'a Path,
    pub key_path: Option<&'a Path>,
    pub version_code: u32,
    pub version_name: &'a str,
    pub debuggable: bool,
}

/// Constrói e assina (v1 JAR/PKCS#7 + v2 APK Sig Block) um APK Android ARM64 soberano
/// sem SDK, NDK, Gradle ou dependências da Google.
pub fn build_sovereign_apk(cfg: ApkBuildConfig<'_>) -> Result<VerificationReport, ForgeError> {
    let daemon_bytes = std::fs::read(cfg.daemon_path)
        .map_err(|_| ForgeError::MissingDaemon(cfg.daemon_path.display().to_string()))?;
    if daemon_bytes.len() < 64 {
        return Err(ForgeError::MissingDaemon(cfg.daemon_path.display().to_string()));
    }

    let manifest = encode_android_manifest(cfg.version_code, cfg.version_name, cfg.debuggable);
    let arsc = encode_resources_arsc();
    let png = generate_launcher_icon_png();
    let dex = compile_classes_dex();
    verify_dex(&dex)?;

    let entries = vec![
        ZipEntryInput {
            name: "AndroidManifest.xml".into(),
            data: manifest,
            store_uncompressed: false,
            alignment: 1,
        },
        ZipEntryInput {
            name: "resources.arsc".into(),
            data: arsc,
            store_uncompressed: true,
            alignment: 4,
        },
        ZipEntryInput {
            name: "res/drawable/ic_launcher.png".into(),
            data: png,
            store_uncompressed: true,
            alignment: 4,
        },
        ZipEntryInput {
            name: "classes.dex".into(),
            data: dex,
            store_uncompressed: false,
            alignment: 1,
        },
        ZipEntryInput {
            name: "lib/arm64-v8a/libmycelium_daemon.so".into(),
            data: daemon_bytes,
            store_uncompressed: true,
            alignment: 4096,
        },
    ];

    let sk = load_or_create_signing_key(cfg.key_path)?;
    let apk_bytes = build_and_sign_apk(&entries, &sk)?;
    if let Some(parent) = cfg.output_apk.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(cfg.output_apk, &apk_bytes)?;
    let report = verify_apk(&apk_bytes)?;
    Ok(report)
}

pub fn verify_apk_file(apk_path: &Path) -> Result<VerificationReport, ForgeError> {
    let bytes = std::fs::read(apk_path)?;
    // Também verifica classes.dex embutido via verificador Dalvik independente
    let (_, _, _, entries) = apk_zip::parse_central_directory(&bytes).map_err(SignerError::from)?;
    if let Some(dex_ent) = entries.iter().find(|e| e.name == "classes.dex") {
        let dex_bytes = apk_zip::read_entry_data(&bytes, dex_ent).map_err(SignerError::from)?;
        verify_dex(&dex_bytes)?;
    } else {
        return Err(ForgeError::Dex(dex::DexError::Invalid("classes.dex ausente no APK".into())));
    }
    Ok(verify_apk(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_signs_verifies_and_detects_tamper() {
        let dir = std::env::temp_dir().join(format!("mycelium-apk-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let fake_elf = dir.join("mycelium-arm64");
        let mut elf_data = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        elf_data.resize(8192, 0xaa);
        std::fs::write(&fake_elf, &elf_data).unwrap();

        let apk_path = dir.join("test.apk");
        let key_path = dir.join("release.p256.key");

        let report = build_sovereign_apk(ApkBuildConfig {
            daemon_path: &fake_elf,
            output_apk: &apk_path,
            key_path: Some(&key_path),
            version_code: 1,
            version_name: "0.1.0",
            debuggable: false,
        })
        .expect("APK deve ser compilado e verificado com sucesso");

        assert_eq!(report.arsc_data_offset % 4, 0);
        assert_eq!(report.native_lib_data_offset % 4096, 0);
        assert_eq!(report.v1_manifest_entries, 5);

        verify_apk_file(&apk_path).expect("re-verificação independente do arquivo APK");

        // Teste de detecção de violação (1 bit flipado dentro do ELF nativo)
        let mut tampered = std::fs::read(&apk_path).unwrap();
        let off = report.native_lib_data_offset as usize + 10;
        tampered[off] ^= 0x01;
        assert!(verify_apk(&tampered).is_err(), "violação deve ser detectada por v1 e v2");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
