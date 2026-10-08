use crate::spore::{ExecutionEngineType, ExecutionMatrix, HardwareRequirements, QemuConfig, SoftwareSpore, SporeLicense, TargetPlatform};
use giggs::{Leaf, Plot};
use mycelium_core::{ContentId, NodeId};
use mycelium_sporebank::{SporeBank, SporeBankError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use tracing::{error, info};

/// Sequencia os nomes dos temporários, para dois `atomic_write` concorrentes
/// nunca disputarem o mesmo ficheiro temporário.
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("sporebank: {0}")]
    SporeBank(#[from] SporeBankError),
    #[error("codec json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("spore {0} não encontrado no catálogo")]
    SporeNotFound(String),
    /// `catalog.json` existe mas não é parseável (escrito por um `write` que
    /// ficou a meio, ou truncado por disco cheio). Distinto de "catálogo
    /// vazio": devolver um índice vazio aqui seria perda de dados silenciosa.
    #[error("catálogo em {path} ilegível: {source}")]
    IndexCorrupt {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    /// Invariante do catálogo que não pode ser satisfeita por um índice em
    /// memória: mutex envenenado, ou `catalog.json` ilegível ou em
    /// desacordo com o índice. Deliberadamente sem `#[source]`: o detalhe
    /// original vai para o log, e a mensagem devolvida ao cliente não o
    /// transporta.
    #[error("catálogo envenenado: {0}")]
    Poisoned(&'static str),
}

/// Catálogo de Jogos e Softwares Legados
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StoreIndex {
    pub spores: HashMap<String, SoftwareSpore>,
}

pub struct StoreCatalog {
    sporebank: SporeBank,
    index: StoreIndex,
    root: PathBuf,
}

impl StoreCatalog {
    pub fn open(home: impl AsRef<Path>) -> Result<Self, CatalogError> {
        let home_ref = home.as_ref();
        let store_dir = home_ref.join("store");
        std::fs::create_dir_all(&store_dir)?;

        let sporebank = SporeBank::open(home_ref)?;

        let index_file = store_dir.join("catalog.json");
        let index: StoreIndex = if index_file.exists() {
            let bytes = std::fs::read(&index_file)?;
            // Só a ausência do ficheiro significa "catálogo vazio". Um ficheiro
            // presente e ilegível é CORRUPÇÃO: propagar o erro, senão o
            // `unwrap_or_default` de antes convertia perda de dados em "a store
            // não tem esporos" sem qualquer sinal.
            serde_json::from_slice(&bytes).map_err(|e| CatalogError::IndexCorrupt {
                path: index_file.clone(),
                source: e,
            })?
        } else {
            StoreIndex::default()
        };

        let mut catalog = Self {
            sporebank,
            index,
            root: store_dir,
        };

        // Popula e atualiza os esporos MS-DOS reais e de preservação
        catalog.seed_real_msdos_spores()?;

        Ok(catalog)
    }

    fn save_index(&self) -> Result<(), CatalogError> {
        let bytes = serde_json::to_vec_pretty(&self.index)?;
        atomic_write(&self.root.join("catalog.json"), &bytes)?;
        Ok(())
    }

    /// Confere as invariantes do índice em memória contra `catalog.json`.
    ///
    /// Separa três estados, e só o terceiro é falha de consistência:
    /// - Ficheiro ausente: catálogo legitimamente vazio (ainda sem nenhum
    ///   `save_index`, ou apagado por fora). NÃO é erro.
    /// - Ficheiro presente e não parseável: corrupção de disco — a mesma
    ///   condição que `IndexCorrupt` cobre no `open`.
    /// - Índice em memória que discorda do disco: chave ausente, registro
    ///   diferente ou `content_id` diferente. É o estado que um mutex
    ///   envenenado pode deixar para trás.
    ///
    /// Esta função RELATA; nunca repara. Substituir `self.index` pela cópia
    /// recém-lida aqui seria exatamente o reset silencioso que `IndexCorrupt`
    /// existe para impedir: o índice recuperado passaria a validar-se a si
    /// próprio no teste seguinte, e a falha original desapareceria sem
    /// registo.
    pub fn validate(&self) -> Result<(), CatalogError> {
        let index_file = self.root.join("catalog.json");
        if !index_file.exists() {
            return Ok(());
        }

        let bytes = std::fs::read(&index_file)?;
        let on_disk: StoreIndex = match serde_json::from_slice(&bytes) {
            Ok(index) => index,
            Err(e) => {
                error!(
                    "[Mycelium Store Catalog] catalog.json ilegível em {}: {e}",
                    index_file.display()
                );
                return Err(CatalogError::Poisoned(
                    "catalog.json presente em disco mas não parseável",
                ));
            }
        };

        for (id, spore) in &self.index.spores {
            let disk_spore = match on_disk.spores.get(id) {
                Some(s) => s,
                None => {
                    error!(
                        "[Mycelium Store Catalog] índice em memória tem '{}' ausente de {}",
                        id,
                        index_file.display()
                    );
                    return Err(CatalogError::Poisoned(
                        "índice em memória tem chave ausente em disco",
                    ));
                }
            };

            // `SoftwareSpore` não deriva `PartialEq` (nem os seus campos
            // aninhados), e adicionar o derive é uma mudança pública fora
            // deste ficheiro. Comparar as formas serializadas é estrutural e
            // determinista: todos os campos são escalares, `Option`, `String`
            // ou `Vec` — nenhum mapa, logo nenhuma ordem de iteração.
            if disk_spore.content_id != spore.content_id {
                error!(
                    "[Mycelium Store Catalog] content_id divergente para '{}' (memória {}, disco {})",
                    id,
                    hex::encode(spore.content_id.0),
                    hex::encode(disk_spore.content_id.0)
                );
                return Err(CatalogError::Poisoned(
                    "content_id em memória não bate com o disco",
                ));
            }
            if serde_json::to_vec(disk_spore)? != serde_json::to_vec(spore)? {
                error!(
                    "[Mycelium Store Catalog] registro divergente para '{}' entre memória e {}",
                    id,
                    index_file.display()
                );
                return Err(CatalogError::Poisoned(
                    "registro em memória não bate com o disco",
                ));
            }
        }

        Ok(())
    }

    /// Popula o catálogo com jogos e softwares MS-DOS autênticos de preservação histórica
    fn seed_real_msdos_spores(&mut self) -> Result<(), CatalogError> {
        let doom_id = ContentId::of(b"doom-1993-shareware-real");
        let doom_spore = SoftwareSpore {
            id: "doom-1993".to_string(),
            title: "DOOM (1993 MS-DOS Shareware)".to_string(),
            description: "O marco histórico dos First-Person Shooters criado pela id Software. Executa via QEMU com emulação SoundBlaster 16 e VGA clássica ou WASM.".to_string(),
            developer_or_publisher: "id Software".to_string(),
            release_year: 1993,
            platform: TargetPlatform::MSDOS,
            category: "jogo".to_string(),
            tags: vec!["fps".to_string(), "msdos".to_string(), "classic".to_string(), "preservation".to_string()],
            license: SporeLicense::Shareware,
            main_binary_file: "DOOM1.WAD".to_string(),
            content_id: doom_id,
            execution_matrix: ExecutionMatrix {
                recommended: ExecutionEngineType::QEMU,
                supports_native: false,
                libretro_core: Some("prboom".to_string()),
                mame_driver: None,
                qemu_config: Some(QemuConfig {
                    arch: "i386".to_string(),
                    machine: Some("pc".to_string()),
                    memory_mb: 32,
                    cpu: Some("pentium".to_string()),
                    sound_card: Some("sb16".to_string()),
                    vga_card: Some("std".to_string()),
                    boot_device: "c".to_string(),
                }),
                supports_wasm: true,
                supports_p2p_stream: true,
            },
            requirements: HardwareRequirements {
                min_ram_mb: 256,
                min_cpu_cores: 1,
                storage_bytes: 4 * 1024 * 1024,
                needs_kvm_acceleration: false,
            },
            extra_args: vec![],
            cover_image_url: Some("/store/api/store/covers/doom-1993.svg".to_string()),
        };

        let wolf_id = ContentId::of(b"wolfenstein-3d-1992-real");
        let wolf_spore = SoftwareSpore {
            id: "wolfenstein-3d".to_string(),
            title: "Wolfenstein 3D (1992 MS-DOS)".to_string(),
            description: "O lendário jogo que popularizou o gênero 3D em computadores PC MS-DOS com renderização por raycasting.".to_string(),
            developer_or_publisher: "id Software / Apogee".to_string(),
            release_year: 1992,
            platform: TargetPlatform::MSDOS,
            category: "jogo".to_string(),
            tags: vec!["fps".to_string(), "msdos".to_string(), "raycasting".to_string()],
            license: SporeLicense::Shareware,
            main_binary_file: "WOLF3D.EXE".to_string(),
            content_id: wolf_id,
            execution_matrix: ExecutionMatrix {
                recommended: ExecutionEngineType::QEMU,
                supports_native: false,
                libretro_core: Some("dosbox_pure".to_string()),
                mame_driver: None,
                qemu_config: Some(QemuConfig {
                    arch: "i386".to_string(),
                    machine: Some("pc".to_string()),
                    memory_mb: 16,
                    cpu: Some("i486".to_string()),
                    sound_card: Some("sb16".to_string()),
                    vga_card: Some("std".to_string()),
                    boot_device: "c".to_string(),
                }),
                supports_wasm: true,
                supports_p2p_stream: true,
            },
            requirements: HardwareRequirements::default(),
            extra_args: vec![],
            cover_image_url: Some("/store/api/store/covers/wolfenstein-3d.svg".to_string()),
        };

        let keen_id = ContentId::of(b"commander-keen-1990-real");
        let keen_spore = SoftwareSpore {
            id: "commander-keen".to_string(),
            title: "Commander Keen: Invasion of the Vorticons (1990 MS-DOS)".to_string(),
            description: "Pioneiro na rolagem suave de tela (smooth scrolling) em monitores EGA de PC IBM.".to_string(),
            developer_or_publisher: "id Software / Apogee".to_string(),
            release_year: 1990,
            platform: TargetPlatform::MSDOS,
            category: "jogo".to_string(),
            tags: vec!["platformer".to_string(), "msdos".to_string(), "ega".to_string()],
            license: SporeLicense::Shareware,
            main_binary_file: "KEEN1.EXE".to_string(),
            content_id: keen_id,
            execution_matrix: ExecutionMatrix {
                recommended: ExecutionEngineType::QEMU,
                supports_native: false,
                libretro_core: Some("dosbox_pure".to_string()),
                mame_driver: None,
                qemu_config: Some(QemuConfig {
                    arch: "i386".to_string(),
                    machine: Some("pc".to_string()),
                    memory_mb: 16,
                    cpu: Some("i386".to_string()),
                    sound_card: Some("sb16".to_string()),
                    vga_card: Some("std".to_string()),
                    boot_device: "c".to_string(),
                }),
                supports_wasm: true,
                supports_p2p_stream: true,
            },
            requirements: HardwareRequirements::default(),
            extra_args: vec![],
            cover_image_url: Some("/store/api/store/covers/commander-keen.svg".to_string()),
        };

        let jill_id = ContentId::of(b"jill-of-the-jungle-1992-shareware");
        let jill_spore = SoftwareSpore {
            id: "jill-of-the-jungle".to_string(),
            title: "Jill of the Jungle (1992 MS-DOS Shareware)".to_string(),
            description: "Clássico platformer da Epic MegaGames, shareware oficialmente distribuível. Aventura de Jill pela Jungle de auto-aventura com 16 níveis.".to_string(),
            developer_or_publisher: "Epic MegaGames".to_string(),
            release_year: 1992,
            platform: TargetPlatform::MSDOS,
            category: "jogo".to_string(),
            tags: vec!["platformer".to_string(), "msdos".to_string(), "shareware".to_string()],
            license: SporeLicense::Shareware,
            main_binary_file: "JILL.EXE".to_string(),
            content_id: jill_id,
            execution_matrix: ExecutionMatrix {
                recommended: ExecutionEngineType::QEMU,
                supports_native: false,
                libretro_core: Some("dosbox_pure".to_string()),
                mame_driver: None,
                qemu_config: Some(QemuConfig {
                    arch: "i386".to_string(),
                    machine: Some("pc".to_string()),
                    memory_mb: 16,
                    cpu: Some("i386".to_string()),
                    sound_card: Some("sb16".to_string()),
                    vga_card: Some("std".to_string()),
                    boot_device: "c".to_string(),
                }),
                supports_wasm: true,
                supports_p2p_stream: true,
            },
            requirements: HardwareRequirements::default(),
            extra_args: vec![],
            cover_image_url: Some("/store/api/store/covers/jill-of-the-jungle.svg".to_string()),
        };

        let omf_id = ContentId::of(b"one-must-fall-2097-shareware");
        let omf_spore = SoftwareSpore {
            id: "one-must-fall-2097".to_string(),
            title: "One Must Fall 2097 (1994 MS-DOS Shareware)".to_string(),
            description: "Fighting game shareware da Epic MegaGames de robôs, shareware oficialmente distribuível, com torneio e modo 2 jogadores.".to_string(),
            developer_or_publisher: "Epic MegaGames".to_string(),
            release_year: 1994,
            platform: TargetPlatform::MSDOS,
            category: "jogo".to_string(),
            tags: vec!["fighting".to_string(), "msdos".to_string(), "shareware".to_string()],
            license: SporeLicense::Shareware,
            main_binary_file: "OMF.EXE".to_string(),
            content_id: omf_id,
            execution_matrix: ExecutionMatrix {
                recommended: ExecutionEngineType::QEMU,
                supports_native: false,
                libretro_core: Some("dosbox_pure".to_string()),
                mame_driver: None,
                qemu_config: Some(QemuConfig {
                    arch: "i386".to_string(),
                    machine: Some("pc".to_string()),
                    memory_mb: 16,
                    cpu: Some("i386".to_string()),
                    sound_card: Some("sb16".to_string()),
                    vga_card: Some("std".to_string()),
                    boot_device: "c".to_string(),
                }),
                supports_wasm: true,
                supports_p2p_stream: true,
            },
            requirements: HardwareRequirements::default(),
            extra_args: vec![],
            cover_image_url: Some("/store/api/store/covers/one-must-fall-2097.svg".to_string()),
        };

        let hocus_id = ContentId::of(b"hocus-pocus-1994-shareware");
        let hocus_spore = SoftwareSpore {
            id: "hocus-pocus".to_string(),
            title: "Hocus Pocus (1994 MS-DOS Shareware)".to_string(),
            description: "Platformer shareware da Apogee com o pequeno feiticeiro Hocus, shareware oficialmente distribuível, 10 níveis de magia e plataformas.".to_string(),
            developer_or_publisher: "Apogee Software".to_string(),
            release_year: 1994,
            platform: TargetPlatform::MSDOS,
            category: "jogo".to_string(),
            tags: vec!["platformer".to_string(), "msdos".to_string(), "shareware".to_string()],
            license: SporeLicense::Shareware,
            main_binary_file: "HOCUS.EXE".to_string(),
            content_id: hocus_id,
            execution_matrix: ExecutionMatrix {
                recommended: ExecutionEngineType::QEMU,
                supports_native: false,
                libretro_core: Some("dosbox_pure".to_string()),
                mame_driver: None,
                qemu_config: Some(QemuConfig {
                    arch: "i386".to_string(),
                    machine: Some("pc".to_string()),
                    memory_mb: 16,
                    cpu: Some("i386".to_string()),
                    sound_card: Some("sb16".to_string()),
                    vga_card: Some("std".to_string()),
                    boot_device: "c".to_string(),
                }),
                supports_wasm: true,
                supports_p2p_stream: true,
            },
            requirements: HardwareRequirements::default(),
            extra_args: vec![],
            cover_image_url: Some("/store/api/store/covers/hocus-pocus.svg".to_string()),
        };

        self.index.spores.insert(doom_spore.id.clone(), doom_spore);
        self.index.spores.insert(wolf_spore.id.clone(), wolf_spore);
        self.index.spores.insert(keen_spore.id.clone(), keen_spore);
        self.index.spores.insert(jill_spore.id.clone(), jill_spore);
        self.index.spores.insert(omf_spore.id.clone(), omf_spore);
        self.index.spores.insert(hocus_spore.id.clone(), hocus_spore);

        self.save_index()?;
        Ok(())
    }

    /// Adiciona um novo Spore de jogo ou software ao catálogo local e deposita no SporeBank
    pub fn publish_spore(&mut self, spore: SoftwareSpore, binary_bytes: &[u8]) -> Result<ContentId, CatalogError> {
        let plot = Plot {
            author: NodeId::derive(spore.id.as_bytes()),
            message: format!("Software Spore: {}", spore.title),
            parents: vec![],
            leaves: vec![Leaf {
                path: spore.main_binary_file.clone(),
                content: binary_bytes.to_vec(),
            }],
        };

        let content_id = self.sporebank.deposit(plot)?;
        let mut spore = spore;
        spore.content_id = content_id;

        self.index.spores.insert(spore.id.clone(), spore);
        self.save_index()?;

        info!("[Mycelium Store Catalog] Spore publicado com ContentId: {}", hex::encode(content_id.0));
        Ok(content_id)
    }

    /// Adiciona um spore ao índice e persiste o catálogo (sem depositar binário no SporeBank)
    pub fn insert_spore(&mut self, spore: SoftwareSpore) -> Result<(), CatalogError> {
        self.index.spores.insert(spore.id.clone(), spore);
        self.save_index()
    }

    /// Lista todos os esporos do catálogo
    pub fn list_spores(&self) -> Vec<&SoftwareSpore> {
        self.index.spores.values().collect()
    }

    /// Lista apenas os esporos com licença que permite distribuição pública
    /// pela rede (Shareware, Freeware, Open Source, Domínio Público).
    /// Spores `proprietary` ficam restritos ao catálogo local do usuário (BYOR).
    pub fn list_public_spores(&self) -> Vec<&SoftwareSpore> {
        self.index
            .spores
            .values()
            .filter(|s| s.license.is_publicly_redistributable())
            .collect()
    }

    /// Busca um esporo pelo ID
    pub fn get_spore(&self, id: &str) -> Option<&SoftwareSpore> {
        self.index.spores.get(id)
    }

    /// Filtra esporos por plataforma de hardware
    pub fn filter_by_platform(&self, platform: &TargetPlatform) -> Vec<&SoftwareSpore> {
        self.index
            .spores
            .values()
            .filter(|s| s.platform == *platform)
            .collect()
    }

    pub fn sporebank(&self) -> &SporeBank {
        &self.sporebank
    }
}

/// Grava `bytes` num temporário, faz `fsync` e promove com `rename`.
///
/// Mesma abordagem de `mycelium_sporebank::atomic_write`: um crash a meio
/// deixa o temporário órfão, nunca um `catalog.json` cortado — que o `open`
/// não pode distinguir de "catálogo vazio" sem `unwrap_or_default`.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let seq = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = path.with_extension(format!("tmp-{}-{seq}", std::process::id()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}
