//! Uma raiz = um diretório `.mycelium-root/` num meio físico.
//!
//! ```text
//! <meio>/.mycelium-root/
//!   root.json              identidade da raiz + parte Shamir da chave
//!   chunks/ab/<id>.<i>     fragmento i (Reed-Solomon) de um pedaço cifrado
//!   carry/<j>/<id>.<j>     fragmentos levados para a raiz j (ausente na escrita)
//!   log/<lamport>-<w>-<h>.e  entradas cifradas do log de metadados
//! ```

use crate::RootError;
use entropy::Shade;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const DIR_NAME: &str = ".mycelium-root";
pub const FORMAT: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootMeta {
    pub format: u32,
    /// Identificador aleatório do cofre (16 bytes hex): agrupa as raízes.
    pub vault: String,
    /// Índice desta raiz, 1..=n. Também é o índice da parte Shamir.
    pub index: u8,
    pub n: u8,
    pub k: u8,
    /// Parte Shamir da chave do cofre. Sozinha não revela nada.
    pub share: Shade,
    /// MAC da chave (BLAKE3-keyed): confere a reconstrução sem expor a chave.
    pub check: String,
    pub label: String,
}

/// Uma raiz encontrada num caminho.
#[derive(Clone, Debug)]
pub struct Root {
    pub base: PathBuf,
    pub meta: RootMeta,
}

impl Root {
    pub fn dir(path: &Path) -> PathBuf {
        path.join(DIR_NAME)
    }

    pub fn exists(path: &Path) -> bool {
        Self::dir(path).join("root.json").is_file()
    }

    pub fn create(path: &Path, meta: RootMeta) -> Result<Self, RootError> {
        let dir = Self::dir(path);
        if dir.join("root.json").exists() {
            return Err(RootError::Msg(format!("{} já é uma raiz", path.display())));
        }
        for sub in ["chunks", "carry", "log"] {
            fs::create_dir_all(dir.join(sub)).map_err(|e| io(&dir, e))?;
        }
        let json = serde_json::to_vec_pretty(&meta).map_err(|e| RootError::Msg(e.to_string()))?;
        write_atomic(&dir.join("root.json"), &json)?;
        Ok(Self {
            base: path.to_path_buf(),
            meta,
        })
    }

    pub fn open(path: &Path) -> Result<Self, RootError> {
        let file = Self::dir(path).join("root.json");
        let raw = fs::read(&file).map_err(|e| io(&file, e))?;
        let meta: RootMeta = serde_json::from_slice(&raw)
            .map_err(|e| RootError::Msg(format!("{}: root.json inválido ({e})", path.display())))?;
        if meta.format != FORMAT {
            return Err(RootError::Msg(format!("{}: formato {} desconhecido", path.display(), meta.format)));
        }
        if meta.index == 0 || meta.index > meta.n || meta.k == 0 || meta.k > meta.n || meta.share.index != meta.index {
            return Err(RootError::Msg(format!("{}: root.json incoerente", path.display())));
        }
        Ok(Self {
            base: path.to_path_buf(),
            meta,
        })
    }

    pub fn root_dir(&self) -> PathBuf {
        Self::dir(&self.base)
    }

    pub fn chunk_path(&self, id: &str) -> PathBuf {
        self.root_dir()
            .join("chunks")
            .join(&id[..2])
            .join(format!("{id}.{}", self.meta.index))
    }

    pub fn carry_path(&self, target: u8, id: &str) -> PathBuf {
        self.root_dir()
            .join("carry")
            .join(target.to_string())
            .join(format!("{id}.{target}"))
    }

    pub fn log_dir(&self) -> PathBuf {
        self.root_dir().join("log")
    }
}

/// Escrita atômica: arquivo temporário + fsync + rename.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), RootError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
    }
    let tmp = path.with_extension(format!("tmp{}", rand::random::<u32>()));
    {
        let mut f = fs::File::create(&tmp).map_err(|e| io(&tmp, e))?;
        f.write_all(bytes).map_err(|e| io(&tmp, e))?;
        f.sync_all().map_err(|e| io(&tmp, e))?;
    }
    fs::rename(&tmp, path).map_err(|e| io(path, e))
}

/// Escrita atômica sem fsync (o chamador faz `sync_fs` em lote depois).
pub fn write_nosync(path: &Path, bytes: &[u8]) -> Result<(), RootError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
    }
    let tmp = path.with_extension(format!("tmp{}", rand::random::<u32>()));
    fs::write(&tmp, bytes).map_err(|e| io(&tmp, e))?;
    fs::rename(&tmp, path).map_err(|e| io(path, e))
}

/// `syncfs(2)` no sistema de arquivos que contém `dir` (uma chamada por raiz).
pub fn sync_fs(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        if let Ok(f) = fs::File::open(dir) {
            unsafe {
                libc::syncfs(f.as_raw_fd());
            }
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
}

pub fn io(path: &Path, e: std::io::Error) -> RootError {
    RootError::Msg(format!("{}: {e}", path.display()))
}

/// Procura raízes em pontos de montagem comuns de mídia removível.
pub fn scan() -> Vec<PathBuf> {
    let mut found = Vec::new();
    let user = std::env::var("USER").unwrap_or_default();
    let bases = [
        PathBuf::from("/media").join(&user),
        PathBuf::from("/run/media").join(&user),
        PathBuf::from("/media"),
        PathBuf::from("/mnt"),
    ];
    for base in bases {
        let Ok(entries) = fs::read_dir(&base) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            if Root::exists(&p) && !found.contains(&p) {
                found.push(p);
            }
        }
    }
    found
}
