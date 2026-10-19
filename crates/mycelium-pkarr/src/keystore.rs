//! Guarda da identidade mestra em disco: arquivo 0600 em diretório 0700,
//! criado de forma exclusiva e recusado na leitura se outros puderem lê-lo.

use crate::blind::MasterIdentity;
use crate::PkarrError;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const MASTER_FILE: &str = "master.key";
pub const ACCESS_FILE: &str = "access.secret";

/// Identidade mestra e, no modo privado, o segredo de acesso.
pub type LoadedIdentity = (MasterIdentity, Option<Zeroizing<[u8; 32]>>);

pub struct Keystore {
    dir: PathBuf,
}

impl Keystore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn exists(&self) -> bool {
        self.dir.join(MASTER_FILE).exists()
    }

    /// Cria identidade nova (e segredo de acesso, se `private`). Nunca
    /// sobrescreve uma identidade existente.
    pub fn init(&self, private: bool) -> Result<(MasterIdentity, Option<[u8; 32]>), PkarrError> {
        create_private_dir(&self.dir)?;
        let id = MasterIdentity::generate();
        write_secret(&self.dir.join(MASTER_FILE), id.seed())?;
        let secret = if private {
            let mut s = Zeroizing::new([0u8; 32]);
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, s.as_mut());
            write_secret(&self.dir.join(ACCESS_FILE), &s)?;
            Some(*s)
        } else {
            None
        };
        Ok((id, secret))
    }

    pub fn load(&self) -> Result<LoadedIdentity, PkarrError> {
        let seed = read_secret(&self.dir.join(MASTER_FILE))?;
        let access = match self.dir.join(ACCESS_FILE).exists() {
            true => Some(read_secret(&self.dir.join(ACCESS_FILE))?),
            false => None,
        };
        Ok((MasterIdentity::from_seed(*seed), access))
    }
}

fn create_private_dir(dir: &Path) -> Result<(), PkarrError> {
    fs::create_dir_all(dir)
        .map_err(|e| PkarrError::Keystore(format!("criar {}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| PkarrError::Keystore(format!("chmod 700: {e}")))?;
    }
    Ok(())
}

fn write_secret(path: &Path, bytes: &[u8; 32]) -> Result<(), PkarrError> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| PkarrError::Keystore(format!("{} (já existe?): {e}", path.display())))?;
    let hexed = Zeroizing::new(hex::encode(bytes));
    f.write_all(hexed.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| PkarrError::Keystore(format!("gravar {}: {e}", path.display())))
}

fn read_secret(path: &Path) -> Result<Zeroizing<[u8; 32]>, PkarrError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // symlink_metadata: não seguir link plantado apontando para outro arquivo
        let meta = fs::symlink_metadata(path)
            .map_err(|e| PkarrError::Keystore(format!("{}: {e}", path.display())))?;
        if !meta.file_type().is_file() {
            return Err(PkarrError::Keystore(format!(
                "{} não é arquivo regular",
                path.display()
            )));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(PkarrError::Keystore(format!(
                "{} legível por outros usuários (chmod 600)",
                path.display()
            )));
        }
        // Arquivo com dono diferente do diretório indica plantio por outro usuário.
        let parent = path.parent().unwrap_or(Path::new("."));
        let pmeta = fs::metadata(parent).map_err(|e| PkarrError::Keystore(e.to_string()))?;
        if meta.uid() != pmeta.uid() {
            return Err(PkarrError::Keystore(format!(
                "{} com dono diferente do diretório",
                path.display()
            )));
        }
    }
    let raw = Zeroizing::new(
        fs::read_to_string(path)
            .map_err(|e| PkarrError::Keystore(format!("{}: {e}", path.display())))?,
    );
    let mut out = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(raw.trim(), out.as_mut())
        .map_err(|_| PkarrError::Keystore(format!("{} corrompido", path.display())))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("myc-pkarr-{tag}-{}", rand::random::<u64>()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn init_load_and_no_overwrite() {
        let dir = tmpdir("ks");
        let ks = Keystore::new(&dir);
        let (id, secret) = ks.init(true).unwrap();
        let (loaded, access) = ks.load().unwrap();
        assert_eq!(id.public(), loaded.public());
        assert_eq!(secret.unwrap(), *access.unwrap());
        assert!(ks.init(false).is_err(), "não pode sobrescrever");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_key_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("perm");
        let ks = Keystore::new(&dir);
        ks.init(false).unwrap();
        fs::set_permissions(dir.join(MASTER_FILE), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ks.load().is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
