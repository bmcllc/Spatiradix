//! `mount`: o Root aparece como uma pasta comum (um "pendrive").
//!
//! Leitura carrega só os pedaços tocados (com cache). Escrita mantém em
//! memória apenas os pedaços em edição; cada pedaço que fica completo é
//! cifrado e gravado na hora, então copiar um arquivo de vários GB usa
//! memória constante. Ao fechar o arquivo, uma entrada `put` vai para o log.
//! Nada é gravado no computador: só nas raízes.

use crate::chunk::CHUNK_SIZE;
use crate::log::Node;
use crate::Vault;
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow,
};
use libc::{EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOTDIR, ENOTEMPTY};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);
const CS: u64 = CHUNK_SIZE as u64;

/// Arquivo aberto: pedaços já gravados + buffers dos pedaços em edição.
struct Handle {
    path: String,
    size: u64,
    /// (id, tamanho) do pedaço gravado em cada índice; `None` = zeros.
    chunks: Vec<Option<(String, usize)>>,
    dirty: BTreeMap<usize, Vec<u8>>,
    modified: bool,
}

impl Handle {
    fn from_tree(path: String, node: Option<&Node>) -> Self {
        let (size, chunks) = match node {
            Some(Node::File { size, chunks, .. }) => {
                let list = chunks
                    .iter()
                    .enumerate()
                    .map(|(i, id)| Some((id.clone(), (size - i as u64 * CS).min(CS) as usize)))
                    .collect();
                (*size, list)
            }
            _ => (0, Vec::new()),
        };
        Self {
            path,
            size,
            chunks,
            dirty: BTreeMap::new(),
            modified: false,
        }
    }

    /// Conteúdo atual do pedaço `idx` (sem o padding além do tamanho).
    fn chunk_data(&self, vault: &Vault, idx: usize) -> Result<Vec<u8>, i32> {
        if let Some(buf) = self.dirty.get(&idx) {
            return Ok(buf.clone());
        }
        match self.chunks.get(idx) {
            Some(Some((id, _))) => vault.load_chunk(id).map(|d| (*d).clone()).map_err(|_| EIO),
            _ => Ok(Vec::new()),
        }
    }

    fn read(&self, vault: &Vault, offset: u64, len: usize) -> Result<Vec<u8>, i32> {
        if offset >= self.size {
            return Ok(Vec::new());
        }
        let end = self.size.min(offset + len as u64);
        let mut out = Vec::with_capacity((end - offset) as usize);
        let mut pos = offset;
        while pos < end {
            let idx = (pos / CS) as usize;
            let chunk_end = ((idx as u64 + 1) * CS).min(end);
            let start = (pos % CS) as usize;
            let want = (chunk_end - pos) as usize;
            let data: std::borrow::Cow<'_, [u8]> = match (self.dirty.get(&idx), self.chunks.get(idx)) {
                (Some(buf), _) => std::borrow::Cow::Borrowed(buf.as_slice()),
                (None, Some(Some((id, _)))) => {
                    std::borrow::Cow::Owned((*vault.load_chunk(id).map_err(|_| EIO)?).clone())
                }
                _ => std::borrow::Cow::Owned(Vec::new()),
            };
            // bytes além do que existe no pedaço são zeros (buraco/expansão)
            for i in 0..want {
                out.push(*data.get(start + i).unwrap_or(&0));
            }
            pos = chunk_end;
        }
        Ok(out)
    }

    fn write(&mut self, vault: &Vault, offset: u64, data: &[u8]) -> Result<(), i32> {
        let mut pos = offset;
        let mut src = data;
        while !src.is_empty() {
            let idx = (pos / CS) as usize;
            let start = (pos % CS) as usize;
            let take = src.len().min(CHUNK_SIZE - start);
            if !self.dirty.contains_key(&idx) {
                let base = self.chunk_data(vault, idx)?;
                self.dirty.insert(idx, base);
            }
            let buf = self.dirty.get_mut(&idx).expect("inserido acima");
            if buf.len() < start + take {
                buf.resize(start + take, 0);
            }
            buf[start..start + take].copy_from_slice(&src[..take]);
            if buf.len() == CHUNK_SIZE {
                // pedaço completo: grava já e libera a memória
                let full = self.dirty.remove(&idx).expect("existe");
                let id = vault.store_chunk(&full).map_err(|_| EIO)?;
                if self.chunks.len() <= idx {
                    self.chunks.resize(idx + 1, None);
                }
                self.chunks[idx] = Some((id, CHUNK_SIZE));
            }
            pos += take as u64;
            src = &src[take..];
        }
        self.size = self.size.max(offset + data.len() as u64);
        self.modified = true;
        Ok(())
    }

    fn truncate(&mut self, size: u64) {
        let n = size.div_ceil(CS) as usize;
        self.chunks.truncate(n);
        self.dirty.retain(|&i, _| i < n);
        if size % CS != 0 {
            let last = n - 1;
            let keep = (size % CS) as usize;
            if let Some(buf) = self.dirty.get_mut(&last) {
                buf.truncate(keep);
            }
        }
        self.size = size;
        self.modified = true;
    }

    /// Grava os pedaços pendentes e registra o arquivo no log.
    fn commit(&mut self, vault: &mut Vault) -> Result<(), i32> {
        if !self.modified {
            return Ok(());
        }
        let n = self.size.div_ceil(CS) as usize;
        let mut ids = Vec::with_capacity(n);
        for idx in 0..n {
            let len = (self.size - idx as u64 * CS).min(CS) as usize;
            let reuse = match (self.dirty.contains_key(&idx), self.chunks.get(idx)) {
                (false, Some(Some((id, l)))) if *l == len => Some(id.clone()),
                _ => None,
            };
            let id = match reuse {
                Some(id) => id,
                None => {
                    let mut data = self.chunk_data(vault, idx)?;
                    data.resize(len, 0);
                    vault.store_chunk(&data).map_err(|_| EIO)?
                }
            };
            ids.push(id);
        }
        vault.commit_file(&self.path, self.size, ids.clone()).map_err(|_| EIO)?;
        self.chunks = ids
            .into_iter()
            .enumerate()
            .map(|(i, id)| Some((id, (self.size - i as u64 * CS).min(CS) as usize)))
            .collect();
        self.dirty.clear();
        self.modified = false;
        Ok(())
    }
}

pub struct RootFs {
    vault: Vault,
    inodes: HashMap<u64, String>,
    paths: HashMap<String, u64>,
    next_ino: u64,
    handles: HashMap<u64, Handle>,
    next_fh: u64,
    uid: u32,
    gid: u32,
    mounted_at: u64,
    exec: bool,
}

impl RootFs {
    pub fn new(vault: Vault, exec: bool) -> Self {
        let mut s = Self {
            vault,
            inodes: HashMap::new(),
            paths: HashMap::new(),
            next_ino: 2,
            handles: HashMap::new(),
            next_fh: 1,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            mounted_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            exec,
        };
        s.inodes.insert(1, String::new());
        s.paths.insert(String::new(), 1);
        s
    }

    fn ino_for(&mut self, path: &str) -> u64 {
        if let Some(i) = self.paths.get(path) {
            return *i;
        }
        let i = self.next_ino;
        self.next_ino += 1;
        self.inodes.insert(i, path.to_string());
        self.paths.insert(path.to_string(), i);
        i
    }

    fn child(&self, parent: u64, name: &OsStr) -> Option<String> {
        let dir = self.inodes.get(&parent)?;
        let name = name.to_str()?;
        if name.contains('/') || name == ".." || name == "." {
            return None;
        }
        Some(if dir.is_empty() { name.to_string() } else { format!("{dir}/{name}") })
    }

    fn attr(&mut self, path: &str) -> Option<FileAttr> {
        let open_size = self
            .handles
            .values()
            .filter(|h| h.path == path && h.modified)
            .map(|h| h.size)
            .max();
        let (kind, size, mtime) = match self.vault.tree().get(path) {
            Some(Node::File { size, mtime, .. }) => (FileType::RegularFile, open_size.unwrap_or(*size), *mtime),
            Some(Node::Dir { .. }) => (FileType::Directory, 0, self.mounted_at),
            None => (FileType::RegularFile, open_size?, self.mounted_at),
        };
        let ino = self.ino_for(path);
        let t = UNIX_EPOCH + Duration::from_secs(mtime);
        let perm = match (kind, self.exec) {
            (FileType::Directory, _) => 0o700,
            (_, true) => 0o700,
            _ => 0o600,
        };
        Some(FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: t,
            mtime: t,
            ctime: t,
            crtime: t,
            kind,
            perm,
            nlink: if kind == FileType::Directory { 2 } else { 1 },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        })
    }

    fn new_handle(&mut self, path: String, truncate: bool) -> u64 {
        let mut h = Handle::from_tree(path.clone(), self.vault.tree().get(&path));
        if truncate {
            h.truncate(0);
        }
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles.insert(fh, h);
        fh
    }

    fn commit(&mut self, fh: u64) -> Result<(), i32> {
        let Some(h) = self.handles.get_mut(&fh) else { return Ok(()) };
        h.commit(&mut self.vault)
    }
}

impl Filesystem for RootFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        match self.child(parent, name).and_then(|p| self.attr(&p)) {
            Some(a) => reply.entry(&TTL, &a, 0),
            None => reply.error(ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let Some(path) = self.inodes.get(&ino).cloned() else { return reply.error(ENOENT) };
        match self.attr(&path) {
            Some(a) => reply.attr(&TTL, &a),
            None => reply.error(ENOENT),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let Some(path) = self.inodes.get(&ino).cloned() else { return reply.error(ENOENT) };
        if let Some(size) = size {
            // truncate dentro de um open do usuário: grava no release; sem
            // handle (truncate(2) direto): abre, aplica, grava e fecha já.
            let (fh, temporary) = match fh.filter(|f| self.handles.contains_key(f)) {
                Some(f) => (f, false),
                None => (self.new_handle(path.clone(), false), true),
            };
            if let Some(h) = self.handles.get_mut(&fh) {
                h.truncate(size);
            }
            if temporary {
                let r = self.commit(fh);
                self.handles.remove(&fh);
                if let Err(e) = r {
                    return reply.error(e);
                }
            }
        }
        match self.attr(&path) {
            Some(a) => reply.attr(&TTL, &a),
            None => reply.error(ENOENT),
        }
    }

    fn mkdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, _mode: u32, _umask: u32, reply: ReplyEntry) {
        let Some(path) = self.child(parent, name) else { return reply.error(EINVAL) };
        if self.vault.tree().get(&path).is_some() {
            return reply.error(EEXIST);
        }
        if self.vault.mkdir(&path).is_err() {
            return reply.error(EIO);
        }
        match self.attr(&path) {
            Some(a) => reply.entry(&TTL, &a, 0),
            None => reply.error(EIO),
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(path) = self.child(parent, name) else { return reply.error(EINVAL) };
        match self.vault.tree().get(&path) {
            Some(Node::File { .. }) => match self.vault.remove(&path) {
                Ok(()) => reply.ok(),
                Err(_) => reply.error(EIO),
            },
            Some(Node::Dir { .. }) => reply.error(EISDIR),
            None => reply.error(ENOENT),
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(path) = self.child(parent, name) else { return reply.error(EINVAL) };
        match self.vault.tree().get(&path) {
            Some(Node::Dir { .. }) if !self.vault.tree().children(&path).is_empty() => reply.error(ENOTEMPTY),
            Some(Node::Dir { .. }) => match self.vault.remove(&path) {
                Ok(()) => reply.ok(),
                Err(_) => reply.error(EIO),
            },
            Some(Node::File { .. }) => reply.error(ENOTDIR),
            None => reply.error(ENOENT),
        }
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let (Some(from), Some(to)) = (self.child(parent, name), self.child(newparent, newname)) else {
            return reply.error(EINVAL);
        };
        match self.vault.rename(&from, &to) {
            Ok(()) => {
                // o kernel mantém o inode após o rename: remapeia (com descendentes)
                let prefix = format!("{from}/");
                let moved: Vec<(String, u64)> = self
                    .paths
                    .iter()
                    .filter(|(p, _)| **p == from || p.starts_with(&prefix))
                    .map(|(p, i)| (p.clone(), *i))
                    .collect();
                for (old, ino) in moved {
                    let new = format!("{to}{}", &old[from.len()..]);
                    self.paths.remove(&old);
                    if let Some(stale) = self.paths.insert(new.clone(), ino) {
                        self.inodes.remove(&stale);
                    }
                    self.inodes.insert(ino, new);
                }
                for h in self.handles.values_mut() {
                    if h.path == from || h.path.starts_with(&prefix) {
                        h.path = format!("{to}{}", &h.path[from.len()..]);
                    }
                }
                reply.ok()
            }
            Err(_) => reply.error(ENOENT),
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let Some(path) = self.inodes.get(&ino).cloned() else { return reply.error(ENOENT) };
        let fh = self.new_handle(path, flags & libc::O_TRUNC != 0);
        reply.opened(fh, 0);
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(path) = self.child(parent, name) else { return reply.error(EINVAL) };
        let fh = self.new_handle(path.clone(), true);
        match self.attr(&path) {
            Some(a) => reply.created(&TTL, &a, 0, fh, 0),
            None => reply.error(EIO),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        let Some(h) = self.handles.get(&fh) else { return reply.error(EIO) };
        match h.read(&self.vault, offset.max(0) as u64, size as usize) {
            Ok(d) => reply.data(&d),
            Err(e) => reply.error(e),
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyWrite,
    ) {
        let Some(h) = self.handles.get_mut(&fh) else { return reply.error(EIO) };
        match h.write(&self.vault, offset.max(0) as u64, data) {
            Ok(()) => reply.written(data.len() as u32),
            Err(e) => reply.error(e),
        }
    }

    fn flush(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _lock: u64, reply: ReplyEmpty) {
        match self.commit(fh) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let r = self.commit(fh);
        self.handles.remove(&fh);
        match r {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn readdir(&mut self, _req: &Request<'_>, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
        let Some(dir) = self.inodes.get(&ino).cloned() else { return reply.error(ENOENT) };
        let mut entries: Vec<(u64, FileType, String)> =
            vec![(ino, FileType::Directory, ".".into()), (1, FileType::Directory, "..".into())];
        let children: Vec<(String, bool)> = self
            .vault
            .tree()
            .children(&dir)
            .into_iter()
            .map(|(name, n)| (name, matches!(n, Node::Dir { .. })))
            .collect();
        for (name, is_dir) in children {
            let full = if dir.is_empty() { name.clone() } else { format!("{dir}/{name}") };
            let i = self.ino_for(&full);
            entries.push((i, if is_dir { FileType::Directory } else { FileType::RegularFile }, name));
        }
        for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(ino, (i + 1) as i64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        reply.statfs(1 << 24, 1 << 23, 1 << 23, 1 << 20, 1 << 19, 4096, 255, 4096);
    }
}

/// Monta e bloqueia até desmontar (`fusermount3 -u <ponto>` ou Ctrl-C).
/// `exec`: permite executar binários a partir do Root (jogos, Proton).
pub fn mount(vault: Vault, mountpoint: &Path, exec: bool) -> Result<(), crate::RootError> {
    let mut opts = vec![
        MountOption::FSName("mycelium-root".into()),
        MountOption::Subtype("root".into()),
        MountOption::NoDev,
        MountOption::NoSuid,
        MountOption::DefaultPermissions,
    ];
    if !exec {
        opts.push(MountOption::NoExec);
    }
    fuser::mount2(RootFs::new(vault, exec), mountpoint, &opts).map_err(|e| crate::RootError::Msg(format!("mount: {e}")))
}
