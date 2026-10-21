//! `mount`: o Root aparece como uma pasta comum (um "pendrive").
//!
//! Leitura reconstrói o arquivo inteiro na abertura; escrita fica num buffer
//! em memória e vira uma entrada `put` quando o arquivo é fechado. Nada é
//! gravado no computador: só nas raízes.

use crate::log::Node;
use crate::Vault;
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow,
};
use libc::{EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOTDIR, ENOTEMPTY};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);

struct Handle {
    path: String,
    data: Vec<u8>,
    dirty: bool,
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
}

impl RootFs {
    pub fn new(vault: Vault) -> Self {
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

    /// Tamanho visto pelo kernel: buffer sujo aberto vence a árvore.
    fn attr(&mut self, path: &str) -> Option<FileAttr> {
        let open_size = self
            .handles
            .values()
            .filter(|h| h.path == path && h.dirty)
            .map(|h| h.data.len() as u64)
            .max();
        let (kind, size, mtime) = match self.vault.tree().get(path) {
            Some(Node::File { size, mtime, .. }) => (FileType::RegularFile, open_size.unwrap_or(*size), *mtime),
            Some(Node::Dir { .. }) => (FileType::Directory, 0, self.mounted_at),
            None => (FileType::RegularFile, open_size?, 0),
        };
        let ino = self.ino_for(path);
        let t = UNIX_EPOCH + Duration::from_secs(mtime);
        Some(FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: t,
            mtime: t,
            ctime: t,
            crtime: t,
            kind,
            perm: if kind == FileType::Directory { 0o700 } else { 0o600 },
            nlink: if kind == FileType::Directory { 2 } else { 1 },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        })
    }

    fn open_handle(&mut self, path: String, load: bool) -> Result<u64, i32> {
        let data = if load {
            match self.vault.read_file(&path) {
                Ok(d) => d,
                Err(_) => return Err(EIO),
            }
        } else {
            Vec::new()
        };
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles.insert(fh, Handle { path, data, dirty: !load });
        Ok(fh)
    }

    fn commit(&mut self, fh: u64) -> Result<(), i32> {
        let Some(h) = self.handles.get_mut(&fh) else { return Ok(()) };
        if !h.dirty {
            return Ok(());
        }
        let (path, data) = (h.path.clone(), h.data.clone());
        h.dirty = false;
        self.vault.write_file(&path, &data).map_err(|_| EIO)
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
                None => match self.open_handle(path.clone(), self.vault.tree().get(&path).is_some()) {
                    Ok(f) => (f, true),
                    Err(e) => return reply.error(e),
                },
            };
            if let Some(h) = self.handles.get_mut(&fh) {
                h.data.resize(size as usize, 0);
                h.dirty = true;
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
        let truncate = flags & libc::O_TRUNC != 0;
        match self.open_handle(path, !truncate) {
            Ok(fh) => reply.opened(fh, 0),
            Err(e) => reply.error(e),
        }
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
        let fh = match self.open_handle(path.clone(), false) {
            Ok(f) => f,
            Err(e) => return reply.error(e),
        };
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
        let start = (offset.max(0) as usize).min(h.data.len());
        let end = (start + size as usize).min(h.data.len());
        reply.data(&h.data[start..end]);
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
        let off = offset.max(0) as usize;
        if h.data.len() < off + data.len() {
            h.data.resize(off + data.len(), 0);
        }
        h.data[off..off + data.len()].copy_from_slice(data);
        h.dirty = true;
        reply.written(data.len() as u32);
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
        let mut entries: Vec<(u64, FileType, String)> = vec![(ino, FileType::Directory, ".".into()), (1, FileType::Directory, "..".into())];
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
        reply.statfs(1 << 20, 1 << 19, 1 << 19, 1 << 20, 1 << 19, 4096, 255, 4096);
    }
}

/// Monta e bloqueia até desmontar (`fusermount3 -u <ponto>` ou Ctrl-C).
pub fn mount(vault: Vault, mountpoint: &Path) -> Result<(), crate::RootError> {
    let opts = vec![
        MountOption::FSName("mycelium-root".into()),
        MountOption::Subtype("root".into()),
        MountOption::NoDev,
        MountOption::NoSuid,
        MountOption::NoExec,
        MountOption::DefaultPermissions,
    ];
    fuser::mount2(RootFs::new(vault), mountpoint, &opts).map_err(|e| crate::RootError::Msg(format!("mount: {e}")))
}
