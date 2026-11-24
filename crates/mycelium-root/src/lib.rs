//! # mycelium-root — nuvem sem servidor e sem P2P
//!
//! Um **Root** é um cofre espalhado por N meios físicos seus (pendrive, cartão
//! SD, celular, HD). Cada meio guarda uma **raiz**: fragmentos Reed-Solomon de
//! pedaços cifrados, uma parte Shamir da chave e uma cópia do log cifrado de
//! metadados. Quaisquer K raízes juntas abrem tudo; menos de K não revelam
//! nada. As raízes sincronizam **por contato** (quando se encontram no mesmo
//! computador), sem rede. Ver `docs/root/ROOT.md`.

pub mod chunk;
pub mod keys;
pub mod log;
pub mod roots;
#[cfg(feature = "mount")]
pub mod mount;

use entropy::{ChaosKey, Shade, Vault as Shamir};
use keys::{key_check, Keys};
use log::{normalize, Entry, Node, Op, Tree};
use rand::RngCore;
use roots::{io, write_atomic, Root, RootMeta, FORMAT};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum RootError {
    #[error("{0}")]
    Msg(String),
    #[error("raízes insuficientes: {have} de {need}")]
    NotEnough { have: usize, need: usize },
    #[error("falha de autenticação/cifragem")]
    Crypto,
    #[error("pedaço {0} corrompido em todas as combinações de fragmentos")]
    Corrupt(String),
    #[error("não existe: {0}")]
    NotFound(String),
}

/// Relatório de uma sincronização por contato.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub log_copied: usize,
    pub delivered: usize,
}

/// Pedaços decifrados recentes (jogos leem o mesmo trecho várias vezes).
struct ChunkCache {
    map: HashMap<String, std::rc::Rc<Vec<u8>>>,
    order: std::collections::VecDeque<String>,
    cap: usize,
}

impl ChunkCache {
    fn get(&mut self, id: &str) -> Option<std::rc::Rc<Vec<u8>>> {
        self.map.get(id).cloned()
    }
    fn put(&mut self, id: String, data: std::rc::Rc<Vec<u8>>) {
        if self.map.insert(id.clone(), data).is_none() {
            self.order.push_back(id);
        }
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }
}

pub struct Vault {
    cache: std::cell::RefCell<ChunkCache>,
    roots: Vec<Root>,
    vault: String,
    k: u8,
    n: u8,
    keys: Keys,
    writer: String,
    entries: Vec<Entry>,
    tree: Tree,
}

impl Vault {
    /// Cria um Root K-de-N, uma raiz por caminho (N = número de caminhos).
    pub fn create(paths: &[PathBuf], k: u8, label: &str) -> Result<Self, RootError> {
        let n = u8::try_from(paths.len()).map_err(|_| RootError::Msg("no máximo 255 raízes".into()))?;
        if k == 0 || k > n {
            return Err(RootError::Msg(format!("K precisa estar em 1..={n}")));
        }
        if paths.iter().any(|p| Root::exists(p)) {
            return Err(RootError::Msg("algum caminho já é uma raiz".into()));
        }
        let distinct: BTreeSet<_> = paths.iter().map(|p| p.canonicalize().unwrap_or(p.clone())).collect();
        if distinct.len() != paths.len() {
            return Err(RootError::Msg("caminhos repetidos".into()));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(key.as_mut());
        let shares = Shamir::shatter(key.as_ref(), k, n).map_err(|e| RootError::Msg(e.to_string()))?;
        let mut vid = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut vid);
        let vault = hex::encode(vid);
        let check = key_check(&key);
        for (path, share) in paths.iter().zip(shares) {
            fs::create_dir_all(path).map_err(|e| io(path, e))?;
            Root::create(
                path,
                RootMeta {
                    format: FORMAT,
                    vault: vault.clone(),
                    index: share.index,
                    n,
                    k,
                    share,
                    check: check.clone(),
                    label: label.to_string(),
                },
            )?;
        }
        Self::open(paths)
    }

    /// Abre com as raízes presentes (precisa de pelo menos K). Ao abrir, já
    /// sincroniza por contato as raízes presentes.
    pub fn open(paths: &[PathBuf]) -> Result<Self, RootError> {
        let roots = load_roots(paths)?;
        let first = &roots[0].meta;
        let (vault, k, n) = (first.vault.clone(), first.k, first.n);
        if roots.len() < k as usize {
            return Err(RootError::NotEnough {
                have: roots.len(),
                need: k as usize,
            });
        }
        let shades: Vec<Shade> = roots.iter().map(|r| r.meta.share.clone()).collect();
        let secret = ChaosKey::materialize(&shades, k).map_err(|e| RootError::Msg(e.to_string()))?;
        let bytes = secret.reveal().map_err(|e| RootError::Msg(e.to_string()))?;
        let mut key = Zeroizing::new([0u8; 32]);
        if bytes.len() != 32 {
            return Err(RootError::Crypto);
        }
        key.copy_from_slice(bytes);
        drop(secret);
        if key_check(&key) != first.check {
            return Err(RootError::Msg("as partes não reconstroem a chave (raiz adulterada?)".into()));
        }
        let keys = Keys::derive(&key);
        sync_roots(&roots)?;
        let mut w = [0u8; 4];
        rand::rngs::OsRng.fill_bytes(&mut w);
        let mut v = Self {
            cache: std::cell::RefCell::new(ChunkCache {
                map: HashMap::new(),
                order: Default::default(),
                cap: 96, // ~96 MiB
            }),
            roots,
            vault,
            k,
            n,
            keys,
            writer: hex::encode(w),
            entries: Vec::new(),
            tree: Tree::default(),
        };
        v.reload()?;
        Ok(v)
    }

    pub fn k(&self) -> u8 {
        self.k
    }
    pub fn n(&self) -> u8 {
        self.n
    }
    pub fn vault_id(&self) -> &str {
        &self.vault
    }
    pub fn present(&self) -> Vec<u8> {
        self.roots.iter().map(|r| r.meta.index).collect()
    }
    pub fn tree(&self) -> &Tree {
        &self.tree
    }
    pub fn history(&self) -> &[Entry] {
        &self.entries
    }

    /// Relê o log de todas as raízes presentes e reconstrói a árvore.
    pub fn reload(&mut self) -> Result<(), RootError> {
        let mut by_id: HashMap<String, Entry> = HashMap::new();
        for r in &self.roots {
            let Ok(dir) = fs::read_dir(r.log_dir()) else { continue };
            for e in dir.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                let Some(id) = name.strip_suffix(".e") else { continue };
                if by_id.contains_key(id) {
                    continue;
                }
                let raw = fs::read(e.path()).map_err(|er| io(&e.path(), er))?;
                // entrada que não autentica é ignorada (não pode ser forjada sem a chave)
                if let Ok(entry) = log::open_entry(&self.keys, id, &raw) {
                    by_id.insert(id.to_string(), entry);
                }
            }
        }
        let mut entries: Vec<Entry> = by_id.into_values().collect();
        entries.sort_by(|a, b| (a.lamport, &a.writer, &a.id).cmp(&(b.lamport, &b.writer, &b.id)));
        self.tree = Tree::replay(&entries);
        self.entries = entries;
        Ok(())
    }

    fn append(&mut self, op: Op, base: Option<String>) -> Result<(), RootError> {
        // pedaços gravados sem fsync individual: um syncfs por raiz antes da
        // entrada de log garante que o log nunca aponta para dado não durável
        for r in &self.roots {
            roots::sync_fs(&r.root_dir());
        }
        let lamport = self.entries.last().map(|e| e.lamport).unwrap_or(0) + 1;
        let (id, sealed) = log::seal_entry(&self.keys, lamport, &self.writer, base, op)?;
        for r in &self.roots {
            write_atomic(&r.log_dir().join(format!("{id}.e")), &sealed)?;
        }
        let entry = log::open_entry(&self.keys, &id, &sealed)?;
        self.tree.apply(&entry);
        self.entries.push(entry);
        Ok(())
    }

    /// Grava um arquivo lendo de `reader` em pedaços (memória constante).
    pub fn write_stream(&mut self, path: &str, reader: &mut dyn std::io::Read) -> Result<u64, RootError> {
        let mut ids = Vec::new();
        let mut size = 0u64;
        let mut buf = vec![0u8; chunk::CHUNK_SIZE];
        loop {
            let mut filled = 0;
            while filled < buf.len() {
                match reader.read(&mut buf[filled..]) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(RootError::Msg(e.to_string())),
                }
            }
            if filled == 0 {
                break;
            }
            ids.push(self.store_chunk(&buf[..filled])?);
            size += filled as u64;
            if filled < buf.len() {
                break;
            }
        }
        self.commit_file(path, size, ids)?;
        Ok(size)
    }

    /// Registra um arquivo cujos pedaços já foram gravados com `store_chunk`.
    pub fn commit_file(&mut self, path: &str, size: u64, chunks: Vec<String>) -> Result<(), RootError> {
        let path = normalize(path).ok_or_else(|| RootError::Msg(format!("caminho inválido: {path}")))?;
        if path.is_empty() {
            return Err(RootError::Msg("caminho vazio".into()));
        }
        let expect = size.div_ceil(chunk::CHUNK_SIZE as u64) as usize;
        if chunks.len() != expect {
            return Err(RootError::Msg(format!("{path}: {} pedaços para {size} bytes", chunks.len())));
        }
        let base = self.tree.entry_of(&path);
        self.append(
            Op::Put {
                path,
                size,
                mtime: now_secs(),
                chunks,
            },
            base,
        )
    }

    /// Lê `len` bytes a partir de `offset`, carregando só os pedaços tocados.
    pub fn read_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, RootError> {
        let path = normalize(path).ok_or_else(|| RootError::NotFound(path.to_string()))?;
        let Some(Node::File { chunks, size, .. }) = self.tree.get(&path) else {
            return Err(RootError::NotFound(path));
        };
        read_chunks_range(self, chunks, *size, offset, len)
    }

    /// Grava (ou substitui) um arquivo.
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), RootError> {
        let path = normalize(path).ok_or_else(|| RootError::Msg(format!("caminho inválido: {path}")))?;
        if path.is_empty() {
            return Err(RootError::Msg("caminho vazio".into()));
        }
        let mut ids = Vec::new();
        for piece in data.chunks(chunk::CHUNK_SIZE) {
            ids.push(self.store_chunk(piece)?);
        }
        self.commit_file(&path, data.len() as u64, ids)
    }

    /// Cifra, codifica e grava um pedaço (até `CHUNK_SIZE`). Devolve o id.
    pub fn store_chunk(&self, plain: &[u8]) -> Result<String, RootError> {
        let id = chunk::chunk_id(&self.keys, plain);
        let present: HashMap<u8, &Root> = self.roots.iter().map(|r| (r.meta.index, r)).collect();
        // dedup: já gravado em todas as raízes presentes?
        let complete = (1..=self.n).all(|i| match present.get(&i) {
            Some(r) => r.chunk_path(&id).exists(),
            None => self.roots.iter().any(|r| r.carry_path(i, &id).exists()),
        });
        if complete {
            return Ok(id);
        }
        let frags = chunk::encode(&self.keys, &id, plain, self.k, self.n)?;
        for (i, frag) in (1..=self.n).zip(frags) {
            match present.get(&i) {
                Some(r) => roots::write_nosync(&r.chunk_path(&id), &frag)?,
                // raiz ausente: todas as presentes levam o fragmento dela
                None => {
                    for r in &self.roots {
                        roots::write_nosync(&r.carry_path(i, &id), &frag)?;
                    }
                }
            }
        }
        Ok(id)
    }

    /// Pedaço decifrado (com cache).
    pub fn load_chunk(&self, id: &str) -> Result<std::rc::Rc<Vec<u8>>, RootError> {
        if let Some(hit) = self.cache.borrow_mut().get(id) {
            return Ok(hit);
        }
        let data = std::rc::Rc::new(self.load_chunk_uncached(id)?);
        self.cache.borrow_mut().put(id.to_string(), data.clone());
        Ok(data)
    }

    fn load_chunk_uncached(&self, id: &str) -> Result<Vec<u8>, RootError> {
        let mut frags: Vec<Option<Vec<u8>>> = vec![None; self.n as usize];
        for i in 1..=self.n {
            let mut candidates: Vec<PathBuf> = Vec::new();
            for r in &self.roots {
                if r.meta.index == i {
                    candidates.push(r.chunk_path(id));
                }
                candidates.push(r.carry_path(i, id));
            }
            frags[(i - 1) as usize] = candidates.iter().find_map(|p| fs::read(p).ok());
        }
        chunk::decode(&self.keys, id, &frags, self.k, self.n)
    }

    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, RootError> {
        let path = normalize(path).ok_or_else(|| RootError::NotFound(path.to_string()))?;
        match self.tree.get(&path) {
            Some(Node::File { chunks, size, .. }) => {
                let mut out = Vec::with_capacity(*size as usize);
                for id in chunks {
                    out.extend_from_slice(&self.load_chunk(id)?);
                }
                if out.len() as u64 != *size {
                    return Err(RootError::Corrupt(path));
                }
                Ok(out)
            }
            _ => Err(RootError::NotFound(path)),
        }
    }

    pub fn mkdir(&mut self, path: &str) -> Result<(), RootError> {
        let path = normalize(path).ok_or_else(|| RootError::Msg(format!("caminho inválido: {path}")))?;
        if path.is_empty() || self.tree.get(&path).is_some() {
            return Ok(());
        }
        self.append(Op::Mkdir { path }, None)
    }

    pub fn remove(&mut self, path: &str) -> Result<(), RootError> {
        let path = normalize(path).ok_or_else(|| RootError::NotFound(path.to_string()))?;
        if self.tree.get(&path).is_none() {
            return Err(RootError::NotFound(path));
        }
        let base = self.tree.entry_of(&path);
        self.append(Op::Remove { path }, base)
    }

    /// Renomeia sem recodificar: reaproveita os pedaços.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), RootError> {
        let from = normalize(from).ok_or_else(|| RootError::NotFound(from.to_string()))?;
        let to = normalize(to).ok_or_else(|| RootError::Msg(format!("caminho inválido: {to}")))?;
        let moves: Vec<(String, Node)> = self
            .tree
            .iter()
            .filter(|(p, _)| *p == &from || p.starts_with(&format!("{from}/")))
            .map(|(p, n)| (p.clone(), n.clone()))
            .collect();
        if moves.is_empty() {
            return Err(RootError::NotFound(from));
        }
        for (p, node) in moves {
            let dest = format!("{to}{}", &p[from.len()..]);
            let base = self.tree.entry_of(&dest);
            match node {
                Node::File { size, mtime, chunks, .. } => self.append(
                    Op::Put {
                        path: dest,
                        size,
                        mtime,
                        chunks,
                    },
                    base,
                )?,
                Node::Dir { .. } => self.append(Op::Mkdir { path: dest }, None)?,
            }
        }
        let base = self.tree.entry_of(&from);
        self.append(Op::Remove { path: from }, base)
    }

    /// Recria a raiz de índice `index` (perdida) num meio novo.
    pub fn heal(&mut self, index: u8, new_path: &Path) -> Result<(), RootError> {
        if index == 0 || index > self.n {
            return Err(RootError::Msg(format!("índice fora de 1..={}", self.n)));
        }
        if self.roots.iter().any(|r| r.meta.index == index) {
            return Err(RootError::Msg(format!("a raiz {index} está presente; nada a repor")));
        }
        let shades: Vec<Shade> = self.roots.iter().map(|r| r.meta.share.clone()).collect();
        let share = Shamir::shade_at(&shades, self.k, index).map_err(|e| RootError::Msg(e.to_string()))?;
        let template = &self.roots[0].meta;
        fs::create_dir_all(new_path).map_err(|e| io(new_path, e))?;
        let root = Root::create(
            new_path,
            RootMeta {
                format: FORMAT,
                vault: self.vault.clone(),
                index,
                n: self.n,
                k: self.k,
                share,
                check: template.check.clone(),
                label: template.label.clone(),
            },
        )?;
        // todos os pedaços já referenciados no histórico
        let ids: BTreeSet<String> = self
            .entries
            .iter()
            .filter_map(|e| match &e.op {
                Op::Put { chunks, .. } => Some(chunks.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        for id in &ids {
            let plain = self.load_chunk_uncached(id)?;
            let frags = chunk::encode(&self.keys, id, &plain, self.k, self.n)?;
            write_atomic(&root.chunk_path(id), &frags[(index - 1) as usize])?;
            for r in &self.roots {
                let _ = fs::remove_file(r.carry_path(index, id));
            }
        }
        self.roots.push(root);
        sync_roots(&self.roots)?;
        Ok(())
    }
}

/// Sincronização por contato entre as raízes presentes. **Não precisa da
/// chave**: copia entradas de log cifradas que faltam e entrega fragmentos
/// levados (`carry/`) à raiz de destino. Funciona com qualquer número de
/// raízes presentes, até com menos de K.
pub fn sync(paths: &[PathBuf]) -> Result<SyncReport, RootError> {
    let roots = load_roots(paths)?;
    sync_roots(&roots)
}

fn sync_roots(roots: &[Root]) -> Result<SyncReport, RootError> {
    let mut report = SyncReport::default();
    // 1. log: união
    let mut all: HashMap<String, PathBuf> = HashMap::new();
    for r in roots {
        if let Ok(dir) = fs::read_dir(r.log_dir()) {
            for e in dir.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.ends_with(".e") {
                    all.entry(name).or_insert(e.path());
                }
            }
        }
    }
    for r in roots {
        for (name, src) in &all {
            let dst = r.log_dir().join(name);
            if !dst.exists() {
                let bytes = fs::read(src).map_err(|e| io(src, e))?;
                write_atomic(&dst, &bytes)?;
                report.log_copied += 1;
            }
        }
    }
    // 2. carry: entrega e propagação
    let present: HashMap<u8, &Root> = roots.iter().map(|r| (r.meta.index, r)).collect();
    let mut carried: HashMap<(u8, String), PathBuf> = HashMap::new();
    for r in roots {
        let Ok(targets) = fs::read_dir(r.root_dir().join("carry")) else { continue };
        for t in targets.flatten() {
            let Ok(target) = t.file_name().to_string_lossy().parse::<u8>() else { continue };
            let Ok(files) = fs::read_dir(t.path()) else { continue };
            for f in files.flatten() {
                let name = f.file_name().to_string_lossy().to_string();
                carried.entry((target, name)).or_insert(f.path());
            }
        }
    }
    for ((target, name), src) in &carried {
        let Some(id) = name.strip_suffix(&format!(".{target}")) else { continue };
        if id.len() < 2 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        if let Some(dest) = present.get(target) {
            let dst = dest.chunk_path(id);
            if !dst.exists() {
                let bytes = fs::read(src).map_err(|e| io(src, e))?;
                write_atomic(&dst, &bytes)?;
                report.delivered += 1;
            }
            for r in roots {
                let _ = fs::remove_file(r.carry_path(*target, id));
            }
        } else {
            // destino ainda ausente: toda raiz presente passa a levar
            for r in roots {
                let dst = r.carry_path(*target, id);
                if !dst.exists() {
                    let bytes = fs::read(src).map_err(|e| io(src, e))?;
                    write_atomic(&dst, &bytes)?;
                }
            }
        }
    }
    Ok(report)
}

/// Trecho `[offset, offset+len)` de um arquivo descrito por seus pedaços.
pub fn read_chunks_range(
    v: &Vault,
    chunks: &[String],
    size: u64,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, RootError> {
    if offset >= size || len == 0 {
        return Ok(Vec::new());
    }
    let end = size.min(offset + len as u64);
    let cs = chunk::CHUNK_SIZE as u64;
    let mut out = Vec::with_capacity((end - offset) as usize);
    let mut pos = offset;
    while pos < end {
        let idx = (pos / cs) as usize;
        let id = chunks.get(idx).ok_or_else(|| RootError::Corrupt(format!("pedaço {idx}")))?;
        let data = v.load_chunk(id)?;
        let start = (pos % cs) as usize;
        let stop = ((end - idx as u64 * cs) as usize).min(data.len());
        if start >= stop {
            return Err(RootError::Corrupt(id.clone()));
        }
        out.extend_from_slice(&data[start..stop]);
        pos += (stop - start) as u64;
    }
    Ok(out)
}

fn load_roots(paths: &[PathBuf]) -> Result<Vec<Root>, RootError> {
    if paths.is_empty() {
        return Err(RootError::Msg("nenhuma raiz informada".into()));
    }
    let mut roots: Vec<Root> = Vec::new();
    for p in paths {
        let r = Root::open(p)?;
        if let Some(first) = roots.first() {
            if r.meta.vault != first.meta.vault || r.meta.k != first.meta.k || r.meta.n != first.meta.n {
                return Err(RootError::Msg(format!("{} é de outro Root", p.display())));
            }
        }
        if roots.iter().any(|x| x.meta.index == r.meta.index) {
            continue; // mesma raiz informada duas vezes
        }
        roots.push(r);
    }
    Ok(roots)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
