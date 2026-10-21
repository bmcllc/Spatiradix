//! Log de metadados: entradas cifradas, só acréscimo, ordenadas por relógio de
//! Lamport. A árvore de arquivos é o replay do log. Edição concorrente vira
//! cópia de conflito, nunca perda.

use crate::keys::Keys;
use crate::RootError;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Op {
    Put {
        path: String,
        size: u64,
        mtime: u64,
        chunks: Vec<String>,
    },
    Mkdir {
        path: String,
    },
    Remove {
        path: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Body {
    lamport: u64,
    writer: String,
    /// Entrada vigente no caminho quando esta foi escrita (detecção de conflito).
    base: Option<String>,
    op: Op,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub id: String,
    pub lamport: u64,
    pub writer: String,
    pub base: Option<String>,
    pub op: Op,
}

pub fn seal_entry(
    keys: &Keys,
    lamport: u64,
    writer: &str,
    base: Option<String>,
    op: Op,
) -> Result<(String, Vec<u8>), RootError> {
    let body = Body {
        lamport,
        writer: writer.to_string(),
        base,
        op,
    };
    let json = serde_json::to_vec(&body).map_err(|e| RootError::Msg(e.to_string()))?;
    let h = blake3::keyed_hash(&keys.mac, &json);
    let id = format!("{lamport:016}-{writer}-{}", &h.to_hex()[..12]);
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new((&keys.log).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &json,
                aad: id.as_bytes(),
            },
        )
        .map_err(|_| RootError::Crypto)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok((id, out))
}

/// Decifra e confere que o nome do arquivo (id) é o desta entrada.
pub fn open_entry(keys: &Keys, id: &str, raw: &[u8]) -> Result<Entry, RootError> {
    if raw.len() < 24 + 16 {
        return Err(RootError::Crypto);
    }
    let json = XChaCha20Poly1305::new((&keys.log).into())
        .decrypt(
            XNonce::from_slice(&raw[..24]),
            Payload {
                msg: &raw[24..],
                aad: id.as_bytes(),
            },
        )
        .map_err(|_| RootError::Crypto)?;
    let body: Body = serde_json::from_slice(&json).map_err(|_| RootError::Crypto)?;
    let h = blake3::keyed_hash(&keys.mac, &json);
    let expect = format!("{:016}-{}-{}", body.lamport, body.writer, &h.to_hex()[..12]);
    if expect != id {
        return Err(RootError::Crypto);
    }
    Ok(Entry {
        id: id.to_string(),
        lamport: body.lamport,
        writer: body.writer,
        base: body.base,
        op: body.op,
    })
}

#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    File {
        size: u64,
        mtime: u64,
        chunks: Vec<String>,
        entry: String,
    },
    Dir {
        entry: Option<String>,
    },
}

#[derive(Clone, Debug, Default)]
pub struct Tree {
    nodes: BTreeMap<String, Node>,
}

impl Tree {
    pub fn replay(entries: &[Entry]) -> Self {
        let mut t = Tree::default();
        for e in entries {
            match &e.op {
                Op::Put {
                    path,
                    size,
                    mtime,
                    chunks,
                } => {
                    let conflict = match t.nodes.get(path) {
                        None => false,
                        Some(Node::Dir { .. }) => true,
                        Some(Node::File { entry, .. }) => e.base.as_deref() != Some(entry.as_str()),
                    };
                    let dest = if conflict { conflict_name(path, &e.writer) } else { path.clone() };
                    t.ensure_parents(&dest);
                    t.nodes.insert(
                        dest,
                        Node::File {
                            size: *size,
                            mtime: *mtime,
                            chunks: chunks.clone(),
                            entry: e.id.clone(),
                        },
                    );
                }
                Op::Mkdir { path } => {
                    if !matches!(t.nodes.get(path), Some(Node::File { .. })) {
                        t.ensure_parents(path);
                        t.nodes.insert(path.clone(), Node::Dir { entry: Some(e.id.clone()) });
                    }
                }
                Op::Remove { path } => {
                    // remoção baseada numa versão antiga não apaga edição mais nova
                    if let Some(Node::File { entry, .. }) = t.nodes.get(path) {
                        if e.base.as_deref() != Some(entry.as_str()) {
                            continue;
                        }
                    }
                    let prefix = format!("{path}/");
                    t.nodes.retain(|p, _| p != path && !p.starts_with(&prefix));
                }
            }
        }
        t
    }

    fn ensure_parents(&mut self, path: &str) {
        let mut acc = String::new();
        let parts: Vec<&str> = path.split('/').collect();
        for part in &parts[..parts.len().saturating_sub(1)] {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(part);
            self.nodes.entry(acc.clone()).or_insert(Node::Dir { entry: None });
        }
    }

    pub fn get(&self, path: &str) -> Option<&Node> {
        if path.is_empty() {
            return Some(&Node::Dir { entry: None });
        }
        self.nodes.get(path)
    }

    pub fn entry_of(&self, path: &str) -> Option<String> {
        match self.nodes.get(path) {
            Some(Node::File { entry, .. }) => Some(entry.clone()),
            Some(Node::Dir { entry }) => entry.clone(),
            None => None,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Node)> {
        self.nodes.iter()
    }

    /// Filhos diretos de `dir` ("" = raiz).
    pub fn children(&self, dir: &str) -> Vec<(String, &Node)> {
        let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
        self.nodes
            .iter()
            .filter(|(p, _)| p.starts_with(&prefix) && !p[prefix.len()..].contains('/') && p.len() > prefix.len())
            .map(|(p, n)| (p[prefix.len()..].to_string(), n))
            .collect()
    }
}

fn conflict_name(path: &str, writer: &str) -> String {
    let (dir, file) = match path.rsplit_once('/') {
        Some((d, f)) => (format!("{d}/"), f),
        None => (String::new(), path),
    };
    match file.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{dir}{stem} (conflito {writer}).{ext}"),
        _ => format!("{dir}{file} (conflito {writer})"),
    }
}

/// Caminho relativo canônico: sem `..`, sem barra inicial, sem componente vazio.
pub fn normalize(path: &str) -> Option<String> {
    let mut parts = Vec::new();
    for p in path.split('/') {
        match p {
            "" | "." => continue,
            ".." => return None,
            p if p.contains('\0') || p.contains('\\') => return None,
            p => parts.push(p),
        }
    }
    Some(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(id: &str, lamport: u64, writer: &str, base: Option<&str>, path: &str) -> Entry {
        Entry {
            id: id.into(),
            lamport,
            writer: writer.into(),
            base: base.map(String::from),
            op: Op::Put {
                path: path.into(),
                size: 1,
                mtime: 0,
                chunks: vec![],
            },
        }
    }

    #[test]
    fn concurrent_edits_become_conflict_copies() {
        let e = vec![
            put("1", 1, "aa", None, "doc.txt"),
            put("2", 2, "aa", Some("1"), "doc.txt"),
            put("3", 2, "bb", Some("1"), "doc.txt"),
        ];
        let t = Tree::replay(&e);
        assert!(matches!(t.get("doc.txt"), Some(Node::File { entry, .. }) if entry == "2"));
        assert!(t.get("doc (conflito bb).txt").is_some());
    }

    #[test]
    fn stale_remove_does_not_delete_newer_edit() {
        let mut e = vec![put("1", 1, "aa", None, "x"), put("2", 2, "aa", Some("1"), "x")];
        e.push(Entry {
            id: "3".into(),
            lamport: 2,
            writer: "bb".into(),
            base: Some("1".into()),
            op: Op::Remove { path: "x".into() },
        });
        assert!(Tree::replay(&e).get("x").is_some());
    }

    #[test]
    fn normalize_rejects_traversal() {
        assert_eq!(normalize("/a//b/./c").as_deref(), Some("a/b/c"));
        assert!(normalize("a/../b").is_none());
    }
}
