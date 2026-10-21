//! Aceitação do Root: cada promessa de `docs/root/ROOT.md` vira um teste.
//! As "raízes" são diretórios temporários que fazem o papel de pendrives.

use mycelium_root::{sync, RootError, Vault};
use std::fs;
use std::path::{Path, PathBuf};

struct Media(Vec<PathBuf>);

impl Media {
    fn new(tag: &str, n: usize) -> Self {
        let base = std::env::temp_dir().join(format!("myc-root-{tag}-{}", rand_u64()));
        Self((1..=n).map(|i| base.join(format!("raiz{i}"))).collect())
    }
    fn pick(&self, idx: &[usize]) -> Vec<PathBuf> {
        idx.iter().map(|i| self.0[i - 1].clone()).collect()
    }
}

impl Drop for Media {
    fn drop(&mut self) {
        if let Some(parent) = self.0.first().and_then(|p| p.parent()) {
            let _ = fs::remove_dir_all(parent);
        }
    }
}

fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 ^ (std::process::id() as u64) << 32
}

fn all_bytes(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.extend(fs::read(&p).unwrap());
                out.extend(p.to_string_lossy().as_bytes());
            }
        }
    }
    out
}

fn big(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + i / 3) as u8).collect()
}

#[test]
fn any_k_roots_open_everything() {
    let m = Media::new("k", 3);
    let photo = big(2_500_000); // 3 pedaços
    {
        let mut v = Vault::create(&m.0, 2, "teste").unwrap();
        v.write_file("fotos/ferias.jpg", &photo).unwrap();
        v.write_file("vazio.txt", b"").unwrap();
        v.mkdir("docs/vazia").unwrap();
    }
    for pair in [[1, 2], [1, 3], [2, 3]] {
        let v = Vault::open(&m.pick(&pair)).unwrap();
        assert_eq!(v.read_file("fotos/ferias.jpg").unwrap(), photo, "{pair:?}");
        assert_eq!(v.read_file("vazio.txt").unwrap(), b"");
        assert!(v.tree().get("docs/vazia").is_some());
    }
}

#[test]
fn fewer_than_k_reveals_nothing() {
    let m = Media::new("leak", 3);
    {
        let mut v = Vault::create(&m.0, 2, "teste").unwrap();
        v.write_file("segredo-NOME-UNICO.txt", b"CONTEUDO-SECRETO-MARCADOR").unwrap();
    }
    assert!(matches!(Vault::open(&m.pick(&[2])), Err(RootError::NotEnough { have: 1, need: 2 })));
    for root in &m.0 {
        let bytes = all_bytes(root);
        for needle in [&b"CONTEUDO-SECRETO-MARCADOR"[..], b"segredo-NOME-UNICO"] {
            assert!(!bytes.windows(needle.len()).any(|w| w == needle), "texto claro numa raiz");
        }
    }
}

#[test]
fn absent_root_receives_by_contact() {
    let m = Media::new("carry", 3);
    Vault::create(&m.0, 2, "teste").unwrap();
    // escreve só com 1 e 2 plugadas: fragmento da 3 vai em carry/
    {
        let mut v = Vault::open(&m.pick(&[1, 2])).unwrap();
        v.write_file("nota.txt", b"escrito sem a raiz 3").unwrap();
    }
    // 2 encontra 3 (sem chave, só contato): entrega log + fragmento
    let r = sync(&m.pick(&[2, 3])).unwrap();
    assert!(r.log_copied >= 1 && r.delivered >= 1, "{r:?}");
    // agora 1 + 3 (a 3 nunca esteve presente na escrita) leem o arquivo
    let v = Vault::open(&m.pick(&[1, 3])).unwrap();
    assert_eq!(v.read_file("nota.txt").unwrap(), b"escrito sem a raiz 3");
}

#[test]
fn concurrent_edits_on_disjoint_roots_keep_both() {
    let m = Media::new("conf", 4);
    {
        let mut v = Vault::create(&m.0, 2, "teste").unwrap();
        v.write_file("lista.txt", b"v0").unwrap();
    }
    // computador A com raízes 1,2; computador B com 3,4 — sem contato entre si
    Vault::open(&m.pick(&[1, 2])).unwrap().write_file("lista.txt", b"versao A").unwrap();
    Vault::open(&m.pick(&[3, 4])).unwrap().write_file("lista.txt", b"versao B").unwrap();
    let v = Vault::open(&m.0).unwrap();
    let names: Vec<String> = v.tree().children("").into_iter().map(|(n, _)| n).collect();
    let contents: Vec<Vec<u8>> = names.iter().map(|n| v.read_file(n).unwrap()).collect();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(contents.contains(&b"versao A".to_vec()) && contents.contains(&b"versao B".to_vec()));
    assert!(names.iter().any(|n| n.contains("conflito")));
}

#[test]
fn lost_root_is_healed_on_new_media() {
    let m = Media::new("heal", 3);
    let data = big(1_500_000);
    {
        let mut v = Vault::create(&m.0, 2, "teste").unwrap();
        v.write_file("backup.tar", &data).unwrap();
    }
    fs::remove_dir_all(&m.0[2]).unwrap(); // pendrive 3 perdido
    let novo = m.0[0].parent().unwrap().join("pendrive-novo");
    Vault::open(&m.pick(&[1, 2])).unwrap().heal(3, &novo).unwrap();
    // o meio novo substitui o perdido: abre com qualquer outra
    let v = Vault::open(&[novo.clone(), m.0[0].clone()]).unwrap();
    assert_eq!(v.read_file("backup.tar").unwrap(), data);
    let v = Vault::open(&[novo, m.0[1].clone()]).unwrap();
    assert_eq!(v.read_file("backup.tar").unwrap(), data);
}

#[test]
fn corruption_and_tampering_are_contained() {
    let m = Media::new("tamper", 3);
    {
        let mut v = Vault::create(&m.0, 2, "teste").unwrap();
        v.write_file("a.bin", &big(4000)).unwrap();
    }
    // corrompe todos os fragmentos da raiz 1
    let chunks = m.0[0].join(".mycelium-root/chunks");
    for d in fs::read_dir(&chunks).unwrap().flatten() {
        for f in fs::read_dir(d.path()).unwrap().flatten() {
            let mut b = fs::read(f.path()).unwrap();
            let last = b.len() - 1;
            b[last] ^= 0x55;
            fs::write(f.path(), b).unwrap();
        }
    }
    // com as três, a paridade cobre a raiz 1 corrompida
    let v = Vault::open(&m.0).unwrap();
    assert_eq!(v.read_file("a.bin").unwrap(), big(4000));
    // com só 1 (corrompida) + 2: não há como reconstruir — erro, nunca dado errado
    let v = Vault::open(&m.pick(&[1, 2])).unwrap();
    assert!(v.read_file("a.bin").is_err());

    // entrada de log forjada (sem a chave) é ignorada
    let log = m.0[1].join(".mycelium-root/log");
    fs::write(log.join("0000000000000099-ffffffff-000000000000.e"), vec![7u8; 200]).unwrap();
    let v = Vault::open(&m.pick(&[2, 3])).unwrap();
    assert_eq!(v.history().len(), 1);

    // parte Shamir adulterada: a chave não confere e o cofre não abre
    let meta = m.0[2].join(".mycelium-root/root.json");
    let mut j: serde_json::Value = serde_json::from_slice(&fs::read(&meta).unwrap()).unwrap();
    let first = j["share"]["shares"][0].as_u64().unwrap();
    j["share"]["shares"][0] = serde_json::json!((first + 1) % 256);
    fs::write(&meta, serde_json::to_vec(&j).unwrap()).unwrap();
    assert!(Vault::open(&m.pick(&[2, 3])).is_err());
}

#[test]
fn rename_and_remove_keep_history() {
    let m = Media::new("mv", 2);
    let mut v = Vault::create(&m.0, 2, "teste").unwrap();
    v.write_file("pasta/a.txt", b"um").unwrap();
    v.rename("pasta", "nova").unwrap();
    assert_eq!(v.read_file("nova/a.txt").unwrap(), b"um");
    assert!(v.read_file("pasta/a.txt").is_err());
    v.remove("nova/a.txt").unwrap();
    assert!(v.read_file("nova/a.txt").is_err());
    assert!(v.history().len() >= 4, "o histórico não apaga nada");
    assert!(Vault::open(&m.0).is_ok());
}
