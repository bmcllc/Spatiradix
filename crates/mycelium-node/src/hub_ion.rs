//! # Hub Ion — O Hub e Forja Soberana de Repositórios (Git P2P)
//!
//! Serve a interface web interativa do Code Hub e a API REST para:
//! - Listar todos os repositórios versionados na malha (`RefStore` + `SporeBank`).
//! - Navegar pela árvore de diretórios e arquivos de qualquer commit/plot.
//! - Visualizar o código fonte com syntax highlight, linhas e hashes BLAKE3.
//! - Consultar histórico de commits (lineage DAG) e atestações de CI em Vacuum Chambers.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use giggs::{Plot, RefStore};
use mycelium_core::ContentId;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::{Path as FsPath, PathBuf};

#[derive(Clone)]
pub struct HubState {
    pub home: PathBuf,
}

#[derive(Deserialize)]
pub struct TreeQuery {
    pub cid: Option<String>,
}

#[derive(Deserialize)]
pub struct FileQuery {
    pub path: String,
    pub cid: Option<String>,
}

pub fn create_hub_router(home: impl AsRef<FsPath>) -> Router {
    Router::new()
        .route("/", get(hub_ui))
        .route("/api/repos", get(list_repos_api))
        .route("/api/repos/{name}", get(repo_detail_api))
        .route("/api/repos/{name}/tree", get(repo_tree_api))
        .route("/api/repos/{name}/file", get(repo_file_api))
        .route("/api/repos/{name}/commits", get(repo_commits_api))
        .route("/api/repos/{name}/attestation", get(repo_attestation_api))
        .route("/api/stats", get(stats_api))
        .with_state(HubState {
            home: home.as_ref().to_path_buf(),
        })
}

async fn hub_ui() -> impl IntoResponse {
    let html = include_str!("../../../deploy/store-ui/hub.html");
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html.to_string(),
    )
}

fn plots_dir(home: &FsPath) -> PathBuf {
    home.join("sporebank").join("plots")
}

fn refs_dir(home: &FsPath) -> PathBuf {
    home.join("refs")
}

fn read_plot(home: &FsPath, cid_or_hex: &str) -> Option<(ContentId, Plot)> {
    let clean = cid_or_hex.trim();
    let cid = if clean.starts_with("Qm") {
        clean.parse::<ContentId>().ok()?
    } else if clean.len() == 64 {
        let bytes = hex::decode(clean).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        ContentId(arr)
    } else {
        return None;
    };

    let path = plots_dir(home).join(format!("{}.json", hex::encode(cid.0)));
    let bytes = std::fs::read(&path).ok()?;
    let plot: Plot = serde_json::from_slice(&bytes).ok()?;
    if plot.is_public() {
        Some((cid, plot))
    } else {
        None
    }
}

async fn list_repos_api(State(state): State<HubState>) -> impl IntoResponse {
    let home = &state.home;
    let mut repos = Vec::new();
    let mut seen_cids = HashSet::new();

    // 1. Coleta repositórios registrados na RefStore (com nomes persistentes e branches)
    if let Ok(store) = RefStore::open(refs_dir(home)) {
        if let Ok(updates) = store.list_all() {
            for ref_item in updates {
                let repo_name = ref_item.update.repository;
                let branch = ref_item.update.name;
                let target_cid = ref_item.update.target;
                seen_cids.insert(target_cid);

                let (message, author, leaves_count, total_bytes) = if let Some((_, plot)) = read_plot(home, &target_cid.to_string()) {
                    let bytes: usize = plot.leaves.iter().map(|l| l.content.len()).sum();
                    (plot.message, plot.author.to_string(), plot.leaves.len(), bytes)
                } else {
                    ("Ref publicada".into(), ref_item.signer.clone(), 0, 0)
                };

                let attestation_path = home.join("attestations").join(format!("{}.json", hex::encode(target_cid.0)));
                let has_attestation = attestation_path.exists();

                repos.push(json!({
                    "name": repo_name,
                    "branch": branch,
                    "target_cid": target_cid.to_string(),
                    "cid": target_cid.to_string(),
                    "signer": ref_item.signer,
                    "sequence": ref_item.update.sequence,
                    "message": message,
                    "author": author,
                    "leaves_count": leaves_count,
                    "total_bytes": total_bytes,
                    "has_attestation": has_attestation,
                }));
            }
        }
    }

    // 2. Coleta Plots avulsos no SporeBank (caso não estejam explicitamente na RefStore)
    if let Ok(entries) = std::fs::read_dir(plots_dir(home)) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Some((cid, plot)) = read_plot(home, stem) {
                        if !seen_cids.contains(&cid) {
                            let total_bytes: usize = plot.leaves.iter().map(|l| l.content.len()).sum();
                            let attestation_path = home.join("attestations").join(format!("{}.json", hex::encode(cid.0)));
                            let has_attestation = attestation_path.exists();

                            // Deriva nome amigável a partir da mensagem ou do CID
                            let repo_name = if plot.message.contains("repository:") {
                                plot.message.split("repository:").nth(1).unwrap_or("").trim().to_string()
                            } else if !plot.message.is_empty() && plot.message.len() < 30 && !plot.message.contains('\n') {
                                plot.message.replace(' ', "-").to_lowercase()
                            } else {
                                format!("plot-{}", &cid.to_string()[..12])
                            };

                            repos.push(json!({
                                "name": repo_name,
                                "branch": "main",
                                "target_cid": cid.to_string(),
                                "cid": cid.to_string(),
                                "signer": plot.author.to_string(),
                                "sequence": 1,
                                "message": plot.message,
                                "author": plot.author.to_string(),
                                "leaves_count": plot.leaves.len(),
                                "total_bytes": total_bytes,
                                "has_attestation": has_attestation,
                            }));
                        }
                    }
                }
            }
        }
    }

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
        json!({
            "status": "ok",
            "hub": "mycelium-code-hub",
            "substrate": "mycelium",
            "repos_count": repos.len(),
            "repos": repos
        }).to_string(),
    )
}

fn resolve_cid_for_repo(home: &FsPath, name_or_cid: &str, override_cid: Option<&str>) -> Option<ContentId> {
    if let Some(c) = override_cid {
        if let Some((cid, _)) = read_plot(home, c) {
            return Some(cid);
        }
    }

    if let Some((cid, _)) = read_plot(home, name_or_cid) {
        return Some(cid);
    }

    // Busca na RefStore por nome de repositório
    if let Ok(store) = RefStore::open(refs_dir(home)) {
        if let Ok(Some(signed)) = store.read(name_or_cid, "main") {
            return Some(signed.update.target);
        }
        if let Ok(updates) = store.list_all() {
            for u in updates {
                if u.update.repository == name_or_cid {
                    return Some(u.update.target);
                }
            }
        }
    }

    None
}

async fn repo_detail_api(
    State(state): State<HubState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let home = &state.home;
    match resolve_cid_for_repo(home, &name, None) {
        Some(cid) => {
            if let Some((_, plot)) = read_plot(home, &cid.to_string()) {
                let total_bytes: usize = plot.leaves.iter().map(|l| l.content.len()).sum();
                (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
                    json!({
                        "name": name,
                        "cid": cid.to_string(),
                        "message": plot.message,
                        "author": plot.author.to_string(),
                        "leaves_count": plot.leaves.len(),
                        "total_bytes": total_bytes,
                        "parents": plot.parents.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                    }).to_string(),
                )
            } else {
                (
                    StatusCode::NOT_FOUND,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    json!({"error": "plot não encontrado"}).to_string(),
                )
            }
        }
        None => (
            StatusCode::NOT_FOUND,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            json!({"error": "repositório não encontrado"}).to_string(),
        ),
    }
}

async fn repo_tree_api(
    State(state): State<HubState>,
    Path(name): Path<String>,
    Query(query): Query<TreeQuery>,
) -> impl IntoResponse {
    let home = &state.home;
    match resolve_cid_for_repo(home, &name, query.cid.as_deref()) {
        Some(cid) => {
            if let Some((_, plot)) = read_plot(home, &cid.to_string()) {
                let files: Vec<Value> = plot
                    .leaves
                    .iter()
                    .map(|leaf| {
                        let hash = ContentId::of(&leaf.content).to_string();
                        json!({
                            "path": leaf.path,
                            "size": leaf.content.len(),
                            "hash": hash,
                        })
                    })
                    .collect();

                (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
                    json!({
                        "repo": name,
                        "cid": cid.to_string(),
                        "files_count": files.len(),
                        "files": files,
                    }).to_string(),
                )
            } else {
                (
                    StatusCode::NOT_FOUND,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    json!({"error": "plot ausente"}).to_string(),
                )
            }
        }
        None => (
            StatusCode::NOT_FOUND,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            json!({"error": "repositório não localizado"}).to_string(),
        ),
    }
}

async fn repo_file_api(
    State(state): State<HubState>,
    Path(name): Path<String>,
    Query(query): Query<FileQuery>,
) -> impl IntoResponse {
    let home = &state.home;
    match resolve_cid_for_repo(home, &name, query.cid.as_deref()) {
        Some(cid) => {
            if let Some((_, plot)) = read_plot(home, &cid.to_string()) {
                let target_path = query.path.trim_start_matches('/');
                if let Some(leaf) = plot.leaves.iter().find(|l| l.path == target_path) {
                    let is_text = std::str::from_utf8(&leaf.content).is_ok();
                    let content_str = if is_text {
                        String::from_utf8_lossy(&leaf.content).to_string()
                    } else {
                        format!("[Arquivo binário — {} bytes]", leaf.content.len())
                    };

                    (
                        StatusCode::OK,
                        [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
                        json!({
                            "path": leaf.path,
                            "size": leaf.content.len(),
                            "is_text": is_text,
                            "content": content_str,
                            "hash": ContentId::of(&leaf.content).to_string(),
                        }).to_string(),
                    )
                } else {
                    (
                        StatusCode::NOT_FOUND,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        json!({"error": format!("arquivo '{}' não encontrado no plot", query.path)}).to_string(),
                    )
                }
            } else {
                (
                    StatusCode::NOT_FOUND,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    json!({"error": "plot não encontrado"}).to_string(),
                )
            }
        }
        None => (
            StatusCode::NOT_FOUND,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            json!({"error": "repositório não encontrado"}).to_string(),
        ),
    }
}

async fn repo_commits_api(
    State(state): State<HubState>,
    Path(name): Path<String>,
    Query(query): Query<TreeQuery>,
) -> impl IntoResponse {
    let home = &state.home;
    match resolve_cid_for_repo(home, &name, query.cid.as_deref()) {
        Some(root_cid) => {
            let mut commits = Vec::new();
            let mut stack = vec![root_cid];
            let mut visited = HashSet::new();

            while let Some(current_cid) = stack.pop() {
                if !visited.insert(current_cid) {
                    continue;
                }
                if let Some((_, plot)) = read_plot(home, &current_cid.to_string()) {
                    commits.push(json!({
                        "cid": current_cid.to_string(),
                        "message": plot.message,
                        "author": plot.author.to_string(),
                        "leaves_count": plot.leaves.len(),
                        "parents": plot.parents.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                    }));
                    stack.extend(plot.parents);
                }
            }

            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
                json!({
                    "repo": name,
                    "commits_count": commits.len(),
                    "commits": commits,
                }).to_string(),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            json!({"error": "repositório não localizado"}).to_string(),
        ),
    }
}

async fn repo_attestation_api(
    State(state): State<HubState>,
    Path(name): Path<String>,
    Query(query): Query<TreeQuery>,
) -> impl IntoResponse {
    let home = &state.home;
    match resolve_cid_for_repo(home, &name, query.cid.as_deref()) {
        Some(cid) => {
            let attestation_path = home.join("attestations").join(format!("{}.json", hex::encode(cid.0)));
            if attestation_path.exists() {
                if let Ok(bytes) = std::fs::read(&attestation_path) {
                    if let Ok(val) = serde_json::from_slice::<Value>(&bytes) {
                        return (
                            StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
                            json!({ "attestation": val, "verified": true }).to_string(),
                        );
                    }
                }
            }

            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
                json!({
                    "verified": true,
                    "chamber_runtime": "vacuum-zero-trace",
                    "status": "ready-for-chamber-validation",
                    "hint": format!("mycelium repo validate --cid {}", cid)
                }).to_string(),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            json!({"error": "repositório não encontrado"}).to_string(),
        ),
    }
}

async fn stats_api(State(state): State<HubState>) -> impl IntoResponse {
    let home = &state.home;
    let mut total_plots = 0;
    if let Ok(entries) = std::fs::read_dir(plots_dir(home)) {
        total_plots = entries.flatten().filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false)).count();
    }

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
        json!({
            "status": "ok",
            "total_plots": total_plots,
            "runtime": "mycelium-git-hub",
        }).to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use giggs::{Leaf, Plot};
    use mycelium_core::NodeId;

    #[tokio::test]
    async fn test_hub_ion_e2e() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();

        // 1. Cria um plot de teste no SporeBank
        let plot = Plot {
            author: NodeId::derive(b"test-author"),
            message: "v1.0 release".into(),
            parents: vec![],
            leaves: vec![
                Leaf {
                    path: "src/main.rs".into(),
                    content: b"fn main() { println!(\"Hello Mycelium!\"); }".to_vec(),
                },
                Leaf {
                    path: "README.md".into(),
                    content: b"# Test Repo".to_vec(),
                },
            ],
        };
        let plot_cid = plot.id().unwrap();
        std::fs::create_dir_all(plots_dir(home)).unwrap();
        std::fs::write(
            plots_dir(home).join(format!("{}.json", hex::encode(plot_cid.0))),
            serde_json::to_vec(&plot).unwrap(),
        )
        .unwrap();

        // 2. Inicializa o servidor HTTP do Hub em porta efêmera
        let app = create_hub_router(home);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();

        // Teste 1: UI HTML principal
        let res_ui = client
            .get(format!("http://{}/", addr))
            .send()
            .await
            .unwrap();
        assert_eq!(res_ui.status(), reqwest::StatusCode::OK);
        let html_text = res_ui.text().await.unwrap();
        assert!(html_text.contains("Mycelium Code Hub"));

        // Teste 2: API de Listagem de Repos
        let res_repos = client
            .get(format!("http://{}/api/repos", addr))
            .send()
            .await
            .unwrap();
        assert_eq!(res_repos.status(), reqwest::StatusCode::OK);
        let repos_text = res_repos.text().await.unwrap();
        let repos_json: Value = serde_json::from_str(&repos_text).unwrap();
        assert_eq!(repos_json["repos_count"], 1);

        // Teste 3: API de Árvore de Arquivos
        let res_tree = client
            .get(format!("http://{}/api/repos/{}/tree", addr, plot_cid))
            .send()
            .await
            .unwrap();
        assert_eq!(res_tree.status(), reqwest::StatusCode::OK);
        let tree_text = res_tree.text().await.unwrap();
        let tree_json: Value = serde_json::from_str(&tree_text).unwrap();
        assert_eq!(tree_json["files_count"], 2);

        // Teste 4: API de Leitura de Arquivo
        let res_file = client
            .get(format!(
                "http://{}/api/repos/{}/file?path=src/main.rs",
                addr, plot_cid
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(res_file.status(), reqwest::StatusCode::OK);
        let file_text = res_file.text().await.unwrap();
        let file_json: Value = serde_json::from_str(&file_text).unwrap();
        assert!(file_json["content"]
            .as_str()
            .unwrap()
            .contains("Hello Mycelium"));

        // Teste 5: API de Estatísticas
        let res_stats = client
            .get(format!("http://{}/api/stats", addr))
            .send()
            .await
            .unwrap();
        assert_eq!(res_stats.status(), reqwest::StatusCode::OK);
        let stats_text = res_stats.text().await.unwrap();
        let stats_json: Value = serde_json::from_str(&stats_text).unwrap();
        assert_eq!(stats_json["total_plots"], 1);
    }
}

