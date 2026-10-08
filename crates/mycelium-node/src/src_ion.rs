//! # Src Ion — Browser de código soberano (repos do SporeBank via HTTP)
//!
//! Serve as árvores de código publicadas como Plots multi-leaf no SporeBank,
//! expostas como ion `src` no Singularity Event Horizon — um "GitHub" próprio,
//! content-addressed (blake3) e servido pelo próprio nó.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use giggs::Plot;
use mycelium_core::ContentId;
use mycelium_s1::publication::{verify_site_plot, MANIFEST_PATH};
use serde_json::Value;
use std::io::Read;
use std::path::{Path as FsPath, PathBuf};

// JSON encodes each byte separately, so this limit applies to the stored Plot,
// rather than just the size of the decoded site assets.
const MAX_STORED_PLOT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct SrcState {
    pub home: PathBuf,
}

pub fn create_src_router(home: impl AsRef<FsPath>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/{cid}", get(list))
        .route("/{cid}/{*path}", get(file))
        .with_state(SrcState {
            home: home.as_ref().to_path_buf(),
        })
}

fn plots_dir(home: &FsPath) -> PathBuf {
    home.join("sporebank").join("plots")
}

fn read_public_plot(home: &FsPath, cid: &str) -> Option<Plot> {
    let id = cid.parse::<ContentId>().ok()?;
    let path = plots_dir(home).join(format!("{}.json", hex::encode(id.0)));
    let metadata = std::fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_STORED_PLOT_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .ok()?
        .take(MAX_STORED_PLOT_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_STORED_PLOT_BYTES {
        return None;
    }
    let plot: Plot = serde_json::from_slice(&bytes).ok()?;
    if !plot.is_public() || plot.id().ok()? != id {
        return None;
    }
    if plot.leaves.iter().any(|leaf| leaf.path == MANIFEST_PATH) {
        verify_site_plot(&plot, id).ok()?;
    }
    Some(plot)
}

fn cids(home: &FsPath) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(plots_dir(home))
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    name.strip_suffix(".json").map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

async fn index(State(state): State<SrcState>) -> impl IntoResponse {
    let entries: Vec<Value> = cids(&state.home)
        .iter()
        .filter_map(|cid| {
            let plot = read_public_plot(&state.home, cid)?;
            Some(serde_json::json!({
                "cid": cid,
                "message": plot.message,
                "leaves": plot.leaves.len(),
                "author": plot.author.to_string(),
                "url": format!("/src/{cid}"),
            }))
        })
        .collect();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )],
        serde_json::json!({ "ion": "src", "substrate": "mycelium", "repos": entries }).to_string(),
    )
}

async fn list(State(state): State<SrcState>, Path(cid): Path<String>) -> impl IntoResponse {
    match read_public_plot(&state.home, &cid) {
        Some(plot) => {
            let files: Vec<Value> = plot
                .leaves
                .iter()
                .map(|leaf| {
                    serde_json::json!({
                        "path": leaf.path,
                        "size": leaf.content.len(),
                        "url": format!("/src/{cid}/{}", leaf.path),
                    })
                })
                .collect();
            (
                StatusCode::OK,
                [(
                    axum::http::header::CONTENT_TYPE,
                    "application/json; charset=utf-8",
                )],
                serde_json::json!({
                    "cid": cid,
                    "message": plot.message,
                    "files": files,
                })
                .to_string(),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )],
            serde_json::json!({ "error": format!("repo {cid} não encontrado no SporeBank local") })
                .to_string(),
        ),
    }
}

async fn file(
    State(state): State<SrcState>,
    Path((cid, path)): Path<(String, String)>,
) -> impl IntoResponse {
    match read_public_plot(&state.home, &cid) {
        Some(plot) => match plot.leaves.iter().find(|leaf| leaf.path == path) {
            Some(leaf) => {
                let mime = mime_for(&path);
                (
                    StatusCode::OK,
                    [
                        (axum::http::header::CONTENT_TYPE, mime),
                        (
                            axum::http::header::CACHE_CONTROL,
                            "public, max-age=31536000",
                        ),
                    ],
                    leaf.content.clone(),
                )
            }
            None => (
                StatusCode::NOT_FOUND,
                [
                    (
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; charset=utf-8",
                    ),
                    (axum::http::header::CACHE_CONTROL, "no-store"),
                ],
                format!("arquivo não encontrado no repo: {path}").into_bytes(),
            ),
        },
        None => (
            StatusCode::NOT_FOUND,
            [
                (
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; charset=utf-8",
                ),
                (axum::http::header::CACHE_CONTROL, "no-store"),
            ],
            format!("repo {cid} não encontrado no SporeBank local").into_bytes(),
        ),
    }
}

fn mime_for(path: &str) -> &'static str {
    let lower = path.to_lowercase();
    if lower.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if lower.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if lower.ends_with(".js") || lower.ends_with(".mjs") {
        "application/javascript; charset=utf-8"
    } else if lower.ends_with(".json") || lower.ends_with(".map") {
        "application/json; charset=utf-8"
    } else if lower.ends_with(".svg") {
        "image/svg+xml"
    } else if lower.ends_with(".png") {
        "image/png"
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg"
    } else if lower.ends_with(".webp") {
        "image/webp"
    } else if lower.ends_with(".ico") {
        "image/x-icon"
    } else if lower.ends_with(".wasm") {
        "application/wasm"
    } else if lower.ends_with(".woff") {
        "font/woff"
    } else if lower.ends_with(".woff2") {
        "font/woff2"
    } else if lower.ends_with(".rs")
        || lower.ends_with(".toml")
        || lower.ends_with(".md")
        || lower.ends_with(".sh")
        || lower.ends_with(".txt")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
    {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

#[cfg(test)]
mod tests {
    use super::{mime_for, plots_dir, read_public_plot, MAX_STORED_PLOT_BYTES};
    use giggs::Plot;
    use mycelium_core::NodeId;

    fn store_plot(home: &std::path::Path, plot: &Plot) -> String {
        let id = plot.id().expect("plot válido");
        let cid = id.to_string();
        std::fs::create_dir_all(plots_dir(home)).expect("diretório de teste");
        std::fs::write(
            plots_dir(home).join(format!("{}.json", hex::encode(id.0))),
            serde_json::to_vec(plot).expect("serialização de teste"),
        )
        .expect("gravação de teste");
        cid
    }

    fn plot(message: &str) -> Plot {
        Plot {
            author: NodeId::derive(b"src-ion-test"),
            message: message.into(),
            parents: vec![],
            leaves: vec![],
        }
    }

    #[test]
    fn src_ion_exposes_only_public_plots() {
        let home = tempfile::tempdir().expect("home temporário");
        let public_cid = store_plot(home.path(), &plot("[public] repo"));
        let private_cid = store_plot(home.path(), &plot("[private] repo"));

        assert!(read_public_plot(home.path(), &public_cid).is_some());
        assert!(read_public_plot(home.path(), &private_cid).is_none());
    }

    #[test]
    fn src_ion_rejects_malformed_cids_before_filesystem_access() {
        let home = tempfile::tempdir().expect("home temporário");
        assert!(read_public_plot(home.path(), "../../segredo").is_none());
        assert!(read_public_plot(home.path(), "not-a-content-id").is_none());
    }

    #[test]
    fn src_ion_fails_closed_for_corrupt_plot_data() {
        let home = tempfile::tempdir().expect("home temporário");
        let cid = "a".repeat(64);
        std::fs::create_dir_all(plots_dir(home.path())).expect("diretório de teste");
        std::fs::write(
            plots_dir(home.path()).join(format!("{cid}.json")),
            b"not json",
        )
        .expect("gravação de teste");
        assert!(read_public_plot(home.path(), &cid).is_none());
    }

    #[test]
    fn src_ion_rejects_valid_plot_stored_under_another_cid() {
        let home = tempfile::tempdir().expect("home temporário");
        let original = plot("[public] repo original");
        let cid = store_plot(home.path(), &original);
        let path =
            plots_dir(home.path()).join(format!("{}.json", hex::encode(original.id().unwrap().0)));
        std::fs::write(
            path,
            serde_json::to_vec(&plot("[public] adulterado")).unwrap(),
        )
        .unwrap();
        assert!(read_public_plot(home.path(), &cid).is_none());
    }

    #[test]
    fn src_ion_checks_site_manifest_even_when_plot_cid_is_valid() {
        let home = tempfile::tempdir().unwrap();
        let build = tempfile::tempdir().unwrap();
        std::fs::write(build.path().join("index.html"), "<h1>S1</h1>").unwrap();
        let site =
            mycelium_s1::publication::prepare_site(build.path(), "mycelium-s1", "index.html")
                .unwrap();
        let mut published = site
            .plot(NodeId::derive(b"src-site-test"), "[public] site", vec![])
            .unwrap();
        let cid = store_plot(home.path(), &published);
        assert!(read_public_plot(home.path(), &cid).is_some());

        published
            .leaves
            .iter_mut()
            .find(|leaf| leaf.path == "index.html")
            .unwrap()
            .content = b"<h1>Alterado</h1>".to_vec();
        let altered_cid = store_plot(home.path(), &published);
        assert!(read_public_plot(home.path(), &altered_cid).is_none());

        published
            .leaves
            .iter_mut()
            .find(|leaf| leaf.path == mycelium_s1::publication::MANIFEST_PATH)
            .unwrap()
            .content = b"{}".to_vec();
        let altered_manifest_cid = store_plot(home.path(), &published);
        assert!(read_public_plot(home.path(), &altered_manifest_cid).is_none());
    }

    #[test]
    fn src_ion_rejects_oversized_stored_plots() {
        let home = tempfile::tempdir().unwrap();
        let id = plot("[public] oversized").id().unwrap();
        std::fs::create_dir_all(plots_dir(home.path())).unwrap();
        let file = std::fs::File::create(
            plots_dir(home.path()).join(format!("{}.json", hex::encode(id.0))),
        )
        .unwrap();
        file.set_len(MAX_STORED_PLOT_BYTES + 1).unwrap();
        assert!(read_public_plot(home.path(), &id.to_string()).is_none());
    }

    #[test]
    fn src_ion_serves_site_asset_mime_types() {
        assert_eq!(mime_for("assets/logo.SVG"), "image/svg+xml");
        assert_eq!(mime_for("assets/logo.png"), "image/png");
        assert_eq!(mime_for("assets/runtime.wasm"), "application/wasm");
        assert_eq!(mime_for("assets/font.woff2"), "font/woff2");
        assert_eq!(mime_for("main.rs"), "text/plain; charset=utf-8");
    }
}
