//! Static S1 portal bundles published through the existing GiGGS/SporeBank path.
//!
//! A bundle is content-addressed, not proof that another peer has replicated it.
//! Submit [`SiteBundle::repo_publish_request`] to the node control socket; the
//! node owns the SporeBank writer and signs the repository reference update.

use giggs::{Leaf, Plot};
use mycelium_core::{ContentId, NodeId};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
};

pub const MANIFEST_PATH: &str = "mycelium-site.json";
pub const MANIFEST_SCHEMA: &str = "mycelium.static-site.v1";
/// A conservative packaging bound; this is not a transport delivery guarantee.
pub const MAX_SITE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SITE_FILES: usize = 1024;
const MAX_MANIFEST_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SiteFile {
    pub path: String,
    pub bytes: u64,
    /// Hex-encoded BLAKE3 of the raw asset, using Mycelium's ContentId digest.
    pub blake3: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SiteManifest {
    pub schema: String,
    pub application: String,
    pub entrypoint: String,
    pub files: Vec<SiteFile>,
}

#[derive(Clone, Debug)]
pub struct SiteBundle {
    pub manifest: SiteManifest,
    pub leaves: Vec<Leaf>,
}

#[derive(Clone, Debug)]
pub struct PublishedAsset {
    pub cid: ContentId,
    pub path: String,
    pub content_type: &'static str,
    pub content: Vec<u8>,
}

/// Package a completed static build. Source files, secrets and symlinks should
/// not be in this directory; hidden paths are rejected instead of ignored.
pub fn prepare_site(
    directory: impl AsRef<Path>,
    application: &str,
    entrypoint: &str,
) -> Result<SiteBundle, String> {
    validate_application(application)?;
    validate_asset_path(entrypoint)?;
    let directory = directory.as_ref();
    let metadata = fs::symlink_metadata(directory).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("site build must be a directory, not a symlink".into());
    }
    let mut leaves = Vec::new();
    let mut total_bytes = 0;
    collect_assets(directory, directory, &mut leaves, &mut total_bytes)?;
    leaves.sort_by(|a, b| a.path.cmp(&b.path));
    if !leaves.iter().any(|leaf| leaf.path == entrypoint) {
        return Err(format!("site entrypoint is missing: {entrypoint}"));
    }
    let manifest = SiteManifest {
        schema: MANIFEST_SCHEMA.into(),
        application: application.into(),
        entrypoint: entrypoint.into(),
        files: leaves
            .iter()
            .map(|leaf| SiteFile {
                path: leaf.path.clone(),
                bytes: leaf.content.len() as u64,
                blake3: digest(&leaf.content),
            })
            .collect(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err("site manifest exceeds packaging limit".into());
    }
    leaves.push(Leaf {
        path: MANIFEST_PATH.into(),
        content: manifest_bytes,
    });
    leaves.sort_by(|a, b| a.path.cmp(&b.path));
    let bundle = SiteBundle { manifest, leaves };
    verify_leaves(&bundle.leaves)?;
    Ok(bundle)
}

impl SiteBundle {
    /// Useful for offline previews and reproducible identity tests. In actual
    /// publication the daemon supplies its author and current reference parent.
    pub fn plot(
        &self,
        author: NodeId,
        message: &str,
        parents: Vec<ContentId>,
    ) -> Result<Plot, String> {
        self.validate()?;
        validate_public_message(message)?;
        Ok(Plot {
            author,
            message: message.into(),
            parents,
            leaves: self.leaves.clone(),
        })
    }

    /// Exact existing node Request::RepoPublish JSON. This deliberately avoids
    /// depending on mycelium-node, which already depends on mycelium-s1.
    /// The control client must add its auth token and inspect the response.
    pub fn repo_publish_request(
        &self,
        repository: &str,
        branch: &str,
        expected_previous: Option<ContentId>,
        message: &str,
    ) -> Result<serde_json::Value, String> {
        self.validate()?;
        validate_public_message(message)?;
        validate_reference_component(repository)?;
        validate_reference_component(branch)?;
        Ok(serde_json::json!({
            "cmd": "repo_publish",
            "repository": repository,
            "branch": branch,
            "expected_previous_cid": expected_previous.map(|id| id.to_string()),
            "message": message,
            "leaves": self.leaves,
        }))
    }

    fn validate(&self) -> Result<(), String> {
        let actual = verify_leaves(&self.leaves)?;
        if actual != self.manifest {
            return Err("bundle manifest differs from its manifest leaf".into());
        }
        Ok(())
    }
}

/// Check the complete Plot identity and each asset before serving an imported
/// bundle. The manifest alone is not a signature or proof of authorship.
pub fn verify_site_plot(plot: &Plot, expected_cid: ContentId) -> Result<SiteManifest, String> {
    if !plot.is_public() {
        return Err("site plot is private".into());
    }
    let actual = plot.id().map_err(|e| e.to_string())?;
    if actual != expected_cid {
        return Err("site plot does not match the requested ContentId".into());
    }
    verify_leaves(&plot.leaves)
}

/// Read the existing SporeBank layout without opening a second writer. A caller
/// can wrap this in a route when it needs stricter integrity validation than
/// the current src.mycelium reader provides.
pub fn read_published_asset(
    home: impl AsRef<Path>,
    cid: &str,
    path: &str,
) -> Result<PublishedAsset, String> {
    let cid = ContentId::from_str(cid).map_err(|e| e.to_string())?;
    let plot_path = home
        .as_ref()
        .join("sporebank/plots")
        .join(format!("{}.json", hex::encode(cid.0)));
    let metadata = fs::symlink_metadata(&plot_path).map_err(|e| e.to_string())?;
    // JSON serializes bytes as number arrays, so encoded size can exceed payload.
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > (MAX_SITE_BYTES * 5 + MAX_MANIFEST_BYTES * 5) as u64
    {
        return Err("stored site plot is not a regular bounded file".into());
    }
    let bytes = read_bounded(&plot_path, MAX_SITE_BYTES * 5 + MAX_MANIFEST_BYTES * 5)?;
    let plot: Plot = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let manifest = verify_site_plot(&plot, cid)?;
    let path = if path.is_empty() || path == "/" {
        manifest.entrypoint
    } else {
        validate_asset_path(path)?;
        path.to_owned()
    };
    let leaf = plot
        .leaves
        .iter()
        .find(|leaf| leaf.path == path)
        .ok_or_else(|| format!("site asset was not found: {path}"))?;
    Ok(PublishedAsset {
        cid,
        content_type: content_type(&path),
        path,
        content: leaf.content.clone(),
    })
}

/// Browser entry via the existing local Event Horizon/SRC ion. The user's
/// Mycelium client must resolve the virtual .mycelium service name.
pub fn site_entry_url(cid: ContentId, entrypoint: &str) -> Result<String, String> {
    validate_asset_path(entrypoint)?;
    Ok(format!("http://src.mycelium/{cid}/{entrypoint}"))
}

fn collect_assets(
    root: &Path,
    directory: &Path,
    leaves: &mut Vec<Leaf>,
    total_bytes: &mut usize,
) -> Result<(), String> {
    let mut entries: Vec<PathBuf> = fs::read_dir(directory)
        .map_err(|e| e.to_string())?
        .map(|entry| entry.map(|entry| entry.path()).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    entries.sort();
    for path in entries {
        let relative = path
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .to_str()
            .ok_or("asset path must be UTF-8")?;
        validate_asset_path(relative)?;
        let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err(format!("site build contains a symlink: {relative}"));
        }
        if metadata.is_dir() {
            collect_assets(root, &path, leaves, total_bytes)?;
        } else if metadata.is_file() {
            if relative == MANIFEST_PATH {
                return Err(format!("reserved site manifest path: {MANIFEST_PATH}"));
            }
            if leaves.len() >= MAX_SITE_FILES {
                return Err("site exceeds file count limit".into());
            }
            let size: usize = metadata
                .len()
                .try_into()
                .map_err(|_| "site asset size is too large")?;
            if size > MAX_SITE_BYTES.saturating_sub(*total_bytes) {
                return Err("site exceeds byte limit".into());
            }
            let content = read_bounded(&path, MAX_SITE_BYTES.saturating_sub(*total_bytes))?;
            if content.len() != size {
                return Err(format!(
                    "site asset changed while being packaged: {relative}"
                ));
            }
            *total_bytes += content.len();
            leaves.push(Leaf {
                path: relative.to_owned(),
                content,
            });
        } else {
            return Err(format!("site build contains a special file: {relative}"));
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("site file exceeds byte limit".into());
    }
    Ok(bytes)
}

fn verify_leaves(leaves: &[Leaf]) -> Result<SiteManifest, String> {
    if leaves.is_empty() || leaves.len() > MAX_SITE_FILES + 1 {
        return Err("site leaf count is invalid".into());
    }
    let mut seen = BTreeSet::new();
    let mut previous: Option<&str> = None;
    let mut total_bytes = 0usize;
    let mut manifest_leaf = None;
    for leaf in leaves {
        validate_asset_path(&leaf.path)?;
        if !seen.insert(leaf.path.as_str()) {
            return Err(format!("duplicate site path: {}", leaf.path));
        }
        if previous.is_some_and(|path| path >= leaf.path.as_str()) {
            return Err("site leaves are not in canonical path order".into());
        }
        previous = Some(&leaf.path);
        if leaf.path == MANIFEST_PATH {
            if leaf.content.len() > MAX_MANIFEST_BYTES {
                return Err("site manifest exceeds packaging limit".into());
            }
            manifest_leaf = Some(leaf);
        } else {
            total_bytes = total_bytes
                .checked_add(leaf.content.len())
                .ok_or("site byte count overflow")?;
            if total_bytes > MAX_SITE_BYTES {
                return Err("site exceeds byte limit".into());
            }
        }
    }
    let manifest_leaf = manifest_leaf.ok_or("site manifest is missing")?;
    let manifest: SiteManifest =
        serde_json::from_slice(&manifest_leaf.content).map_err(|e| e.to_string())?;
    if manifest.schema != MANIFEST_SCHEMA {
        return Err("site manifest schema is unsupported".into());
    }
    validate_application(&manifest.application)?;
    validate_asset_path(&manifest.entrypoint)?;
    if manifest.files.len() + 1 != leaves.len() {
        return Err("site manifest does not account for every asset".into());
    }
    let actual: Vec<SiteFile> = leaves
        .iter()
        .filter(|leaf| leaf.path != MANIFEST_PATH)
        .map(|leaf| SiteFile {
            path: leaf.path.clone(),
            bytes: leaf.content.len() as u64,
            blake3: digest(&leaf.content),
        })
        .collect();
    if manifest.files != actual {
        return Err("site asset hashes, sizes or paths do not match the manifest".into());
    }
    if !actual.iter().any(|file| file.path == manifest.entrypoint) {
        return Err("site entrypoint is missing from the manifest".into());
    }
    if serde_json::to_vec(&manifest).map_err(|e| e.to_string())? != manifest_leaf.content {
        return Err("site manifest is not canonically encoded".into());
    }
    Ok(manifest)
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(ContentId::of(bytes).0)
}

fn validate_asset_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > 1024
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        || path
            .split('/')
            .any(|part| part.is_empty() || part.starts_with('.'))
    {
        return Err(format!("unsafe site asset path: {path}"));
    }
    Ok(())
}

fn validate_application(application: &str) -> Result<(), String> {
    if application.trim().is_empty()
        || application.len() > 128
        || application.chars().any(char::is_control)
    {
        return Err("site application must have a bounded non-empty name".into());
    }
    Ok(())
}

fn validate_public_message(message: &str) -> Result<(), String> {
    if !message.trim_start().starts_with("[public]") || message.len() > 4096 {
        return Err("site publication message must begin with [public] and fit 4096 bytes".into());
    }
    Ok(())
}

fn validate_reference_component(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('.')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("site repository and branch must be safe reference components".into());
    }
    Ok(())
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            static SEQUENCE: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "mycelium-s1-site-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn write(&self, path: &str, bytes: &[u8]) {
            let target = self.0.join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, bytes).unwrap();
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn bundle() -> (TestDirectory, SiteBundle) {
        let directory = TestDirectory::new();
        directory.write("assets/main.js", b"console.log('s1');");
        directory.write("index.html", b"<h1>Mycelium S1</h1>");
        let bundle = prepare_site(&directory.0, "Mycelium S1", "index.html").unwrap();
        (directory, bundle)
    }

    #[test]
    fn reproducible_bundle_and_real_repo_publish_shape() {
        let (first, bundle) = bundle();
        let second = TestDirectory::new();
        second.write("index.html", b"<h1>Mycelium S1</h1>");
        second.write("assets/main.js", b"console.log('s1');");
        let repeated = prepare_site(&second.0, "Mycelium S1", "index.html").unwrap();
        assert_eq!(bundle.leaves, repeated.leaves);
        let author = NodeId::derive(b"site-publisher");
        let plot = bundle.plot(author, "[public] S1 portal", vec![]).unwrap();
        let other = repeated.plot(author, "[public] S1 portal", vec![]).unwrap();
        assert_eq!(plot.id().unwrap(), other.id().unwrap());
        assert_eq!(
            verify_site_plot(&plot, plot.id().unwrap()).unwrap(),
            bundle.manifest
        );
        let request = bundle
            .repo_publish_request("mycelium-s1", "site", None, "[public] S1 portal")
            .unwrap();
        assert_eq!(request["cmd"], "repo_publish");
        assert!(request["expected_previous_cid"].is_null());
        assert_eq!(request["leaves"].as_array().unwrap().len(), 3);
        assert!(first.0.is_dir());
    }

    #[test]
    fn rejects_corrupted_plot_and_corrupted_manifest_asset() {
        let (_directory, bundle) = bundle();
        let mut plot = bundle
            .plot(NodeId::derive(b"publisher"), "[public] S1", vec![])
            .unwrap();
        let original_cid = plot.id().unwrap();
        plot.leaves[0].content.push(42);
        assert!(verify_site_plot(&plot, original_cid).is_err());
        // Even if a sender supplies the new Plot CID, the asset manifest fails.
        assert!(verify_site_plot(&plot, plot.id().unwrap()).is_err());
    }

    #[test]
    fn rejects_hidden_and_traversal_paths_and_private_message() {
        let (directory, bundle) = bundle();
        for path in [
            "../index.html",
            "/index.html",
            "assets//x.js",
            ".env",
            "a%2fb",
            "a\\b",
        ] {
            assert!(validate_asset_path(path).is_err(), "{path}");
        }
        assert!(bundle
            .repo_publish_request("mycelium-s1", "site", None, "[private] S1")
            .is_err());
        directory.write(".env", b"secret");
        assert!(prepare_site(&directory.0, "S1", "index.html").is_err());
    }

    #[test]
    fn reads_verified_asset_from_existing_sporebank_layout() {
        let (_directory, bundle) = bundle();
        let home = TestDirectory::new();
        let plot = bundle
            .plot(NodeId::derive(b"publisher"), "[public] S1", vec![])
            .unwrap();
        let cid = plot.id().unwrap();
        home.write(
            &format!("sporebank/plots/{}.json", hex::encode(cid.0)),
            &serde_json::to_vec(&plot).unwrap(),
        );
        let asset = read_published_asset(&home.0, &cid.to_string(), "").unwrap();
        assert_eq!(asset.path, "index.html");
        assert_eq!(asset.content_type, "text/html; charset=utf-8");
        assert!(read_published_asset(&home.0, &cid.to_string(), "../index.html").is_err());
        assert!(site_entry_url(cid, "index.html")
            .unwrap()
            .contains("src.mycelium/"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_build_assets() {
        let (directory, _) = bundle();
        std::os::unix::fs::symlink("index.html", directory.0.join("link.html")).unwrap();
        assert!(prepare_site(&directory.0, "S1", "index.html").is_err());
    }
}
