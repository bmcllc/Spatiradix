//! # mycelium-media: playlists descentralizadas
//!
//! Playlists como manifestos portáteis compartilháveis entre quaisquer clientes Mycelium.

use crate::manifest::PlaylistManifest;
use mycelium_core::ContentId;

pub struct PlaylistService;

impl PlaylistService {
    pub fn create_playlist(
        playlist_id: &str,
        owner_pubkey: &str,
        title: &str,
        description: &str,
        initial_videos: Vec<ContentId>,
    ) -> PlaylistManifest {
        PlaylistManifest {
            playlist_id: playlist_id.to_string(),
            owner_pubkey: owner_pubkey.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            videos: initial_videos,
            is_collaborative: false,
            revision: 1,
            signature: String::new(),
        }
    }

    pub fn append_video(playlist: &mut PlaylistManifest, video_cid: ContentId) {
        if !playlist.videos.contains(&video_cid) {
            playlist.videos.push(video_cid);
            playlist.revision += 1;
        }
    }

    pub fn save(playlist: &PlaylistManifest, dir: impl AsRef<std::path::Path>) -> Result<(), std::io::Error> {
        let dir_buf = dir.as_ref();
        std::fs::create_dir_all(dir_buf)?;
        let path = dir_buf.join(format!("{}.json", playlist.playlist_id));
        let bytes = serde_json::to_vec_pretty(playlist).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, bytes)
    }

    pub fn load(playlist_id: &str, dir: impl AsRef<std::path::Path>) -> Result<PlaylistManifest, std::io::Error> {
        let path = dir.as_ref().join(format!("{playlist_id}.json"));
        let bytes = std::fs::read(path)?;
        serde_json::from_slice(&bytes).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

