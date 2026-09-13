//! Filesystem content-addressed blob storage.

use std::path::{Path, PathBuf};

use axum::body::Body;
use futures_util::StreamExt as _;
use sha2::{Digest as _, Sha256};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt as _,
};

use crate::{
    domain::validate_digest,
    error::{ApiError, Result},
};

/// Verified blob write result.
#[derive(Debug)]
pub struct StoredBlob {
    /// Number of bytes stored.
    pub size: u64,
    /// Whether bytes already existed.
    pub existed: bool,
}

/// Filesystem SHA-256 blob store.
#[derive(Clone)]
pub struct BlobStore {
    root: PathBuf,
    temp: PathBuf,
    max_bytes: u64,
}

impl BlobStore {
    /// Create storage directories.
    pub async fn new(root: PathBuf, temp: PathBuf, max_bytes: u64) -> Result<Self> {
        fs::create_dir_all(root.join("sha256")).await?;
        fs::create_dir_all(&temp).await?;
        Ok(Self {
            root,
            temp,
            max_bytes,
        })
    }

    /// Resolve a previously validated digest to its storage path.
    pub fn path(&self, digest: &str) -> Result<PathBuf> {
        let hex = validate_digest(digest)?;
        Ok(self
            .root
            .join("sha256")
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(hex))
    }

    /// Stream a body into a temporary file, verify it, then atomically publish.
    pub async fn put(&self, expected_digest: &str, body: Body) -> Result<StoredBlob> {
        validate_digest(expected_digest)?;
        let destination = self.path(expected_digest)?;
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| ApiError::internal("secure random generation failed"))?;
        let temporary = self
            .temp
            .join(format!("upload-{}.tmp", hex::encode(random)));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await?;
        let mut stream = body.into_data_stream();
        let mut hasher = Sha256::new();
        let mut size = 0_u64;
        let result: Result<()> = async {
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| {
                    ApiError::bad_request("invalid_body", "upload body could not be read")
                })?;
                size = size
                    .checked_add(
                        u64::try_from(chunk.len())
                            .map_err(|_| ApiError::too_large("blob is too large"))?,
                    )
                    .ok_or_else(|| ApiError::too_large("blob size overflow"))?;
                if size > self.max_bytes {
                    return Err(ApiError::too_large(format!(
                        "blob exceeds {} bytes",
                        self.max_bytes
                    )));
                }
                hasher.update(&chunk);
                file.write_all(&chunk).await?;
            }
            file.flush().await?;
            file.sync_all().await?;
            let actual = format!("sha256:{}", hex::encode(hasher.finalize()));
            if actual != expected_digest {
                return Err(ApiError::bad_request(
                    "digest_mismatch",
                    "uploaded bytes do not match URL digest",
                )
                .detail("actual", actual));
            }
            Ok(())
        }
        .await;
        drop(file);
        if let Err(error) = result {
            let _ = fs::remove_file(&temporary).await;
            return Err(error);
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).await?;
        }
        if fs::try_exists(&destination).await? {
            let _ = fs::remove_file(&temporary).await;
            return Ok(StoredBlob {
                size: fs::metadata(&destination).await?.len(),
                existed: true,
            });
        }
        match fs::rename(&temporary, &destination).await {
            Ok(()) => Ok(StoredBlob {
                size,
                existed: false,
            }),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&temporary).await;
                Ok(StoredBlob {
                    size: fs::metadata(&destination).await?.len(),
                    existed: true,
                })
            }
            Err(error) => {
                let _ = fs::remove_file(&temporary).await;
                Err(error.into())
            }
        }
    }

    /// Test blob existence.
    pub async fn exists(&self, digest: &str) -> Result<bool> {
        Ok(fs::try_exists(self.path(digest)?).await?)
    }

    /// Blob root for operational reporting.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;

    use super::*;

    #[tokio::test]
    async fn rejects_digest_mismatch_and_removes_temp() {
        let directory = tempfile::tempdir().unwrap();
        let store = BlobStore::new(
            directory.path().join("blobs"),
            directory.path().join("tmp"),
            100,
        )
        .await
        .unwrap();
        let digest = format!("sha256:{}", "00".repeat(32));
        let error = store.put(&digest, Body::from("wasm")).await.unwrap_err();
        assert_eq!(error.code, "digest_mismatch");
        assert_eq!(
            std::fs::read_dir(directory.path().join("tmp"))
                .unwrap()
                .count(),
            0
        );
    }
}
