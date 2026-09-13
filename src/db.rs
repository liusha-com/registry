//! SQLite metadata persistence.

use std::{path::Path, str::FromStr};

use semver::{Version, VersionReq};
use sha2::{Digest as _, Sha256};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    component::ComponentAnalysis,
    domain::{PackageManifest, PackageRecord, RegistryStats, SearchResult, VersionRecord},
    error::{ApiError, Result},
};

/// Stored authorization token metadata.
#[derive(Debug, sqlx::FromRow)]
pub struct TokenRow {
    /// Identifier.
    pub id: String,
    /// JSON scopes.
    pub scopes_json: String,
    /// Optional namespace restriction.
    pub namespace: Option<String>,
}

/// Stored namespace.
#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct NamespaceRow {
    /// Account owning this namespace; legacy namespaces remain administrator-managed.
    pub owner_username: Option<String>,
    /// Namespace name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Creation timestamp.
    pub created_at: String,
}

/// Stored blob metadata.
#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct BlobRow {
    /// Digest.
    pub digest: String,
    /// Bytes.
    pub size: i64,
    /// Media type.
    pub media_type: String,
    /// Creation timestamp.
    pub created_at: String,
}

/// SQLite registry database.
#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Open a database, apply pragmas, and run embedded migrations.
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .busy_timeout(std::time::Duration::from_secs(10));
        let pool = SqlitePoolOptions::new()
            .max_connections(10)
            .connect_with(options)
            .await?;
        sqlx::migrate!().run(&pool).await.map_err(|error| {
            tracing::error!(%error, "database migration failed");
            ApiError::internal("database migration failed")
        })?;
        Ok(Self { pool })
    }

    /// Verify the database answers a query.
    pub async fn ready(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Return aggregate public counters for registry discovery pages.
    pub async fn stats(&self) -> Result<RegistryStats> {
        Ok(sqlx::query_as(
            "SELECT \
                (SELECT COUNT(*) FROM namespaces) AS namespaces, \
                (SELECT COUNT(*) FROM packages) AS packages, \
                (SELECT COUNT(*) FROM versions) AS versions, \
                (SELECT COUNT(*) FROM blobs) AS blobs, \
                (SELECT COUNT(*) FROM component_analyses) AS components",
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// Create a namespace.
    pub async fn create_namespace(&self, name: &str, description: &str) -> Result<NamespaceRow> {
        self.create_namespace_owned(name, description, None).await
    }

    /// Create a namespace and its owner in one SQLite statement.
    pub async fn create_namespace_owned(
        &self,
        name: &str,
        description: &str,
        owner: Option<&str>,
    ) -> Result<NamespaceRow> {
        let now = now()?;
        let result = sqlx::query(
            "INSERT INTO namespaces(name,description,created_at,owner_username) VALUES(?,?,?,?)",
        )
        .bind(name)
        .bind(description)
        .bind(&now)
        .bind(owner)
        .execute(&self.pool)
        .await;
        if let Err(error) = result {
            if is_unique(&error) {
                return Err(ApiError::conflict(
                    "namespace_exists",
                    "namespace already exists",
                ));
            }
            return Err(error.into());
        }
        Ok(NamespaceRow {
            owner_username: owner.map(str::to_owned),
            name: name.to_owned(),
            description: description.to_owned(),
            created_at: now,
        })
    }

    /// Fetch a namespace.
    pub async fn require_owner(&self, name: &str, username: &str) -> Result<()> {
        let owner = sqlx::query_scalar::<_, Option<String>>(
            "SELECT owner_username FROM namespaces WHERE name=?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .flatten();
        if owner.as_deref() != Some(username) {
            return Err(ApiError::forbidden("You do not own this namespace."));
        }
        Ok(())
    }

    /// Fetch a namespace.
    pub async fn namespace(&self, name: &str) -> Result<NamespaceRow> {
        sqlx::query_as(
            "SELECT name,description,created_at,owner_username FROM namespaces WHERE name=?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("namespace not found"))
    }

    /// Insert a scoped token hash.
    pub async fn create_token(
        &self,
        id: &str,
        name: &str,
        token_hash: &[u8],
        scopes_json: &str,
        namespace: Option<&str>,
    ) -> Result<()> {
        sqlx::query("INSERT INTO api_tokens(id,name,token_hash,scopes_json,namespace,created_at) VALUES(?,?,?,?,?,?)")
            .bind(id).bind(name).bind(token_hash).bind(scopes_json).bind(namespace).bind(now()?).execute(&self.pool).await?;
        Ok(())
    }

    /// Look up a non-revoked token by hash.
    pub async fn token_by_hash(&self, hash: &[u8]) -> Result<Option<TokenRow>> {
        Ok(sqlx::query_as("SELECT id,scopes_json,namespace FROM api_tokens WHERE token_hash=? AND revoked_at IS NULL")
            .bind(hash).fetch_optional(&self.pool).await?)
    }

    /// Revoke a token.
    pub async fn revoke_token(&self, id: &str) -> Result<()> {
        let result =
            sqlx::query("UPDATE api_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL")
                .bind(now()?)
                .bind(id)
                .execute(&self.pool)
                .await?;
        if result.rows_affected() == 0 {
            return Err(ApiError::not_found("token not found or already revoked"));
        }
        Ok(())
    }

    /// Record or verify immutable blob metadata.
    pub async fn put_blob(&self, digest: &str, size: u64, media_type: &str) -> Result<BlobRow> {
        let size_i64 = i64::try_from(size)
            .map_err(|_| ApiError::too_large("blob size exceeds database range"))?;
        if let Some(existing) = self.blob(digest).await? {
            if existing.size != size_i64 {
                return Err(ApiError::conflict(
                    "blob_metadata_conflict",
                    "digest exists with a different size",
                ));
            }
            return Ok(existing);
        }
        let created_at = now()?;
        sqlx::query("INSERT INTO blobs(digest,size,media_type,created_at) VALUES(?,?,?,?)")
            .bind(digest)
            .bind(size_i64)
            .bind(media_type)
            .bind(&created_at)
            .execute(&self.pool)
            .await?;
        Ok(BlobRow {
            digest: digest.to_owned(),
            size: size_i64,
            media_type: media_type.to_owned(),
            created_at,
        })
    }

    /// Find blob metadata.
    pub async fn blob(&self, digest: &str) -> Result<Option<BlobRow>> {
        Ok(
            sqlx::query_as("SELECT digest,size,media_type,created_at FROM blobs WHERE digest=?")
                .bind(digest)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Persist derived Component Model metadata for an immutable blob.
    pub async fn put_component_analysis(&self, analysis: &ComponentAnalysis) -> Result<()> {
        let json = serde_json::to_string(analysis)
            .map_err(|_| ApiError::internal("component analysis serialization failed"))?;
        sqlx::query(
            "INSERT INTO component_analyses(digest,analysis_json,created_at) VALUES(?,?,?) \
             ON CONFLICT(digest) DO UPDATE SET analysis_json=excluded.analysis_json",
        )
        .bind(&analysis.digest)
        .bind(json)
        .bind(now()?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Fetch Component Model metadata derived from a blob.
    pub async fn component_analysis(&self, digest: &str) -> Result<Option<ComponentAnalysis>> {
        let json: Option<String> =
            sqlx::query_scalar("SELECT analysis_json FROM component_analyses WHERE digest=?")
                .bind(digest)
                .fetch_optional(&self.pool)
                .await?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|_| ApiError::internal("stored component analysis is invalid"))
        })
        .transpose()
    }

    /// Atomically publish an immutable package version.
    pub async fn publish(
        &self,
        manifest: &PackageManifest,
        publisher_token_id: Option<&str>,
    ) -> Result<VersionRecord> {
        manifest.validate()?;
        for artifact in &manifest.artifacts {
            let blob = self.blob(&artifact.digest).await?.ok_or_else(|| {
                ApiError::conflict(
                    "blob_missing",
                    format!("blob {} has not been uploaded", artifact.digest),
                )
            })?;
            if u64::try_from(blob.size).ok() != Some(artifact.size) {
                return Err(ApiError::conflict(
                    "blob_size_mismatch",
                    format!(
                        "artifact {} size does not match uploaded blob",
                        artifact.name
                    ),
                ));
            }
        }
        let manifest_json = serde_json::to_string(manifest)
            .map_err(|_| ApiError::internal("manifest serialization failed"))?;
        let manifest_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(manifest_json.as_bytes()))
        );
        let timestamp = now()?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO packages(namespace,name,description,created_at,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(namespace,name) DO UPDATE SET description=excluded.description,updated_at=excluded.updated_at")
            .bind(&manifest.namespace).bind(&manifest.name).bind(&manifest.description).bind(&timestamp).bind(&timestamp).execute(&mut *tx).await?;
        let inserted = sqlx::query("INSERT INTO versions(namespace,package,version,manifest_json,manifest_digest,created_at,updated_at,publisher_token_id) VALUES(?,?,?,?,?,?,?,?)")
            .bind(&manifest.namespace).bind(&manifest.name).bind(&manifest.version).bind(&manifest_json).bind(&manifest_digest)
            .bind(&timestamp).bind(&timestamp).bind(publisher_token_id).execute(&mut *tx).await;
        if let Err(error) = inserted {
            tx.rollback().await?;
            if is_unique(&error) {
                return Err(ApiError::conflict(
                    "version_exists",
                    "package version is immutable and already exists",
                ));
            }
            return Err(error.into());
        }
        for artifact in &manifest.artifacts {
            sqlx::query("INSERT INTO version_artifacts(namespace,package,version,artifact_name,digest,size,media_type) VALUES(?,?,?,?,?,?,?)")
                .bind(&manifest.namespace).bind(&manifest.name).bind(&manifest.version).bind(&artifact.name).bind(&artifact.digest)
                .bind(i64::try_from(artifact.size).map_err(|_| ApiError::too_large("artifact size exceeds database range"))?)
                .bind(&artifact.media_type).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(VersionRecord {
            version: manifest.version.clone(),
            manifest_digest,
            yanked: false,
            created_at: timestamp,
        })
    }

    /// Fetch exact manifest and record.
    pub async fn manifest(
        &self,
        namespace: &str,
        package: &str,
        version: &str,
    ) -> Result<(PackageManifest, VersionRecord)> {
        let row = sqlx::query("SELECT manifest_json,manifest_digest,yanked,created_at FROM versions WHERE namespace=? AND package=? AND version=?")
            .bind(namespace).bind(package).bind(version).fetch_optional(&self.pool).await?
            .ok_or_else(|| ApiError::not_found("package version not found"))?;
        let manifest = serde_json::from_str(row.get("manifest_json"))
            .map_err(|_| ApiError::internal("stored manifest is invalid"))?;
        Ok((
            manifest,
            VersionRecord {
                version: version.to_owned(),
                manifest_digest: row.get("manifest_digest"),
                yanked: row.get("yanked"),
                created_at: row.get("created_at"),
            },
        ))
    }

    /// Fetch package and all versions.
    pub async fn package(&self, namespace: &str, package: &str) -> Result<PackageRecord> {
        let row =
            sqlx::query("SELECT description,updated_at FROM packages WHERE namespace=? AND name=?")
                .bind(namespace)
                .bind(package)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| ApiError::not_found("package not found"))?;
        let versions = sqlx::query_as("SELECT version,manifest_digest,yanked,created_at FROM versions WHERE namespace=? AND package=?")
            .bind(namespace).bind(package).fetch_all(&self.pool).await?;
        Ok(PackageRecord {
            namespace: namespace.to_owned(),
            name: package.to_owned(),
            description: row.get("description"),
            updated_at: row.get("updated_at"),
            versions,
        })
    }

    /// Resolve the greatest matching non-yanked version.
    pub async fn resolve(
        &self,
        namespace: &str,
        package: &str,
        requirement: &str,
    ) -> Result<(PackageManifest, VersionRecord)> {
        let requirement = VersionReq::parse(requirement)
            .map_err(|e| ApiError::bad_request("invalid_requirement", e.to_string()))?;
        let rows = sqlx::query("SELECT version,manifest_json,manifest_digest,created_at FROM versions WHERE namespace=? AND package=? AND yanked=0")
            .bind(namespace).bind(package).fetch_all(&self.pool).await?;
        let mut candidates = Vec::new();
        for row in rows {
            let text: String = row.get("version");
            let version = Version::parse(&text)
                .map_err(|_| ApiError::internal("stored version is invalid"))?;
            if requirement.matches(&version) {
                candidates.push((version, row));
            }
        }
        let (_, row) = candidates
            .into_iter()
            .max_by(|(left, _), (right, _)| left.cmp(right))
            .ok_or_else(|| {
                ApiError::not_found("no non-yanked version satisfies the requirement")
            })?;
        let version: String = row.get("version");
        let manifest = serde_json::from_str(row.get("manifest_json"))
            .map_err(|_| ApiError::internal("stored manifest is invalid"))?;
        Ok((
            manifest,
            VersionRecord {
                version,
                manifest_digest: row.get("manifest_digest"),
                yanked: false,
                created_at: row.get("created_at"),
            },
        ))
    }

    /// Change yank state without mutating package content.
    pub async fn set_yanked(
        &self,
        namespace: &str,
        package: &str,
        version: &str,
        yanked: bool,
    ) -> Result<()> {
        let result = sqlx::query("UPDATE versions SET yanked=?,updated_at=? WHERE namespace=? AND package=? AND version=?")
            .bind(yanked).bind(now()?).bind(namespace).bind(package).bind(version).execute(&self.pool).await?;
        if result.rows_affected() == 0 {
            return Err(ApiError::not_found("package version not found"));
        }
        Ok(())
    }

    /// Search packages.
    pub async fn search(&self, query: &str, limit: u32, offset: u32) -> Result<Vec<SearchResult>> {
        let pattern = format!("%{}%", query.replace('%', "\\%").replace('_', "\\_"));
        let mut results: Vec<SearchResult> = sqlx::query_as(
            "SELECT p.namespace,p.name,p.description,p.updated_at,NULL AS latest_version FROM packages p WHERE p.namespace LIKE ? ESCAPE '\\' OR p.name LIKE ? ESCAPE '\\' OR p.description LIKE ? ESCAPE '\\' ORDER BY p.updated_at DESC LIMIT ? OFFSET ?")
            .bind(&pattern).bind(&pattern).bind(&pattern).bind(i64::from(limit)).bind(i64::from(offset)).fetch_all(&self.pool).await?;
        for result in &mut results {
            let versions: Vec<String> = sqlx::query_scalar(
                "SELECT version FROM versions WHERE namespace=? AND package=? AND yanked=0",
            )
            .bind(&result.namespace)
            .bind(&result.name)
            .fetch_all(&self.pool)
            .await?;
            result.latest_version = versions
                .into_iter()
                .filter_map(|text| Version::parse(&text).ok())
                .max()
                .map(|version| version.to_string());
        }
        Ok(results)
    }
}

fn now() -> Result<String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| ApiError::internal("clock formatting failed"))
}

fn is_unique(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.is_unique_violation())
}
