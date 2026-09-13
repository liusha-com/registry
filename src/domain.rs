//! Registry domain and wire types.

use std::collections::{BTreeMap, BTreeSet};

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{ApiError, Result};

/// Current package envelope schema.
pub const PACKAGE_SCHEMA: &str = "wasmd.package/v0";
/// Registry protocol version.
pub const REGISTRY_VERSION: &str = "0.1";

/// A package artifact descriptor.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Artifact {
    /// Unique artifact name within the version.
    pub name: String,
    /// SHA-256 content digest.
    pub digest: String,
    /// Blob size in bytes.
    pub size: u64,
    /// Artifact media type.
    pub media_type: String,
    /// Extensible artifact kind.
    pub kind: String,
    /// Optional target triple or execution target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Forward-compatible artifact properties.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Version publication envelope.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct PackageManifest {
    /// Envelope schema identifier.
    pub schema: String,
    /// Owning namespace.
    pub namespace: String,
    /// Package name.
    pub name: String,
    /// Semantic version.
    pub version: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// SPDX license expression when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Source repository URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// One or more immutable artifacts.
    pub artifacts: Vec<Artifact>,
    /// Package reference to SemVer requirement.
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    /// Extensible user metadata.
    #[serde(default)]
    pub annotations: BTreeMap<String, Value>,
    /// Forward-compatible manifest properties.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl PackageManifest {
    /// Validate the envelope and return its parsed canonical version.
    pub fn validate(&self) -> Result<Version> {
        if self.schema != PACKAGE_SCHEMA {
            return Err(ApiError::bad_request(
                "unsupported_schema",
                format!("expected {PACKAGE_SCHEMA}"),
            ));
        }
        validate_name("namespace", &self.namespace)?;
        validate_name("package", &self.name)?;
        let version = Version::parse(&self.version)
            .map_err(|e| ApiError::bad_request("invalid_version", e.to_string()))?;
        if version.to_string() != self.version {
            return Err(ApiError::bad_request(
                "noncanonical_version",
                format!("canonical version is {version}"),
            ));
        }
        if self.artifacts.is_empty() {
            return Err(ApiError::bad_request(
                "artifact_required",
                "at least one artifact is required",
            ));
        }
        let mut names = BTreeSet::new();
        for artifact in &self.artifacts {
            validate_name("artifact", &artifact.name)?;
            validate_digest(&artifact.digest)?;
            if artifact.media_type.trim().is_empty() || artifact.media_type.len() > 255 {
                return Err(ApiError::bad_request(
                    "invalid_media_type",
                    "artifact media type is empty or too long",
                ));
            }
            if artifact.kind.trim().is_empty() || artifact.kind.len() > 64 {
                return Err(ApiError::bad_request(
                    "invalid_artifact_kind",
                    "artifact kind is empty or too long",
                ));
            }
            if !names.insert(&artifact.name) {
                return Err(ApiError::bad_request(
                    "duplicate_artifact",
                    artifact.name.clone(),
                ));
            }
        }
        for (package, requirement) in &self.dependencies {
            validate_package_ref(package)?;
            VersionReq::parse(requirement).map_err(|e| {
                ApiError::bad_request("invalid_dependency_requirement", format!("{package}: {e}"))
            })?;
        }
        if self.description.len() > 4096 {
            return Err(ApiError::bad_request(
                "description_too_long",
                "description exceeds 4096 bytes",
            ));
        }
        if let Some(repository) = &self.repository {
            let url = url::Url::parse(repository)
                .map_err(|error| ApiError::bad_request("invalid_repository", error.to_string()))?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err(ApiError::bad_request(
                    "invalid_repository",
                    "repository URL must use HTTP or HTTPS",
                ));
            }
        }
        Ok(version)
    }
}

/// Namespace creation request.
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateNamespace {
    /// Namespace name.
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: String,
}

/// Token creation request.
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateToken {
    /// Human-readable token label.
    pub name: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Optional namespace restriction.
    pub namespace: Option<String>,
}

/// Returned token secret; only produced once.
#[derive(Debug, Serialize)]
pub struct CreatedToken {
    /// Token database identifier.
    pub id: String,
    /// Bearer token secret.
    pub token: String,
}

/// Result returned after validating registry credentials.
#[derive(Debug, Serialize)]
pub struct AuthStatus {
    /// Authentication succeeded.
    pub authenticated: bool,
    /// Persistent token ID, absent for the bootstrap administrator.
    pub token_id: Option<String>,
    /// Granted scopes in stable lexical order.
    pub scopes: Vec<String>,
    /// Optional namespace restriction.
    pub namespace: Option<String>,
}

/// Registry information response.
#[derive(Debug, Serialize)]
pub struct RegistryInfo {
    /// Protocol version.
    pub registry_version: &'static str,
    /// Supported package schemas.
    pub package_schemas: Vec<&'static str>,
    /// Maximum blob bytes.
    pub max_blob_bytes: u64,
    /// Anonymous read policy.
    pub public_read: bool,
    /// Active admission-policy engine.
    pub admission_engine: String,
    /// Optional protocol capabilities implemented by this server.
    pub features: Vec<&'static str>,
    /// Maximum blob size eligible for automatic Component Model analysis.
    pub component_analysis_max_bytes: u64,
}

/// Public aggregate registry counters used by discovery clients.
#[derive(Debug, Serialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(sqlx::FromRow))]
pub struct RegistryStats {
    /// Number of namespaces.
    pub namespaces: i64,
    /// Number of packages.
    pub packages: i64,
    /// Number of immutable package versions.
    pub versions: i64,
    /// Number of content-addressed blobs.
    pub blobs: i64,
    /// Number of blobs with decoded Component Model metadata.
    pub components: i64,
}

/// A version record returned by the service.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(sqlx::FromRow))]
pub struct VersionRecord {
    /// Semantic version.
    pub version: String,
    /// SHA-256 digest of canonical manifest JSON.
    pub manifest_digest: String,
    /// Yank status.
    pub yanked: bool,
    /// Creation timestamp.
    pub created_at: String,
}

/// Package detail response.
#[derive(Debug, Serialize)]
pub struct PackageRecord {
    /// Namespace.
    pub namespace: String,
    /// Package name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Last update timestamp.
    pub updated_at: String,
    /// Published versions.
    pub versions: Vec<VersionRecord>,
}

/// Search result row.
#[derive(Debug, Serialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(sqlx::FromRow))]
pub struct SearchResult {
    /// Namespace.
    pub namespace: String,
    /// Package name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Latest non-yanked stable or prerelease version.
    pub latest_version: Option<String>,
    /// Update timestamp.
    pub updated_at: String,
}

/// Validate a registry name.
pub fn validate_name(kind: &str, name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    let valid_edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let valid_middle = |b: u8| valid_edge(b) || matches!(b, b'.' | b'_' | b'-');
    if bytes.is_empty()
        || bytes.len() > 64
        || !valid_edge(bytes[0])
        || !valid_edge(bytes[bytes.len() - 1])
        || !bytes.iter().copied().all(valid_middle)
    {
        return Err(ApiError::bad_request(
            "invalid_name",
            format!("invalid {kind} name: {name}"),
        ));
    }
    Ok(())
}

/// Validate and return digest hex.
pub fn validate_digest(digest: &str) -> Result<&str> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(ApiError::bad_request(
            "invalid_digest",
            "digest must start with sha256:",
        ));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ApiError::bad_request(
            "invalid_digest",
            "digest must contain 64 lowercase hexadecimal digits",
        ));
    }
    Ok(hex)
}

/// Validate `namespace/package` reference.
pub fn validate_package_ref(reference: &str) -> Result<()> {
    let mut parts = reference.split('/');
    let (Some(namespace), Some(package), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(ApiError::bad_request(
            "invalid_package_ref",
            reference.to_owned(),
        ));
    };
    validate_name("namespace", namespace)?;
    validate_name("package", package)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_strict_and_lowercase() {
        for valid in ["a", "demo", "hello-world", "foo.bar", "x_1"] {
            assert!(validate_name("test", valid).is_ok());
        }
        for invalid in ["", "A", "-x", "x-", "two words", "é"] {
            assert!(validate_name("test", invalid).is_err());
        }
    }

    #[test]
    fn digest_is_canonical() {
        assert!(validate_digest(&format!("sha256:{}", "ab".repeat(32))).is_ok());
        assert!(validate_digest(&format!("sha256:{}", "AB".repeat(32))).is_err());
    }

    #[test]
    fn repository_urls_are_safe_for_registry_clients() {
        let artifact = Artifact {
            name: "module".to_owned(),
            digest: format!("sha256:{}", "00".repeat(32)),
            size: 8,
            media_type: "application/wasm".to_owned(),
            kind: "core-module".to_owned(),
            target: None,
            extra: BTreeMap::new(),
        };
        let manifest = |repository: &str| PackageManifest {
            schema: PACKAGE_SCHEMA.to_owned(),
            namespace: "demo".to_owned(),
            name: "hello".to_owned(),
            version: "1.0.0".to_owned(),
            description: String::new(),
            license: None,
            repository: Some(repository.to_owned()),
            artifacts: vec![artifact.clone()],
            dependencies: BTreeMap::new(),
            annotations: BTreeMap::new(),
            extra: BTreeMap::new(),
        };
        assert!(manifest("https://example.com/source").validate().is_ok());
        assert!(manifest("javascript:alert(1)").validate().is_err());
    }
}
