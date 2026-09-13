//! Server configuration.

use std::{env, net::SocketAddr, path::PathBuf};

use crate::error::{ApiError, Result};

/// Runtime server configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listening address.
    pub listen: SocketAddr,
    /// SQLite database path.
    pub database_path: PathBuf,
    /// Content-addressed blob directory.
    pub blob_dir: PathBuf,
    /// Temporary upload directory.
    pub temp_dir: PathBuf,
    /// Maximum accepted blob size.
    pub max_blob_bytes: u64,
    /// Whether read endpoints are anonymous.
    pub public_read: bool,
    /// Optional bootstrap administrator token.
    pub admin_token: Option<String>,
    /// Public base URL reported to clients.
    pub public_url: String,
    /// Optional Wasmd executable used for admission policy execution.
    pub wasmd_binary: Option<PathBuf>,
    /// Optional Wasm admission-policy module run by Wasmd.
    pub wasmd_policy_module: Option<PathBuf>,
    /// Maximum policy invocation time.
    pub wasmd_policy_timeout_ms: u64,
    /// Maximum concurrent Wasmd policy processes.
    pub wasmd_policy_concurrency: usize,
}

impl Default for Config {
    fn default() -> Self {
        let data = PathBuf::from("data");
        Self {
            listen: "127.0.0.1:8080".parse().expect("literal socket address"),
            database_path: data.join("registry.db"),
            blob_dir: data.join("blobs"),
            temp_dir: data.join("tmp"),
            max_blob_bytes: 512 * 1024 * 1024,
            public_read: true,
            admin_token: None,
            public_url: "http://127.0.0.1:8080".to_owned(),
            wasmd_binary: None,
            wasmd_policy_module: None,
            wasmd_policy_timeout_ms: 5_000,
            wasmd_policy_concurrency: 4,
        }
    }
}

impl Config {
    /// Load configuration from `WASMD_REGISTRY_*` environment variables.
    pub fn from_env() -> Result<Self> {
        let mut config = Self::default();
        if let Ok(value) = env::var("WASMD_REGISTRY_LISTEN") {
            config.listen = value.parse().map_err(|_| {
                ApiError::bad_request(
                    "invalid_config",
                    "WASMD_REGISTRY_LISTEN is not a socket address",
                )
            })?;
        }
        if let Ok(value) = env::var("WASMD_REGISTRY_DATABASE") {
            config.database_path = value.into();
        }
        if let Ok(value) = env::var("WASMD_REGISTRY_BLOB_DIR") {
            config.blob_dir = value.into();
        }
        if let Ok(value) = env::var("WASMD_REGISTRY_TEMP_DIR") {
            config.temp_dir = value.into();
        }
        if let Ok(value) = env::var("WASMD_REGISTRY_MAX_BLOB_BYTES") {
            config.max_blob_bytes = value.parse().map_err(|_| {
                ApiError::bad_request(
                    "invalid_config",
                    "WASMD_REGISTRY_MAX_BLOB_BYTES is not an integer",
                )
            })?;
        }
        if let Ok(value) = env::var("WASMD_REGISTRY_PUBLIC_READ") {
            config.public_read = value.parse().map_err(|_| {
                ApiError::bad_request(
                    "invalid_config",
                    "WASMD_REGISTRY_PUBLIC_READ must be true or false",
                )
            })?;
        }
        config.admin_token = env::var("WASMD_REGISTRY_ADMIN_TOKEN")
            .ok()
            .filter(|v| !v.is_empty());
        if config
            .admin_token
            .as_ref()
            .is_some_and(|token| token.len() < 32)
        {
            return Err(ApiError::bad_request(
                "invalid_config",
                "WASMD_REGISTRY_ADMIN_TOKEN must contain at least 32 characters",
            ));
        }
        if let Ok(value) = env::var("WASMD_REGISTRY_PUBLIC_URL") {
            config.public_url = value.trim_end_matches('/').to_owned();
        }
        config.wasmd_binary = env::var("WASMD_REGISTRY_WASMD_BIN")
            .ok()
            .filter(|value| !value.is_empty())
            .map(Into::into);
        config.wasmd_policy_module = env::var("WASMD_REGISTRY_WASM_POLICY")
            .ok()
            .filter(|value| !value.is_empty())
            .map(Into::into);
        if config.wasmd_binary.is_some() != config.wasmd_policy_module.is_some() {
            return Err(ApiError::bad_request(
                "invalid_config",
                "WASMD_REGISTRY_WASMD_BIN and WASMD_REGISTRY_WASM_POLICY must be set together",
            ));
        }
        if let Ok(value) = env::var("WASMD_REGISTRY_WASM_POLICY_TIMEOUT_MS") {
            config.wasmd_policy_timeout_ms = value.parse().map_err(|_| {
                ApiError::bad_request(
                    "invalid_config",
                    "WASMD_REGISTRY_WASM_POLICY_TIMEOUT_MS is not an integer",
                )
            })?;
        }
        if let Ok(value) = env::var("WASMD_REGISTRY_WASM_POLICY_CONCURRENCY") {
            config.wasmd_policy_concurrency = value.parse().map_err(|_| {
                ApiError::bad_request(
                    "invalid_config",
                    "WASMD_REGISTRY_WASM_POLICY_CONCURRENCY is not an integer",
                )
            })?;
        }
        if config.wasmd_policy_timeout_ms == 0 || config.wasmd_policy_concurrency == 0 {
            return Err(ApiError::bad_request(
                "invalid_config",
                "Wasmd policy timeout and concurrency must be positive",
            ));
        }
        if config.max_blob_bytes == 0 {
            return Err(ApiError::bad_request(
                "invalid_config",
                "maximum blob size must be positive",
            ));
        }
        Ok(config)
    }
}
