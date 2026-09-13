//! Optional manifest admission policy executed by Wasmd.

use std::{path::PathBuf, sync::Arc, time::Duration};

use tokio::{process::Command, sync::Semaphore, time::timeout};

use crate::{
    config::Config,
    domain::PackageManifest,
    error::{ApiError, Result},
};

/// Manifest admission engine.
#[derive(Clone)]
pub enum AdmissionPolicy {
    /// Native validation only.
    Native,
    /// Additional Wasm policy executed by Wasmd.
    Wasmd(Arc<WasmdPolicy>),
}

/// Wasmd subprocess policy configuration.
pub struct WasmdPolicy {
    binary: PathBuf,
    module: PathBuf,
    temp_root: PathBuf,
    timeout: Duration,
    permits: Semaphore,
}

impl AdmissionPolicy {
    /// Construct and validate the configured policy engine.
    pub async fn from_config(config: &Config) -> Result<Self> {
        let (Some(binary), Some(module)) = (&config.wasmd_binary, &config.wasmd_policy_module)
        else {
            return Ok(Self::Native);
        };
        for (kind, path) in [("Wasmd executable", binary), ("Wasm policy module", module)] {
            if !tokio::fs::try_exists(path).await? {
                return Err(ApiError::bad_request(
                    "invalid_config",
                    format!("{kind} does not exist: {}", path.display()),
                ));
            }
        }
        let mut command = Command::new(binary);
        command
            .kill_on_drop(true)
            .arg("validate")
            .arg(module)
            .arg("--json");
        let output = timeout(
            Duration::from_millis(config.wasmd_policy_timeout_ms),
            command.output(),
        )
        .await
        .map_err(|_| ApiError::bad_request("invalid_config", "Wasmd policy validation timed out"))?
        .map_err(|error| {
            ApiError::bad_request("invalid_config", format!("cannot execute Wasmd: {error}"))
        })?;
        if !output.status.success() {
            return Err(ApiError::bad_request(
                "invalid_config",
                format!(
                    "Wasmd rejected policy module: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        Ok(Self::Wasmd(Arc::new(WasmdPolicy {
            binary: binary.clone(),
            module: module.clone(),
            temp_root: config.temp_dir.join("admission"),
            timeout: Duration::from_millis(config.wasmd_policy_timeout_ms),
            permits: Semaphore::new(config.wasmd_policy_concurrency),
        })))
    }

    /// Engine identifier exposed by `/v1/info`.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Wasmd(_) => "wasmd",
        }
    }

    /// Run the configured admission policy.
    pub async fn validate(&self, manifest: &PackageManifest) -> Result<()> {
        let Self::Wasmd(policy) = self else {
            return Ok(());
        };
        policy.validate(manifest).await
    }

    /// Verify configured runtime artifacts remain available.
    pub async fn ready(&self) -> Result<()> {
        let Self::Wasmd(policy) = self else {
            return Ok(());
        };
        if !tokio::fs::try_exists(&policy.binary).await?
            || !tokio::fs::try_exists(&policy.module).await?
        {
            return Err(ApiError::internal("Wasmd admission engine is unavailable"));
        }
        Ok(())
    }
}

impl WasmdPolicy {
    async fn validate(&self, manifest: &PackageManifest) -> Result<()> {
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|_| ApiError::internal("Wasmd policy executor is closed"))?;
        tokio::fs::create_dir_all(&self.temp_root).await?;
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| ApiError::internal("secure random generation failed"))?;
        let request_dir = self.temp_root.join(hex::encode(random));
        tokio::fs::create_dir(&request_dir).await?;
        let bytes = serde_json::to_vec(manifest)
            .map_err(|_| ApiError::internal("manifest serialization failed"))?;
        tokio::fs::write(request_dir.join("manifest.json"), bytes).await?;
        let mapping = format!("/input={}", request_dir.display());
        let mut command = Command::new(&self.binary);
        command
            .kill_on_drop(true)
            .arg("run")
            .arg(&self.module)
            .arg("--wasi")
            .arg("--dir")
            .arg(mapping)
            .arg("--fuel")
            .arg("10000000")
            .arg("--json");
        let execution = timeout(self.timeout, command.output()).await;
        let _ = tokio::fs::remove_dir_all(&request_dir).await;
        let output = execution
            .map_err(|_| {
                ApiError::new(
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "policy_timeout",
                    "Wasmd admission policy timed out",
                )
            })?
            .map_err(|error| ApiError::internal(format!("cannot execute Wasmd policy: {error}")))?;
        if output.status.success() {
            tracing::debug!(engine = "wasmd", "manifest admitted by Wasm policy");
            return Ok(());
        }
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        Err(ApiError::bad_request(
            "policy_rejected",
            "manifest was rejected by Wasmd admission policy",
        )
        .detail("engine", "wasmd")
        .detail("diagnostic", truncate(&diagnostic, 2048)))
    }
}

fn truncate(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}
