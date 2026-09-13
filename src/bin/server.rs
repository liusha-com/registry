//! Wasmd Registry server executable.

use anyhow::Context as _;
use clap::Parser;
use tracing_subscriber::EnvFilter;
use wasmd_registry::{Config, serve};

#[derive(Parser)]
#[command(
    name = "wasmd-registry",
    version,
    about = "Open Wasm Native Registry server"
)]
struct Args {
    /// Emit structured JSON logs.
    #[arg(long, env = "WASMD_REGISTRY_JSON_LOGS", default_value_t = false)]
    json_logs: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("wasmd_registry=info,tower_http=info"));
    if args.json_logs {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    let config = Config::from_env().context("invalid registry configuration")?;
    serve(config)
        .await
        .context("registry terminated with an error")
}
