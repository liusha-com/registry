//! `wr` registry command-line client.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};
use futures_util::StreamExt as _;
use reqwest::{Client, Method, Response, header};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::{
    fs,
    io::{AsyncReadExt as _, AsyncWriteExt as _},
};
use tokio_util::io::ReaderStream;
use wasmd_registry::domain::{PackageManifest, validate_digest, validate_package_ref};

#[derive(Parser)]
#[command(
    name = "wr",
    version,
    about = "Wasm Native Registry command-line client"
)]
struct Args {
    /// Registry base URL.
    #[arg(
        long,
        env = "WASMD_REGISTRY_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    registry: String,
    /// Bearer token for write operations.
    #[arg(long, env = "WASMD_REGISTRY_TOKEN", hide_env_values = true)]
    token: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show server protocol and limits.
    Info,
    /// Namespace administration.
    Namespace {
        #[command(subcommand)]
        command: NamespaceCommand,
    },
    /// Token administration.
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// Hash and upload one immutable blob.
    Upload {
        path: PathBuf,
        #[arg(long, default_value = "application/wasm")]
        media_type: String,
    },
    /// Publish a package manifest after blobs are uploaded.
    Publish { manifest: PathBuf },
    /// Resolve the highest matching version.
    Resolve {
        package: String,
        #[arg(default_value = "*")]
        requirement: String,
    },
    /// Fetch an exact package manifest.
    Get { package: String, version: String },
    /// Download and verify a blob.
    Download { digest: String, output: PathBuf },
    /// Search packages.
    Search {
        #[arg(default_value = "")]
        query: String,
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
    /// Yank a published version from resolution.
    Yank { package: String, version: String },
    /// Restore a yanked version to resolution.
    Unyank { package: String, version: String },
}

#[derive(Subcommand)]
enum NamespaceCommand {
    /// Create a namespace.
    Create {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    /// Get namespace metadata.
    Get { name: String },
}

#[derive(Subcommand)]
enum TokenCommand {
    /// Create a scoped token. The secret is printed exactly once.
    Create {
        name: String,
        #[arg(long, value_delimiter = ',', required = true)]
        scopes: Vec<String>,
        #[arg(long)]
        namespace: Option<String>,
    },
    /// Revoke a token by ID.
    Revoke { id: String },
}

struct RegistryClient {
    base: String,
    token: Option<String>,
    http: Client,
}

impl RegistryClient {
    fn new(base: &str, token: Option<String>) -> anyhow::Result<Self> {
        let base = base.trim_end_matches('/').to_owned();
        let _ = url::Url::parse(&base).context("registry URL is invalid")?;
        let http = Client::builder()
            .timeout(Duration::from_secs(300))
            .user_agent(concat!("wr/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { base, token, http })
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        let request = self.http.request(method, format!("{}{}", self.base, path));
        if let Some(token) = &self.token {
            request.bearer_auth(token)
        } else {
            request
        }
    }

    async fn json(&self, method: Method, path: &str, body: Option<Value>) -> anyhow::Result<Value> {
        let mut request = self.request(method, path);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = check(request.send().await?).await?;
        if response.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(Value::Null);
        }
        response
            .json()
            .await
            .context("server returned invalid JSON")
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let client = RegistryClient::new(&args.registry, args.token)?;
    let result = match args.command {
        Command::Info => client.json(Method::GET, "/v1/info", None).await?,
        Command::Namespace { command } => match command {
            NamespaceCommand::Create { name, description } => {
                client
                    .json(
                        Method::POST,
                        "/v1/namespaces",
                        Some(json!({"name":name,"description":description})),
                    )
                    .await?
            }
            NamespaceCommand::Get { name } => {
                client
                    .json(Method::GET, &format!("/v1/namespaces/{name}"), None)
                    .await?
            }
        },
        Command::Token { command } => match command {
            TokenCommand::Create {
                name,
                scopes,
                namespace,
            } => {
                client
                    .json(
                        Method::POST,
                        "/v1/admin/tokens",
                        Some(json!({"name":name,"scopes":scopes,"namespace":namespace})),
                    )
                    .await?
            }
            TokenCommand::Revoke { id } => {
                client
                    .json(Method::DELETE, &format!("/v1/admin/tokens/{id}"), None)
                    .await?
            }
        },
        Command::Upload { path, media_type } => upload(&client, &path, &media_type).await?,
        Command::Publish { manifest } => publish(&client, &manifest).await?,
        Command::Resolve {
            package,
            requirement,
        } => {
            let (namespace, name) = split_package(&package)?;
            let encoded: String =
                url::form_urlencoded::byte_serialize(requirement.as_bytes()).collect();
            client
                .json(
                    Method::GET,
                    &format!("/v1/packages/{namespace}/{name}/resolve?requirement={encoded}"),
                    None,
                )
                .await?
        }
        Command::Get { package, version } => {
            let (namespace, name) = split_package(&package)?;
            client
                .json(
                    Method::GET,
                    &format!("/v1/packages/{namespace}/{name}/{version}"),
                    None,
                )
                .await?
        }
        Command::Download { digest, output } => download(&client, &digest, &output).await?,
        Command::Search { query, limit } => {
            let encoded: String = url::form_urlencoded::byte_serialize(query.as_bytes()).collect();
            client
                .json(
                    Method::GET,
                    &format!("/v1/search?q={encoded}&limit={limit}"),
                    None,
                )
                .await?
        }
        Command::Yank { package, version } => set_yank(&client, &package, &version, true).await?,
        Command::Unyank { package, version } => {
            set_yank(&client, &package, &version, false).await?
        }
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

async fn upload(client: &RegistryClient, path: &Path, media_type: &str) -> anyhow::Result<Value> {
    let digest = digest_file(path).await?;
    let file = fs::File::open(path)
        .await
        .with_context(|| format!("cannot open {}", path.display()))?;
    let length = file.metadata().await?.len();
    let body = reqwest::Body::wrap_stream(ReaderStream::new(file));
    let response = client
        .request(Method::PUT, &format!("/v1/blobs/{digest}"))
        .header(header::CONTENT_TYPE, media_type)
        .header(header::CONTENT_LENGTH, length)
        .body(body)
        .send()
        .await?;
    let response = check(response).await?;
    response
        .json()
        .await
        .context("server returned invalid JSON")
}

async fn publish(client: &RegistryClient, path: &Path) -> anyhow::Result<Value> {
    let bytes = fs::read(path)
        .await
        .with_context(|| format!("cannot read {}", path.display()))?;
    let manifest: PackageManifest =
        serde_json::from_slice(&bytes).context("manifest is invalid JSON")?;
    manifest.validate().context("manifest validation failed")?;
    let namespace = &manifest.namespace;
    let name = &manifest.name;
    let response = client
        .request(
            Method::POST,
            &format!("/v1/packages/{namespace}/{name}/versions"),
        )
        .json(&manifest)
        .send()
        .await?;
    check(response)
        .await?
        .json()
        .await
        .context("server returned invalid JSON")
}

async fn download(client: &RegistryClient, digest: &str, output: &Path) -> anyhow::Result<Value> {
    validate_digest(digest).context("invalid digest")?;
    let response = check(
        client
            .request(Method::GET, &format!("/v1/blobs/{digest}"))
            .send()
            .await?,
    )
    .await?;
    let temporary = output.with_extension("part");
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).await?;
    }
    let mut file = fs::File::create(&temporary).await?;
    let mut stream = response.bytes_stream();
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        size += u64::try_from(chunk.len())?;
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    file.sync_all().await?;
    drop(file);
    let actual = format!("sha256:{}", hex::encode(hasher.finalize()));
    if actual != digest {
        let _ = fs::remove_file(&temporary).await;
        bail!("download digest mismatch: expected {digest}, got {actual}");
    }
    fs::rename(&temporary, output).await?;
    Ok(json!({"digest":digest,"size":size,"output":output}))
}

async fn set_yank(
    client: &RegistryClient,
    package: &str,
    version: &str,
    value: bool,
) -> anyhow::Result<Value> {
    let (namespace, name) = split_package(package)?;
    let method = if value { Method::POST } else { Method::DELETE };
    client
        .json(
            method,
            &format!("/v1/packages/{namespace}/{name}/{version}/yank"),
            None,
        )
        .await
}

async fn digest_file(path: &Path) -> anyhow::Result<String> {
    let mut file = fs::File::open(path)
        .await
        .with_context(|| format!("cannot open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn split_package(package: &str) -> anyhow::Result<(&str, &str)> {
    validate_package_ref(package).context("package must be namespace/name")?;
    package
        .split_once('/')
        .context("package must be namespace/name")
}

async fn check(response: Response) -> anyhow::Result<Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    bail!("registry returned {status}: {body}")
}
