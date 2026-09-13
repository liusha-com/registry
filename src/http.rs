//! HTTP API and server lifecycle.

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, put},
};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_util::io::ReaderStream;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{catch_panic::CatchPanicLayer, trace::TraceLayer};

use crate::{
    admission::AdmissionPolicy,
    auth::{Principal, authenticate as authenticate_bearer, create_token},
    component::{MAX_ANALYSIS_BYTES, analyze},
    config::Config,
    db::Database,
    domain::{
        AuthStatus, CreateNamespace, CreateToken, PACKAGE_SCHEMA, PackageManifest,
        REGISTRY_VERSION, RegistryInfo, validate_digest, validate_name,
    },
    error::{ApiError, Result},
    storage::BlobStore,
};

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// Configuration.
    pub config: Arc<Config>,
    /// Metadata database.
    pub db: Database,
    /// Content store.
    pub blobs: BlobStore,
    /// Manifest admission engine.
    pub admission: AdmissionPolicy,
}

impl AppState {
    /// Initialize all persistence backends.
    pub async fn new(config: Config) -> Result<Self> {
        let db = Database::open(&config.database_path).await?;
        let blobs = BlobStore::new(
            config.blob_dir.clone(),
            config.temp_dir.clone(),
            config.max_blob_bytes,
        )
        .await?;
        let admission = AdmissionPolicy::from_config(&config).await?;
        Ok(Self {
            config: Arc::new(config),
            db,
            blobs,
            admission,
        })
    }
}

/// Construct the complete HTTP router.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(registry_page))
        .route("/explore", get(registry_page))
        .route("/login", get(registry_page))
        .route("/register", get(registry_page))
        .route("/account", get(registry_page))
        .route("/publish", get(registry_page))
        .route("/docs", get(registry_page))
        .route("/packages/{namespace}/{package}", get(registry_page))
        .route(
            "/packages/{namespace}/{package}/{version}",
            get(registry_page),
        )
        .route(
            "/v1/auth/{action}",
            get(account_endpoint).post(account_endpoint),
        )
        .route(
            "/v1/account/tokens",
            get(account_endpoint).post(account_endpoint),
        )
        .route("/v1/account/tokens/{id}", delete(account_endpoint))
        .route("/assets/app.css", get(registry_ui_css))
        .route("/assets/app.js", get(registry_ui_js))
        .route("/favicon.svg", get(registry_favicon))
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/openapi.yaml", get(openapi))
        .route("/v1/info", get(info))
        .route("/v1/auth/check", get(check_auth))
        .route("/v1/stats", get(stats))
        .route(
            "/v1/blobs/{digest}",
            put(put_blob).get(get_blob).head(get_blob),
        )
        .route("/v1/blobs/{digest}/component", get(get_component_analysis))
        .route("/v1/namespaces", axum::routing::post(create_namespace))
        .route("/v1/namespaces/{namespace}", get(get_namespace))
        .route("/v1/admin/tokens", axum::routing::post(create_api_token))
        .route("/v1/admin/tokens/{id}", delete(revoke_api_token))
        .route(
            "/v1/packages/{namespace}/{package}/versions",
            axum::routing::post(publish),
        )
        .route("/v1/packages/{namespace}/{package}/resolve", get(resolve))
        .route(
            "/v1/packages/{namespace}/{package}/{version}/yank",
            axum::routing::post(yank).delete(unyank),
        )
        .route(
            "/v1/packages/{namespace}/{package}/{version}",
            get(get_manifest),
        )
        .route("/v1/packages/{namespace}/{package}", get(get_package))
        .route("/v1/search", get(search))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(ConcurrencyLimitLayer::new(256))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn check_auth(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<AuthStatus>> {
    let principal = authenticate(&state, &headers, false).await?;
    Ok(Json(AuthStatus {
        authenticated: true,
        token_id: principal.token_id,
        scopes: principal.scopes.into_iter().collect(),
        namespace: principal.namespace,
    }))
}

async fn registry_page(uri: axum::http::Uri) -> Response {
    crate::pages::render(uri.path()).map_or_else(
        || (StatusCode::NOT_FOUND, "Page not found").into_response(),
        |html| {
            (
                [
                    (header::CONTENT_SECURITY_POLICY, crate::pages::CSP),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                    (header::REFERRER_POLICY, "same-origin"),
                ],
                Html(html),
            )
                .into_response()
        },
    )
}

async fn registry_ui_css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("../ui/app.css"),
    )
}

async fn registry_ui_js() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("../ui/app.js"),
    )
}

async fn registry_favicon() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        include_str!("../ui/favicon.svg"),
    )
}

/// Run until a shutdown signal is received.
pub async fn serve(config: Config) -> Result<()> {
    let listen = config.listen;
    let state = AppState::new(config).await?;
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|error| ApiError::internal(format!("cannot bind {listen}: {error}")))?;
    tracing::info!(%listen, blob_root = %state.blobs.root().display(), "registry listening");
    axum::serve(listener, build_router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|error| ApiError::internal(format!("HTTP server failed: {error}")))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = terminate => {} }
    tracing::info!("shutdown signal received");
}

async fn health() -> impl IntoResponse {
    Json(json!({"status":"ok"}))
}

async fn openapi() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/yaml; charset=utf-8")],
        include_str!("../openapi/registry.yaml"),
    )
}

async fn ready(State(state): State<AppState>) -> Result<impl IntoResponse> {
    state.db.ready().await?;
    state.admission.ready().await?;
    if !tokio::fs::try_exists(state.blobs.root()).await? {
        return Err(ApiError::internal("blob storage is unavailable"));
    }
    Ok(Json(json!({"status":"ready"})))
}

async fn info(State(state): State<AppState>, headers: HeaderMap) -> Result<impl IntoResponse> {
    require_read(&state, &headers).await?;
    Ok(Json(RegistryInfo {
        registry_version: REGISTRY_VERSION,
        package_schemas: vec![PACKAGE_SCHEMA],
        max_blob_bytes: state.config.max_blob_bytes,
        public_read: state.config.public_read,
        admission_engine: state.admission.name().to_owned(),
        features: vec![
            "component-model",
            "wit-analysis",
            "dependency-graph",
            "user-accounts",
            "multi-page-ui",
            "namespace-ownership",
            "yanking",
        ],
        component_analysis_max_bytes: MAX_ANALYSIS_BYTES,
    }))
}

async fn stats(State(state): State<AppState>, headers: HeaderMap) -> Result<impl IntoResponse> {
    require_read(&state, &headers).await?;
    Ok(Json(state.db.stats().await?))
}

async fn create_namespace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateNamespace>,
) -> Result<impl IntoResponse> {
    validate_name("namespace", &request.name)?;
    if request.description.len() > 4096 {
        return Err(ApiError::bad_request(
            "description_too_long",
            "description exceeds 4096 bytes",
        ));
    }
    let principal = authenticate(&state, &headers, true).await?;
    principal.require("namespace:create", Some(&request.name))?;
    Ok((
        StatusCode::CREATED,
        Json(
            state
                .db
                .create_namespace_owned(
                    &request.name,
                    &request.description,
                    principal.username.as_deref(),
                )
                .await?,
        ),
    ))
}

async fn get_namespace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
) -> Result<impl IntoResponse> {
    require_read(&state, &headers).await?;
    validate_name("namespace", &namespace)?;
    Ok(Json(state.db.namespace(&namespace).await?))
}

async fn create_api_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateToken>,
) -> Result<impl IntoResponse> {
    let principal = authenticate(&state, &headers, true).await?;
    principal.require("admin", None)?;
    Ok((
        StatusCode::CREATED,
        Json(create_token(&state.db, &request).await?),
    ))
}

async fn revoke_api_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    let principal = authenticate(&state, &headers, true).await?;
    principal.require("admin", None)?;
    state.db.revoke_token(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn put_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(digest): Path<String>,
    body: Body,
) -> Result<impl IntoResponse> {
    validate_digest(&digest)?;
    let principal = authenticate(&state, &headers, true).await?;
    principal.require("package:publish", None)?;
    if let Some(length) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        if length > state.config.max_blob_bytes {
            return Err(ApiError::too_large(
                "Content-Length exceeds maximum blob size",
            ));
        }
    }
    let media_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    if media_type.len() > 255 {
        return Err(ApiError::bad_request(
            "invalid_media_type",
            "Content-Type is too long",
        ));
    }
    let stored = state.blobs.put(&digest, body).await?;
    let metadata = state.db.put_blob(&digest, stored.size, &media_type).await?;
    if stored.size <= MAX_ANALYSIS_BYTES && state.db.component_analysis(&digest).await?.is_none() {
        let bytes = tokio::fs::read(state.blobs.path(&digest)?).await?;
        let analysis_digest = digest.clone();
        match tokio::task::spawn_blocking(move || analyze(&analysis_digest, &bytes)).await {
            Ok(Ok(analysis)) => state.db.put_component_analysis(&analysis).await?,
            Ok(Err(error)) => {
                tracing::debug!(%digest, %error, "blob does not contain decodable component WIT");
            }
            Err(error) => tracing::warn!(%digest, %error, "component analysis task failed"),
        }
    }
    let status = if stored.existed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((
        status,
        [(header::ETAG, format!("\"{digest}\""))],
        Json(metadata),
    ))
}

async fn get_component_analysis(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(digest): Path<String>,
) -> Result<impl IntoResponse> {
    require_read(&state, &headers).await?;
    validate_digest(&digest)?;
    let analysis = state
        .db
        .component_analysis(&digest)
        .await?
        .ok_or_else(|| ApiError::not_found("component metadata not found"))?;
    Ok(Json(analysis))
}

async fn get_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: Method,
    Path(digest): Path<String>,
) -> Result<Response> {
    require_read(&state, &headers).await?;
    validate_digest(&digest)?;
    let metadata = state
        .db
        .blob(&digest)
        .await?
        .ok_or_else(|| ApiError::not_found("blob not found"))?;
    let etag = format!("\"{digest}\"");
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        == Some(etag.as_str())
    {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(header::ETAG, etag)
            .body(Body::empty())
            .map_err(|_| ApiError::internal("response construction failed"));
    }
    let path = state.blobs.path(&digest)?;
    let file = tokio::fs::File::open(path).await.map_err(|error| {
        tracing::error!(%error, %digest, "blob metadata exists but file is missing");
        ApiError::internal("blob storage is inconsistent")
    })?;
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from_stream(ReaderStream::new(file))
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, metadata.media_type)
        .header(header::CONTENT_LENGTH, metadata.size)
        .header(header::ETAG, etag)
        .header(header::CONTENT_DISPOSITION, "attachment")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(
            header::CONTENT_SECURITY_POLICY,
            "sandbox; default-src 'none'",
        )
        .header(
            header::CACHE_CONTROL,
            if state.config.public_read {
                "public, max-age=31536000, immutable"
            } else {
                "private, no-store"
            },
        )
        .body(body)
        .map_err(|_| ApiError::internal("response construction failed"))
}

#[derive(Serialize)]
struct Published {
    manifest: PackageManifest,
    record: crate::domain::VersionRecord,
}

async fn publish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((namespace, package)): Path<(String, String)>,
    Json(manifest): Json<PackageManifest>,
) -> Result<impl IntoResponse> {
    validate_name("namespace", &namespace)?;
    validate_name("package", &package)?;
    if manifest.namespace != namespace || manifest.name != package {
        return Err(ApiError::bad_request(
            "path_manifest_mismatch",
            "path namespace/package differs from manifest",
        ));
    }
    let principal = authenticate(&state, &headers, true).await?;
    principal.require("package:publish", Some(&namespace))?;
    if let Some(username) = &principal.username {
        state.db.require_owner(&namespace, username).await?;
    }
    state.db.namespace(&namespace).await?;
    state.admission.validate(&manifest).await?;
    let record = state
        .db
        .publish(&manifest, principal.token_id.as_deref())
        .await?;
    Ok((
        StatusCode::CREATED,
        [(header::ETAG, format!("\"{}\"", record.manifest_digest))],
        Json(Published { manifest, record }),
    ))
}

#[derive(Serialize)]
struct ManifestResponse {
    manifest: PackageManifest,
    record: crate::domain::VersionRecord,
}

async fn get_manifest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((namespace, package, version)): Path<(String, String, String)>,
) -> Result<impl IntoResponse> {
    require_read(&state, &headers).await?;
    validate_coordinates(&namespace, &package, Some(&version))?;
    let (manifest, record) = state.db.manifest(&namespace, &package, &version).await?;
    Ok((
        [(header::ETAG, format!("\"{}\"", record.manifest_digest))],
        Json(ManifestResponse { manifest, record }),
    ))
}

async fn get_package(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((namespace, package)): Path<(String, String)>,
) -> Result<impl IntoResponse> {
    require_read(&state, &headers).await?;
    validate_coordinates(&namespace, &package, None)?;
    let mut record = state.db.package(&namespace, &package).await?;
    record.versions.sort_by(|left, right| {
        Version::parse(&right.version)
            .ok()
            .cmp(&Version::parse(&left.version).ok())
    });
    Ok(Json(record))
}

#[derive(Deserialize)]
struct ResolveQuery {
    #[serde(default = "default_requirement")]
    requirement: String,
}
fn default_requirement() -> String {
    "*".to_owned()
}

async fn resolve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((namespace, package)): Path<(String, String)>,
    Query(query): Query<ResolveQuery>,
) -> Result<impl IntoResponse> {
    require_read(&state, &headers).await?;
    validate_coordinates(&namespace, &package, None)?;
    let (manifest, record) = state
        .db
        .resolve(&namespace, &package, &query.requirement)
        .await?;
    Ok((
        [(header::ETAG, format!("\"{}\"", record.manifest_digest))],
        Json(ManifestResponse { manifest, record }),
    ))
}

async fn yank(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((namespace, package, version)): Path<(String, String, String)>,
) -> Result<impl IntoResponse> {
    set_yanked(state, headers, namespace, package, version, true).await
}

async fn unyank(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((namespace, package, version)): Path<(String, String, String)>,
) -> Result<impl IntoResponse> {
    set_yanked(state, headers, namespace, package, version, false).await
}

async fn set_yanked(
    state: AppState,
    headers: HeaderMap,
    namespace: String,
    package: String,
    version: String,
    value: bool,
) -> Result<impl IntoResponse> {
    validate_coordinates(&namespace, &package, Some(&version))?;
    let principal = authenticate(&state, &headers, true).await?;
    principal.require("package:yank", Some(&namespace))?;
    if let Some(username) = &principal.username {
        state.db.require_owner(&namespace, username).await?;
    }
    state
        .db
        .set_yanked(&namespace, &package, &version, value)
        .await?;
    Ok(Json(json!({"yanked":value})))
}

#[derive(Deserialize)]
struct SearchQuery {
    #[serde(default)]
    q: String,
    #[serde(default = "default_limit")]
    limit: u32,
    #[serde(default)]
    offset: u32,
}
const fn default_limit() -> u32 {
    20
}

async fn search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> Result<impl IntoResponse> {
    require_read(&state, &headers).await?;
    if query.q.len() > 200 {
        return Err(ApiError::bad_request(
            "query_too_long",
            "search query exceeds 200 bytes",
        ));
    }
    if query.limit == 0 || query.limit > 100 {
        return Err(ApiError::bad_request(
            "invalid_limit",
            "limit must be 1 through 100",
        ));
    }
    Ok(Json(
        json!({"items":state.db.search(&query.q, query.limit, query.offset).await?,"limit":query.limit,"offset":query.offset}),
    ))
}

async fn require_read(state: &AppState, headers: &HeaderMap) -> Result<()> {
    if state.config.public_read {
        return Ok(());
    }
    let principal = authenticate(state, headers, false).await?;
    if principal.scopes.is_empty() {
        return Err(ApiError::forbidden("read access denied"));
    }
    Ok(())
}

fn validate_coordinates(namespace: &str, package: &str, version: Option<&str>) -> Result<()> {
    validate_name("namespace", namespace)?;
    validate_name("package", package)?;
    if let Some(version) = version {
        let parsed = Version::parse(version)
            .map_err(|e| ApiError::bad_request("invalid_version", e.to_string()))?;
        if parsed.to_string() != version {
            return Err(ApiError::bad_request(
                "noncanonical_version",
                format!("canonical version is {parsed}"),
            ));
        }
    }
    Ok(())
}

async fn not_found() -> ApiError {
    ApiError::not_found("endpoint not found")
}

fn account_store(state: &AppState) -> crate::accounts::Store {
    crate::accounts::Store::new(
        state.config.database_path.with_extension("accounts.json"),
        &state.config.public_url,
    )
}
fn account_headers(headers: &HeaderMap) -> crate::accounts::Headers {
    headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_owned(), v.to_owned()))
        })
        .collect()
}
fn account_error(error: crate::accounts::Error) -> ApiError {
    ApiError::new(
        StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        error.code,
        error.message,
    )
}
async fn authenticate(state: &AppState, headers: &HeaderMap, mutation: bool) -> Result<Principal> {
    if headers.contains_key(header::AUTHORIZATION) {
        if let Ok(principal) =
            authenticate_bearer(headers, &state.db, state.config.admin_token.as_deref()).await
        {
            return Ok(principal);
        }
    }
    let store = account_store(state);
    let headers = account_headers(headers);
    let identity = tokio::task::spawn_blocking(move || store.identify(&headers, mutation))
        .await
        .map_err(|_| ApiError::internal("Authentication task failed"))?
        .map_err(account_error)?;
    Ok(Principal {
        username: Some(identity.username),
        token_id: None,
        namespace: None,
        scopes: ["namespace:create", "package:publish", "package:yank"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    })
}
async fn account_endpoint(
    State(state): State<AppState>,
    method: Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response> {
    let store = account_store(&state);
    let headers = account_headers(&headers);
    let reply = tokio::task::spawn_blocking(move || {
        store.handle(method.as_str(), uri.path(), &headers, &body)
    })
    .await
    .map_err(|_| ApiError::internal("Account task failed"))?
    .map_err(account_error)?;
    let mut response = (
        StatusCode::from_u16(reply.status).unwrap_or(StatusCode::OK),
        Json(reply.body),
    )
        .into_response();
    for (key, value) in reply.headers {
        response.headers_mut().insert(
            axum::http::HeaderName::try_from(key)
                .map_err(|_| ApiError::internal("Invalid response header"))?,
            axum::http::HeaderValue::try_from(value)
                .map_err(|_| ApiError::internal("Invalid response header"))?,
        );
    }
    Ok(response)
}
