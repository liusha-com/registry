//! End-to-end HTTP API tests.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use tower::ServiceExt as _;
use wasmd_registry::{AppState, Config, build_router};

const ADMIN: &str = "test-admin-token-with-at-least-32-characters";

async fn app() -> (Router, TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let config = Config {
        database_path: directory.path().join("registry.db"),
        blob_dir: directory.path().join("blobs"),
        temp_dir: directory.path().join("tmp"),
        admin_token: Some(ADMIN.to_owned()),
        ..Config::default()
    };
    let state = AppState::new(config).await.unwrap();
    (build_router(state), directory)
}

fn request(method: &str, uri: &str, body: Body, auth: bool) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if auth {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {ADMIN}"));
    }
    builder
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .unwrap()
}

async fn json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn authentication_check_reports_effective_credentials() {
    let (app, _directory) = app().await;
    let unauthorized = app
        .clone()
        .oneshot(request("GET", "/v1/auth/check", Body::empty(), false))
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let authenticated = app
        .oneshot(request("GET", "/v1/auth/check", Body::empty(), true))
        .await
        .unwrap();
    assert_eq!(authenticated.status(), StatusCode::OK);
    let body = json(authenticated).await;
    assert_eq!(body["authenticated"], true);
    assert_eq!(body["scopes"], json!(["admin"]));
    assert!(body["namespace"].is_null());
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn publish_resolve_yank_and_exact_download() {
    let (app, _directory) = app().await;
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/namespaces",
            Body::from(r#"{"name":"demo"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let wasm = b"\0asm\x01\0\0\0";
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(wasm)));
    let upload = Request::builder()
        .method("PUT")
        .uri(format!("/v1/blobs/{digest}"))
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
        .header(header::CONTENT_TYPE, "application/wasm")
        .body(Body::from(wasm.as_slice()))
        .unwrap();
    let response = app.clone().oneshot(upload).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let manifest = json!({
        "schema":"wasmd.package/v0","namespace":"demo","name":"hello","version":"1.0.0",
        "description":"hello","artifacts":[{"name":"module","digest":digest,"size":8,"media_type":"application/wasm","kind":"core-module"}]
    });
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/packages/demo/hello/versions",
            Body::from(manifest.to_string()),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "{}",
        json(response).await
    );

    let duplicate = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/packages/demo/hello/versions",
            Body::from(manifest.to_string()),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);

    let resolved = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/packages/demo/hello/resolve?requirement=%5E1",
            Body::empty(),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(resolved.status(), StatusCode::OK);
    assert_eq!(json(resolved).await["record"]["version"], "1.0.0");

    let yanked = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/packages/demo/hello/1.0.0/yank",
            Body::empty(),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(yanked.status(), StatusCode::OK);
    let no_resolution = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/packages/demo/hello/resolve",
            Body::empty(),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(no_resolution.status(), StatusCode::NOT_FOUND);
    let exact = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/packages/demo/hello/1.0.0",
            Body::empty(),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(exact.status(), StatusCode::OK);

    let blob = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/v1/blobs/{digest}"),
            Body::empty(),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(blob.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(blob.into_body(), 100).await.unwrap().as_ref(),
        wasm
    );
}

#[tokio::test]
async fn namespace_scoped_token_cannot_cross_namespace() {
    let (app, _directory) = app().await;
    for namespace in ["alpha", "beta"] {
        let body = json!({"name":namespace}).to_string();
        assert_eq!(
            app.clone()
                .oneshot(request("POST", "/v1/namespaces", Body::from(body), true))
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
    }
    let token_request = json!({"name":"alpha publisher","scopes":["package:publish","package:yank"],"namespace":"alpha"}).to_string();
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/admin/tokens",
            Body::from(token_request),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let token = json(response).await["token"].as_str().unwrap().to_owned();
    let manifest = json!({"schema":"wasmd.package/v0","namespace":"beta","name":"denied","version":"1.0.0","artifacts":[{"name":"module","digest":format!("sha256:{}", "00".repeat(32)),"size":0,"media_type":"application/wasm","kind":"core-module"}]});
    let denied = Request::builder()
        .method("POST")
        .uri("/v1/packages/beta/denied/versions")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(manifest.to_string()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(denied).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn digest_mismatch_does_not_create_blob() {
    let (app, _directory) = app().await;
    let digest = format!("sha256:{}", "00".repeat(32));
    let upload = Request::builder()
        .method("PUT")
        .uri(format!("/v1/blobs/{digest}"))
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
        .body(Body::from("not the digest"))
        .unwrap();
    let response = app.clone().oneshot(upload).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["error"]["code"], "digest_mismatch");
    assert_eq!(
        app.clone()
            .oneshot(request(
                "GET",
                &format!("/v1/blobs/{digest}"),
                Body::empty(),
                false
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn registry_ui_and_assets_are_embedded() {
    let (app, _directory) = app().await;
    for (path, content_type) in [
        ("/", "text/html; charset=utf-8"),
        ("/assets/app.css", "text/css; charset=utf-8"),
        ("/assets/app.js", "text/javascript; charset=utf-8"),
        ("/favicon.svg", "image/svg+xml"),
    ] {
        let response = app
            .clone()
            .oneshot(request("GET", path, Body::empty(), false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            content_type,
            "{path}"
        );
        assert!(
            !to_bytes(response.into_body(), 256 * 1024)
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn registry_stats_are_public_and_data_backed() {
    let (app, _directory) = app().await;
    let response = app
        .oneshot(request("GET", "/v1/stats", Body::empty(), false))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let stats = json(response).await;
    assert_eq!(stats["packages"], 0);
    assert_eq!(stats["versions"], 0);
    assert_eq!(stats["components"], 0);
}

#[tokio::test]
async fn component_upload_extracts_wit_and_dependency_graph() {
    let (app, _directory) = app().await;
    let component = wat::parse_str(
        r#"(component
            (type $greeting (func (param "name" string) (result string)))
            (import "host-greet" (func $host-greet (type $greeting)))
            (export "run" (func $host-greet))
        )"#,
    )
    .unwrap();
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&component)));
    let upload = Request::builder()
        .method("PUT")
        .uri(format!("/v1/blobs/{digest}"))
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
        .header(header::CONTENT_TYPE, "application/wasm")
        .body(Body::from(component))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(upload).await.unwrap().status(),
        StatusCode::CREATED
    );

    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/v1/blobs/{digest}/component"),
            Body::empty(),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let analysis = json(response).await;
    assert_eq!(analysis["kind"], "component");
    assert_eq!(analysis["imports"][0]["name"], "host-greet");
    assert_eq!(analysis["exports"][0]["name"], "run");
    assert_eq!(analysis["edges"].as_array().unwrap().len(), 2);
    assert!(analysis["wit"].as_str().unwrap().contains("world"));
}
