//! Account, cookie, CSRF, ownership and revocation integration coverage.
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt;
use wasmd_registry::{AppState, Config, build_router};

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    value: Value,
    cookie: Option<&str>,
    csrf: Option<&str>,
    bearer: Option<&str>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("origin", "http://127.0.0.1:8080");
    if let Some(v) = cookie {
        request = request.header("cookie", v);
    }
    if let Some(v) = csrf {
        request = request.header("x-csrf-token", v);
    }
    if let Some(v) = bearer {
        request = request.header("authorization", format!("Bearer {v}"));
    }
    app.clone()
        .oneshot(request.body(Body::from(value.to_string())).unwrap())
        .await
        .unwrap()
}
async fn body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap()
}
async fn register(app: &Router, name: &str) -> (String, String) {
    let response = call(
        app,
        "POST",
        "/v1/auth/register",
        json!({"username":name,"password":"a sufficiently long test passphrase"}),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
    let cookie = cookie.split(';').next().unwrap().to_owned();
    let data = body(response).await;
    assert!(data.get("password").is_none() && data.get("token").is_none());
    (cookie, data["csrf_token"].as_str().unwrap().into())
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn accounts_survive_restart_and_enforce_ownership_csrf_and_revocation() {
    let temp = tempfile::tempdir().unwrap();
    let config = Config {
        database_path: temp.path().join("registry.db"),
        blob_dir: temp.path().join("blobs"),
        temp_dir: temp.path().join("tmp"),
        ..Config::default()
    };
    let app = build_router(AppState::new(config.clone()).await.unwrap());
    let (cookie, csrf) = register(&app, "alice").await;
    let (other, other_csrf) = register(&app, "bob").await;
    let namespace = json!({"name":"alice-tools","description":"Owned by Alice"});
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/namespaces",
            namespace.clone(),
            Some(&cookie),
            None,
            None
        )
        .await
        .status(),
        403
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/namespaces",
            namespace,
            Some(&cookie),
            Some(&csrf),
            None
        )
        .await
        .status(),
        201
    );
    let manifest = json!({"schema":"wasmd.package/v0","namespace":"alice-tools","name":"demo","version":"1.0.0","artifacts":[]});
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/packages/alice-tools/demo/versions",
            manifest,
            Some(&other),
            Some(&other_csrf),
            None
        )
        .await
        .status(),
        403
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/admin/tokens",
            json!({"name":"escalation","scopes":["admin"]}),
            Some(&cookie),
            Some(&csrf),
            None
        )
        .await
        .status(),
        403
    );
    let response = call(
        &app,
        "POST",
        "/v1/account/tokens",
        json!({"name":"Development"}),
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(response.status(), 201);
    let token = body(response).await;
    let secret = token["token"].as_str().unwrap();
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/auth/check",
            json!({}),
            None,
            None,
            Some(secret)
        )
        .await
        .status(),
        200
    );
    let disk = std::fs::read_to_string(temp.path().join("registry.accounts.json")).unwrap();
    assert!(!disk.contains(secret) && !disk.contains("a sufficiently long test passphrase"));
    assert!(disk.contains("$argon2id$v=19$m=19456,t=2,p=1$"));
    let app = build_router(AppState::new(config).await.unwrap());
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/auth/me",
            json!({}),
            Some(&cookie),
            None,
            None
        )
        .await
        .status(),
        200
    );
    let tokens = body(
        call(
            &app,
            "GET",
            "/v1/account/tokens",
            json!({}),
            Some(&cookie),
            None,
            None,
        )
        .await,
    )
    .await;
    assert!(tokens["tokens"][0].get("token").is_none());
    let revoke = format!("/v1/account/tokens/{}", token["id"].as_str().unwrap());
    assert_eq!(
        call(
            &app,
            "DELETE",
            &revoke,
            json!({}),
            Some(&other),
            Some(&other_csrf),
            None
        )
        .await
        .status(),
        404
    );
    assert_eq!(
        call(
            &app,
            "DELETE",
            &revoke,
            json!({}),
            Some(&cookie),
            Some(&csrf),
            None
        )
        .await
        .status(),
        200
    );
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/auth/check",
            json!({}),
            None,
            None,
            Some(secret)
        )
        .await
        .status(),
        401
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/auth/logout",
            json!({}),
            Some(&cookie),
            Some(&csrf),
            None
        )
        .await
        .status(),
        200
    );
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/auth/me",
            json!({}),
            Some(&cookie),
            None,
            None
        )
        .await
        .status(),
        401
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/auth/login",
            json!({"username":"alice","password":"the wrong test password"}),
            None,
            None,
            None
        )
        .await
        .status(),
        401
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/auth/login",
            json!({"username":"alice","password":"a sufficiently long test passphrase"}),
            None,
            None,
            None
        )
        .await
        .status(),
        200
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/auth/register",
            json!({"username":"alice","password":"a sufficiently long test passphrase"}),
            None,
            None,
            None
        )
        .await
        .status(),
        409
    );
}

#[tokio::test]
async fn independent_pages_and_cross_origin_registration() {
    let temp = tempfile::tempdir().unwrap();
    let app = build_router(
        AppState::new(Config {
            database_path: temp.path().join("registry.db"),
            blob_dir: temp.path().join("blobs"),
            temp_dir: temp.path().join("tmp"),
            ..Config::default()
        })
        .await
        .unwrap(),
    );
    for (path, marker) in [
        ("/", "home"),
        ("/explore", "explore"),
        ("/login", "login"),
        ("/register", "register"),
        ("/account", "account"),
        ("/publish", "publish"),
        ("/docs", "docs"),
        ("/packages/acme/hello", "package"),
        ("/packages/acme/hello/1.0.0", "release"),
    ] {
        let response = call(&app, "GET", path, json!({}), None, None, None).await;
        assert_eq!(response.status(), 200);
        assert!(response.headers().contains_key("content-security-policy"));
        let html = String::from_utf8(
            to_bytes(response.into_body(), 100_000)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(html.contains(&format!("data-page=\"{marker}\"")));
        assert!(!html.contains("href=\"#/"));
        assert!(!html.contains("{{body}}"));
    }
    let request = Request::builder()
        .method("POST")
        .uri("/v1/auth/register")
        .header("content-type", "application/json")
        .header("origin", "https://attacker.invalid")
        .body(Body::from(
            json!({"username":"alice","password":"a sufficiently long test passphrase"})
                .to_string(),
        ))
        .unwrap();
    assert_eq!(app.oneshot(request).await.unwrap().status(), 403);
}

#[tokio::test]
async fn private_reads_use_cookies_without_csrf_but_writes_still_require_it() {
    let temp = tempfile::tempdir().unwrap();
    let app = build_router(
        AppState::new(Config {
            database_path: temp.path().join("registry.db"),
            blob_dir: temp.path().join("blobs"),
            temp_dir: temp.path().join("tmp"),
            public_read: false,
            ..Config::default()
        })
        .await
        .unwrap(),
    );
    let (cookie, _) = register(&app, "reader").await;
    assert_eq!(
        call(&app, "GET", "/v1/stats", json!({}), None, None, None)
            .await
            .status(),
        401
    );
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/stats",
            json!({}),
            Some(&cookie),
            None,
            None
        )
        .await
        .status(),
        200
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/namespaces",
            json!({"name":"private-tools"}),
            Some(&cookie),
            None,
            None
        )
        .await
        .status(),
        403
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn authentication_limits_expiration_and_storage_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let config = Config {
        database_path: temp.path().join("registry.db"),
        blob_dir: temp.path().join("blobs"),
        temp_dir: temp.path().join("tmp"),
        ..Config::default()
    };
    let app = build_router(AppState::new(config.clone()).await.unwrap());
    // Four multibyte characters are not a twelve-character passphrase.
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/auth/register",
            json!({"username":"short","password":"密码太短"}),
            None,
            None,
            None
        )
        .await
        .status(),
        400
    );
    let (cookie, csrf) = register(&app, "alice").await;
    let malformed = Request::builder()
        .method("POST")
        .uri("/v1/account/tokens")
        .header("content-type", "application/json")
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .body(Body::from("{"))
        .unwrap();
    let response = app.clone().oneshot(malformed).await.unwrap();
    assert_eq!(response.status(), 400);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let bearer = cookie.strip_prefix("registry_session=").unwrap();
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/auth/me",
            json!({}),
            None,
            None,
            Some(bearer)
        )
        .await
        .status(),
        401
    );
    // Login attempt limits survive a reconstructed service and reject before hashing.
    for _ in 0..8 {
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/auth/login",
                json!({"username":"alice","password":"incorrect test password"}),
                None,
                None,
                None
            )
            .await
            .status(),
            401
        );
    }
    let app = build_router(AppState::new(config).await.unwrap());
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/auth/login",
            json!({"username":"alice","password":"a sufficiently long test passphrase"}),
            None,
            None,
            None
        )
        .await
        .status(),
        429
    );
    let path = temp.path().join("registry.accounts.json");
    let mut data: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    for credential in data["credentials"].as_object_mut().unwrap().values_mut() {
        credential["expires_at"] = json!(0);
    }
    std::fs::write(&path, data.to_string()).unwrap();
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/auth/me",
            json!({}),
            Some(&cookie),
            None,
            None
        )
        .await
        .status(),
        401
    );
    // A held/stale lock never lets a second writer overwrite the last snapshot.
    std::fs::create_dir(temp.path().join("registry.accounts.lock")).unwrap();
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/auth/register",
            json!({"username":"new-user","password":"a sufficiently long test passphrase"}),
            None,
            None,
            None
        )
        .await
        .status(),
        503
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), data.to_string());
    std::fs::write(&path, "corrupt snapshot").unwrap();
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/auth/me",
            json!({}),
            Some(&cookie),
            None,
            None
        )
        .await
        .status(),
        500
    );
}

#[tokio::test]
async fn uploaded_html_is_downloaded_without_same_origin_execution_or_shared_cache() {
    use sha2::{Digest, Sha256};
    let temp = tempfile::tempdir().unwrap();
    let app = build_router(
        AppState::new(Config {
            database_path: temp.path().join("registry.db"),
            blob_dir: temp.path().join("blobs"),
            temp_dir: temp.path().join("tmp"),
            public_read: false,
            ..Config::default()
        })
        .await
        .unwrap(),
    );
    let (cookie, csrf) = register(&app, "uploader").await;
    let html = "<script>fetch('/v1/auth/me')</script>";
    let path = format!(
        "/v1/blobs/sha256:{}",
        hex::encode(Sha256::digest(html.as_bytes()))
    );
    let request = Request::builder()
        .method("PUT")
        .uri(&path)
        .header("content-type", "text/html")
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .body(Body::from(html))
        .unwrap();
    assert_eq!(app.clone().oneshot(request).await.unwrap().status(), 201);
    let download = call(&app, "GET", &path, json!({}), Some(&cookie), None, None).await;
    assert_eq!(download.status(), 200);
    assert_eq!(download.headers()["content-disposition"], "attachment");
    assert_eq!(download.headers()["x-content-type-options"], "nosniff");
    assert_eq!(
        download.headers()["content-security-policy"],
        "sandbox; default-src 'none'"
    );
    assert_eq!(download.headers()["cache-control"], "private, no-store");
}
