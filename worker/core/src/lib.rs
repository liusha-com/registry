//! Pure synchronous logic shared with the native registry; no WASI imports.
#![allow(dead_code)]
use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use wasm_bindgen::prelude::*;

#[path = "../../../src/component.rs"]
mod component;
#[path = "../../../src/domain.rs"]
mod domain;
#[path = "../../../src/pages.rs"]
mod pages;

mod error {
    pub type Result<T> = std::result::Result<T, ApiError>;
    #[derive(Debug, serde::Serialize)]
    pub struct ApiError {
        pub code: &'static str,
        pub message: String,
    }
    impl ApiError {
        pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
            Self {
                code,
                message: message.into(),
            }
        }
    }
}

#[wasm_bindgen]
pub fn manifest(input: &str) -> std::result::Result<String, JsValue> {
    let value: domain::PackageManifest =
        serde_json::from_str(input).map_err(|e| JsValue::from_str(&e.to_string()))?;
    value
        .validate()
        .map_err(|e| JsValue::from_str(&format!("{}: {}", e.code, e.message)))?;
    Ok(serde_json::to_string(&value).unwrap())
}

#[wasm_bindgen]
pub fn versions(input: &str, requirement: Option<String>) -> std::result::Result<String, JsValue> {
    let values: Vec<String> =
        serde_json::from_str(input).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let req = requirement
        .map(|s| semver::VersionReq::parse(&s))
        .transpose()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mut values: Vec<_> = values
        .into_iter()
        .filter_map(|s| semver::Version::parse(&s).ok())
        .filter(|v| req.as_ref().is_none_or(|r| r.matches(v)))
        .collect();
    values.sort_by(|a, b| b.cmp(a));
    Ok(serde_json::to_string(&values.iter().map(ToString::to_string).collect::<Vec<_>>()).unwrap())
}

#[wasm_bindgen]
pub fn analyze(digest: &str, bytes: &[u8]) -> Option<String> {
    component::analyze(digest, bytes)
        .ok()
        .and_then(|v| serde_json::to_string(&v).ok())
}

fn argon() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19456, 2, 1, None).unwrap(),
    )
}

#[wasm_bindgen]
pub fn password_hash(password: &str, salt: &[u8]) -> String {
    argon()
        .hash_password(password.as_bytes(), &SaltString::encode_b64(salt).unwrap())
        .unwrap()
        .to_string()
}

#[wasm_bindgen]
pub fn password_verify(password: &str, encoded: &str) -> bool {
    PasswordHash::new(encoded)
        .is_ok_and(|h| argon().verify_password(password.as_bytes(), &h).is_ok())
}

#[wasm_bindgen]
pub fn page(path: &str) -> Option<String> {
    pages::render(path)
}

#[wasm_bindgen]
pub fn content_security_policy() -> String {
    pages::CSP.to_owned()
}
