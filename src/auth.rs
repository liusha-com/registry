//! Bearer-token authentication and authorization.

use std::collections::BTreeSet;

use axum::http::{HeaderMap, header::AUTHORIZATION};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::{
    db::Database,
    domain::{CreateToken, CreatedToken, validate_name},
    error::{ApiError, Result},
};

/// Authenticated caller.
#[derive(Clone, Debug)]
pub struct Principal {
    /// Account owner, absent for administrator and legacy scoped credentials.
    pub username: Option<String>,
    /// Persistent token ID, absent for bootstrap admin.
    pub token_id: Option<String>,
    /// Granted scopes.
    pub scopes: BTreeSet<String>,
    /// Optional namespace restriction.
    pub namespace: Option<String>,
}

impl Principal {
    /// Require scope and namespace compatibility.
    pub fn require(&self, scope: &str, namespace: Option<&str>) -> Result<()> {
        if !self.scopes.contains("admin") && !self.scopes.contains(scope) {
            return Err(ApiError::forbidden(format!("scope {scope} is required")));
        }
        if let (Some(restricted), Some(requested)) = (&self.namespace, namespace) {
            if restricted != requested {
                return Err(ApiError::forbidden(
                    "token is restricted to another namespace",
                ));
            }
        }
        Ok(())
    }
}

/// Authenticate a bearer token from headers.
pub async fn authenticate(
    headers: &HeaderMap,
    db: &Database,
    bootstrap_admin: Option<&str>,
) -> Result<Principal> {
    let header = headers
        .get(AUTHORIZATION)
        .ok_or_else(|| ApiError::unauthorized("bearer token required"))?
        .to_str()
        .map_err(|_| ApiError::unauthorized("authorization header is invalid"))?;
    let token = header
        .strip_prefix("Bearer ")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::unauthorized("expected Authorization: Bearer <token>"))?;
    let hash = Sha256::digest(token.as_bytes());
    if let Some(admin) = bootstrap_admin {
        let admin_hash = Sha256::digest(admin.as_bytes());
        if hash.as_slice().ct_eq(admin_hash.as_slice()).into() {
            return Ok(Principal {
                username: None,
                token_id: None,
                scopes: BTreeSet::from(["admin".to_owned()]),
                namespace: None,
            });
        }
    }
    let row = db
        .token_by_hash(hash.as_slice())
        .await?
        .ok_or_else(|| ApiError::unauthorized("token is invalid or revoked"))?;
    let scopes: Vec<String> = serde_json::from_str(&row.scopes_json)
        .map_err(|_| ApiError::internal("stored token scopes are invalid"))?;
    Ok(Principal {
        username: None,
        token_id: Some(row.id),
        scopes: scopes.into_iter().collect(),
        namespace: row.namespace,
    })
}

/// Create and persist a new token.
pub async fn create_token(db: &Database, request: &CreateToken) -> Result<CreatedToken> {
    if request.name.trim().is_empty() || request.name.len() > 128 {
        return Err(ApiError::bad_request(
            "invalid_token_name",
            "token name is empty or too long",
        ));
    }
    if request.scopes.is_empty() {
        return Err(ApiError::bad_request(
            "scope_required",
            "at least one scope is required",
        ));
    }
    let allowed = [
        "admin",
        "namespace:create",
        "package:publish",
        "package:yank",
    ];
    let scopes: BTreeSet<_> = request.scopes.iter().cloned().collect();
    if let Some(scope) = scopes
        .iter()
        .find(|scope| !allowed.contains(&scope.as_str()))
    {
        return Err(ApiError::bad_request(
            "invalid_scope",
            format!("unknown scope {scope}"),
        ));
    }
    if scopes.contains("admin") && request.namespace.is_some() {
        return Err(ApiError::bad_request(
            "invalid_scope",
            "admin tokens cannot be namespace restricted",
        ));
    }
    if let Some(namespace) = &request.namespace {
        validate_name("namespace", namespace)?;
        db.namespace(namespace).await?;
    }
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret)
        .map_err(|_| ApiError::internal("secure random generation failed"))?;
    let token = format!("wrt_{}", URL_SAFE_NO_PAD.encode(secret));
    let mut id_bytes = [0_u8; 12];
    getrandom::fill(&mut id_bytes)
        .map_err(|_| ApiError::internal("secure random generation failed"))?;
    let id = format!("tok_{}", URL_SAFE_NO_PAD.encode(id_bytes));
    let hash = Sha256::digest(token.as_bytes());
    let scopes_vec: Vec<_> = scopes.into_iter().collect();
    let scopes_json = serde_json::to_string(&scopes_vec)
        .map_err(|_| ApiError::internal("scope serialization failed"))?;
    db.create_token(
        &id,
        &request.name,
        hash.as_slice(),
        &scopes_json,
        request.namespace.as_deref(),
    )
    .await?;
    Ok(CreatedToken { id, token })
}
