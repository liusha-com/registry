//! Stable HTTP API error model.

use std::collections::BTreeMap;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::Value;

/// Registry result type.
pub type Result<T> = std::result::Result<T, ApiError>;

/// A stable API failure.
#[derive(Debug, thiserror::Error)]
#[error("{code}: {message}")]
pub struct ApiError {
    /// HTTP status.
    pub status: StatusCode,
    /// Stable machine code.
    pub code: &'static str,
    /// Human-readable message.
    pub message: String,
    /// Structured details.
    pub details: BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
    details: BTreeMap<String, Value>,
    request_id: String,
}

impl ApiError {
    /// Construct a bad request.
    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }
    /// Construct an unauthorized response.
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }
    /// Construct a forbidden response.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }
    /// Construct a missing-resource response.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }
    /// Construct a conflict response.
    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }
    /// Construct a payload-too-large response.
    pub fn too_large(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "limit_exceeded", message)
    }
    /// Construct an internal response without leaking internals.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
    }
    /// Construct an error.
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            details: BTreeMap::new(),
        }
    }
    /// Add a structured detail.
    #[must_use]
    pub fn detail(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut random = [0_u8; 12];
        let _ = getrandom::fill(&mut random);
        let request_id = hex::encode(random);
        tracing::warn!(%request_id, code = self.code, status = %self.status, message = %self.message, "request failed");
        let body = ErrorEnvelope {
            error: ErrorBody {
                code: self.code,
                message: self.message,
                details: self.details,
                request_id,
            },
        };
        (
            self.status,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(body),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "database operation failed");
        Self::internal("database operation failed")
    }
}

impl From<std::io::Error> for ApiError {
    fn from(error: std::io::Error) -> Self {
        tracing::error!(%error, "storage operation failed");
        Self::internal("storage operation failed")
    }
}
