//! Wasmd Registry server library.

mod accounts;
mod admission;
pub mod auth;
pub mod component;
pub mod config;
pub mod db;
pub mod domain;
pub mod error;
pub mod http;
mod pages;
pub mod storage;

pub use config::Config;
pub use error::{ApiError, Result};
pub use http::{AppState, build_router, serve};
