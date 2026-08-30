#![forbid(unsafe_code)]

//! Authentication and authorization middleware for Axum.
//!
//! `barbican` provides extractors, role-based guards, and public path bypass
//! utilities for building secure Axum applications.

mod error;

#[cfg(feature = "extractors")]
pub mod extractors;
pub mod middleware;
pub mod path;

pub use error::AuthRejection;
