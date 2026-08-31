#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Authentication and authorization middleware for Axum.
//!
//! `barbican` provides extractors, role-based guards, and public path bypass
//! utilities for building secure Axum applications.

mod error;
mod extractors;
mod middleware;
mod path;

pub use error::AuthRejection;
pub use extractors::{BearerToken, Claims, OptionalAuth};
pub use middleware::{auth_middleware_fn, require_permission_fn};
pub use path::{is_public_path, public_path_bypass};
