use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Errors that can occur during authentication or authorization.
#[derive(Debug, thiserror::Error)]
pub enum AuthRejection {
    /// No credentials were provided.
    #[error("Missing or invalid Authorization header")]
    MissingCredentials,
    /// The provided token is invalid.
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    /// The token has expired.
    #[error("Token expired")]
    TokenExpired,
    /// The token has been revoked.
    #[error("Token revoked")]
    TokenRevoked,
    /// The authenticated principal lacks required permissions.
    #[error("Insufficient permissions: {0}")]
    InsufficientPermissions(String),
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::MissingCredentials => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::InvalidToken(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::TokenExpired => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::TokenRevoked => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::InsufficientPermissions(_) => (StatusCode::FORBIDDEN, self.to_string()),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
