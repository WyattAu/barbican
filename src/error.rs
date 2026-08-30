use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Errors that can occur during authentication or authorization.
#[derive(Debug, thiserror::Error)]
pub enum AuthRejection {
    /// No credentials were provided.
    #[error("missing credentials")]
    MissingCredentials,

    /// The provided token is invalid.
    #[error("invalid token")]
    InvalidToken,

    /// The token has expired.
    #[error("token expired")]
    TokenExpired,

    /// The token has been revoked.
    #[error("token revoked")]
    TokenRevoked,

    /// The authenticated principal lacks required permissions.
    #[error("insufficient permissions")]
    InsufficientPermissions,

    /// The provided API key is invalid.
    #[error("invalid API key")]
    InvalidApiKey,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::MissingCredentials => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::InvalidToken => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::TokenExpired => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::TokenRevoked => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::InsufficientPermissions => (StatusCode::FORBIDDEN, self.to_string()),
            Self::InvalidApiKey => (StatusCode::UNAUTHORIZED, self.to_string()),
        };

        let body = axum::Json(json!({ "error": message }));
        (status, body).into_response()
    }
}
