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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[test]
    fn missing_credentials_status_401() {
        let resp = AuthRejection::MissingCredentials.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn invalid_token_status_401() {
        let resp = AuthRejection::InvalidToken("bad-jwt".into()).into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn insufficient_permissions_status_403() {
        let resp = AuthRejection::InsufficientPermissions("write".into()).into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn display_messages_contain_expected_text() {
        let msg = AuthRejection::MissingCredentials.to_string();
        assert!(msg.contains("Missing"), "got: {msg}");

        let msg = AuthRejection::InvalidToken("x".into()).to_string();
        assert!(msg.contains("Invalid"), "got: {msg}");

        let msg = AuthRejection::InsufficientPermissions("admin".into()).to_string();
        assert!(msg.contains("Insufficient"), "got: {msg}");

        let msg = AuthRejection::TokenExpired.to_string();
        assert!(msg.contains("expired"), "got: {msg}");

        let msg = AuthRejection::TokenRevoked.to_string();
        assert!(msg.contains("revoked"), "got: {msg}");
    }

    #[test]
    fn public_paths() {
        let prefixes = &["/health", "/api/docs"];
        assert!(is_public_path("/health", prefixes));
        assert!(is_public_path("/api/docs", prefixes));
        assert!(is_public_path("/api/docs/something", prefixes));
    }

    #[test]
    fn non_public_paths() {
        let prefixes = &["/health", "/api/docs"];
        assert!(!is_public_path("/api/users", prefixes));
        assert!(!is_public_path("/protected", prefixes));
        assert!(!is_public_path("/", prefixes));
    }
}

#[cfg(test)]
mod proptest_tests {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use proptest::prelude::*;

    fn arb_auth_rejection() -> impl Strategy<Value = super::error::AuthRejection> {
        prop_oneof![(0u8..5u8).prop_map(|v| match v {
            0 => super::error::AuthRejection::MissingCredentials,
            1 => super::error::AuthRejection::TokenExpired,
            2 => super::error::AuthRejection::TokenRevoked,
            3 => super::error::AuthRejection::InvalidToken("test".into()),
            _ => super::error::AuthRejection::InsufficientPermissions("test".into()),
        }),]
    }

    proptest! {
        #[test]
        fn bearer_token_extraction(token in "[a-zA-Z0-9._-]{1,200}") {
            let header_value = format!("Bearer {}", token);
            let result = tokenkit::extractors::extract_bearer_token(&header_value);
            prop_assert_eq!(result, Some(token));
        }

        #[test]
        fn is_public_path(public_prefix in "/[a-z]{1,10}", suffix in "[a-z/]{0,20}") {
            let full_path = format!("{}{}", public_prefix, suffix);
            prop_assert!(super::path::is_public_path(&full_path, &[&public_prefix]));
        }

        #[test]
        fn auth_rejection_status_codes(variant in arb_auth_rejection()) {
            let resp = variant.into_response();
            match resp.status() {
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {}
                other => prop_assert!(false, "unexpected status: {}", other),
            }
        }
    }
}
