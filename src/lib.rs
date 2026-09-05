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
        // exact
        assert!(is_public_path("/health", prefixes));
        assert!(is_public_path("/api/docs", prefixes));
        // trailing slash — subtree of the entry
        assert!(is_public_path("/health/", prefixes));
        assert!(is_public_path("/api/docs/", prefixes));
        // subtree
        assert!(is_public_path("/health/detail", prefixes));
        assert!(is_public_path("/api/docs/something", prefixes));
    }

    #[test]
    fn non_public_paths() {
        let prefixes = &["/health", "/api/docs"];
        assert!(!is_public_path("/api/users", prefixes));
        assert!(!is_public_path("/protected", prefixes));
        assert!(!is_public_path("/", prefixes));
    }

    #[test]
    fn req_barbican_100_text_prefix_sharing_is_not_public() {
        // The bypass class OPEN-1 was closed for: routes that merely START
        // with a public prefix must NOT be classified public.
        let prefixes = &["/health", "/api/docs"];
        assert!(!is_public_path("/healthcheck", prefixes));
        assert!(!is_public_path("/healthz-admin", prefixes));
        assert!(!is_public_path("/healthcheck/deep", prefixes));
        assert!(!is_public_path("/api/docsx", prefixes));
        assert!(!is_public_path("/api/docs-v2/item", prefixes));
    }

    #[test]
    fn req_barbican_100_input_is_path_component_query_not_split() {
        // Contract: `is_public_path` receives the path component only
        // (axum's `Uri::path()` never carries a query). The function does
        // not split queries, so a caller passing one gets no match —
        // fail-closed. Pinned so the contract can't silently change.
        let prefixes = &["/health"];
        assert!(!is_public_path("/health?x=1", prefixes));
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
        fn is_public_path_exact_and_subtree(public_prefix in "/[a-z]{1,10}", sub in "[a-z/]{0,19}") {
            let prefixes = &[public_prefix.as_str()];
            // exact match is public
            prop_assert!(super::path::is_public_path(public_prefix.as_str(), prefixes));
            // subtree (prefix + segment boundary) is public
            let subtree = format!("{public_prefix}/{sub}");
            prop_assert!(super::path::is_public_path(&subtree, prefixes));
        }

        #[test]
        fn is_public_path_no_text_prefix_over_match(
            public_prefix in "/[a-z]{1,10}",
            tail in "[a-z]{1,10}",
        ) {
            // REQ-BARBICAN-100: a path sharing a text prefix with a public
            // entry (no '/' at the boundary) must NOT be public.
            let impostor = format!("{public_prefix}{tail}");
            prop_assert!(!super::path::is_public_path(&impostor, &[&public_prefix]));
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
