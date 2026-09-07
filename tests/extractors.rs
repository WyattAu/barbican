//! Integration tests for `BearerToken`, `Claims`, and `OptionalAuth` extractors.
//!
//! Each test drives the extractor through `axum::extract::FromRequestParts`
//! with a real `Arc<JwtService>` in state and asserts on the extracted
//! value or the exact `AuthRejection` variant returned.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{FromRef, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};

use barbican::{AuthRejection, BearerToken, Claims, OptionalAuth};
use tokenkit::service::{JwtConfig, JwtService};

/// Custom claims payload carried by test tokens. `iss` and `exp` are
/// required spec claims in tokenkit's decode validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TestClaims {
    sub: String,
    iss: String,
    exp: i64,
}

fn service() -> Arc<JwtService> {
    let config = JwtConfig {
        secret: "barbican-integration-test-secret".to_string(),
        ..JwtConfig::default()
    };
    Arc::new(JwtService::new(config))
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn valid_token(service: &JwtService) -> String {
    let claims = TestClaims {
        sub: "user-1".to_string(),
        iss: "barbican-test".to_string(),
        exp: now_epoch() + 3600,
    };
    service.encode(&claims).unwrap_or_default()
}

fn expired_token(service: &JwtService) -> String {
    let claims = TestClaims {
        sub: "user-1".to_string(),
        iss: "barbican-test".to_string(),
        exp: now_epoch() - 100,
    };
    service.encode(&claims).unwrap_or_default()
}

fn parts_with_bearer(token: Option<&str>) -> Parts {
    let mut builder = http::Request::builder().uri("/protected");
    if let Some(tok) = token {
        builder = builder.header(AUTHORIZATION, format!("Bearer {tok}"));
    }
    let built = builder.body(());
    assert!(
        built.is_ok(),
        "request build failed: {:?}",
        built.as_ref().err()
    );
    match built {
        Ok(req) => req.into_parts().0,
        Err(_) => unreachable!("checked above"),
    }
}

fn parts_with_raw_auth_header(value: &str) -> Parts {
    let built = http::Request::builder()
        .uri("/protected")
        .header(AUTHORIZATION, value)
        .body(());
    assert!(
        built.is_ok(),
        "request build failed: {:?}",
        built.as_ref().err()
    );
    match built {
        Ok(req) => req.into_parts().0,
        Err(_) => unreachable!("checked above"),
    }
}

fn expect_missing_credentials<T>(result: Result<T, AuthRejection>) {
    match result {
        Err(AuthRejection::MissingCredentials) => {}
        Err(other) => unreachable!("expected MissingCredentials, got: {other:?}"),
        Ok(_) => unreachable!("expected MissingCredentials, got Ok(_)"),
    }
}

fn expect_invalid_token<T>(result: Result<T, AuthRejection>) {
    match result {
        Err(AuthRejection::InvalidToken(msg)) => {
            assert!(!msg.is_empty(), "rejection message empty")
        }
        Err(other) => unreachable!("expected InvalidToken, got: {other:?}"),
        Ok(_) => unreachable!("expected InvalidToken, got Ok(_)"),
    }
}

#[tokio::test]
async fn bearer_token_extractor_returns_raw_token() {
    let state = service();
    let token = valid_token(&state);
    let mut parts = parts_with_bearer(Some(&token));
    let extracted = BearerToken::from_request_parts(&mut parts, &state).await;
    match extracted {
        Ok(BearerToken(actual)) => assert_eq!(actual, token),
        Err(rej) => unreachable!("expected token, got rejection: {rej}"),
    }
}

#[tokio::test]
async fn bearer_token_missing_header_rejects_with_missing_credentials() {
    let state = service();
    let mut parts = parts_with_bearer(None);
    let result = BearerToken::from_request_parts(&mut parts, &state).await;
    expect_missing_credentials(result);
}

#[tokio::test]
async fn bearer_token_non_bearer_scheme_rejects_with_missing_credentials() {
    let state = service();
    let mut parts = parts_with_raw_auth_header("Basic dXNlcjpwYXNz");
    let result = BearerToken::from_request_parts(&mut parts, &state).await;
    expect_missing_credentials(result);
}

#[tokio::test]
async fn claims_extractor_decodes_valid_token() {
    let state = service();
    let token = valid_token(&state);
    let mut parts = parts_with_bearer(Some(&token));
    let extracted = Claims::<TestClaims>::from_request_parts(&mut parts, &state).await;
    match extracted {
        Ok(Claims(claims)) => {
            assert_eq!(claims.sub, "user-1");
            assert_eq!(claims.iss, "barbican-test");
        }
        Err(rej) => unreachable!("expected claims, got rejection: {rej}"),
    }
}

#[tokio::test]
async fn claims_extractor_without_header_rejects_with_missing_credentials() {
    let state = service();
    let mut parts = parts_with_bearer(None);
    let result = Claims::<TestClaims>::from_request_parts(&mut parts, &state).await;
    expect_missing_credentials(result);
}

#[tokio::test]
async fn claims_extractor_garbage_token_rejects_with_invalid_token() {
    let state = service();
    let mut parts = parts_with_bearer(Some("not-a-jwt"));
    let result = Claims::<TestClaims>::from_request_parts(&mut parts, &state).await;
    expect_invalid_token(result);
}

#[tokio::test]
async fn claims_extractor_expired_token_rejects_with_invalid_token() {
    let state = service();
    let mut parts = parts_with_bearer(Some(&expired_token(&state)));
    // tokenkit surfaces expiry through its decode error path; the extractor
    // maps any decode failure to InvalidToken (fail-closed) — pin that.
    let result = Claims::<TestClaims>::from_request_parts(&mut parts, &state).await;
    expect_invalid_token(result);
}

#[tokio::test]
async fn claims_extractor_token_signed_with_wrong_key_rejects() {
    let state = service();
    let other_config = JwtConfig {
        secret: "a-completely-different-secret".to_string(),
        ..JwtConfig::default()
    };
    let other = Arc::new(JwtService::new(other_config));
    let mut parts = parts_with_bearer(Some(&valid_token(&other)));
    let result = Claims::<TestClaims>::from_request_parts(&mut parts, &state).await;
    expect_invalid_token(result);
}

#[tokio::test]
async fn optional_auth_returns_some_claims_for_valid_token() {
    let state = service();
    let mut parts = parts_with_bearer(Some(&valid_token(&state)));
    let extracted = OptionalAuth::<TestClaims>::from_request_parts(&mut parts, &state).await;
    match extracted {
        Ok(OptionalAuth(Some(claims))) => assert_eq!(claims.sub, "user-1"),
        Ok(OptionalAuth(None)) => unreachable!("expected Some(claims), got None"),
        Err(inf) => match inf {},
    }
}

#[tokio::test]
async fn optional_auth_returns_none_without_header() {
    let state = service();
    let mut parts = parts_with_bearer(None);
    let extracted = OptionalAuth::<TestClaims>::from_request_parts(&mut parts, &state).await;
    match extracted {
        Ok(OptionalAuth(None)) => {}
        Ok(OptionalAuth(Some(c))) => unreachable!("expected None, got claims: {c:?}"),
        Err(inf) => match inf {},
    }
}

#[tokio::test]
async fn optional_auth_returns_none_for_garbage_token() {
    let state = service();
    let mut parts = parts_with_bearer(Some("garbage-token"));
    let extracted = OptionalAuth::<TestClaims>::from_request_parts(&mut parts, &state).await;
    match extracted {
        Ok(OptionalAuth(None)) => {}
        Ok(OptionalAuth(Some(c))) => unreachable!("expected None, got claims: {c:?}"),
        Err(inf) => match inf {},
    }
}

#[tokio::test]
async fn optional_auth_returns_none_for_expired_token() {
    let state = service();
    let mut parts = parts_with_bearer(Some(&expired_token(&state)));
    let extracted = OptionalAuth::<TestClaims>::from_request_parts(&mut parts, &state).await;
    match extracted {
        Ok(OptionalAuth(None)) => {}
        Ok(OptionalAuth(Some(c))) => unreachable!("expected None, got claims: {c:?}"),
        Err(inf) => match inf {},
    }
}

/// `FromRef` blanket bound used by the extractors resolves for
/// `Arc<JwtService>` state — pin the bound so a refactor cannot
/// silently break extractor usage in routers.
#[test]
fn arc_jwt_service_is_its_own_from_ref_state() {
    fn assert_from_ref<S: Send + Sync + 'static>()
    where
        Arc<JwtService>: FromRef<S>,
    {
    }
    assert_from_ref::<Arc<JwtService>>();
}
