//! Integration tests for `auth_middleware_fn` and `public_path_bypass`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Router, middleware};
use tower::ServiceExt;

use barbican::{AuthRejection, auth_middleware_fn, public_path_bypass};

async fn handler() -> &'static str {
    "ok"
}

fn bearer_request(auth: Option<&str>, uri: &'static str) -> Request<Body> {
    let mut builder = Request::builder().uri(uri);
    if let Some(a) = auth {
        builder = builder.header(http::header::AUTHORIZATION, a);
    }
    let built = builder.body(Body::empty());
    assert!(
        built.is_ok(),
        "request build failed: {:?}",
        built.as_ref().err()
    );
    match built {
        Ok(req) => req,
        Err(_) => unreachable!("checked above"),
    }
}

async fn oneshot_ok(app: Router, req: Request<Body>) -> axum::response::Response {
    let resp = app.oneshot(req).await;
    match resp {
        Ok(r) => r,
        Err(e) => match e {},
    }
}

fn router_with_auth() -> Router {
    let validate = |token: String| async move {
        if token == "good-token" {
            Ok(())
        } else {
            Err(AuthRejection::InvalidToken(token))
        }
    };
    let mw = auth_middleware_fn(validate);
    Router::new()
        .route("/protected", get(handler))
        .layer(middleware::from_fn_with_state((), mw))
}

#[tokio::test]
async fn middleware_passes_valid_token_through_to_handler() {
    let req = bearer_request(Some("Bearer good-token"), "/protected");
    let resp = oneshot_ok(router_with_auth(), req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn middleware_rejects_missing_authorization_header_with_401() {
    let req = bearer_request(None, "/protected");
    let resp = oneshot_ok(router_with_auth(), req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn middleware_rejects_non_bearer_header_with_401() {
    let req = bearer_request(Some("Basic dXNlcjpwYXNz"), "/protected");
    let resp = oneshot_ok(router_with_auth(), req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn middleware_rejects_token_failing_validation_with_401() {
    let req = bearer_request(Some("Bearer wrong-token"), "/protected");
    let resp = oneshot_ok(router_with_auth(), req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn middleware_validate_error_can_map_to_forbidden() {
    // A validator returning InsufficientPermissions must surface 403 —
    // proves the middleware forwards the exact rejection, not just 401.
    let validate =
        |_token: String| async move { Err(AuthRejection::InsufficientPermissions("write".into())) };
    let mw = auth_middleware_fn(validate);
    let app = Router::new()
        .route("/protected", get(handler))
        .layer(middleware::from_fn_with_state((), mw));
    let req = bearer_request(Some("Bearer whatever"), "/protected");
    let resp = oneshot_ok(app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn public_path_bypass_forwards_request_to_inner_service() {
    let inner = Router::new().route("/health", get(handler));
    let svc = public_path_bypass(vec!["/health"], inner);
    let req = bearer_request(None, "/health");
    let resp = oneshot_ok_router(svc, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn public_path_bypass_preserves_inner_status_codes() {
    // Bypass never rewrites the response: a 404 from the inner router for an
    // unrouted path must pass through unchanged.
    let inner = Router::new().route("/health", get(handler));
    let svc = public_path_bypass(vec!["/health"], inner);
    let req = bearer_request(None, "/nope");
    let resp = oneshot_ok_router(svc, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

async fn oneshot_ok_router<S>(svc: S, req: Request<Body>) -> axum::response::Response
where
    S: tower::Service<Request<Body>, Response = axum::response::Response> + Send,
    S::Error: std::fmt::Debug,
{
    let resp = svc.oneshot(req).await;
    assert!(resp.is_ok(), "service errored: {:?}", resp.as_ref().err());
    match resp {
        Ok(r) => r,
        Err(_) => unreachable!("checked above"),
    }
}

#[test]
fn require_permission_fn_is_cloneable_and_callable() {
    let check = barbican::require_permission_fn("write");
    let cloned = check.clone();
    cloned();
    check();
}
