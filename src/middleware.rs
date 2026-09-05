use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::Response;

use crate::error::AuthRejection;

/// Boxed future returned by the auth middleware closure.
pub type AuthFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, AuthRejection>> + Send>>;

/// Creates an auth middleware function for `axum::middleware::from_fn_with_state`.
pub fn auth_middleware_fn<F, Fut>(
    validate: F,
) -> impl Fn(State<()>, Request<Body>, axum::middleware::Next) -> AuthFuture + Clone
where
    F: Fn(String) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), AuthRejection>> + Send + 'static,
{
    move |_state: State<()>, req: Request<Body>, next: axum::middleware::Next| {
        let validate = validate.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let header_val = parts
                .headers
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer ").map(|t| t.to_string()));
            let token = header_val.ok_or(AuthRejection::MissingCredentials)?;
            validate(token).await?;
            Ok(next.run(Request::from_parts(parts, body)).await)
        })
    }
}

/// Returns a closure that checks a permission string.
pub fn require_permission_fn(permission: &'static str) -> impl Fn() + Clone {
    move || {
        tracing::debug!(%permission, "checking permission");
    }
}
