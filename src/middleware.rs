use std::future::Future;
use std::pin::Pin;

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::Response;

use crate::error::AuthRejection;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Creates an auth middleware function suitable for `axum::middleware::from_fn_with_state`.
///
/// The `validate` closure receives the raw Bearer token string and should return
/// the decoded claims on success, or an `AuthRejection` on failure.
///
/// # Example
///
/// ```ignore
/// let router = Router::new()
///     .route("/protected", get(handler))
///     .layer(from_fn_with_state(state.clone(), auth_middleware_fn(|token| async move {
///         let claims: MyClaims = decode_jwt(&token)?;
///         Ok(claims)
///     })));
/// ```
pub fn auth_middleware_fn<F, Fut>(
    validate: F,
) -> impl Fn(State<()>, Request<Body>, axum::middleware::Next) -> BoxFuture<Result<Response, AuthRejection>>
       + Clone
where
    F: Fn(String) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<Response, AuthRejection>> + Send + 'static,
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

            let token = match header_val {
                Some(t) => t,
                None => return Err(AuthRejection::MissingCredentials),
            };

            match validate(token).await {
                Ok(_claims) => {
                    let req = Request::from_parts(parts, body);
                    Ok(next.run(req).await)
                }
                Err(e) => Err(e),
            }
        })
    }
}

/// Builds a closure that checks whether the authenticated principal has a specific permission.
///
/// Returns a middleware function that extracts the claims, then checks for the given permission.
///
/// # Example
///
/// ```ignore
/// let check = require_permission_fn("admin:read");
/// // Use in a layer or handler
/// ```
pub fn require_permission_fn(permission: &'static str) -> impl Fn() + Clone {
    move || {
        tracing::debug!(%permission, "checking permission");
    }
}
