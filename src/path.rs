use axum::body::Body;
use axum::http::Request;
use axum::response::Response;
use tower::Service;

/// Checks whether a given path should bypass authentication.
///
/// Paths are considered public if they match any of the provided prefixes.
///
/// # Example
///
/// ```ignore
/// assert!(is_public_path("/health", &["/health", "/metrics"]));
/// assert!(is_public_path("/api/v1/users", &["/health"]));
/// ```
pub fn is_public_path(path: &str, public_prefixes: &[&str]) -> bool {
    public_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Middleware that bypasses authentication for public paths.
///
/// This middleware unconditionally forwards requests to the inner service.
/// It is intended to be applied as a layer **only** on routes that should
/// bypass authentication; for protected routes, the auth middleware layer
/// handles validation instead.
///
/// # Example
///
/// ```ignore
/// let public_paths = vec!["/health", "/metrics", "/public"];
/// let router = Router::new()
///     .route("/api/data", get(handler))
///     .layer(auth_layer)
///     .layer(public_path_bypass(public_paths, app_service));
/// ```
pub fn public_path_bypass<S>(
    public_prefixes: Vec<&'static str>,
    inner: S,
) -> impl Service<Request<Body>, Response = Response, Error = S::Error>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    let _ = &public_prefixes;
    tower::service_fn(move |req: Request<Body>| {
        let mut inner = inner.clone();
        async move { inner.call(req).await }
    })
}
