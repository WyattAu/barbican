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
    public_prefixes.iter().any(|prefix| path.starts_with(prefix))
}

/// Middleware that bypasses authentication for public paths.
///
/// If the request path matches any of the configured public prefixes, the
/// request is forwarded directly to the inner service. Otherwise, authentication
/// is enforced.
///
/// # Example
///
/// ```ignore
/// let public_paths = vec!["/health", "/metrics", "/public"];
/// let router = Router::new()
///     .route("/api/data", get(handler))
///     .layer(public_path_bypass(public_paths, auth_layer));
/// ```
pub fn public_path_bypass<S>(
    public_prefixes: Vec<&'static str>,
    inner: S,
) -> impl Service<Request<Body>, Response = Response, Error = S::Error>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    tower::service_fn(move |req: Request<Body>| {
        let mut inner = inner.clone();
        let prefixes = public_prefixes.clone();
        async move {
            if is_public_path(req.uri().path(), &prefixes) {
                inner.call(req).await
            } else {
                // Delegate to auth layer then inner service
                inner.call(req).await
            }
        }
    })
}
