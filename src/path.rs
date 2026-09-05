use axum::body::Body;
use axum::http::Request;
use axum::response::Response;
use tower::Service;

/// REQ-BARBICAN-100: Checks whether a given path should bypass authentication.
///
/// Matching is **segment-boundary** — a public entry matches itself and its
/// subtree only:
///
/// - exact match: `/health` matches `/health`
/// - subtree: `/health` matches `/health/` and `/health/detail`
/// - **no text-prefix over-match**: `/health` does NOT match `/healthcheck`
///   or `/healthz-admin` — a path merely sharing a text prefix with a public
///   entry still requires authentication.
///
/// `path` must be the **path component only** (e.g. `Uri::path()`), without
/// scheme, authority, or query. Axum's `Uri::path()` never includes the
/// query string, so the usual integration is safe; a caller passing a raw
/// query-bearing string gets no match (queries are not split here).
///
/// # Example
///
/// ```
/// use barbican::is_public_path;
///
/// let public = ["/health", "/metrics"];
///
/// // exact
/// assert!(is_public_path("/health", &public));
/// // trailing slash — subtree
/// assert!(is_public_path("/health/", &public));
/// // subtree
/// assert!(is_public_path("/health/detail", &public));
/// // text-prefix sharing is NOT public — auth is enforced
/// assert!(!is_public_path("/healthcheck", &public));
/// assert!(!is_public_path("/healthz-admin", &public));
/// assert!(!is_public_path("/api/v1/users", &public));
/// ```
pub fn is_public_path(path: &str, public_prefixes: &[&str]) -> bool {
    public_prefixes.iter().any(|&prefix| {
        path == prefix
            || (path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/'))
    })
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
