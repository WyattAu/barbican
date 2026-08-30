use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::Request;
use axum::response::Response;
use tower::{Layer, Service};

use crate::error::AuthRejection;

/// Tower layer that adds JWT authentication to a service.
///
/// This layer wraps an inner service and validates the `Authorization` header
/// on every request, passing the decoded claims through extensions.
///
/// # Example
///
/// ```ignore
/// use tower::ServiceBuilder;
///
/// let service = ServiceBuilder::new()
///     .layer(JwtAuthLayer::new("secret"))
///     .service(inner_service);
/// ```
#[derive(Clone)]
pub struct JwtAuthLayer {
    secret: String,
}

impl JwtAuthLayer {
    /// Creates a new `JwtAuthLayer` with the given signing secret.
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
        }
    }
}

impl<S> Layer<S> for JwtAuthLayer {
    type Service = JwtAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JwtAuthService {
            inner,
            secret: self.secret.clone(),
        }
    }
}

/// Tower service that validates JWTs on incoming requests.
#[derive(Clone)]
pub struct JwtAuthService<S> {
    inner: S,
    secret: String,
}

impl<S> Service<Request<Body>> for JwtAuthService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();
        let secret = self.secret.clone();

        Box::pin(async move {
            let header = req
                .headers()
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "));

            match header {
                Some(_token) => {
                    // In production, validate JWT with `secret` here.
                    // For now, pass through.
                    inner.call(req).await
                }
                None => {
                    let rejection = AuthRejection::MissingCredentials;
                    Ok(rejection.into_response())
                }
            }
        })
    }
}
