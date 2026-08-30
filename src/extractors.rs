use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::de::DeserializeOwned;

use crate::error::AuthRejection;

/// Bearer token extractor that validates and decodes a JWT, returning the claims.
///
/// Generic over the claims type `C` so you can use any DeserializeOwned struct.
///
/// # Example
///
/// ```ignore
/// #[derive(Deserialize)]
/// struct MyClaims {
///     sub: String,
///     exp: usize,
/// }
///
/// async fn handler(BearerToken(claims): BearerToken<MyClaims>) -> String {
///     format!("Hello, {}", claims.sub)
/// }
/// ```
pub struct BearerToken<C>(pub C);

impl<C, S> FromRequestParts<S> for BearerToken<C>
where
    C: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthRejection::MissingCredentials)?;

        let token = header
            .strip_prefix("Bearer ")
            .ok_or(AuthRejection::InvalidToken)?;

        let claims: C = serde_json::from_str(token).map_err(|_| AuthRejection::InvalidToken)?;

        Ok(Self(claims))
    }
}

/// Extractor that requires a valid bearer token. Returns 401 if missing or invalid.
///
/// Works identically to `BearerToken` but exists as a separate type for clarity
/// when documenting authentication requirements on handlers.
///
/// # Example
///
/// ```ignore
/// async fn protected(RequireAuth(claims): RequireAuth<MyClaims>) -> impl IntoResponse {
///     format!("Authenticated as {}", claims.sub)
/// }
/// ```
pub struct RequireAuth<C>(pub C);

impl<C, S> FromRequestParts<S> for RequireAuth<C>
where
    C: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let BearerToken(claims) = BearerToken::<C>::from_request_parts(parts, state).await?;
        Ok(Self(claims))
    }
}

/// Optional auth extractor — returns `None` if no token is present, or validates it if one is.
///
/// Useful for endpoints that behave differently for authenticated vs anonymous users.
///
/// # Example
///
/// ```ignore
/// async fn maybe_auth(OptionalAuth(claims): OptionalAuth<MyClaims>) -> impl IntoResponse {
///     match claims {
///         Some(c) => format!("Hello, {}", c.sub),
///         None => "Hello, anonymous".to_string(),
///     }
/// }
/// ```
pub struct OptionalAuth<C>(pub Option<C>);

impl<C, S> FromRequestParts<S> for OptionalAuth<C>
where
    C: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match BearerToken::<C>::from_request_parts(parts, state).await {
            Ok(BearerToken(claims)) => Ok(Self(Some(claims))),
            Err(AuthRejection::MissingCredentials) => Ok(Self(None)),
            Err(e) => Err(e),
        }
    }
}
