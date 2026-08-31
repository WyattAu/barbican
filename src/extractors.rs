use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use serde::de::DeserializeOwned;
use std::sync::Arc;

use crate::error::AuthRejection;

/// Raw bearer token string extracted from Authorization header.
pub struct BearerToken(pub String);

impl<S: Send + Sync> FromRequestParts<S> for BearerToken {
    type Rejection = AuthRejection;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthRejection::MissingCredentials)?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or(AuthRejection::MissingCredentials)?;
        Ok(BearerToken(token.to_string()))
    }
}

/// Authenticated claims extracted from a valid JWT.
///
/// Requires `Arc<tokenkit::JwtService>` to be in Axum state via `FromRef`.
pub struct Claims<C>(pub C);

#[cfg(feature = "tokenkit")]
impl<C, S> FromRequestParts<S> for Claims<C>
where
    C: DeserializeOwned + Send + 'static,
    S: Send + Sync,
    Arc<tokenkit::service::JwtService>: axum::extract::FromRef<S>,
{
    type Rejection = AuthRejection;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let service = Arc::<tokenkit::service::JwtService>::from_ref(state);
        let BearerToken(token) = BearerToken::from_request_parts(parts, state).await?;
        let claims = service.decode::<C>(&token).map_err(|e| match e {
            tokenkit::error::JwtError::Expired => AuthRejection::TokenExpired,
            tokenkit::error::JwtError::Revoked => AuthRejection::TokenRevoked,
            tokenkit::error::JwtError::InvalidSignature => {
                AuthRejection::InvalidToken("Invalid signature".into())
            }
            other => AuthRejection::InvalidToken(other.to_string()),
        })?;
        Ok(Claims(claims))
    }
}

/// Optional authenticated claims — never rejects the request.
pub struct OptionalAuth<C>(pub Option<C>);

#[cfg(feature = "tokenkit")]
impl<C, S> FromRequestParts<S> for OptionalAuth<C>
where
    C: DeserializeOwned + Send + 'static,
    S: Send + Sync,
    Arc<tokenkit::service::JwtService>: axum::extract::FromRef<S>,
{
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let service = Arc::<tokenkit::service::JwtService>::from_ref(state);
        let Ok(BearerToken(token)) = BearerToken::from_request_parts(parts, state).await else {
            return Ok(OptionalAuth(None));
        };
        let claims = service.decode::<C>(&token).ok();
        Ok(OptionalAuth(claims))
    }
}
