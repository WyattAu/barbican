# barbican

[![docs.rs](https://docs.rs/barbican/badge.svg)](https://docs.rs/barbican)
[![crates.io](https://img.shields.io/crates/v/barbican.svg)](https://crates.io/crates/barbican)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

Authentication and authorization middleware for Axum — extractors, role-based guards, and public path bypass.

## Purpose

`barbican` simplifies securing Axum applications by providing ready-to-use extractors and middleware
that handle JWT validation, role checking, and public path bypass. Instead of writing boilerplate
middleware for every protected endpoint, you extract authenticated claims directly from the request.

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `extractors` | ✅ | `BearerToken`, `RequireAuth`, and `OptionalAuth` extractors plus public-path bypass helpers. |
| `tokenkit` | ✅ | Token validation via the [`tokenkit`](https://docs.rs/tokenkit) crate: `Claims`/`OptionalAuth` extraction backed by `JwtService`. |

Middleware helpers (`auth_middleware_fn`, `require_permission_fn`) and the Tower Layer/Service pattern are always available and require no feature flag.

## Usage

### BearerToken Extractor

```rust
use barbican::extractors::BearerToken;

#[derive(serde::Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

async fn handler(BearerToken(claims): BearerToken<Claims>) -> String {
    format!("Hello, {}", claims.sub)
}
```

### RequireAuth Extractor

```rust
use barbican::extractors::RequireAuth;

async fn protected(RequireAuth(claims): RequireAuth<Claims>) -> impl IntoResponse {
    format!("Authenticated as {}", claims.sub)
}
```

### OptionalAuth Extractor

```rust
use barbican::extractors::OptionalAuth;

async fn maybe_auth(OptionalAuth(claims): OptionalAuth<Claims>) -> String {
    match claims {
        Some(c) => format!("Hello, {}", c.sub),
        None => "Hello, anonymous".to_string(),
    }
}
```

### Public Path Bypass

```rust
use barbican::path::is_public_path;

assert!(is_public_path("/health", &["/health", "/metrics"]));
```

### Middleware Function

For the Tower middleware pattern, `auth_middleware_fn` plugs into
`axum::middleware::from_fn_with_state`:

```rust
use barbican::middleware::auth_middleware_fn;

let mw = auth_middleware_fn(|token: String| async move {
    // validate the bearer token; return Err(AuthRejection::...) to reject
    Ok(())
});
```

## Comparison with Manual Middleware

Without `barbican`:

```rust
async fn my_handler(Extension(auth): Extension<AuthState>) -> impl IntoResponse {
    let token = auth.extract_token().ok_or(AuthError::Missing)?;
    let claims = validate_jwt(token)?;
    Ok(format!("Hello, {}", claims.sub))
}
```

With `barbican`:

```rust
async fn my_handler(BearerToken(claims): BearerToken<Claims>) -> String {
    format!("Hello, {}", claims.sub)
}
```

## License

MIT OR Apache-2.0

## Security

Threat model: [THREAT-MODEL.md](THREAT-MODEL.md).
