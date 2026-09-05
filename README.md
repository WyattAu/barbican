# barbican

Authentication and authorization middleware for Axum — extractors, role-based guards, and public path bypass.

## Purpose

`barbican` simplifies securing Axum applications by providing ready-to-use extractors and middleware
that handle JWT validation, role checking, and public path bypass. Instead of writing boilerplate
middleware for every protected endpoint, you extract authenticated claims directly from the request.

## Features

- **`extractors`** (default) — `BearerToken`, `RequireAuth`, `OptionalAuth` extractors
- **`tokenkit`** (default) — Integration with the `tokenkit` crate for token operations
- **`tower-layer`** — `JwtAuthLayer` / `JwtAuthService` for the Tower Layer/Service pattern

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

### Tower Layer

```rust
use barbican::tower_layer::JwtAuthLayer;

let service = ServiceBuilder::new()
    .layer(JwtAuthLayer::new("my-secret"))
    .service(inner_service);
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
