# Threat Model — barbican

Status: **v1.0** · Method: STRIDE over the public API surface
(`BearerToken`/`Claims<C>`/`OptionalAuth<C>` extractors, `AuthRejection`,
`is_public_path`, `public_path_bypass`, `auth_middleware_fn`).

Trust boundaries: (1) HTTP request parts (headers, paths) from clients,
(2) the `tokenkit::JwtService` shared via Axum state, (3) route
configuration the integrator assembles (which routes get the auth layer).

## Assets

| ID | Asset | Example |
|----|-------|---------|
| A1 | Authentication decisions | Request reaching a protected handler without valid credentials |
| A2 | Public/protected route partition | Protected endpoint accidentally classified public |
| A3 | Token/claim confidentiality | Token or claim details echoed to clients or logs |
| A4 | Availability | Malformed headers/paths stalling extraction |

## STRIDE Analysis

| # | Threat | Category | Surface | Mitigation | Verifying test |
|---|--------|----------|---------|------------|----------------|
| T1 | Request without credentials reaching handler | Spoofing | `BearerToken::from_request_parts` | Missing header or non-`Bearer ` scheme → `AuthRejection::MissingCredentials` (401) | `src/lib.rs::missing_credentials_status_401`; `src/extractors.rs` rejection paths |
| T2 | Invalid/expired/revoked token accepted | Spoofing | `Claims<C>` extractor | Decoding delegated to `tokenkit::JwtService`; error mapped to typed rejections — `Expired`/`Revoked`/`InvalidSignature` → 401 | `src/lib.rs::invalid_token_status_401`, `display_messages_contain_expected_text`; proptest `auth_rejection_status_codes` |
| T3 | Forged `AuthRejection` status (error confusion) | Tampering | `AuthRejection::into_response` | Exhaustive mapping: only 401/403 statuses possible | proptest `auth_rejection_status_codes` (asserts no other status escapes) |
| T4 | Arbitrary header bytes crash extraction | DoS | `BearerToken` extraction | `to_str()` failure and prefix mismatch both yield typed rejection, never panic; `#![forbid(unsafe_code)]` | proptest `bearer_token_extraction` (adversarial token charset `[a-zA-Z0-9._-]{1,200}`); extractor error paths |
| T5 | Public-path bypass abused on protected routes | Elevation | `is_public_path` | Prefix list is explicit; middleware ordering is integrator-owned (documented: bypass layer only on public routes) | `src/lib.rs::public_paths`, `non_public_paths`; proptest `is_public_path` |
| T6 | Auth failure detail oracle / token echo | Info disclosure | `AuthRejection::InvalidToken` | Token itself is never echoed; `InvalidSignature` case sends fixed "Invalid signature" text | `display_messages_contain_expected_text` (fixed strings asserted) |

## OPEN RISKS (missing mitigations — not fabricated)

- **OPEN-1 — `is_public_path` matches on raw prefix with no boundary
  check.** Listing `/health` makes `/healthcheck` (or `/health/../admin`,
  pre-normalization) public. A segment-aware match or trailing-slash
  convention is needed; no test pins the over-match behavior.
- **OPEN-2 — `InvalidToken(other.to_string())` forwards the underlying
  `JwtError` text into the JSON response body** (`src/error.rs`
  `into_response`). Tokenkit decode errors embed `jsonwebtoken` internals —
  internal detail is disclosed to clients. Only the `InvalidSignature`
  variant is currently scrubbed to a fixed string.
- **OPEN-3 — `public_path_bypass` ignores its `public_prefixes` argument**
  (stub that always forwards). Documented in the doc comment, but a caller
  expecting it to *enforce* the bypass list gets an unconditional pass-through.
- **OPEN-4 — bearer scheme is case-sensitive** (`strip_prefix("Bearer ")`).
  RFC 6750 schemes are case-insensitive; `ws-kit`'s extractor accepts any
  case. Cross-kit inconsistency can cause spurious 401s, and callers
  "fixing" it may add permissive pre-parsing.
- **OPEN-5 — no revocation-specific surfaced test** (`TokenRevoked` status is
  unit-tested, but no integration test drives a revoked token through
  `Claims<C>` end-to-end).

## Out of Scope

- Permission model semantics (`require_permission_fn` is a stub returning a
  closure; RBAC decisions live in the caller).
- Transport security (TLS), CORS, rate limiting of auth endpoints.
- CSRF (bearer tokens are not cookie-authenticated by this crate).

## Residual Risks

- Correctness of the public/protected partition ultimately rests on Axum
  layer ordering — a mis-layered router silently widens A2; barbican can
  only document the pattern.
- `OptionalAuth` swallowing extraction failures (returns `None`) is correct
  for optional routes but means *any* downstream code treating it as
  required auth has no failure signal.
