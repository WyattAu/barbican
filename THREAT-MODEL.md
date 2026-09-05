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
| T5 | Public-path bypass abused on protected routes | Elevation | `is_public_path` | Segment-boundary matching (REQ-BARBICAN-100): a public entry matches itself and its subtree only — text-prefix sharing (`/healthcheck` vs `/health`) does NOT bypass auth; middleware ordering is integrator-owned (documented: bypass layer only on public routes) | `src/lib.rs::req_barbican_100_text_prefix_sharing_is_not_public`, `public_paths`, `non_public_paths`, `req_barbican_100_input_is_path_component_query_not_split`; proptests `is_public_path_exact_and_subtree`, `is_public_path_no_text_prefix_over_match` |
| T6 | Auth failure detail oracle / token echo | Info disclosure | `AuthRejection::InvalidToken` | Token itself is never echoed; `InvalidSignature` case sends fixed "Invalid signature" text | `display_messages_contain_expected_text` (fixed strings asserted) |

## CLOSED RISKS (mitigated — cited by tests)

- **CLOSED-1 (was OPEN-1) — `is_public_path` raw-prefix over-match** —
  closed in **0.2.0** (REQ-BARBICAN-100). Matching is now segment-boundary:
  a public entry matches itself and its subtree (`/health`, `/health/`,
  `/health/detail`) but NOT text-prefix impostors (`/healthcheck`,
  `/healthz-admin`). The bypass class is pinned by
  `src/lib.rs::req_barbican_100_text_prefix_sharing_is_not_public` and the
  adversarial proptest `is_public_path_no_text_prefix_over_match` (arbitrary
  suffix text glued to a public prefix must stay non-public). Residual:
  the function receives the path component only; callers passing raw URIs
  with queries fail closed (contract test
  `req_barbican_100_input_is_path_component_query_not_split`), and Axum
  layer ordering remains integrator-owned (see Residual Risks).

## OPEN RISKS (missing mitigations — not fabricated)

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
