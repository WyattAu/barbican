# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

## [0.2.0] - 2026-09-05

### Changed — public path matching is now segment-boundary

- `is_public_path` (REQ-BARBICAN-100) matches a public entry **exact-or-
  subtree** only: `/health` matches `/health`, `/health/`, `/health/detail`
  — but no longer `/healthcheck` or `/healthz-admin`. Previously raw
  `starts_with` prefix matching made any path sharing a text prefix public,
  an auth-bypass surface (THREAT-MODEL OPEN-1, closed).
- **Breaking** for deployments that relied on the over-match (unlikely but
  possible): routes whose names merely extend a public prefix now require
  authentication. Input contract documented: the function takes the path
  component (`Uri::path()`); queries are not split (fail-closed).

## [0.1.0] - 2026-09-01

### Added

- Axum auth extractors: `BearerToken`, `RequireAuth`, `OptionalAuth`
  (feature `extractors`, on by default).
- `tokenkit` integration for token operations (feature `tokenkit`,
  on by default).
- Tower Layer/Service pattern: `JwtAuthLayer` / `JwtAuthService`
  (feature `tower-layer`), with public-path bypass.
