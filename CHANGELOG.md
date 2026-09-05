# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

## [0.1.0] - 2026-09-01

### Added

- Axum auth extractors: `BearerToken`, `RequireAuth`, `OptionalAuth`
  (feature `extractors`, on by default).
- `tokenkit` integration for token operations (feature `tokenkit`,
  on by default).
- Tower Layer/Service pattern: `JwtAuthLayer` / `JwtAuthService`
  (feature `tower-layer`), with public-path bypass.
