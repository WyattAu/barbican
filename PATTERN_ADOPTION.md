# PATTERN_ADOPTION

barbican's declared relationship to the WyattAu pattern canon
(`WyattAu/pattern-standards`). Format: `references/adoption-format.md`
in the canon. Validated by `scripts/adoption-check.py`.

| Pattern | Status | Evidence |
|---|---|---|
| T13 | adopted | src/path.rs:40 (pure segment-boundary classifier, no I/O; extractors and middleware form the shell) |
| P64 | adopted | src/lib.rs:110 (proptest module pins path matching and rejection status contracts) |
| P66 | adopted | .github/workflows/mutation.yml (weekly cargo-mutants; 2026-09-06 baseline: 0 viable survivors) |
| P114 | partial | src/extractors.rs:47 (every Claims extraction decodes through tokenkit JwtService; Expired, Revoked, InvalidSignature map to distinct rejections; algorithm pinning and claim policy live in tokenkit) |
| T8 | refused | R6 (claims cross the boundary as data, not attenuated capabilities; the crate holds no ambient authority, and the permission guard is a logging stub: src/middleware.rs:37) |

## Notes

- Patterns with no relationship to this crate are omitted rather than
  rowed: P43, P85, and P115 (no key material or crypto surface here;
  key lifecycle and algorithm choice are owned by tokenkit), and P4
  (no secret-display surface; token values are never logged, and the
  crate serializes nothing).
- `require_permission_fn` (src/middleware.rs:37) validates nothing; it
  emits a debug line. The README's "role-based guards" wording
  overstates it.
