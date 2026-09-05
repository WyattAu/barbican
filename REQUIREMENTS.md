# Requirements — barbican

Each requirement is tagged in code (`REQ-BARBICAN-*` doc-comment markers) and
mapped to verifying tests. Security requirements are closed only when the
cited test exists and passes in CI.

## REQ-BARBICAN-100 — Public-path matching is segment-boundary

`is_public_path` classifies a request path as public **only** when it equals
a configured public entry or lies inside its subtree.

- **Exact**: `/health` is public under entry `/health`.
- **Subtree**: `/health/` and `/health/detail` are public under entry
  `/health` (prefix match where the next byte is `/`).
- **No text-prefix over-match (auth-bypass class)**: a path that merely
  *starts with* the same characters — `/healthcheck`, `/healthz-admin`,
  `/api/docsx` — is **NOT** public; authentication is enforced.
- **Input contract**: the function receives the **path component only**
  (e.g. `Axum Uri::path()`, which never carries a query). Queries are not
  split; a query-bearing input match fails closed. Callers passing raw URIs
  must strip scheme/authority/query first.
- **Semantics summary**: a public entry matches itself and its subtree;
  nothing else.

Tagged at: `src/path.rs::is_public_path`.

### Verifying tests

| Case | Test |
|------|------|
| exact match | `src/lib.rs::public_paths` |
| trailing slash / subtree | `src/lib.rs::public_paths` |
| text-prefix bypass class rejected (`/healthcheck`, `/healthz-admin`, `/api/docsx`, …) | `src/lib.rs::req_barbican_100_text_prefix_sharing_is_not_public` |
| non-public paths stay non-public | `src/lib.rs::non_public_paths` |
| query is not split — fail-closed contract | `src/lib.rs::req_barbican_100_input_is_path_component_query_not_split` |
| property: exact + subtree always public | proptest `src/lib.rs::is_public_path_exact_and_subtree` |
| property: no over-match for arbitrary text-prefix impostors | proptest `src/lib.rs::is_public_path_no_text_prefix_over_match` |

### Behavior change (0.1.0 → 0.2.0)

0.1.0 used raw `starts_with` prefix matching, so listing `/health` made
`/healthcheck` public. 0.2.0 closes that over-match. **Breaking** for any
deployments that (inadvisably) relied on the over-match: such routes now
require authentication.
