# TODO-249: Audit and Remove .expect() Calls in Production Code

## Severity: HIGH

## Context
206 `.expect()` calls exist across 19 production source files. Largest concentrations: fec.rs (30), admin_http.rs (29), h3.rs (28), xdp.rs (27), qkey_registry.rs (21). Each `.expect()` is a potential panic vector in production. While some may be justified (provably infallible operations), many likely should use proper `Result` propagation.

## Desired Outcome
- Audit all 206 `.expect()` calls. For each one, either:
  - Replace with `?` operator or `.ok_or()` for proper error propagation, OR
  - Add a `// SAFETY:` style comment explaining why the expect can never fail.
- Priority order: admin_http.rs (network-facing) > h3.rs > fec.rs > qkey_registry.rs > others.
- xdp.rs expects are lower priority since XDP code is behind a never-compiled feature gate.

## Files
- `src/fec.rs`, `src/implementations/server/admin_http.rs`, `src/transport/h3.rs`
- `src/transport/xdp.rs`, `src/implementations/server/qkey_registry.rs`
- 14 additional files with smaller counts

## Completion Criteria
- All `.expect()` calls in network-facing code (admin_http, h3) are replaced with error propagation.
- Remaining `.expect()` calls have justification comments.
- `cargo test` passes, clippy clean.
