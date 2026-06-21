# TODO 118 - Public XDP Fastpath Token Removal and io_uring Truth Tightening

## Goal

Remove the public `xdp` fastpath token entirely, keep no alias parsing, and collapse the public fastpath surface to `auto` and `off` while `io_uring` remains the internal Linux high-end implementation.

## Why

The previous public `xdp` token no longer represented a real AF_XDP product path. It acted as historical compatibility surface that mapped into the UDP/`io_uring` runtime story, which was semantically misleading and reviewer-hostile.

The correct end state is:
- public fastpath modes: `off`, `auto`
- no public `xdp` token
- no alias parsing for `xdp`
- no separate public `uring` token
- AF_XDP retained only as internal experimental machinery behind its explicit feature gate

## Scope

- Public fastpath mode contract:
  - `src/interface.rs`
- Optimize config surface:
  - `src/optimize.rs`
- CLI/runtime glue:
  - `src/main.rs`
  - `src/implementations/client/io_driver.rs`
  - `src/implementations/server/mod.rs`
  - `src/implementations/client/connection.rs`
  - `src/engine/engine.rs`
- Compat/internal AF_XDP surface:
  - `src/transport.rs`
  - `src/transport/xdp.rs`
- Build/test/docs/guardrails:
  - `scripts/tests/build/build-dev-tools.sh`
  - `scripts/tests/build/build-release.sh`
  - `scripts/tests/audits/audit-runtime-guardrails.sh`
  - `README.md`
  - `docs/DOCUMENTATION.md`

## Implemented End State

- `FastpathMode::Xdp` removed from `src/interface.rs`
- `parse("xdp")` removed
- `xdp` compatibility helper functions removed
- `OptimizeConfig.request_xdp_compat` removed
- runtime normalization no longer carries an `xdp` compatibility branch
- hidden CLI `xdp` smoke surface removed
- public docs now describe only:
  - `off`
  - `auto`
- runtime wiring uses `io_uring` internally when `auto` is selected and Linux support is available
- AF_XDP remains only as internal experimental feature-gated machinery
- guardrails fail if public `xdp` token or alias behavior returns

## Validation

- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- `bash scripts/tests/audits/audit-runtime-guardrails.sh`

All green after the final cleanup pass.
