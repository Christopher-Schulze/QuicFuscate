# TODO 117 - XDP Compatibility Shim io_uring Ownership Collapse

## Goal
- Remove the last private `io_uring` machine-room from `src/transport/xdp.rs`.
- Keep `src/transport/uring.rs` as the only runtime `io_uring` owner.
- Leave the XDP compat/test shim with only narrowed `udpfast` coverage for local smoke and parity tests.

## Why this existed
- A forensic follow-up after the runtime cleanup found that `src/transport/xdp.rs` still carried a second internal `io_uring` implementation:
  - `uring_udp::UringUdp`
  - local `enable_uring(...)`
  - local `try_enable_uring_fastpath(...)`
  - local `enable_uring_or_udp_fallback(...)`
- This was not the active canonical runtime path anymore, but it kept a second Linux send-path story alive inside the compat shim.

## Target State
- `src/transport/uring.rs` remains the only runtime `io_uring` implementation.
- `src/transport/xdp.rs` retains only compat/test-scoped `udpfast` coverage.
- No private `io_uring` adapter or duplicated fallback ladder remains under `xdp.rs`.

## Files
- `src/transport/xdp.rs`
- `src/transport/uring.rs`
- `scripts/tests/audits/audit-runtime-guardrails.sh`
- `docs/todo.md`

## Acceptance Criteria
- The `uring_udp` module is gone from `src/transport/xdp.rs`.
- `FastPathTransport` in `xdp.rs` no longer owns or enables a private `io_uring` adapter.
- `enable_fastpath_from_env(...)` in `xdp.rs` narrows to `udpfast` only.
- Guardrails fail if `xdp.rs` regains a private `io_uring` runtime.
- Targeted rust-tests, `cargo check`, and `cargo clippy --all-targets --all-features -- -W clippy::all` are green.

## Validation
- `cargo test --features rust-tests uring_mode_falls_back_to_udp_fastpath_when_uring_unavailable --lib`
- `cargo test --features rust-tests recv_coalesced_fastpath_reads_from_udp_fastpath --lib`
- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
