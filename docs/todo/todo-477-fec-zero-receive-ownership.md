# TODO-477: FEC zero-mode receive ownership preservation

## Status

DONE

## Context

`AdaptiveFec::on_receive()` previously routed every incoming FEC packet through the active decoder, including `FecMode::Zero`. That preserved a decoder-side clone of the pooled payload even though Zero mode has no repair packets and cannot recover old Zero-mode payloads. The extra shared owner forced the QUIC receive path into its copy-on-mutate fallback before decrypt/header-unprotect, adding avoidable clean-link overhead.

## Desired Outcome

When FEC is in Zero mode and no mode transition is active, receive should be a true ownership-preserving passthrough:

- return the systematic packet directly;
- do not retain decoder state for a mode with no recovery capability;
- keep pooled payload ownership unique so downstream QUIC processing can mutate in place;
- preserve all recovery-capable mode behavior and transition behavior.

## Implementation

- `src/fec/mod.rs`: `AdaptiveFec::on_receive()` now exits early for `FecMode::Zero` when `transition_left == 0`.
- `src/fec/tests.rs`: added `test_zero_mode_receive_preserves_unique_payload_owner`.
- `README.md` and `docs/DOCUMENTATION.md`: documented Zero-mode receive as ownership-preserving clean-link passthrough.

## Verification

- `cargo fmt --all -- --check`
- `git diff --check`
- `cargo check --lib`
- `cargo clippy --lib -- -D warnings`
- `cargo test --lib`
- `cargo test --lib test_zero_mode_receive_preserves_unique_payload_owner -- --nocapture`
- `cargo test --lib fec::transition_tests:: -- --nocapture`
- `cargo test --lib fec::e2e_tests::test_fec_e2e_zero_mode_passthrough_no_repairs -- --nocapture`
- `cargo bench --features benches --bench fec_pipeline -- fec_lazy_fast_path/zero_mode_passthrough`: Criterion reported about 29% improvement.
- Broderick release gates:
  - `cargo clippy --lib -- -D warnings`
  - `cargo test --release --lib test_zero_mode_receive_preserves_unique_payload_owner -- --nocapture`
  - `cargo test --release --lib fec::transition_tests:: -- --nocapture`
  - `cargo test --release --lib fec::e2e_tests::test_fec_e2e_zero_mode_passthrough_no_repairs -- --nocapture`
  - `cargo test --release --features io_uring --test rt-transport-uring -- --nocapture`
- GitHub Actions run `28477451629`: CI success, Clippy Matrix success, Release Build success.

## Completion Criteria

- [x] Zero-mode receive preserves unique pooled payload ownership.
- [x] Transition and recovery-capable modes remain unchanged.
- [x] Local, Broderick, and GitHub CI verification passed.
