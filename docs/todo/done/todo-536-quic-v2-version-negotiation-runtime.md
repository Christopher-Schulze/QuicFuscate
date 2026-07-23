---
id: TODO-536
title: Wire QUIC v2 and version negotiation end to end
severity: CRITICAL
phase: S
priority: P0
status: DONE
created: 2026-07-22
depends_on: [TODO-453]
---

# TODO-536: Wire QUIC v2 and Version Negotiation End to End

## Why

The crate defines v2, validates supported-version config, and builds/parses standalone VN packets, but connections never consume them. Runtime remains v1-only with no VN restart, v2 type mapping or initial crypto, connection-ID validation, compatible-version protection, or greasing.

## Acceptance

- Implement standards-compliant QUIC v1/v2 packet mapping, version-specific initial key derivation, and one explicit connection negotiation state machine.
- Wire server VN generation and client retry/no-overlap behavior with strict DCID/SCID validation and bounded restart handling.
- Encode, validate, and enforce compatible-version information so injected downgrade choices fail with the correct transport error.
- Respect ordered endpoint configuration and add standards-compliant version greasing without advertising unsupported versions as usable.
- Prove all v1-only, v2-only, preferred-version, fallback, no-overlap, malformed/spoofed VN, greasing, downgrade, and no-regression cases end to end.
- Keep private custom versions outside product scope; support only standards-based v1/v2 in this task.
- Pass local Rust gates, native CI, Omega client/server interop proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [x] Verify current RFC and implementation reference requirements before editing.
- [x] Design version ownership across config, packets, crypto, TLS, and connection state.
- [x] Implement v2, VN, compatible-version validation, and greasing atomically.
- [x] Add complete unit, integration, adversarial, native, and Omega proof.
- [x] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-453 reconciliation. Existing VN helpers are not runtime proof and may require signature changes once connection-ID validation is owned correctly.
- RFC 8999/9000/9001/9368/9369 and rustls 0.23.37 source were checked before edits. Verified runtime gaps are version-aware long-header mapping, RFC HKDF-Expand-Label use including v2 labels, v2 Retry integrity constants, rustls `quic::Version` selection, authenticated transport-parameter exchange and validation, strict VN CID/original-version handling, bounded client restart, stateless server VN, ordered runtime config, and reserved-version greasing.
- Design ownership: `Config` owns the ordered usable versions and initial choice; packet code owns invariant parsing, version-specific type bits, Retry integrity, Version Information encoding, and grease generation; `Connection` owns original/chosen/negotiated versions plus the one-restart VN lifecycle; rustls owns TLS-derived Handshake/1-RTT keys for the selected version; server admission emits VN before allocating connection state. Grease values are wire-only and never enter usable-version selection.
- Runtime closure: v2-first ordered configuration now reaches the direct CLI, engine, client, and server paths; v1/v2 long-header mapping, bounded connection IDs, Initial secrets, Retry integrity, authenticated Version Information, stateless server VN, strict client restart, downgrade rejection, and reserved-version greasing share one explicit version state.
- Local proof: the complete `cargo test --features rust-tests` gate passed with 1,795 library tests plus all binary, integration, and documentation targets; `cargo clippy --all-targets --all-features -- -D warnings`, `cargo fmt --all -- --check`, ShellCheck, `git diff --check`, runtime guardrails (0 critical, 0 warnings), and TODO consistency (190 active files, 0 violations) passed.
- Native ARM64 proof: Omega used official minimal Rust 1.97.1 with Clippy plus Clang/Libclang 18 on `aarch64-unknown-linux-gnu`. The complete native gate passed 1,812 library tests plus every binary, integration, and documentation target; `cargo clippy --all-targets --all-features -- -D warnings` passed. The exact release binary SHA-256 is `5b2df020527a781f1174fd70e0ed350b606c163772bdf482d056d936af02b69b`; the isolated source runtime is `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-todo536-20260723-final`, with source archive SHA-256 `7903797bfa419d339c0d7aabdd5389814be3cb3455dd4a126087891cb107ee59`.
- Live Omega proof: fresh v2-only, v1-only, and v2-preferred to v1-only fallback roots each used the exact final binary and completed 5/5 TUN pings with 0% loss and no panic, AEAD, decrypt, or version-mismatch error. TLS identified `QUIC V2`, `QUIC V1`, and `QUIC V1` respectively; the fallback client recorded `version-negotiation-restart`. All processes and network namespaces were absent after each run.

## Deviations

None.
