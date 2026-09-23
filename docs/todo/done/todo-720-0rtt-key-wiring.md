---
id: TODO-720
title: Wire 0-RTT key installation or remove the advertised capability
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-08-01
depends_on: [TODO-539]
---

# TODO-720: Wire 0-RTT Key Installation or Remove the Advertised Capability

## Why

0-RTT is enabled in engine and rustls configuration and the transport exposes early-data state, but the provider and packet crypto boundaries do not have a complete production key-installation path.

## Findings

### 1. 0-RTT configuration is not connected to packet crypto keys
- **Files:** `src/engine/engine.rs:124-126`, `src/engine/config.rs:88,214,243`, `src/qftls.rs:1340-1398,1629,1970-1989`, `src/transport/packet.rs:2100-2144`, `src/transport/connection/parts/impl_lifecycle.rs:1059-1070`.
- **Problem:** Engine and rustls set early-data flags, and `enable_0rtt()` only sets a provider-local boolean. The Rustls provider's `get_0rtt_keys()` returns `None`; `CryptoContext::install_0rtt_keys()` exists but has no production caller, and `set_zero_rtt_enabled()` is not wired from transport configuration. The key schedule hook paths therefore cannot be assumed to enable packet-level 0-RTT.
- **Impact:** A user can enable a documented capability that either never sends/accepts 0-RTT or fails to install the required packet protection, while replay-protection readiness remains ambiguous.
- **Boundary:** TLS early-data policy, session-ticket/key derivation, packet AEAD/header protection, anti-replay admission, and application data eligibility must be one proven path.

## Acceptance

- Either complete 0-RTT wiring installs read/write AEAD and header-protection keys at the correct handshake stage and enforces anti-replay, or the capability is disabled and rejected until that proof exists.
- Client resumption with a valid ticket has a wire-level 0-RTT regression; no-ticket and replay cases fail closed.
- `is_in_early_data`, packet crypto state, TLS provider state, and configuration report the same truth.
- No 0-RTT data is admitted without an attached strike/replay register.

## Sub-Tasks

- [x] Evaluate the rustls early-data, packet-key and anti-replay boundary.
- [x] Select the documented disable-and-reject branch of Acceptance.
- [x] Cover default-off and explicitly requested early-data rejection in tests.
- [x] Remove the default/configuration claim and keep the transport disabled.

## Notes

- `CryptoContext::install_0rtt_keys()` is an existing primitive, not proof of a live runtime path.
- Do not enable 0-RTT merely by setting a boolean.

## Current Reconciliation (2026-08-07)

- The Rustls provider still returns None from get_0rtt_keys(), while packet code exposes install_0rtt_keys() and a zero-RTT enable flag without a production caller. Configuration enables early data, but the negotiated key path is not wired end to end. No crypto or transport implementation was performed.

## Deviations

None.

## Archive reconciliation (2026-09-23)

The selected disable-and-reject branch and its test evidence are recorded in
the TODO-720 section of `docs/todo.md`. This metadata reconciliation did not
rerun transport tests.
