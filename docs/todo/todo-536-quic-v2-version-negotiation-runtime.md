---
id: TODO-536
title: Wire QUIC v2 and version negotiation end to end
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-453, TODO-521]
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

- [ ] Verify current RFC and implementation reference requirements before editing.
- [ ] Design version ownership across config, packets, crypto, TLS, and connection state.
- [ ] Implement v2, VN, compatible-version validation, and greasing atomically.
- [ ] Add complete unit, integration, adversarial, native, and Omega proof.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-453 reconciliation. Existing VN helpers are not runtime proof and may require signature changes once connection-ID validation is owned correctly.

## Deviations

None.
