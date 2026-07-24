---
id: TODO-543
title: Complete TCP and ICMP fingerprint runtime proof
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-462, TODO-534, TODO-544]
---

# TODO-543: Complete TCP and ICMP Fingerprint Runtime Proof

## Why

The packet normalizer has field/checksum units, but live TUN and MASQUE paths call only IPv4 normalization. TCP normalization, ICMP policy, disabled passthrough, profile-rotation coupling, tool classification, allocation, and throughput acceptance are unproven.

## Acceptance

- Define explicit disabled, Linux, Windows, macOS, and Android profiles with one validated mapping from current stealth OS profile.
- Apply complete IPv4 and SYN-only TCP normalization once at the correct egress boundary for every TUN/MASQUE path, never per connection-poll construction.
- Implement PMTUD-safe ICMP unreachable policy and profile-consistent echo behavior without suppressing Packet Too Big.
- Rotate TLS and network-stack profile atomically or keep both fixed; no observable mismatch window is allowed.
- Prove checksums by capture, p0f and active fingerprint results, pure passthrough, zero hot-path allocation, and at least 900 Mbps on the retained benchmark host.
- Pass local Rust gates, native CI, privileged Omega capture/tool proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Completion Gates

- Wiring gate: every TUN/MASQUE raw-IP egress path reaches one normalizer exactly once and disabled mode is proven byte-for-byte passthrough.
- Correctness gate: profile vectors and captures prove IPv4/TCP checksums, SYN-only fields, ICMP unreachable/echo behavior, Packet Too Big preservation, and atomic TLS/network-profile rotation.
- Tool and performance gate: p0f plus active fingerprint results match each profile, allocation instrumentation reports zero hot-path allocation, and retained-host throughput is at least 900 Mbps.
- Release gate: local Rust gates, native CI, exact-artifact privileged Omega capture/tool proof, SHA-256, cleanup, protected UI diff, and owning-doc updates all pass.

## Sub-Tasks

- [ ] Map every raw-IP ingress/egress path, profile owner, ICMP builder, and rotation event.
- [ ] Design one normalizer lifecycle and PMTUD-safe policy.
- [ ] Implement full runtime wiring and failable units/integration tests.
- [ ] Execute p0f/nmap/capture/allocation/throughput proof.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-462 reconciliation. Active tool classification is evidence, not permission to weaken packet correctness.
- Primary surfaces: `src/stealth/fingerprint.rs`, `src/stealth/mod.rs`, `src/implementations/server/icmp.rs`, `src/implementations/server/mod.rs`, `src/transport/config.rs`, and the raw TUN/MASQUE paths in `src/core.rs`.
- Scope lock: normalize each raw egress packet exactly once and preserve PMTUD. Do not rewrite encrypted QUIC packets, normalize non-SYN TCP traffic without an explicit contract, couple profile rotation non-atomically, or tune values only to fool one classifier.
- Evidence bundle: retain profile vectors, before/after packet bytes, checksum validation, p0f/nmap versions and outputs, rotation timeline, PMTUD outcomes, allocation counters, throughput distribution, artifact hash, captures, and cleanup.

## Deviations

None.
