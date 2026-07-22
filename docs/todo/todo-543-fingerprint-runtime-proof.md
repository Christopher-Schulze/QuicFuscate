---
id: TODO-543
title: Complete TCP and ICMP fingerprint runtime proof
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-462, TODO-521]
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

## Sub-Tasks

- [ ] Map every raw-IP ingress/egress path, profile owner, ICMP builder, and rotation event.
- [ ] Design one normalizer lifecycle and PMTUD-safe policy.
- [ ] Implement full runtime wiring and failable units/integration tests.
- [ ] Execute p0f/nmap/capture/allocation/throughput proof.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-462 reconciliation. Active tool classification is evidence, not permission to weaken packet correctness.

## Deviations

None.
