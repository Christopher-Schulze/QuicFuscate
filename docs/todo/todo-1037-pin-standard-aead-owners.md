---
id: TODO-1037
title: Pin standard AEGIS MORUS rustls owners for the bakeoff
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-21
depends_on: [TODO-1032]
---

# TODO-1037: Pin standard AEAD owners

## Why

A bakeoff without pinned owners is shopping. Each candidate needs a crate or reference, license, API, allocation behavior, and a reason it is allowed as a bench-only dep.

## Acceptance

- [ ] R-RING: rustls 0.23 + ring, current repo versions, recorded
- [ ] R-LC: rustls aws-lc-rs feature, version and license recorded; `UNAVAILABLE` only if the build is impossible on a host
- [ ] R-CHACHA: rustls ChaCha20-Poly1305 PacketKey path recorded
- [ ] S-AEGIS: exact crate (`aegis` / libaegis binding), version, license, maintainer, whether it is allocation-free on the packet path
- [ ] S-MORUS: exact crate or CAESAR reference; if no license-clean maintained crate exists, status is `UNAVAILABLE` with the search record, not a silent skip
- [ ] C-* owners: current qf-crypto paths and git commit
- [ ] Bench-only deps do not enter the default runtime graph
- [ ] No native download, no opaque binary, no GPL surprise
- [ ] Inventory written into this file as a table: owner, crate, version, license, API entry, alloc, CT claim, notes

## Sub-Tasks

- [ ] Search crates.io and upstream for `aegis`, libaegis, `morus`, rustls backends
- [ ] Read actual crate APIs before wrapping
- [ ] Reject owners that need uncontrolled download or break reproducible builds
- [ ] Hand the pin table to TODO-1038

## Notes

Do not start until explicitly requested. Pinning is not promotion. S-MORUS being `UNAVAILABLE` is an allowed honest outcome and then C-MORUS only competes against rustls and S-AEGIS.
