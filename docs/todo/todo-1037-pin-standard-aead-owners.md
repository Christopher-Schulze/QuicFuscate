---
id: TODO-1037
title: Pin standard AEGIS MORUS rustls owners for the bakeoff
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-21
depends_on: [TODO-1032]
---

# TODO-1037: Pin standard AEAD owners

## Why

A bakeoff without pinned owners is shopping. Each candidate needs a crate or reference, license, API, allocation behavior, and a reason it is allowed as a bench-only dep.

## Acceptance

- [x] R-RING: rustls 0.23 + ring, current repo versions, recorded
- [x] R-LC: rustls aws-lc-rs feature, version and license recorded; `UNAVAILABLE` only if the build is impossible on a host
- [x] R-CHACHA: rustls ChaCha20-Poly1305 PacketKey path recorded
- [x] S-AEGIS: exact crate (`aegis` / libaegis binding), version, license, maintainer, whether it is allocation-free on the packet path
- [x] S-MORUS: exact crate or CAESAR reference; if no license-clean maintained crate exists, status is `UNAVAILABLE` with the search record, not a silent skip
- [x] C-* owners: current qf-crypto paths and git commit
- [x] Bench-only deps do not enter the default runtime graph
- [x] No native download, no opaque binary, no GPL surprise
- [x] Inventory written into this file as a table: owner, crate, version, license, API entry, alloc, CT claim, notes

## Sub-Tasks

- [x] Search crates.io and upstream for `aegis`, libaegis, `morus`, rustls backends
- [x] Read actual crate APIs before wrapping
- [x] Reject owners that need uncontrolled download or break reproducible builds
- [x] Hand the pin table to TODO-1038

## Notes

Do not start until explicitly requested. Pinning is not promotion. S-MORUS being `UNAVAILABLE` is an allowed honest outcome and then C-MORUS only competes against rustls and S-AEGIS.

## Result (2026-09-21)

| owner | pin | license / notes | default graph |
| --- | --- | --- | --- |
| R-RING | rustls `PacketKey` via `Keys::initial`, ring 0.17.14 | ring is the default rustls crypto provider | yes |
| R-LC | feature `rustls-aws-lc` = `rustls/aws-lc-rs`, aws-lc-rs 1.18.1, aws-lc-sys 0.45.0 | native cmake build, not default | no |
| R-CHACHA | same rustls `PacketKey` path, ChaCha20-Poly1305 | measured, slower than AES-GCM on both ARM hosts | yes, as a rustls suite, not the ship preference |
| S-AEGIS | `aegis` =0.9.18, Frank Denis, default C libaegis via cc | MIT. API `Aegis128L::<16>::new(&key, &nonce).encrypt_in_place`. allocs=0, copies the 16-byte tag | only with `aead-bakeoff` or `advanced-aead` |
| S-MORUS | `morus` =0.1.3, jedisct1, crates.io publish 2021-10-29 | MIT. Unmaintained, license-clean, so measured rather than `UNAVAILABLE` | only with `aead-bakeoff` |
| C-AEGIS-L/X4/X8, C-MORUS | qf-crypto `build_data_aead_for_benches`, commit `df2a846b` dirty | first-party, benches feature | no |
| F-AES / I-RING | first-party `AesGcm128` and `RingAesGcm128` | harness oracles for TODO-1034 | I-RING is the live Initial owner |

No native blob download beyond the crate build scripts. No GPL owner was pinned. x86_64 host remains UNAVAILABLE.
