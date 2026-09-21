---
id: TODO-1036
title: Evaluate rustls aws-lc-rs for the standard AES-GCM path
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-21
depends_on: [TODO-1033]
---

# TODO-1036: rustls aws-lc-rs standard-path speed

## Why

Legal speed on the stealth default is a rustls backend swap, not a new AES. Current `Cargo.toml` pins rustls to `ring`. aws-lc-rs is the audited candidate that often wins on AES-NI and Apple/ARM crypto. This is the standard-cipher performance track.

## Acceptance

- [ ] Bench-only or feature-gated rustls `aws-lc-rs` build exists; default runtime stays `ring` until the verdict
- [ ] TODO-1038 cells R-RING and R-LC are filled on macOS ARM and Omega
- [ ] Verdict: keep `ring`, switch default rustls backend to aws-lc-rs, or keep aws-lc-rs as an explicit feature
- [ ] Switch is allowed only if R-LC is at least as fast as R-RING at 1400 B packet path and does not break rustls QUIC tests
- [ ] License, build-script, and native-code cost are written down
- [ ] No AEGIS/MORUS work in this task

## Sub-Tasks

- [ ] Add a non-default feature `rustls-aws-lc` (name may follow repo style)
- [ ] Prove Handshake + 1-RTT still install rustls `PacketKey`
- [ ] Feed R-LC into TODO-1038
- [ ] Write the keep/switch record into this file and TODO-1030

## Notes

Do not start until explicitly requested. Disk check before any extra native build. This task must not wait for next-gen custom work.
