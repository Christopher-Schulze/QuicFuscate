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

- [x] Bench-only or feature-gated rustls `aws-lc-rs` build exists; default runtime stays `ring` until the verdict
- [x] TODO-1038 cells R-RING and R-LC are filled on macOS ARM and Omega
- [x] Verdict: keep `ring`, switch default rustls backend to aws-lc-rs, or keep aws-lc-rs as an explicit feature
- [x] Switch is allowed only if R-LC is at least as fast as R-RING at 1400 B packet path and does not break rustls QUIC tests
- [x] License, build-script, and native-code cost are written down
- [x] No AEGIS/MORUS work in this task

## Sub-Tasks

- [x] Add a non-default feature `rustls-aws-lc` (name may follow repo style)
- [x] Prove Handshake + 1-RTT still install rustls `PacketKey`
- [x] Feed R-LC into TODO-1038
- [x] Write the keep/switch record into this file and TODO-1030

## Notes

The operator has authorized work through the open task queue. This native
x86_64 measurement still requires a real host and the repository disk/build
gate; absence of that host is an explicit blocker, not an ARM substitute.

## Result (2026-09-21)

Keep ring as the rustls default. Feature `rustls-aws-lc` maps to `rustls/aws-lc-rs` and is not in the default feature set. Locked backend in the bakeoff build: aws-lc-rs 1.18.1 / aws-lc-sys 0.45.0. The native cmake build on Omega took 3m 39s (`EXIT:0`). That native cost is paid only when the feature is on.

Paired P1 median ns:

| host | size | R-RING | R-LC |
| --- | --- | --- | --- |
| macOS ARM | 1200 | 500 | 500 |
| macOS ARM | 1400 | 667 | 583 |
| macOS ARM | 8192 | 2959 | 2584 |
| Omega | 1200 | 1120 | 1160 |
| Omega | 1400 | 1280 | 1360 |
| Omega | 8192 | 6120 | 6200 |

macOS 1400 favors R-LC by one timer bucket; other R-RING 1400 runs on that host were 583-709 ns. Omega favors R-RING at every decision size. Handshake and 1-RTT install paths stay rustls `PacketKey` on either provider. Do not switch the default on ARM evidence.

## x86_64 VAES remeasure (OPEN)

ARM does not decide VAES. aws-lc can still win on x86_64 because that ISA issues more AES rounds per instruction. This cell was never run (TODO-1038 x86_64 is UNAVAILABLE).

Rules:

- Same API as TODO-1038. Owners R-RING and R-LC only. No AEGIS, no first-party AES.
- Sizes 1200 and 1400 bytes. P1 median and spread over at least five paired
  same-host runs per provider. Record host, CPU flags (`vaes`, `avx512f`),
  rustc, lockfile provider versions, exact features, and revision.
- Feature stays `rustls-aws-lc`. Default features stay ring for the build under test and for the product.
- Consider a default switch only if R-LC improves the 1400 B packet cell by
  at least 10% on the target x86_64 host, does not regress 1200 B or the
  supported ARM deployment path beyond measurement noise, and focused QUIC
  handshake/1-RTT tests pass with that provider. If the benefit is x86-only,
  retain the portable ring default and document an explicit x86 package or
  feature policy before adding platform-dependent provider selection.
- If R-LC is equal or slower, close this section as "keep ring" and set status back to DONE.
- Disk check before the native aws-lc cmake build. Do not run this on the Mac ARM laptop as a substitute for x86.

### Sub-Tasks

- [ ] x86_64 host with VAES available.
- [ ] Fill the 1200 and 1400 cells for R-RING and R-LC.
- [ ] Write the keep-or-switch sentence in this file.
- [ ] Do not flip `Cargo.toml` default features before that sentence exists.
