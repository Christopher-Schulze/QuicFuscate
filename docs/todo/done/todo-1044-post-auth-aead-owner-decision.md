---
id: TODO-1044
title: Post-auth AEAD owner decision rustls default stays
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-21
depends_on: [TODO-1033, TODO-1038, TODO-1040, TODO-1041, TODO-1043]
---

# TODO-1044: Post-auth AEAD owner decision

## Why

After the bakeoff, profile, stealth residue, integration contract, and optional next-gen re-bench, one written owner decision is required. The ship default stays rustls AES-GCM. This task only picks the opt-in post-auth owner, or refuses one.

## Inputs

- TODO-1033 default is already standard rustls AES-GCM
- TODO-1038/1043 P1 1400 B table
- TODO-1040 distinguisher result
- TODO-1041 unique-hook result
- TODO-885 machine already exists and stays inert until this freeze

## Decision rule

Pick exactly one:

1. `none`: no private family. `aead_preference="auto"` stays `None`. TODO-885 stays inert. This is the expected outcome unless a private owner clearly wins.
2. `opt-in S-AEGIS`: standard libaegis/aegis, feature-gated, never default.
3. `opt-in N-AEGIS` or `opt-in N-MORUS`: next-gen first-party, feature-gated, never default.
4. `opt-in C-*`: current first-party, only if N-* was skipped and C-* still beats S-* and rustls on P1.

A private pick also needs:

- >=10 percent P1 1200-1400 B gain over R-RING and R-LC on both ARM hosts, or a documented unique 1041 hook that rustls cannot provide
- no cheap 1040 distinguisher if the operator goal is max stealth (max-stealth deployments stay on rustls even if a private owner exists)
- FEC epoch isolation proven
- TODO-1029 pcap before any production enable

## Acceptance

- [x] One written pick from the four options
- [x] Table of rejected options with one-line reasons
- [x] Config mapping: default remains `packet_protection_mode=standard`
- [x] If a private pick exists: `advanced-aead` feature, explicit `aead_preference`, `auto` still does not silently upgrade max-stealth defaults
- [x] TODO-1028 records the same freeze or refuse
- [x] TODO-885 is not enabled on the shipped default
- [x] Docs call the private owner a QuicFuscate opt-in, never a QUIC standard

## Sub-Tasks

- [x] Collect 1038/1040/1041/1043 artifacts
- [x] Apply the rule without changing it after seeing numbers
- [x] Update TODO-884, TODO-885, TODO-1028, TODO-1030
- [x] Do not flip TODO-1033

## Notes

Max stealth and max performance can disagree. If they disagree, ship two configs: default stealth = rustls AES-GCM; explicit performance profile may opt into the private owner. Never merge those into a silent `auto`.

## Result (2026-09-21)

Pick: `opt-in S-AEGIS`.

The non-default feature `advanced-aead` swaps only the private AEGIS-128L owner to `aegis` 0.9.18 (`LibAegis128L`). Default builds keep first-party `Aegis128LAead`. `libaegis_matches_first_party_aegis128l_ciphertext` passed. Ship default stays `packet_protection_mode=standard`. `aead_preference="auto"` still installs no family. Compatibility Initial, Handshake, and pre-auth 1-RTT secret installs use `standard_aes128_gcm` (ring). Header protection stays ring AES. This is a QuicFuscate opt-in, not a QUIC or TLS cipher suite.

Same-binary Omega P1 median ns (Neoverse-N1, rustc 1.97.1, iters 400, aws-lc binary):

| owner | 1200 | 1400 | 8192 |
| --- | --- | --- | --- |
| R-RING | 1120 | 1280 | 6120 |
| R-LC | 1160 | 1360 | 6200 |
| S-AEGIS | 640 | 720 | 3000 |

Omega throughput GM at 1200+1400: S-AEGIS / R-RING = 1.76x, S-AEGIS / R-LC = 1.85x.

macOS ARM (rustc 1.98.0, commit `df2a846b`, dirty). Conservative cross-run: S-AEGIS full-matrix P1 417 ns at both 1200 and 1400, versus the paired aws-lc binary R-LC 500 / 583 ns. GM = 1.29x. Profile rerun P1 1400: R-RING 583 ns, S-AEGIS 334 ns (1.75x). The full-matrix R-RING 1200 cell (1542 ns) is timer noise against the paired 500 ns cell and is not the decision cell.

Rejected:

- `none`: S-AEGIS clears the 10 percent bar on both ARM hosts against R-RING and R-LC. Max-stealth deployments still stay on rustls.
- `opt-in N-*`: TODO-1042 is SKIP. The in-place NEON AESENC scheduling landed in the existing C-AEGIS update and still loses to S-AEGIS.
- `opt-in C-*`: before that scheduling, C-AEGIS-L P1 1400 was 2500 ns on macOS and 4120 ns on Omega. After it: macOS 750 ns, Omega 1360 ns. S-AEGIS is 334 ns and 720 ns on those same runs. C-* remains slower than S-AEGIS on both hosts and slower than R-RING on macOS (584 ns).

TODO-1040: nearest-mean accuracy against R-RING is 0.495 for S-AEGIS and 0.500 for C-MORUS (`cheap_keyless_distinguisher=false`, chi-square max 295.21). Private ciphertext is not more Chrome-shaped than AES-GCM. TODO-1029 pcap is still required before any production enable. x86_64 is UNAVAILABLE. TODO-1028 records refuse. TODO-1033 was not flipped.

Tests: `cargo test -p qf-crypto --lib --offline` 156 passed; `cargo test -p qf-crypto --features advanced-aead --lib --offline libaegis_matches_first_party` 1 passed; `cargo test --offline --lib packet::tests` 41 passed.
