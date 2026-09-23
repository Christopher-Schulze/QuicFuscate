---
id: TODO-1084
title: Make TUN E2E capture artifacts nonempty and collision-safe
severity: MED
phase: M
priority: P2
status: OPEN
created: 2026-09-23
depends_on: [TODO-1071]
---

# TODO-1084: TUN E2E evidence ownership

## Why and evidence

`scripts/tests/tun-e2e-hooks/udp-ready.sh` accepts a capture with `-s`,
which is true for a pcap header containing zero packets. Its and
`scripts/tests/tun-e2e-netns.sh`'s `[ ! -e path ]` preflight misses dangling
symlinks. A check followed by `tcpdump -w` or shell redirection is also
non-atomic: another process can take the path before the writer. The current
"capture nonempty" and "refuse overwrite" claims therefore exceed the proof.

## Target contract

- Reserve each evidence directory and file by an atomic, exclusive operation;
  refuse existing regular files, directories, symlinks (including dangling),
  and concurrent reservations. Never follow a user-controlled symlink.
- Start capture only after reservation. On failure, preserve pre-existing
  evidence and report ownership/cleanup state. Generated partial artifacts
  may be removed only when this runner created and still owns them.
- Decode the completed pcap, validate link type and exact underlay filter,
  and require at least one matching UDP packet for a successful wire proof.
  Record packet count, byte count, capture window, command, exit status,
  source commit, and artifact hash. A header-only capture is a failed proof.

## Implementation and proof

- [ ] Trace all evidence paths in `udp-ready.sh`, `tcp-ready.sh`,
      `tun-e2e-netns.sh`, and traffic-analysis hooks; use one existing
      ownership pattern if available rather than a parallel utility.
- [ ] Add atomic no-clobber reservation and owned cleanup for logs and pcap.
- [ ] Add pcap decode/count validation after `tcpdump` exits; preserve its
      stderr and nonzero status as distinct failure causes.
- [ ] Exercise zero-packet pcap, dangling symlink, pre-existing file,
      concurrent writer, interrupted tcpdump, and a positive loaded capture.

## Acceptance

- Zero successful capture proofs with zero matching packets; zero overwritten
  or symlink-target artifacts in all adversarial path tests.
- Every accepted capture records a positive packet count and reproducible
  artifact metadata; interrupted runs leave existing evidence byte-identical.
