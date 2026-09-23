---
id: TODO-1111
title: Restore Windows compilation and outer-header socket policy
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1057]
---

# TODO-1111: Windows outer-header portability

## Why and evidence

TODO-1057 added `src/stealth/outer_header.rs`, which unconditionally imports
`std::os::unix::io::AsRawFd` and exposes functions accepting `RawFd`.
`src/stealth/mod.rs` exports the module unconditionally, and
`src/main/runtime/client.rs` calls `apply_outer_header_logged` for the
initial socket and a migrated socket without a Windows gate. The repo has a
Windows client build in `.github/workflows/windows-omega-e2e.yml` (`cargo
build --locked --bin quicfuscate --features tun-windows`); the new module
cannot type-check on that target. This is a source-proven compile blocker;
the current Mac has no installed Windows Rust target, so the exact Windows
compiler output has not yet been captured.
The Windows E2E workflow is manual-only, and the required `ci.yml` matrix
currently runs its primary build/test job only on macOS. That gate cannot
catch this platform regression before a release.

Microsoft documents `IP_TTL` and `IP_DONTFRAGMENT` for Windows datagram
sockets, with support-dependent `setsockopt`/`getsockopt` behavior:
https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options.

## Target contract

- Keep one `OsOuterHeader` policy and one caller-visible
  `OuterHeaderOutcome`; separate only the platform socket operations.
  Unix keeps its existing `AsRawFd` path. Windows uses the actual socket
  handle and the pinned `windows-sys` WinSock API, without a Unix import or
  a fake success result. Unsupported platforms remain explicit at compile
  time and report truthful option failures at runtime.
- For an IPv4 Windows UDP socket, set the requested TTL and DF policy with
  documented Winsock options; for IPv6, set the unicast hop limit and do not
  claim a nonexistent IPv4 DF field. A failed option must preserve the
  connection and report that specific failure once through the existing
  warning policy. Validate the socket after bind, so option success is not
  inferred from an unchecked pre-bind call.
- Apply the same policy on the first client socket and every replacement
  socket after migration. Do not change the frozen persona, kernel-controlled
  IPv4 ID, or the inner packet normalizer. Wire fidelity remains owned by
  TODO-1085.

## Implementation and proof

- [ ] Read the exact pinned `windows-sys` WinSock `setsockopt`, option
      constants, handle and return signatures, and both client socket call
      sites before editing. Keep the shared policy in one owner and add
      narrowly gated Unix/Windows operations.
- [ ] Add native Windows socket tests that bind a UDP socket, apply an IPv4
      persona, and read back supported TTL/DF options; cover an IPv6
      hop-limit request, an unsupported option, and reapply on a fresh
      migrated socket. Keep socket tests separate from TODO-1085's raw-wire
      persona capture.
- [ ] Run `cargo build --locked --bin quicfuscate --features tun-windows`
      and `cargo test --locked --lib --features tun-windows,rust-tests
      --no-run` on a native Windows runner; then run the relevant platform
      socket tests. Check macOS and Linux compilation and existing
      outer-header tests for regressions, respecting the disk-space guard.
- [ ] Add a bounded native Windows compile lane to the push/PR gate in
      `.github/workflows/ci.yml`. Keep the secret-bearing authenticated
      Windows/Omega E2E workflow manual; do not turn it into an untrusted
      pull-request job. Verify that the lane actually reports failure for
      an unconditional Unix-only import.
- [ ] Update TODO-1057 outcome and `docs/DOCUMENTATION.md`/`docs/MAP.md`
      platform statements only to match tested socket and wire evidence.

## Acceptance

- Native Windows client binary and library test compilation pass with the
  exact feature set above on the gated push/PR runner; no unconditional Unix
  API remains in a module exported on Windows.
- On supported Windows sockets, IPv4 TTL/DF and IPv6 hop-limit outcomes match
  `getsockopt`; failures are visible and fail-soft. Initial and migrated
  sockets take the same policy. Existing Unix tests remain green.
- The task does not claim browser-equivalent outer packets until TODO-1085
  supplies capture comparison.
