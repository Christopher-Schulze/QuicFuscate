---
id: TODO-1131
title: Diagnose build artifact removal during active Cargo compilation
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-23
depends_on: []
---

# TODO-1131: Prevent Cargo target cleanup from racing an active build

## Why and evidence

During `cargo test --lib --features rust-tests,stream_ring_buffer,zero_copy_dgram`
for TODO-1130, rustc failed to copy an object from
`target/debug/incremental/quicfuscate-1anua9r9h3o2e/...-working/` to
`target/debug/deps/` because the source path no longer existed. Immediately
afterward, `target/` itself was absent and free disk space had risen from
4.7 to 13 GiB. No product test had started. A retry with
`CARGO_INCREMENTAL=0` rebuilt and passed `1,870` tests with one ignored.
The actor that removed `target/` was not identified; do not attribute it to
a specific script, process or user without evidence.

## Target contract

- No scheduled, manual or agent-owned cleanup removes any part of an active
  Cargo target while Cargo/rustc owns that build. Keep the repository rule
  of at least 2 GiB free disk and allow safe cleanup after builds.
- Identify the actual cleanup entrypoint or external actor from process,
  timestamp and artifact evidence before changing scripts or configuration.
  If it is repo-owned, coordinate cleanup with the build lock or a scoped
  target owner; avoid a global cleanup disable or a second unbounded cache.
- A build failure caused by cache removal must be distinguished from a
  compiler, test or product failure in task evidence.

## Implementation and proof

- [ ] Inventory repo cleanup scripts, scheduled jobs, agent hooks and Cargo
      target configuration; correlate the observed timestamp and target loss
      with process or log evidence. Record unknowns explicitly.
- [ ] Reproduce or instrument one bounded debug build and cleanup window
      without deleting user data; identify the exact racing operation.
- [ ] Apply the smallest lock-aware or target-ownership fix at the proven
      cleanup owner, preserving free-space checks and safe manual cleanup.
- [ ] Verify two representative Cargo builds and one permitted cleanup
      sequence without target disappearance or a drop below 2 GiB free;
      document commands, disk readings and any environment-only limit.

## Acceptance

- The cleanup owner is evidenced, active target artifacts survive builds,
  and post-build cleanup remains safe and bounded.
- Required build gates pass; no product behavior or test assertion is
  changed to mask the original cache-race symptom.
