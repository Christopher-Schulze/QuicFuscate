---
id: TODO-1099
title: Restrict private packet key dump to owned proof artifacts
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1029, TODO-1084]
---

# TODO-1099: Private packet key-dump proof boundary

## Why and evidence

TODO-1029 added `dump_private_packet_install` in
`src/transport/connection/api.rs` to the normal product build. Setting
`QUICFUSCATE_PRIVATE_KEY_DUMP` makes it append write/read packet keys, IVs,
packet boundaries, and `PrivateEpochSchedule::wire_proof_material()`'s root
to an arbitrary path via `OpenOptions::create(true).append(true).open()`.
That call supplies no explicit 0600 mode, exclusive creation, symlink check,
or trusted directory contract. Under a permissive umask, newly created files
may be readable beyond the owner; an existing path can be appended to, and
an existing symlink can be followed. `scripts/tests/tun-e2e-netns.sh` passes
one `QF_E2E_PRIVATE_DUMP_FILE` to both peer processes, so evidence ownership
and record separation depend on concurrent appends. The hook is opt-in by
environment; this is an avoidable secret-export surface, not evidence that
keys have already leaked.
The Devin CLI `lake-rooster` history contains a diagnostic tool result at
node 11478 with raw ephemeral packet key/IV hex. That proves local transcript
retention of traffic secrets, not external disclosure. The bytes must never
be copied into tracker files or audit reports.
Commit `22164456` additionally retained the standard header-protection key
inside analyzer `DirectionKeys` solely to print its raw hex value on a failed
1-RTT open (`src/bin/qf-aead-wire-proof.rs`). An error report can therefore
copy a traffic secret into terminal capture, CI logs or pasted diagnostics.

## Target contract

- Normal release/default builds contain no private packet key-dump call or
  environment hook. A non-default, explicit `wire-proof` diagnostic feature
  may compile it for the controlled TODO-1029 verifier. The feature is never
  silently enabled by `--all-features` release packaging; if the workspace
  uses all-features for verification, distinguish test builds from release
  artifacts without breaking that gate.
- The proof runner reserves an owned directory and distinct client/server
  dump paths atomically before starting either process. New files are
  regular, exclusive, mode 0600; parent directories are mode 0700 and cannot
  be replaced by symlinks. Existing paths, including dangling symlinks, fail
  before any key is emitted. Do not overwrite or auto-delete user evidence.
- Each dump record carries a role, connection/session identifier, epoch and
  format version, and is written as one bounded atomic record or by one
  writer. If multiple connections share a process, records cannot be
  assigned to the wrong pcap. Never print key bytes in logs, failure output,
  task docs, or benchmark metadata.
- Remove the analyzer's raw header-protection key from failure output and
  any storage maintained solely for that output. A non-secret key
  fingerprint, version, sample and packet number can identify the attempted
  key without revealing it; bound diagnostic volume as well.
- Treat the existing Devin transcript and copied terminal captures as
  sensitive evidence under the repository's retention policy. Do not
  rewrite or delete user-owned history as part of this task; prevent future
  diagnostic commands and failed-proof paths from echoing key/IV/root bytes.
- Prefer exporter-derived per-epoch proof material to a long-lived schedule
  root when the analyzer can prove the same owner without the root. If the
  root is genuinely required for future epochs, limit retention to the
  exact run and record that scope. Preserve the packet-boundary proof, with
  analyzer input explicitly naming both role files.

## Implementation and proof

- [ ] Trace feature/config gates, all call sites of
      `dump_private_packet_install` and `wire_proof_material`, rustls
      `SSLKEYLOGFILE`, E2E runner and analyzer file parsing. Confirm the
      deployed build recipe and the smallest diagnostic compilation gate.
- [ ] Remove the dump hook from default/release product compilation, add
      explicit diagnostic build invocation, and make the runner refuse a
      binary built without the diagnostic hook when proof is requested.
- [ ] Reserve artifact directory and per-role files exclusively with
      platform-appropriate no-follow and owner-only permissions. Verify mode
      and inode identity before/after the run; handle partial writes without
      mixing records. Keep existing paths byte-identical on failure.
- [ ] Update analyzer to bind records to exact role/session/pcap and reject
      duplicate, truncated, mixed or stale records. Remove raw key printing
      and verify failed-packet diagnostics and manual proof commands contain
      no secret bytes. Re-run private and standard control proof under
      TODO-1029's acceptance contract.
- [ ] Test restrictive/permissive umask, symlink/dangling symlink, existing
      file, concurrent peers, multiple connections, interrupted writer,
      missing diagnostic feature, and default binary with env variable set.
      Inspect the build artifact for absence of diagnostic behavior.
- [ ] Correct TODO-1029 and security/product docs to state the exact
      diagnostic feature and artifact sensitivity without including keys.

## Acceptance

- Default/release product binaries never emit private packet keys for any
  environment setting. The explicit proof build writes only to owned 0600
  regular files in an owned 0700 directory and never follows symlinks or
  appends to a pre-existing artifact.
- Analyzer attribution is exact for both peers and every tested connection;
  malformed/colliding input fails rather than producing a private-AEAD
  verdict. No secret material appears in repository-tracked artifacts.
- Existing TODO-1029 private-owner and standard-control conclusions are
  reproducible through the gated diagnostic path, subject to TODO-1095's
  corrected QUIC framing proof.
