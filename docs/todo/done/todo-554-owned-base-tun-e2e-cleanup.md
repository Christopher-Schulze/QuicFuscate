---
id: TODO-554
title: Make the base TUN E2E harness own its process cleanup
severity: CRITICAL
phase: S
priority: P0
status: DONE
created: 2026-07-23
depends_on: []
---

# TODO-554: Make the Base TUN E2E Harness Own Its Process Cleanup

## Why

Three otherwise-successful exact-artifact Omega runs completed TLS, MASQUE, and five TUN pings with zero loss, but the harness returned `137` or SSH `255`. Its global `pkill -9 -f quicfuscate` cleanup matched the parent runner whenever an absolute source path or lock name contained `quicfuscate`. The same command could terminate an unrelated runtime on a shared host.

## Acceptance

- Capture the exact server and client child PIDs started by `scripts/tests/tun-e2e-netns.sh`.
- Kill and reap only those owned child processes during success, failure, or shell exit.
- Refuse to start when an existing `quicfuscate` process or an unowned `ns-srv`/`ns-cli` namespace is present.
- Preserve `QF_E2E_KEEP_ON_FAIL=1`, diagnostics, lock serialization, TLS/MASQUE behavior, and zero-loss TUN acceptance.
- Add a failable runtime guardrail against broad QuicFuscate process reapers returning to this harness.
- Preserve all protected UI files and make no unrelated Omega changes.

## Completion Gates

- Static gate: `bash -n`, runtime guardrails, TODO consistency, and exact source review prove PID capture, scoped cleanup, exit trapping, and fail-closed preflight.
- Isolation gate: a deliberately unrelated process whose command line contains `quicfuscate` survives the harness cleanup.
- Live gate: two sequential runs with the exact ARM64 artifact each return zero, complete TLS on both peers, open MASQUE, deliver five of five TUN pings, and leave no product process or test namespace.
- Native gate: exact-commit CI, Clippy Matrix, and required Release Build jobs pass.
- Truth gate: exact commit, run IDs, artifact and binary SHA-256 values, protected UI diff, and Omega evidence path are documented before closure.

## Sub-Tasks

- [x] Reproduce and isolate the parent-runner collision.
- [x] Replace global process matching with exact child ownership.
- [x] Add static regression gates; prove unrelated-process survival live.
- [x] Prove two clean exact-artifact Omega runs and zero residue.
- [x] Flush documentation and close only with exact evidence.

## Notes

- The product path itself passed on all three diagnostic runs: client/server TLS completion, MASQUE flow establishment, and `5/5` TUN pings with `0%` loss.
- Diagnostic evidence is isolated under `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-todo553-362-545-f5d1f69/evidence/failed-run1-wrapper-collision*`.
- The harness now captures and reaps exact child PIDs, tracks whether it created the test namespaces, installs an exit cleanup trap, and refuses pre-existing product processes or test namespaces before touching certificates or runtime state.
- Local static evidence: both edited scripts pass `bash -n`; runtime guardrails pass with zero critical findings and zero warnings; final TODO consistency scans 193 active detail files with zero violations; diff integrity and protected UI checks pass.
- Full local evidence: workspace all-target Clippy with `rust-tests` and warnings denied passes; workspace all-target tests with `rust-tests` pass with 1,795 library tests and every binary, integration, property, security, TLS Cover, and example target green. The 3.6 GiB build cache was removed after the run and free space recovered from 2.0 GiB to 5.3 GiB.
- Exact implementation checkpoint `f7af807` is represented by source archive SHA-256 `611bcfa0a0194951fb25da5e83c304b86f8c2847d9cb6bb0f737e627a28bad9a`. Final native closure checkpoint `30eac28` passed CI run `30020551603`, all eight jobs in Clippy Matrix run `30020553909`, and every Release Build job in run `30020551548`.
- Exact ARM64 artifact `8569137110` contains `quicfuscate-server-bundle-linux-arm64-0.4.3-20260723_152933.tar.gz`. Direct clean-directory verification passes; bundle SHA-256 is `e216d21b6b9a03838d6914278166809c5ded2313983504fbc98a8ddfb78d84ec`, sidecar SHA-256 is `60ba542e983dece5be7c865bef7d6ccc4bcf02c80757d951a5fabac87bbc4a0d`, and packaged binary SHA-256 is `8b6ff22e0f410ac6cd5c553786bd5c7584d99c6da0f346a46d9e8839a9e1c2b1`.
- Omega evidence is isolated under `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-todo554-553-362-545-f7af807/evidence`. Two sequential runs of that exact binary each returned zero, completed TLS on client and server, opened the H3/MASQUE flow, delivered `5/5` TUN pings with `0%` loss, and retained validated evidence checksums.
- A deliberately unrelated process with `quicfuscate-sentinel` in its command line survived both cleanup passes. After each run, exact product processes, the sentinel after its explicit PID-scoped stop, `ns-srv`, `ns-cli`, shared logs, admin socket, certificate temporaries, and generated source runtime state were absent; retained logs, test certificates, and `qkeys.json` live only inside the evidence directories.
- `docs/MAP.md` now owns the base-harness lifecycle wiring and explicitly routes the four specialized FEC/loss harness migrations to TODO-555. No protected Svelte, Tauri, shared UI/theme, or generated web-admin path changed.

## Deviations

None.
