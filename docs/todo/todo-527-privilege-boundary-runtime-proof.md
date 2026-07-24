---
id: TODO-527
title: Complete irreversible privilege reduction and post-drop proof
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-441, TODO-515]
---

# TODO-527: Complete Irreversible Privilege Reduction and Post-Drop Proof

## Why

Server startup performs TUN, routing, socket, and audit initialization before switching to the `quicfuscate` UID/GID. The drop helper does not clear supplementary groups, set `PR_SET_NO_NEW_PRIVS`, explicitly clear capability sets, or verify the final real/effective identity and capabilities. The diagnostics CLI remains compile-time-only, and no root-start E2E proves that the open UDP and TUN descriptors carry traffic after the drop.

## Acceptance

- Resolve and validate the configured target user/group before privileged initialization; support explicit name or numeric identity without ambiguous precedence.
- Clear supplementary groups, set GID then UID, set `PR_SET_NO_NEW_PRIVS`, clear effective/permitted/inheritable/ambient capabilities, and verify the complete post-drop state on Linux.
- Fail closed with actionable diagnostics when required startup capabilities or the target identity are missing.
- Make `quicfuscate capabilities --json` report real/effective UID/GID, supplementary groups, relevant capability sets, target-user existence, and required-operation readiness.
- Prove on Omega that a root-started server completes privileged setup, irreversibly drops privileges, accepts an authenticated client, and transfers bidirectional TUN traffic through the already-open descriptors.
- Keep application-owned chroot and deprecated macOS sandbox profiles outside scope; document service-manager confinement as the platform contract.
- Add unit and privileged subprocess tests that cannot mutate the parent test process identity.
- Pass full local Rust gates, native CI, Omega proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Completion Gates

- State gate: subprocess evidence proves target UID/GID, empty expected supplementary groups, `no_new_privs`, cleared capability sets, and inability to regain privilege after initialization.
- Failure gate: unknown identities, missing capabilities, wrong syscall order, and partial initialization fail before service exposure with exact diagnostics and no parent-process mutation.
- Runtime gate: an exact-artifact root-started Omega server drops irreversibly, accepts an authenticated client, and carries bidirectional TUN traffic through retained descriptors.
- Release gate: full Rust gates, Linux native CI, artifact SHA-256, service teardown/residue inspection, protected UI diff, and owning-doc updates all pass.

## Sub-Tasks

- [ ] Define exact identity, capability, syscall order, and failure semantics from platform signatures.
- [ ] Implement irreversible Linux reduction and runtime capability reporting.
- [ ] Add subprocess and negative preflight tests.
- [ ] Execute root-start post-drop UDP/TUN proof on Omega.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-441 reconciliation. Service-manager filesystem confinement remains the canonical chroot/sandbox replacement.
- Primary surfaces: `src/privilege/drop.rs`, `src/privilege/mod.rs`, `src/main.rs`, `src/implementations/server/systemd.rs`, `scripts/install/quicfuscate-server.service`, and `scripts/tests/rust/integration/interface_capabilities.rs`.
- Scope lock: Linux process identity and capability reduction is the product change. macOS sandboxing, chroot, containers, and service-manager policy redesign stay outside scope; subprocesses must isolate irreversible identity mutations from the test runner.
- Evidence bundle: retain syscall order, starting/final UID/GID/groups/capability snapshots, negative preflight mutations, descriptor inventory, authenticated traffic result, inability-to-regain proof, service teardown, artifact hash, and host residue diff.

## Deviations

None.
