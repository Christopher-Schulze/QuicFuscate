---
id: TODO-528
title: Prove Wintun native adapter and data-plane lifecycle
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-442, TODO-519, TODO-530, TODO-542]
---

# TODO-528: Prove Wintun Native Adapter and Data-Plane Lifecycle

## Why

Windows core and MSI production are native-proven, and the Wintun backend dynamically resolves the required DLL exports. No native privileged gate creates an adapter, verifies address assignment, transfers packets, exercises the kill switch, or proves that blocked reads terminate safely during concurrent close.

## Acceptance

- Build, test, and Clippy the exact `tun-windows` feature surface on native MSVC and retain the result as a required CI gate.
- Provision an authentic upstream Wintun DLL through a documented, integrity-checked test dependency without committing an opaque binary to the repository.
- Create a privileged adapter, verify configured name, MTU, IPv4/IPv6 state, and `tun_capabilities()` on Windows 10/11.
- Transfer bidirectional IP packets through a real Wintun session and complete an authenticated ping to a running QuicFuscate server.
- Prove Windows Firewall fail-closed and connected exceptions against real packet outcomes.
- Make close/read concurrency bounded and race-safe; adapter, session, and DLL handles must release once with no busy loop, use-after-close, panic, or leaked adapter.
- Pass full local Rust gates, native Windows CI, documentation/MAP/TODO truth, and preserve protected UI files.

## Completion Gates

- Supply-chain gate: the exact upstream Wintun artifact, source URL, version, hash, loading contract, and non-redistribution decision are documented and integrity-checked.
- Native data-plane gate: Windows 10 and 11 evidence proves adapter configuration, IPv4/IPv6 packets, authenticated server traffic, firewall block/allow outcomes, and exact capability reporting.
- Concurrency gate: forced close during blocked read, repeated open/close, failure injection, and process exit complete without race, busy loop, double close, use-after-close, panic, or leaked adapter.
- Release gate: `tun-windows` format, Clippy, tests, signed native artifact, exact SHA-256, cleanup inspection, protected UI diff, and owning-doc updates all pass.

## Sub-Tasks

- [ ] Audit the exact Wintun C signatures and handle lifetime before editing.
- [ ] Add native feature-enabled adapter, I/O, and shutdown tests.
- [ ] Add authenticated server and firewall E2E proof.
- [ ] Execute native Windows gates and inspect adapter cleanup.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-442 reconciliation. TODO-519 remains closed for core/MSI portability.
- TODO-522 removed the unsafe Windows `netsh` activation path from production use: broad Windows Firewall block rules override narrower endpoint and interface allow rules, so activation now fails closed with `NotSupported` instead of claiming protection. This task must implement the replacement through WFP and prove it on native privileged Windows before restoring the support claim.

## Deviations

None.
