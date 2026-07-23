---
id: TODO-545
title: Prove cipher reinstallation state safety
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: []
---

# TODO-545: Prove Cipher Reinstallation State Safety

## Why

`src/stealth/mod.rs` retains a TODO-269 safety note requiring cipher-specific mutable state to reset before key reinstallation. The invariant is security-critical and lacks one exhaustive test across every cipher/profile reinstall transition.

## Acceptance

- Enumerate every retained cover/data cipher implementation, installation caller, mutable counter/keystream state, and key-update/reconnect path.
- Define one typed reinstall contract that cannot reuse nonce, counter, keystream, buffered block, or prior-key state.
- Add adversarial tests for same-key reinstall, different-key reinstall, partial use, boundary counters, profile rotation, reconnect, and repeated transitions.
- Remove the unresolved source marker only after the invariant is proven and documented at the owning API.
- Pass full local Rust gates, native CI, security audit evidence, documentation/MAP/TODO truth, and preserve protected UI files.

## Completion Gates

- Inventory gate: every retained cipher, installer, caller, mutable counter/keystream state, reconnect, rotation, and key-update path is mapped with no unclassified reinstall route.
- Adversarial gate: same-key, different-key, partial-use, boundary-counter, profile-rotation, reconnect, repeated-transition, and failure-path tests prove no nonce, counter, keystream, buffer, or prior-key reuse.
- Evidence gate: the already-green local format, Clippy, test, and runtime-guardrail results remain reproducible; required native security CI and independent source audit complete for the exact commit.
- Artifact and truth gate: exact release artifact SHA-256, protected UI diff, owning API documentation, MAP/TODO evidence, and removal of the resolved marker all pass before closure.

## Sub-Tasks

- [x] Read every cipher state type, constructor, installer, and caller.
- [x] Model exact reset and uniqueness invariants before editing.
- [x] Implement minimal contract changes and adversarial tests.
- [~] Run local/native security gates.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-378 reconciliation. Informational references to completed tasks remain valid and are not cleanup targets.
- Retained TLS Cover ciphers are ChaCha20-Poly1305 and AES-128-GCM. Both are stateless AEAD objects over explicit `u64` record counters; mutable state is owned by `CryptoContext::{tls_cover_write_seq,tls_cover_read_seq}`. `TlsCoverProvider::new` is the only production installer through `qftls::CombinedProvider`; the rust-tests cipher harness is the only external test caller.
- Audit discovery: the old provider material was deterministic by profile and role, so separate connections reused the same key/IV and restarted at sequence zero. The lazy kind-only reinstall path could also reset counters without proving key uniqueness. Both conditions were security defects, not merely an unresolved comment.
- Current invariant: every provider uses fresh OS entropy plus profile/role-domain-separated HKDF; one typed `TlsCoverKeyMaterial` installation API owns both cipher variants; same active material preserves counters; fresh material retires the previous identity before resetting counters; retired material is rejected; record-counter exhaustion returns `AeadLimitReached`; frame generation never reinstalls lazily and fails closed if constructor-owned state disappears.
- Adversarial tests cover same-material reinstall after partial use, cross-cipher fresh rotation, retired-material rejection, repeated A/B/C transitions, fresh-context reconnect ownership, `u64::MAX` boundaries, profile/role domain separation, and per-provider material freshness. The runtime guardrail rejects the old installers, TODO marker, wrapping counters, or an incomplete typed/fresh-entropy contract.
- Local evidence: 40 targeted TLS Cover tests and the 3-test external TLS Cover cipher target pass; workspace all-target Clippy with `rust-tests` and warnings denied passes; workspace all-target tests with `rust-tests` pass with 1,684 library tests and zero failures; runtime guardrails pass with zero critical findings and zero warnings; formatting and diff checks pass. Native CI remains the open closure gate.

## Deviations

None.
