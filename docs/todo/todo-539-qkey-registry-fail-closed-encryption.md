---
id: TODO-539
title: Make QKey registry encryption fail closed
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-458, TODO-526]
---

# TODO-539: Make QKey Registry Encryption Fail Closed

## Why

The QKey registry has a ChaCha20-Poly1305 file format, but decryption failure can be treated as plaintext and encryption failure can write plaintext. Missing keys, wrong keys, and corrupt files are not typed startup failures, and key ownership is not zeroizing.

## Acceptance

- Define a versioned authenticated registry envelope and typed outcomes for plaintext, encrypted, missing key, wrong key, corruption, unsupported version, and I/O failure.
- Support a zeroizing master-key owner from environment or protected file and a production KDF when passphrases are accepted; never log secrets.
- Never write plaintext after encryption is configured and never parse failed ciphertext as plaintext.
- Migrate plaintext atomically with backup/recovery guarantees, define explicit compatibility policy, and support crash-safe old-key/new-key rotation.
- Prove no plaintext hashes in ciphertext, tamper/wrong/missing-key rejection, migration, rotation, permissions, zeroization boundaries, and failure atomicity.
- Pass local Rust gates, native CI, Omega file/process proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Completion Gates

- Format gate: versioned envelope vectors cover valid data, tamper, truncation, unsupported version, wrong/missing key, permissions, and I/O failure without plaintext fallback.
- Migration gate: plaintext migration and old-key/new-key rotation are crash-safe, atomic, recoverable, and proven across every injected interruption point.
- Secrecy gate: scans and tests prove no plaintext token/hash leakage in ciphertext, logs, temporary files, backups, process arguments, or retained non-zeroizing owners.
- Release gate: local Rust gates, native CI, exact-artifact Omega file/process/restart proof, SHA-256, residue inspection, protected UI diff, and owning-doc updates all pass.

## Sub-Tasks

- [ ] Map registry startup, persistence, admin mutation, key sources, and error surfaces.
- [ ] Design the versioned envelope, zeroizing key owner, migration, and rotation transaction.
- [ ] Implement fail-closed behavior and exhaustive adversarial tests.
- [ ] Execute local, native, and Omega evidence.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-458 reconciliation. ChaCha20-Poly1305 is retained unless source review proves a reason to change AEAD.

## Deviations

None.
