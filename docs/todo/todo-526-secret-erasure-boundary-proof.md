---
id: TODO-526
title: Close retained secret erasure boundaries
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-440, TODO-516, TODO-521]
---

# TODO-526: Close Retained Secret Erasure Boundaries

## Why

AEAD wrapper keys, AES-GCM schedules, MORUS fields, locked memory-pool blocks, and process memory locking are implemented. The AEGIS wrapper drop path does not explicitly clear initialized cipher state, and raw QKey token strings plus decoded bytes survive hashing in ordinary allocations. Existing tests prove crypto behavior, not failable erasure of every retained secret representation.

## Acceptance

- Zeroize AEGIS L/X4/X8 wrapper keys, IVs, and initialized derived cipher state on every drop path without weakening SIMD dispatch or adding hot-path work.
- Keep raw QKey token strings and decoded binary tokens inside zeroizing owners from parse through hash/verification; stored identifiers and hashes remain non-secret typed values.
- Audit TLS and QKey authentication owners for duplicate raw-secret copies and remove or wrap every retained copy in the touched paths.
- Add failable erasure tests that observe the owned memory before deallocation without reading freed memory or relying on allocator reuse.
- Preserve constant-time authentication comparison, full crypto correctness, TODO-516 memory-lock evidence, and benchmark guardrails.
- Pass full local Rust gates, native CI, documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [ ] Map exact secret ownership and drop order for AEGIS, QKey parsing, registry insertion, and authentication.
- [ ] Implement minimal zeroizing owners and derived-state clearing.
- [ ] Add failable erasure and crypto regression tests.
- [ ] Execute correctness, Clippy, native, and performance gates.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-440 reconciliation. TODO-516 remains closed for memory locking.

## Deviations

None.
