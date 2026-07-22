---
id: TODO-524
title: Prove interleaved FEC mapping and random plus burst recovery
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-433, TODO-521]
---

# TODO-524: Prove Interleaved FEC Mapping and Random Plus Burst Recovery

## Why

All decoder families now use depth-aware coefficient-to-source-ID arithmetic, but the legacy task's exact proof never landed. Many recovery tests still force interleaving off, and there is no deterministic 1,000-packet integrity gate for 5% random loss or four-of-sixteen burst loss with interleaving enabled.

## Acceptance

- Add exact mapping tests for Decoder8, Decoder16, and Decoder4 in interleaved and non-interleaved modes.
- Add deterministic 1,000-packet interleaved recovery gates for 5% random loss and four consecutive losses per sixteen packets.
- Assert 1,000/1,000 unique deliveries, zero duplicates, byte-exact payload integrity, and bounded recovery latency.
- Remove interleave-off workarounds from tests whose production contract requires the default interleaved path; retain explicit off-mode tests only as regression coverage.
- Run the interleaved random/burst matrix locally and on Omega with real runtime loss injection where applicable.
- Pass full local Rust gates, FEC benchmarks/soaks relevant to the changed path, native CI, documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [ ] Verify encoder/decoder window and ID invariants before editing.
- [ ] Add exact family-level mapping and integrity tests.
- [ ] Add deterministic random/burst E2E recovery gates.
- [ ] Execute local, native, and Omega performance/correctness evidence.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-433 reconciliation. No product code changed during classification.

## Deviations

None.
