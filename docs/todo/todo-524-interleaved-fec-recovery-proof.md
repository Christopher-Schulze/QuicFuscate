---
id: TODO-524
title: Prove interleaved FEC mapping and random plus burst recovery
severity: CRITICAL
phase: S
priority: P0
status: DONE
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

- [x] Verify encoder/decoder window and ID invariants before editing.
- [x] Add exact family-level mapping and integrity tests.
- [x] Add deterministic random/burst E2E recovery gates.
- [x] Execute local, native, and Omega performance/correctness evidence.
- [x] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-433 reconciliation. No product code changed during classification.
- Verified the encoder invariant: GF4, GF8, and GF16 repairs carry the maximum source ID in the block window as `id`; interleaving spaces source IDs by `depth` and tags the lane in repair `seq`.
- Found a residual non-interleaved GF4 defect: `Decoder4::source_id_for()` mapped forward from the maximum window anchor instead of mapping the preceding `k` source IDs like GF8/GF16.
- The first exact gates exposed silent GF8 corruption: arithmetic repair rows were rank-deficient for the four-of-sixteen loss pattern, and more than 32 retained equations selected an unvalidated Wiedemann result that materialized zero-filled sources.
- GF8 bounded blocks now use Cauchy repair rows; GF8/GF16 removed the ambiguous normalized-anchor fallback, require full-rank pivots, retire solved equations, and validate every Wiedemann byte solution against the original system before Gaussian fallback.
- Native Windows CI exposed a second integrity defect: the x86 GFNI slice path multiplied in Intel's fixed AES 0x11B field while the FEC wire contract uses 0x11D. Canonical GF8 now excludes raw GFNI multiplication and retains the 0x11D nibble-LUT/scalar paths; the runtime guard rejects its return.
- Local targeted evidence: all three family mapping tests pass; the repeated ten-window lane test passes; the repeated interleaved 640-packet burst test passes; both 1,000-packet exact E2E gates pass; the complete `fec::e2e_tests` module passes 19/19.
- Local full evidence: workspace all-target Clippy with `rust-tests` and warnings denied passes; workspace all-target tests pass with 1,691 library tests and every integration/example target green; the complete FEC module passes 187/187; TODO consistency reports 192 files and zero violations; runtime guardrails report zero critical findings and zero warnings. The Criterion GF(256) matrix benchmark reports 1.1030 us for 4x4, 4.6060-4.6078 us for 8x8, and 18.016-18.423 us for 16x16 on this Apple Silicon host. The bench-only build emits one pre-existing release-only dead-field warning for `RustlsProviderImpl::verify_peer`, outside this FEC change.
- Closure evidence on `15570abf772766c76959f6aae6ba16b2b9c26fd7`: both deterministic 1,000-packet interleaved gates pass inside the 1,717-test full workspace run with unique byte-exact delivery, zero duplicates, and bounded latency. The exact native ARM64 artifact then passes Omega's 1,000-packet uniform 0/5/10/25% netem matrix (`4 passed, 0 failed`) and the 1,000-packet correlated-burst matrix (`2 passed, 0 failed`), with final residual burst loss of 2% in both scenarios. CI `29915916296`, Clippy Matrix `29915916332`, and native artifact job `88909647690` are green; protected UI files remain unchanged.

## Deviations

None.
