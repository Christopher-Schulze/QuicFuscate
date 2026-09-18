# TODO-971 — Wiedemann per-worker matrix/rhs scratch + lookup build

## Status
DONE

## Problem
`Decoder8::try_eliminate_wiedemann` (block-Wiedemann fallback for >32
queued equations) had two allocation/complexity hotspots per solve:

1. **Per-byte matrix + rhs allocation**: inside the Rayon byte loop, every
   byte index allocated `vec![vec![0u8; n]; equation_count]` plus a
   `vec![0u8; equation_count]` RHS — for a typical payload of ~1200 bytes
   that is ~1200 × (m × n) matrix allocations plus 1200 RHS vectors, all
   charged to `WIEDEMANN_MATRIX_RHS_ALLOCS` telemetry.
2. **O(m × n × k) coefficient lookup build**: `eq_coeff_lookup` nested-
   looped `for sid in unknowns { for j in 0..k { if source_id_for(j)==sid } }`
   — same anti-pattern fixed in the Gaussian path (TODO-970).

The byte-dependent matrix content is required: rows belonging to
equations shorter than `byte_idx` must be zero, and the post-solve
`valid` check reads the matrix. So the matrix cannot simply be hoisted —
but its *storage* can.

## Solution
- `matrix` and `rhs` moved into the `map_init` worker state
  `(WiedemannScratch, matrix, rhs)` — allocated once per Rayon worker
  (~8 allocations) instead of once per byte (~1200 × workers).
- Per byte: `rhs.fill(0)`; active rows restored from `eq_coeff_lookup`
  (`unwrap_or(0)` covers both `None` and stale values — one pass);
  inactive rows `fill(0)`. Identical matrix contents as before.
- `eq_coeff_lookup` now walks each coefficient row once and places
  entries via `unknowns.binary_search(&sid)` — O(m × k). Subtlety: the
  old code could produce `Some(0)` for a zero coefficient; the new code
  leaves `None`, which materializes as `0` in the matrix either way —
  identical output.
- `WIEDEMANN_MATRIX_RHS_ALLOCS` no longer increments per byte (the
  counter measured real allocations; they no longer occur).

## Verification
- `cargo test -p qf-fec` — 85/85 (local + Omega aarch64 Linux)
- `cargo clippy -p qf-fec --all-targets` — clean
- `cargo fmt --check` — clean
- `cargo bench --bench fec_pipeline --features benches -- wiedemann` —
  baseline: high_loss/128 ≈ 7.0 ms, high_loss/256 ≈ 181 µs
