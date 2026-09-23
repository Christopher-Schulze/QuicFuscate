---
id: TODO-970
title: Gaussian elimination hot path acceleration (Decoder8/16)
status: DONE
created: 2026-09-18
---

# TODO-970 - Gaussian elimination hot path acceleration (Decoder8/16)

## Status
DONE

## Problem
`Decoder8::try_eliminate_unmeasured` (Gaussian fallback, reached per
repair packet when peeling stalls) had three nested-scan hotspots.
`Decoder16`'s Gaussian elimination had the same patterns and received
the same fixes in commit `73ed3c8`.

1. **Matrix build O(m x u x k)**: for every (row, unknown-column) cell it
   linearly scanned all `k` coefficient indices to find the `j` mapping to
   that unknown's source id. At k=256, m=u=128: ~4M iterations per solve.
2. **RHS build O(min_len x k)**: for every payload byte it rescanned all
   `k` coefficients and did a scalar `gf_mul_table` lookup per hit -
   ~300k table lookups per equation at min_len~1200.
3. **`yb[row].clone()` per (pivot x eliminated row)**: each pivot pass
   cloned the min_len-byte RHS row for *every* eliminated row -
   ~u x m clones ~ 20 MB of churn at u=m=128, min_len~1200. The follow-up
   update loop then did byte-wise `gf_mul_table` multiplication.

## Solution
1. **Matrix build**: iterate each equation's coefficient row once, place
   non-zero entries via `unknowns.binary_search(&sid)` (the list is
   BTreeSet-sorted) - O(m x k) with `source_id_for` injectivity making
   the mapping exact.
2. **RHS build**: copy `eq_data` into the row once, then for each non-zero
   coefficient `gf_mul_scalar_slice(cj, &kd[..sl], &mut yb[i][..sl])` -
   SIMD XOR-accumulation over the whole row, O(min_len x nnz).
3. **Pivot elimination**: `yb.split_at_mut(row)` + `split_at_mut(1)`
   borrows the pivot RHS row once while other rows mutate - zero clones -
   and the per-row update uses `gf_mul_scalar_slice` (one SIMD pass)
   instead of a byte-wise `gf_mul_table` loop.

## Correctness notes
- Matrix contents are bit-identical: non-zero coefficients post-solve are
  exactly the unknowns, so every `binary_search` hit lands where the old
  scan did; misses correspond to known sids that belong in RHS, not in A.
- RHS rows are bit-identical: `gf_mul_scalar_slice` XOR-accumulates
  `coeff x src` over the row, which is exactly `rhs ^= cj * kd[b]` per
  byte, and XOR accumulation is commutative across coefficients.
- `split_at_mut` yields three disjoint borrows (`yb_lo`, `yb_pivot`,
  `yb_hi`); `r_idx < row` indexes `yb_lo`, `r_idx > row` indexes
  `yb_hi[r_idx - row - 1]` - same rows as before.
- `ab = a.clone()` and `pivot_row_snapshot` remain - required for
  correctness (in-place pivot mutation vs. read of the original row).

## Verification
- `cargo test -p qf-fec` - 85/85 (local + Omega aarch64 Linux; decoder16
  changes verified in `73ed3c8` with 85/85 on both)
- `cargo clippy -p qf-fec --all-targets` - clean
- `cargo fmt --check` - clean
