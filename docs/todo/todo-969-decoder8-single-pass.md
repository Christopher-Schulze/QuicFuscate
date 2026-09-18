# TODO-969 — Decoder8/16 single-pass solve + SmallVec rejection evidence

## Status
DONE

## Problem
`Decoder8::try_solve_equation` and `Decoder16::try_solve_equation` ran two
full O(k) scans per attempt: one to subtract known sources and zero their
coefficients, then a second to count remaining unknowns (with a redundant
`known.contains_key` recheck per surviving coefficient — a coefficient
that survives subtraction is unknown by construction). Attempts run once
per queued equation per peeling pass. `Decoder4` already used the merged
single-pass form.

## Solution
Merged both passes in decoder8 and decoder16: while subtracting, a
non-zero coefficient that is not in `known` is counted directly as an
unknown. Multiple unknowns set a flag and keep subtracting (the partially
reduced equation is retained for later passes — identical semantics to the
old early-return, which also returned after the subtract pass had already
run to completion).

Effect: one O(k) pass instead of two. On degree-2 workloads the gain is
marginal (the old count pass early-exited after ~2 hits); on denser
systems the scan work halves.

## Measured evidence (fec_peeling/gf8_k256_linear_equation_traversal)
| Variant | Time | Criterion verdict |
|---|---|---|
| baseline | ~116 µs | — |
| + `SmallVec<[u8;256]>` coeffs | ~130 µs | +7% regression flag |
| + revert to `Vec<u8>` | ~133 µs | no change (p=0.47) |

Noise dominates at this scale; the merge is kept for halved scan work and
removed redundant lookups, not for a measured degree-2 win.

## Negative result kept in code
`SmallVec<[u8; 256]>` for `Equation8.coeffs` was implemented, benchmarked
and **reverted**: the struct grows to ~280 B and `try_peel_all` rotates
equations through `VecDeque::pop_front`/`push_back` every pass — trading a
per-packet heap alloc for ~280-byte memmoves per rotation is not a win.
The comment on `Equation8::coeffs` records this so it isn't retried.

## Verification
- `cargo test -p qf-fec` — 85/85 (local + Omega aarch64 Linux)
- `cargo clippy -p qf-fec --all-targets` — clean
- `cargo fmt --check` — clean
- `cargo bench --bench fec_pipeline --features benches -- fec_peeling` —
  numbers above
