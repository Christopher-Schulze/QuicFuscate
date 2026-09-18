# TODO-965 — Feature-matrix verification and `rust-tests` repair

## Status
DONE

## Problem
The `AckRanges` SmallVec switch (TODO-957) changed `Frame::Ack.ranges` from
`Vec<(u64, u64)>` to `SmallVec<[(u64, u64); 8]>`. All default-feature check and
test runs passed, but the `scripts/tests/rust/*` integration targets are
gated behind the `rust-tests` feature and were never compiled during that
work — they kept `vec![...]` literals and `assert_eq!(ranges, vec![...])`
comparisons and failed with `E0308 mismatched types` under
`--features rust-tests` / `throughput,rust-tests`.

Root cause of the escape: the standard verification gates
(`cargo check --all-targets` without feature flags) do not build
feature-gated test targets, so a type change that is source-compatible for
all default targets can still break gated ones.

## Solution
- `scripts/tests/rust/rt-transport-frames-roundtrip.rs`: four `vec![...]`
  Ack-range literals → `smallvec::smallvec![...]`; the canonicalization
  assertion → `ranges.as_slice()`; the malformed-ranges table converted to
  `smallvec!` entries.
- `scripts/tests/rust/rt-security-suite.rs`: two `vec![...]` literals →
  `smallvec::smallvec![...]`; the replay-collapse assertion →
  `ranges.as_slice()`.
- `benches/ack_pipeline.rs`: `cargo fmt` normalization only.
- `smallvec` is already a dependency of the `quicfuscate` crate, so the
  integration tests can use `smallvec::smallvec!` without new deps.

## Feature matrix verified (all `cargo check -p quicfuscate --all-targets`)
| Feature set | Local (aarch64 macOS) | Omega (aarch64 Linux) |
|---|---|---|
| default | pass (TODO-957) | pass |
| throughput | pass | pass |
| stream_ring_buffer | pass | n/a |
| zero_copy_dgram | pass | n/a |
| rust-tests | pass | pass |
| throughput,zero_copy_dgram | pass | n/a |
| throughput,rust-tests | pass | n/a |
| zero_copy_dgram,rust-tests | pass | n/a |
| io_uring | n/a (Linux-only) | pass |
| io_uring,rust-tests | n/a (Linux-only) | pass |

`io_uring` is Linux-only and can only be exercised on Omega; its
aarch64/Linux check now passes as part of this matrix.

## Verification
- `cargo check -p quicfuscate --all-targets --features rust-tests` — clean
- `cargo check -p quicfuscate --all-targets --features throughput,rust-tests` — clean
- `cargo check -p quicfuscate --all-targets --features zero_copy_dgram,rust-tests` — clean
- `cargo test -p quicfuscate --features rust-tests --test rt-transport-frames-roundtrip` — 8/8
- `cargo test -p quicfuscate --features rust-tests --test rt-security-suite` — 26/26
- `cargo clippy -p quicfuscate --all-targets --features rust-tests` — clean
- `cargo fmt --check` — clean
- Omega: `cargo check --all-targets` for `io_uring`, `rust-tests`,
  `io_uring,rust-tests` — all clean on aarch64 Linux

## Lesson / gate note
Any type change to public frame/transport types must include at least one
`--features rust-tests` check, since those targets are the only consumers
that construct `Frame` values literally in test code. This check is now part
of the sweep verification set.
