---
id: TODO-498
title: FEC lazy source-buffer replay
severity: LOW
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-476, TODO-484, TODO-490, TODO-491, TODO-497]
---

# TODO-498: FEC Lazy Source-Buffer Replay

## Context

Broderick screening after TODO-497 showed that `fec_lazy_fast_path` still spent
microseconds in Normal no-loss receive. The root cause was in `LazyDecoder`:
even on clean systematic packets, the lazy path still forwarded every source
clone into the heavy decoder. That made clean receive pay decoder bookkeeping
cost before any gap or repair made recovery useful.

The lazy contract should be stricter: when no recovery can happen, keep only
bounded source context and stay away from the heavy decoder.

## Desired Outcome

- Preserve immediate forwarding of systematic packets to the QUIC stack.
- Avoid heavy decoder source ingestion on clean receive.
- Replay buffered source context only when a repair makes recovery useful.
- Keep source buffering bounded under sustained lossy systematic-only traffic.
- Preserve tail-loss recovery when repairs arrive after incomplete blocks.
- Avoid UI, frontend, Docker, Kubernetes, Helm, or unrelated runtime changes.

## Implementation

- Added `LazyDecoder::pending_sources` as bounded source context.
- Added `LazyDecoder::push_pending_source()` to cap source buffering by the
  active decoder block size.
- Changed clean systematic receive to buffer source clones instead of feeding
  the heavy decoder.
- Changed gap-without-repair receive to remain lazy because no recovery can
  advance without repair data.
- Changed gap-with-repair and tail-loss repair paths to replay buffered sources
  plus repairs into the heavy decoder before full recovery.
- Changed `AdaptiveFec::on_receive_into()` to move repair packets directly into
  the decoder instead of cloning packets that are never forwarded as originals.

## Verification

- Local: `cargo fmt --all -- --check` pass.
- Local: `cargo clippy --lib -- -D warnings` pass.
- Local: `cargo test --lib -- fec::` pass (`176 passed`).
- Local: `cargo test --lib` pass (`1637 passed`).
- Broderick: focused lazy decoder + sustained-load memory tests pass (`8 passed`).
- Broderick: `cargo bench --bench fec_pipeline --features benches --
  fec_lazy_fast_path` pass.

## Criterion Evidence

Broderick ARM/AArch64 `fec_lazy_fast_path`, TODO-497 baseline versus TODO-498
patch:

| Case | TODO-497 | TODO-498 | Result |
|------|----------|----------|--------|
| `zero_mode_passthrough` | `286.29 ns` | `285.14 ns` | neutral |
| `zero_mode_passthrough_reuse` | `272.81 ns` | `266.47 ns` | about 3.9% faster |
| `normal_mode_no_loss` | `4.30 us` noisy mean | `1.284 us` | materially faster, noise removed |
| `normal_mode_no_loss_reuse` | `3.388 us` | `1.244 us` | about 51% faster |

## Notes

The initial source-buffer patch correctly improved clean receive but tripped the
existing sustained-load memory test because source replay still woke the heavy
decoder on gap-only traffic. The final behavior intentionally treats a gap
without repair as non-recoverable until repair data arrives. This keeps the
decoder bounded under lossy systematic-only streams and matches the lazy
receive contract.
