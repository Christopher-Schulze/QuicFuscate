---
id: TODO-962
title: `benches/ack_pipeline.rs`: criterion evidence for the alloc-free ACK path
status: DONE
created: 2026-09-18
---

# TODO-962 - `benches/ack_pipeline.rs`: criterion evidence for the alloc-free ACK path

## Status
DONE

## Purpose
Quantify the hot paths made allocation-free by TODO-956..961. Until this
suite existed, the ACK pipeline (parse -> recovery -> outcome -> emit) had no
criterion coverage - `benches/` only carried `fec_pipeline`,
`dns_forwarding`, `fingerprint_normalizer`, and `ci_regression`.

## Coverage
- `recovery_ack_steady/{8,64,256}` - one `on_packet_sent_in_space` +
  `on_ack_received` per iteration over a constant window; exercises
  `acked_scratch`/`lost_scratch` reuse and `SmallVec` `AckOutcome`.
- `recovery_ack_loss_64` - 63-packet loss detection on a cold Recovery
  (via `iter_batched`, setup excluded).
- `pnspace_ack_emit/{8,64}` - `peek_ack_at` range construction; sets
  `ack_elicited` explicitly (the transport owns that flag) so the real emit
  path is measured, not the `None` fast path.
- `frame_ack_parse/{1,8,64}` - `frames::from_bytes` of a wire ACK.
- `frame_ack_emit/{1,8,64}` - `frames::to_bytes` of `Frame::Ack`.

## Measured (release builds)
| Bench | Blocks/Window | macOS arm64 | Omega aarch64 Linux |
|---|---|---|---|
| recovery_ack_steady | 8 / 64 / 256 | 79-81 ns | 164-166 ns - flat |
| recovery_ack_loss_64 | 63 lost | ~1.54 us | ~2.90 us |
| pnspace_ack_emit | 8 / 64 | 24 ns / 330 ns | 60 ns / 579 ns |
| frame_ack_parse | 1 / 8 / 64 | 42 / 184 / 1070 ns | 138 / 540 / 3390 ns |
| frame_ack_emit | 1 / 8 / 64 | 91 / 277 / 1820 ns | 262 / 848 / 3660 ns |

Flat steady-state timing across a 32x window growth confirms the O(1)
scratch-reuse claim on both architectures; <=8-block frames (the common
case) carry zero heap traffic.

## Run
```
cargo bench --features benches --bench ack_pipeline
```

## Notes
- Criterion baselines live under `target/criterion/` - re-run after future
  ACK-path changes for regression evidence.
