---
id: TODO-495
title: QUIC padding direct writer hotpath
severity: LOW
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-486, TODO-492, TODO-494]
---

# TODO-495: QUIC padding direct writer hotpath

## Context

Broderick `connection_1rtt_stealth_compare` showed the real 1-RTT
`stream_send -> send -> recv` path still paid generic `Frame::Padding` encoding
overhead in every transport-padding branch. QUIC PADDING frames are simply zero
bytes, but the hot path constructed a `Frame::Padding` enum and routed through
generic `frames::to_bytes()`, which first called `wire_len()` and matched the
enum again.

## Desired Outcome

- Keep QUIC PADDING wire format identical.
- Preserve existing `frames::to_bytes(Frame::Padding)` behavior for callers.
- Let hot paths write padding bytes directly without generic frame dispatch.
- Improve real 1-RTT stealth-on send/receive timing on Broderick.
- Avoid UI, frontend, Docker, deployment manifests, or unrelated runtime changes.

## Implementation

- Added `frames::write_padding(len, out)`.
- Reused the helper from `frames::to_bytes(Frame::Padding)` so public frame
  encoding remains behaviorally identical.
- Replaced transport padding writes in `Connection` with direct helper calls:
  long-header padding, traffic-analysis defense padding, packet-normalize
  padding, legacy stealth padding, DPLPMTUD probe padding, and chaff padding.
- Added a focused unit test for the direct helper's write length, zero-fill
  behavior, untouched tail bytes, and buffer-too-short error.

## Verification

- Local: `cargo fmt --all` pass.
- Local: `cargo test --lib --features rust-tests test_write_padding_direct_helper` pass.
- Local: `cargo test --lib --features rust-tests test_roundtrip_padding` pass.
- Local: `cargo test --lib --features rust-tests test_padding_adaptive` pass.
- Broderick: `cargo test --lib --features rust-tests transport::frames::tests::` pass.
- Broderick: `cargo test --lib --features rust-tests test_padding_adaptive` pass.
- Broderick: `cargo bench --bench ci_regression --features benches -- 'connection_1rtt_stealth_compare|connection_1rtt_send_recv' --sample-size 30 --measurement-time 2` pass.

## Criterion Evidence

Broderick ARM/AArch64 `ci_regression` after direct padding writer:

| Case | Median | Result |
|------|--------|--------|
| `connection_1rtt_send_recv/payload_256B` | `5.51 us` | noise, about 0.61% faster |
| `connection_1rtt_send_recv/payload_1024B` | `7.14 us` | about 1.85% faster |
| `connection_1rtt_send_recv/payload_1400B` | `7.58 us` | about 2.21% faster |
| `connection_1rtt_stealth_compare/stealth_off` | `7.07 us` | about 1.62% faster |
| `connection_1rtt_stealth_compare/stealth_on` | `7.18 us` | about 2.23% faster |

## Notes

This is intentionally a narrow writer extraction, not a new frame abstraction.
The hot path now expresses the wire truth directly: QUIC PADDING is N zero
bytes.
