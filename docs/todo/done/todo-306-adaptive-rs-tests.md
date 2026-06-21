---
id: TODO-306
title: src/fec/adaptive_reed_solomon.rs - add unit tests for parameter adaptation
severity: MEDIUM
status: done
created: 2026-03-25
---

# TODO-306: AdaptiveReedSolomon Parameter Adaptation Tests

## Problem

`src/fec/adaptive_reed_solomon.rs` (94 LoC) has **zero tests**. It implements the adaptive FEC parameter selection logic that determines how much redundancy to add based on observed loss, latency, and bandwidth. Silent bugs here cause suboptimal FEC protection without any error signal.

## Key Public API

```rust
pub fn adapt_parameters(loss: f32, latency_ms: u32, bandwidth_mbps: f32)
pub fn current_parameters() -> FecParameters
```

## What Tests Are Needed

### 1. Loss threshold switching (4 tests)
```rust
fn low_loss_selects_minimal_redundancy()      // loss < 0.05 -> base k, n
fn moderate_loss_increases_redundancy()       // 0.05..0.15 -> medium overhead
fn high_loss_triggers_gf16_switch()           // loss > 0.30 -> GF(2^16)
fn extreme_loss_caps_at_max_overhead()        // loss = 1.0 -> capped, no panic
```

### 2. Bandwidth-aware clamping (2 tests)
```rust
fn low_bandwidth_limits_max_n()              // 0.1 Mbps -> N is capped to avoid overload
fn high_bandwidth_allows_full_redundancy()   // 100 Mbps -> N uncapped
```

### 3. Latency-driven adaptation (2 tests)
```rust
fn high_latency_reduces_n_for_quick_repair() // latency > 200ms -> smaller n
fn low_latency_allows_larger_n()             // latency < 10ms -> n uncapped
```

### 4. Parameter stability (2 tests)
```rust
fn repeated_calls_same_input_stable_output() // idempotent
fn parameter_update_reflected_in_current()   // adapt -> current_parameters() matches
```

**Total: ~10 tests**

## Completion Criteria

- All 10 tests in `#[cfg(test)]` in adaptive_reed_solomon.rs or fec/tests.rs
- Tests verify actual threshold behavior (not just "runs without panicking")
- Clippy GREEN, `cargo test --lib` passes
