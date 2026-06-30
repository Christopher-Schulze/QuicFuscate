---
id: TODO-426
title: FEC memory pressure and resource efficiency tests
severity: MEDIUM
phase: "F"
priority: P1
status: DONE
created: 2026-06-29
depends_on: ["TODO-423"]
---

# TODO-426: FEC Memory Pressure & Resource Efficiency Tests

## Problem

No existing test verifies FEC behavior under memory pressure or measures resource efficiency.
The FEC module uses `Arc<MemoryPool>` for buffer allocation, but there are no tests for:

1. Memory pool exhaustion (what happens when the pool is empty?)
2. Unbounded queue growth (FEC repair queue, emitted_ids, emitted_order)
3. Memory usage scaling with packet rate and loss rate
4. Buffer recycling effectiveness under sustained load
5. Memory leak detection during mode transitions

## Goal

Verify FEC is resource-efficient at every load level and degrades gracefully under memory
pressure. In extreme loss scenarios, FEC may use more resources — but it must never leak,
never grow unbounded, and never crash under memory pressure.

## Implementation Plan

### 1. Memory pool exhaustion test (Rust unit test)

```rust
#[test]
fn test_fec_memory_pool_exhaustion_graceful() {
    // Create FEC with a tiny memory pool (4 blocks)
    // Feed 1000 packets through on_send
    // Verify: no panic, no OOM, repair packets dropped gracefully when pool empty
    // Verify: systematic packets always forwarded (never dropped for repair)
}
```

### 2. Unbounded queue growth test (Rust unit test)

```rust
#[test]
fn test_fec_emitted_order_bounded() {
    // Feed 100k packets through on_send
    // Verify: emitted_order.len() <= 4096 (bounded by existing cap)
    // Verify: emitted_ids.len() <= 4096 (bounded by emitted_order)
    // Verify: no unbounded Vec growth in any internal queue
}
```

### 3. Memory usage scaling test (Rust integration test)

```rust
#[test]
fn test_fec_memory_scales_with_load_not_unbounded() {
    // Run 10k packets at 0% loss → measure memory
    // Run 10k packets at 50% loss → measure memory
    // Verify: memory at 50% loss is <5x memory at 0% loss (not 50x)
    // Verify: memory returns to baseline after run (no leak)
}
```

### 4. Buffer recycling effectiveness test

```rust
#[test]
fn test_fec_buffer_recycling_rate() {
    // Feed 10k packets through on_send + on_receive cycle
    // Track: pool.alloc() calls vs pool.free() calls
    // Verify: recycling rate >90% (fewer than 10% new allocations)
    // Verify: pool.in_use stays bounded (< pool.capacity)
}
```

### 5. Mode transition memory leak test

```rust
#[test]
fn test_fec_mode_transition_no_memory_leak() {
    // Force 100 mode transitions (Zero → Extreme → Zero → ...)
    // Measure memory before and after
    // Verify: memory delta < 1KB (no leak from transition_encoder/decoder cleanup)
}
```

### 6. Sustained load memory stability test (Rust integration test)

```rust
#[test]
fn test_fec_sustained_load_memory_stable() {
    // Run 100k packets through on_send + on_receive at 10% loss
    // Sample memory every 10k packets
    // Verify: memory does not grow monotonically (flat or oscillating is OK)
    // Verify: no OOM after 100k packets
}
```

### 7. Resource efficiency telemetry verification

```rust
#[test]
fn test_fec_resource_telemetry_accurate() {
    // Run known workload
    // Verify: FEC_EMITTED_QUEUE, FEC_EMITTED_ORDER_DEPTH, FEC_EMITTED_UNIQUE
    //         match actual queue lengths
    // Verify: MEM_POOL_IN_USE matches actual pool usage
    // Verify: RS_ENC_TIME_NS and RS_DEC_TIME_NS are plausible (>0, <1ms per packet)
}
```

## Files to Create
- `src/fec/resource_tests.rs` — all 7 tests above

## Acceptance Criteria
- Pool exhaustion: no panic, systematic packets always forwarded
- Queue growth: all internal queues bounded (emitted_order ≤ 4096, no unbounded Vecs)
- Memory scaling: 50% loss memory < 5x zero-loss memory
- Buffer recycling: >90% recycling rate under sustained load
- Mode transitions: zero memory leak after 100 transitions
- Sustained load: memory stable (not monotonically growing) over 100k packets
- Telemetry: all FEC resource metrics match actual values

## Resource Budget
| Scenario | Max Memory | Max CPU | Notes |
|----------|-----------|---------|-------|
| Zero mode, 10k pps | <1MB | <1% | Passthrough, no repair |
| Normal mode, 10k pps, 5% loss | <10MB | <10% | Steady state |
| Extreme mode, 10k pps, 50% loss | <100MB | <50% | Heavy recovery, acceptable |
| Mode transition | +0MB | +5% transient | No persistent allocation |
| 100k packets sustained | <2x steady-state | stable | No leak, no growth |
