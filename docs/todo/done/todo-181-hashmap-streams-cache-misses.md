# TODO-181: HashMap Stream Cache Locality at Scale

## Status
**DOCUMENTED** - Performance consideration comment added to `streams: HashMap<u64, Stream>` field in src/transport/connection.rs. Recommends slotmap or arena-based structure for >10k streams.

## Severity
LOW

## Context
Stream management uses `HashMap<u64, Stream>` which provides O(1) amortized lookup but poor cache locality when stream counts exceed ~10k. At high stream counts, hash table entries are scattered across memory, causing frequent cache misses during iteration and lookup. This becomes a measurable bottleneck under high-concurrency workloads.

- `src/transport/connection.rs:93`: `HashMap<u64, Stream>` for stream storage
- HashMap bucket chasing causes L1/L2 cache misses at scale
- Iteration over all streams (for timeout checks, cleanup) touches scattered memory
- Problem only manifests at >10k concurrent streams per connection

## Root Cause
HashMap was the natural first choice for stream lookup by ID. At low stream counts it performs well, but the hash-based memory layout degrades cache performance as the table grows and entries scatter across heap pages.

## Fix Plan
1. Benchmark current HashMap performance at 1k, 10k, 50k, 100k stream counts
   - Measure: lookup latency, iteration time, cache miss rate (perf stat)
2. Evaluate alternative data structures:
   - **Slot map** (slotmap crate): dense storage, stable keys, excellent cache locality
   - **Arena + index**: arena-allocated streams with u64 index, contiguous memory
   - **BTreeMap**: ordered, better locality than HashMap for iteration-heavy workloads
3. Implement the best-performing alternative behind a feature flag for A/B comparison
4. Benchmark the replacement at the same scale points
5. If improvement confirmed (>15% at 10k+ streams): replace HashMap, remove feature flag

## Acceptance Criteria
- Benchmark data at 1k/10k/50k/100k streams for both implementations
- Replacement demonstrates measurable improvement at >10k streams
- No regression at low stream counts
- Stream lookup API unchanged (transparent to callers)

## Dependencies
- Benchmark infrastructure (criterion)
- Potentially `slotmap` crate

## Affected Files
- `src/transport/connection.rs`
- `examples/microbench.rs` (add stream benchmark)
- `docs/documentation.md`
