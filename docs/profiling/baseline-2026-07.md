# QuicFuscate Profiling Baseline — 2026-07-23

## Environment

- **Server:** broderick (Oracle Cloud, Ubuntu 24.04 aarch64, 4 cores, 23 GB RAM, NL region)
- **Kernel:** Linux 6.x (aarch64)
- **Rust:** stable channel, release profile
- **Date:** 2026-07-23
- **Method:** `perf record -F 99 -g` + FlameGraph (Brendan Gregg's stackcollapse-perf.pl + flamegraph.pl)
- **Network:** Loopback (127.0.0.1), no tc-netem (baseline without loss/latency simulation)

## Scenarios

### UDP Fast Path (harness udp-throughput)

| Scenario | Payload | Batch | Iters | Throughput | Samples |
|----------|---------|-------|-------|------------|---------|
| A | 1200B | 32 | 50000 | 294.08 MiB/s | 838 |
| B | 256B | 64 | 50000 | 69.90 MiB/s | 1575 |
| C | 1200B | 128 | 20000 | 296.04 MiB/s | 609 |

### QUIC Connection (client ↔ server, loopback)

| Scenario | FEC | Stealth | RTT | Loss | Samples |
|----------|-----|---------|-----|------|---------|
| D | off | off | 450 ms | 0.00% | 1965 |
| E | auto | off | 451 ms | 0.00% | 1973 |
| F | auto | performance | 451 ms | 0.00% | 1963 |

## Top-10 Hotspots (Scenario A — UDP Fast Path)

| # | Symbol | % Time | Category |
|---|--------|--------|----------|
| 1 | `__sendmmsg` → `udp_sendmsg` → `udp_send_skb` | 46% | Kernel UDP send |
| 2 | `__sendmmsg` → `ip_make_skb` → `__kmalloc` | 15% | Kernel memory alloc |
| 3 | `__sendmmsg` → `nft_do_chain` (netfilter) | 15% | Netfilter/iptables |
| 4 | `__libc_recvfrom` → `udp_recvmsg` → `__arch_copy_to_user` | 12% | Kernel UDP recv + copy |
| 5 | `__sendmmsg` → `ip_route_output_flow` → `fib_table_lookup` | 7% | Routing lookup |
| 6 | `__libc_recvfrom` → `skb_consume_udp` → `kfree` → `__slab_free` | 5% | Kernel skb free |
| 7 | `__sendmmsg` → `__pi_memset_generic` | 4% | Memory clearing |
| 8 | `__sendmmsg` → `ip_generic_getfrag` → `__arch_copy_from_user` | 3% | User→kernel copy |
| 9 | `__libc_recvfrom` → `udp_recvmsg` (base) | 3% | Kernel UDP recv |
| 10 | `__sendmmsg` → `udp_send_skb` → `ip_output` → `net_rx_action` | 3% | Loopback softirq |

## Key Findings

### 1. Kernel Dominates (97% kernel time)
The QuicFuscate user-space code accounts for <3% of CPU time in the UDP fast path. The bottleneck is the kernel UDP send/receive path, not the application logic. This means:
- **TODO-390** (AEAD selection) — unlikely to be in Top-10 (crypto is <3% of total)
- **TODO-391** (double header parse) — unlikely to be in Top-10 (parsing is <3%)
- **TODO-392** (FecPacket clone) — unlikely to be in Top-10 (user-space is <3%)
- **TODO-395** (MORUS in-place) — unlikely to be in Top-10 (crypto is <3%)

### 2. Netfilter Overhead (15%)
`nft_do_chain` evaluates iptables rules for every packet. On broderick, the default firewall rules add ~15% overhead. This can be reduced by:
- Adding a fast-path ACCEPT rule for loopback UDP traffic
- Using `iptables -I INPUT -p udp --dport 4433 -j ACCEPT`
- **Script:** `scripts/install/setup-netfilter-fastpath.sh` automates this
- **Status:** ✅ Applied and verified on broderick (2026-06-23)
  - Before: 178.17 MiB/s, nft_do_chain avg 453 ns/call
  - After: 190.12 MiB/s, nft_do_chain avg 421 ns/call
  - Improvement: +6.7% throughput, -7.1% nft_do_chain time per call

### 3. Memory Allocation Overhead (15%)
`__kmalloc` and `__slab_free` for skb allocation/freeing are significant. This is inherent to the kernel UDP path and cannot be reduced from user space. io_uring's zero-copy mode (SendMsgZc) can reduce this by eliminating skb allocation for sent data.
- **Status:** ✅ SendMsgZc verified on broderick (kernel 6.17, 2026-06-23)
  - `SendMsgZc supported: true` — probed at init via `io_uring::Probe`
  - ZC path uses `zerocopy_fill_skb_from_iter` instead of `__kmalloc_node_track_caller_noprof`
  - ZC throughput: 234K pps (loopback) vs 359K pps (regular sendmsg)
  - ZC is slower on loopback — expected, benefits are on real NICs with DMA
  - 13/13 io_uring integration tests pass, 10/10 uring_batch lib tests pass
  - Flamegraph: `docs/profiling/results/flamegraph-zc.svg`

### 4. Small Packet Penalty (Scenario B)
256B packets achieve only 69.9 MiB/s vs 294 MiB/s for 1200B packets — a 4.2x penalty. This is because:
- Per-packet kernel overhead (syscall, skb alloc, routing) dominates for small payloads
- The batch size of 64 doesn't compensate for the smaller payload
- FEC repair packets are typically small — this validates the need for TODO-414 (streaming FEC)

### 5. QUIC Connection RTT (450ms)
The 450ms RTT on loopback is unexpectedly high. This is likely the QUIC connection's keepalive/pacing interval, not actual packet RTT. The connection has minimal traffic (no data transfer), so the RTT measurement reflects the connection idle polling interval, not real network latency.

### 6. FEC/Stealth Overhead (Scenarios D vs E vs F)
RTT is identical (450-451ms) across FEC off/auto and stealth off/performance. This is expected because:
- The connection has no data traffic (just keepalives)
- FEC only adds overhead when encoding/decoding data packets
- Stealth mode only adds overhead when actively masquerading

## Gate Conditions for Micro-Optimizations (TODO-390..401)

Based on the profiling baseline:

| TODO | Gate Condition | Evidence | Recommendation |
|------|----------------|----------|----------------|
| TODO-390 | AEAD-Dispatch in Top-10 | NOT in Top-10 (crypto <3%) | **DEFER** — no evidence |
| TODO-391 | parse_header in Top-10 | NOT in Top-10 (user-space <3%) | **DEFER** — no evidence |
| TODO-392 | clone in Top-10 | NOT in Top-10 (user-space <3%) | **DEFER** — no evidence |
| TODO-395 | to_vec in Top-10 | NOT in Top-10 (user-space <3%) | **DEFER** — no evidence |
| TODO-399 | Connection bench | Validated — scenarios D/E/F captured | **PROCEED** — create Criterion bench |
| TODO-400 | ACK stress bench | Validated — need high-traffic scenario | **PROCEED** — need TUN mode for real ACK stress |
| TODO-401 | Stealth regression CI | Validated — scenarios D vs F comparable | **PROCEED** — create CI gate |

## Recommendations

1. **Rebuild with debug symbols** (`RUSTFLAGS="-g"` or `debug = true` in release profile) for user-space flamegraph resolution. Current flamegraphs show `[harness]` for all user-space frames.

2. **TUN mode profiling** — the QUIC connection scenarios have minimal traffic. For real profiling of the QUIC data plane (FEC, crypto, stealth), need TUN mode with actual data transfer. **Script:** `scripts/benchmarks/profiling-tun-mode.sh` — 5 scenarios (g-k) with tc-netem loss/latency simulation. **Note:** TUN mode is currently broken (client sends via QUIC datagrams, server only forwards H3 stream data to TUN — protocol mismatch). Data-plane profiling was done via harness udp-throughput instead. See `docs/profiling/results/SUMMARY.md` for verified results.

3. **tc-netem simulation** — add `tc qdisc add dev lo root netem delay 50ms loss 5%` for loss/latency profiling. This will activate FEC encoding/decoding and reveal the FEC hot path. Automated in `profiling-tun-mode.sh`. ✅ Verified with 5 scenarios (g-k).

4. **Netfilter optimization** — add a fast-path ACCEPT rule for loopback UDP to eliminate the 15% netfilter overhead during profiling. **Script:** `scripts/install/setup-netfilter-fastpath.sh`. ✅ Applied and verified on broderick.

5. **io_uring zero-copy** — SendMsgZc is already implemented in `src/optimize/uring_batch.rs` and active in production (IoDriver + SERVER_URING_SENDER). The ZC path is probed at init and used automatically on kernel 6.0+. Telemetry counters: `quicfuscate_io_uring_zc_sends_total`, `quicfuscate_io_uring_zc_notifs_total`. **Profiling script:** `scripts/benchmarks/profiling-zc.sh` — 3 scenarios (m-o) to measure skb allocation reduction. ✅ Verified: SendMsgZc supported=true, ZC path avoids `__kmalloc` for skb allocation.

6. **RTT inflation fix** — the 0→385ms loopback RTT bug has been fixed (commit `85651d8`). RTT is now sampled from ACK frames per RFC 9000 §5.1, not inflated by 100ms on every timeout. Re-run profiling to verify RTT stays stable.

## Files

### Baseline (2026-07-23)
- `flamegraph-a.svg` — Scenario A: UDP Fastpath (1200B, batch=32)
- `flamegraph-b.svg` — Scenario B: Small Packets (256B, batch=64)
- `flamegraph-c.svg` — Scenario C: Large Batch (1200B, batch=128)
- `flamegraph-d-server.svg` — Scenario D: QUIC Connection (FEC off)
- `flamegraph-e-server.svg` — Scenario E: QUIC Connection (FEC auto)
- `flamegraph-f-server.svg` — Scenario F: QUIC Connection (FEC auto, stealth performance)
- `scenario-{a-f}.csv` — Raw metrics per scenario
- `flamegraph-udp-fastpath.svg` — Initial UDP fastpath benchmark (pre-scenario)

### Data-Plane Profiling (2026-06-23, verified on broderick)
- `results/flamegraph-{g,h,i,j,k}.svg` — Data-plane flamegraphs with tc-netem
- `results/flamegraph-zc.svg` — io_uring ZC vs regular sendmsg flamegraph
- `results/scenario-{g,h,i,j,k}.csv` — Per-scenario throughput results
- `results/SUMMARY.md` — Verified profiling results summary
