# Data-Plane Profiling Results (broderick, 2026-06-23)

Server: broderick (aarch64, Ubuntu 24.04, kernel 6.17, 4 cores, 23 GB RAM)
Date: 2026-06-23
Method: harness udp-throughput → QuicFuscate server (UDP 4433), perf record -F 999 -a -g

## Scenario Results

| Scenario | FEC | Delay | Loss | Throughput (MiB/s) | Flamegraph |
|----------|-----|-------|------|--------------------|------------|
| g | auto | 0ms | 0% | 262.58 | flamegraph-g.svg |
| h | auto | 50ms | 0% | 652.98 | flamegraph-h.svg |
| i | auto | 0ms | 5% | 259.93 | flamegraph-i.svg |
| j | auto | 50ms | 5% | 646.44 | flamegraph-j.svg |
| k | off | 0ms | 5% | 254.06 | flamegraph-k.svg |

## Key Findings

### 1. Netfilter fast-path (verified)
- **Before fast-path rule:** 178.17 MiB/s, nft_do_chain avg 453 ns/call
- **After fast-path rule:** 190.12 MiB/s, nft_do_chain avg 421 ns/call
- **Improvement:** +6.7% throughput, -7.1% nft_do_chain time per call
- Rule: `iptables -I INPUT 1 -p udp --dport 4433 -j ACCEPT`
- Status: Applied and verified on broderick

### 2. FEC impact (scenarios i vs k, 5% loss)
- FEC auto: 259.93 MiB/s
- FEC off: 254.06 MiB/s
- FEC overhead: ~2.3% throughput cost for FEC encoding
- FEC benefit: loss recovery (not measurable on loopback without real packet loss impact)

### 3. Latency impact (scenarios g vs h)
- No delay: 262.58 MiB/s
- 50ms delay: 652.98 MiB/s (higher due to batching effect with tc-netem delay)
- Note: harness measures send throughput, not end-to-end latency

### 4. Top hotspots (scenario g, no loss)
- `el0_svc` (syscall entry): 4.20%
- `nft_do_chain` (netfilter): 3.71% (with fast-path rule; OUTPUT chain still traversed)
- `__skb_recv_udp` (kernel UDP recv): 3.26%
- `__wake_up_sync_key`: 3.90%
- QuicFuscate user-space: ~5% total (no debug symbols for function identification)
- `__kmalloc_node_track_caller_noprof`: 0.56% (skb allocation — much less than 15% baseline claim)

### 5. TUN-mode status
- TUN mode is **broken** (pre-existing bug, not introduced by profiling work)
- Bug: Client sends TUN packets via `dgram_send` (QUIC datagrams), but server only
  forwards H3 stream data to TUN (not datagrams). Protocol mismatch.
- Workaround: Used harness udp-throughput for data-plane profiling instead.
- TODO: Fix server to handle QUIC datagrams → TUN forwarding.

### 6. io_uring SendMsgZc (verified)
- **SendMsgZc supported:** true (kernel 6.17)
- **ZC path active:** Uses `zerocopy_fill_skb_from_iter` instead of `__kmalloc_node_track_caller_noprof`
- **ZC throughput:** 234K pps (loopback) vs 359K pps (regular sendmsg)
- **ZC is slower on loopback** — expected, ZC benefits are on real NICs with DMA
- **kmalloc avoidance verified:** ZC path does not call `__kmalloc_node_track_caller_noprof`
  for skb allocation; uses `kmem_cache_alloc_node_noprof` + `zerocopy_fill_skb_from_iter` instead
- Flamegraph: flamegraph-zc.svg
- 13/13 io_uring unit tests pass, 10/10 uring_batch lib tests pass

## Files
- `flamegraph-{g,h,i,j,k}.svg` — data-plane flamegraphs
- `flamegraph-zc.svg` — ZC vs regular sendmsg flamegraph
- `scenario-{g,h,i,j,k}.csv` — per-scenario throughput results
