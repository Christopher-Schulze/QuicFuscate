# Issue: AF_XDP Zero-Copy Path

## Description
`src/xdp_socket.rs` only contains placeholders and returns errors when attempting to create an AF_XDP socket. PLAN.txt specifies a zero-copy network path with XDP acceleration.

## Tasks
- [ ] Implement full AF_XDP socket initialization including UMEM setup and ring configuration.
- [ ] Provide graceful fallback to standard UDP sockets when XDP is unavailable.
- [ ] Add path migration support by reconfiguring the XDP socket on the fly.
- [ ] Benchmark throughput and update telemetry metrics for XDP specific statistics.

## Planned Commits
1. **af_xdp module** – new low level wrapper around libbpf for UMEM and rings.
2. **xdp_socket integration** – replace placeholders with real send/recv implementation.
3. **fallback logic** – detect kernel support and revert to UDP if required.
4. **tests and benchmarks** – automated tests using veth pairs and integration into CI.
