# Issue: AF_XDP Zero-Copy Path

## Description
`src/xdp_socket.rs` now supports setting up UMEM and ring buffers using the
`afxdp` crate. If initialization fails or the feature is not compiled the code
falls back to ordinary UDP sockets. The active interface can be overridden via
the `XDP_IFACE` environment variable which makes testing with veth pairs
possible.

## Tasks
- [x] Implement full AF_XDP socket initialization including UMEM setup and ring configuration.
- [x] Provide graceful fallback to standard UDP sockets when XDP is unavailable.
- [x] Add path migration support by reconfiguring the XDP socket on the fly.
- [x] Benchmark throughput and update telemetry metrics for XDP specific statistics.

## Kernel & System Setup

The benchmarks require a recent Linux kernel (5.15+) with the following options
compiled in:

- `CONFIG_BPF` and `CONFIG_BPF_SYSCALL`
- `CONFIG_XDP_SOCKETS`

Install `libbpf-dev` and ensure the test user has `CAP_NET_ADMIN`.  To avoid
packet drops when using zero-copy, raise the locked memory limit:

```bash
sudo ulimit -l unlimited
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.wmem_max=26214400
```

## Planned Commits
1. **af_xdp module** – new low level wrapper around libbpf for UMEM and rings.
2. **xdp_socket integration** – replace placeholders with real send/recv implementation.
3. **fallback logic** – detect kernel support and revert to UDP if required.
4. **tests and benchmarks** – automated tests using veth pairs and integration into CI.
