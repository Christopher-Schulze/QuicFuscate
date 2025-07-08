# Usage Examples

## Client

```
quicfuscate client \
  --remote 203.0.113.1:4433 \
  --local 127.0.0.1:1080 \
  --profile chrome \
  --front-domain cdn.example.com \
  --verify-peer \
  --config ./example_config.toml
```

Telemetry metrics are disabled by default. Launch the binary with `--telemetry`
to expose Prometheus statistics on `0.0.0.0:9898`.

## Server

```
quicfuscate server \
  --listen 0.0.0.0:4433 \
  --cert ./server.crt \
  --key ./server.key \
  --profile firefox \
  --config ./example_config.toml
```

Ensure certificate and key are valid PEM files. Use `CTRL+C` to gracefully stop the process.

Use the `--config` flag to load a unified TOML file containing FEC, stealth and optimization settings. See `docs/example_config.toml` for details.

### Stealth Options

```
    --front-domain <d>     Domain used for fronting (repeatable)
    --doh-provider <url>   Custom DNS-over-HTTPS resolver
    --verify-peer          Validate the server certificate
    --ca-file <path>       CA file for verification
    --disable-doh          Disable DNS over HTTPS
    --disable-fronting     Disable domain fronting
    --disable-xor          Disable XOR obfuscation
    --disable-http3        Disable HTTP/3 masquerading
    --no-utls              Use native TLS instead of uTLS
    --debug-tls            Dump TLS keys for debugging
    --list-fingerprints    Show available browser fingerprints
```

### Real TLS Fingerprints

When built against the patched `quiche` library, QuicFuscate can replay
captured TLS ClientHello messages. Store the base64 encoded handshake in
`browser_profiles/<browser>_<os>.chlo` and build with `QUICHE_PATH` pointing
to the patched sources. The runtime loads the file, feeds the bytes to
`ChloBuilder` and attaches it to the configuration:

```bash
export QUICHE_PATH=$(pwd)/libs/patched_quiche/quiche
./scripts/quiche_workflow.sh --step build
```

The runtime automatically loads the matching profile based on the selected
`--profile` and `--os` options.

### FakeTLS Handshake

When stealth mode is active, QuicFuscate sends a minimal TLS handshake.
The ClientHello bytes are taken from the selected fingerprint profile and
a synthetic ServerHello with placeholder certificate is returned. This
reduces handshake overhead while still presenting TLS-like packets on the
wire.

### Optimization Parameters

Both client and server accept additional flags to tune the memory pool used for
zero-copy buffers:

```
    --pool-capacity <num>    Number of blocks to keep in the pool (default: 1024)
    --pool-block <bytes>     Size of each block in bytes (default: 4096)
```
Increase the capacity when handling high traffic volumes or decrease it to save
memory.

### Standard Configuration

The following setup provides a good starting point on most systems:

```
quicfuscate client \
  --remote 203.0.113.1:4433 \
  --profile chrome \
  --front-domain cdn.example.com \
  --pool-capacity 1024 \
  --pool-block 4096 \
  --xdp
```

```
quicfuscate server \
  --listen 0.0.0.0:4433 \
  --cert ./server.crt \
  --key ./server.key \
  --profile chrome \
  --pool-capacity 1024 \
  --pool-block 4096 \
  --xdp
```

### Example Configuration

The unified configuration file combines FEC tuning with stealth and optimization
options. Below is the content of `docs/example_config.toml`:

```toml
[adaptive_fec]
lambda = 0.05
burst_window = 30
hysteresis = 0.02
kalman_enabled = true
kalman_q = 0.002
kalman_r = 0.02

[[adaptive_fec.modes]]
name = "light"
w0 = 20

[stealth]
browser_profile = "chrome"
os_profile = "windows"
enable_doh = true
doh_provider = "https://cloudflare-dns.com/dns-query"
enable_domain_fronting = true
fronting_domains = ["cdn.example.com"]
enable_xor_obfuscation = true
enable_http3_masquerading = true
use_qpack_headers = true

[optimize]
pool_capacity = 1024
block_size = 4096
enable_xdp = true
```

### Connection Migration

To migrate an established connection to a new local port, call `migrate_connection` on the active session:

```rust
let new_addr = "127.0.0.1:0".parse().unwrap();
let path_id = conn.migrate_connection(new_addr).unwrap();
println!("migrated to path {path_id}");
```
The library records successful migrations via the `path_migrations_total` telemetry counter.
