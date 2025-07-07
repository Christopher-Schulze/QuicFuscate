# Usage Examples

## Client

```
quicfuscate client \
  --remote 203.0.113.1:4433 \
  --local 127.0.0.1:1080 \
  --profile chrome \
  --front-domain cdn.example.com \
  --verify-peer \
  --fec-config ./fec.toml
```

## Server

```
quicfuscate server \
  --listen 0.0.0.0:4433 \
  --cert ./server.crt \
  --key ./server.key \
  --profile firefox \
  --fec-config ./fec.toml
```

Ensure certificate and key are valid PEM files. Use `CTRL+C` to gracefully stop the process.

The optional `--fec-config` flag loads Adaptive FEC parameters from the specified TOML file.

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
  --pool-block 4096
```

```
quicfuscate server \
  --listen 0.0.0.0:4433 \
  --cert ./server.crt \
  --key ./server.key \
  --profile chrome \
  --pool-capacity 1024 \
  --pool-block 4096
```
