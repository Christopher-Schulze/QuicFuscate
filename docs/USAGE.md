# Usage Examples

## Client

```
quicfuscate client --remote 203.0.113.1:4433 --local 127.0.0.1:1080 --profile chrome --fec-config ./fec.toml
```

## Server

```
quicfuscate server --listen 0.0.0.0:4433 --cert ./server.crt --key ./server.key --profile firefox --fec-config ./fec.toml
```

Ensure certificate and key are valid PEM files. Use `CTRL+C` to gracefully stop the process.

The optional `--fec-config` flag loads Adaptive FEC parameters from the specified TOML file.

### Optimization Parameters

Both client and server accept additional flags to tune the memory pool used for
zero-copy buffers:

```
    --pool-capacity <num>    Number of blocks to keep in the pool (default: 1024)
    --pool-block <bytes>     Size of each block in bytes (default: 4096)
```
Increase the capacity when handling high traffic volumes or decrease it to save
memory.
