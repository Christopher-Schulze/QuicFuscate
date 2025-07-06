# Usage Examples

## Client

```
quicfuscate client --remote 203.0.113.1:4433 --local 127.0.0.1:1080 --profile chrome
```

## Server

```
quicfuscate server --listen 0.0.0.0:4433 --cert ./server.crt --key ./server.key --profile firefox
```

Ensure certificate and key are valid PEM files. Use `CTRL+C` to gracefully stop the process.

### Custom FEC configuration

Create a TOML file and pass it via `--fec-config`:

```toml
[adaptive_fec]
lambda = 0.05
burst_window = 30
hysteresis = 0.01
pid = { kp = 1.5, ki = 0.2, kd = 0.1 }

[[adaptive_fec.modes]]
name = "light"
w0 = 20
```

Example usage:

```
quicfuscate client --remote 203.0.113.1:4433 --fec-config ./fec.toml
```
