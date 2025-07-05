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
