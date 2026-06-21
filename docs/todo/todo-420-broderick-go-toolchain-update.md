---
id: TODO-420
title: Update broderick Go toolchain 1.22.2 → 1.26.4
severity: HIGH
phase: legacy
priority: P0
status: DONE
created: 2026-07-23
resolved: 2026-07-23
---

# TODO-420: Update `broderick` Go toolchain 1.22.2 → 1.26.4

## Problem

Server `broderick` (Oracle Cloud, Ubuntu 24.04 aarch64) had an outdated Go installation via the system package (`/usr/lib/go-1.22` → `/usr/bin/go`), reporting:

```
go version go1.22.2 linux/arm64
```

Latest stable Go release was `go1.26.4`.

## Action

Installed the latest stable Go release from the official tarball:

```bash
cd /tmp
curl -sLO https://go.dev/dl/go1.26.4.linux-arm64.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf go1.26.4.linux-arm64.tar.gz
ln -sf /usr/local/go/bin/go /usr/local/bin/go
```

Verified:

```bash
$ go version
go version go1.26.4 linux/arm64
```

## Acceptance

- [x] `broderick` reports `go1.26.4`.
- [x] `go` is available via `/usr/local/bin/go` and in `PATH`.
- [x] No QuicFuscate project files were changed (project remains Rust-only).

## Notes

Go is not part of the QuicFuscate codebase (Rust-only project). This is a server/toolchain maintenance task to keep the environment current.
