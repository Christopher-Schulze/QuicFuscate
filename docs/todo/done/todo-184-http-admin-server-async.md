# TODO-184: HTTP Admin Server Async Migration

## Status
DONE (2026-03-21) - fully migrated from std::thread::spawn to tokio::spawn with async I/O, connection timeout, and concurrency limit.

## Severity
MEDIUM

## Context
The admin HTTP server spawns a `std::thread` for each incoming HTTP connection. This is not scalable and is vulnerable to Slowloris-style DoS attacks where an attacker opens many connections slowly, exhausting the thread pool and blocking legitimate admin access.

- `src/implementations/server/admin_http.rs:407`: `std::thread::spawn` per connection
- Each thread consumes ~8MB stack by default (OS thread)
- 100 slow connections = 800MB memory + 100 OS threads
- No connection timeout or rate limiting on the thread-per-connection model
- Blocking I/O in threads prevents efficient multiplexing

## Root Cause
The admin HTTP server was implemented with a simple thread-per-connection model for ease of implementation. Since admin traffic is typically low-volume, this was acceptable initially. However, it creates a DoS vector and is architecturally inconsistent with the async Tokio runtime used everywhere else.

## Fix Plan
1. Replace `std::thread::spawn` with `tokio::spawn` for connection handling
2. Convert blocking read/write to async equivalents (`tokio::io::AsyncRead`/`AsyncWrite`)
3. Add per-connection timeout (e.g., 30 seconds idle disconnect)
4. Add connection rate limiting (max concurrent admin connections, e.g., 16)
5. Reuse existing Tokio runtime instead of spawning OS threads
6. Coordinate with todo-121 (HTTP parser replacement) - if HTTP parser is also being replaced, do both in same pass

## Acceptance Criteria
- Admin HTTP uses `tokio::spawn` for connection handling, zero `std::thread::spawn`
- Per-connection idle timeout enforced (configurable, default 30s)
- Max concurrent connections capped (configurable, default 16)
- Slowloris test: 1000 slow connections do not degrade server
- All admin API endpoints functional after migration

## Dependencies
- todo-121 (manual HTTP parser replacement) - related, can be combined
- Tokio runtime already available in server context

## Affected Files
- `src/implementations/server/admin_http.rs`
- `src/implementations/server/admin.rs`
- `src/implementations/server/mod.rs`
