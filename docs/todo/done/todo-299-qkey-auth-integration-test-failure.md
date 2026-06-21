---
id: TODO-299
title: it-qkey-auth-integration TLS Handshake Failure
severity: CRITICAL
status: done
created: 2026-03-24
---

# TODO-299: it-qkey-auth-integration Test Failure - Missing AEAD Sealer

## Mandatory Gate

**Before marking this TODO complete, ALL of the following must be checked and updated:**
- `scripts/tests/rust/integration/qkey_auth_integration.rs` - the test itself
- `scripts/tests/suites/test-desktop-webadmin-rust-integration.sh` - suite runner
- `src/core.rs`, `src/qftls.rs`, `src/transport/connection.rs` - any changed code
- `docs/DOCUMENTATION.md` - sections: QKey Auth, TLS Cover, Transport internals
- `docs/MAP.md` - if any module wiring changes
- `docs/context.md` - session state update
- `docs/changelog.md` - grouped entry

No fix is complete without verifying all relevant scripts run clean and docs are synchronized.

---

## Current Failure

```
test qkey_http3_auth_accepts_valid_and_rejects_invalid_token ... FAILED

thread 'qkey_auth_integration' panicked at scripts/tests/rust/integration/qkey_auth_integration.rs:367:18:
simulation must run: "server send failed: TlsError(\"missing AEAD sealer for short-header packet\")"
```

**Note:** The compile error (`bool` vs `Option` in `token_matches_hash` match arms) was fixed in Session 23. The runtime failure is the pre-existing issue.

---

## Root Cause Analysis

### What "missing AEAD sealer for short-header packet" means

In QUIC (RFC 9001), short-header packets are 1-RTT packets encrypted with the application-level TLS keys (derived after the TLS handshake completes). The QUIC stack maintains separate AEAD sealers per encryption level:

- **Initial level**: HKDF-derived from connection ID (always available)
- **Handshake level**: derived after ClientHello/ServerHello exchange
- **1-RTT level** (short header): derived only after TLS Finished messages exchanged

When the server attempts to send a short-header packet without the 1-RTT sealer installed, this error fires. This means one of:

1. **The handshake loop in the test is incomplete** - the server creates a new connection and immediately tries to send data before the TLS handshake has progressed far enough to install 1-RTT keys.
2. **The server `conn.send()` is called before `tls_handshake_complete()`** - the test does not guard server sends behind handshake completion checks.
3. **The TLS key schedule is not being driven** - in the in-memory simulation, the test manually pumps packets between client and server. If a Handshake-level flight from the server is missed or dropped, the 1-RTT keys never derive.

### Test Architecture (in-memory QUIC simulator)

The test in `qkey_auth_integration.rs` simulates a full QUIC handshake in memory:

```rust
loop {
    // Client: send
    // Server: recv client packet, create server conn on first packet
    // Server: send
    // Client: recv server packet
    // Once handshake complete: HTTP/3 auth check
}
```

The test uses `conn.send()` and `conn.recv()` in a tight loop. The critical ordering requirement for QUIC+TLS:

```
Client:  Initial[ClientHello CRYPTO frame]  →  Server
Server:  Initial[ServerHello]               →  Client
Server:  Handshake[EncryptedExtensions + Certificate + CertificateVerify + Finished]  →  Client
Client:  Handshake[Finished]               →  Server
           ↓ Both sides now have 1-RTT keys
Client:  Short-Header[HTTP/3 request]      →  Server
```

If the simulation loop does not pump the full Handshake flight from server to client AND the client's Handshake-Finished back to server before attempting to send 1-RTT data, the server will have queued 1-RTT data without the sealer.

### Specific Code Path

At `scripts/tests/rust/integration/qkey_auth_integration.rs`:

1. Line ~168-210: Server is created upon first client Initial packet
2. Line ~220-260: Main loop drives `client.conn.send()` -> `server.conn.recv()` -> `server.conn.send()` -> `client.conn.recv()`
3. The server's HTTP/3 poll is called starting around line ~275 regardless of handshake completion state
4. The `conn.send()` at server side can return a short-header packet if the QUIC stack internally queued it, but if the 1-RTT sealer is not installed, it panics

### Why This Is Non-Trivial

The test must correctly alternate between:
- Initial-level packets (before keys)
- Handshake-level packets (after ServerHello)
- 1-RTT packets (after Finished)

And the server's `new_server()` call must be fed the correct `odcid` so the TLS context can be looked up. If any packet is dropped or re-ordered in the simulation, the key derivation can fail silently and the sealer is never installed.

---

## Investigation Steps

1. Add `RUST_LOG=debug` to the test to see what encryption-level packets are being exchanged
2. Add explicit `tls_handshake_complete()` guards before attempting 1-RTT sends:
   ```rust
   if !client.conn.tls_handshake_complete() { continue; }
   ```
3. Check if the server is driving ALL handshake-level packets to completion before the HTTP/3 poll runs
4. Verify `conn.send()` processes all queued packets per level (call in a loop until `Done`)
5. Check if `QuicFuscateConnection::new_server` correctly initializes the TLS context from `odcid`

---

## Fix Strategy

### Option A: Guard HTTP/3 poll behind handshake completion
Add `if !srv.conn.tls_handshake_complete() { continue; }` before the HTTP/3 poll block. This ensures the server never enters the 1-RTT send path until keys are available.

### Option B: Drain all pending sends per connection per loop tick
Replace single `conn.send()` calls with drain loops:
```rust
loop {
    match conn.send(buf) {
        Ok((n, _)) if n > 0 => { /* feed to peer */ }
        _ => break,
    }
}
```
This ensures every pending packet (across all encryption levels) is sent before switching to the other peer.

### Option C: Verify root cause is in core.rs / qftls.rs sealer installation
If Option A+B don't resolve it, the TLS sealer may not be installed at the right point in `src/qftls.rs` during `QuicFuscateConnection::new_server()` creation. Check that the sealer installation callback fires correctly when processing the Initial packet that creates the server connection.

---

## Completion Criteria

- `cargo test --features rust-tests --test it-qkey-auth-integration` passes GREEN
- The test verifies both: valid token accepted, invalid token rejected
- No changes to the test's authentication logic - only the handshake simulation loop
- `cargo test --lib` still 450 passed, 0 failed
- All mandatory gate items above checked and updated
