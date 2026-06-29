---
id: TODO-436
title: "QKey auto-rotation and immediate revocation of active connections"
severity: HIGH
phase: "H"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-436: QKey auto-rotation and immediate revocation of active connections

## Problem

The QKey system has two critical security gaps: keys never rotate, and
revocation does not terminate active connections.

### 1. No key rotation

`QKeyRegistry` (`src/implementations/server/qkey_registry.rs`) has no
rotation function. A grep for `rotate` in the file returns zero
results. QKeys are issued via `insert_with_ttl` (line 150) or
`insert_with_ttl_and_name` (line 160) and persist unchanged until they
expire (via `prune_expired` at line 250) or are manually revoked (via
`revoke` at line 222). There is no mechanism to automatically issue a
replacement key and transition active connections to it. This means a
compromised QKey token remains valid for its entire TTL, and long-lived
connections use the same key material indefinitely — violating
forward-secrecy principles for the QKey layer.

The `QKeyRecord` struct (line 62) has an `expires_at: Option<u64>`
field used only for TTL pruning, not for rotation scheduling. There is
no `rotated_from` / `rotated_to` field, no rotation history, and no
volume counter for volume-based rotation.

### 2. Revocation does not terminate active connections

`QKeyRegistry::revoke` (line 222-232) simply removes the entry from
`self.entries` and persists:
```rust
pub fn revoke(&mut self, id: &str) -> bool {
    self.prune_expired();
    let before = self.entries.len();
    self.entries.retain(|entry| entry.id != id);
    let changed = before != self.entries.len();
    if changed {
        self.persist();
    }
    changed
}
```

This only affects **future** connection attempts — the
`lookup_initial_id_token` (line 239) and `record_for_id_token` (line
233) methods will no longer find the revoked key. But **already
established** connections continue to run with full access.

The auth check in the server's live datagram path
(`src/implementations/server/mod.rs:1941-1992`) only validates QKey
tokens on **new streams** via `poll_http3_with_headers` (line 1939).
The `QKeyHeaderAuthOutcome::Reject` path (line 1987) calls
`close_live_client_for_qkey_auth_failure` (line 1699), which closes
the QUIC connection — but this only triggers when a client opens a new
HTTP/3 stream after revocation. If the client has an active MASQUE
datagram flow and opens no new streams, the connection persists
indefinitely.

### 3. No QKey-to-connection mapping

`LiveServerState` (`src/implementations/server/mod.rs:2010-2015`):
```rust
pub struct LiveServerState {
    clients: std::collections::HashMap<SocketAddr, QuicFuscateConnection>,
    qkey_auth: std::collections::HashMap<Vec<u8>, QKeyAuthState>,
    domain: LiveServerDomain,
}
```

The `clients` map is keyed by `SocketAddr` and the `qkey_auth` map is
keyed by a `Vec<u8>` (connection ID), but neither maps a QKey ID to
the connections using it. The `QKeyAuthState` (referenced at line 1942)
contains `expected_token_sha256` and `authed` but not the QKey ID
itself. There is no way to look up which live connections are using a
given QKey, so revocation cannot find and terminate them.

The `Session` struct (`src/implementations/server/session.rs:41-51`)
also has no QKey ID field:
```rust
pub struct Session {
    id: SessionId,
    remote_addr: SocketAddr,
    client_ip: Ipv4Addr,
    created_at: Instant,
    timeout: Duration,
    stats: Arc<SessionStats>,
}
```

## Goal

- QKeys auto-rotate based on time (default: every 24 hours) and volume
  (default: every 100 GB of traffic).
- A `QKey-to-connection` mapping allows the server to find all live
  connections using a given QKey.
- Revoking a QKey immediately terminates all active connections using
  that QKey (within 1 second).
- Rotation transitions active connections to the new key without
  dropping them.
- A revocation audit log records who revoked which key, when, and
  which connections were terminated.
- Tests verify that revoking a QKey with an active connection
  terminates it within 1 second.

## Implementation Plan

### Step 1: Add rotation fields to `QKeyRecord`

**File:** `src/implementations/server/qkey_registry.rs`

- Add fields to `QKeyRecord` (line 62):
  ```rust
  pub rotated_from: Option<String>,   // QKey ID this key replaced
  pub rotated_to: Option<String>,     // QKey ID that replaced this key
  pub bytes_relayed: u64,             // volume counter for volume-based rotation
  pub rotated_at: Option<u64>,        // timestamp when rotation occurred
  ```
- Update `insert_with_ttl` (line 150) and
  `insert_with_ttl_and_name` (line 160) to initialize
  `rotated_from: None`, `rotated_to: None`, `bytes_relayed: 0`,
  `rotated_at: None`.
- Update the serde serialization to include the new fields with
  `#[serde(default)]` for backward compatibility with existing
  `qkeys.json` files.

### Step 2: Implement `rotate` method on `QKeyRegistry`

**File:** `src/implementations/server/qkey_registry.rs`

- Add a `rotate` method:
  ```rust
  pub fn rotate(&mut self, id: &str) -> Result<QKeyEntry, String>
  ```
  - Looks up the existing `QKeyRecord` by `id`.
  - Generates a new QKey token (32 random bytes, hex-encoded) and a
    new QKey ID (12 hex chars, same format as `insert_with_ttl`).
  - Copies the `name`, `stealth`, `fec`, and `expires_at` (rebased
    from now) from the old record.
  - Sets `rotated_from: Some(old_id)` on the new record and
    `rotated_to: Some(new_id)` + `rotated_at: Some(now)` on the old
    record.
  - Marks the old record as superseded (keeps it in the registry for
    audit but flags it so `lookup_initial_id_token` skips it).
  - Persists the registry.
  - Returns the new `QKeyEntry`.

### Step 3: Add auto-rotation scheduler

**File:** `src/implementations/server/qkey_rotation.rs` (new)

- Create a `QKeyRotationScheduler` that runs as a background Tokio
  task on the server:
  - **Time-based rotation**: Every `rotation_interval_secs` (default:
    86400 = 24h), iterate all non-expired, non-superseded QKeys and
    call `registry.rotate(id)`.
  - **Volume-based rotation**: Periodically (every 60 s) check
    `bytes_relayed` on each QKey. If it exceeds
    `rotation_volume_bytes` (default: 100 GB = 107_374_182_400),
    trigger rotation.
  - After rotation, notify the connection manager (Step 5) to
    transition active connections to the new QKey.
- Configuration fields added to `ServerConfig`
  (`src/implementations/server/mod.rs:104`):
  ```rust
  pub qkey_rotation_interval_secs: u64,   // default: 86400
  pub qkey_rotation_volume_bytes: u64,    // default: 107_374_182_400
  pub qkey_auto_rotation: bool,           // default: true
  ```

### Step 4: Track `bytes_relayed` per QKey

**File:** `src/implementations/server/mod.rs`

- In the live datagram processing path (line 1898,
  `process_live_server_datagram`), after recording
  `record_live_snapshot_bytes_in` / `record_live_snapshot_bytes_out`
  (lines 1722, 1739), also increment the QKey's `bytes_relayed`
  counter in the registry. This requires accessing the QKey ID for
  the current connection (from `QKeyAuthState` — see Step 5).
- The increment can be batched (accumulate in an atomic counter per
  connection, flush to the registry every 10 s) to avoid lock
  contention on the registry mutex.

### Step 5: Add QKey ID to `QKeyAuthState` and `Session`

**File:** `src/implementations/server/mod.rs`, `src/implementations/server/session.rs`

- Add `qkey_id: Option<String>` to `QKeyAuthState` (the struct
  referenced at line 1942; find its definition and add the field).
  Populate it during `parse_live_server_initial_auth` (the function
  that creates `QKeyAuthState` from the initial packet's QKey token).
- Add `qkey_id: Option<String>` to `Session`
  (`src/implementations/server/session.rs:41`). Populate it in
  `Session::new` or via a setter when the QKey is authenticated.
- Add `qkey_id: Option<String>` to `LiveClientRuntime` (line 2104)
  and `LiveClientInit` (line 2017) so the datagram processing path
  has access to the QKey ID.

### Step 6: Build QKey-to-connection mapping

**File:** `src/implementations/server/mod.rs`

- Add a new field to `LiveServerState` (line 2010):
  ```rust
  qkey_connections: HashMap<String, Vec<SocketAddr>>,
  ```
  mapping QKey ID → list of client `SocketAddr`s.
- When a client is added to `LiveServerState.clients` (in the
  `LiveClientAcquire::Ready` path, line 2348), also insert the
  client's `SocketAddr` into `qkey_connections` under their QKey ID.
- When a client is removed (connection close / reap), remove their
  `SocketAddr` from `qkey_connections`.
- Add a method:
  ```rust
  pub fn connections_for_qkey(&self, qkey_id: &str) -> Vec<SocketAddr>
  ```

### Step 7: Immediate termination on revoke

**File:** `src/implementations/server/mod.rs`, `src/implementations/server/qkey_registry.rs`

- Add a `revoke_and_terminate` method to the server's admin action
  handler (`src/implementations/server/admin.rs` — the `revoke_qkey`
  action):
  1. Call `registry.revoke(id)` to remove from the registry.
  2. Look up `LiveServerState::connections_for_qkey(id)`.
  3. For each `SocketAddr`, get the `QuicFuscateConnection` from
     `LiveServerState.clients` and call
     `conn.close(true, 0x0, b"qkey_revoked")` — the same pattern as
     `close_live_client_for_qkey_auth_failure` (line 1699).
  4. Remove the client from `LiveServerState.clients` and
     `qkey_connections`.
  5. Write a revocation audit log entry (see TODO-439 for the audit
     log infrastructure; if not yet implemented, log at `warn!`
     level with structured fields).

### Step 8: Graceful rotation transition for active connections

**File:** `src/implementations/server/mod.rs`

- When `QKeyRotationScheduler` rotates a QKey:
  1. The new QKey ID is sent to the client via an HTTP/3 unidirectional
     stream or a MASQUE capsule (using the existing capsule protocol
     in `src/transport/h3.rs:804`).
  2. The client stores the new QKey for future reconnections.
  3. The current connection continues to operate using the old QKey
     until the client reconnects (the old key is marked superseded but
     not revoked, so the connection remains valid).
  4. The server schedules a connection migration: after a grace period
     (default: 300 s), if the client has not reconnected with the new
     key, the server closes the old connection with reason
     `b"qkey_rotated"`, forcing the client to reconnect with the new
     key.

### Step 9: Tests

**File:** `src/implementations/server/qkey_registry.rs` (inline tests),
`tests/qkey_rotation_test.rs` (new)

- Unit test: `rotate()` creates a new QKey with `rotated_from` set to
  the old ID and the old record has `rotated_to` set to the new ID.
- Unit test: After rotation, `lookup_initial_id_token` with the old
  token returns `None` (superseded), and with the new token returns
  the new record.
- Unit test: `revoke()` removes the entry and `persist()` is called.
- Integration test: Issue a QKey, connect a client, revoke the QKey.
  Verify the client's QUIC connection is closed within 1 second
  (check `conn.close()` was called and the connection state is
  `Closed`).
- Integration test: Time-based rotation triggers after
  `rotation_interval_secs`. Verify a new QKey is created and the old
  one is superseded.
- Integration test: Volume-based rotation triggers after
  `rotation_volume_bytes` of traffic. Verify `bytes_relayed` is
  tracked correctly.

## Files to Modify/Create

- `src/implementations/server/qkey_registry.rs` — add rotation fields
  to `QKeyRecord`, implement `rotate()` method, update serde
- `src/implementations/server/qkey_rotation.rs` — **new**: auto-rotation
  scheduler (time + volume based)
- `src/implementations/server/mod.rs` — add `qkey_connections` map to
  `LiveServerState`, add QKey ID to `QKeyAuthState` /
  `LiveClientRuntime`, implement `revoke_and_terminate`, track
  `bytes_relayed`
- `src/implementations/server/session.rs` — add `qkey_id` field to
  `Session`
- `src/implementations/server/admin.rs` — wire `revoke_and_terminate`
  into the admin revoke action
- `src/engine/config.rs` — add rotation config fields to
  `ServerConfig` / `EngineConfig`
- `tests/qkey_rotation_test.rs` — **new**: integration tests

## Acceptance Criteria

- [ ] `QKeyRegistry::rotate()` exists and creates a new QKey with
      `rotated_from` pointing to the old key.
- [ ] After rotation, the old QKey token is superseded and
      `lookup_initial_id_token` returns `None` for it.
- [ ] `LiveServerState` has a `qkey_connections` map that tracks
      which connections use which QKey.
- [ ] Revoking a QKey with an active connection closes the QUIC
      connection within 1 second.
- [ ] Time-based rotation triggers every `rotation_interval_secs`
      (default 24h).
- [ ] Volume-based rotation triggers after `rotation_volume_bytes`
      (default 100 GB).
- [ ] `bytes_relayed` is tracked per QKey and incremented during
      live datagram processing.
- [ ] Rotation sends the new QKey to the client and forces
      reconnection after a grace period.
- [ ] Revocation audit log entry is written (or `warn!` log if
      TODO-439 is not yet implemented).
- [ ] `cargo test` passes with all new tests green.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| Rotation check interval | 60 s | Background task polls registry; negligible CPU |
| Rotate one QKey | < 5 ms | Generate token + update 2 records + persist JSON |
| Revoke + terminate N connections | < 1 s for 100 connections | Iterate `qkey_connections`, close each QUIC connection |
| `bytes_relayed` tracking overhead | < 0.1% throughput | Atomic counter per connection, batch flush every 10 s |
| Memory per QKey record (with rotation fields) | < 200 bytes | Additional fields: `rotated_from`, `rotated_to`, `bytes_relayed`, `rotated_at` |
