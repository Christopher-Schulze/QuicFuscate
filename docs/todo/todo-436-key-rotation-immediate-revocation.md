---
id: TODO-436
title: Key rotation & immediate revocation (incl. race condition fix)
severity: HIGH
phase: "G"
priority: P0
status: OPEN
created: 2026-07-23
depends_on: []
---

# TODO-436: Key rotation & immediate revocation (incl. race condition fix)

## Goal
Implement automatic QKey rotation with configurable intervals, atomic revocation that terminates active connections immediately, O(1) QKey-to-connection mapping for instant lookup, and fix all race conditions in the revoke/rotate paths (TOCTOU on revoke, concurrent revoke vs. rotation, rotation-vs-revoke ordering). The system must rotate keys without service interruption using an overlap window and terminate revoked connections via QUIC CONNECTION_CLOSE frames.

## Current State (verified against code)

### QKey registry
- `src/implementations/server/qkey_registry.rs:159-407` — `QKeyRegistry` stores entries in a `Vec<QKeyRecord>`. Lookup by ID is O(n) linear scan (`entries.iter().find()`, line 330). No index/map for O(1) lookup.
- `src/implementations/server/qkey_registry.rs:310-319` — `revoke()` removes by ID via `entries.retain(|entry| entry.id != id)`. This is O(n) and only removes from the registry — it does NOT terminate active connections using that QKey.
- `src/implementations/server/qkey_registry.rs:349-366` — `prune_expired()` removes expired entries. Called on every registry access (list, lookup, insert, revoke, has_entries). Also O(n).
- `src/implementations/server/qkey_registry.rs:233-292` — `insert_with_ttl()` checks for existing entry by linear scan, inserts, persists. No rotation logic — keys are only added manually.

### QKey-to-connection mapping (the gap)
- `src/implementations/server/mod.rs:2904-2909` — `QKeyAuthState` struct has `expected_token_sha256`, `authed`, `connected_at`. No QKey ID field — the mapping from QKey ID to connection is indirect.
- `src/implementations/server/mod.rs:2091-2096` — `LiveServerState` has `qkey_auth: HashMap<Vec<u8>, QKeyAuthState>` keyed by connection ID (the QUIC source connection ID), NOT by QKey ID. To find connections using a specific QKey, you must iterate all `qkey_auth` entries and match `expected_token_sha256` — O(n) with string comparison.
- `src/implementations/server/mod.rs:2540-2542` — When a new client is accepted, `pending_qkey_auth` is inserted into `qkey_auth` keyed by `conn_id` (connection ID). The QKey record's `id` is not stored in the auth state.

### Revocation race conditions
- `src/implementations/server/mod.rs:1596-1613` — `reconcile_live_clients()` removes closed connections from `clients` and `qkey_auth` by iterating and checking `conn.conn.is_closed()`. This runs concurrently with the main accept loop. If a QKey is revoked between the `reconcile` call and the next accept, a new connection using the revoked QKey could be accepted.
- `src/implementations/server/mod.rs:2741-2758` — `enforce_qkey_auth_timeouts()` iterates `qkey_auth`, collects timed-out conn IDs, then iterates `self.values_mut()` (all connections) to find and close matching connections. This is a TOCTOU race: between collecting the timed-out IDs and closing the connections, new connections could be added or existing ones could change their connection ID (QUIC migration).
- `src/implementations/server/mod.rs:2668-2705` — `close_live_client()` closes a connection by address, but the connection may have migrated to a new address (QUIC connection migration). The old address is stale.
- No locking or generation counters protect the revoke → close path. A revoke call from the admin API (`admin_http.rs` or `admin.rs`) and the periodic `enforce_qkey_auth_timeouts` can race.

### No rotation
- There is no automatic key rotation. QKeys are created manually via the admin API and persist until their TTL expires or they are manually revoked. No overlap window, no generation counters, no scheduled rotation.

## Problem Analysis

### Race conditions in detail

**Race 1: TOCTOU on revoke**
1. Admin calls `revoke(qkey_id)` → removes from registry.
2. Between registry removal and connection termination, a new client connects using the same QKey ID.
3. `lookup_initial_id_token()` returns `None` (key removed) → client is rejected. This is correct behavior, but:
4. An existing connection using the revoked QKey is still active. The revoke only removed the registry entry — it did not close the connection.
5. The existing connection continues to send/receive data until it naturally times out or disconnects.

**Race 2: Concurrent revoke vs. enforce_qkey_auth_timeouts**
1. `enforce_qkey_auth_timeouts` collects timed-out conn IDs into a `Vec`.
2. Admin calls `revoke()` which removes a QKey from the registry.
3. `enforce_qkey_auth_timeouts` iterates connections to close timed-out ones.
4. A connection that was using the revoked QKey is not in the timed-out list (it authenticated successfully), so it is not closed by `enforce_qkey_auth_timeouts`.
5. The revoke did not close it either (revoke only touches the registry).
6. The connection remains active indefinitely.

**Race 3: Rotation vs. revoke**
1. Rotation starts: new key generated, old key scheduled for removal after overlap window.
2. During the overlap window, admin revokes the old key.
3. The rotation timer fires and removes the old key from the registry — but the admin already revoked it, so the removal is a no-op.
4. However, connections using the old key were not terminated by either the rotation or the revoke (neither closes active connections).
5. The connections remain active with a key that was both rotated and revoked.

### Why current state is insufficient
- **No immediate termination**: Revoking a QKey should immediately close all connections using it. Currently it only prevents new connections — existing ones continue.
- **O(n) lookup**: Finding connections by QKey ID requires iterating all auth states and comparing token hashes. With 1000+ connections, this is slow.
- **No rotation**: Keys don't expire on a schedule. Long-lived keys increase the blast radius of key compromise.
- **No overlap window**: When a key is rotated, existing connections should continue working during a grace period while new connections use the new key. Currently there's no mechanism for this.

## Proposed Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    QKey Lifecycle Manager                         │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────┐ │
│  │  Rotation    │  │  Revocation  │  │  Connection Tracker     │ │
│  │  Scheduler   │  │  Manager     │  │  (QKey → ConnId map)    │ │
│  │              │  │              │  │                         │ │
│  │ • Interval   │  │ • Atomic     │  │ • HashMap<QKeyId,       │ │
│  │   timer      │  │   revoke     │  │   HashSet<ConnId>>      │ │
│  │ • Overlap    │  │ • Immediate  │  │ • O(1) lookup           │ │
│  │   window     │  │   close      │  │ • Generation counter    │ │
│  │ • Gen counter│  │ • Race-safe  │  │ • Epoch-based reclamation│ │
│  └──────┬───────┘  └──────┬───────┘  └───────────┬─────────────┘ │
│         │                 │                       │               │
│         ▼                 ▼                       ▼               │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              QKeyRegistry (enhanced)                         │ │
│  │  • HashMap<String, QKeyRecord> (O(1) lookup by ID)          │ │
│  │  • Generation counter on each record                        │ │
│  │  • Revocation list (separate from active keys)              │ │
│  └─────────────────────────────────────────────────────────────┘ │
│         │                 │                       │               │
│         ▼                 ▼                       ▼               │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              Connection Terminator                           │ │
│  │  • Sends CONNECTION_CLOSE frame to target connections        │ │
│  │  • Removes from LiveServerState.clients and qkey_auth       │ │
│  │  • Updates metrics (revoked, terminated)                     │ │
│  │  • Emits audit log event                                    │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### Generation counters
Each QKey record has a `generation: u64` field. When a key is rotated, the new key gets `generation + 1`. When a key is revoked, its generation is marked as revoked. Connection auth state stores the generation it authenticated with. If the generation doesn't match the current active generation, the connection is terminated.

### Epoch-based reclamation
To safely remove connections from the tracker without use-after-free races, use epoch-based reclamation (via `crossbeam-epoch` or a simple generation-based approach). Connections are marked for removal, and actual removal happens after all in-flight operations on that epoch complete.

## Implementation Plan

### Phase 1: O(1) QKey-to-connection mapping
1. Add `qkey_id: String` field to `QKeyAuthState` (currently only has `expected_token_sha256`).
2. Create `QKeyConnectionTracker` in `src/implementations/server/qkey_tracker.rs`:
   ```rust
   pub struct QKeyConnectionTracker {
       by_qkey: HashMap<String, HashSet<Vec<u8>>>,  // QKeyId → Set<ConnId>
       by_conn: HashMap<Vec<u8>, String>,            // ConnId → QKeyId
       generations: HashMap<String, u64>,            // QKeyId → current generation
   }
   ```
3. On client accept: insert `(qkey_id, conn_id)` into tracker.
4. On client disconnect: remove from tracker.
5. On revoke: `tracker.get_connections(qkey_id)` returns O(1) set of conn IDs to terminate.
6. Protect with `parking_lot::RwLock` — reads (lookup) don't block other reads, only writes (insert/remove) block.

### Phase 2: Atomic revocation with immediate termination
1. Create `RevocationManager` in `src/implementations/server/revocation.rs`:
   ```rust
   pub struct RevocationManager {
       registry: Arc<Mutex<QKeyRegistry>>,
       tracker: Arc<RwLock<QKeyConnectionTracker>>,
       revoked_generations: RwLock<HashSet<(String, u64)>>,
   }
   ```
2. `revoke(qkey_id)`:
   a. Acquire registry lock, remove key, record generation as revoked.
   b. Acquire tracker read lock, get all conn IDs for this QKey.
   c. For each conn ID: find connection in `LiveServerState`, send CONNECTION_CLOSE with reason `b"qkey_revoked"`, remove from `clients` and `qkey_auth`.
   d. Remove all entries from tracker for this QKey.
   e. Emit audit event (TODO-439).
   f. All steps are atomic with respect to the accept loop: the registry lock prevents new accepts using the revoked key, and the tracker lock prevents the connection list from changing during iteration.
3. Fix Race 1: The registry lock is held during the entire revoke operation, preventing new accepts.
4. Fix Race 2: `enforce_qkey_auth_timeouts` checks the revoked generations set before processing — if a conn's QKey generation is revoked, it's closed as revoked (not as timed out).

### Phase 3: Automatic rotation with overlap window
1. Create `RotationScheduler` in `src/implementations/server/rotation.rs`:
   ```rust
   pub struct RotationScheduler {
       interval: Duration,           // e.g., 24 hours
       overlap_window: Duration,     // e.g., 1 hour
       next_rotation: Instant,
   }
   ```
2. On rotation:
   a. Generate new QKey with `generation + 1`.
   b. Insert new key into registry (both old and new are valid during overlap).
   c. Schedule old key revocation after `overlap_window`.
   d. New connections use the new key (registry returns the highest-generation key).
   e. Existing connections continue with the old key during overlap.
   f. After overlap: revoke old key (Phase 2 logic), terminate remaining connections using old key.
3. Rotation is non-disruptive: existing connections keep working during the overlap window. Only after the overlap do old-key connections get terminated.
4. Fix Race 3: Rotation and revoke both go through `RevocationManager`, which serializes operations via the registry lock. If admin revokes a key that's being rotated, the revoke takes precedence (immediate termination, no overlap grace period).

### Phase 4: Connection ID migration handling
1. QUIC connection migration changes the connection's source ID. The tracker must update the conn ID mapping when migration occurs.
2. Hook into the existing migration detection in `reconcile_live_clients()` (line 1596) — when a connection's source ID changes, update the tracker.
3. Use a generation counter on the connection itself: `conn.generation` is set at accept time. If the tracker's generation for this QKey doesn't match, the connection is stale and should be terminated.

### Phase 5: Configuration and CLI
1. Add rotation config to `ServerConfig`:
   ```rust
   pub qkey_rotation_interval_secs: Option<u64>,  // None = no auto-rotation
   pub qkey_overlap_window_secs: u64,             // default 3600 (1 hour)
   ```
2. CLI flags: `--qkey-rotate-interval 86400` (24h), `--qkey-overlap-window 3600` (1h).
3. Admin API: `POST /api/qkey/rotate` triggers manual rotation. `POST /api/qkey/:id/revoke` triggers revocation (already exists but needs to call `RevocationManager`).

## Technology Choices

### Chosen: `parking_lot::RwLock` for tracker
- Already used throughout the codebase (`parking_lot` is a dependency).
- Reader-biased: lookups (frequent) don't block each other. Only writes (accept/disconnect/revoke) block.
- Alternative: `dashmap` — concurrent HashMap with sharded locks. Rejected for simplicity — the tracker is not hot enough to justify sharding. A single RwLock with HashMap is sufficient for <10,000 connections.

### Chosen: Generation counters (not epoch-based reclamation)
- Simpler than `crossbeam-epoch`. Each QKey has a generation. Each connection stores the generation it authenticated with. On any operation, compare generations — if mismatched, the connection is stale.
- No unsafe code. No pinning/unpinning. Just a u64 comparison.
- Alternative: `crossbeam-epoch` — more general but adds complexity and unsafe code for a problem that generation counters solve adequately.

### Chosen: QUIC CONNECTION_CLOSE for termination
- The existing code already uses `conn.conn.close(true, 0x0, reason)` (line 1786, 2751). This sends an immediate CONNECTION_CLOSE frame.
- The `true` parameter means "immediate close" (application error code 0x0).
- Reason is a static byte slice (e.g., `b"qkey_revoked"`, `b"qkey_rotated"`).

### Evaluated and rejected
- **Token-based revocation (per-session tokens)**: Rejected — would require changing the QKey format and breaking backward compatibility. Generation counters achieve the same goal without protocol changes.
- **External revocation service (OCSP for QKeys)**: Rejected — over-engineered for a private VPN. The registry is local; no need for a distributed revocation protocol.
- **Bloom filter for revoked keys**: Rejected — false positives would terminate legitimate connections. The revoked set is small (typically <100 keys); a HashSet is fine.

## Stealth/Efficiency Considerations

### Stealth
- **CONNECTION_CLOSE reason**: The reason field in the CONNECTION_CLOSE frame is visible to DPI. Use generic reasons like `b"connection_closed"` instead of `b"qkey_revoked"` to avoid fingerprinting. The actual reason is logged server-side for audit purposes.
- **Rotation timing**: Randomize rotation interval ±10% to avoid predictable patterns. A fixed 24h rotation creates a detectable pattern in connection churn.
- **Overlap window**: During overlap, both old and new keys are valid. This means no sudden burst of connection terminations at rotation time, which would be a traffic pattern visible to DPI.

### Performance
- **O(1) lookup**: The tracker reduces revocation from O(n) to O(1) for finding affected connections. With 1000 connections, this is the difference between <1ms and ~10ms.
- **RwLock reader bias**: Lookups during normal operation (accept, disconnect) take a read lock — no contention with other readers.
- **Generation counter comparison**: A single u64 compare — negligible overhead.
- **Rotation overlap**: No reconnection storm. Clients can naturally reconnect with the new key during the overlap window, spreading the load.

## Testing Plan

### Unit tests
- `QKeyConnectionTracker`: insert, lookup, remove, O(1) behavior verification.
- `RevocationManager::revoke`: removes key from registry, terminates all connections, emits audit event.
- `RotationScheduler`: generates new key, schedules old key revocation after overlap.
- Generation counter: stale connections (wrong generation) are detected and terminated.
- Race condition tests:
  - Concurrent revoke + accept: no new connection accepted with revoked key.
  - Concurrent revoke + enforce_qkey_auth_timeouts: no double-close, no missed close.
  - Concurrent rotation + revoke: revoke takes precedence, no overlap grace period for revoked key.
  - Connection migration during revoke: tracker updates conn ID, revoke still finds the connection.

### Integration tests
- Full revocation flow: accept client with QKey A → revoke QKey A → verify client receives CONNECTION_CLOSE → verify client is removed from `clients` and `qkey_auth` → verify metrics updated.
- Full rotation flow: accept client with QKey A (gen 1) → rotate → new connections use QKey A (gen 2) → old client still works → overlap expires → old client terminated.
- Rotation under load: 100 active connections, rotate, verify zero dropped packets during overlap, verify all old connections terminated after overlap.

### E2E tests
- Multi-client revocation: 10 clients with QKey A, 10 with QKey B. Revoke A. Verify all A clients terminated, all B clients unaffected.
- Rotation chain: rotate 5 times over 5 minutes. Verify each generation is properly tracked, old generations terminated after overlap.

## Files to Create/Modify

### New files
- `src/implementations/server/qkey_tracker.rs` — `QKeyConnectionTracker` (O(1) QKey→conn mapping)
- `src/implementations/server/revocation.rs` — `RevocationManager` (atomic revoke + terminate)
- `src/implementations/server/rotation.rs` — `RotationScheduler` (auto-rotation with overlap)
- `tests/qkey_revocation.rs` — Revocation integration tests
- `tests/qkey_rotation.rs` — Rotation integration tests
- `tests/qkey_race_conditions.rs` — Race condition tests (concurrent revoke/rotate/accept)

### Modified files
- `src/implementations/server/qkey_registry.rs` — Change `entries: Vec<QKeyRecord>` to `entries: HashMap<String, QKeyRecord>` for O(1) lookup; add `generation: u64` to `QKeyRecord`; add `revoked_generations: HashSet<(String, u64)>`
- `src/implementations/server/mod.rs` — Add `qkey_id` to `QKeyAuthState`; integrate `QKeyConnectionTracker` into `LiveServerState`; replace `revoke()` call in admin handlers with `RevocationManager::revoke()`; add rotation config to `ServerConfig`
- `src/implementations/server/admin_http.rs` — Wire revoke endpoint to `RevocationManager`
- `src/implementations/server/admin.rs` — Wire revoke command to `RevocationManager`
- `src/main.rs` — Add `--qkey-rotate-interval` and `--qkey-overlap-window` CLI flags
- `Cargo.toml` — No new dependencies needed (parking_lot already present)

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Lock contention between accept loop and revocation | Use RwLock (reader-biased). Accept takes read lock on tracker (fast), revoke takes write lock (brief). |
| Connection migration changes conn ID during revoke | Tracker is updated on migration detection (in `reconcile_live_clients`). Revoke re-checks tracker after closing to catch any migrated connections. |
| Generation counter overflow | u64 at 1 rotation/second overflows in 584 billion years. Not a concern. |
| Rotation fails (new key generation error) | Retry with exponential backoff. Old key remains valid until successful rotation. Alert via audit log. |
| Overlap window too short → mass termination | Configurable. Default 1 hour. Document recommendation: set to 2x the typical client session duration. |
| Revocation of non-existent key | Return `false` (already handled). Log warning. No-op. |
| Registry migration (Vec → HashMap) | Backward compatible: `QKeyRecord` adds `generation` field with `#[serde(default)]`. Old registry files load with generation 0. |

## Completion Criteria

- [ ] `QKeyConnectionTracker` provides O(1) lookup of connections by QKey ID
- [ ] `RevocationManager::revoke()` atomically removes key from registry AND terminates all active connections via CONNECTION_CLOSE
- [ ] `RotationScheduler` auto-rotates keys at configurable intervals with overlap window
- [ ] New connections during overlap use the new key generation; existing connections keep the old generation
- [ ] After overlap expires, old-generation connections are terminated
- [ ] Generation counters detect stale connections (wrong generation → terminate)
- [ ] Race condition: concurrent revoke + accept — no new connection accepted with revoked key
- [ ] Race condition: concurrent revoke + enforce_qkey_auth_timeouts — no double-close, no missed close
- [ ] Race condition: rotation + revoke — revoke takes precedence, no grace period for revoked key
- [ ] Connection migration during revoke — tracker updates, revoke finds migrated connection
- [ ] CONNECTION_CLOSE reason is generic (not `b"qkey_revoked"`) for stealth
- [ ] Rotation interval is randomized ±10% to avoid traffic patterns
- [ ] All unit, integration, race condition, and E2E tests pass
- [ ] Audit events emitted for: key issuance, rotation, revocation, connection termination
