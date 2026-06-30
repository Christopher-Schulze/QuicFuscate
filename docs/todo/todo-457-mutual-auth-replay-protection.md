---
id: TODO-457
title: "Mutual authentication and replay protection for QKey transport"
severity: HIGH
phase: "I"
priority: P1
status: DONE
created: 2026-07-23
depends_on: ["TODO-434"]
---

# TODO-457: Mutual Authentication and Replay Protection for QKey Transport

## Goal
Replace the current one-way bearer-token QKey authentication with a challenge-response protocol that binds the QKey proof to the TLS session (RFC 5705 keying material exporter), tracks nonces for replay protection, and optionally requires mutual TLS (client certificates). The design must be backward compatible — supporting both bearer token (legacy) and challenge-response (new) during a transition period, then phasing out bearer tokens. Nonce storage must use bounded memory (TTL-based eviction or ring buffer).

## Current State (verified against code)

### QKey auth is a one-way bearer-token check
`src/implementations/server/mod.rs:1630-1677` — `parse_live_server_initial_auth` extracts the QKey ID from the Initial packet token and creates a `QKeyAuthState`:
```rust
pub fn parse_live_server_initial_auth(
    packet: &[u8],
    qkey_registry: &std::sync::Mutex<QKeyRegistry>,
    metrics: &Metrics,
) -> Option<LiveInitialAuthContext> {
    // ...
    let record = registry.lookup_initial_id_token(&token);
    let Some(record) = record else {
        record_qkey_auth_rejection(metrics);
        return None;
    };
    pending_qkey_auth = Some(QKeyAuthState {
        expected_token_sha256: record.token_sha256.clone(),
        authed: false,
        connected_at: Instant::now(),
    });
    // ...
}
```

### QKeyAuthState stores only a hash
`src/implementations/server/mod.rs:2904-2909`:
```rust
pub struct QKeyAuthState {
    pub expected_token_sha256: String,
    pub authed: bool,
    pub connected_at: Instant,
}
```
No nonce, no timestamp, no challenge, no session binding.

### Token verification is a plain hash comparison
`src/implementations/server/mod.rs:1738-1776` — `QKeyHeaderAuthOutcome`:
```rust
pub enum QKeyHeaderAuthOutcome {
    Unchanged,
    Authenticated,
    Reject(&'static [u8]),
}
```
The actual verification at line 1771:
```rust
if crate::implementations::server::qkey_registry::token_matches_hash(provided, expected.trim()) {
    QKeyHeaderAuthOutcome::Authenticated
} else {
    QKeyHeaderAuthOutcome::Reject(b"invalid_qkey_auth")
}
```

### token_matches_hash is a SHA-256 comparison
`src/implementations/server/qkey_registry.rs:446-450`:
```rust
pub fn token_matches_hash(token_hex: &str, stored_hash: &str) -> bool {
    token_sha256_hex_from_token_hex(token_hex)
        .map(|h| h.eq_ignore_ascii_case(stored_hash))
        .unwrap_or(false)
}
```
The raw token is sent over the wire and compared against a stored hash. Anyone who captures the token can replay it indefinitely.

### QKeyRecord stores token_sha256
`src/implementations/server/qkey_registry.rs:138-153`:
```rust
pub struct QKeyRecord {
    pub id: String,
    pub name: Option<String>,
    pub token_sha256: String,    // SHA-256 of the 32-byte token
    pub stealth: Option<String>,
    pub fec: Option<String>,
    pub created_at: u64,
    // ... no nonce tracking, no replay window
}
```

### QKeyConfig has token field
`src/engine/qkey.rs:59-79`:
```rust
pub struct QKeyConfig {
    pub remote: String,
    pub sni: String,
    pub stealth: Option<String>,
    pub fec: Option<String>,
    pub extra: Option<String>,
    pub token: Option<String>,   // QKey auth token (hex)
    pub md5: String,             // Checksum
}
```

### No TLS exporter binding
No `export_keying_material` or `KeyingMaterialExporter` usage anywhere in the codebase. The QKey verification is independent of the TLS session. A token from session A works on session B.

### No mutual TLS
The server's TLS configuration does not require client certificates. Server identity is proven only by its TLS certificate (server-only auth).

### No nonce tracking
No `HashSet<Nonce>` or `HashMap<Nonce, Instant>` anywhere in `qkey_registry.rs` or `mod.rs`. A replayed token is indistinguishable from a fresh token.

### QKey auth timeout exists
`src/implementations/server/mod.rs:2911-2914`:
```rust
impl QKeyAuthState {
    pub fn is_expired(&self) -> bool {
        !self.authed && self.connected_at.elapsed() > QKEY_AUTH_TIMEOUT
    }
}
```
This is a connection-level timeout (unauthenticated connections are dropped after `QKEY_AUTH_TIMEOUT`), not a replay window.

## Problem Analysis

The current QKey authentication has three critical vulnerabilities:

1. **Token replay**: An attacker who captures a QKey token (via network sniffing on an insecure side-channel, log file, or backup) can authenticate as the legitimate client until the token expires. The raw token is sent over the wire and compared against a stored hash — it's a bearer credential.

2. **No session binding (token transplant)**: A QKey token from TLS session A works on TLS session B because there is no binding to the TLS session. The token is verified independently of the connection's cryptographic context.

3. **No mutual authentication**: Without mutual TLS, a rogue server with a stolen/compromised CA can present a valid certificate, collect the client's QKey token, and forward traffic (MITM attack).

## Proposed Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│              Challenge-Response Auth Flow                         │
│                                                                   │
│  Client                           Server                          │
│    │                                │                              │
│    │  QUIC Initial (with QKey ID)   │                              │
│    │───────────────────────────────▶│                              │
│    │                                │                              │
│    │  Auth Challenge Frame          │                              │
│    │  (32-byte random challenge)    │                              │
│    │◀───────────────────────────────│                              │
│    │                                │                              │
│    │  Compute:                      │                              │
│    │  exporter = TLS_exporter(      │                              │
│    │    label, context, 32)         │                              │
│    │  proof = HMAC-SHA-256(         │                              │
│    │    qkey_token,                 │                              │
│    │    challenge || exporter)      │                              │
│    │  nonce = random 16 bytes       │                              │
│    │  timestamp = current Unix      │                              │
│    │                                │                              │
│    │  Auth Response Frame           │                              │
│    │  (nonce, timestamp, proof)     │                              │
│    │───────────────────────────────▶│                              │
│    │                                │                              │
│    │                    Verify:     │                              │
│    │                    1. Check timestamp ±60s                   │
│    │                    2. Check nonce not in ReplayWindow        │
│    │                    3. Compute expected_proof =               │
│    │                       HMAC-SHA-256(stored_token,             │
│    │                       challenge || exporter)                 │
│    │                    4. Compare proof == expected_proof        │
│    │                    5. Insert nonce into ReplayWindow         │
│    │                                │                              │
│    │  Authenticated / Rejected      │                              │
│    │◀───────────────────────────────│                              │
│                                                                   │
│  Backward compat: legacy clients send raw token →                 │
│    server accepts if `allow_legacy_auth = true`                   │
└──────────────────────────────────────────────────────────────────┘
```

## Implementation Plan

### Step 1: Enable mutual TLS (client certificate required)
In `src/qftls.rs`, where `rustls::ServerConfig` is built:
```rust
server_config.client_auth = rustls::server::ClientAuth::Required;
```
with a `WebPakiClientVerifier` rooted in a configurable client CA. Add `require_client_cert: bool` config field (default: `true` for QKey-protected servers). On client side, load cert + key from `QUICFUSCATE_CLIENT_CERT_PATH` / `QUICFUSCATE_CLIENT_KEY_PATH`.

### Step 2: Add TLS exporter binding (RFC 5705)
In `src/qftls.rs` / `src/crypto/mod.rs`:
```rust
pub fn tls_exporter_secret(
    &self,
    label: &str,
    context: &[u8],
    out: &mut [u8],
) -> Result<(), ExporterError>
```
Uses rustls `KeyingMaterialExporter::derive()` (RFC 5705). The exporter value is a per-session secret bound to the TLS handshake — cannot be computed by an attacker who doesn't participate in the session.

### Step 3: Redesign QKey auth as challenge-response
Replace `token_matches_hash(provided, expected)` at `mod.rs:1771` with:
1. **Server sends challenge**: 32-byte random `challenge` in the initial auth frame
2. **Client computes proof**: `proof = HMAC-SHA-256(qkey_token, challenge || tls_exporter_secret)`
3. **Client sends**: `nonce` (16 bytes) + `timestamp` (8 bytes) + `proof` (32 bytes)
4. **Server verifies**: recomputes `expected_proof = HMAC-SHA-256(stored_token, challenge || tls_exporter_secret)`, compares in constant time

The raw QKey token is **never sent over the wire** after this change.

### Step 4: Add nonce + timestamp replay protection
In `src/implementations/server/qkey_registry.rs`, add `ReplayWindow`:
```rust
pub struct ReplayWindow {
    used_nonces: HashMap<[u8; 16], Instant>,
    max_nonces: usize,           // default 100,000
    replay_window_secs: u64,     // default 300 (5 min)
}
impl ReplayWindow {
    pub fn check_and_insert(&mut self, nonce: &[u8; 16]) -> bool { ... }
    pub fn prune_expired(&mut self) { ... }
}
```
On receiving an auth proof:
1. Check `timestamp` within ±60s skew window. Reject if stale.
2. Check `nonce` not in `used_nonces`. If present, reject as replay.
3. After successful verification, insert `nonce` with current `Instant`.
4. Prune entries older than `replay_window_secs` in the existing `prune_expired` call.
5. Bound `used_nonces` size: if exceeds `max_nonces`, evict oldest (LRU).

### Step 5: Define wire format for auth frame
Create `src/implementations/server/auth_frame.rs`:
```
[1 byte:  frame_type = 0xQK]
[1 byte:  version = 0x02]     (0x01 = legacy bearer)
[32 bytes: challenge (server→client)]
[16 bytes: nonce (client→server)]
[8 bytes:  timestamp (client→server, Unix epoch seconds)]
[32 bytes: proof (client→server, HMAC-SHA-256)]
```
Update `parse_live_server_initial_auth` to parse the new frame format.

### Step 6: Update client-side QKey auth
The client must:
1. Receive the server's `challenge`
2. Compute `tls_exporter_secret` for the current QUIC connection
3. Generate a 16-byte random `nonce` and current `timestamp`
4. Compute `proof = HMAC-SHA-256(qkey_token, challenge || tls_exporter_secret)`
5. Send `nonce || timestamp || proof` to the server
6. Never send the raw QKey token

### Step 7: Backward compatibility
Support both bearer token (legacy) and challenge-response (new):
- Config field: `allow_legacy_auth: bool` (default: `true` during transition, `false` after phase-out)
- When `allow_legacy_auth = true` and client sends `version = 0x01` (bearer), fall back to `token_matches_hash`
- When `allow_legacy_auth = false` and client sends `version = 0x01`, reject with `b"legacy_auth_disabled"`
- Log warning when legacy auth is used: `WARN qkey_auth: client used legacy bearer auth, consider upgrading`

## Technology Choices

| Choice | Selection | Rationale |
|--------|-----------|-----------|
| TLS exporter | rustls `KeyingMaterialExporter::derive()` (RFC 5705) | Standard TLS keying material exporter; per-session secret; cannot be computed without participating in TLS handshake |
| Challenge-response | HMAC-SHA-256(qkey_token, challenge || exporter) | Standard challenge-response; token never sent over wire; HMAC provides cryptographic proof of possession |
| Nonce | 16-byte random (client-generated) | Sufficient entropy (128 bits); client-generated to prevent server-side prediction |
| Timestamp | 8-byte Unix epoch seconds | Allows server to reject stale auth attempts; ±60s skew window handles clock drift |
| Replay window | `HashMap<[u8;16], Instant>` with TTL-based eviction | Bounded memory (max 100K entries); prune expired entries periodically; O(1) lookup |
| Mutual TLS | rustls `ClientAuth::Required` with `WebPakiClientVerifier` | Standard rustls API; requires client cert at TLS layer before QKey processing |
| Nonce storage alternative: ring buffer | Considered | Fixed-size, no eviction needed; but can't guarantee replay detection within full window. HashMap with TTL is more flexible |
| Alternative: Bloom filter for nonces | Considered | O(1) memory, but has false positives (would reject legitimate nonces). HashMap is more reliable |

## Stealth/Efficiency Considerations

- **TLS exporter computation**: < 50µs per auth (one `KeyingMaterialExporter::derive()` call). Only computed once per connection at auth time — not on the hot path.
- **HMAC-SHA-256 proof**: < 5µs total (two HMAC computations over ~64 bytes on client + server). Only at auth time.
- **Challenge generation**: < 1µs (`rand::fill` for 32 bytes). Only at auth time.
- **Nonce lookup**: < 200ns (`HashMap` lookup under `Mutex`). Only at auth time.
- **ReplayWindow prune**: < 100µs (`HashMap::retain` over ~10K entries). Runs every 60s in the existing `prune_expired` call — not on the hot path.
- **Memory per tracked nonce**: ~40 bytes (`Nonce (16B)` + `Instant (16B)` + HashMap overhead). For 100K nonces: ~4MB — bounded by `max_nonces`.
- **Mutual TLS handshake overhead**: +1 RTT for client cert verification. Only at connection setup — not on the hot path. Document this latency cost.
- **Stealth impact**: The challenge-response auth flow adds one round trip to the connection setup. This is within the QUIC handshake and doesn't create a distinguishable traffic pattern. The auth frame is encrypted within the TLS session — an observer can't see the challenge, nonce, or proof.
- **Backward compatibility**: Legacy bearer auth is supported during transition. The `version` byte in the auth frame distinguishes legacy from new. This allows gradual client upgrades without breaking existing deployments.
- **No hot-path impact**: All auth operations happen once per connection at setup time. The per-packet path is unaffected.

## Testing Plan

### Unit tests
- `test_replay_window_check_and_insert` — fresh nonce is accepted, duplicate is rejected
- `test_replay_window_prune_expired` — entries older than TTL are pruned
- `test_replay_window_max_nonces` — when `max_nonces` exceeded, oldest entries evicted
- `test_timestamp_skew_accept` — timestamp within ±60s is accepted
- `test_timestamp_skew_reject_stale` — timestamp > 60s old is rejected
- `test_timestamp_skew_reject_future` — timestamp > 60s in future is rejected
- `test_hmac_proof_verification` — correct proof is verified, wrong proof is rejected
- `test_auth_frame_serialize_deserialize` — frame round-trips correctly
- `test_auth_frame_legacy_version` — version 0x01 is parsed as legacy bearer

### Integration tests
- `test_replay_attack_fails` — capture a valid `(nonce, timestamp, proof)`, replay it; server rejects with `b"replay_detected"`
- `test_token_binding_detects_mitm` — compute proof with TLS session A's exporter, present on session B; server rejects with `b"token_binding_failed"`
- `test_mutual_auth_requires_client_cert` — connect without a client cert; TLS handshake fails
- `test_challenge_response_raw_token_rejected` — client sends raw token instead of proof; server rejects with `b"invalid_auth_frame"`
- `test_nonce_uniqueness` — two auth attempts with same nonce; second is rejected
- `test_timestamp_stale_rejected` — auth with timestamp >60s old is rejected with `b"stale_timestamp"`
- `test_legitimate_auth_succeeds` — valid client cert + valid challenge-response proof + fresh nonce → `Authenticated`
- `test_legacy_auth_backward_compat` — with `allow_legacy_auth = true`, legacy bearer token is accepted
- `test_legacy_auth_disabled` — with `allow_legacy_auth = false`, legacy bearer token is rejected with `b"legacy_auth_disabled"`
- `test_replay_window_bounded_memory` — after 100K+ auth attempts, `used_nonces` size stays within `max_nonces`

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `src/qftls.rs` | Modify | Enable mutual TLS (client cert required); expose TLS exporter secret via `KeyingMaterialExporter` |
| `src/implementations/server/auth_frame.rs` | Create | Wire format for challenge-response auth frame (serialize/deserialize) |
| `src/implementations/server/mod.rs:1630-1677, 1738-1776` | Modify | Replace `token_matches_hash` with challenge-response verification; parse new auth frame; send challenge |
| `src/implementations/server/mod.rs:2904-2909` | Modify | Extend `QKeyAuthState` with challenge, nonce tracking |
| `src/implementations/server/qkey_registry.rs` | Modify | Add `ReplayWindow` struct with nonce tracking, TTL-based eviction, `max_nonces` bound |
| `src/implementations/client/` | Modify | Client-side challenge-response computation (no raw token sent) |
| `src/engine/config.rs` | Modify | Add `require_client_cert`, `client_ca_path`, `replay_window_secs`, `max_nonces`, `allow_legacy_auth` config fields |
| `src/engine/qkey.rs` | Modify | Update `QKeyConfig` if needed for challenge-response protocol version |
| `tests/mutual_auth_replay_test.rs` | Create | Integration tests for replay, binding, mutual auth, challenge-response, backward compat |

## Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Mutual TLS breaks existing clients without client certs | High | `require_client_cert` defaults to `true` but is configurable; document migration path; provide cert generation tooling |
| TLS exporter not available in QUIC transport layer | Medium | Verify `quinn`/transport layer supports `export_keying_material`; if not, use rustls `KeyingMaterialExporter` directly |
| ReplayWindow memory growth under attack | Medium | `max_nonces` bound (default 100K); LRU eviction; TTL-based pruning in existing `prune_expired` |
| Clock skew between client and server | Medium | ±60s skew window (configurable); document NTP requirement for server |
| Backward compatibility breaks during transition | Medium | `allow_legacy_auth = true` during transition; log warnings for legacy auth; phase out after all clients upgraded |
| Challenge-response adds latency to connection setup | Low | +1 RTT for challenge-response + +1 RTT for mutual TLS = +2 RTT total; acceptable for VPN connection setup |
| Client cert distribution complexity | Medium | Document cert generation (openssl); provide admin API for cert management; consider auto-provisioning |
| Nonce collision (birthday paradox) | Low | 16-byte nonce = 128 bits; collision probability negligible for 100K nonces |

## Completion Criteria

- [ ] Server requires client certificates when `require_client_cert` is `true` (default for QKey-protected servers)
- [ ] Client cert path is configurable via `QUICFUSCATE_CLIENT_CERT_PATH` / `QUICFUSCATE_CLIENT_KEY_PATH`
- [ ] Client CA path is configurable via `QUICFUSCATE_CLIENT_CA_PATH`
- [ ] QKey auth uses challenge-response: server sends 32-byte challenge, client sends `HMAC-SHA-256(token, challenge || exporter_secret)` proof
- [ ] Raw QKey token is never transmitted after this change (for new protocol version)
- [ ] TLS exporter (RFC 5705) binds the proof to the active TLS session; proof from session A fails on session B
- [ ] Server tracks used nonces in a `ReplayWindow`; replayed nonces are rejected
- [ ] Timestamps outside ±60s skew window are rejected
- [ ] `used_nonces` is pruned periodically and bounded by `max_nonces`
- [ ] Backward compatibility: legacy bearer auth works when `allow_legacy_auth = true`
- [ ] Legacy auth is rejected when `allow_legacy_auth = false`
- [ ] Test: replay attack fails
- [ ] Test: token binding detects MITM (cross-session proof rejected)
- [ ] Test: mutual auth requires client cert
- [ ] Test: legitimate auth with valid cert + proof + nonce succeeds
- [ ] Test: replay window memory stays bounded under high auth volume
- [ ] `cargo test` passes with all new tests green
- [ ] `cargo clippy` reports no new warnings
