---
id: TODO-457
title: "Mutual authentication and replay protection for QKey system"
severity: HIGH
phase: "H"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: ["TODO-434"]
---

# TODO-457: Mutual authentication and replay protection for QKey system

## Problem

The QKey authentication system is a **one-way bearer-token check** with
no mutual authentication and no replay protection. The client presents
a QKey token to prove its identity, but the server never proves its
identity to the client beyond the TLS certificate. If the QKey token is
transported over any channel other than the TLS-protected QUIC
connection (e.g. a sidecar HTTP API, a control-plane proxy, or a
future non-QUIC transport), the token is a replayable bearer
credential.

### Evidence

1. `QKeyRegistry::insert_with_ttl`
   (`src/implementations/server/qkey_registry.rs:154-179`) stores only
   a SHA-256 hash of the token (`token_sha256`). Authentication is a
   pure hash comparison — there is no nonce, no timestamp, no
   challenge, and no session binding.
2. `token_matches_hash` (`qkey_registry.rs`, called at
   `mod.rs:1691`) compares `provided` against `expected.trim()`. This
   is a constant-time comparison of a raw token against a stored hash.
   The token itself is the credential — anyone who captures it can
   replay it indefinitely.
3. There is no TLS exporter binding (RFC 5705): the QKey verification
   is independent of the TLS session. A token captured from one TLS
   session can be replayed on a different TLS session to the same
   server.
4. The server does not require client certificates. TLS mutual auth is
   not configured anywhere in the QUIC/TLS setup path
   (`src/qftls.rs`). The server's identity is proven only by its TLS
   certificate (server-only auth), so a client cannot cryptographically
   verify that it is talking to the *authorized* QKey-protected server
   vs. a rogue server that stole the certificate.
5. No nonce tracking exists: there is no `HashSet<Nonce>` or
   `HashMap<Nonce, Instant>` anywhere in `qkey_registry.rs` or
   `mod.rs`. A replayed token is indistinguishable from a fresh token.

### Attack scenarios

- **Token replay:** An attacker who captures a QKey token (via
  network sniffing on an insecure side-channel, log file, or backup)
  can authenticate as the legitimate client until the token expires.
- **MITM without client cert:** Without mutual TLS, a rogue server
  with a stolen/compromised CA can present a valid certificate, collect
  the client's QKey token, and forward traffic.
- **Token transplant:** A QKey token from TLS session A works on TLS
  session B because there is no session binding.

## Goal

- **Mutual TLS authentication:** QKey-protected servers require client
  certificates. A client without a valid client cert cannot even reach
  the QKey auth stage.
- **QKey token binding to TLS session:** QKey verification is derived
  from the TLS exporter (RFC 5705) so that a token is valid only
  within the TLS session that created it. A token from session A
  fails on session B.
- **Replay protection:** QKey auth uses a nonce + timestamp. The
  server tracks used nonces within the token's validity window and
  rejects replayed nonces.
- **Challenge-response for QKey transport:** The server sends a random
  challenge; the client proves QKey possession by computing
  `HMAC-SHA-256(qkey, challenge || tls_exporter_value)` and sending
  the result — never the raw token.
- Tests prove: replay attacks fail, token binding detects MITM
  (token from session A rejected on session B), mutual auth requires a
  client cert.

## Implementation Plan

### Step 1: Enable mutual TLS (client certificate required)

**File:** `src/qftls.rs`, `src/implementations/server/mod.rs`

- In the server's TLS configuration (where `rustls::ServerConfig` is
  built), set:
  ```rust
  server_config.client_auth = rustls::server::ClientAuth::Required;
  ```
  with a `WebPkiClientVerifier` rooted in a configurable client CA
  (path from `QUICFUSCATE_CLIENT_CA_PATH` env var or config field
  `client_ca_path`).
- Add a `require_client_cert: bool` config field (default: `true` for
  QKey-protected servers, `false` for open servers).
- On the client side, load a client cert + key pair from
  `QUICFUSCATE_CLIENT_CERT_PATH` / `QUICFUSCATE_CLIENT_KEY_PATH` and
  set `client_config.client_auth = ClientAuth::Single(cert_chain, key)`.
- Reject connections that do not present a client cert at the TLS
  layer, before any QKey processing.

### Step 2: Add TLS exporter binding (RFC 5705)

**File:** `src/qftls.rs`, `src/crypto/mod.rs`

- Expose the TLS exporter on the QUIC connection:
  ```rust
  pub fn tls_exporter_secret(&self, label: &str, context: &[u8], out: &mut [u8]) -> Result<(), ExporterError>
  ```
  This calls `rustls`'s exporter API (or `quinn`'s
  `Connection::export_keying_material`) with a label like
  `b"quicfuscate qkey binding"` and a context derived from the QKey
  ID.
- The exporter value is a per-session secret that is cryptographically
  bound to the TLS handshake. It cannot be computed by an attacker who
  does not participate in the TLS session.

### Step 3: Redesign QKey auth as challenge-response

**File:** `src/implementations/server/qkey_registry.rs`,
`src/implementations/server/mod.rs`

- Replace the current `token_matches_hash(provided, expected)` call
  (`mod.rs:1691`) with a challenge-response protocol:
  1. **Server sends challenge:** During the initial handshake (before
     QKey auth), the server generates a 32-byte random `challenge`
     and sends it to the client (in the initial auth frame).
  2. **Client computes proof:** The client computes
     `proof = HMAC-SHA-256(qkey_token, challenge || tls_exporter_secret)`
     and sends `proof` + `nonce` + `timestamp` to the server (instead
     of the raw token).
  3. **Server verifies:** The server looks up the QKey entry by ID,
     recomputes `expected_proof = HMAC-SHA-256(stored_token, challenge
     || tls_exporter_secret)`, and compares `proof == expected_proof`
     in constant time.
- The raw QKey token is **never sent over the wire** after this change.
- The `tls_exporter_secret` is computed on both sides from the active
  TLS session, binding the proof to this specific connection.

### Step 4: Add nonce + timestamp replay protection

**File:** `src/implementations/server/qkey_registry.rs`

- Add a `used_nonces: HashMap<Nonce, Instant>` to `QKeyRegistry` (or
  to a per-QKey `ReplayWindow` struct). The nonce is a client-generated
  16-byte random value included in the auth proof.
- On receiving an auth proof:
  1. Check `timestamp` is within the allowed clock skew window
     (default ±60s). Reject if stale.
  2. Check `nonce` is not in `used_nonces`. If present, reject as
     replay.
  3. After successful verification, insert `nonce` into
     `used_nonces` with the current `Instant`.
- Prune `used_nonces` entries older than the QKey's validity window
  (or a fixed `replay_window` duration, default 5 minutes) in the
  existing `prune_expired` call.
- Bound `used_nonces` size: if it exceeds `max_nonces` (default
  100_000), evict oldest entries (LRU).

### Step 5: Define wire format for the challenge-response auth frame

**File:** `src/implementations/server/mod.rs` (or a new
`src/implementations/server/auth_frame.rs`)

- Define a binary frame:
  ```
  [1 byte: frame_type = 0xQK]
  [32 bytes: challenge (server→client)]
  [16 bytes: nonce (client→server)]
  [8 bytes: timestamp (client→server, Unix epoch seconds)
  [32 bytes: proof (client→server, HMAC-SHA-256)]
  ```
- Update `parse_live_server_initial_auth` (the function that currently
  extracts the raw QKey token) to parse the new frame format instead.

### Step 6: Update client-side QKey auth

**File:** `src/implementations/client/` (client auth path)

- The client must:
  1. Receive the server's `challenge`.
  2. Compute `tls_exporter_secret` for the current QUIC connection.
  3. Generate a 16-byte random `nonce` and current `timestamp`.
  4. Compute `proof = HMAC-SHA-256(qkey_token, challenge ||
     tls_exporter_secret)`.
  5. Send `nonce || timestamp || proof` to the server.
- The client no longer sends the raw QKey token.

### Step 7: Tests

**File:** `tests/mutual_auth_replay_test.rs` (new),
`src/implementations/server/qkey_registry.rs` (inline tests)

- Test: replay attack — capture a valid `(nonce, timestamp, proof)`,
  replay it; server rejects with `b"replay_detected"`.
- Test: token binding — compute a proof with TLS session A's exporter
  secret, present it on TLS session B; server rejects with
  `b"token_binding_failed"`.
- Test: mutual auth — connect without a client cert; TLS handshake
  fails (server rejects at TLS layer).
- Test: challenge-response — client sends raw token instead of proof;
  server rejects with `b"invalid_auth_frame"`.
- Test: nonce uniqueness — two auth attempts with the same nonce
  (within the replay window); second is rejected.
- Test: timestamp skew — auth with a timestamp >60s old is rejected
  with `b"stale_timestamp"`.
- Test: legitimate auth — valid client cert + valid challenge-response
  proof + fresh nonce → `Authenticated`.

## Files to Modify/Create

- `src/qftls.rs` — enable mutual TLS (client cert required), expose
  TLS exporter secret
- `src/implementations/server/mod.rs` — replace `token_matches_hash`
  with challenge-response verification; parse new auth frame; send
  challenge
- `src/implementations/server/qkey_registry.rs` — add `used_nonces`
  replay window, nonce/timestamp validation, `ReplayWindow` struct
- `src/implementations/client/` — client-side challenge-response
  computation (no raw token sent)
- `src/implementations/server/auth_frame.rs` — **new**: wire format
  for challenge-response auth frame
- `src/engine/config.rs` — add `require_client_cert`,
  `client_ca_path`, `replay_window_secs`, `max_nonces` config fields
- `tests/mutual_auth_replay_test.rs` — **new**: integration tests for
  replay, binding, mutual auth, challenge-response

## Acceptance Criteria

- [ ] Server requires client certificates when `require_client_cert`
      is `true` (default for QKey-protected servers).
- [ ] Client cert path is configurable via
      `QUICFUSCATE_CLIENT_CERT_PATH` / `QUICFUSCATE_CLIENT_KEY_PATH`.
- [ ] Client CA path is configurable via
      `QUICFUSCATE_CLIENT_CA_PATH`.
- [ ] QKey auth uses challenge-response: server sends 32-byte
      challenge, client sends `HMAC-SHA-256(token, challenge ||
      exporter_secret)` proof.
- [ ] Raw QKey token is never transmitted after this change.
- [ ] TLS exporter (RFC 5705) binds the proof to the active TLS
      session; proof from session A fails on session B.
- [ ] Server tracks used nonces in a `ReplayWindow`; replayed nonces
      are rejected.
- [ ] Timestamps outside ±60s skew window are rejected.
- [ ] `used_nonces` is pruned periodically and bounded by
      `max_nonces`.
- [ ] Test: replay attack fails.
- [ ] Test: token binding detects MITM (cross-session proof
      rejected).
- [ ] Test: mutual auth requires client cert.
- [ ] Test: legitimate auth with valid cert + proof + nonce succeeds.
- [ ] `cargo test` passes with all new tests green.
- [ ] `cargo clippy` reports no new warnings.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| TLS exporter computation | < 50 µs | `quinn::Connection::export_keying_material`; one per auth |
| HMAC-SHA-256 proof (client + server) | < 5 µs total | Two HMAC computations over ~64 bytes |
| Challenge generation (32 bytes) | < 1 µs | `rand::fill` |
| Nonce lookup in `used_nonces` | < 200 ns | `HashMap` lookup under `Mutex` |
| `ReplayWindow` prune per cycle | < 100 µs | `HashMap::retain` over ~10k entries; runs every 60s |
| Memory per tracked nonce | ~40 bytes | `Nonce (16B)` + `Instant (16B)` + HashMap overhead |
| Mutual TLS handshake overhead | +1 RTT | Client cert verification adds one round trip |
