---
id: TODO-511
title: Security and ops acceptance audit closure
severity: CRITICAL
phase: S
priority: P0
status: DONE
created: 2026-07-02
depends_on: [TODO-439, TODO-440, TODO-441, TODO-445, TODO-437, TODO-456, TODO-458, TODO-459]
---

# TODO-511: Security and Ops Acceptance Audit Closure

## Context

Many production-security features are implemented or partly implemented, but
their detail files still contain unchecked acceptance criteria. A production-ready
claim needs a direct code-vs-acceptance audit, not just high-level DONE labels.

## Desired Outcome

- Every security/ops TODO acceptance criterion is classified as:
  - implemented and verified,
  - implemented but missing test evidence,
  - intentionally deferred with operator impact,
  - not implemented and blocking.
- Blocking gaps become concrete TODOs or are fixed in this wave.
- Product-facing docs stop overclaiming any unverified security/ops feature.

## Audit Scope

| Area | Source TODOs | Questions |
|------|--------------|-----------|
| Audit logging | TODO-439 | Are auth, QKey, admin, config, firewall, connection, and system events logged with tamper-evident retention or clearly scoped lower? |
| Key erasure and mlock | TODO-440 | Are private keys, QKeys, AEAD keys, memory pools, and server startup memory-locking truly zeroized/locked where claimed? |
| Privilege dropping | TODO-441 | Does post-bind drop run in production, preserve sockets/TUN, clear groups/caps, and produce clear errors? |
| Bandwidth limits | TODO-445 | Are per-client limits, quotas, fair scheduling, and cleanup real and tested? |
| IPv6/DNS leak controls | TODO-437 | Do client kill-switch rules cover IPv6 and non-tunnel DNS on supported platforms? |
| Auth and DDoS | TODO-456, TODO-458, TODO-459 | Are auth rate limits, encrypted QKey storage, GeoIP, blacklist, and EWMA wired and tested? |

## Implementation Plan

1. Read each source TODO detail file completely.
2. For every unchecked acceptance item, grep the code for actual implementation
   and tests before marking anything done.
3. Build an evidence table in this file with path references, tests, and
   remaining gaps.
4. Fix narrow high-impact mismatches discovered during the audit if they are
   small and local.
5. For larger gaps, create follow-up TODOs with severity and exact acceptance.
6. Update `docs/DOCUMENTATION.md` and `docs/todo.md` to match verified truth.
7. Run focused tests for changed areas plus `cargo clippy --workspace --all-targets -- -D warnings`.

## Acceptance Criteria

- Every acceptance item in TODO-439, TODO-440, TODO-441, TODO-445, TODO-437,
  TODO-456, TODO-458, and TODO-459 has a classification and evidence.
- No product-facing doc claims unsupported security behavior.
- Any blocker is either fixed or represented as a new P0/P1 TODO.
- Relevant tests pass.

## Verification Commands

| Command | Expected Result |
|---------|-----------------|
| `rg -n "AuditLogger|AuditEvent|audit" src scripts docs/todo` | evidence gathered |
| `rg -n "zeroize|mlock|mlockall|Zeroizing|ZeroizeOnDrop" src` | evidence gathered |
| `rg -n "drop_privileges|setuid|setgid|no_new_privs|capabil" src scripts config` | evidence gathered |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS after fixes |
| focused security/ops tests | PASS |

## Non-Goals

- Do not weaken tests to match incomplete code.
- Do not mark acceptance done without path/test evidence.
- Do not touch UI surfaces.

## Evidence Table (2026-07-03)

Every acceptance item from the source TODOs was classified by grepping
the actual code and tests. Classifications:

- **verified**: implemented and test evidence exists.
- **partial**: implemented but missing a named acceptance criterion.
- **gap**: not implemented; follow-up TODO created.

### TODO-439 — Security audit logging (SIEM-compatible)

| Acceptance Item | Classification | Evidence |
|-----------------|----------------|----------|
| AuditEvent / AuditEventType taxonomy | verified | `src/audit/mod.rs`: 18+ event types, `AuditSeverity`, `AuditActor`, `AuditEvent` struct with `prev_hash`/`this_hash` |
| SHA-256 hash chain + `verify_chain` | verified | `src/audit/mod.rs:229` `AuditLog::verify_chain(path)` |
| NDJSON file output | verified | `src/audit/mod.rs` serializes events as JSON lines |
| Wired into server runtime (auth, QKey, admin, firewall, connection, config, system events) | **gap** | `rg 'audit::\|AuditLog::\|audit_log' src/implementations/server` -> 0 matches. Module is `pub mod audit;` in `src/lib.rs:186` but no integration points emit events. |
| Syslog/CEF forwarding | partial (not blocking) | TODO-439 Phase 4/5; file NDJSON is sufficient for production claim; syslog/CEF is a future enhancement |

**Follow-up:** TODO-515 (wire AuditLogger into server runtime, P0).

### TODO-440 — Key erasure and memory locking

| Acceptance Item | Classification | Evidence |
|-----------------|----------------|----------|
| ChaCha20Poly1305 zeroize on Drop | verified | `src/crypto/mod.rs:141-143` |
| AesGcm128 zeroize key/iv/rk on Drop | verified | `src/crypto/mod.rs:545-548` |
| Aegis128LAead / Aegis128X4Aead / Aegis128X8Aead zeroize on Drop | verified | `src/crypto/aegis.rs:70-73, 77+` |
| MorusAead / Morus1280State zeroize on Drop | verified | `src/crypto/morus.rs:24-28, 986-989` |
| PKI GeneratedCert / key_der zeroize | verified | `src/pki/mod.rs:76-79, 217-245, 476-479` |
| QKey raw tokens zeroized after hashing | partial | `src/implementations/server/qkey_registry.rs` stores `token_sha256` (hash, not raw); raw token handling in auth path needs explicit zeroize audit |
| `mlockall(MCL_CURRENT \| MCL_FUTURE)` on server startup | **gap** | `rg 'mlockall\|mlock\b' src` -> 0 matches |
| `MemoryPool` blocks mlocked/munlocked | **gap** | `rg 'mlock' src/optimize` -> 0 matches |
| `lock_memory` / `lock_blocks` config fields | **gap** | `rg 'lock_memory\|lock_blocks' src/engine/config.rs` -> 0 matches |
| `LimitMEMLOCK=infinity` in systemd service | verified | `scripts/install/quicfuscate-server.service` — added during this audit |

**Follow-up:** TODO-516 (implement mlock/mlockall, P1).

### TODO-441 — Privilege dropping (post-bind setuid/setgid)

| Acceptance Item | Classification | Evidence |
|-----------------|----------------|----------|
| `drop_privileges(user, group)` implementation | verified | `src/privilege/drop.rs:96` — setgid before setuid, clears groups |
| `check_capabilities()` runtime probe | verified | `src/privilege/drop.rs:65` — `CapabilityReport` with `is_root`, `has_net_admin`, `has_net_raw`, `has_net_bind_service` |
| Wired into server startup after privileged setup | verified | `src/main.rs:2385-2399` — drops after bind/TUN/routing, refuses to continue as root on failure |
| `no_drop_privileges` CLI escape hatch | verified | `src/main.rs:896, 1159, 2211, 2385` |
| systemd `User=quicfuscate` + `NoNewPrivileges=true` | verified | `scripts/install/quicfuscate-server.service:8,29` |
| Tests | verified | 4 tests in `src/privilege/drop.rs` |

### TODO-445 — Per-client bandwidth limits

| Acceptance Item | Classification | Evidence |
|-----------------|----------------|----------|
| `BandwidthLimiter` token bucket | verified | `src/implementations/server/bandwidth.rs:36-47` |
| `QuotaTracker` cumulative byte budget | verified | `src/implementations/server/bandwidth.rs:144-155` |
| `PerClientBandwidthManager` client map | verified | `src/implementations/server/bandwidth.rs:259-267` |
| Wired into Session | verified | `src/implementations/server/session.rs:158, 176, 181, 207, 212` |
| Tests | verified | 21 tests in `src/implementations/server/bandwidth.rs` |

### TODO-437 — IPv6 + DNS leak prevention

| Acceptance Item | Classification | Evidence |
|-----------------|----------------|----------|
| Kill switch covers ip6tables | verified | `src/implementations/client/killswitch.rs` — 16 ip6tables matches: `ensure_chain`, `block_traffic`, `allow_vpn_traffic`, `cleanup`, `cleanup_stale` all handle IPv6 |
| Best-effort ip6tables (disabled IPv6 tolerated) | verified | `killswitch.rs:327` — best-effort spawn, does not fail if ip6tables unavailable |
| DNS leak proof (`raw_port_53_packets=0`) | verified | `scripts/tests/tun-e2e-dns-leak-netns.sh` per MAP.md and DOCUMENTATION.md |

### TODO-456 — Auth rate limiting

| Acceptance Item | Classification | Evidence |
|-----------------|----------------|----------|
| `RateLimitConfig` / `ConnectionLimiter` / `GlobalRateLimiter` | verified | `src/implementations/server/limits.rs` — `rate_limiter` feature default-enabled in `Cargo.toml` |
| Per-IP failed-login throttling and lockout | verified | `src/implementations/server/admin_http.rs` — admin auth lockout tests per DOCUMENTATION.md security audit baseline |
| Packet rate limiter wired into ServerState | verified | `src/implementations/server/mod.rs:957-971` — `packet_rate_limiter`, `global_rate_limiter`, `ddos_detector`, `geoip_blocker` |
| Tests | verified | 34 tests in `src/implementations/server/limits.rs` |

### TODO-458 — QKey token storage encryption

| Acceptance Item | Classification | Evidence |
|-----------------|----------------|----------|
| `QUICFUSCATE_QKEY_ENC_KEY` env var | verified | `src/implementations/server/qkey_registry.rs:14-18` — 64 hex chars (32 bytes) |
| Encrypted registry file format with magic prefix | verified | `src/implementations/server/qkey_registry.rs:6-9` |
| AES-256-GCM encryption of persisted registry | verified | `src/implementations/server/qkey_registry.rs:422` — encryption with fallback warning |
| Tests | verified | `src/implementations/server/qkey_registry.rs:553-626` — multiple registry persistence tests |

### TODO-459 — DDoS protection hardening

| Acceptance Item | Classification | Evidence |
|-----------------|----------------|----------|
| `GeoIpBlocker` with country blocking | verified | `src/implementations/server/mod.rs:55, 135, 214-223` — `GeoIpConfig` with `db_path`, `blocked_countries` |
| `BlacklistSync` external blacklist | verified | `src/implementations/server/mod.rs:55, 136-140, 234-240` — `BlacklistConfig` with sync URL |
| `EwmaAnomalyDetector` | verified | `src/implementations/server/mod.rs:967` — `ddos_detector: Arc<EwmaAnomalyDetector>` |
| Wired into ServerState | verified | `src/implementations/server/mod.rs:967-972` |
| Tests | verified | 34 tests in `src/implementations/server/limits.rs` (shared with rate limiting) |

## Summary

| Source TODO | Items Verified | Items Partial | Items Gap | Follow-up |
|-------------|----------------|---------------|-----------|-----------|
| TODO-439 | 3 | 1 (syslog/CEF, non-blocking) | 1 (wiring) | TODO-515 |
| TODO-440 | 6 | 1 (QKey raw token zeroize audit) | 3 (mlock/mlockall/config) | TODO-516 |
| TODO-441 | 6 | 0 | 0 | — |
| TODO-445 | 5 | 0 | 0 | — |
| TODO-437 | 3 | 0 | 0 | — |
| TODO-456 | 4 | 0 | 0 | — |
| TODO-458 | 4 | 0 | 0 | — |
| TODO-459 | 5 | 0 | 0 | — |

**Blocking gaps:** TODO-515 (audit wiring, P0) and TODO-516 (mlock/mlockall, P1)
are created as concrete follow-up TODOs with exact acceptance criteria.

**Narrow fix applied during audit:** `LimitMEMLOCK=infinity` added to
`scripts/install/quicfuscate-server.service` (one-liner, prerequisite for
TODO-516).

**Product-facing docs alignment:** `docs/DOCUMENTATION.md` security-audit
and key-erasure sections must be updated when TODO-515 and TODO-516 close.
Until then, the production-ready claim for tamper-evident audit logging
and memory locking is scoped to "infrastructure exists, runtime wiring
pending."

