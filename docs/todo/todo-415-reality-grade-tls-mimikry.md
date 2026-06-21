---
id: TODO-415
title: Reality-Grade TLS-Mimikry (3 Phasen, inkrementell)
severity: HIGH
phase: "3"
priority: P1
status: OPEN
created: 2026-07-23
depends_on: [TODO-416]
supersedes: []
---

# TODO-415: Reality-Grade TLS-Mimikry

## Problem

QuicFuscate's current stealth approach is **fallback-proxy, not reality-grade mimicry**:

### Current State
- **`RealityProxy`** (`src/reality.rs:35-306`): A reverse proxy that relays active probes to upstream resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9). When a probe connects, it gets a real TLS response — but from the upstream, not from QuicFuscate. This is a **relay**, not **mimicry**.
- **`TlsClientHelloSpoofer`** (`src/stealth/mod.rs:2881`): Generates **synthetic** ClientHello messages. DPI can distinguish synthetic from real (Extension ordering, GREASE positions, key-share curve selection differ from real browser fingerprints).
- **`Http3Masquerade`** (`src/stealth/mod.rs:1618`): Adds realistic HTTP/3 headers but the TLS layer beneath is still synthetic.

### SOTA: XTLS-Reality
XTLS-Reality (used in Xray-core) **captures the real TLS handshake** of a cover site and mirrors it exactly:
- Server connects to cover site as a TLS client, caches the ServerHello + certificate + extensions.
- When a real client connects to the proxy, it receives the **exact** cover-site ServerHello — byte-identical fingerprint.
- Active probes receive the same cover-site response — indistinguishable from the real site.
- Client authentication is hidden in SNI padding or session ticket entropy — invisible in the handshake.
- DPI cannot distinguish proxy traffic from real cover-site traffic at the TLS layer.

**QuicFuscate's `RealityProxy` is the architectural shell for this, but it relays instead of mirroring.**

## Acceptance

This is a **3-phase incremental** task. Each phase is independently shippable.

### Phase 1: Reality-Capture-Modus (Server caches Cover-Hello)
1. Server config option `[reality]` with:
   - `cover_host`: e.g. `www.cloudflare.com`
   - `cover_port`: 443
   - `cache_ttl`: seconds (default 3600)
2. On server start (or cache miss), server connects to `cover_host:443` as a TLS 1.3 client.
3. Captures: ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished — the full server-side handshake material.
4. Caches material in memory (with TTL refresh).
5. When a QuicFuscate client connects, server responds with the **cached** cover-site ServerHello (not a synthetic one).
6. Client authentication: QKey token embedded in a TLS extension or session ticket field that is **encrypted** and invisible to DPI.
7. Active probes receive the cached cover-site response — indistinguishable from real cover site.
8. **Fallback**: if cover host is unreachable, fall back to synthetic `TlsClientHelloSpoofer` (current behavior) with a logged warning.

### Phase 2: ClientHello-Mirror
1. Client connects first to `cover_host:443` as a TLS 1.3 client (or uses cached fingerprint).
2. Captures the ClientHello that a real browser would send to the cover host.
3. Sends an **identical** ClientHello to the QuicFuscate server (same extensions, same GREASE, same key-share curves, same ordering).
4. Server validates: ClientHello fingerprint matches expected pattern. QKey token in encrypted extension.
5. DPI sees: client→server traffic looks identical to client→cover-site traffic.

### Phase 3: Probe-Resistenz mit echtem Material
1. `RealityProxy` (`src/reality.rs`) is restructured:
   - Instead of relaying probes to upstream, it serves the **cached cover-site material** directly.
   - Probe gets a full, valid TLS 1.3 handshake response with real cover-site certificate.
   - No upstream dependency at probe time (cover-site material is cached).
   - Only periodic background refresh connects to cover host.
2. Probe response is **byte-identical** to what the real cover site would return.
3. `ActiveProbeDetector` still logs probe patterns for telemetry, but the response is cover-grade.

## Fix Plan

### Phase 1 Implementation (4-8 weeks)

#### Step 1: Reality config schema
1. Add `[reality]` section to `server-linux.default.toml`:
   ```toml
   [reality]
   enabled = false
   cover_host = "www.cloudflare.com"
   cover_port = 443
   cache_ttl = 3600
   fallback_to_synthetic = true
   ```
2. Parse in server config loader.
3. Document in `DOCUMENTATION.md`.

#### Step 2: Cover-site handshake capture
1. New module `src/reality_capture.rs` (or extend `src/reality.rs`):
   - `CoverHandshakeCache` struct: holds cached ServerHello, extensions, certificate.
   - `capture_cover_handshake(host, port) -> Result<CoverMaterial>`: connects via `rustls` as client, captures server-side flight 1+2.
   - `refresh_if_stale()`: background task, refreshes on TTL expiry.
2. Use `rustls` client config (already a dependency) to connect to cover host.
3. Capture raw TLS handshake bytes (not just parsed structure — need byte-identical reproduction).

#### Step 3: Server response with cached material
1. In server handshake path (`src/server/` or `src/transport/`):
   - If `[reality] enabled = true`: use `CoverHandshakeCache` material for ServerHello.
   - Inject QKey authentication into an encrypted extension (not visible in plaintext handshake).
   - The application data layer (post-handshake) uses QuicFuscate's AEAD as normal.
2. Client must know to expect cover-site ServerHello and extract QKey auth from the agreed-upon extension.

#### Step 4: Client-side handling
1. Client config: `[reality] cover_host = "www.cloudflare.com"` (must match server).
2. Client validates: ServerHello matches expected cover-site fingerprint.
3. Client extracts QKey auth response from encrypted extension.
4. If validation fails: abort connection (possible MITM or misconfigured server).

#### Step 5: Fallback
1. If `CoverHandshakeCache` is empty (cover host unreachable at startup):
   - If `fallback_to_synthetic = true`: use `TlsClientHelloSpoofer` (current behavior).
   - Log warning: "Reality cover unavailable, falling back to synthetic TLS".
   - Background retry to populate cache.

#### Step 6: Tests
- Unit test: `CoverHandshakeCache` populates from mock cover host.
- Unit test: cached material served on client connection.
- Unit test: fallback to synthetic on cache miss.
- Integration test: client connects to server with reality enabled, QKey auth succeeds.
- `cargo test --lib` green.

### Phase 2 Implementation (additional 2-4 weeks after Phase 1)

#### Step 1: Client-side cover fingerprint capture
1. Client captures real ClientHello for cover host (using `rustls` or raw TLS).
2. Or: client uses a pre-built fingerprint database (browser profiles, already in `stealth/`).
3. Sends identical ClientHello to QuicFuscate server.

#### Step 2: Server-side ClientHello validation
1. Server checks: ClientHello fingerprint matches expected cover-host pattern.
2. Extracts QKey from encrypted extension.
3. If fingerprint doesn't match: reject (possible probe or misconfigured client).

### Phase 3 Implementation (additional 2-4 weeks after Phase 2)

#### Step 1: RealityProxy restructuring
1. `src/reality.rs`: `RealityProxy` serves cached material directly instead of relaying.
2. Remove upstream relay dependency at probe time.
3. Background refresh task populates cache periodically.

#### Step 2: Probe response validation
1. Active probe receives full TLS 1.3 handshake with real cover-site certificate.
2. Byte-identical to real cover site.
3. `ActiveProbeDetector` logs probe but response is automatic (no relay latency).

## Files

- `src/reality.rs` (restructure RealityProxy for Phase 3)
- `src/reality_capture.rs` (new — CoverHandshakeCache, capture logic)
- `src/stealth/mod.rs` (TlsClientHelloSpoofer fallback integration)
- `src/server/mod.rs` (reality config parsing, handshake path)
- `src/transport/` (handshake response with cached material)
- `server-linux.default.toml` (reality config section)
- `src/DOCUMENTATION.md` (reality mode documentation)
- `docs/profiling/reality-mimikry-results.md` (new — Phase 1/2/3 validation)

## Risks

- **TLS 1.3 session resumption**: Cover site may use session tickets that expire. Cache must handle ticket refresh.
- **Certificate chain**: Cover-site certificate is real — but the private key is NOT available. QuicFuscate cannot complete a real TLS handshake with the cover-site cert. **Key insight**: the proxy doesn't need the private key — it replays the **server's** flight of the handshake, but the actual QUIC AEAD keys are derived from the QuicFuscate handshake, not the TLS handshake. The TLS layer is a **cover shell**, the real data is in QUIC frames underneath.
- **Cover site availability**: If cover host goes down, cache expires and fallback kicks in. Monitor cover host health.
- **Legal/ethical**: Using a real cover site's TLS fingerprint is standard practice (XTLS-Reality, Trojan). No impersonation of the cover site to third parties — the cover material is only shown to the client and probes connecting to the QuicFuscate server.

## SOTA References

- XTLS-Reality (Xray-core): https://github.com/XTLS/Realitty
- Trojan-GFW: TLS camouflage approach
- Cloak: TLS multiplexing with cover traffic
- QuicFuscate existing: `RealityProxy` (relay), `TlsClientHelloSpoofer` (synthetic)

## Notes

- No UI changes.
- Precondition: TODO-416 (gradual escalation) — reality-grade mimicry is the "Level 2" stealth response. The escalation system from 416 decides WHEN to use reality mode.
- **Phase 1 alone is a massive win** — server-side cover handshake caching eliminates synthetic fingerprint detection.
- Phase 2 and 3 are incremental improvements (client-side mirror + probe resistance).
- Each phase should be shipped independently — don't block Phase 1 on Phase 2/3 completion.
- The `[reality]` config section is **opt-in** (default `enabled = false`) — existing deployments are unaffected.
- `rustls` 0.23 (already a dependency) supports client-side TLS 1.3 — no new crypto dependency needed.
