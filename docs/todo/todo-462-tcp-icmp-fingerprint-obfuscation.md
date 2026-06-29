---
id: TODO-462
title: "TCP/ICMP network-level fingerprint obfuscation through the tunnel"
severity: MEDIUM
phase: "J"
priority: P2
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-462: TCP/ICMP Network-Level Fingerprint Obfuscation Through the Tunnel

## Problem

Anti-fingerprinting in QuicFuscate currently exists **only at the TLS/QUIC
layer**: HTTP/3 header spoofing and GREASE are implemented in
`src/stealth/mod.rs`, and the outer (client→server) packets are QUIC/UDP.
However, the **inner packets** that traverse the TUN tunnel carry the
client's raw TCP/IP stack fingerprint. A passive observer on the server
side, or any upstream hop, can run `p0f` or `nmap -O` against the
tunneled traffic and identify the client's operating system from
network-layer characteristics — defeating the QUIC-layer mimicry.

There is **no network-level packet fingerprint normalization** anywhere in
the codebase. A grep for `ttl`, `mss`, `window_size`, `ip_df`, `p0f`,
`fingerprint` across `src/` returns no packet-normalization logic in the
TUN data path.

### Specific fingerprint vectors not addressed

1. **TCP fingerprinting (p0f, nmap OS detection)** — the OS can be
   identified from:
   - IP **TTL** at egress (Linux ~64, Windows ~128, macOS ~64).
   - TCP **window size** (Linux uses scaling curves, Windows uses fixed
     multiples, macOS different again).
   - TCP **MSS** (Linux 1460, some embedded stacks 1400/1380).
   - TCP **options order** (Linux: MSS,MSS,Window,SACK,TS,OPT-Path; Windows:
     Window,MSS,SACK,OPT-Path,TS; macOS differs again).
   - IP **DF bit** (Linux sets DF on TCP, some stacks do not).
2. **ICMP fingerprinting** — the OS can be identified from:
   - ICMP **echo reply** format (padding bytes, code field).
   - ICMP **TTL** on replies.
   - ICMP **unreachable** structure (e.g. Linux includes the original
     IP header + 8 bytes, some stacks include more).

Because QuicFuscate is a VPN, the **inner** packets (client TCP/IP stack →
TUN → server → upstream) carry the client's native fingerprint. Without
normalization, `p0f` on the server's upstream interface reports the
client's real OS regardless of the QUIC-layer cover traffic.

## Goal

Normalize all outgoing TUN packets so that traffic emerging from the
tunnel matches a configurable target OS fingerprint profile:

- **TTL normalization**: set IP TTL on all outgoing TUN packets to the
  target profile's value (Linux 64, Windows 128, macOS 64).
- **TCP window size normalization**: rewrite the TCP window to a fixed
  value or a profile-derived value.
- **TCP MSS normalization**: rewrite MSS to 1460 (or MTU-derived).
- **TCP options reordering**: rewrite the TCP options order to match the
  target profile (e.g. Linux 5.x: `MSS,Window,SACK,TS`).
- **IP DF bit normalization**: set/clear DF per target profile.
- **ICMP normalization**: suppress or normalize ICMP responses that reveal
  OS (normalize echo reply padding/TTL; optionally drop ICMP unreachables
  from the tunnel egress).
- **Config**: `fingerprint_profile = "linux" | "windows" | "macos" | "none"`.

Success: `p0f` run on traffic emerging from the tunnel reports the target
OS; `nmap -O` against the tunneled client returns the target OS fingerprint.

## Implementation Plan

### Step 1: Fingerprint profile config

**File:** `src/engine/config.rs` (or the relevant TUN/stealth config struct)

Add:

```rust
pub enum FingerprintProfile {
    None,     // No normalization (passthrough)
    Linux,    // TTL 64, MSS 1460, options: MSS,Window,SACK,TS, DF set
    Windows,  // TTL 128, MSS 1460, options: Window,MSS,SACK,TS, DF set
    MacOS,    // TTL 64, MSS 1460, options: MSS,Window,SACK,TS,OPT-Path, DF set
}

pub struct FingerprintConfig {
    pub profile: FingerprintProfile,         // default: None (backward compat)
    pub normalize_ttl: bool,                 // default: true when profile != None
    pub normalize_window: bool,
    pub normalize_mss: bool,
    pub reorder_options: bool,
    pub normalize_df: bool,
    pub suppress_icmp_unreachable: bool,     // default: true
    pub normalize_icmp: bool,
}
```

Parse from TOML:

```toml
[fingerprint]
profile = "linux"
normalize_ttl = true
normalize_window = true
normalize_mss = true
reorder_options = true
normalize_df = true
suppress_icmp_unreachable = true
normalize_icmp = true
```

### Step 2: Packet normalizer module

**File:** `src/stealth/fingerprint.rs` (new)

Create a `PacketNormalizer` that rewrites IP/TCP/ICMP headers on the egress
path (packets leaving the TUN toward the network):

```rust
pub struct PacketNormalizer {
    cfg: FingerprintConfig,
    target_ttl: u8,
    target_mss: u16,
    target_window: u16,
    target_options_order: &'static [TcpOptionKind],
    target_df: bool,
}

impl PacketNormalizer {
    pub fn new(cfg: FingerprintConfig) -> Self { ... }

    /// Rewrite an IPv4 packet in-place to match the target profile.
    /// Returns true if the packet was modified (so checksums can be
    /// recomputed by the caller).
    pub fn normalize(&self, pkt: &mut [u8]) -> bool { ... }
}
```

`normalize` performs, per packet:

1. Parse the IP header (IPv4; IPv6 in TODO-431 scope).
2. Set `ttl` to `target_ttl`. Recompute IP header checksum.
3. Set/clear the DF bit in the IP flags field per `target_df`.
4. If the packet is TCP:
   - Set the TCP window to `target_window` (or apply a profile-specific
     scaling function).
   - Find the MSS option and set it to `target_mss`.
   - Reorder the TCP options bytes to match `target_options_order`
     (parse the options list, emit in target order, pad with NOP/EOL).
   - Recompute the TCP checksum (incremental update preferred).
5. If the packet is ICMP:
   - If `suppress_icmp_unreachable` and type is Destination Unreachable:
     drop the packet (return a sentinel so the caller skips send).
   - Else normalize echo reply padding/TTL per profile; recompute ICMP
     checksum.

### Step 3: Integrate into the TUN egress path

**File:** `src/implementations/server/mod.rs` (server egress: TUN → WAN),
and the client TUN egress path.

After a packet is read from the TUN and before it is forwarded to the
network socket, pass it through `PacketNormalizer::normalize`:

```rust
if let Some(ref normalizer) = self.fingerprint_normalizer {
    if !normalizer.normalize(&mut buf[..len]) {
        // Packet dropped (e.g. suppressed ICMP unreachable).
        continue;
    }
}
```

The normalizer is constructed once at startup from `FingerprintConfig` and
stored alongside the TUN/routing resources.

### Step 4: Checksum recomputation

**File:** `src/stealth/fingerprint.rs`

Because TTL/window/MSS/options changes alter both the IP header checksum
and the TCP checksum (TCP checksum includes the IP pseudo-header only for
addresses, not TTL, so only the TCP header checksum needs updating for
TCP field changes; the IP header checksum must be updated for TTL/DF
changes), implement incremental checksum updates:

```rust
fn update_ip_checksum(ip_hdr: &mut [u8]) { ... }
fn update_tcp_checksum(ip_pkt: &mut [u8]) { ... }
fn update_icmp_checksum(icmp: &mut [u8]) { ... }
```

Use the standard ones-complement incremental update algorithm
(RFC 1071 / RFC 1624) to avoid full re-scan on every packet.

### Step 5: ICMP suppression/normalization

**File:** `src/stealth/fingerprint.rs`

- **Suppress**: if `suppress_icmp_unreachable` is set, drop ICMP type 3
  (Destination Unreachable) packets at the egress normalizer. This
  prevents the OS-specific unreachable format from leaking.
- **Normalize**: for ICMP echo replies (type 0), set the TTL in the inner
  IP header to `target_ttl` and normalize padding to a fixed pattern
  (e.g. zeros) so the reply matches the target profile.

### Step 6: Profile definitions

**File:** `src/stealth/fingerprint.rs`

```rust
impl FingerprintProfile {
    fn target_ttl(&self) -> u8 {
        match self {
            FingerprintProfile::Linux | FingerprintProfile::MacOS => 64,
            FingerprintProfile::Windows => 128,
            FingerprintProfile::None => 0, // unused
        }
    }
    fn target_mss(&self) -> u16 { 1460 }
    fn target_window(&self) -> u16 {
        match self {
            FingerprintProfile::Linux => 64240,
            FingerprintProfile::Windows => 65535,
            FingerprintProfile::MacOS => 65535,
            FingerprintProfile::None => 0,
        }
    }
    fn target_options_order(&self) -> &'static [TcpOptionKind] {
        match self {
            FingerprintProfile::Linux => &[MSS, Window, SACK, TS],
            FingerprintProfile::Windows => &[Window, MSS, SACK, TS],
            FingerprintProfile::MacOS => &[MSS, Window, SACK, TS, OptPath],
            FingerprintProfile::None => &[],
        }
    }
    fn target_df(&self) -> bool { true }
}
```

### Step 7: Tests

**File:** `tests/fingerprint_normalizer_test.rs` (new)

- **Unit**: construct a raw IPv4/TCP SYN packet with Linux-default TTL
  (64), normalize to Windows profile, assert TTL == 128, window ==
  65535, MSS == 1460, options order matches Windows, DF set, IP + TCP
  checksums valid.
- **Unit**: ICMP unreachable packet with `suppress_icmp_unreachable =
  true` → normalizer returns false (dropped).
- **Unit**: ICMP echo reply normalized → TTL and padding match profile.
- **Integration (Linux, requires TUN + p0f)**: send a stream of TCP SYN
  packets through the tunnel with `fingerprint_profile = "linux"`, run
  `p0f` on the egress interface, assert it reports Linux. Repeat with
  `fingerprint_profile = "windows"`, assert p0f reports Windows.
- **Integration**: `nmap -O` against the tunneled client returns the
  target OS fingerprint.
- **Performance**: normalizer throughput on a 1 Gbps stream must not
  drop below 900 Mbps (incremental checksums, no allocation in hot path).

## Files to Modify/Create

- `src/stealth/fingerprint.rs` — **new**: `FingerprintProfile`,
  `FingerprintConfig`, `PacketNormalizer`, checksum update helpers,
  profile definitions.
- `src/stealth/mod.rs` — re-export `PacketNormalizer`,
  `FingerprintProfile`, `FingerprintConfig`; add module declaration.
- `src/engine/config.rs` — `FingerprintConfig` fields + TOML parsing.
- `src/implementations/server/mod.rs` — construct `PacketNormalizer` at
  startup; apply on TUN egress path.
- Client TUN egress path — apply `PacketNormalizer` analogously.
- `tests/fingerprint_normalizer_test.rs` — **new**: unit + integration
  tests (p0f / nmap -O verification).

## Acceptance Criteria

- [ ] `FingerprintProfile` enum supports `linux`, `windows`, `macos`,
      `none`.
- [ ] `PacketNormalizer::normalize` rewrites TTL, TCP window, MSS, TCP
      options order, and DF bit on IPv4/TCP packets, with valid
      recomputed IP + TCP checksums.
- [ ] ICMP Destination Unreachable packets are suppressed when
      `suppress_icmp_unreachable = true`.
- [ ] ICMP echo replies are normalized (TTL + padding) to the target
      profile.
- [ ] `fingerprint_profile = "none"` is a pure passthrough (no
      modification, no measurable overhead).
- [ ] `p0f` on egress traffic reports the target OS for each profile.
- [ ] `nmap -O` against the tunneled client returns the target OS
      fingerprint.
- [ ] Normalizer hot path performs no heap allocation; throughput on a
      1 Gbps stream stays above 900 Mbps.
- [ ] IP and TCP checksums are valid after normalization (verified by
      `wireshark` / `tcpdump` with no checksum errors).
- [ ] `cargo test` passes; `cargo clippy` reports no new warnings.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| Per-packet normalization (IPv4/TCP) | < 1 µs | Incremental checksum, no alloc |
| Per-packet normalization (ICMP) | < 0.5 µs | Single header rewrite |
| p0f integration test (10s capture) | < 20s | Capture + p0f analysis |
| nmap -O integration test | < 30s | Single OS-detection scan |
| Throughput test (1 Gbps, 64-byte pkts) | > 900 Mbps | Must not be the bottleneck |
| Profile = none overhead | < 1% | Early-return passthrough |
