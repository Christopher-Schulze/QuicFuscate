---
id: TODO-462
title: "TCP/ICMP fingerprint obfuscation through the VPN tunnel"
severity: HIGH
phase: "J"
priority: P2
status: DONE
created: 2026-07-23
depends_on: []
---

# TODO-462: TCP/ICMP Fingerprint Obfuscation Through the VPN Tunnel

## Goal

Normalize all outgoing TUN-interface packets so that traffic emerging from the tunnel
matches a configurable target OS fingerprint profile, defeating passive OS fingerprinting
tools (p0f, nmap -O, Satori, Zeek fingerprinting) that operate on network-layer
characteristics. This covers the inner IP stack fingerprint — the OS inside the VPN
tunnel should have a consistent, configurable fingerprint that is independent of the
client's actual operating system. Must integrate with the existing browser_profile
stealth system so that the TLS/QUIC fingerprint and the IP/TCP fingerprint tell a
consistent story.

## Current State (verified against code)

### Existing fingerprint management (TLS/QUIC layer only)

- **`src/stealth/mod.rs:41-57`** — User-Agent string constants for Chrome 136, Firefox
  138, Edge 136, Safari 18.3 across Windows/macOS/Linux/Android/iOS. These are
  application-layer fingerprints.

- **`src/stealth/mod.rs:232-353`** — `TlsCoverProvider`: manages TLS ClientHello
  spoofing with per-profile templates (chrome, firefox, safari, edge, random). This is
  the TLS-layer fingerprint — cipher suites, extensions, ordering.

- **`src/stealth/mod.rs:2882-2945`** — `TlsClientHelloSpoofer`: generates advanced
  ClientHello bytes with browser-specific extension ordering, GREASE, ECH, key share.
  Uses `BrowserProfile` and `OsProfile` enums.

- **`src/stealth/mod.rs:3182-3199`** — `StealthConfig` fields:
  `initial_browser: BrowserProfile`, `initial_os: OsProfile`,
  `enable_fingerprint_rotation: bool`, `fingerprint_rotation_mode: RotationMode`.
  These control TLS/QUIC fingerprint rotation, not IP/TCP fingerprint normalization.

- **`src/stealth/mod.rs:3313-3335`** — `FingerprintRotationConfig` and `RotationMode`:
  rotation through browser/OS profile slots. Again, TLS-layer only.

### ICMP handling (server-side, no normalization)

- **`src/implementations/server/icmp.rs:1-366`** — Complete ICMP packet handling:
  - `build_echo_reply()` (line 56): swaps src/dst, sets ICMP type to Echo Reply (0),
    recomputes checksums, sets **hardcoded TTL=64** (line 95). This TTL is fixed
    regardless of the target fingerprint profile.
  - `build_icmp_unreachable()` (line 102): constructs Destination Unreachable / Packet
    Too Big messages with hardcoded TTL=64 (line 127), hardcoded IPv4 IHL=5 (line 122).
  - `parse_icmpv4()` (line 36): parses ICMP headers from raw IPv4 packets.
  - No fingerprint normalization: TTL is always 64, no options normalization, no
    payload pattern normalization.

### TUN interface and routing (no packet normalization)

- **`src/implementations/server/mod.rs:862-924`** — `ServerHostResources`: creates TUN
  interface (`qfserver0`) and `RoutingManager` for NAT/forwarding. Packets are forwarded
  via iptables MASQUERADE with no fingerprint normalization in the data path.

- **`src/implementations/server/routing.rs:1-942`** — `RoutingManager`: handles IP
  forwarding enablement, iptables NAT rules, firewall rules. No packet content
  modification — pure kernel-level forwarding.

- **`src/implementations/client/platform/linux.rs`** — Client TUN interface setup.
  No packet normalization on the client egress path either.

### Key gap: no IP/TCP/ICMP fingerprint normalization

A grep for `ttl`, `mss`, `window_size`, `tcp_option`, `p0f`, `os_detect` across `src/`
returns **no packet-normalization logic** in the TUN data path. The only TTL handling
is the hardcoded `reply[8] = 64` in `icmp.rs:95` and `pkt[8] = 64` in `icmp.rs:127`.

The client's raw TCP/IP stack fingerprint traverses the TUN tunnel unchanged. A passive
observer on the server's upstream side can run p0f or nmap -O against the tunneled
traffic and identify the client's actual operating system — completely defeating the
QUIC-layer browser/OS mimicry.

## Problem Analysis

### Fingerprint vectors not addressed

#### TCP fingerprinting (p0f, nmap OS detection)

p0f (v3, still effective in 2026) identifies OS from a single SYN packet by examining:

1. **IP TTL at egress** — Linux defaults to 64, Windows to 128, macOS to 64, Cisco IOS
   to 255. The adversary rounds TTL to the nearest standard value to account for hop
   decrement. This is the single most reliable OS signal.

2. **TCP window size** — Linux 5.x uses 64240, earlier Linux used 29200 or 65535,
   Windows uses 65535 (or multiples of MSS), macOS uses 65535. The window size
   reveals the OS's preferred BDP-aware tuning.

3. **TCP MSS** — Linux 1460, some embedded stacks 1400/1380. Usually consistent but
   can reveal non-standard MTU configurations.

4. **TCP options order** — The most discriminative signal. Linux 5.x:
   `MSS,Window,SACK,TS,NOP,WS`; Windows: `Window,MSS,SACK,TS,NOP,WS`; macOS:
   `MSS,Window,SACK,TS,NOP,WS,OPT-Path`. The number of possible orderings is large
   but each OS uses only one — making this a strong fingerprint.

5. **IP DF bit** — Linux sets DF on TCP SYN, some stacks do not. Minor signal but
   contributes to the composite fingerprint.

6. **IP ID field** — Linux uses per-connection random IDs, Windows uses incrementing
   counters, some embedded systems use constant 0. p0f normalizes this to `id+` or
   `id-` or `random`.

#### ICMP fingerprinting

1. **ICMP echo reply format** — Padding bytes, code field value, payload echo behavior
   differ by OS. Linux echoes the request payload exactly; Windows may zero-fill.
2. **ICMP TTL on replies** — Currently hardcoded to 64 in `icmp.rs:95`, which always
   looks like Linux/macOS. If the target profile is Windows, this leaks.
3. **ICMP unreachable structure** — Linux includes original IP header + 8 bytes of
   payload (RFC 792 compliant). Some stacks include more or less. The `build_icmp_unreachable`
   function (line 102) includes `original_header_len + 8` bytes, which is RFC-compliant
   but may not match all OS profiles.

### Why this matters for QuicFuscate

QuicFuscate is a VPN. The **inner** packets (client TCP/IP stack → TUN → server →
upstream) carry the client's native fingerprint. Without normalization:

- `p0f` on the server's upstream interface reports the client's real OS (e.g., "Linux
  5.15, Ubuntu 22.04") regardless of the QUIC-layer cover traffic that mimics Chrome
  on Windows.
- `nmap -O` against the tunneled client returns the client's real OS fingerprint.
- The TLS fingerprint says "Chrome on Windows" but the IP fingerprint says "Linux
  5.15" — this **inconsistency** is itself a signal that the traffic is being
  obfuscated, potentially flagging the connection for further scrutiny.

### Research context

**SOFI** (NSF research, 2024) demonstrates that OS fingerprint spoofing is effective
against both passive (p0f) and active (nmap) fingerprinting tools. The key is
**consistency** — all fingerprint signals must agree. If TTL says Windows (128) but
TCP options say Linux, the fingerprint is invalid and tools report "unknown" or flag
the traffic.

**RouteHarden** (2025) confirms that p0f's signature grammar encodes the full TCP/IP
stack fingerprint in a single string like `Linux 5.x: 64+0:0:1460:mss*44,7:mss,sok,ts,nop,ws:df,id+:0`.
Each field contributes bits of entropy; the option-order field alone has substantial
discriminative power. Normalizing all fields to a consistent target profile is the
only way to defeat composite fingerprinting.

**Ephemeral Network-Layer Fingerprinting Defenses** (PoPETS 2026) evaluates padding-only
vs. blocking defenses and confirms that network-layer normalization (TTL, window,
options) is a necessary complement to application-layer obfuscation.

## Proposed Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    PacketNormalizer                                   │
│                                                                      │
│  FingerprintProfile: Linux | Windows | MacOS | Android | None        │
│                                                                      │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐      │
│  │ IP Header   │  │ TCP Header   │  │ ICMP Header            │      │
│  │ Normalizer  │  │ Normalizer   │  │ Normalizer             │      │
│  │             │  │              │  │                        │      │
│  │ • TTL       │  │ • Window     │  │ • Echo reply TTL       │      │
│  │ • DF bit    │  │ • MSS        │  │ • Echo reply padding   │      │
│  │ • IP ID     │  │ • Options    │  │ • Unreachable format   │      │
│  │             │  │   reorder    │  │ • Suppress unreachable │      │
│  └──────┬──────┘  └──────┬───────┘  └──────────┬─────────────┘      │
│         │                │                     │                     │
│         ▼                ▼                     ▼                     │
│  Incremental checksum updates (RFC 1071 / RFC 1624)                  │
│                                                                      │
│  Integration point: TUN egress path (server + client)                │
│  Applied after TUN read, before network send                         │
└──────────────────────────────────────────────────────────────────────┘
```

### Profile definitions

Each profile specifies a complete, consistent TCP/IP stack fingerprint:

| Field | Linux 5.x | Windows 10/11 | macOS 14/15 | Android 15 |
|-------|-----------|---------------|-------------|------------|
| TTL | 64 | 128 | 64 | 64 |
| TCP Window | 64240 | 65535 | 65535 | 65535 |
| MSS | 1460 | 1460 | 1460 | 1460 |
| Options Order | MSS,Win,SACK,TS,NOP,WS | Win,MSS,SACK,TS,NOP,WS | MSS,Win,SACK,TS,NOP,WS | MSS,Win,SACK,TS,NOP,WS |
| DF bit | set | set | set | set |
| IP ID | random | incremental | random | random |
| ICMP reply TTL | 64 | 128 | 64 | 64 |
| ICMP padding | echo exact | zero-fill | echo exact | echo exact |

### Consistency with browser_profile

The `FingerprintProfile` must be consistent with the `BrowserProfile` and `OsProfile`
used for TLS/QUIC fingerprinting:

- `BrowserProfile::Chrome` + `OsProfile::Windows` → `FingerprintProfile::Windows`
- `BrowserProfile::Firefox` + `OsProfile::Linux` → `FingerprintProfile::Linux`
- `BrowserProfile::Safari` + `OsProfile::MacOS` → `FingerprintProfile::MacOS`
- `BrowserProfile::Chrome` + `OsProfile::Android` → `FingerprintProfile::Android`

When fingerprint rotation is enabled (`enable_fingerprint_rotation = true`), the
`FingerprintProfile` must rotate in lockstep with the `BrowserProfile`/`OsProfile`
rotation to maintain consistency.

## Implementation Plan

### Step 1: FingerprintProfile enum and config

**File:** `src/stealth/fingerprint.rs` (new)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum FingerprintProfile {
    None,     // No normalization (passthrough)
    Linux,    // TTL 64, window 64240, options: MSS,Win,SACK,TS,NOP,WS
    Windows,  // TTL 128, window 65535, options: Win,MSS,SACK,TS,NOP,WS
    MacOS,    // TTL 64, window 65535, options: MSS,Win,SACK,TS,NOP,WS
    Android,  // TTL 64, window 65535, options: MSS,Win,SACK,TS,NOP,WS
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FingerprintConfig {
    pub profile: FingerprintProfile,         // default: None (backward compat)
    pub normalize_ttl: bool,                 // default: true when profile != None
    pub normalize_window: bool,
    pub normalize_mss: bool,
    pub reorder_options: bool,
    pub normalize_df: bool,
    pub normalize_ip_id: bool,
    pub suppress_icmp_unreachable: bool,     // default: true
    pub normalize_icmp: bool,
}
```

Parse from TOML in `src/engine/config.rs`:

```toml
[fingerprint]
profile = "linux"
normalize_ttl = true
normalize_window = true
normalize_mss = true
reorder_options = true
normalize_df = true
normalize_ip_id = true
suppress_icmp_unreachable = true
normalize_icmp = true
```

### Step 2: PacketNormalizer

**File:** `src/stealth/fingerprint.rs`

```rust
pub struct PacketNormalizer {
    cfg: FingerprintConfig,
    target_ttl: u8,
    target_mss: u16,
    target_window: u16,
    target_options_order: &'static [TcpOptionKind],
    target_df: bool,
    target_ip_id_mode: IpIdMode,  // Random, Incremental, Constant
}

impl PacketNormalizer {
    pub fn new(cfg: FingerprintConfig) -> Self;

    /// Rewrite an IPv4 packet in-place to match the target profile.
    /// Returns NormalizeResult::Modified, NormalizeResult::Dropped (suppressed),
    /// or NormalizeResult::Passthrough (no change needed).
    pub fn normalize(&self, pkt: &mut [u8]) -> NormalizeResult;
}

pub enum NormalizeResult {
    Passthrough, // No modification (profile = None or already matches)
    Modified,    // Packet was rewritten, checksums recomputed
    Dropped,     // Packet suppressed (e.g. ICMP unreachable)
}
```

`normalize` performs, per packet:

1. Parse the IP header (IPv4; IPv6 in future scope).
2. Set `ttl` to `target_ttl`. Recompute IP header checksum (incremental update).
3. Set/clear the DF bit in the IP flags field per `target_df`.
4. Normalize IP ID field per `target_ip_id_mode` (random/incremental/constant).
5. If the packet is TCP:
   - Set the TCP window to `target_window` (or apply a profile-specific scaling
     function for non-SYN packets).
   - Find the MSS option and set it to `target_mss`.
   - Reorder the TCP options bytes to match `target_options_order` (parse the options
     list, emit in target order, pad with NOP/EOL).
   - Recompute the TCP checksum (incremental update preferred — only changed fields
     need delta computation per RFC 1624).
6. If the packet is ICMP:
   - If `suppress_icmp_unreachable` and type is Destination Unreachable: return
     `Dropped`.
   - Else normalize echo reply TTL and padding per profile; recompute ICMP checksum.

### Step 3: TCP options reordering

**File:** `src/stealth/fingerprint.rs`

TCP options reordering is the most complex part. The algorithm:

1. Parse the TCP options from the SYN packet (options are only in SYN/SYN-ACK; data
   packets typically have no options or just timestamps).
2. Extract each option: kind, length, value.
3. Re-emit options in the target profile's order.
4. Pad remaining space with NOP (0x01) and EOL (0x00) to match the original options
   length (or the target profile's typical options length).
5. Recompute TCP checksum incrementally.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOptionKind {
    End = 0,
    Nop = 1,
    Mss = 2,
    WindowScale = 3,
    SackPermitted = 4,
    Sack = 5,
    Timestamps = 8,
    // Add others as needed
}

fn reorder_tcp_options(
    options: &[u8],
    target_order: &[TcpOptionKind],
) -> Vec<u8>;
```

**Important**: Only reorder options on SYN packets (where options are negotiated).
Data packets should not have their options reordered — this would break TCP semantics
and potentially corrupt the connection. The normalizer should detect SYN packets
(flags = SYN, ACK=0) and only apply option reordering to those.

### Step 4: Checksum recomputation

**File:** `src/stealth/fingerprint.rs`

Use the standard ones-complement incremental update algorithm (RFC 1071 / RFC 1624)
to avoid full re-scan on every packet:

```rust
/// Incremental IP checksum update for a modified 16-bit field.
/// HC' = HC - ~m - m' (RFC 1624 §3)
fn incremental_ip_checksum_update(
    old_value: u16,
    new_value: u16,
    checksum: u16,
) -> u16;

/// Full IP header checksum recompute (fallback).
fn recompute_ip_checksum(ip_hdr: &mut [u8]);

/// Full TCP checksum recompute (includes pseudo-header).
fn recompute_tcp_checksum(ip_pkt: &mut [u8]);

/// ICMP checksum recompute.
fn recompute_icmp_checksum(icmp: &mut [u8]);
```

For TTL changes: only the IP header checksum needs updating (TTL is in the IP header,
not the TCP pseudo-header). For TCP window/MSS/options changes: both the IP header
checksum (if IP fields changed) and the TCP checksum need updating.

### Step 5: ICMP normalization

**File:** `src/stealth/fingerprint.rs`, `src/implementations/server/icmp.rs`

Update `build_echo_reply` and `build_icmp_unreachable` to use the target profile's TTL
instead of hardcoded 64:

```rust
// In icmp.rs, parameterize TTL:
pub fn build_echo_reply_with_profile(
    original_pkt: &[u8],
    target_ttl: u8,
    padding_pattern: PaddingPattern,
) -> Vec<u8>;
```

Where `PaddingPattern` controls the echo reply payload:
- `EchoExact` — echo the request payload exactly (Linux/macOS behavior)
- `ZeroFill` — zero-fill the payload (Windows behavior)

For ICMP unreachable suppression: the `PacketNormalizer::normalize` method returns
`NormalizeResult::Dropped` for ICMP type 3 packets when `suppress_icmp_unreachable`
is true. The TUN egress path skips sending dropped packets.

### Step 6: Integrate into TUN egress path

**File:** `src/implementations/server/mod.rs`, client TUN egress path

After a packet is read from the TUN and before it is forwarded to the network socket,
pass it through `PacketNormalizer::normalize`:

```rust
if let Some(ref normalizer) = self.fingerprint_normalizer {
    match normalizer.normalize(&mut buf[..len]) {
        NormalizeResult::Dropped => continue,  // Skip this packet
        NormalizeResult::Modified => {
            // Checksums already recomputed by normalizer
        }
        NormalizeResult::Passthrough => {}  // No change
    }
}
```

The normalizer is constructed once at startup from `FingerprintConfig` and stored
alongside the TUN/routing resources in `ServerHostResources`.

### Step 7: Consistency with browser_profile rotation

**File:** `src/stealth/mod.rs`

When fingerprint rotation is enabled, the `FingerprintProfile` must rotate in lockstep
with `BrowserProfile`/`OsProfile`. Add a mapping function:

```rust
impl FingerprintProfile {
    pub fn from_browser_os(browser: BrowserProfile, os: OsProfile) -> Self {
        match (browser, os) {
            (_, OsProfile::Windows) => FingerprintProfile::Windows,
            (_, OsProfile::Linux) => FingerprintProfile::Linux,
            (_, OsProfile::MacOS) => FingerprintProfile::MacOS,
            (_, OsProfile::Android) => FingerprintProfile::Android,
            (_, OsProfile::IOS) => FingerprintProfile::MacOS, // iOS ~ macOS fingerprint
        }
    }
}
```

When `FingerprintConfig.profile == None` but `FingerprintConfig.auto_from_stealth ==
true`, the normalizer automatically derives the profile from the current
`BrowserProfile`/`OsProfile` in the `StealthManager`.

### Step 8: IPv6 support (future scope)

IPv6 fingerprint normalization is structurally similar but uses Hop Limit instead of
TTL, has no IP checksum (IPv6 has no header checksum), and has different option encoding
(extension headers). This is deferred to a future TODO but the architecture should
accommodate it via a `normalize_ipv6` method.

## Technology Choices

### Incremental checksum (RFC 1624) vs. full recompute

**Choice**: Incremental checksum update for TTL-only changes (most common case), full
recompute for TCP option reordering (options length may change, invalidating the
incremental approach).

**Rationale**: TTL normalization is the hot path — every packet needs it. Incremental
update is O(1) (one 16-bit subtraction). TCP option reordering is rare (only SYN
packets) and may change the options length, so full recompute is simpler and correct.

### In-place packet modification vs. copy

**Choice**: In-place modification of the TUN packet buffer.

**Rationale**: The TUN read buffer is owned by the forwarding path. Modifying in-place
avoids allocation. The normalizer must not change the packet length for TTL/DF/window
changes (same-size fields). For TCP option reordering, the options area is padded to
the original length, so the total packet size is unchanged.

### p0f signature database reference

**Choice**: Hardcode profile values based on p0f v3 signature database analysis (2025
research confirms p0f is still effective in 2026).

**Rationale**: p0f's signature format (`OS:ttl:df:id:window:mss:options:quirks`) is
the de facto standard. Our profiles must produce valid p0f signatures that match real
OS entries. The values are stable across OS minor versions (Linux 5.x TTL is always 64,
Windows 10/11 TTL is always 128).

## Stealth/Efficiency Considerations

### Stealth integration

- **Consistency with TLS fingerprint**: The `FingerprintProfile` must agree with the
  `BrowserProfile`/`OsProfile` used for TLS/QUIC. If TLS says "Chrome on Windows" but
  IP TTL says 64 (Linux), the inconsistency is a stronger signal than either
  fingerprint alone — it indicates obfuscation.
- **Rotation lockstep**: When fingerprint rotation is enabled, the `FingerprintProfile`
  must rotate simultaneously with the TLS profile. A 1-second skew between TLS
  rotation and IP normalization rotation creates a detectable inconsistency window.
- **ICMP suppression**: Suppressing ICMP unreachable messages is itself a signal (some
  firewalls do this). Make it configurable — `suppress_icmp_unreachable = false` with
  `normalize_icmp = true` is a softer approach that normalizes but does not suppress.
- **IP ID normalization**: Random IP IDs (Linux) vs. incremental (Windows) is a subtle
  but detectable signal. Normalizing this adds entropy reduction at the IP layer.

### Performance considerations

- **Per-packet normalization cost**: TTL update + incremental IP checksum = ~50ns
  (two 16-bit operations). TCP window/MSS update + incremental TCP checksum = ~100ns.
  TCP option reordering (SYN only) = ~500ns (parse + reorder + full checksum). All
  well under 1µs per packet.
- **No allocation in hot path**: The normalizer operates in-place on the packet buffer.
  TCP option reordering uses a stack-allocated buffer (options are typically <40 bytes).
- **Throughput target**: Normalizer must not drop below 900 Mbps on a 1 Gbps stream
  (64-byte packets). At 1.48 Mpps, 500ns/packet = 740 Mbps — within target for the
  common case (TTL-only normalization at 50ns/packet = 14.8 Gbps).
- **Profile = None overhead**: Early return, < 1% overhead. Must be a branch-predicted
  fast path.

## Testing Plan

### Unit tests

1. **TTL normalization**: Construct a raw IPv4/TCP SYN packet with Linux TTL (64),
   normalize to Windows profile, assert TTL == 128, IP checksum valid.
2. **TCP window normalization**: Normalize a SYN with window 64240 (Linux) to Windows
   profile, assert window == 65535, TCP checksum valid.
3. **TCP MSS normalization**: Normalize MSS to 1460, assert MSS option value correct,
   TCP checksum valid.
4. **TCP options reordering**: Construct a SYN with Linux options order
   (`MSS,Win,SACK,TS,NOP,WS`), normalize to Windows order
   (`Win,MSS,SACK,TS,NOP,WS`), assert options bytes match expected Windows pattern,
   TCP checksum valid.
5. **Options reordering only on SYN**: Verify data packets (ACK, PSH) are not
   reordered — only TTL/DF/window are normalized.
6. **DF bit normalization**: Set DF on a packet with DF=0, assert DF=1 after
   normalization, IP checksum valid.
7. **IP ID normalization**: Normalize IP ID from incremental to random, assert ID
   field changed, IP checksum valid.
8. **ICMP unreachable suppression**: Construct ICMP type 3 packet, normalize with
   `suppress_icmp_unreachable = true`, assert `NormalizeResult::Dropped`.
9. **ICMP echo reply normalization**: Construct echo request, build reply with Windows
   profile, assert TTL == 128, padding is zero-filled.
10. **ICMP echo reply (Linux profile)**: Assert TTL == 64, payload is exact echo.
11. **Profile = None passthrough**: Assert `NormalizeResult::Passthrough` for all
    packet types, no modification, no measurable overhead.
12. **Checksum validity**: After all normalizations, verify IP + TCP/ICMP checksums
    are valid using wireshark/tcpdump checksum verification.
13. **Consistency mapping**: `FingerprintProfile::from_browser_os(Chrome, Windows)`
    returns `Windows`; `(Firefox, Linux)` returns `Linux`; `(Safari, MacOS)` returns
    `MacOS`.

### Integration tests

14. **p0f verification (Linux, requires TUN + p0f)**: Send TCP SYN packets through
    the tunnel with `fingerprint_profile = "linux"`, run p0f on the egress interface,
    assert it reports Linux.
15. **p0f verification (Windows)**: Repeat with `fingerprint_profile = "windows"`,
    assert p0f reports Windows.
16. **nmap -O verification**: Run `nmap -O` against the tunneled client with each
    profile, assert the target OS is returned.
17. **Consistency check**: With `auto_from_stealth = true` and TLS profile = Chrome/Windows,
    verify p0f reports Windows AND TLS fingerprint matches Chrome on Windows.
18. **Rotation lockstep**: With fingerprint rotation enabled, verify that p0f and TLS
    fingerprint rotate simultaneously (no inconsistency window > 100ms).

### Performance tests

19. **Throughput**: Normalizer throughput on a 1 Gbps stream (64-byte packets) must
    not drop below 900 Mbps.
20. **Profile = None overhead**: < 1% overhead vs. raw forwarding.
21. **No allocation**: Verify via heap profiling that the normalizer hot path performs
    zero heap allocations.

## Files to Create/Modify

- `src/stealth/fingerprint.rs` — **new**: `FingerprintProfile`, `FingerprintConfig`,
  `PacketNormalizer`, `TcpOptionKind`, checksum update helpers, profile definitions,
  `from_browser_os` mapping.
- `src/stealth/mod.rs` — re-export `PacketNormalizer`, `FingerprintProfile`,
  `FingerprintConfig`; add module declaration; wire rotation lockstep.
- `src/engine/config.rs` — `FingerprintConfig` fields + TOML parsing +
  `auto_from_stealth` option.
- `src/implementations/server/mod.rs` — construct `PacketNormalizer` at startup;
  apply on TUN egress path; store in `ServerHostResources`.
- `src/implementations/server/icmp.rs` — parameterize TTL and padding pattern in
  `build_echo_reply` and `build_icmp_unreachable`; add profile-aware variants.
- Client TUN egress path (`src/implementations/client/` or `src/core.rs`) — apply
  `PacketNormalizer` analogously on the client side.
- `tests/fingerprint_normalizer_test.rs` — **new**: unit + integration tests
  (p0f / nmap -O verification).

## Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| TCP option reordering corrupts connections | HIGH | Only reorder on SYN packets. Data packets are TTL/DF/window only. Extensive checksum validation tests. |
| p0f signature mismatch (profile doesn't match real OS entry) | MEDIUM | Profile values derived from p0f v3 signature database. Validate against real p0f captures. |
| Inconsistency between TLS and IP fingerprint | HIGH | `auto_from_stealth` mode derives IP profile from TLS profile. Rotation lockstep enforced. |
| Normalizer adds latency to TUN forwarding | MEDIUM | In-place modification, incremental checksum, no allocation. Target < 1µs/packet. |
| ICMP suppression breaks Path MTU Discovery | MEDIUM | Only suppress when `suppress_icmp_unreachable = true`. Packet Too Big (type 3, code 4) should not be suppressed — add exception. |
| IPv6 not supported | LOW | Architecture accommodates IPv6 via `normalize_ipv6` method. Deferred to future TODO. |
| nmap -O still detects real OS via active probes | LOW | Active probes (nmap) send crafted packets to the tunneled client. The normalizer only affects egress packets, not the client's responses to probes. This is a known limitation — document it. |
| IP ID normalization breaks IP fragmentation reassembly | LOW | Only normalize IP ID on non-fragmented packets. Fragmented packets keep original ID. |

## Completion Criteria

- [ ] `FingerprintProfile` enum supports `Linux`, `Windows`, `MacOS`, `Android`, `None`.
- [ ] `PacketNormalizer::normalize` rewrites TTL, TCP window, MSS, TCP options order,
      DF bit, and IP ID on IPv4/TCP packets, with valid recomputed checksums.
- [ ] TCP option reordering is applied **only** to SYN packets (data packets unchanged).
- [ ] ICMP Destination Unreachable packets are suppressed when
      `suppress_icmp_unreachable = true` (with exception for Packet Too Big / PMTUD).
- [ ] ICMP echo replies are normalized (TTL + padding pattern) to the target profile.
- [ ] `fingerprint_profile = "none"` is a pure passthrough (no modification, < 1%
      overhead).
- [ ] `auto_from_stealth = true` derives `FingerprintProfile` from current
      `BrowserProfile`/`OsProfile` and rotates in lockstep.
- [ ] `p0f` on egress traffic reports the target OS for each profile.
- [ ] `nmap -O` against the tunneled client returns the target OS fingerprint.
- [ ] TLS fingerprint and IP fingerprint are consistent (no mismatch detected by
      composite fingerprinting tools).
- [ ] Normalizer hot path performs no heap allocation; throughput on a 1 Gbps stream
      stays above 900 Mbps.
- [ ] IP and TCP checksums are valid after normalization (verified by wireshark /
      tcpdump with no checksum errors).
- [ ] `cargo test` passes; `cargo clippy` reports no new warnings.
