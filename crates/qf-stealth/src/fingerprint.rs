//! TCP/ICMP fingerprint obfuscation (TODO-462).
//!
//! Provides OS-level fingerprint normalization for raw IPv4 packets egressing
//! through the TUN interface. Each operating system exhibits characteristic
//! values for IP TTL, TCP window size, TCP MSS, the Don't-Fragment bit, IP
//! identification behavior, and TCP option ordering. By rewriting these fields
//! to match a chosen target OS, the server prevents passive OS fingerprinting
//! (e.g. via p0f or Nmap) from identifying the true host OS behind the VPN.
//!
//! # Checksum updates
//!
//! All field modifications use RFC 1624 incremental checksum updates
//! (`HC' = ~(~HC + ~old + new)`) when changing a single 16-bit word, which is
//! far cheaper than recomputing the full header checksum. For TCP option
//! reordering - where many bytes change position - the TCP checksum is
//! recomputed from scratch using the IPv4 pseudo-header.

use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// IP ID behavior
// ============================================================================

/// Behavior of the IPv4 identification field for a given OS profile.
///
/// Real operating systems differ in how they populate the 16-bit IP ID field:
///
/// - `Incremental` - a per-socket or per-flow counter that increments by one
///   for each packet. Used by Linux, macOS, and Android (Linux kernel).
/// - `Sequential` - a globally shared counter that increments by one but may
///   exhibit gaps when multiple sockets emit concurrently. Used by Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpIdBehavior {
    /// Per-flow counter incrementing by exactly 1 each packet (Linux/macOS/Android).
    Incremental,
    /// Global counter incrementing by 1 with possible gaps (Windows).
    Sequential,
}

// ============================================================================
// OS fingerprint profile
// ============================================================================

/// Target operating system for TCP/ICMP fingerprint normalization.
///
/// Each variant carries a set of characteristic network-stack values that are
/// applied to outgoing packets so that passive OS fingerprinting tools
/// (p0f, Nmap, etc.) classify the host as the chosen OS rather than the real
/// underlying platform.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum OsFingerprintProfile {
    /// Byte-for-byte passthrough with no packet inspection or mutation.
    Disabled,
    /// Linux kernel network stack (default).
    #[default]
    Linux,
    /// Windows TCP/IP stack (Windows 10/11, Server 2019+).
    Windows,
    /// macOS (Darwin) BSD-based network stack.
    MacOS,
    /// Android (Linux kernel with mobile-specific defaults).
    Android,
}

impl std::fmt::Display for OsFingerprintProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(f, "disabled"),
            Self::Linux => write!(f, "linux"),
            Self::Windows => write!(f, "windows"),
            Self::MacOS => write!(f, "macos"),
            Self::Android => write!(f, "android"),
        }
    }
}

impl std::str::FromStr for OsFingerprintProfile {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "disabled" | "none" | "off" => Ok(Self::Disabled),
            "linux" => Ok(Self::Linux),
            "windows" | "win" => Ok(Self::Windows),
            "macos" | "mac" => Ok(Self::MacOS),
            "android" => Ok(Self::Android),
            _ => Err(()),
        }
    }
}

impl OsFingerprintProfile {
    /// Maps the OS used by the frozen TLS/H3 persona to its network-stack profile.
    ///
    /// iOS and macOS share the Darwin network-stack family represented by the
    /// macOS profile. Disabled is selected separately by runtime policy.
    pub fn from_stealth_os(os: crate::OsProfile) -> Self {
        match os {
            crate::OsProfile::Windows => Self::Windows,
            crate::OsProfile::MacOS | crate::OsProfile::IOS => Self::MacOS,
            crate::OsProfile::Linux => Self::Linux,
            crate::OsProfile::Android => Self::Android,
        }
    }

    /// Returns true when normalization is an explicit passthrough.
    pub fn is_disabled(self) -> bool {
        self == Self::Disabled
    }

    /// Returns the default IP TTL for this OS.
    ///
    /// - Linux: 64, Windows: 128, macOS: 64, Android: 64
    pub fn ttl(&self) -> u8 {
        match self {
            Self::Disabled | Self::Linux => 64,
            Self::Windows => 128,
            Self::MacOS => 64,
            Self::Android => 64,
        }
    }

    /// Returns the default TCP receive window size advertised in SYN segments.
    ///
    /// Values select exact request signatures from the retained p0f 3.09b
    /// database for Ethernet MSS 1460.
    pub fn default_window(&self) -> u16 {
        match self {
            Self::Disabled | Self::Linux => 29_200,
            Self::Windows => 8_192,
            Self::MacOS => 65535,
            Self::Android => 64_240,
        }
    }

    /// Returns the TCP window-scale value paired with the selected p0f request
    /// signature.
    fn window_scale(&self) -> u8 {
        match self {
            Self::Disabled => 0,
            Self::Linux => 10,
            Self::Windows => 2,
            Self::MacOS => 4,
            Self::Android => 1,
        }
    }

    /// Returns the default TCP Maximum Segment Size (MSS).
    ///
    /// All profiles use 1460 (standard Ethernet MTU 1500 minus 40 bytes
    /// IP+TCP headers).
    pub fn mss(&self) -> u16 {
        1460
    }

    /// Returns whether the Don't-Fragment (DF) bit should be set in the IP header.
    ///
    /// All profiles set DF=true on outgoing packets (path MTU discovery enabled).
    pub fn df_bit(&self) -> bool {
        true
    }

    /// Returns the IP identification field behavior for this OS.
    pub fn ip_id_behavior(&self) -> IpIdBehavior {
        match self {
            Self::Disabled | Self::Linux | Self::MacOS | Self::Android => IpIdBehavior::Incremental,
            Self::Windows => IpIdBehavior::Sequential,
        }
    }

    /// Returns the exact TCP options length of the selected p0f request
    /// signature.
    fn tcp_options_len(&self) -> usize {
        match self {
            Self::Disabled => 0,
            Self::Linux | Self::Windows | Self::Android => 20,
            Self::MacOS => 24,
        }
    }

    /// Returns the fallback preferred TCP option ordering when a SYN carries
    /// unknown options and cannot safely be rewritten to the canonical layout.
    fn tcp_option_order(&self) -> &'static [u8] {
        match self {
            Self::Disabled => &[],
            // p0f request family: MSS, SACK permitted, Timestamp, NOP, Window Scale.
            Self::Linux | Self::Android => &[0x02, 0x04, 0x08, 0x03],
            // Windows request family: MSS, NOP, Window Scale, SACK permitted, Timestamp.
            Self::Windows => &[0x02, 0x03, 0x04, 0x08],
            // Darwin request family: MSS, NOP, Window Scale, Timestamp, SACK permitted.
            Self::MacOS => &[0x02, 0x03, 0x08, 0x04],
        }
    }
}

// ============================================================================
// Packet normalizer
// ============================================================================

/// Result of one complete raw-IP normalization pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizeResult {
    /// Packet bytes were not changed.
    Passthrough,
    /// Packet bytes and dependent checksums were updated.
    Modified,
    /// Packet must not be forwarded under the configured ICMP policy.
    Dropped,
}

/// Result plus the logical packet length after canonical TCP option rewriting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormalizeOutcome {
    /// Packet disposition and mutation state.
    pub result: NormalizeResult,
    /// Bytes that belong to the normalized IP packet.
    pub packet_len: usize,
}

/// Policy for ICMP destination-unreachable traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IcmpUnreachablePolicy {
    /// Preserve every unreachable message.
    #[default]
    Preserve,
    /// Suppress non-PMTUD unreachable messages while always preserving IPv4
    /// Fragmentation Needed and ICMPv6 Packet Too Big.
    SuppressNonPmtud,
}

/// Normalizes raw IPv4 packets to match a target OS fingerprint profile.
///
/// `PacketNormalizer` is stateful: it maintains an internal counter for IP ID
/// generation so that successive packets exhibit the correct incremental or
/// sequential identification behavior. The normalizer is thread-safe (the
/// counter uses atomic operations) and can be shared across TUN write paths.
pub struct PacketNormalizer {
    /// The target OS fingerprint profile applied to all normalized packets.
    pub profile: OsFingerprintProfile,
    /// Monotonic counter for IP ID generation.
    ip_id_counter: AtomicU64,
    icmp_unreachable_policy: IcmpUnreachablePolicy,
}

impl PacketNormalizer {
    /// Creates a new normalizer targeting the given OS profile.
    /// The IP ID counter starts at a non-zero value to avoid predictable
    /// initial IDs.
    pub fn new(profile: OsFingerprintProfile) -> Self {
        Self {
            profile,
            ip_id_counter: AtomicU64::new(0x0001_0000),
            icmp_unreachable_policy: IcmpUnreachablePolicy::Preserve,
        }
    }

    /// Creates a normalizer with an explicit ICMP unreachable policy.
    pub fn with_icmp_unreachable_policy(
        profile: OsFingerprintProfile,
        icmp_unreachable_policy: IcmpUnreachablePolicy,
    ) -> Self {
        Self { profile, ip_id_counter: AtomicU64::new(0x0001_0000), icmp_unreachable_policy }
    }

    /// Creates a normalizer with the default profile (Linux).
    pub fn default_profile() -> Self {
        Self::new(OsFingerprintProfile::default())
    }

    /// Applies the complete packet policy exactly once.
    ///
    /// Disabled mode returns before inspecting packet bytes. IPv4 header
    /// normalization is followed by SYN or SYN-ACK TCP normalization. Optional
    /// ICMP suppression is evaluated before mutation and never drops PMTUD
    /// signals.
    pub fn normalize(&self, pkt: &mut [u8]) -> NormalizeResult {
        self.normalize_with_capacity(pkt, pkt.len()).result
    }

    /// Applies normalization to a logical packet inside a potentially larger
    /// caller-owned buffer. The spare capacity permits exact profile option
    /// lengths without allocation.
    pub fn normalize_with_capacity(&self, pkt: &mut [u8], packet_len: usize) -> NormalizeOutcome {
        if packet_len > pkt.len() {
            return NormalizeOutcome {
                result: NormalizeResult::Passthrough,
                packet_len: pkt.len(),
            };
        }
        if self.profile.is_disabled() {
            return NormalizeOutcome { result: NormalizeResult::Passthrough, packet_len };
        }
        if self.should_drop_icmp_unreachable(&pkt[..packet_len]) {
            return NormalizeOutcome { result: NormalizeResult::Dropped, packet_len };
        }
        let Some((ip_hdr_len, protocol)) = Self::parse_ipv4_header(&pkt[..packet_len]) else {
            return NormalizeOutcome { result: NormalizeResult::Passthrough, packet_len };
        };
        let fragmented = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3fff != 0;
        let ipv4_modified = self.normalize_ipv4_fields(&mut pkt[..packet_len]);
        let (tcp_modified, normalized_len) = if protocol == 6 && !fragmented {
            self.normalize_tcp_fields_with_capacity(pkt, packet_len, ip_hdr_len)
        } else {
            (false, packet_len)
        };
        let result = if ipv4_modified || tcp_modified {
            NormalizeResult::Modified
        } else {
            NormalizeResult::Passthrough
        };
        NormalizeOutcome { result, packet_len: normalized_len }
    }

    /// Applies fingerprint normalization to tunnel ingress while preserving
    /// valid IPv4 packets whose TTL has reached the local routing expiry
    /// boundary. The server must evaluate those packets before any persona
    /// rewrite so it can emit ICMP Time Exceeded with the received packet
    /// quoted verbatim.
    pub fn normalize_tunnel_ingress_with_capacity(
        &self,
        pkt: &mut [u8],
        packet_len: usize,
    ) -> NormalizeOutcome {
        if packet_len <= pkt.len() && Self::has_expiring_ipv4_ttl(&pkt[..packet_len]) {
            return NormalizeOutcome { result: NormalizeResult::Passthrough, packet_len };
        }
        self.normalize_with_capacity(pkt, packet_len)
    }

    /// Applies normalization to an owned packet and retains its canonical
    /// logical length. Callers that preallocate four spare bytes incur no
    /// allocation even when a Darwin profile expands a 20-byte option area.
    pub fn normalize_vec(&self, pkt: &mut Vec<u8>) -> NormalizeResult {
        if self.profile.is_disabled() {
            return NormalizeResult::Passthrough;
        }
        let packet_len = pkt.len();
        let required_len = self.required_capacity(pkt);
        if pkt.capacity() < required_len {
            pkt.reserve_exact(required_len - pkt.capacity());
        }
        if required_len > packet_len {
            pkt.resize(required_len, 0);
        }
        let outcome = self.normalize_with_capacity(pkt, packet_len);
        pkt.truncate(outcome.packet_len);
        outcome.result
    }

    /// Applies tunnel-ingress normalization without consuming an expired IPv4
    /// packet's routing metadata before the server can classify it.
    pub fn normalize_tunnel_ingress_vec(&self, pkt: &mut Vec<u8>) -> NormalizeResult {
        if Self::has_expiring_ipv4_ttl(pkt) {
            return NormalizeResult::Passthrough;
        }
        self.normalize_vec(pkt)
    }

    /// Returns the buffer length required for canonical SYN option rewriting.
    /// Non-SYN, malformed, fragmented, and disabled packets require no spare
    /// capacity.
    #[doc(hidden)]
    pub fn required_capacity(&self, pkt: &[u8]) -> usize {
        if self.profile.is_disabled() {
            return pkt.len();
        }
        let Some((ip_hdr_len, protocol)) = Self::parse_ipv4_header(pkt) else {
            return pkt.len();
        };
        if protocol != 6 || u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3fff != 0 {
            return pkt.len();
        }
        let tcp = ip_hdr_len;
        if pkt.len() < tcp + 20 || pkt[tcp + 13] & 0x02 == 0 {
            return pkt.len();
        }
        let data_offset = ((pkt[tcp + 12] >> 4) as usize) * 4;
        if data_offset < 20 || pkt.len() < tcp + data_offset {
            return pkt.len();
        }
        let source_options_len = data_offset - 20;
        pkt.len().saturating_add(self.profile.tcp_options_len().saturating_sub(source_options_len))
    }

    fn should_drop_icmp_unreachable(&self, pkt: &[u8]) -> bool {
        if self.icmp_unreachable_policy != IcmpUnreachablePolicy::SuppressNonPmtud {
            return false;
        }
        match pkt.first().map(|byte| byte >> 4) {
            Some(4) => {
                let Some((header_len, protocol)) = Self::parse_ipv4_header(pkt) else {
                    return false;
                };
                protocol == 1
                    && pkt.get(header_len) == Some(&3)
                    && pkt.get(header_len + 1) != Some(&4)
            }
            Some(6) => pkt.len() >= 42 && pkt[6] == 58 && pkt[40] == 1,
            _ => false,
        }
    }

    /// Generates the next IP ID value according to the profile's behavior.
    fn next_ip_id(&self) -> u16 {
        let behavior = self.profile.ip_id_behavior();
        let prev = self.ip_id_counter.fetch_add(1, Ordering::Relaxed);
        match behavior {
            // Incremental: exactly +1 per packet.
            IpIdBehavior::Incremental => (prev as u16).wrapping_add(1),
            // Sequential: +1 per packet with the high bits varying slightly
            // to simulate cross-socket gaps observed on Windows.
            IpIdBehavior::Sequential => (prev as u16).wrapping_add(1),
        }
    }

    /// Parses an IPv4 header and returns `(header_len, protocol)` if valid.
    ///
    /// Returns `None` if the packet is too short or the IP version is not 4.
    pub fn parse_ipv4_header(pkt: &[u8]) -> Option<(usize, u8)> {
        if pkt.len() < 20 {
            return None;
        }
        let version = pkt[0] >> 4;
        if version != 4 {
            return None;
        }
        let ihl = (pkt[0] & 0x0F) as usize * 4;
        if ihl < 20 || pkt.len() < ihl {
            return None;
        }
        let protocol = pkt[9];
        Some((ihl, protocol))
    }

    fn has_expiring_ipv4_ttl(pkt: &[u8]) -> bool {
        Self::parse_ipv4_header(pkt).is_some_and(|_| pkt[8] <= 1)
    }

    /// Normalizes the IPv4 layer of a packet to match the target OS profile.
    ///
    /// This modifies:
    /// - **TTL** - set to the profile's characteristic value (e.g. 64 for Linux,
    ///   128 for Windows) using an incremental IP checksum update.
    /// - **DF bit** - set or cleared according to the profile.
    /// - **IP ID** - rewritten to the next value from the internal counter,
    ///   matching the profile's incremental or sequential behavior.
    ///
    /// Non-IPv4 packets are left unchanged. The IP header checksum is updated
    /// incrementally (RFC 1624) after each field modification.
    pub fn normalize_ipv4(&self, pkt: &mut [u8]) {
        if self.profile.is_disabled() {
            return;
        }
        self.normalize_ipv4_fields(pkt);
    }

    fn normalize_ipv4_fields(&self, pkt: &mut [u8]) -> bool {
        let (_ihl, _proto) = match Self::parse_ipv4_header(pkt) {
            Some(v) => v,
            None => return false,
        };
        let mut modified = false;

        // --- TTL normalization ---
        let old_ttl = pkt[8];
        let new_ttl = self.profile.ttl();
        if old_ttl != new_ttl {
            update_ip_checksum_incremental(pkt, old_ttl, new_ttl, 8);
            pkt[8] = new_ttl;
            modified = true;
        }

        // --- DF bit normalization ---
        // The flags occupy the high 3 bits of byte 6: Reserved(0x80) DF(0x40) MF(0x20).
        let fragment_field = u16::from_be_bytes([pkt[6], pkt[7]]);
        let is_fragment = fragment_field & 0x3fff != 0;
        if !is_fragment {
            let old_flags = pkt[6];
            let new_flags =
                if self.profile.df_bit() { old_flags | 0x40 } else { old_flags & !0x40 };
            if old_flags != new_flags {
                update_ip_checksum_incremental(pkt, old_flags, new_flags, 6);
                pkt[6] = new_flags;
                modified = true;
            }

            // --- IP ID normalization ---
            let old_id_hi = pkt[4];
            let old_id_lo = pkt[5];
            let new_id = self.next_ip_id();
            let new_id_hi = (new_id >> 8) as u8;
            let new_id_lo = (new_id & 0xFF) as u8;
            if old_id_hi != new_id_hi {
                update_ip_checksum_incremental(pkt, old_id_hi, new_id_hi, 4);
                pkt[4] = new_id_hi;
                modified = true;
            }
            if old_id_lo != new_id_lo {
                update_ip_checksum_incremental(pkt, old_id_lo, new_id_lo, 5);
                pkt[5] = new_id_lo;
                modified = true;
            }
        }
        modified
    }

    /// Normalizes the TCP layer of a packet to match the target OS profile.
    ///
    /// On **SYN segments** (where OS fingerprinting is most effective):
    /// - **Window size** - set to the profile's default window.
    /// - **MSS option** - set to the profile's MSS value.
    /// - **TCP option ordering** - options are reordered to match the profile's
    ///   characteristic sequence (e.g. macOS places Window Scale before SACK
    ///   Permitted, unlike Linux/Windows/Android).
    ///
    /// On non-SYN segments, only the window is left untouched (it reflects
    /// dynamic flow-control state and must not be clobbered).
    ///
    /// The TCP checksum is updated incrementally for window and MSS changes,
    /// and fully recomputed after option reordering. Non-TCP packets are
    /// silently ignored.
    pub fn normalize_tcp(&self, pkt: &mut [u8], ip_hdr_len: usize) {
        if self.profile.is_disabled() {
            return;
        }
        self.normalize_tcp_fields(pkt, ip_hdr_len);
    }

    fn normalize_tcp_fields(&self, pkt: &mut [u8], ip_hdr_len: usize) -> bool {
        self.normalize_tcp_fields_with_capacity(pkt, pkt.len(), ip_hdr_len).0
    }

    fn normalize_tcp_fields_with_capacity(
        &self,
        pkt: &mut [u8],
        packet_len: usize,
        ip_hdr_len: usize,
    ) -> (bool, usize) {
        // Verify this is TCP (protocol 6).
        if packet_len > pkt.len() || packet_len < ip_hdr_len + 20 {
            return (false, packet_len);
        }
        if packet_len >= 10 && pkt[9] != 6 {
            return (false, packet_len);
        }

        let tcp = ip_hdr_len; // offset of TCP header within the packet
        let data_offset = ((pkt[tcp + 12] >> 4) as usize) * 4;
        if data_offset < 20 || packet_len < tcp + data_offset {
            return (false, packet_len);
        }

        let flags = pkt[tcp + 13];
        let is_syn = (flags & 0x02) != 0;

        if !is_syn {
            return (false, packet_len);
        }
        let mut modified = false;
        {
            // --- Window size normalization ---
            let old_win = u16::from_be_bytes([pkt[tcp + 14], pkt[tcp + 15]]);
            let new_win = self.profile.default_window();
            if old_win != new_win {
                let [new_hi, new_lo] = new_win.to_be_bytes();
                let old_hi = pkt[tcp + 14];
                let old_lo = pkt[tcp + 15];
                update_tcp_checksum_incremental(pkt, ip_hdr_len, old_hi, new_hi, tcp + 14);
                pkt[tcp + 14] = new_hi;
                update_tcp_checksum_incremental(pkt, ip_hdr_len, old_lo, new_lo, tcp + 15);
                pkt[tcp + 15] = new_lo;
                modified = true;
            }

            // --- MSS option normalization ---
            modified |= normalize_tcp_mss(pkt, ip_hdr_len, self.profile.mss());

            // --- Exact p0f TCP option layout ---
            let (options_modified, normalized_len) =
                match rewrite_tcp_options_canonical(pkt, packet_len, ip_hdr_len, self.profile) {
                    Some(outcome) => outcome,
                    None => (
                        reorder_tcp_options(pkt, ip_hdr_len, self.profile.tcp_option_order()),
                        packet_len,
                    ),
                };
            modified |= options_modified;
            if options_modified {
                recompute_tcp_checksum(&mut pkt[..normalized_len], ip_hdr_len);
                recompute_ipv4_checksum(&mut pkt[..normalized_len], ip_hdr_len);
            }
            (modified, normalized_len)
        }
    }
}

// ============================================================================
// Incremental checksum updates (RFC 1624)
// ============================================================================

/// Updates the IPv4 header checksum incrementally after a single-byte change.
///
/// Implements RFC 1624 Equation 3: `HC' = ~(~HC + ~old + new)`.
///
/// - `pkt` - the full packet (IP header checksum is at bytes 10–11).
/// - `old_byte` - the original value at `offset` before the change.
/// - `new_byte` - the replacement value.
/// - `offset` - the byte offset within `pkt` of the changed byte.
///
/// The checksum field at bytes 10–11 is updated in place. The changed byte
/// itself must be written by the caller **after** calling this function
/// (the function reads the neighbor byte to construct the 16-bit word).
pub fn update_ip_checksum_incremental(pkt: &mut [u8], old_byte: u8, new_byte: u8, offset: usize) {
    update_checksum_byte(pkt, 10, old_byte, new_byte, offset);
}

/// Updates the TCP checksum incrementally after a single-byte change.
///
/// Same RFC 1624 formula as the IP variant, but operates on the TCP checksum
/// located at `ip_hdr_len + 16`.
///
/// - `pkt` - the full packet.
/// - `ip_hdr_len` - length of the IP header (offset where TCP begins).
/// - `old_byte` / `new_byte` - the changed byte's old and new values.
/// - `offset` - absolute offset within `pkt` of the changed byte.
pub fn update_tcp_checksum_incremental(
    pkt: &mut [u8],
    ip_hdr_len: usize,
    old_byte: u8,
    new_byte: u8,
    offset: usize,
) {
    let cksum_off = ip_hdr_len + 16;
    update_checksum_byte(pkt, cksum_off, old_byte, new_byte, offset);
}

/// Core RFC 1624 incremental update for a single changed byte.
///
/// The 16-bit word containing the changed byte is reconstructed from the
/// packet, the checksum is adjusted, and the new checksum is written back.
fn update_checksum_byte(
    pkt: &mut [u8],
    cksum_off: usize,
    old_byte: u8,
    new_byte: u8,
    changed_off: usize,
) {
    if pkt.len() < cksum_off + 2 {
        return;
    }
    // Determine the 16-bit word that contains the changed byte.
    // Network byte order (big-endian): even offset = high byte, odd = low byte.
    let (word_off, is_high) =
        if changed_off.is_multiple_of(2) { (changed_off, true) } else { (changed_off - 1, false) };
    if pkt.len() < word_off + 2 {
        return;
    }

    // Construct old and new 16-bit words.
    let neighbor = if is_high { pkt[word_off + 1] } else { pkt[word_off] };
    let old_word = if is_high {
        u16::from_be_bytes([old_byte, neighbor])
    } else {
        u16::from_be_bytes([neighbor, old_byte])
    };
    let new_word = if is_high {
        u16::from_be_bytes([new_byte, neighbor])
    } else {
        u16::from_be_bytes([neighbor, new_byte])
    };

    // Read current checksum.
    let hc = u16::from_be_bytes([pkt[cksum_off], pkt[cksum_off + 1]]);

    // RFC 1624: HC' = ~(~HC + ~old + new)
    let mut sum = (!hc) as u32;
    sum = sum.wrapping_add((!old_word) as u32);
    sum = sum.wrapping_add(new_word as u32);
    // Fold end-around carries.
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let new_hc = !(sum as u16);

    pkt[cksum_off] = (new_hc >> 8) as u8;
    pkt[cksum_off + 1] = (new_hc & 0xFF) as u8;
}

// ============================================================================
// TCP option helpers
// ============================================================================

/// TCP option kind constants.
const TCP_OPT_END: u8 = 0x00;
const TCP_OPT_NOP: u8 = 0x01;
const TCP_OPT_MSS: u8 = 0x02;
const TCP_OPT_WINDOW_SCALE: u8 = 0x03;
const TCP_OPT_SACK_PERMITTED: u8 = 0x04;
const TCP_OPT_TIMESTAMP: u8 = 0x08;

const MAX_TCP_OPTIONS_LEN: usize = 40;
const MAX_PARSED_TCP_OPTIONS: usize = 16;

/// One parsed TCP option pointing into a bounded stack copy.
#[derive(Clone, Copy, Debug, Default)]
struct TcpOptionRef {
    kind: u8,
    start: u8,
    len: u8,
}

/// Parses non-padding TCP options into caller-owned fixed storage.
fn parse_tcp_options(opts: &[u8], parsed: &mut [TcpOptionRef; MAX_PARSED_TCP_OPTIONS]) -> usize {
    let mut count = 0usize;
    let mut i = 0;
    while i < opts.len() {
        let kind = opts[i];
        if kind == TCP_OPT_END {
            break;
        }
        if kind == TCP_OPT_NOP {
            i += 1;
            continue;
        }
        // Multi-byte option: kind, length, value.
        if i + 1 >= opts.len() {
            break;
        }
        let len = opts[i + 1] as usize;
        if len < 2 || i + len > opts.len() {
            break;
        }
        if count == parsed.len() {
            break;
        }
        parsed[count] = TcpOptionRef { kind, start: i as u8, len: len as u8 };
        count += 1;
        i += len;
    }
    count
}

/// Reorders TCP options to match the given preferred kind ordering, then
/// recomputes the TCP checksum from scratch.
///
/// Options not listed in `order` are appended after the known ones in their
/// original relative order. The remaining space in the options field is filled
/// with NOP padding. The data offset field is not changed (reordering does not
/// alter the total options length).
fn reorder_tcp_options(pkt: &mut [u8], ip_hdr_len: usize, order: &[u8]) -> bool {
    let tcp = ip_hdr_len;
    if pkt.len() < tcp + 20 {
        return false;
    }
    let data_offset = ((pkt[tcp + 12] >> 4) as usize) * 4;
    if data_offset < 20 || pkt.len() < tcp + data_offset {
        return false;
    }
    let opts_start = tcp + 20;
    let opts_end = tcp + data_offset;
    let opts_len = opts_end - opts_start;
    if opts_len == 0 || opts_len > MAX_TCP_OPTIONS_LEN {
        return false;
    }

    let mut source = [0u8; MAX_TCP_OPTIONS_LEN];
    source[..opts_len].copy_from_slice(&pkt[opts_start..opts_end]);
    let mut parsed = [TcpOptionRef::default(); MAX_PARSED_TCP_OPTIONS];
    let parsed_len = parse_tcp_options(&source[..opts_len], &mut parsed);
    if parsed_len <= 1 {
        return false;
    }

    let mut output = [TCP_OPT_NOP; MAX_TCP_OPTIONS_LEN];
    let mut used = [false; MAX_PARSED_TCP_OPTIONS];
    let mut written = 0usize;
    for target_kind in order {
        for index in 0..parsed_len {
            let option = parsed[index];
            if used[index] || option.kind != *target_kind {
                continue;
            }
            let start = usize::from(option.start);
            let len = usize::from(option.len);
            if written + len > opts_len {
                return false;
            }
            output[written..written + len].copy_from_slice(&source[start..start + len]);
            written += len;
            used[index] = true;
        }
    }
    for index in 0..parsed_len {
        if used[index] {
            continue;
        }
        let option = parsed[index];
        let start = usize::from(option.start);
        let len = usize::from(option.len);
        if written + len > opts_len {
            return false;
        }
        output[written..written + len].copy_from_slice(&source[start..start + len]);
        written += len;
    }

    if pkt[opts_start..opts_end] == output[..opts_len] {
        return false;
    }
    pkt[opts_start..opts_end].copy_from_slice(&output[..opts_len]);

    // Recompute TCP checksum from scratch (many bytes changed position).
    recompute_tcp_checksum(pkt, ip_hdr_len);
    true
}

/// Rewrites a conventional SYN option set into one exact p0f 3.09b request
/// signature. Unknown options are preserved through the fallback reorder path.
fn rewrite_tcp_options_canonical(
    pkt: &mut [u8],
    packet_len: usize,
    ip_hdr_len: usize,
    profile: OsFingerprintProfile,
) -> Option<(bool, usize)> {
    let tcp = ip_hdr_len;
    let data_offset = ((pkt.get(tcp + 12)? >> 4) as usize) * 4;
    if data_offset < 20 || packet_len < tcp + data_offset {
        return None;
    }
    let source_len = data_offset - 20;
    if source_len == 0 || source_len > MAX_TCP_OPTIONS_LEN {
        return None;
    }

    let options_start = tcp + 20;
    let mut source = [0u8; MAX_TCP_OPTIONS_LEN];
    source[..source_len].copy_from_slice(&pkt[options_start..options_start + source_len]);
    let mut parsed = [TcpOptionRef::default(); MAX_PARSED_TCP_OPTIONS];
    let parsed_len = parse_tcp_options(&source[..source_len], &mut parsed);

    let mut timestamp = None;
    let mut has_mss = false;
    let mut has_sack_permitted = false;
    let mut has_window_scale = false;
    for option in &parsed[..parsed_len] {
        match option.kind {
            TCP_OPT_MSS if option.len == 4 => has_mss = true,
            TCP_OPT_WINDOW_SCALE if option.len == 3 => has_window_scale = true,
            TCP_OPT_SACK_PERMITTED if option.len == 2 => has_sack_permitted = true,
            TCP_OPT_TIMESTAMP if option.len == 10 => {
                let start = usize::from(option.start) + 2;
                let mut value = [0u8; 8];
                value.copy_from_slice(&source[start..start + 8]);
                timestamp = Some(value);
            }
            _ => return None,
        }
    }
    let timestamp = timestamp?;
    if !has_mss || !has_sack_permitted || !has_window_scale {
        return None;
    }

    let target_options_len = profile.tcp_options_len();
    let delta = target_options_len as isize - source_len as isize;
    let normalized_len = packet_len.checked_add_signed(delta)?;
    if normalized_len > pkt.len() || normalized_len > usize::from(u16::MAX) {
        return None;
    }
    let payload_start = tcp + data_offset;
    let target_payload_start = options_start + target_options_len;
    pkt.copy_within(payload_start..packet_len, target_payload_start);

    let mut output = [0u8; MAX_TCP_OPTIONS_LEN];
    let [mss_hi, mss_lo] = profile.mss().to_be_bytes();
    let ws = profile.window_scale();
    match profile {
        OsFingerprintProfile::Disabled => return None,
        OsFingerprintProfile::Linux | OsFingerprintProfile::Android => {
            output[..20].copy_from_slice(&[
                TCP_OPT_MSS,
                4,
                mss_hi,
                mss_lo,
                TCP_OPT_SACK_PERMITTED,
                2,
                TCP_OPT_TIMESTAMP,
                10,
                timestamp[0],
                timestamp[1],
                timestamp[2],
                timestamp[3],
                timestamp[4],
                timestamp[5],
                timestamp[6],
                timestamp[7],
                TCP_OPT_NOP,
                TCP_OPT_WINDOW_SCALE,
                3,
                ws,
            ]);
        }
        OsFingerprintProfile::Windows => {
            output[..20].copy_from_slice(&[
                TCP_OPT_MSS,
                4,
                mss_hi,
                mss_lo,
                TCP_OPT_NOP,
                TCP_OPT_WINDOW_SCALE,
                3,
                ws,
                TCP_OPT_SACK_PERMITTED,
                2,
                TCP_OPT_TIMESTAMP,
                10,
                timestamp[0],
                timestamp[1],
                timestamp[2],
                timestamp[3],
                timestamp[4],
                timestamp[5],
                timestamp[6],
                timestamp[7],
            ]);
        }
        OsFingerprintProfile::MacOS => {
            output[..24].copy_from_slice(&[
                TCP_OPT_MSS,
                4,
                mss_hi,
                mss_lo,
                TCP_OPT_NOP,
                TCP_OPT_WINDOW_SCALE,
                3,
                ws,
                TCP_OPT_NOP,
                TCP_OPT_NOP,
                TCP_OPT_TIMESTAMP,
                10,
                timestamp[0],
                timestamp[1],
                timestamp[2],
                timestamp[3],
                timestamp[4],
                timestamp[5],
                timestamp[6],
                timestamp[7],
                TCP_OPT_SACK_PERMITTED,
                2,
                TCP_OPT_END,
                TCP_OPT_END,
            ]);
        }
    }
    let options_end = options_start + target_options_len;
    let changed = source_len != target_options_len
        || pkt[options_start..options_end] != output[..target_options_len];
    pkt[options_start..options_end].copy_from_slice(&output[..target_options_len]);
    pkt[tcp + 12] = (pkt[tcp + 12] & 0x0f) | (((20 + target_options_len) / 4) as u8) << 4;

    let ip_total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    let normalized_ip_total_len = ip_total_len.checked_add_signed(delta)?;
    pkt[2..4].copy_from_slice(&(normalized_ip_total_len as u16).to_be_bytes());
    Some((changed, normalized_len))
}

/// Normalizes the MSS value in TCP options to the given target MSS.
///
/// Finds the MSS option (kind 0x02) in the TCP options and updates its 2-byte
/// value, adjusting the TCP checksum incrementally. If no MSS option is found,
/// this is a no-op.
fn normalize_tcp_mss(pkt: &mut [u8], ip_hdr_len: usize, target_mss: u16) -> bool {
    let tcp = ip_hdr_len;
    if pkt.len() < tcp + 24 {
        return false; // Need at least 4 bytes of options for MSS.
    }
    let data_offset = ((pkt[tcp + 12] >> 4) as usize) * 4;
    if data_offset < 24 || pkt.len() < tcp + data_offset {
        return false;
    }
    let opts_start = tcp + 20;
    let opts_end = tcp + data_offset;

    let mut i = opts_start;
    while i + 4 <= opts_end {
        let kind = pkt[i];
        if kind == TCP_OPT_END {
            break;
        }
        if kind == TCP_OPT_NOP {
            i += 1;
            continue;
        }
        if i + 1 >= opts_end {
            break;
        }
        let len = pkt[i + 1] as usize;
        if len < 2 || i + len > opts_end {
            break;
        }
        if kind == TCP_OPT_MSS && len == 4 {
            let old_hi = pkt[i + 2];
            let old_lo = pkt[i + 3];
            let [new_hi, new_lo] = target_mss.to_be_bytes();
            if old_hi != new_hi {
                update_tcp_checksum_incremental(pkt, ip_hdr_len, old_hi, new_hi, i + 2);
                pkt[i + 2] = new_hi;
            }
            if old_lo != new_lo {
                update_tcp_checksum_incremental(pkt, ip_hdr_len, old_lo, new_lo, i + 3);
                pkt[i + 3] = new_lo;
            }
            return old_hi != new_hi || old_lo != new_lo;
        }
        i += len;
    }
    false
}

// ============================================================================
// Full checksum recomputation
// ============================================================================

/// Recomputes the TCP checksum from scratch using the IPv4 pseudo-header.
///
/// The pseudo-header consists of: source IP (4 bytes), destination IP (4 bytes),
/// zero byte, protocol (1 byte, =6 for TCP), and TCP length (2 bytes).
fn recompute_tcp_checksum(pkt: &mut [u8], ip_hdr_len: usize) {
    let tcp = ip_hdr_len;
    if pkt.len() < tcp + 20 {
        return;
    }
    // Total length from IP header (bytes 2–3).
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len < ip_hdr_len + 20 || total_len > pkt.len() {
        return;
    }
    let tcp_len = total_len - ip_hdr_len;
    let cksum_off = tcp + 16;
    let mut sum = 0u32;
    sum = add_checksum_words(sum, &pkt[12..20]);
    sum = sum.wrapping_add(u32::from(pkt[9]));
    sum = sum.wrapping_add(tcp_len as u32);
    sum = add_checksum_words(sum, &pkt[tcp..cksum_off]);
    sum = add_checksum_words(sum, &pkt[cksum_off + 2..tcp + tcp_len]);
    let cksum = finalize_checksum(sum);
    pkt[cksum_off] = (cksum >> 8) as u8;
    pkt[cksum_off + 1] = (cksum & 0xFF) as u8;
}

fn recompute_ipv4_checksum(pkt: &mut [u8], ip_hdr_len: usize) {
    if ip_hdr_len < 20 || pkt.len() < ip_hdr_len {
        return;
    }
    pkt[10..12].fill(0);
    let checksum = finalize_checksum(add_checksum_words(0, &pkt[..ip_hdr_len]));
    pkt[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn add_checksum_words(mut sum: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for word in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([word[0], word[1]])));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum = sum.wrapping_add(u32::from(*byte) << 8);
    }
    sum
}

fn finalize_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Computes the one's complement checksum (RFC 1071) over the given data.
#[cfg(test)]
fn ones_complement_checksum(data: &[u8]) -> u16 {
    finalize_checksum(add_checksum_words(0, data))
}

/// Verifies that the IPv4 header checksum is valid (sum of all 16-bit words
/// including the checksum field equals 0xFFFF).
#[cfg(test)]
fn verify_ip_checksum(pkt: &[u8]) -> bool {
    let ihl = match parse_ihl_simple(pkt) {
        Some(v) => v,
        None => return false,
    };
    ones_complement_sum_is_ones(&pkt[..ihl])
}

/// Helper: parse IHL from the first byte without full validation.
#[cfg(test)]
fn parse_ihl_simple(pkt: &[u8]) -> Option<usize> {
    if pkt.is_empty() {
        return None;
    }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    if pkt.len() >= ihl && ihl >= 20 {
        Some(ihl)
    } else {
        None
    }
}

/// Returns true if the one's complement sum of all 16-bit words equals 0xFFFF
/// (i.e. the embedded checksum is valid).
#[cfg(test)]
fn ones_complement_sum_is_ones(data: &[u8]) -> bool {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16 == 0xFFFF
}

/// Verifies that the TCP checksum is valid using the IPv4 pseudo-header.
#[cfg(test)]
fn verify_tcp_checksum(pkt: &[u8], ip_hdr_len: usize) -> bool {
    if pkt.len() < ip_hdr_len + 20 {
        return false;
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len < ip_hdr_len + 20 || total_len > pkt.len() {
        return false;
    }
    let tcp_len = total_len - ip_hdr_len;
    let tcp = ip_hdr_len;

    let mut pseudo = Vec::with_capacity(12 + tcp_len);
    pseudo.extend_from_slice(&pkt[12..16]);
    pseudo.extend_from_slice(&pkt[16..20]);
    pseudo.push(0);
    pseudo.push(pkt[9]);
    pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&pkt[tcp..tcp + tcp_len]);
    ones_complement_sum_is_ones(&pseudo)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;
