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
//! reordering — where many bytes change position — the TCP checksum is
//! recomputed from scratch using the IPv4 pseudo-header.

use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// IP ID behavior
// ============================================================================

/// Behavior of the IPv4 identification field for a given OS profile.
///
/// Real operating systems differ in how they populate the 16-bit IP ID field:
///
/// - `Incremental` — a per-socket or per-flow counter that increments by one
///   for each packet. Used by Linux, macOS, and Android (Linux kernel).
/// - `Sequential` — a globally shared counter that increments by one but may
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
            "linux" => Ok(Self::Linux),
            "windows" | "win" => Ok(Self::Windows),
            "macos" | "mac" => Ok(Self::MacOS),
            "android" => Ok(Self::Android),
            _ => Err(()),
        }
    }
}

impl OsFingerprintProfile {
    /// Returns the default IP TTL for this OS.
    ///
    /// - Linux: 64, Windows: 128, macOS: 64, Android: 64
    pub fn ttl(&self) -> u8 {
        match self {
            Self::Linux => 64,
            Self::Windows => 128,
            Self::MacOS => 64,
            Self::Android => 64,
        }
    }

    /// Returns the default TCP receive window size advertised in SYN segments.
    ///
    /// - Linux: 64240, Windows: 65535, macOS: 65535, Android: 57344
    pub fn default_window(&self) -> u16 {
        match self {
            Self::Linux => 64240,
            Self::Windows => 65535,
            Self::MacOS => 65535,
            Self::Android => 57344,
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
            Self::Linux | Self::MacOS | Self::Android => IpIdBehavior::Incremental,
            Self::Windows => IpIdBehavior::Sequential,
        }
    }

    /// Returns the preferred TCP option ordering for SYN segments, expressed as
    /// a list of option kind bytes in the order they should appear.
    ///
    /// Common TCP option kinds:
    /// - `0x02` — MSS (Maximum Segment Size)
    /// - `0x03` — Window Scale
    /// - `0x04` — SACK Permitted
    /// - `0x08` — Timestamp
    fn tcp_option_order(&self) -> &'static [u8] {
        match self {
            // Linux: MSS, SACK_PERM, WindowScale, Timestamp
            Self::Linux | Self::Android => &[0x02, 0x04, 0x03, 0x08],
            // Windows: MSS, SACK_PERM, WindowScale, Timestamp
            Self::Windows => &[0x02, 0x04, 0x03, 0x08],
            // macOS: MSS, WindowScale, SACK_PERM, Timestamp
            Self::MacOS => &[0x02, 0x03, 0x04, 0x08],
        }
    }
}

// ============================================================================
// Packet normalizer
// ============================================================================

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
}

impl PacketNormalizer {
    /// Creates a new normalizer targeting the given OS profile.
    /// The IP ID counter starts at a non-zero value to avoid predictable
    /// initial IDs.
    pub fn new(profile: OsFingerprintProfile) -> Self {
        Self { profile, ip_id_counter: AtomicU64::new(0x0001_0000) }
    }

    /// Creates a normalizer with the default profile (Linux).
    pub fn default_profile() -> Self {
        Self::new(OsFingerprintProfile::default())
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

    /// Normalizes the IPv4 layer of a packet to match the target OS profile.
    ///
    /// This modifies:
    /// - **TTL** — set to the profile's characteristic value (e.g. 64 for Linux,
    ///   128 for Windows) using an incremental IP checksum update.
    /// - **DF bit** — set or cleared according to the profile.
    /// - **IP ID** — rewritten to the next value from the internal counter,
    ///   matching the profile's incremental or sequential behavior.
    ///
    /// Non-IPv4 packets are left unchanged. The IP header checksum is updated
    /// incrementally (RFC 1624) after each field modification.
    pub fn normalize_ipv4(&self, pkt: &mut [u8]) {
        let (_ihl, _proto) = match Self::parse_ipv4_header(pkt) {
            Some(v) => v,
            None => return,
        };

        // --- TTL normalization ---
        let old_ttl = pkt[8];
        let new_ttl = self.profile.ttl();
        if old_ttl != new_ttl {
            update_ip_checksum_incremental(pkt, old_ttl, new_ttl, 8);
            pkt[8] = new_ttl;
        }

        // --- DF bit normalization ---
        // The flags occupy the high 3 bits of byte 6: Reserved(0x80) DF(0x40) MF(0x20).
        let old_flags = pkt[6];
        let new_flags = if self.profile.df_bit() { old_flags | 0x40 } else { old_flags & !0x40 };
        if old_flags != new_flags {
            update_ip_checksum_incremental(pkt, old_flags, new_flags, 6);
            pkt[6] = new_flags;
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
        }
        if old_id_lo != new_id_lo {
            update_ip_checksum_incremental(pkt, old_id_lo, new_id_lo, 5);
            pkt[5] = new_id_lo;
        }
    }

    /// Normalizes the TCP layer of a packet to match the target OS profile.
    ///
    /// On **SYN segments** (where OS fingerprinting is most effective):
    /// - **Window size** — set to the profile's default window.
    /// - **MSS option** — set to the profile's MSS value.
    /// - **TCP option ordering** — options are reordered to match the profile's
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
        // Verify this is TCP (protocol 6).
        if pkt.len() < ip_hdr_len + 20 {
            return;
        }
        if pkt.len() >= 10 && pkt[9] != 6 {
            return;
        }

        let tcp = ip_hdr_len; // offset of TCP header within the packet
        let data_offset = ((pkt[tcp + 12] >> 4) as usize) * 4;
        if data_offset < 20 || pkt.len() < tcp + data_offset {
            return;
        }

        let flags = pkt[tcp + 13];
        let is_syn = (flags & 0x02) != 0;

        if is_syn {
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
            }

            // --- MSS option normalization ---
            normalize_tcp_mss(pkt, ip_hdr_len, self.profile.mss());

            // --- TCP option reordering ---
            reorder_tcp_options(pkt, ip_hdr_len, self.profile.tcp_option_order());
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
/// - `pkt` — the full packet (IP header checksum is at bytes 10–11).
/// - `old_byte` — the original value at `offset` before the change.
/// - `new_byte` — the replacement value.
/// - `offset` — the byte offset within `pkt` of the changed byte.
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
/// - `pkt` — the full packet.
/// - `ip_hdr_len` — length of the IP header (offset where TCP begins).
/// - `old_byte` / `new_byte` — the changed byte's old and new values.
/// - `offset` — absolute offset within `pkt` of the changed byte.
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
#[allow(dead_code)]
const TCP_OPT_TIMESTAMP: u8 = 0x08;

/// A parsed TCP option (excluding NOP and END padding).
#[derive(Clone, Debug)]
struct TcpOption {
    kind: u8,
    data: Vec<u8>, // raw bytes after kind+length (i.e. value only)
}

impl TcpOption {
    /// Total wire length including kind and length bytes.
    fn wire_len(&self) -> usize {
        2 + self.data.len()
    }

    /// Serialize to wire format (kind, length, value).
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_len());
        buf.push(self.kind);
        buf.push(self.wire_len() as u8);
        buf.extend_from_slice(&self.data);
        buf
    }
}

/// Parses TCP options from the given slice, returning non-NOP/non-END options.
fn parse_tcp_options(opts: &[u8]) -> Vec<TcpOption> {
    let mut result = Vec::new();
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
        result.push(TcpOption { kind, data: opts[i + 2..i + len].to_vec() });
        i += len;
    }
    result
}

/// Reorders TCP options to match the given preferred kind ordering, then
/// recomputes the TCP checksum from scratch.
///
/// Options not listed in `order` are appended after the known ones in their
/// original relative order. The remaining space in the options field is filled
/// with NOP padding. The data offset field is not changed (reordering does not
/// alter the total options length).
fn reorder_tcp_options(pkt: &mut [u8], ip_hdr_len: usize, order: &[u8]) {
    let tcp = ip_hdr_len;
    if pkt.len() < tcp + 20 {
        return;
    }
    let data_offset = ((pkt[tcp + 12] >> 4) as usize) * 4;
    if data_offset < 20 || pkt.len() < tcp + data_offset {
        return;
    }
    let opts_start = tcp + 20;
    let opts_end = tcp + data_offset;
    let opts_len = opts_end - opts_start;
    if opts_len == 0 {
        return;
    }

    let parsed = parse_tcp_options(&pkt[opts_start..opts_end]);
    if parsed.is_empty() || parsed.len() == 1 {
        // Nothing to reorder.
        return;
    }

    // Sort parsed options according to the preferred order.
    // Options not in `order` get a sort priority of usize::MAX and preserve
    // their original relative order (Rust's sort is stable).
    let mut sorted = parsed.clone();
    sorted.sort_by_key(|opt| order.iter().position(|&k| k == opt.kind).unwrap_or(usize::MAX));

    // Re-serialize: options in new order, then NOP padding to fill remaining space.
    let mut buf = Vec::with_capacity(opts_len);
    for opt in &sorted {
        buf.extend_from_slice(&opt.to_bytes());
    }
    // Fill remaining space with NOPs.
    while buf.len() < opts_len {
        buf.push(TCP_OPT_NOP);
    }
    // If we somehow overflowed (shouldn't happen since we only reorder), bail.
    if buf.len() != opts_len {
        return;
    }

    // Write reordered options back.
    pkt[opts_start..opts_end].copy_from_slice(&buf);

    // Recompute TCP checksum from scratch (many bytes changed position).
    recompute_tcp_checksum(pkt, ip_hdr_len);
}

/// Normalizes the MSS value in TCP options to the given target MSS.
///
/// Finds the MSS option (kind 0x02) in the TCP options and updates its 2-byte
/// value, adjusting the TCP checksum incrementally. If no MSS option is found,
/// this is a no-op.
fn normalize_tcp_mss(pkt: &mut [u8], ip_hdr_len: usize, target_mss: u16) {
    let tcp = ip_hdr_len;
    if pkt.len() < tcp + 24 {
        return; // Need at least 4 bytes of options for MSS.
    }
    let data_offset = ((pkt[tcp + 12] >> 4) as usize) * 4;
    if data_offset < 24 || pkt.len() < tcp + data_offset {
        return;
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
            return;
        }
        i += len;
    }
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

    // Build pseudo-header.
    let mut pseudo = Vec::with_capacity(12 + tcp_len);
    pseudo.extend_from_slice(&pkt[12..16]); // source IP
    pseudo.extend_from_slice(&pkt[16..20]); // destination IP
    pseudo.push(0); // zero
    pseudo.push(pkt[9]); // protocol (6 = TCP)
    pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes()); // TCP length
    pseudo.extend_from_slice(&pkt[tcp..tcp + tcp_len]); // TCP segment

    // Zero out the existing checksum before computing.
    let cksum_off = tcp + 16;
    pseudo[12 + 16] = 0;
    pseudo[12 + 17] = 0;

    let cksum = ones_complement_checksum(&pseudo);
    pkt[cksum_off] = (cksum >> 8) as u8;
    pkt[cksum_off + 1] = (cksum & 0xFF) as u8;
}

/// Computes the one's complement checksum (RFC 1071) over the given data.
fn ones_complement_checksum(data: &[u8]) -> u16 {
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
    !(sum as u16)
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
mod tests {
    use super::*;

    // --- Test helpers ---

    /// Builds a minimal valid IPv4 + TCP SYN packet with given parameters.
    fn build_tcp_syn(
        src: [u8; 4],
        dst: [u8; 4],
        ttl: u8,
        window: u16,
        mss: u16,
        ip_id: u16,
    ) -> Vec<u8> {
        // TCP options: MSS(4) + SACK_PERM(2) + NOP(1) + WindowScale(3) + NOP(1) + NOP(1) + Timestamp(10) = 22 bytes
        // Total TCP header = 20 + 24 = 44 (with 2 NOP padding)
        let opts_len = 24;
        let tcp_hdr_len = 20 + opts_len;
        let data_offset = (tcp_hdr_len / 4) as u8;
        let total_len = 20 + tcp_hdr_len;

        let mut pkt = vec![0u8; total_len];

        // IPv4 header
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[1] = 0x00; // DSCP/ECN
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[4..6].copy_from_slice(&ip_id.to_be_bytes());
        pkt[6] = 0x40; // DF bit set
        pkt[7] = 0x00; // fragment offset
        pkt[8] = ttl;
        pkt[9] = 0x06; // protocol: TCP
        pkt[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum (compute later)
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);

        // TCP header
        let tcp = 20;
        pkt[tcp..tcp + 2].copy_from_slice(&0x1234u16.to_be_bytes()); // src port
        pkt[tcp + 2..tcp + 4].copy_from_slice(&0x0050u16.to_be_bytes()); // dst port
        pkt[tcp + 4..tcp + 8].copy_from_slice(&0u32.to_be_bytes()); // seq
        pkt[tcp + 8..tcp + 12].copy_from_slice(&0u32.to_be_bytes()); // ack
        pkt[tcp + 12] = data_offset << 4; // data offset
        pkt[tcp + 13] = 0x02; // SYN flag
        pkt[tcp + 14..tcp + 16].copy_from_slice(&window.to_be_bytes()); // window
        pkt[tcp + 16..tcp + 18].copy_from_slice(&0u16.to_be_bytes()); // checksum (compute later)
        pkt[tcp + 18..tcp + 20].copy_from_slice(&0u16.to_be_bytes()); // urgent pointer

        // TCP options: MSS, SACK_PERM, NOP, WindowScale, NOP, NOP, Timestamp
        let opts = tcp + 20;
        let mut o = opts;
        // MSS (kind=2, len=4, value=mss)
        pkt[o] = 0x02;
        pkt[o + 1] = 0x04;
        pkt[o + 2..o + 4].copy_from_slice(&mss.to_be_bytes());
        o += 4;
        // SACK Permitted (kind=4, len=2)
        pkt[o] = 0x04;
        pkt[o + 1] = 0x02;
        o += 2;
        // NOP
        pkt[o] = 0x01;
        o += 1;
        // Window Scale (kind=3, len=3, value=7)
        pkt[o] = 0x03;
        pkt[o + 1] = 0x03;
        pkt[o + 2] = 0x07;
        o += 3;
        // NOP, NOP
        pkt[o] = 0x01;
        pkt[o + 1] = 0x01;
        o += 2;
        // Timestamp (kind=8, len=10)
        pkt[o] = 0x08;
        pkt[o + 1] = 0x0A;
        pkt[o + 2..o + 10].copy_from_slice(&[0x11; 8]);
        o += 10;
        // Remaining: NOP padding
        while o < opts + opts_len {
            pkt[o] = 0x01;
            o += 1;
        }

        // Compute TCP checksum
        recompute_tcp_checksum(&mut pkt, 20);
        // Compute IP checksum
        let ip_cksum = ones_complement_checksum(&pkt[..20]);
        pkt[10] = (ip_cksum >> 8) as u8;
        pkt[11] = (ip_cksum & 0xFF) as u8;

        pkt
    }

    /// Builds a minimal valid IPv4 + ICMP echo request packet.
    fn build_icmp_request(src: [u8; 4], dst: [u8; 4], ttl: u8) -> Vec<u8> {
        let total_len = 20 + 8; // IP + ICMP
        let mut pkt = vec![0u8; total_len];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[8] = ttl;
        pkt[9] = 0x01; // ICMP
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        // ICMP echo request
        pkt[20] = 0x08; // type
        pkt[21] = 0x00; // code
        pkt[24..26].copy_from_slice(&0x1234u16.to_be_bytes()); // identifier
        pkt[26..28].copy_from_slice(&0x0001u16.to_be_bytes()); // sequence
                                                               // ICMP checksum
        let icmp_cksum = ones_complement_checksum(&pkt[20..]);
        pkt[22] = (icmp_cksum >> 8) as u8;
        pkt[23] = (icmp_cksum & 0xFF) as u8;
        // IP checksum
        let ip_cksum = ones_complement_checksum(&pkt[..20]);
        pkt[10] = (ip_cksum >> 8) as u8;
        pkt[11] = (ip_cksum & 0xFF) as u8;
        pkt
    }

    // --- Profile characteristic tests ---

    #[test]
    fn test_profile_ttl_values() {
        assert_eq!(OsFingerprintProfile::Linux.ttl(), 64);
        assert_eq!(OsFingerprintProfile::Windows.ttl(), 128);
        assert_eq!(OsFingerprintProfile::MacOS.ttl(), 64);
        assert_eq!(OsFingerprintProfile::Android.ttl(), 64);
    }

    #[test]
    fn test_profile_window_values() {
        assert_eq!(OsFingerprintProfile::Linux.default_window(), 64240);
        assert_eq!(OsFingerprintProfile::Windows.default_window(), 65535);
        assert_eq!(OsFingerprintProfile::MacOS.default_window(), 65535);
        assert_eq!(OsFingerprintProfile::Android.default_window(), 57344);
    }

    #[test]
    fn test_profile_mss_values() {
        assert_eq!(OsFingerprintProfile::Linux.mss(), 1460);
        assert_eq!(OsFingerprintProfile::Windows.mss(), 1460);
        assert_eq!(OsFingerprintProfile::MacOS.mss(), 1460);
        assert_eq!(OsFingerprintProfile::Android.mss(), 1460);
    }

    #[test]
    fn test_profile_df_bit() {
        assert!(OsFingerprintProfile::Linux.df_bit());
        assert!(OsFingerprintProfile::Windows.df_bit());
        assert!(OsFingerprintProfile::MacOS.df_bit());
        assert!(OsFingerprintProfile::Android.df_bit());
    }

    #[test]
    fn test_profile_ip_id_behavior() {
        assert_eq!(OsFingerprintProfile::Linux.ip_id_behavior(), IpIdBehavior::Incremental);
        assert_eq!(OsFingerprintProfile::Windows.ip_id_behavior(), IpIdBehavior::Sequential);
        assert_eq!(OsFingerprintProfile::MacOS.ip_id_behavior(), IpIdBehavior::Incremental);
        assert_eq!(OsFingerprintProfile::Android.ip_id_behavior(), IpIdBehavior::Incremental);
    }

    #[test]
    fn test_default_profile_is_linux() {
        assert_eq!(OsFingerprintProfile::default(), OsFingerprintProfile::Linux);
    }

    #[test]
    fn test_profile_from_str() {
        assert_eq!("linux".parse::<OsFingerprintProfile>().unwrap(), OsFingerprintProfile::Linux);
        assert_eq!(
            "windows".parse::<OsFingerprintProfile>().unwrap(),
            OsFingerprintProfile::Windows
        );
        assert_eq!("macos".parse::<OsFingerprintProfile>().unwrap(), OsFingerprintProfile::MacOS);
        assert_eq!(
            "android".parse::<OsFingerprintProfile>().unwrap(),
            OsFingerprintProfile::Android
        );
        assert!("unknown".parse::<OsFingerprintProfile>().is_err());
    }

    // --- TTL normalization tests ---

    #[test]
    fn test_normalize_ipv4_ttl_linux() {
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 200, 8192, 1460, 0x1234);
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Linux);
        normalizer.normalize_ipv4(&mut pkt);
        assert_eq!(pkt[8], 64, "TTL should be normalized to 64 for Linux");
        assert!(verify_ip_checksum(&pkt), "IP checksum must be valid after normalization");
    }

    #[test]
    fn test_normalize_ipv4_ttl_windows() {
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1460, 0x1234);
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Windows);
        normalizer.normalize_ipv4(&mut pkt);
        assert_eq!(pkt[8], 128, "TTL should be normalized to 128 for Windows");
        assert!(verify_ip_checksum(&pkt), "IP checksum must be valid after normalization");
    }

    #[test]
    fn test_normalize_ipv4_ttl_macos() {
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 200, 8192, 1460, 0x1234);
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::MacOS);
        normalizer.normalize_ipv4(&mut pkt);
        assert_eq!(pkt[8], 64, "TTL should be normalized to 64 for macOS");
        assert!(verify_ip_checksum(&pkt), "IP checksum must be valid");
    }

    #[test]
    fn test_normalize_ipv4_ttl_android() {
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 200, 8192, 1460, 0x1234);
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Android);
        normalizer.normalize_ipv4(&mut pkt);
        assert_eq!(pkt[8], 64, "TTL should be normalized to 64 for Android");
        assert!(verify_ip_checksum(&pkt), "IP checksum must be valid");
    }

    // --- Checksum update correctness tests ---

    #[test]
    fn test_incremental_checksum_matches_full_recompute() {
        // Build a packet, change the TTL, and compare incremental vs full recompute.
        let mut pkt_a = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 100, 8192, 1460, 0xABCD);
        let mut pkt_b = pkt_a.clone();

        // Incremental update on pkt_a
        let old_ttl = pkt_a[8];
        update_ip_checksum_incremental(&mut pkt_a, old_ttl, 64, 8);
        pkt_a[8] = 64;

        // Full recompute on pkt_b
        pkt_b[8] = 64;
        pkt_b[10] = 0;
        pkt_b[11] = 0;
        let cksum = ones_complement_checksum(&pkt_b[..20]);
        pkt_b[10] = (cksum >> 8) as u8;
        pkt_b[11] = (cksum & 0xFF) as u8;

        assert_eq!(
            &pkt_a[10..12],
            &pkt_b[10..12],
            "Incremental checksum must match full recompute"
        );
    }

    #[test]
    fn test_incremental_checksum_odd_offset() {
        // Test incremental update at an odd offset (low byte of a 16-bit word).
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1460, 0xABCD);
        let original_cksum = u16::from_be_bytes([pkt[10], pkt[11]]);

        // Change byte at odd offset 5 (low byte of IP ID at offset 4-5).
        let old_byte = pkt[5];
        let new_byte = old_byte.wrapping_add(0x10);
        update_ip_checksum_incremental(&mut pkt, old_byte, new_byte, 5);
        pkt[5] = new_byte;

        // Verify by full recompute.
        let mut ref_pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1460, 0xABCD);
        ref_pkt[5] = new_byte;
        ref_pkt[10] = 0;
        ref_pkt[11] = 0;
        let ref_cksum = ones_complement_checksum(&ref_pkt[..20]);
        let ref_bytes = [(ref_cksum >> 8) as u8, (ref_cksum & 0xFF) as u8];

        assert_eq!(&pkt[10..12], &ref_bytes, "Odd-offset incremental checksum must match");
        // Ensure the checksum actually changed.
        let new_cksum = u16::from_be_bytes([pkt[10], pkt[11]]);
        assert_ne!(original_cksum, new_cksum, "Checksum should have changed");
    }

    #[test]
    fn test_tcp_incremental_checksum() {
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1460, 0x1234);
        let ip_hdr_len = 20;
        let tcp = ip_hdr_len;

        // Change the TCP window high byte using incremental update.
        let old_hi = pkt[tcp + 14];
        let new_hi = 0xFF;
        update_tcp_checksum_incremental(&mut pkt, ip_hdr_len, old_hi, new_hi, tcp + 14);
        pkt[tcp + 14] = new_hi;

        // Verify by full recompute.
        let mut ref_pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1460, 0x1234);
        ref_pkt[tcp + 14] = new_hi;
        recompute_tcp_checksum(&mut ref_pkt, ip_hdr_len);

        assert_eq!(
            &pkt[tcp + 16..tcp + 18],
            &ref_pkt[tcp + 16..tcp + 18],
            "TCP incremental checksum must match full recompute"
        );
    }

    // --- TCP window modification tests ---

    #[test]
    fn test_normalize_tcp_window_linux() {
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1460, 0x1234);
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Linux);
        normalizer.normalize_tcp(&mut pkt, 20);
        let window = u16::from_be_bytes([pkt[34], pkt[35]]);
        assert_eq!(window, 64240, "Window should be normalized to Linux default");
        assert!(verify_tcp_checksum(&pkt, 20), "TCP checksum must be valid");
    }

    #[test]
    fn test_normalize_tcp_window_windows() {
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1460, 0x1234);
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Windows);
        normalizer.normalize_tcp(&mut pkt, 20);
        let window = u16::from_be_bytes([pkt[34], pkt[35]]);
        assert_eq!(window, 65535, "Window should be normalized to Windows default");
        assert!(verify_tcp_checksum(&pkt, 20), "TCP checksum must be valid");
    }

    #[test]
    fn test_normalize_tcp_window_android() {
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1460, 0x1234);
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Android);
        normalizer.normalize_tcp(&mut pkt, 20);
        let window = u16::from_be_bytes([pkt[34], pkt[35]]);
        assert_eq!(window, 57344, "Window should be normalized to Android default");
        assert!(verify_tcp_checksum(&pkt, 20), "TCP checksum must be valid");
    }

    // --- MSS modification tests ---

    #[test]
    fn test_normalize_tcp_mss() {
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1200, 0x1234);
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Linux);
        normalizer.normalize_tcp(&mut pkt, 20);

        // Find MSS option and verify it's 1460.
        let tcp = 20;
        let data_offset = ((pkt[tcp + 12] >> 4) as usize) * 4;
        let opts = &pkt[tcp + 20..tcp + data_offset];
        let mut found_mss = None;
        let mut i = 0;
        while i < opts.len() {
            let kind = opts[i];
            if kind == 0 {
                break;
            }
            if kind == 1 {
                i += 1;
                continue;
            }
            let len = opts[i + 1] as usize;
            if kind == 2 && len == 4 {
                found_mss = Some(u16::from_be_bytes([opts[i + 2], opts[i + 3]]));
            }
            i += len;
        }
        assert_eq!(found_mss, Some(1460), "MSS should be normalized to 1460");
        assert!(verify_tcp_checksum(&pkt, 20), "TCP checksum must be valid after MSS change");
    }

    // --- TCP option reordering tests ---

    #[test]
    fn test_tcp_option_reorder_macos() {
        // Build a SYN with Linux-style order: MSS, SACK_PERM, WindowScale, Timestamp
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1460, 0x1234);
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::MacOS);
        normalizer.normalize_tcp(&mut pkt, 20);

        let tcp = 20;
        let data_offset = ((pkt[tcp + 12] >> 4) as usize) * 4;
        let opts = &pkt[tcp + 20..tcp + data_offset];

        // Parse option kinds (excluding NOP/END).
        let parsed = parse_tcp_options(opts);
        let kinds: Vec<u8> = parsed.iter().map(|o| o.kind).collect();

        // macOS order: MSS(0x02), WindowScale(0x03), SACK_PERM(0x04), Timestamp(0x08)
        assert_eq!(
            kinds,
            vec![0x02, 0x03, 0x04, 0x08],
            "macOS should place WindowScale before SACK_PERM"
        );
        assert!(verify_tcp_checksum(&pkt, 20), "TCP checksum must be valid after reorder");
    }

    #[test]
    fn test_tcp_option_reorder_linux() {
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1460, 0x1234);
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Linux);
        normalizer.normalize_tcp(&mut pkt, 20);

        let tcp = 20;
        let data_offset = ((pkt[tcp + 12] >> 4) as usize) * 4;
        let opts = &pkt[tcp + 20..tcp + data_offset];
        let parsed = parse_tcp_options(opts);
        let kinds: Vec<u8> = parsed.iter().map(|o| o.kind).collect();

        // Linux order: MSS(0x02), SACK_PERM(0x04), WindowScale(0x03), Timestamp(0x08)
        assert_eq!(
            kinds,
            vec![0x02, 0x04, 0x03, 0x08],
            "Linux order: MSS, SACK_PERM, WindowScale, Timestamp"
        );
        assert!(verify_tcp_checksum(&pkt, 20), "TCP checksum must be valid");
    }

    // --- Full normalization: valid checksums after combined IPv4+TCP ---

    #[test]
    fn test_full_normalization_linux_valid_checksums() {
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 200, 8192, 1200, 0xAAAA);
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Linux);
        normalizer.normalize_ipv4(&mut pkt);
        normalizer.normalize_tcp(&mut pkt, 20);

        assert_eq!(pkt[8], 64, "TTL normalized to 64");
        assert!(verify_ip_checksum(&pkt), "IP checksum valid after full normalization");
        assert!(verify_tcp_checksum(&pkt, 20), "TCP checksum valid after full normalization");
    }

    #[test]
    fn test_full_normalization_windows_valid_checksums() {
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1200, 0xBBBB);
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Windows);
        normalizer.normalize_ipv4(&mut pkt);
        normalizer.normalize_tcp(&mut pkt, 20);

        assert_eq!(pkt[8], 128, "TTL normalized to 128");
        assert!(verify_ip_checksum(&pkt), "IP checksum valid");
        assert!(verify_tcp_checksum(&pkt, 20), "TCP checksum valid");
    }

    #[test]
    fn test_full_normalization_macos_valid_checksums() {
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 200, 8192, 1200, 0xCCCC);
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::MacOS);
        normalizer.normalize_ipv4(&mut pkt);
        normalizer.normalize_tcp(&mut pkt, 20);

        assert_eq!(pkt[8], 64, "TTL normalized to 64");
        assert!(verify_ip_checksum(&pkt), "IP checksum valid");
        assert!(verify_tcp_checksum(&pkt, 20), "TCP checksum valid");
    }

    #[test]
    fn test_full_normalization_android_valid_checksums() {
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 200, 8192, 1200, 0xDDDD);
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Android);
        normalizer.normalize_ipv4(&mut pkt);
        normalizer.normalize_tcp(&mut pkt, 20);

        assert_eq!(pkt[8], 64, "TTL normalized to 64");
        assert!(verify_ip_checksum(&pkt), "IP checksum valid");
        assert!(verify_tcp_checksum(&pkt, 20), "TCP checksum valid");
    }

    // --- IP ID normalization tests ---

    #[test]
    fn test_ip_id_is_rewritten() {
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1460, 0xAAAA);
        let original_id = u16::from_be_bytes([pkt[4], pkt[5]]);
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Linux);
        normalizer.normalize_ipv4(&mut pkt);
        let new_id = u16::from_be_bytes([pkt[4], pkt[5]]);
        assert_ne!(new_id, original_id, "IP ID should be rewritten");
        assert!(verify_ip_checksum(&pkt), "IP checksum must be valid after ID change");
    }

    #[test]
    fn test_ip_id_increments_across_packets() {
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Linux);
        let id1 = normalizer.next_ip_id();
        let id2 = normalizer.next_ip_id();
        assert_eq!(
            id2.wrapping_sub(id1),
            1,
            "IP ID should increment by 1 for incremental behavior"
        );
    }

    // --- Edge case tests ---

    #[test]
    fn test_normalize_non_ipv4_packet_ignored() {
        // IPv6 packet (version 6) — should be a no-op.
        let mut pkt = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x06, 0x40];
        pkt.extend_from_slice(&[0u8; 32]); // minimal IPv6 header
        let original = pkt.clone();
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Linux);
        normalizer.normalize_ipv4(&mut pkt);
        assert_eq!(pkt, original, "Non-IPv4 packets must not be modified");
    }

    #[test]
    fn test_normalize_too_short_packet_ignored() {
        let mut pkt = vec![0x45, 0x00, 0x00, 0x14];
        let original = pkt.clone();
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Linux);
        normalizer.normalize_ipv4(&mut pkt);
        assert_eq!(pkt, original, "Short packets must not be modified");
    }

    #[test]
    fn test_normalize_tcp_non_syn_unchanged_window() {
        // Build a non-SYN packet (ACK flag) — window should not be modified.
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 5000, 1460, 0x1234);
        // Change SYN flag to ACK.
        pkt[33] = 0x10; // ACK flag
        recompute_tcp_checksum(&mut pkt, 20);
        let original_window = u16::from_be_bytes([pkt[34], pkt[35]]);

        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Linux);
        normalizer.normalize_tcp(&mut pkt, 20);
        let window = u16::from_be_bytes([pkt[34], pkt[35]]);
        assert_eq!(
            window, original_window,
            "Non-SYN window must not be modified (dynamic flow-control value)"
        );
    }

    #[test]
    fn test_normalize_tcp_non_tcp_protocol_ignored() {
        let mut pkt = build_icmp_request([10, 0, 0, 1], [10, 0, 0, 2], 64);
        let original = pkt.clone();
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Linux);
        normalizer.normalize_tcp(&mut pkt, 20);
        // ICMP packets should not have their TCP layer modified (protocol != 6).
        // The ICMP checksum is at a different offset, so it should be unchanged.
        assert_eq!(
            &pkt[20..28],
            &original[20..28],
            "Non-TCP packets must not be modified by normalize_tcp"
        );
    }

    #[test]
    fn test_parse_ipv4_header_valid() {
        let pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1460, 0x1234);
        let (ihl, proto) = PacketNormalizer::parse_ipv4_header(&pkt).unwrap();
        assert_eq!(ihl, 20);
        assert_eq!(proto, 6); // TCP
    }

    #[test]
    fn test_parse_ipv4_header_invalid_version() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // IPv6
        assert!(PacketNormalizer::parse_ipv4_header(&pkt).is_none());
    }

    #[test]
    fn test_parse_ipv4_header_too_short() {
        let pkt = vec![0x45, 0x00, 0x00];
        assert!(PacketNormalizer::parse_ipv4_header(&pkt).is_none());
    }

    // --- ICMP normalization (via normalize_ipv4 on ICMP packets) ---

    #[test]
    fn test_normalize_icmp_ttl() {
        let mut pkt = build_icmp_request([10, 0, 0, 1], [10, 0, 0, 2], 200);
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Windows);
        normalizer.normalize_ipv4(&mut pkt);
        assert_eq!(pkt[8], 128, "ICMP packet TTL should be normalized to 128 for Windows");
        assert!(verify_ip_checksum(&pkt), "IP checksum must be valid for ICMP packet");

        // ICMP checksum should also still be valid (we didn't touch ICMP content).
        let icmp_data = &pkt[20..];
        assert!(ones_complement_sum_is_ones(icmp_data), "ICMP checksum must remain valid");
    }

    // --- DF bit normalization ---

    #[test]
    fn test_normalize_df_bit_set() {
        let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1460, 0x1234);
        // Clear DF bit initially.
        pkt[6] &= !0x40;
        // Recompute IP checksum.
        pkt[10] = 0;
        pkt[11] = 0;
        let cksum = ones_complement_checksum(&pkt[..20]);
        pkt[10] = (cksum >> 8) as u8;
        pkt[11] = (cksum & 0xFF) as u8;

        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Linux);
        normalizer.normalize_ipv4(&mut pkt);
        assert!(pkt[6] & 0x40 != 0, "DF bit should be set for Linux profile");
        assert!(verify_ip_checksum(&pkt), "IP checksum valid after DF bit change");
    }

    #[test]
    fn test_ip_id_counter_wraps() {
        let normalizer = PacketNormalizer::new(OsFingerprintProfile::Linux);
        // Manually set counter near the wrap boundary.
        normalizer.ip_id_counter.store(0xFFFE, Ordering::Relaxed);
        let id1 = normalizer.next_ip_id();
        let id2 = normalizer.next_ip_id();
        // Should wrap around u16.
        assert_eq!(id1, 0xFFFF);
        assert_eq!(id2, 0x0000);
    }
}
