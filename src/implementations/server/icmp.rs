//! ICMP packet handling for the VPN server TUN interface.
//!
//! Provides echo reply generation, destination unreachable, packet too big,
//! and time exceeded message construction. All functions operate on raw IP
//! packet bytes and produce ready-to-send IP packets with correct checksums.

/// ICMP message types (RFC 792)
pub mod icmp_type {
    pub const ECHO_REPLY: u8 = 0;
    pub const DESTINATION_UNREACHABLE: u8 = 3;
    pub const ECHO_REQUEST: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
}

/// ICMP destination unreachable codes (RFC 792)
pub mod icmp_code {
    pub const NET_UNREACHABLE: u8 = 0;
    pub const HOST_UNREACHABLE: u8 = 1;
    pub const PROTOCOL_UNREACHABLE: u8 = 2;
    pub const PORT_UNREACHABLE: u8 = 3;
    pub const FRAGMENTATION_NEEDED: u8 = 4;
}

/// Parsed ICMP header from a raw IP packet.
#[derive(Debug, Clone)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence: u16,
}

/// Parse ICMP header from an IPv4 packet.
/// Returns None if the packet is too short or not ICMP (protocol 1).
pub fn parse_icmpv4(ip_header_len: usize, pkt: &[u8]) -> Option<IcmpHeader> {
    if pkt.len() < ip_header_len + 8 {
        return None;
    }
    // Check protocol field in IPv4 header (offset 9)
    if pkt.len() >= 10 && pkt[9] != 1 {
        return None; // Not ICMP
    }
    let icmp = &pkt[ip_header_len..];
    Some(IcmpHeader {
        icmp_type: icmp[0],
        code: icmp[1],
        checksum: u16::from_be_bytes([icmp[2], icmp[3]]),
        identifier: u16::from_be_bytes([icmp[4], icmp[5]]),
        sequence: u16::from_be_bytes([icmp[6], icmp[7]]),
    })
}

/// Build an ICMP Echo Reply from an Echo Request.
/// Swaps src/dst IP, sets ICMP type to 0, recomputes checksums, sets fresh TTL=64.
pub fn build_echo_reply(original_pkt: &[u8]) -> Vec<u8> {
    let mut reply = original_pkt.to_vec();
    if reply.len() < 20 {
        return reply;
    }

    // Swap source and destination IPv4 addresses
    let src: [u8; 4] = reply[12..16].try_into().unwrap_or([0; 4]);
    let dst: [u8; 4] = reply[16..20].try_into().unwrap_or([0; 4]);
    reply[12..16].copy_from_slice(&dst);
    reply[16..20].copy_from_slice(&src);

    let ihl = ((reply[0] & 0x0F) as usize) * 4;
    if reply.len() < ihl + 8 {
        return reply;
    }

    // Set ICMP type to Echo Reply (0)
    reply[ihl] = icmp_type::ECHO_REPLY;
    reply[ihl + 1] = 0; // code 0

    // Recompute ICMP checksum
    reply[ihl + 2] = 0;
    reply[ihl + 3] = 0;
    let checksum = icmp_checksum(&reply[ihl..]);
    reply[ihl + 2] = (checksum >> 8) as u8;
    reply[ihl + 3] = (checksum & 0xFF) as u8;

    // Recompute IP header checksum
    reply[10] = 0;
    reply[11] = 0;
    let ip_cksum = ip_checksum(&reply[..ihl]);
    reply[10] = (ip_cksum >> 8) as u8;
    reply[11] = (ip_cksum & 0xFF) as u8;

    // Set a fresh TTL for the echo reply (this is a new packet originated
    // by the server, not a forwarded packet — TTL should not be decremented
    // from the original request). RFC 1812 §5.3.1: TTL for locally-generated
    // packets should be a configured default (typically 64).
    reply[8] = 64;

    reply
}

/// Build an ICMP Destination Unreachable / Packet Too Big message.
/// The message includes the original IP header + first 8 bytes of payload.
pub fn build_icmp_unreachable(
    original_pkt: &[u8],
    icmp_type_val: u8,
    code: u8,
    next_hop_mtu: Option<u16>,
) -> Vec<u8> {
    if original_pkt.len() < 20 {
        return Vec::new();
    }

    let original_src: [u8; 4] = original_pkt[12..16].try_into().unwrap_or([0; 4]);
    let server_ip: [u8; 4] = original_pkt[16..20].try_into().unwrap_or([0; 4]);

    let original_header_len = ((original_pkt[0] & 0x0F) as usize) * 4;
    let copy_len = (original_header_len + 8).min(original_pkt.len());
    let icmp_payload_len = 8 + copy_len;
    let total_len = 20 + icmp_payload_len;

    let mut pkt = vec![0u8; total_len];
    // IPv4 header
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[1] = 0; // DSCP/ECN
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    pkt[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
    pkt[8] = 64; // TTL
    pkt[9] = 1; // protocol: ICMP
    pkt[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum (compute later)
    pkt[12..16].copy_from_slice(&server_ip); // src = server TUN IP (was dest of original)
    pkt[16..20].copy_from_slice(&original_src); // dst = original sender

    // ICMP header
    pkt[20] = icmp_type_val;
    pkt[21] = code;
    pkt[22..24].copy_from_slice(&0u16.to_be_bytes()); // checksum (compute later)
    if icmp_type_val == icmp_type::DESTINATION_UNREACHABLE && code == icmp_code::FRAGMENTATION_NEEDED {
        // Packet Too Big: next-hop MTU in bytes 24-25, unused in 26-27
        let mtu = next_hop_mtu.unwrap_or(1200);
        pkt[24..26].copy_from_slice(&mtu.to_be_bytes());
        pkt[26..28].copy_from_slice(&0u16.to_be_bytes());
    } else {
        pkt[24..28].copy_from_slice(&0u32.to_be_bytes()); // unused
    }

    // Copy original header + 8 bytes of payload
    pkt[28..28 + copy_len].copy_from_slice(&original_pkt[..copy_len]);

    // Compute ICMP checksum
    let icmp_cksum = icmp_checksum(&pkt[20..]);
    pkt[22] = (icmp_cksum >> 8) as u8;
    pkt[23] = (icmp_cksum & 0xFF) as u8;

    // Compute IP checksum
    let ip_cksum = ip_checksum(&pkt[..20]);
    pkt[10] = (ip_cksum >> 8) as u8;
    pkt[11] = (ip_cksum & 0xFF) as u8;

    pkt
}

/// Compute ICMP checksum (one's complement of one's complement sum).
fn icmp_checksum(data: &[u8]) -> u16 {
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
    !sum as u16
}

/// Compute IPv4 header checksum.
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_echo_request(src: [u8; 4], dst: [u8; 4], ident: u16, seq: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 28]; // 20 IP + 8 ICMP
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[1] = 0;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes()); // total length
        pkt[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
        pkt[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags + frag offset
        pkt[8] = 64; // TTL
        pkt[9] = 1; // protocol: ICMP
        pkt[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        // ICMP header
        pkt[20] = icmp_type::ECHO_REQUEST;
        pkt[21] = 0; // code
        pkt[22..24].copy_from_slice(&0u16.to_be_bytes()); // checksum
        pkt[24..26].copy_from_slice(&ident.to_be_bytes());
        pkt[26..28].copy_from_slice(&seq.to_be_bytes());
        // Compute ICMP checksum
        let cksum = icmp_checksum(&pkt[20..]);
        pkt[22] = (cksum >> 8) as u8;
        pkt[23] = (cksum & 0xFF) as u8;
        // Compute IP checksum
        let ip_cksum = ip_checksum(&pkt[..20]);
        pkt[10] = (ip_cksum >> 8) as u8;
        pkt[11] = (ip_cksum & 0xFF) as u8;
        pkt
    }

    #[test]
    fn test_parse_icmpv4_echo_request() {
        let pkt = make_echo_request([10, 8, 0, 2], [10, 8, 0, 1], 0x1234, 1);
        let icmp = parse_icmpv4(20, &pkt).unwrap();
        assert_eq!(icmp.icmp_type, icmp_type::ECHO_REQUEST);
        assert_eq!(icmp.identifier, 0x1234);
        assert_eq!(icmp.sequence, 1);
    }

    #[test]
    fn test_parse_icmpv4_not_icmp() {
        let mut pkt = make_echo_request([10, 8, 0, 2], [10, 8, 0, 1], 0x1234, 1);
        pkt[9] = 6; // TCP, not ICMP
        assert!(parse_icmpv4(20, &pkt).is_none());
    }

    #[test]
    fn test_parse_icmpv4_too_short() {
        let pkt = vec![0u8; 10];
        assert!(parse_icmpv4(20, &pkt).is_none());
    }

    #[test]
    fn test_build_echo_reply_swaps_src_dst() {
        let src = [10, 8, 0, 2];
        let dst = [10, 8, 0, 1];
        let request = make_echo_request(src, dst, 0xABCD, 42);
        let reply = build_echo_reply(&request);

        // Reply should have src=dst, dst=src
        assert_eq!(&reply[12..16], &dst);
        assert_eq!(&reply[16..20], &src);
        // ICMP type should be Echo Reply (0)
        assert_eq!(reply[20], icmp_type::ECHO_REPLY);
        // Identifier and sequence preserved
        assert_eq!(&reply[24..26], &0xABCDu16.to_be_bytes());
        assert_eq!(&reply[26..28], &42u16.to_be_bytes());
        // TTL set to fresh value 64 (locally-originated reply, not decremented)
        assert_eq!(reply[8], 64);
    }

    #[test]
    fn test_build_echo_reply_checksum_valid() {
        let request = make_echo_request([10, 8, 0, 2], [10, 8, 0, 1], 0x1234, 1);
        let reply = build_echo_reply(&request);
        // Verify ICMP checksum is valid (sum of all 16-bit words = 0xFFFF)
        let icmp_data = &reply[20..];
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < icmp_data.len() {
            sum += u16::from_be_bytes([icmp_data[i], icmp_data[i + 1]]) as u32;
            i += 2;
        }
        if i < icmp_data.len() {
            sum += (icmp_data[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xFFFF, "ICMP checksum invalid");
    }

    #[test]
    fn test_build_icmp_unreachable_basic() {
        let original = make_echo_request([10, 8, 0, 2], [10, 8, 0, 1], 0x1234, 1);
        let unreachable = build_icmp_unreachable(
            &original,
            icmp_type::DESTINATION_UNREACHABLE,
            icmp_code::HOST_UNREACHABLE,
            None,
        );

        assert_eq!(unreachable.len(), 20 + 8 + 28); // IP + ICMP header + original header+8
        assert_eq!(unreachable[0] >> 4, 4); // IPv4
        assert_eq!(unreachable[9], 1); // ICMP
        assert_eq!(unreachable[20], icmp_type::DESTINATION_UNREACHABLE);
        assert_eq!(unreachable[21], icmp_code::HOST_UNREACHABLE);
        // Src = server IP (was dest of original)
        assert_eq!(&unreachable[12..16], &[10, 8, 0, 1]);
        // Dst = original sender
        assert_eq!(&unreachable[16..20], &[10, 8, 0, 2]);
    }

    #[test]
    fn test_build_icmp_packet_too_big_has_mtu() {
        let original = make_echo_request([10, 8, 0, 2], [10, 8, 0, 1], 0x1234, 1);
        let too_big = build_icmp_unreachable(
            &original,
            icmp_type::DESTINATION_UNREACHABLE,
            icmp_code::FRAGMENTATION_NEEDED,
            Some(1200),
        );

        assert_eq!(too_big[20], icmp_type::DESTINATION_UNREACHABLE);
        assert_eq!(too_big[21], icmp_code::FRAGMENTATION_NEEDED);
        let mtu = u16::from_be_bytes([too_big[24], too_big[25]]);
        assert_eq!(mtu, 1200);
    }

    #[test]
    fn test_build_icmp_unreachable_checksum_valid() {
        let original = make_echo_request([10, 8, 0, 2], [10, 8, 0, 1], 0x1234, 1);
        let unreachable = build_icmp_unreachable(
            &original,
            icmp_type::DESTINATION_UNREACHABLE,
            icmp_code::HOST_UNREACHABLE,
            None,
        );

        // Verify ICMP checksum
        let icmp_data = &unreachable[20..];
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < icmp_data.len() {
            sum += u16::from_be_bytes([icmp_data[i], icmp_data[i + 1]]) as u32;
            i += 2;
        }
        if i < icmp_data.len() {
            sum += (icmp_data[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xFFFF, "ICMP checksum invalid");

        // Verify IP header checksum
        let ip_hdr = &unreachable[..20];
        let mut ip_sum: u32 = 0;
        let mut j = 0;
        while j + 1 < ip_hdr.len() {
            ip_sum += u16::from_be_bytes([ip_hdr[j], ip_hdr[j + 1]]) as u32;
            j += 2;
        }
        while ip_sum >> 16 != 0 {
            ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
        }
        assert_eq!(ip_sum as u16, 0xFFFF, "IP checksum invalid");
    }
}
