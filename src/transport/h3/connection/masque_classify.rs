//! Per-packet traffic classification for MASQUE-tunneled payloads (TODO-1011).
//!
//! QUIC DATAGRAM frames are never retransmitted (RFC 9221 sec. 2), so the
//! connection-level FEC layer is the only loss protection a datagram gets.
//! QUIRL-style unequal protection spends repair bandwidth only on payloads
//! that cannot recover themselves: `Bulk` payloads (inner TCP data, large
//! UDP transfers) skip FEC framing entirely and rely on the inner
//! protocol's own end-to-end reliability, while everything ambiguous stays
//! `Protected`.

use crate::transport::DatagramClass;

/// UDP payloads at or below this size are treated as latency-sensitive
/// (DNS answers, QUIC handshakes, WireGuard keepalives, game ticks) and
/// stay FEC-protected; larger UDP payloads are bulk-classified.
const UDP_PROTECTED_MAX_PAYLOAD: usize = 384;

/// TCP segments at or below this payload size carry interactive traffic or
/// pure signaling (SSH keystrokes, ACKs, request headers) and stay
/// protected; larger segments are bulk transfers.
const TCP_PROTECTED_MAX_PAYLOAD: usize = 128;

const IP_PROTO_ICMP: u8 = 1;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

/// Classifies one MASQUE-tunneled payload for FEC gating.
///
/// The payload of a CONNECT-IP association is a full IP packet; anything
/// that cannot be parsed unambiguously - non-IP data (CONNECT-UDP
/// associations), truncated headers, fragments, IPv6 extension headers -
/// stays `Protected` so classification can only ever *remove* redundancy
/// where it is provably redundant.
pub(crate) fn classify_tunneled_payload(payload: &[u8]) -> DatagramClass {
    let Some(&version_byte) = payload.first() else {
        return DatagramClass::Protected;
    };
    match version_byte >> 4 {
        4 => classify_ipv4(payload),
        6 => classify_ipv6(payload),
        _ => DatagramClass::Protected,
    }
}

fn classify_ipv4(packet: &[u8]) -> DatagramClass {
    if packet.len() < 20 {
        return DatagramClass::Protected;
    }
    let ihl = usize::from(packet[0] & 0x0F) * 4;
    if ihl < 20 || packet.len() < ihl {
        return DatagramClass::Protected;
    }
    // Non-first fragments carry no L4 header; the first fragment's MF flag
    // also stays protected so classification never desynchronizes flows.
    let frag = u16::from_be_bytes([packet[6], packet[7]]);
    if frag & 0x3FFF != 0 {
        return DatagramClass::Protected;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let proto = packet[9];
    classify_l4(&packet[ihl..], proto, total_len.saturating_sub(ihl))
}

fn classify_ipv6(packet: &[u8]) -> DatagramClass {
    if packet.len() < 40 {
        return DatagramClass::Protected;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let next = packet[6];
    match next {
        IP_PROTO_TCP | IP_PROTO_UDP => classify_l4(&packet[40..], next, payload_len),
        // ICMPv6 (echo, NDP, PMTU signaling) is latency-critical and tiny;
        // extension headers (hop-by-hop, routing, fragment, ESP, AH,
        // destination options, mobility, HIP, shim6) are not walked, and
        // anything unknown stays protected as well.
        _ => DatagramClass::Protected,
    }
}

fn classify_l4(segment: &[u8], proto: u8, payload_len: usize) -> DatagramClass {
    match proto {
        IP_PROTO_TCP => classify_tcp(segment, payload_len),
        IP_PROTO_UDP => classify_udp(segment, payload_len),
        // ICMP (echo/PMTU signaling) is latency-critical and tiny.
        IP_PROTO_ICMP => DatagramClass::Protected,
        _ => DatagramClass::Protected,
    }
}

fn classify_tcp(segment: &[u8], segment_len: usize) -> DatagramClass {
    if segment.len() < 20 {
        return DatagramClass::Protected;
    }
    // SYN, FIN, RST are signaling, not bulk - loss costs a full inner-RTT
    // the inner stack cannot recover from quickly.
    let flags = segment[13];
    if flags & 0x07 != 0 {
        return DatagramClass::Protected;
    }
    let data_offset = usize::from(segment[12] >> 4) * 4;
    if data_offset < 20 || segment.len() < data_offset {
        return DatagramClass::Protected;
    }
    let tcp_payload = segment_len.saturating_sub(data_offset);
    if tcp_payload <= TCP_PROTECTED_MAX_PAYLOAD {
        return DatagramClass::Protected;
    }
    DatagramClass::Bulk
}

fn classify_udp(segment: &[u8], _segment_len: usize) -> DatagramClass {
    if segment.len() < 8 {
        return DatagramClass::Protected;
    }
    let src_port = u16::from_be_bytes([segment[0], segment[1]]);
    let dst_port = u16::from_be_bytes([segment[2], segment[3]]);
    // DNS is the canonical latency-critical small datagram flow.
    if src_port == 53 || dst_port == 53 {
        return DatagramClass::Protected;
    }
    let udp_len = usize::from(u16::from_be_bytes([segment[4], segment[5]]));
    let udp_payload = udp_len.saturating_sub(8);
    if udp_payload <= UDP_PROTECTED_MAX_PAYLOAD {
        return DatagramClass::Protected;
    }
    DatagramClass::Bulk
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(proto: u8, l4: &[u8], l4_len: usize) -> Vec<u8> {
        let total = 20 + l4_len;
        let mut packet = vec![0u8; 20 + l4.len()];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = proto;
        packet[20..20 + l4.len()].copy_from_slice(l4);
        packet
    }

    fn tcp_segment(flags: u8, payload_len: usize) -> Vec<u8> {
        let mut segment = vec![0u8; 20 + payload_len];
        segment[12] = 0x50;
        segment[13] = flags;
        segment
    }

    fn udp_datagram(src: u16, dst: u16, payload_len: usize) -> Vec<u8> {
        let mut segment = vec![0u8; 8 + payload_len];
        segment[0..2].copy_from_slice(&src.to_be_bytes());
        segment[2..4].copy_from_slice(&dst.to_be_bytes());
        segment[4..6].copy_from_slice(&((8 + payload_len) as u16).to_be_bytes());
        segment
    }

    #[test]
    fn tcp_data_segment_is_bulk() {
        let segment = tcp_segment(0x18, 1200);
        let packet = ipv4_packet(6, &segment, 20 + 1200);
        assert_eq!(classify_tunneled_payload(&packet), DatagramClass::Bulk);
    }

    #[test]
    fn tcp_syn_fin_rst_and_small_payloads_stay_protected() {
        for flags in [0x02, 0x01, 0x04, 0x03] {
            let segment = tcp_segment(flags, 1400);
            let packet = ipv4_packet(6, &segment, 20 + 1400);
            assert_eq!(
                classify_tunneled_payload(&packet),
                DatagramClass::Protected,
                "flags={flags:#x}"
            );
        }
        let segment = tcp_segment(0x10, 64);
        let packet = ipv4_packet(6, &segment, 20 + 64);
        assert_eq!(classify_tunneled_payload(&packet), DatagramClass::Protected);
    }

    #[test]
    fn udp_large_payload_is_bulk_but_dns_and_small_stay_protected() {
        let segment = udp_datagram(51234, 443, 1000);
        let packet = ipv4_packet(17, &segment, 8 + 1000);
        assert_eq!(classify_tunneled_payload(&packet), DatagramClass::Bulk);

        let dns = udp_datagram(53, 51234, 900);
        let packet = ipv4_packet(17, &dns, 8 + 900);
        assert_eq!(classify_tunneled_payload(&packet), DatagramClass::Protected);

        let small = udp_datagram(1234, 443, 200);
        let packet = ipv4_packet(17, &small, 8 + 200);
        assert_eq!(classify_tunneled_payload(&packet), DatagramClass::Protected);
    }

    #[test]
    fn icmp_and_non_ip_stay_protected() {
        let icmp = ipv4_packet(1, &[8, 0, 0, 0, 0, 0, 0, 0], 8);
        assert_eq!(classify_tunneled_payload(&icmp), DatagramClass::Protected);
        assert_eq!(classify_tunneled_payload(&[]), DatagramClass::Protected);
        assert_eq!(classify_tunneled_payload(&[0xFF; 40]), DatagramClass::Protected);
        assert_eq!(classify_tunneled_payload(&[0x45; 4]), DatagramClass::Protected);
    }

    #[test]
    fn ipv4_fragment_stays_protected() {
        let mut packet = ipv4_packet(6, &tcp_segment(0x18, 1200), 1220);
        packet[7] = 0x01; // fragment offset 256, MF clear
        assert_eq!(classify_tunneled_payload(&packet), DatagramClass::Protected);
        packet[6] = 0x20; // MF set
        assert_eq!(classify_tunneled_payload(&packet), DatagramClass::Protected);
    }

    #[test]
    fn ipv6_tcp_bulk_and_extension_header_protected() {
        let segment = tcp_segment(0x18, 1200);
        let mut packet = vec![0u8; 40 + segment.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(segment.len() as u16).to_be_bytes());
        packet[6] = 6;
        packet[40..].copy_from_slice(&segment);
        assert_eq!(classify_tunneled_payload(&packet), DatagramClass::Bulk);

        // next-header 44 (fragment) must not be walked.
        packet[6] = 44;
        assert_eq!(classify_tunneled_payload(&packet), DatagramClass::Protected);
    }
}
