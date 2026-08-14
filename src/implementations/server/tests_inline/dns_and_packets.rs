use super::*;

#[test]
fn test_server_config_default() {
    let config = ServerConfig::default();
    assert_eq!(config.max_clients, 100);
    assert_eq!(config.server_ip, Ipv4Addr::new(10, 8, 0, 1));
    // IPv6 defaults
    assert!(config.ipv6_server_ip.is_some());
    assert_eq!(config.ipv6_server_ip.unwrap(), Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0001));
    assert_eq!(config.ipv6_prefix_len, 64);
    assert_eq!(
        config.revocation_retention_secs,
        crate::implementations::server::revocation::DEFAULT_REVOCATION_RETENTION_SECS
    );
    assert!(config.validate_revocation_retention().is_ok());
    let invalid = ServerConfig { revocation_retention_secs: 0, ..config };
    assert!(invalid.validate_revocation_retention().is_err());
}

#[test]
fn test_parse_ipv6_dest_valid() {
    // Construct a minimal IPv6 packet header (40 bytes)
    let mut pkt = [0u8; 40];
    pkt[0] = 0x60; // version 6
                   // Destination at offset 24-39: fd00::1
    pkt[24] = 0xfd;
    pkt[39] = 0x01;
    let dest = parse_ipv6_dest(&pkt).unwrap();
    assert_eq!(dest, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0001));
}

#[test]
fn test_parse_ipv6_dest_too_short() {
    let pkt = vec![0u8; 30];
    assert!(parse_ipv6_dest(&pkt).is_none());
}

#[test]
fn test_parse_ipv6_dest_wrong_version() {
    let mut pkt = [0u8; 40];
    pkt[0] = 0x45; // IPv4
    assert!(parse_ipv6_dest(&pkt).is_none());
}

#[test]
fn test_parse_ip_dest_dispatches_v4_and_v6() {
    // IPv4 packet
    let mut pkt4 = [0u8; 20];
    pkt4[0] = 0x45;
    pkt4[16] = 10;
    pkt4[17] = 8;
    pkt4[18] = 0;
    pkt4[19] = 2;
    match parse_ip_dest(&pkt4) {
        Some(std::net::IpAddr::V4(v4)) => assert_eq!(v4, Ipv4Addr::new(10, 8, 0, 2)),
        other => panic!("expected V4, got {:?}", other),
    }

    // IPv6 packet
    let mut pkt6 = [0u8; 40];
    pkt6[0] = 0x60;
    pkt6[24] = 0xfd;
    pkt6[39] = 0x01;
    match parse_ip_dest(&pkt6) {
        Some(std::net::IpAddr::V6(v6)) => {
            assert_eq!(v6, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0001))
        }
        other => panic!("expected V6, got {:?}", other),
    }
}

fn test_dns_query_payload() -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&0x1234u16.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00]);
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    for label in ["example", "com"] {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt
}

pub(super) fn test_ipv4_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    let ip_checksum = ones_complement_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    let udp_checksum = ipv4_udp_checksum(src_ip, dst_ip, &pkt[20..]);
    pkt[26..28].copy_from_slice(&udp_checksum.to_be_bytes());
    pkt
}

fn test_ipv6_udp_packet(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut pkt = vec![0u8; 40 + udp_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[6] = 17;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_ip.octets());
    pkt[24..40].copy_from_slice(&dst_ip.octets());
    pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
    pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
    pkt[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[48..].copy_from_slice(payload);
    let udp_checksum = ipv6_udp_checksum(src_ip, dst_ip, &pkt[40..]);
    pkt[46..48].copy_from_slice(&udp_checksum.to_be_bytes());
    pkt
}

fn refresh_ipv4_header_checksum(pkt: &mut [u8]) {
    pkt[10..12].fill(0);
    let checksum = ones_complement_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&checksum.to_be_bytes());
}

#[test]
fn test_parse_ipv4_udp_dns_query_detects_port_53_payload() {
    let payload = test_dns_query_payload();
    let pkt = test_ipv4_udp_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(1, 1, 1, 1),
        53000,
        53,
        &payload,
    );
    let query = parse_ipv4_udp_dns_query(&pkt).expect("DNS query must parse");
    assert_eq!(query.src_ip, Ipv4Addr::new(10, 8, 0, 2));
    assert_eq!(query.dst_ip, Ipv4Addr::new(1, 1, 1, 1));
    assert_eq!(query.src_port, 53000);
    assert_eq!(query.dst_port, 53);
    assert_eq!(query.payload, payload.as_slice());
}

#[test]
fn test_parse_ipv6_udp_dns_query_detects_port_53_payload() {
    let payload = test_dns_query_payload();
    let src_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let dst_ip = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
    let pkt = test_ipv6_udp_packet(src_ip, dst_ip, 53000, 53, &payload);
    let query = parse_ipv6_udp_dns_query(&pkt).expect("IPv6 DNS query must parse");
    assert_eq!(query.src_ip, src_ip);
    assert_eq!(query.dst_ip, dst_ip);
    assert_eq!(query.src_port, 53000);
    assert_eq!(query.dst_port, 53);
    assert_eq!(query.payload, payload.as_slice());
}

#[test]
fn test_parse_ipv4_udp_dns_query_rejects_fragment_length_trailing_and_checksum_errors() {
    let payload = test_dns_query_payload();
    let base = test_ipv4_udp_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(1, 1, 1, 1),
        53000,
        53,
        &payload,
    );

    let mut fragmented = base.clone();
    fragmented[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
    refresh_ipv4_header_checksum(&mut fragmented);
    assert!(parse_ipv4_udp_dns_query(&fragmented).is_none());

    let mut offset_fragment = base.clone();
    offset_fragment[6..8].copy_from_slice(&1u16.to_be_bytes());
    refresh_ipv4_header_checksum(&mut offset_fragment);
    assert!(parse_ipv4_udp_dns_query(&offset_fragment).is_none());

    let mut bad_ip_checksum = base.clone();
    bad_ip_checksum[10] ^= 0x01;
    assert!(parse_ipv4_udp_dns_query(&bad_ip_checksum).is_none());

    let mut bad_udp_checksum = base.clone();
    bad_udp_checksum[26] ^= 0x01;
    assert!(parse_ipv4_udp_dns_query(&bad_udp_checksum).is_none());

    let mut bad_udp_length = base.clone();
    bad_udp_length[24..26].copy_from_slice(&((8 + payload.len() - 1) as u16).to_be_bytes());
    assert!(parse_ipv4_udp_dns_query(&bad_udp_length).is_none());

    let mut bad_total_length = base.clone();
    bad_total_length[2..4].copy_from_slice(&((base.len() - 1) as u16).to_be_bytes());
    assert!(parse_ipv4_udp_dns_query(&bad_total_length).is_none());

    let mut trailing = base.clone();
    trailing.push(0);
    assert!(parse_ipv4_udp_dns_query(&trailing).is_none());

    let mut omitted_udp_checksum = base;
    omitted_udp_checksum[26..28].fill(0);
    assert!(parse_ipv4_udp_dns_query(&omitted_udp_checksum).is_some());
}

#[test]
fn test_parse_ipv6_udp_dns_query_rejects_length_and_checksum_errors() {
    let payload = test_dns_query_payload();
    let src_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let dst_ip = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
    let base = test_ipv6_udp_packet(src_ip, dst_ip, 53000, 53, &payload);

    let mut bad_checksum = base.clone();
    bad_checksum[46] ^= 0x01;
    assert!(parse_ipv6_udp_dns_query(&bad_checksum).is_none());

    let mut zero_checksum = base.clone();
    zero_checksum[46..48].fill(0);
    assert!(parse_ipv6_udp_dns_query(&zero_checksum).is_none());

    let mut bad_udp_length = base.clone();
    bad_udp_length[44..46].copy_from_slice(&((8 + payload.len() - 1) as u16).to_be_bytes());
    assert!(parse_ipv6_udp_dns_query(&bad_udp_length).is_none());

    let mut trailing = base.clone();
    trailing.push(0);
    assert!(parse_ipv6_udp_dns_query(&trailing).is_none());
}

#[test]
fn test_build_ipv4_udp_dns_response_packet_swaps_tuple() {
    let payload = test_dns_query_payload();
    let pkt = test_ipv4_udp_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(1, 1, 1, 1),
        53000,
        53,
        &payload,
    );
    let query = parse_ipv4_udp_dns_query(&pkt).expect("DNS query must parse");
    let parsed = crate::dns::parse_dns_query(query.payload).expect("DNS payload must parse");
    let dns_response = crate::dns::build_dns_nxdomain(&parsed);
    let response =
        build_ipv4_udp_dns_response_packet(&query, &dns_response, OsFingerprintProfile::Linux)
            .expect("DNS response packet must build");
    assert_eq!(parse_ipv4_dest(&response), Some(Ipv4Addr::new(10, 8, 0, 2)));
    assert_eq!(
        Ipv4Addr::new(response[12], response[13], response[14], response[15]),
        Ipv4Addr::new(1, 1, 1, 1)
    );
    assert_eq!(u16::from_be_bytes([response[20], response[21]]), 53);
    assert_eq!(u16::from_be_bytes([response[22], response[23]]), 53000);
    assert_eq!(ones_complement_checksum_raw(&response[..20]), 0);
    assert!(ipv4_udp_checksum_is_valid(
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(10, 8, 0, 2),
        &response[20..]
    ));
    assert_eq!(&response[28..], dns_response.as_slice());
}

#[test]
fn test_build_ipv6_udp_dns_response_packet_swaps_tuple() {
    let payload = test_dns_query_payload();
    let src_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let dst_ip = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
    let pkt = test_ipv6_udp_packet(src_ip, dst_ip, 53000, 53, &payload);
    let query = parse_ipv6_udp_dns_query(&pkt).expect("IPv6 DNS query must parse");
    let parsed = crate::dns::parse_dns_query(query.payload).expect("DNS payload must parse");
    let dns_response = crate::dns::build_dns_nxdomain(&parsed);
    let response =
        build_ipv6_udp_dns_response_packet(&query, &dns_response, OsFingerprintProfile::Linux)
            .expect("IPv6 DNS response packet must build");
    assert_eq!(parse_ipv6_dest(&response), Some(src_ip));
    assert_eq!(Ipv6Addr::from(<[u8; 16]>::try_from(&response[8..24]).unwrap()), dst_ip);
    assert_eq!(u16::from_be_bytes([response[40], response[41]]), 53);
    assert_eq!(u16::from_be_bytes([response[42], response[43]]), 53000);
    assert!(ipv6_udp_checksum_is_valid(dst_ip, src_ip, &response[40..]));
    assert_eq!(&response[48..], dns_response.as_slice());
}

#[test]
fn test_server_dns_upstream_failure_returns_servfail() {
    let payload = test_dns_query_payload();
    let response = resolve_dns_query_via_upstream(&payload, &[]);
    assert!(!response.is_empty(), "server failure must remain a DNS response");
    assert_eq!(response[3] & 0x0f, 2, "upstream failure must be SERVFAIL");
    let parsed = crate::dns::parse_dns_query(&payload).expect("query must parse");
    let mut pos = 12;
    loop {
        let label_len = response[pos] as usize;
        pos += 1;
        if label_len == 0 {
            break;
        }
        pos += label_len;
    }
    assert_eq!(u16::from_be_bytes([response[pos], response[pos + 1]]), parsed.raw_qtype);
}

#[test]
fn test_server_dns_genuine_nxdomain_passes_through_unchanged() {
    let payload = test_dns_query_payload();
    let parsed = crate::dns::parse_dns_query(&payload).expect("query must parse");
    let genuine_nxdomain = crate::dns::build_dns_nxdomain(&parsed);
    let response = response_from_dns_upstream_result(&payload, Ok(genuine_nxdomain.clone()));

    assert_eq!(response, genuine_nxdomain);
    assert_eq!(response[3] & 0x0f, 3, "genuine upstream NXDOMAIN must remain NXDOMAIN");
}

#[test]
fn test_parse_ipv4_dest_valid() {
    // Construct a minimal IPv4 packet with dest 10.8.0.2
    let mut pkt = [0u8; 20];
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[16] = 10;
    pkt[17] = 8;
    pkt[18] = 0;
    pkt[19] = 2;
    let dest = parse_ipv4_dest(&pkt).unwrap();
    assert_eq!(dest, Ipv4Addr::new(10, 8, 0, 2));
}

#[test]
fn test_parse_ipv4_dest_too_short() {
    let pkt = [0u8; 10];
    assert!(parse_ipv4_dest(&pkt).is_none());
}

#[test]
fn test_parse_ipv4_dest_not_ipv4() {
    // IPv6 packet (version 6)
    let mut pkt = [0u8; 40];
    pkt[0] = 0x60; // version 6
    assert!(parse_ipv4_dest(&pkt).is_none());
}

#[test]
fn test_parse_ipv4_dest_with_options() {
    // IPv4 packet with IHL=6 (24 bytes header)
    let mut pkt = [0u8; 24];
    pkt[0] = 0x46; // version 4, IHL 6
    pkt[16] = 192;
    pkt[17] = 168;
    pkt[18] = 1;
    pkt[19] = 100;
    let dest = parse_ipv4_dest(&pkt).unwrap();
    assert_eq!(dest, Ipv4Addr::new(192, 168, 1, 100));
}

#[test]
fn test_parse_ipv4_dest_invalid_ihl() {
    let mut pkt = [0u8; 20];
    pkt[0] = 0x40; // IHL=0, invalid
    assert!(parse_ipv4_dest(&pkt).is_none());
}
