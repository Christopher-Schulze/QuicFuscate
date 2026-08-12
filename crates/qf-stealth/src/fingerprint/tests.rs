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

/// Builds a minimal IPv4 + UDP probe with a valid IP header checksum.
fn build_udp_probe(src: [u8; 4], dst: [u8; 4], ttl: u8, ip_id: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 28];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
    pkt[4..6].copy_from_slice(&ip_id.to_be_bytes());
    pkt[8] = ttl;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..22].copy_from_slice(&40_000u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&33434u16.to_be_bytes());
    pkt[24..26].copy_from_slice(&8u16.to_be_bytes());
    let ip_checksum = ones_complement_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    pkt
}

fn parsed_option_kinds(options: &[u8]) -> Vec<u8> {
    let mut parsed = [TcpOptionRef::default(); MAX_PARSED_TCP_OPTIONS];
    let count = parse_tcp_options(options, &mut parsed);
    parsed[..count].iter().map(|option| option.kind).collect()
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
fn disabled_profile_parses_and_maps_every_stealth_os() {
    assert_eq!("none".parse::<OsFingerprintProfile>().unwrap(), OsFingerprintProfile::Disabled);
    assert_eq!(
        OsFingerprintProfile::from_stealth_os(crate::OsProfile::Windows),
        OsFingerprintProfile::Windows
    );
    assert_eq!(
        OsFingerprintProfile::from_stealth_os(crate::OsProfile::MacOS),
        OsFingerprintProfile::MacOS
    );
    assert_eq!(
        OsFingerprintProfile::from_stealth_os(crate::OsProfile::IOS),
        OsFingerprintProfile::MacOS
    );
    assert_eq!(
        OsFingerprintProfile::from_stealth_os(crate::OsProfile::Linux),
        OsFingerprintProfile::Linux
    );
    assert_eq!(
        OsFingerprintProfile::from_stealth_os(crate::OsProfile::Android),
        OsFingerprintProfile::Android
    );
}

#[test]
fn test_profile_window_values() {
    assert_eq!(OsFingerprintProfile::Linux.default_window(), 29_200);
    assert_eq!(OsFingerprintProfile::Windows.default_window(), 8_192);
    assert_eq!(OsFingerprintProfile::MacOS.default_window(), 65535);
    assert_eq!(OsFingerprintProfile::Android.default_window(), 64_240);
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
    assert_eq!("windows".parse::<OsFingerprintProfile>().unwrap(), OsFingerprintProfile::Windows);
    assert_eq!("macos".parse::<OsFingerprintProfile>().unwrap(), OsFingerprintProfile::MacOS);
    assert_eq!("android".parse::<OsFingerprintProfile>().unwrap(), OsFingerprintProfile::Android);
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

#[test]
fn tunnel_ingress_preserves_expiring_ipv4_packets_before_normalization() {
    let original = build_icmp_request([10, 0, 0, 1], [198, 51, 100, 1], 1);
    let normalizer = PacketNormalizer::new(OsFingerprintProfile::Windows);

    let mut datagram = original.clone();
    assert_eq!(
        normalizer.normalize_tunnel_ingress_vec(&mut datagram),
        NormalizeResult::Passthrough
    );
    assert_eq!(datagram, original);

    let mut storage = [0u8; 64];
    storage[..original.len()].copy_from_slice(&original);
    let outcome = normalizer.normalize_tunnel_ingress_with_capacity(&mut storage, original.len());
    assert_eq!(outcome.result, NormalizeResult::Passthrough);
    assert_eq!(outcome.packet_len, original.len());
    assert_eq!(&storage[..original.len()], original.as_slice());
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

    assert_eq!(&pkt_a[10..12], &pkt_b[10..12], "Incremental checksum must match full recompute");
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
    assert_eq!(window, 29_200, "Window should match the selected Linux p0f signature");
    assert!(verify_tcp_checksum(&pkt, 20), "TCP checksum must be valid");
}

#[test]
fn test_normalize_tcp_window_windows() {
    let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1460, 0x1234);
    let normalizer = PacketNormalizer::new(OsFingerprintProfile::Windows);
    normalizer.normalize_tcp(&mut pkt, 20);
    let window = u16::from_be_bytes([pkt[34], pkt[35]]);
    assert_eq!(window, 8_192, "Window should match the selected Windows p0f signature");
    assert!(verify_tcp_checksum(&pkt, 20), "TCP checksum must be valid");
}

#[test]
fn test_normalize_tcp_window_android() {
    let mut pkt = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 64, 8192, 1460, 0x1234);
    let normalizer = PacketNormalizer::new(OsFingerprintProfile::Android);
    normalizer.normalize_tcp(&mut pkt, 20);
    let window = u16::from_be_bytes([pkt[34], pkt[35]]);
    assert_eq!(window, 64_240, "Window should match the selected Android p0f signature");
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
    let kinds = parsed_option_kinds(opts);

    // macOS order: MSS, WindowScale, Timestamp, SACK permitted.
    assert_eq!(kinds, vec![0x02, 0x03, 0x08, 0x04], "macOS should use the Darwin option ordering");
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
    let kinds = parsed_option_kinds(opts);

    // Linux order: MSS, SACK permitted, Timestamp, Window Scale.
    assert_eq!(
        kinds,
        vec![0x02, 0x04, 0x08, 0x03],
        "Linux order: MSS, SACK permitted, Timestamp, Window Scale"
    );
    assert!(verify_tcp_checksum(&pkt, 20), "TCP checksum must be valid");
}

#[test]
fn canonical_p0f_option_vectors_and_lengths_are_exact() {
    let timestamp = [0x11; 8];
    let cases = [
        (
            OsFingerprintProfile::Linux,
            60usize,
            vec![
                2,
                4,
                0x05,
                0xb4,
                4,
                2,
                8,
                10,
                timestamp[0],
                timestamp[1],
                timestamp[2],
                timestamp[3],
                timestamp[4],
                timestamp[5],
                timestamp[6],
                timestamp[7],
                1,
                3,
                3,
                10,
            ],
        ),
        (
            OsFingerprintProfile::Windows,
            60,
            vec![
                2,
                4,
                0x05,
                0xb4,
                1,
                3,
                3,
                2,
                4,
                2,
                8,
                10,
                timestamp[0],
                timestamp[1],
                timestamp[2],
                timestamp[3],
                timestamp[4],
                timestamp[5],
                timestamp[6],
                timestamp[7],
            ],
        ),
        (
            OsFingerprintProfile::Android,
            60,
            vec![
                2,
                4,
                0x05,
                0xb4,
                4,
                2,
                8,
                10,
                timestamp[0],
                timestamp[1],
                timestamp[2],
                timestamp[3],
                timestamp[4],
                timestamp[5],
                timestamp[6],
                timestamp[7],
                1,
                3,
                3,
                1,
            ],
        ),
    ];
    for (profile, expected_len, expected_options) in cases {
        let mut packet = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 37, 8192, 1200, 0x1234);
        packet.reserve_exact(4);
        let normalizer = PacketNormalizer::new(profile);
        assert_eq!(normalizer.normalize_vec(&mut packet), NormalizeResult::Modified);
        assert_eq!(packet.len(), expected_len);
        assert_eq!(&packet[40..], expected_options);
        assert!(verify_ip_checksum(&packet));
        assert!(verify_tcp_checksum(&packet, 20));
    }

    let mut packet = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 37, 8192, 1200, 0x1234);
    packet.reserve_exact(4);
    PacketNormalizer::new(OsFingerprintProfile::Linux).normalize_vec(&mut packet);
    assert_eq!(packet.len(), 60);
    PacketNormalizer::new(OsFingerprintProfile::MacOS).normalize_vec(&mut packet);
    assert_eq!(packet.len(), 64);
    assert_eq!(
        &packet[40..],
        &[
            2, 4, 0x05, 0xb4, 1, 3, 3, 4, 1, 1, 8, 10, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 4, 2, 0, 0,
        ]
    );
    assert!(verify_ip_checksum(&packet));
    assert!(verify_tcp_checksum(&packet, 20));
}

#[test]
fn macos_canonical_expansion_supports_jumbo_syn_without_allocation() {
    let mut packet = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 37, 8192, 1200, 0x1234);
    PacketNormalizer::new(OsFingerprintProfile::Linux).normalize_vec(&mut packet);
    assert_eq!(packet.len(), 60);
    packet.resize(9_000, 0x5a);
    packet[2..4].copy_from_slice(&(9_000u16).to_be_bytes());
    recompute_ipv4_checksum(&mut packet, 20);
    recompute_tcp_checksum(&mut packet, 20);

    let mut storage = [0u8; 9_004];
    storage[..packet.len()].copy_from_slice(&packet);
    let normalizer = PacketNormalizer::new(OsFingerprintProfile::MacOS);
    assert_eq!(normalizer.required_capacity(&packet), storage.len());

    let outcome = normalizer.normalize_with_capacity(&mut storage, packet.len());

    assert_eq!(outcome.result, NormalizeResult::Modified);
    assert_eq!(outcome.packet_len, storage.len());
    assert_eq!(u16::from_be_bytes([storage[2], storage[3]]), 9_004);
    assert_eq!(storage[32] >> 4, 11);
    assert_eq!(&storage[64..], &packet[60..]);
    assert!(verify_ip_checksum(&storage));
    assert!(verify_tcp_checksum(&storage, 20));
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
    assert_eq!(id2.wrapping_sub(id1), 1, "IP ID should increment by 1 for incremental behavior");
}

// --- Edge case tests ---

#[test]
fn test_normalize_non_ipv4_packet_ignored() {
    // IPv6 packet (version 6) - should be a no-op.
    let mut pkt = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x06, 0x40];
    pkt.extend_from_slice(&[0u8; 32]); // minimal IPv6 header
    let original = pkt.clone();
    let normalizer = PacketNormalizer::new(OsFingerprintProfile::Linux);
    normalizer.normalize_ipv4(&mut pkt);
    assert_eq!(pkt, original, "Non-IPv4 packets must not be modified");
}

#[test]
fn disabled_profile_is_byte_for_byte_passthrough() {
    let mut packet = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 37, 8192, 1200, 0x1234);
    packet.shrink_to_fit();
    let original = packet.clone();
    let original_capacity = packet.capacity();
    let normalizer = PacketNormalizer::new(OsFingerprintProfile::Disabled);
    assert_eq!(normalizer.normalize_vec(&mut packet), NormalizeResult::Passthrough);
    assert_eq!(packet, original);
    assert_eq!(packet.capacity(), original_capacity);
    assert_eq!(normalizer.ip_id_counter.load(Ordering::Relaxed), 0x0001_0000);
}

#[test]
fn complete_normalization_updates_ipv4_and_tcp_once() {
    let mut packet = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 37, 8192, 1200, 0x1234);
    let normalizer = PacketNormalizer::new(OsFingerprintProfile::Windows);
    assert_eq!(normalizer.normalize(&mut packet), NormalizeResult::Modified);
    assert_eq!(packet[8], 128);
    assert_eq!(u16::from_be_bytes([packet[34], packet[35]]), 8_192);
    assert!(verify_ip_checksum(&packet));
    assert!(verify_tcp_checksum(&packet, 20));
    assert_eq!(normalizer.ip_id_counter.load(Ordering::Relaxed), 0x0001_0001);
}

#[test]
fn suppress_policy_drops_unreachable_but_preserves_fragmentation_needed() {
    let mut unreachable = build_icmp_request([10, 0, 0, 1], [10, 0, 0, 2], 200);
    unreachable[20] = 3;
    unreachable[21] = 1;
    unreachable[22..24].fill(0);
    let checksum = ones_complement_checksum(&unreachable[20..]);
    unreachable[22..24].copy_from_slice(&checksum.to_be_bytes());
    let original = unreachable.clone();
    let normalizer = PacketNormalizer::with_icmp_unreachable_policy(
        OsFingerprintProfile::Windows,
        IcmpUnreachablePolicy::SuppressNonPmtud,
    );
    assert_eq!(normalizer.normalize(&mut unreachable), NormalizeResult::Dropped);
    assert_eq!(unreachable, original);

    let mut packet_too_big = original;
    packet_too_big[21] = 4;
    packet_too_big[22..24].fill(0);
    let checksum = ones_complement_checksum(&packet_too_big[20..]);
    packet_too_big[22..24].copy_from_slice(&checksum.to_be_bytes());
    assert_eq!(normalizer.normalize(&mut packet_too_big), NormalizeResult::Modified);
    assert_eq!(packet_too_big[8], 128);
    assert!(verify_ip_checksum(&packet_too_big));
    assert!(ones_complement_sum_is_ones(&packet_too_big[20..]));
}

#[test]
fn fragmented_ipv4_packet_preserves_fragment_identity() {
    let mut packet = build_tcp_syn([10, 0, 0, 1], [10, 0, 0, 2], 37, 8192, 1200, 0x1234);
    packet[6] = 0x20;
    packet[7] = 0x01;
    packet[10..12].fill(0);
    let checksum = ones_complement_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    let original_fragment = packet[4..8].to_vec();
    let normalizer = PacketNormalizer::new(OsFingerprintProfile::Windows);
    assert_eq!(normalizer.normalize(&mut packet), NormalizeResult::Modified);
    assert_eq!(&packet[4..8], original_fragment.as_slice());
    assert_eq!(normalizer.ip_id_counter.load(Ordering::Relaxed), 0x0001_0000);
    assert!(verify_ip_checksum(&packet));
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
    // Build a non-SYN packet (ACK flag) - window should not be modified.
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
fn active_probe_response_classes_preserve_transport_and_normalize_ip_layer() {
    let normalizer = PacketNormalizer::new(OsFingerprintProfile::Windows);

    let mut closed_tcp = build_tcp_syn([10, 0, 0, 2], [10, 0, 0, 1], 37, 5000, 1460, 0x1234);
    closed_tcp[33] = 0x14; // RST + ACK, as returned for a closed TCP port.
    recompute_tcp_checksum(&mut closed_tcp, 20);
    let tcp_transport = closed_tcp[20..].to_vec();
    assert_eq!(normalizer.normalize(&mut closed_tcp), NormalizeResult::Modified);
    assert_eq!(&closed_tcp[20..], tcp_transport.as_slice());
    assert_eq!(closed_tcp[8], 128);
    assert!(verify_ip_checksum(&closed_tcp));
    assert!(verify_tcp_checksum(&closed_tcp, 20));

    let mut udp = build_udp_probe([10, 0, 0, 2], [10, 0, 0, 1], 31, 0x4321);
    let udp_payload = udp[20..].to_vec();
    assert_eq!(normalizer.normalize(&mut udp), NormalizeResult::Modified);
    assert_eq!(&udp[20..], udp_payload.as_slice());
    assert_eq!(udp[8], 128);
    assert!(udp[6] & 0x40 != 0);
    assert!(verify_ip_checksum(&udp));

    let mut icmp = build_icmp_request([10, 0, 0, 2], [10, 0, 0, 1], 29);
    icmp[20] = 3;
    icmp[21] = 3; // ICMP port unreachable, as returned for a closed UDP port.
    icmp[22..24].fill(0);
    let icmp_checksum = ones_complement_checksum(&icmp[20..]);
    icmp[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    let icmp_payload = icmp[20..].to_vec();
    assert_eq!(normalizer.normalize(&mut icmp), NormalizeResult::Modified);
    assert_eq!(&icmp[20..], icmp_payload.as_slice());
    assert_eq!(icmp[8], 128);
    assert!(verify_ip_checksum(&icmp));
    assert!(ones_complement_sum_is_ones(&icmp[20..]));
}

#[test]
fn active_probe_ip_layer_matches_each_enabled_profile() {
    for (profile, expected_ttl) in [
        (OsFingerprintProfile::Linux, 64),
        (OsFingerprintProfile::Windows, 128),
        (OsFingerprintProfile::MacOS, 64),
        (OsFingerprintProfile::Android, 64),
    ] {
        let mut packet = build_udp_probe([10, 0, 0, 2], [10, 0, 0, 1], 17, 0x9999);
        let normalizer = PacketNormalizer::new(profile);
        assert_eq!(normalizer.normalize(&mut packet), NormalizeResult::Modified);
        assert_eq!(packet[8], expected_ttl);
        assert!(packet[6] & 0x40 != 0);
        assert!(verify_ip_checksum(&packet));
    }
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
