use super::*;

#[test]
fn packet_number_encoding_is_big_endian_for_all_lengths() {
    let pn = 0x01_02_03_04u64;
    for (len, expected) in [
        (1usize, [0x04u8, 0, 0, 0]),
        (2, [0x03, 0x04, 0, 0]),
        (3, [0x02, 0x03, 0x04, 0]),
        (4, [0x01, 0x02, 0x03, 0x04]),
    ] {
        let mut encoded = [0u8; 4];
        assert_eq!(encode_pkt_num(pn, len, &mut encoded[..len]), Ok(len));
        assert_eq!(&encoded[..len], &expected[..len]);
    }
}

#[test]
fn private_packet_boundary_selection_is_deterministic_and_fail_closed() {
    assert_eq!(
        select_private_packet_protection(9, Some(10), true),
        PrivatePacketProtectionSelection::Standard
    );
    assert_eq!(
        select_private_packet_protection(10, Some(10), true),
        PrivatePacketProtectionSelection::Advanced
    );
    assert_eq!(
        select_private_packet_protection(10, Some(10), false),
        PrivatePacketProtectionSelection::Standard
    );
    assert_eq!(
        select_private_packet_protection(u64::MAX, None, true),
        PrivatePacketProtectionSelection::Standard
    );
    assert_eq!(
        select_private_packet_protection(10, Some(0), true),
        PrivatePacketProtectionSelection::Standard
    );
}

#[test]
fn authenticated_private_owner_installs_exact_material_and_preserves_standard_hp() {
    let mut crypto = CryptoContext::default();
    let standard_secret = [0x42u8; 32];
    crate::crypto::aead::KeyScheduleHooks::set_read_secret(
        &mut crypto,
        crate::crypto::aead::Level::OneRTT,
        crate::crypto::aead::Algorithm::AES128_GCM,
        &standard_secret,
    )
    .expect("standard read secret");
    crate::crypto::aead::KeyScheduleHooks::set_write_secret(
        &mut crypto,
        crate::crypto::aead::Level::OneRTT,
        crate::crypto::aead::Algorithm::AES128_GCM,
        &standard_secret,
    )
    .expect("standard write secret");

    crypto
        .install_authenticated_private_1rtt(
            qf_crypto::PrivateAeadFamily::Aegis128L,
            &[0x11; qf_crypto::PrivateAeadFamily::KEY_LEN],
            &[0x22; qf_crypto::PrivateAeadFamily::IV_LEN],
            &[0x33; qf_crypto::PrivateAeadFamily::KEY_LEN],
            &[0x44; qf_crypto::PrivateAeadFamily::IV_LEN],
            10,
            20,
        )
        .expect("authenticated private owner");

    let snapshot = crypto.packet_protection_snapshot();
    assert_eq!(
        snapshot.one_rtt.packet_aead_owner,
        crate::qftls::PacketProtectionOwner::PrivateAdvanced
    );
    assert_eq!(
        snapshot.one_rtt.header_protection_owner,
        crate::qftls::PacketProtectionOwner::TransportStandard
    );
    assert_eq!(crypto.private_write_boundary_1rtt, Some(10));
    assert_eq!(crypto.private_read_boundary_1rtt, Some(20));
    assert!(matches!(crypto.key_update_1rtt_write(), Err(ConnectionError::KeyUpdateError)));
    assert!(matches!(
        crypto.install_authenticated_private_1rtt(
            qf_crypto::PrivateAeadFamily::Aegis128L,
            &[0x11; qf_crypto::PrivateAeadFamily::KEY_LEN],
            &[0x22; qf_crypto::PrivateAeadFamily::IV_LEN],
            &[0x33; qf_crypto::PrivateAeadFamily::KEY_LEN],
            &[0x44; qf_crypto::PrivateAeadFamily::IV_LEN],
            11,
            21,
        ),
        Err(ConnectionError::InvalidState)
    ));
}

fn private_packet_for_test(
    crypto: &CryptoContext,
    packet_number: u64,
    plaintext: &[u8],
) -> Vec<u8> {
    private_packet_for_test_with_phase(crypto, packet_number, false, plaintext)
}

fn private_packet_for_test_with_phase(
    crypto: &CryptoContext,
    packet_number: u64,
    key_phase: bool,
    plaintext: &[u8],
) -> Vec<u8> {
    let header = Header {
        ty: PacketType::Short,
        version: 0,
        dcid: Vec::new(),
        scid: Vec::new(),
        pkt_num: 0,
        pkt_num_len: 0,
        token: None,
        versions: None,
        key_phase,
    };
    let pn_len = 2usize;
    let mut packet = vec![0u8; 96];
    let header_len = format_header(&header, &mut packet).expect("format");
    packet[header_len] = (packet_number >> 8) as u8;
    packet[header_len + 1] = packet_number as u8;
    let aad_len = header_len + pn_len;
    packet[aad_len..aad_len + plaintext.len()].copy_from_slice(plaintext);
    let total = aad_len + plaintext.len() + qf_crypto::PrivateAeadFamily::TAG_LEN;
    let used = encrypt_and_protect(
        crypto,
        &mut packet[..total],
        aad_len,
        packet_number,
        pn_len,
        PacketType::Short,
    )
    .expect("private packet seal");
    packet.truncate(used);
    packet
}

#[test]
fn authenticated_private_owner_selects_standard_then_private_by_packet_boundary() {
    let mut sender = CryptoContext::default();
    let mut receiver = CryptoContext::default();
    let standard_secret = [0x51u8; 32];
    for crypto in [&mut sender, &mut receiver] {
        crate::crypto::aead::KeyScheduleHooks::set_read_secret(
            crypto,
            crate::crypto::aead::Level::OneRTT,
            crate::crypto::aead::Algorithm::AES128_GCM,
            &standard_secret,
        )
        .expect("standard read secret");
        crate::crypto::aead::KeyScheduleHooks::set_write_secret(
            crypto,
            crate::crypto::aead::Level::OneRTT,
            crate::crypto::aead::Algorithm::AES128_GCM,
            &standard_secret,
        )
        .expect("standard write secret");
        crypto
            .install_authenticated_private_1rtt(
                qf_crypto::PrivateAeadFamily::Morus1280_128,
                &[0x61; qf_crypto::PrivateAeadFamily::KEY_LEN],
                &[0x62; qf_crypto::PrivateAeadFamily::IV_LEN],
                &[0x61; qf_crypto::PrivateAeadFamily::KEY_LEN],
                &[0x62; qf_crypto::PrivateAeadFamily::IV_LEN],
                10,
                10,
            )
            .expect("private owner");
    }

    for (packet_number, plaintext) in
        [(9u64, b"standard-owner".as_slice()), (10u64, b"private-owner".as_slice())]
    {
        let mut packet = private_packet_for_test(&sender, packet_number, plaintext);
        let (_header, aad_len, plaintext_len) =
            unprotect_and_decrypt(&receiver, &mut packet, 0, 0).expect("private packet open");
        assert_eq!(&packet[aad_len..aad_len + plaintext_len], plaintext);
    }
}

#[test]
fn private_epoch_update_requires_staged_authenticated_schedule() {
    let mut crypto = CryptoContext::default();
    let standard_secret = [0x71u8; 32];
    crate::crypto::aead::KeyScheduleHooks::set_read_secret(
        &mut crypto,
        crate::crypto::aead::Level::OneRTT,
        crate::crypto::aead::Algorithm::AES128_GCM,
        &standard_secret,
    )
    .expect("standard read secret");
    crate::crypto::aead::KeyScheduleHooks::set_write_secret(
        &mut crypto,
        crate::crypto::aead::Level::OneRTT,
        crate::crypto::aead::Algorithm::AES128_GCM,
        &standard_secret,
    )
    .expect("standard write secret");
    crypto
        .install_authenticated_private_1rtt(
            qf_crypto::PrivateAeadFamily::Aegis128L,
            &[0x81; qf_crypto::PrivateAeadFamily::KEY_LEN],
            &[0x82; qf_crypto::PrivateAeadFamily::IV_LEN],
            &[0x83; qf_crypto::PrivateAeadFamily::KEY_LEN],
            &[0x84; qf_crypto::PrivateAeadFamily::IV_LEN],
            10,
            10,
        )
        .expect("private owner");
    assert_eq!(crypto.stage_private_read_update(), Err(ConnectionError::KeyUpdateError));
}

fn activated_private_machine(
    role: crate::qftls::PrivateNegotiationRole,
) -> crate::qftls::PrivateNegotiationMachine {
    let mut machine = crate::qftls::PrivateNegotiationMachine::new(
        qf_crypto::PacketProtectionMode::Auto,
        role,
        Some(qf_crypto::PrivateAeadFamily::Aegis128L),
        9,
        crate::transport::PROTOCOL_VERSION,
        b"h3".to_vec(),
        vec![1, 2, 3],
        vec![4, 5, 6],
        [0x91; crate::qftls::PRIVATE_HASH_LEN],
        if role == crate::qftls::PrivateNegotiationRole::Client {
            [0x11; crate::qftls::PRIVATE_NONCE_LEN]
        } else {
            [0x22; crate::qftls::PRIVATE_NONCE_LEN]
        },
    )
    .expect("private machine");
    machine.install_exporter_root(&[0x72; crate::qftls::PRIVATE_HASH_LEN]).expect("exporter root");
    machine.mark_authenticated().expect("authenticated machine");
    machine
}

#[test]
fn private_epoch_update_roundtrips_after_authenticated_phase_transition() {
    let mut client = activated_private_machine(crate::qftls::PrivateNegotiationRole::Client);
    let mut server = activated_private_machine(crate::qftls::PrivateNegotiationRole::Server);
    let proposal = client.build_proposal().expect("proposal");
    server.receive_proposal(&proposal).expect("proposal received");
    let selection = server.build_selection().expect("selection");
    client.receive_selection(&selection).expect("selection received");
    let client_confirmation = client.build_confirmation(10).expect("client boundary");
    server.receive_confirmation(&client_confirmation).expect("client confirmation");
    let server_confirmation = server.build_confirmation(10).expect("server boundary");
    client.receive_confirmation(&server_confirmation).expect("server confirmation");
    client.activate().expect("client active");
    server.activate().expect("server active");

    let standard_secret = [0x73u8; 32];
    let mut sender = CryptoContext::default();
    let mut receiver = CryptoContext::default();
    for crypto in [&mut sender, &mut receiver] {
        crate::crypto::aead::KeyScheduleHooks::set_read_secret(
            crypto,
            crate::crypto::aead::Level::OneRTT,
            crate::crypto::aead::Algorithm::AES128_GCM,
            &standard_secret,
        )
        .expect("standard read secret");
        crate::crypto::aead::KeyScheduleHooks::set_write_secret(
            crypto,
            crate::crypto::aead::Level::OneRTT,
            crate::crypto::aead::Algorithm::AES128_GCM,
            &standard_secret,
        )
        .expect("standard write secret");
    }
    let client_schedule = client.epoch_schedule().expect("client schedule");
    let server_schedule = server.epoch_schedule().expect("server schedule");
    let client_write = client
        .derive_material(crate::qftls::PrivateDirection::ClientToServer, 1)
        .expect("client write material");
    let client_read = client
        .derive_material(crate::qftls::PrivateDirection::ServerToClient, 1)
        .expect("client read material");
    let server_write = server
        .derive_material(crate::qftls::PrivateDirection::ServerToClient, 1)
        .expect("server write material");
    let server_read = server
        .derive_material(crate::qftls::PrivateDirection::ClientToServer, 1)
        .expect("server read material");
    sender
        .install_authenticated_private_1rtt_with_schedule(
            qf_crypto::PrivateAeadFamily::Aegis128L,
            client_write.key.as_slice(),
            client_write.iv.as_slice(),
            client_read.key.as_slice(),
            client_read.iv.as_slice(),
            10,
            10,
            Some(client_schedule),
            Some(crate::qftls::PrivateDirection::ClientToServer),
            Some(crate::qftls::PrivateDirection::ServerToClient),
            false,
        )
        .expect("client private owner");
    receiver
        .install_authenticated_private_1rtt_with_schedule(
            qf_crypto::PrivateAeadFamily::Aegis128L,
            server_write.key.as_slice(),
            server_write.iv.as_slice(),
            server_read.key.as_slice(),
            server_read.iv.as_slice(),
            10,
            10,
            Some(server_schedule),
            Some(crate::qftls::PrivateDirection::ServerToClient),
            Some(crate::qftls::PrivateDirection::ClientToServer),
            false,
        )
        .expect("server private owner");

    let first = private_packet_for_test(&sender, 10, b"epoch-one");
    let mut first_incoming = first;
    let (_, first_aad, first_len) =
        unprotect_and_decrypt(&receiver, &mut first_incoming, 0, 0).expect("epoch one open");
    assert_eq!(&first_incoming[first_aad..first_aad + first_len], b"epoch-one");

    assert!(sender.key_update_1rtt_write().expect("write update"));
    receiver.stage_private_read_update().expect("stage read update");
    assert_eq!(receiver.stage_private_read_update(), Err(ConnectionError::KeyUpdateError));
    let second = private_packet_for_test_with_phase(&sender, 11, true, b"epoch-two");
    let mut second_incoming = second;
    let (second_header, second_aad, second_len) =
        unprotect_and_decrypt(&receiver, &mut second_incoming, 0, 0).expect("epoch two open");
    assert!(second_header.key_phase);
    assert_eq!(&second_incoming[second_aad..second_aad + second_len], b"epoch-two");
    assert!(receiver
        .commit_private_read_epoch(second_header.pkt_num, second_header.key_phase)
        .expect("commit epoch two"));
}

#[test]
fn initial_header_token_roundtrip() {
    let header = Header {
        ty: PacketType::Initial,
        version: crate::transport::PROTOCOL_VERSION,
        dcid: vec![0x11, 0x22, 0x33],
        scid: vec![0x44, 0x55],
        pkt_num: 0,
        pkt_num_len: 0,
        token: Some(vec![0x01, 0x02, 0x03, 0x04]),
        versions: None,
        key_phase: false,
    };
    let mut buf = vec![0u8; 64];
    let off = format_header(&header, &mut buf).expect("format header");
    let (parsed, parsed_off) = parse_header(&buf[..off], 0).expect("parse header");
    assert_eq!(parsed.ty, PacketType::Initial);
    assert_eq!(parsed.token, header.token);
    assert_eq!(off, parsed_off);
}

#[test]
fn initial_header_empty_token_roundtrip() {
    let header = Header {
        ty: PacketType::Initial,
        version: crate::transport::PROTOCOL_VERSION,
        dcid: vec![0x01],
        scid: vec![0x02],
        pkt_num: 0,
        pkt_num_len: 0,
        token: None,
        versions: None,
        key_phase: false,
    };
    let mut buf = vec![0u8; 32];
    let off = format_header(&header, &mut buf).expect("format header");
    let (parsed, parsed_off) = parse_header(&buf[..off], 0).expect("parse header");
    assert_eq!(parsed.ty, PacketType::Initial);
    assert!(parsed.token.is_none());
    assert_eq!(off, parsed_off);
}

#[test]
fn packet_boundaries_reject_oversized_cids_before_mutation() {
    let header = Header {
        ty: PacketType::Initial,
        version: crate::transport::PROTOCOL_VERSION,
        dcid: vec![0x11; MAX_CID_LEN + 1],
        scid: vec![0x22],
        pkt_num: 0,
        pkt_num_len: 0,
        token: None,
        versions: None,
        key_phase: false,
    };
    let mut output = [0xA5u8; 64];
    let original = output;
    assert_eq!(format_header(&header, &mut output), Err(ConnectionError::InvalidPacket));
    assert_eq!(output, original);
    assert_eq!(
        format_short_header(&[0x33; MAX_CID_LEN + 1], false, &mut output),
        Err(ConnectionError::InvalidPacket)
    );
    assert_eq!(output, original);
}

#[test]
fn packet_number_encoding_supports_unaligned_output() {
    let mut storage = [0u8; 8];
    assert_eq!(encode_pkt_num(0x01_02_03_04, 4, &mut storage[1..5]), Ok(4));
    assert_eq!(&storage[1..5], &[0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn version_negotiation_sets_recommended_fixed_bit_and_parses() {
    let pkt = generate_version_negotiation_packet(
        &[crate::transport::PROTOCOL_VERSION],
        &[crate::transport::PROTOCOL_VERSION],
        &[0x22], // dcid (echoes client SCID)
        &[0x11], // scid (echoes client DCID)
    )
    .expect("generate VN");
    assert_eq!(pkt[0] & FORM_BIT, FORM_BIT);
    assert_eq!(pkt[0] & FIXED_BIT, FIXED_BIT);
    let (parsed, _) = parse_header(&pkt, 0).expect("parse vn");
    assert_eq!(parsed.ty, PacketType::VersionNegotiation);
}

#[test]
fn version_negotiation_ignores_non_form_bits() {
    let mut pkt = vec![
        FORM_BIT | FIXED_BIT,
        0x00,
        0x00,
        0x00,
        0x00, // version = 0 (VN)
        0x01,
        0x11, // dcid
        0x01,
        0x22, // scid
    ];
    pkt.extend_from_slice(&crate::transport::PROTOCOL_VERSION.to_be_bytes());
    let (parsed, _) = parse_header(&pkt, 0).expect("VN fixed bit is not invariant");
    assert_eq!(parsed.ty, PacketType::VersionNegotiation);
}

// --- QUIC version negotiation ---

#[test]
fn vn_packet_generation_and_parsing_roundtrip() {
    let server_versions =
        vec![crate::transport::PROTOCOL_VERSION_V2, crate::transport::PROTOCOL_VERSION];
    let pkt = generate_version_negotiation_packet(
        &[crate::transport::PROTOCOL_VERSION],
        &server_versions,
        &[0xaa, 0xbb], // dcid
        &[0xcc],       // scid
    )
    .expect("generate VN");
    let parsed = parse_version_negotiation(&pkt).expect("VN must parse");
    assert_eq!(parsed, server_versions);
}

#[test]
fn vn_generation_rejects_invalid_cid_and_version_lengths() {
    assert_eq!(
        generate_version_negotiation_packet(
            &[],
            &[crate::transport::PROTOCOL_VERSION],
            &[0u8; MAX_CID_LEN + 1],
            &[],
        ),
        Err(ConnectionError::InvalidPacket)
    );
    assert_eq!(
        generate_version_negotiation_packet(&[], &[], &[], &[]),
        Err(ConnectionError::InvalidPacket)
    );
}

#[test]
fn vn_packet_parse_rejects_non_vn_packets() {
    // Missing form bit => not a VN packet.
    let bad = vec![FORM_BIT | FIXED_BIT, 0, 0, 0, 0, 0, 0, 0];
    let mut bad = bad;
    bad[0] &= !FORM_BIT;
    assert!(parse_version_negotiation(&bad).is_none());
    // Non-zero version field => not a VN packet.
    let bad2 = vec![FORM_BIT, 0, 0, 0, 1, 0, 0];
    assert!(parse_version_negotiation(&bad2).is_none());
    // Truncated version list (not a multiple of 4).
    let bad3 = vec![FORM_BIT, 0, 0, 0, 0, 0x01, 0xaa, 0x01, 0xbb, 0x01, 0x02, 0x03];
    assert!(parse_version_negotiation(&bad3).is_none());
    // Empty packet.
    assert!(parse_version_negotiation(&[]).is_none());
}

#[test]
fn vn_parser_rejects_oversized_connection_ids() {
    let mut packet = vec![FORM_BIT, 0, 0, 0, 0, (MAX_CID_LEN + 1) as u8];
    packet.extend_from_slice(&[0u8; MAX_CID_LEN + 1]);
    packet.push(0);
    packet.extend_from_slice(&crate::transport::PROTOCOL_VERSION.to_be_bytes());
    assert!(parse_version_negotiation(&packet).is_none());
    assert_eq!(parse_header(&packet, 0), Err(ConnectionError::InvalidPacket));
}

#[test]
fn negotiate_version_selects_highest_common() {
    let client = vec![crate::transport::PROTOCOL_VERSION];
    let server = vec![crate::transport::PROTOCOL_VERSION_V2, crate::transport::PROTOCOL_VERSION];
    // Server prefers v2 but client only offers v1 => v1 selected.
    assert_eq!(negotiate_version(&client, &server), Some(crate::transport::PROTOCOL_VERSION));
    // Both offer v2 => server's top preference (v2) selected.
    let client2 = vec![crate::transport::PROTOCOL_VERSION, crate::transport::PROTOCOL_VERSION_V2];
    assert_eq!(negotiate_version(&client2, &server), Some(crate::transport::PROTOCOL_VERSION_V2));
}

#[test]
fn negotiate_version_no_common_returns_none() {
    let client = vec![0xdeadbeef];
    let server = vec![crate::transport::PROTOCOL_VERSION];
    assert!(negotiate_version(&client, &server).is_none());
}

#[test]
fn v1_and_v2_coexistence_roundtrip() {
    // Server advertises both v1 and v2; client offers v2 first.
    let server_versions =
        vec![crate::transport::PROTOCOL_VERSION_V2, crate::transport::PROTOCOL_VERSION];
    let client_versions = vec![crate::transport::PROTOCOL_VERSION_V2];
    // Version selection picks v2.
    assert_eq!(
        negotiate_version(&client_versions, &server_versions),
        Some(crate::transport::PROTOCOL_VERSION_V2)
    );
    // VN packet contains both server versions and parses back identically.
    let pkt =
        generate_version_negotiation_packet(&client_versions, &server_versions, &[0x01], &[0x02])
            .expect("generate VN");
    assert_eq!(parse_version_negotiation(&pkt).unwrap(), server_versions);
}

#[test]
fn unsupported_version_triggers_vn_response() {
    // Client offers only an unsupported version; server has no common match.
    let client_versions = vec![0xdeadbeef];
    let server_versions =
        vec![crate::transport::PROTOCOL_VERSION_V2, crate::transport::PROTOCOL_VERSION];
    assert!(negotiate_version(&client_versions, &server_versions).is_none());
    // Server responds with a VN packet advertising its supported versions.
    let pkt =
        generate_version_negotiation_packet(&client_versions, &server_versions, &[0x11], &[0x22])
            .expect("generate VN");
    let parsed = parse_version_negotiation(&pkt).expect("VN response must parse");
    assert_eq!(parsed, server_versions);
    assert!(!parsed.contains(&0xdeadbeef));
}

#[test]
fn stateless_vn_swaps_connection_ids_and_adds_non_selectable_grease() {
    let client_dcid = [0x11, 0x12, 0x13, 0x14];
    let client_scid = [0x21, 0x22, 0x23];
    let mut packet = vec![FORM_BIT | FIXED_BIT];
    packet.extend_from_slice(&0xdead_beefu32.to_be_bytes());
    packet.push(client_dcid.len() as u8);
    packet.extend_from_slice(&client_dcid);
    packet.push(client_scid.len() as u8);
    packet.extend_from_slice(&client_scid);
    packet.resize(crate::transport::MIN_CLIENT_INITIAL_LEN, 0);

    let response = server_version_negotiation_response(
        &packet,
        &[crate::transport::PROTOCOL_VERSION_V2, crate::transport::PROTOCOL_VERSION],
    )
    .expect("valid unsupported Initial")
    .expect("VN response");
    let (header, _) = parse_header(&response, 0).expect("parse VN response");
    assert_eq!(header.dcid, client_scid);
    assert_eq!(header.scid, client_dcid);
    let versions = header.versions.expect("VN version list");
    assert_eq!(versions[0], crate::transport::PROTOCOL_VERSION_V2);
    assert_eq!(versions[1], crate::transport::PROTOCOL_VERSION);
    assert!(crate::transport::version::is_reserved_version(versions[2]));
    assert!(!crate::transport::is_supported_version(versions[2]));

    packet[1..5].copy_from_slice(&crate::transport::PROTOCOL_VERSION_V2.to_be_bytes());
    assert!(server_version_negotiation_response(&packet, &[crate::transport::PROTOCOL_VERSION])
        .expect("known but disabled version")
        .is_some());
}

#[test]
fn retry_header_parses_token_payload() {
    let mut pkt = vec![
        FORM_BIT | FIXED_BIT | 0x30, // Retry
        0x00,
        0x00,
        0x00,
        0x01, // version = v1
        0x01,
        0xaa, // dcid
        0x01,
        0xbb, // scid
        0x01,
        0x02, // token
    ];
    pkt.extend_from_slice(&[0u8; 16]); // integrity tag
    let (parsed, _) = parse_header(&pkt, 0).expect("parse retry");
    assert_eq!(parsed.ty, PacketType::Retry);
    assert_eq!(parsed.scid, vec![0xbb]);
    assert_eq!(parsed.token, Some(vec![0x01, 0x02]));
}

#[test]
fn retry_integrity_roundtrips_for_v1_and_v2() {
    let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    for version in [crate::transport::PROTOCOL_VERSION, crate::transport::PROTOCOL_VERSION_V2] {
        let header = Header {
            ty: PacketType::Retry,
            version,
            dcid: vec![0xaa],
            scid: vec![0xbb],
            pkt_num: 0,
            pkt_num_len: 0,
            token: Some(vec![0x01, 0x02, 0x03]),
            versions: None,
            key_phase: false,
        };
        let mut storage = [0u8; 64];
        let header_len = format_header(&header, &mut storage).expect("format Retry");
        let mut packet = storage[..header_len].to_vec();
        append_retry_tag(&mut packet, &odcid, version).expect("append Retry tag");
        verify_retry_tag(&packet, &odcid, version).expect("verify Retry tag");
        let (parsed, _) = parse_header(&packet, 0).expect("parse Retry");
        assert_eq!(parsed.version, version);
        assert_eq!(parsed.ty, PacketType::Retry);
        assert_eq!(parsed.token, header.token);

        packet[header_len] ^= 1;
        assert!(verify_retry_tag(&packet, &odcid, version).is_err());
    }
}

#[test]
fn v2_long_header_types_roundtrip_with_rfc9369_mapping() {
    for packet_type in [PacketType::Initial, PacketType::ZeroRTT, PacketType::Handshake] {
        let header = Header {
            ty: packet_type,
            version: crate::transport::PROTOCOL_VERSION_V2,
            dcid: vec![0xaa],
            scid: vec![0xbb],
            pkt_num: 0,
            pkt_num_len: 0,
            token: None,
            versions: None,
            key_phase: false,
        };
        let mut packet = [0u8; 64];
        let len = format_header(&header, &mut packet).expect("format v2 header");
        let (parsed, _) = parse_header(&packet[..len], 0).expect("parse v2 header");
        assert_eq!(parsed.ty, packet_type);
        assert_eq!(parsed.version, crate::transport::PROTOCOL_VERSION_V2);
    }
}

#[test]
fn supported_versions_reject_oversized_connection_ids() {
    for version in [crate::transport::PROTOCOL_VERSION, crate::transport::PROTOCOL_VERSION_V2] {
        let type_bits =
            crate::transport::version::long_header_type_bits(version, PacketType::Initial)
                .expect("Initial type bits");
        let mut packet = vec![FORM_BIT | FIXED_BIT | type_bits];
        packet.extend_from_slice(&version.to_be_bytes());
        packet.push((crate::transport::MAX_CONN_ID_LEN + 1) as u8);
        packet.resize(6 + crate::transport::MAX_CONN_ID_LEN + 1, 0xaa);
        packet.push(0);
        packet.push(0);
        assert_eq!(parse_header(&packet, 0), Err(ConnectionError::InvalidPacket));
    }
}

#[test]
fn unprotect_requires_keys_for_encrypted_packets() {
    let header = Header {
        ty: PacketType::Initial,
        version: crate::transport::PROTOCOL_VERSION,
        dcid: vec![0x11, 0x22, 0x33],
        scid: vec![0x44, 0x55],
        pkt_num: 0,
        pkt_num_len: 0,
        token: None,
        versions: None,
        key_phase: false,
    };
    let mut buf = vec![0u8; 64];
    let off = format_header(&header, &mut buf).expect("format");
    let crypto = CryptoContext::default();
    let err = unprotect_and_decrypt(&crypto, &mut buf[..off], 0, 0).expect_err("must fail");
    assert!(matches!(err, ConnectionError::Done));
}

#[test]
fn read_key_window_retains_recent_generations() {
    let mut crypto = CryptoContext::default();
    let secret = [0x11u8; 32];
    crate::crypto::aead::KeyScheduleHooks::set_read_secret(
        &mut crypto,
        crate::crypto::aead::Level::OneRTT,
        crate::crypto::aead::Algorithm::AES128_GCM,
        &secret,
    )
    .expect("valid read secret");
    for _ in 0..(ONE_RTT_READ_KEY_WINDOW + 3) {
        assert!(crypto.key_update_1rtt_read().expect("valid read key update"));
    }
    assert_eq!(crypto.previous_read_1rtt.len(), ONE_RTT_READ_KEY_WINDOW);
}

#[test]
fn short_header_decrypt_falls_back_to_previous_read_key() {
    let mut crypto = CryptoContext::default();
    let secret = [0x42u8; 32];
    crate::crypto::aead::KeyScheduleHooks::set_read_secret(
        &mut crypto,
        crate::crypto::aead::Level::OneRTT,
        crate::crypto::aead::Algorithm::AES128_GCM,
        &secret,
    )
    .expect("valid read secret");
    crate::crypto::aead::KeyScheduleHooks::set_write_secret(
        &mut crypto,
        crate::crypto::aead::Level::OneRTT,
        crate::crypto::aead::Algorithm::AES128_GCM,
        &secret,
    )
    .expect("valid write secret");

    let header = Header {
        ty: PacketType::Short,
        version: 0,
        dcid: vec![],
        scid: vec![],
        pkt_num: 0,
        pkt_num_len: 0,
        token: None,
        versions: None,
        key_phase: false,
    };

    let mut packet = vec![0u8; 64];
    let hdr_no_pn = format_header(&header, &mut packet).expect("format");
    let pn = 7u64;
    let pn_len = 1usize;
    packet[hdr_no_pn] = pn as u8;
    let hdr_len = hdr_no_pn + pn_len;
    let plaintext = b"hello";
    packet[hdr_len..hdr_len + plaintext.len()].copy_from_slice(plaintext);
    let total = hdr_len + plaintext.len() + 16;
    let used =
        encrypt_and_protect(&crypto, &mut packet[..total], hdr_len, pn, pn_len, PacketType::Short)
            .expect("seal");

    assert!(crypto.key_update_1rtt_read().expect("valid read key update"));

    let mut incoming = packet[..used].to_vec();
    let (_hdr, aad_len, pt_len) =
        unprotect_and_decrypt(&crypto, &mut incoming, 0, 0).expect("decrypt with read window");
    assert_eq!(&incoming[aad_len..aad_len + pt_len], plaintext);
}

#[test]
fn data_aead_batch_seal_open_via_crypto_context() {
    use crate::crypto::aead::{AeadOpenItem, AeadSealItem};

    let key = [0x7Eu8; 32];
    let iv = [0x6Du8; 12];
    let (seal, open) = select_packet_data_aead(&key, &iv);
    let crypto = CryptoContext {
        seal_1rtt: Some(Arc::new(seal)),
        open_1rtt: Some(Arc::new(open)),
        ..CryptoContext::default()
    };

    let ad = b"pkt-batch-ad";
    let pt = b"packet-batch-payload";
    let mut bufs: Vec<Vec<u8>> = (0..4)
        .map(|_| {
            let mut b = vec![0u8; pt.len() + 16];
            b[..pt.len()].copy_from_slice(pt);
            b
        })
        .collect();
    let mut seal_items: Vec<AeadSealItem<'_>> = bufs
        .iter_mut()
        .enumerate()
        .map(|(i, buf)| AeadSealItem {
            counter: i as u64 + 10,
            ad,
            buf: buf.as_mut_slice(),
            plaintext_len: pt.len(),
        })
        .collect();
    seal_data_aead_batch(&crypto, seal_items.as_mut_slice()).expect("batch seal");

    let mut open_items: Vec<AeadOpenItem<'_>> = bufs
        .iter_mut()
        .enumerate()
        .map(|(i, buf)| AeadOpenItem { counter: i as u64 + 10, ad, buf: buf.as_mut_slice() })
        .collect();
    open_data_aead_batch(&crypto, open_items.as_mut_slice()).expect("batch open");
    for buf in &bufs {
        assert_eq!(&buf[..pt.len()], pt);
    }
}

#[test]
fn tls_cover_same_material_reinstall_preserves_counters() {
    let mut crypto = CryptoContext::default();
    let key = [0x11u8; 32];
    let iv = [0x22u8; 12];
    let material = TlsCoverKeyMaterial::ChaCha20Poly1305 { key: &key, iv: &iv };
    assert_eq!(crypto.install_tls_cover_cipher(material), Ok(TlsCoverInstallOutcome::Installed));

    let plaintext = b"partial-session";
    let aad = b"tls-cover-aad";
    let mut ciphertext = crypto.encrypt_tls_cover_record(aad, plaintext).expect("seal");
    crypto.decrypt_tls_cover_record(aad, &mut ciphertext).expect("open");
    assert_eq!((crypto.tls_cover_write_seq, crypto.tls_cover_read_seq), (1, 1));

    assert_eq!(crypto.install_tls_cover_cipher(material), Ok(TlsCoverInstallOutcome::Unchanged));
    assert_eq!((crypto.tls_cover_write_seq, crypto.tls_cover_read_seq), (1, 1));
}

#[test]
fn tls_cover_fresh_material_rotation_resets_state_and_retires_old_material() {
    let mut crypto = CryptoContext::default();
    let chacha_key = [0x31u8; 32];
    let aes_key = [0x42u8; 16];
    let first_iv = [0x53u8; 12];
    let second_iv = [0x64u8; 12];
    let first = TlsCoverKeyMaterial::ChaCha20Poly1305 { key: &chacha_key, iv: &first_iv };
    let second = TlsCoverKeyMaterial::Aes128Gcm { key: &aes_key, iv: &second_iv };
    crypto.install_tls_cover_cipher(first).expect("initial install");
    crypto.encrypt_tls_cover_record(b"aad", b"record").expect("partial use");

    assert_eq!(crypto.install_tls_cover_cipher(second), Ok(TlsCoverInstallOutcome::Installed));
    assert_eq!(crypto.tls_cover_cipher_kind(), Some(TlsCoverCipherKind::Aes128Gcm));
    assert_eq!((crypto.tls_cover_write_seq, crypto.tls_cover_read_seq), (0, 0));
    assert_eq!(crypto.tls_cover_cipher.retired_identity_count(), 1);
    assert_eq!(crypto.install_tls_cover_cipher(first), Err(ConnectionError::KeyUpdateError));
}

#[test]
fn tls_cover_repeated_rotation_never_reactivates_retired_material() {
    let mut crypto = CryptoContext::default();
    let key_a = [0x71u8; 32];
    let key_b = [0x72u8; 16];
    let key_c = [0x73u8; 32];
    let iv_a = [0x81u8; 12];
    let iv_b = [0x82u8; 12];
    let iv_c = [0x83u8; 12];
    let material_a = TlsCoverKeyMaterial::ChaCha20Poly1305 { key: &key_a, iv: &iv_a };
    let material_b = TlsCoverKeyMaterial::Aes128Gcm { key: &key_b, iv: &iv_b };
    let material_c = TlsCoverKeyMaterial::ChaCha20Poly1305 { key: &key_c, iv: &iv_c };

    crypto.install_tls_cover_cipher(material_a).expect("install A");
    crypto.install_tls_cover_cipher(material_b).expect("rotate to B");
    crypto.install_tls_cover_cipher(material_c).expect("rotate to C");
    assert_eq!(crypto.tls_cover_cipher.retired_identity_count(), 2);
    assert_eq!(crypto.install_tls_cover_cipher(material_a), Err(ConnectionError::KeyUpdateError));
    assert_eq!(crypto.install_tls_cover_cipher(material_b), Err(ConnectionError::KeyUpdateError));
    assert_eq!(crypto.install_tls_cover_cipher(material_c), Ok(TlsCoverInstallOutcome::Unchanged));

    let mut reconnect = CryptoContext::default();
    assert_eq!(
        reconnect.install_tls_cover_cipher(material_a),
        Ok(TlsCoverInstallOutcome::Installed),
        "a fresh connection owns an independent sequence space"
    );
}

#[test]
fn tls_cover_sequence_exhaustion_fails_closed() {
    let mut crypto = CryptoContext::default();
    let key = [0x91u8; 32];
    let iv = [0x92u8; 12];
    crypto
        .install_tls_cover_cipher(TlsCoverKeyMaterial::ChaCha20Poly1305 { key: &key, iv: &iv })
        .expect("install");

    crypto.tls_cover_write_seq = u64::MAX;
    assert_eq!(
        crypto.encrypt_tls_cover_record(b"aad", b"record"),
        Err(ConnectionError::AeadLimitReached)
    );
    crypto.tls_cover_read_seq = u64::MAX;
    let mut ciphertext = [0u8; 16];
    assert_eq!(
        crypto.decrypt_tls_cover_record(b"aad", &mut ciphertext),
        Err(ConnectionError::AeadLimitReached)
    );
}

#[test]
fn tls_cover_open_failure_preserves_sequence_state() {
    let mut crypto = CryptoContext::default();
    let key = [0xA1u8; 32];
    let iv = [0xA2u8; 12];
    crypto
        .install_tls_cover_cipher(TlsCoverKeyMaterial::ChaCha20Poly1305 { key: &key, iv: &iv })
        .expect("install");

    let mut truncated = [0u8; AEAD_TAG_LEN - 1];
    assert_eq!(
        crypto.decrypt_tls_cover_record(b"aad", &mut truncated),
        Err(ConnectionError::BufferTooShort)
    );
    assert_eq!(crypto.tls_cover_read_seq, 0);
}

#[test]
fn packet_payload_boundaries_reject_overflow_before_aead() {
    let aead = AesGcm128::from_arrays(&[0xB1; 16], &[0xB2; 12]);
    let mut packet = [0xC3u8; 64];
    let original = packet;
    assert!(encrypt_packet(&mut packet, usize::MAX, 0, 8, &aead).is_err());
    assert_eq!(packet, original);
    assert!(decrypt_payload(&mut packet, 0, 1, usize::MAX, &aead).is_err());
    assert_eq!(packet, original);
    let crypto = CryptoContext::default();
    assert!(encrypt_and_protect(&crypto, &mut packet, usize::MAX, 0, 1, PacketType::Short).is_err());
    assert_eq!(packet, original);
}

#[test]
fn pending_handshake_send_tracks_only_unsent_handshake_flights() {
    let mut crypto = CryptoContext::default();
    assert!(!crypto.has_pending_handshake_send());

    crypto.crypto_handshake.send(b"client-finished").expect("queue handshake flight");
    assert!(crypto.has_pending_handshake_send());

    let (_, bytes) = crypto
        .crypto_handshake
        .next_crypto_frame(usize::MAX)
        .expect("next handshake frame")
        .expect("queued handshake flight");
    assert_eq!(bytes, b"client-finished");
    assert!(!crypto.has_pending_handshake_send());
}

#[test]
fn qftls_key_installer_replaces_and_clears_complete_packet_key_bundles() {
    use crate::qftls::{QuicTlsHandshakeKeys, QuicTlsKeyInstaller, QuicTlsOneRttKeys};

    let installer = parking_lot::RwLock::new(CryptoContext::default());
    {
        let mut crypto = installer.write();
        crypto
            .install_aes_gcm_initial(&[0x11; 32], &[0x12; 32], crate::transport::PROTOCOL_VERSION)
            .expect("install Initial packet keys");
        crypto
            .install_hp_initial(&[0x11; 32], &[0x12; 32], crate::transport::PROTOCOL_VERSION)
            .expect("install Initial header keys");
        let snapshot = crypto.packet_protection_snapshot();
        assert_eq!(
            snapshot.initial.packet_aead_owner,
            crate::qftls::PacketProtectionOwner::QuicInitialStandard
        );
        assert_eq!(
            snapshot.initial.header_protection_owner,
            crate::qftls::PacketProtectionOwner::QuicInitialStandard
        );
        assert_eq!(
            snapshot.initial.standard_cipher_suite,
            Some(crate::qftls::StandardCipherSuite::Aes128GcmSha256)
        );
        assert_eq!(
            snapshot.zero_rtt.packet_aead_owner,
            crate::qftls::PacketProtectionOwner::Disabled
        );
    }
    let previous_secret = [0x21; 32];
    {
        let mut crypto = installer.write();
        crate::crypto::aead::KeyScheduleHooks::set_read_secret(
            &mut *crypto,
            crate::crypto::aead::Level::OneRTT,
            crate::crypto::aead::Algorithm::AES128_GCM,
            &previous_secret,
        )
        .expect("install previous read secret");
        crate::crypto::aead::KeyScheduleHooks::set_write_secret(
            &mut *crypto,
            crate::crypto::aead::Level::OneRTT,
            crate::crypto::aead::Algorithm::AES128_GCM,
            &previous_secret,
        )
        .expect("install previous write secret");
        let snapshot = crypto.packet_protection_snapshot();
        assert_eq!(
            snapshot.one_rtt.packet_aead_owner,
            crate::qftls::PacketProtectionOwner::TransportStandard
        );
        assert_eq!(
            snapshot.one_rtt.header_protection_owner,
            crate::qftls::PacketProtectionOwner::TransportStandard
        );
        assert!(crypto.key_update_1rtt_read().expect("advance previous read generation"));
        assert_eq!(crypto.previous_read_1rtt.len(), 1);
    }
    let handshake_key = [0x31; 16];
    let handshake_iv = [0x32; 12];
    let handshake_hp_key = [0x33; 16];
    installer.install_handshake_keys(QuicTlsHandshakeKeys {
        seal: Box::new(AesGcm128::from_arrays(&handshake_key, &handshake_iv)),
        open: Box::new(AesGcm128::from_arrays(&handshake_key, &handshake_iv)),
        hp_seal: Box::new(crate::crypto::aead::AesHp::from_key(&handshake_hp_key)),
        hp_open: Box::new(crate::crypto::aead::AesHp::from_key(&handshake_hp_key)),
        standard_cipher_suite: crate::qftls::StandardCipherSuite::Aes128GcmSha256,
    });

    let one_rtt_key = [0x41; 16];
    let one_rtt_iv = [0x42; 12];
    let one_rtt_hp_key = [0x43; 16];
    installer.install_one_rtt_keys(QuicTlsOneRttKeys {
        seal: Arc::new(qf_crypto::PacketAeadSeal::dynamic(Box::new(AesGcm128::from_arrays(
            &one_rtt_key,
            &one_rtt_iv,
        )))),
        open: Arc::new(qf_crypto::PacketAeadOpen::dynamic(Box::new(AesGcm128::from_arrays(
            &one_rtt_key,
            &one_rtt_iv,
        )))),
        hp_seal: Arc::new(crate::crypto::aead::AesHp::from_key(&one_rtt_hp_key)),
        hp_open: Arc::new(crate::crypto::aead::AesHp::from_key(&one_rtt_hp_key)),
        standard_cipher_suite: crate::qftls::StandardCipherSuite::Aes128GcmSha256,
    });

    {
        let crypto = installer.read();
        assert!(crypto.seal_handshake.is_some());
        assert!(crypto.open_handshake.is_some());
        assert!(crypto.hp_handshake.is_some());
        assert!(crypto.hp_handshake_open.is_some());
        assert!(crypto.seal_1rtt.is_some());
        assert!(crypto.open_1rtt.is_some());
        assert!(crypto.hp_1rtt.is_some());
        assert!(crypto.hp_1rtt_open.is_some());
        assert!(crypto.read_secret_1rtt.is_none());
        assert!(crypto.write_secret_1rtt.is_none());
        assert_eq!(crypto.read_generation_1rtt, 0);
        assert_eq!(crypto.write_generation_1rtt, 0);
        assert!(crypto.previous_read_1rtt.is_empty());
        let snapshot = crypto.packet_protection_snapshot();
        assert_eq!(
            snapshot.handshake.packet_aead_owner,
            crate::qftls::PacketProtectionOwner::RustlsStandard
        );
        assert_eq!(
            snapshot.one_rtt.header_protection_owner,
            crate::qftls::PacketProtectionOwner::RustlsStandard
        );
        assert_eq!(
            snapshot.negotiated_tls_cipher_suite,
            Some(crate::qftls::StandardCipherSuite::Aes128GcmSha256)
        );
    }
    assert!(installer.has_one_rtt_keys());

    installer.clear_handshake_and_one_rtt_keys();
    let crypto = installer.read();
    assert!(crypto.seal_handshake.is_none());
    assert!(crypto.open_handshake.is_none());
    assert!(crypto.hp_handshake.is_none());
    assert!(crypto.hp_handshake_open.is_none());
    assert!(crypto.seal_1rtt.is_none());
    assert!(crypto.open_1rtt.is_none());
    assert!(crypto.hp_1rtt.is_none());
    assert!(crypto.hp_1rtt_open.is_none());
    assert!(crypto.read_secret_1rtt.is_none());
    assert!(crypto.write_secret_1rtt.is_none());
    assert_eq!(crypto.read_generation_1rtt, 0);
    assert_eq!(crypto.write_generation_1rtt, 0);
    assert!(crypto.previous_read_1rtt.is_empty());
    let snapshot = crypto.packet_protection_snapshot();
    assert_eq!(
        snapshot.handshake.packet_aead_owner,
        crate::qftls::PacketProtectionOwner::Uninstalled
    );
    assert_eq!(
        snapshot.one_rtt.header_protection_owner,
        crate::qftls::PacketProtectionOwner::Uninstalled
    );
}

fn header_protection_test_context() -> CryptoContext {
    let mut crypto = CryptoContext::default();
    crypto.hp_initial = Some(Box::new(
        crate::crypto::aead::AesHp::new(&[0x42; 16]).expect("valid header-protection key"),
    ));
    crypto
}

#[test]
fn protect_header_rejects_invalid_packet_number_bounds_before_mutation() {
    let crypto = header_protection_test_context();
    for (pn_offset, pn_len) in [(0, 1), (1, 0), (1, 5), (usize::MAX, 1), (60, 4)] {
        let mut packet = vec![0x40; 64];
        let original = packet.clone();
        let result = protect_header(&crypto, &mut packet, pn_offset, pn_len, PacketType::Initial);
        assert!(result.is_err(), "invalid PN bounds must be rejected");
        assert_eq!(packet, original, "validation must precede header mutation");
    }
}

#[test]
fn protect_and_remove_header_reject_missing_sample_without_mutation() {
    let crypto = header_protection_test_context();
    let hp = crypto.hp_initial.as_deref().expect("test header protector");
    let mut packet = vec![0x40; 1 + MAX_PKT_NUM_LEN + SAMPLE_LEN - 1];
    let original = packet.clone();

    assert_eq!(
        protect_header(&crypto, &mut packet, 1, 1, PacketType::Initial),
        Err(ConnectionError::InvalidPacket)
    );
    assert_eq!(packet, original);
    assert_eq!(remove_hp(&mut packet, hp, 1), Err(ConnectionError::InvalidPacket));
    assert_eq!(packet, original);
}

#[test]
fn unprotect_rejects_missing_sample_before_header_or_payload_processing() {
    let hp = crate::crypto::aead::AesHp::new(&[0x43; 16]).expect("valid header-protection key");
    let aead = AesGcm128::from_arrays(&[0x44; 16], &[0x45; 12]);
    let header = Header {
        ty: PacketType::Initial,
        version: crate::transport::PROTOCOL_VERSION,
        dcid: Vec::new(),
        scid: Vec::new(),
        pkt_num: 0,
        pkt_num_len: 0,
        token: None,
        versions: None,
        key_phase: false,
    };
    let mut packet = vec![0xC0; 1 + MAX_PKT_NUM_LEN + SAMPLE_LEN - 1];
    let original = packet.clone();

    assert_eq!(
        unprotect_and_decrypt_with_key(&hp, &aead, &mut packet, 0, 0, Some((header, 1))),
        Err(ConnectionError::InvalidPacket)
    );
    assert_eq!(packet, original);
}

#[test]
fn apply_hp_rejects_short_sample_and_packet_number_buffer() {
    let hp = crate::crypto::aead::AesHp::new(&[0x46; 16]).expect("valid header-protection key");
    let mut pn = [0u8; 4];
    assert!(apply_hp(0x40, &mut pn, &[0u8; SAMPLE_LEN - 1], true, &hp).is_err());

    let mut no_packet_number = [];
    assert!(apply_hp(0x40, &mut no_packet_number, &[0u8; SAMPLE_LEN], true, &hp).is_err());
}
