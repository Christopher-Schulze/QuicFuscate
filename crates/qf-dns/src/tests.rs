use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn make_dns_query_packet(domain: &str, qtype: u16) -> Vec<u8> {
    make_dns_query_packet_with_flags(domain, qtype, 0x0100)
}

fn make_dns_query_packet_with_flags(domain: &str, qtype: u16, flags: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&12345u16.to_be_bytes()); // ID
    pkt.extend_from_slice(&flags.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                // Question: encode domain name.
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // Root terminator.
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    pkt
}

fn response_from_question_packet(question: &[u8], flags: u16) -> Vec<u8> {
    let mut response = question[..DNS_HEADER_SIZE].to_vec();
    response[2..4].copy_from_slice(&flags.to_be_bytes());
    response[4..6].copy_from_slice(&1u16.to_be_bytes());
    response[6..12].fill(0);
    response.extend_from_slice(&question[DNS_HEADER_SIZE..]);
    response
}

fn valid_doh_response(query: &[u8]) -> Vec<u8> {
    let mut response = response_from_question_packet(query, DNS_FLAG_QR | DNS_FLAG_RD | 0x0080);
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    response[10..12].copy_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&30u32.to_be_bytes());
    response.extend_from_slice(&4u16.to_be_bytes());
    response.extend_from_slice(&[192, 0, 2, 1]);
    response.extend_from_slice(&[0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
    response
}

fn malformed_doh_response(query: &[u8]) -> Vec<u8> {
    let mut response = query[..DNS_HEADER_SIZE].to_vec();
    response[2..4].copy_from_slice(&(DNS_FLAG_QR | DNS_FLAG_RD).to_be_bytes());
    response[4..6].copy_from_slice(&1u16.to_be_bytes());
    response[6..12].fill(0);
    response.extend_from_slice(&[3, b'e']);
    response
}

async fn resolve_against_local_response(
    query: &[u8],
    body: Vec<u8>,
    status: &str,
    content_type: &str,
) -> Result<Vec<u8>, DnsProxyError> {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind DoH test listener");
    let address = listener.local_addr().expect("DoH test listener address");
    let status = status.to_owned();
    let content_type = content_type.to_owned();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept DoH test request");
        let mut request = [0u8; 8192];
        let _ = stream.read(&mut request).await.expect("read DoH test request");
        let headers = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes()).await.expect("write DoH test headers");
        stream.write_all(&body).await.expect("write DoH test body");
    });
    let client = reqwest::Client::builder()
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build local DoH test client");
    let endpoint = format!("http://{address}/dns-query");
    let result = resolve_via_doh_with_client(query, &endpoint, &client).await;
    server.await.expect("DoH test server task");
    result
}

#[test]
fn test_parse_dns_query() {
    let pkt = make_dns_query_packet("example.com", 1);
    let query = parse_dns_query(&pkt).unwrap();
    assert_eq!(query.id, 12345);
    assert_eq!(query.qname, "example.com");
    assert_eq!(query.qtype, DnsQType::A);
    assert_eq!(query.qclass, 1);
}

#[test]
fn test_parse_dns_query_aaaa() {
    let pkt = make_dns_query_packet("example.com", 28);
    let query = parse_dns_query(&pkt).unwrap();
    assert_eq!(query.qtype, DnsQType::AAAA);
}

#[test]
fn test_parse_dns_query_too_short() {
    assert!(parse_dns_query(&[0, 1, 2]).is_none());
}

#[test]
fn dns_query_size_validation_is_typed_and_bounded() {
    assert_eq!(
        validate_dns_query_size(&[0u8; DNS_HEADER_SIZE - 1]),
        Err(DnsQuerySizeError::TooShort { actual: DNS_HEADER_SIZE - 1, minimum: DNS_HEADER_SIZE })
    );
    let oversized = vec![0u8; DNS_MESSAGE_MAX_SIZE + 1];
    assert_eq!(
        validate_dns_query_size(&oversized),
        Err(DnsQuerySizeError::TooLarge {
            actual: DNS_MESSAGE_MAX_SIZE + 1,
            maximum: DNS_MESSAGE_MAX_SIZE,
        })
    );
    assert!(validate_dns_query_size(&[0u8; DNS_HEADER_SIZE]).is_ok());
}

#[test]
fn test_parse_dns_query_rejects_response_packets() {
    let mut pkt = make_dns_query_packet("example.com", 1);
    pkt[2] |= 0x80;
    assert!(parse_dns_query(&pkt).is_none());
}

#[test]
fn doh_name_matching_accepts_case_insensitive_bounded_compression() {
    let mut packet = vec![0u8; DNS_HEADER_SIZE];
    packet.extend_from_slice(&[3, b'w', b'w', b'w', 0]);
    let compressed_start = packet.len();
    packet.extend_from_slice(&[3, b'W', b'W', b'W', 0xc0, 0x0c]);

    let (name, end) = parse_canonical_dns_name(&packet, compressed_start).expect("compressed name");
    assert_eq!(name, vec![3, b'w', b'w', b'w', 3, b'w', b'w', b'w', 0]);
    assert_eq!(end, packet.len());
}

#[test]
fn test_unknown_qtype_is_preserved_in_servfail_question() {
    let raw_qtype = 65280;
    let pkt = make_dns_query_packet("example.com", raw_qtype);
    let query = parse_dns_query(&pkt).expect("query should parse");
    assert_eq!(query.qtype, DnsQType::Unknown);
    assert_eq!(query.raw_qtype, raw_qtype);

    let response = build_dns_servfail(&query);
    let mut pos = 12;
    parse_name(&response, &mut pos).expect("response question name");
    assert_eq!(u16::from_be_bytes([response[pos], response[pos + 1]]), raw_qtype);
}

#[test]
fn test_synthesized_response_preserves_rd_and_cd() {
    let pkt = make_dns_query_packet_with_flags("example.com", 1, 0x0110);
    let query = parse_dns_query(&pkt).expect("query should parse");
    let response = build_dns_servfail(&query);
    assert_eq!(
        u16::from_be_bytes([response[2], response[3]]),
        0x8112,
        "response must set QR, preserve RD/CD, and set SERVFAIL"
    );
}

#[test]
fn test_parse_dns_query_rejects_unsupported_header_semantics() {
    for flags in [0x0800, 0x0400, 0x0200, 0x0080, 0x0040, 0x0001] {
        let packet = make_dns_query_packet_with_flags("example.com", 1, flags);
        assert!(parse_dns_query(&packet).is_none(), "flags {flags:#06x} must be rejected");
    }

    let mut multiple = make_dns_query_packet("example.com", 1);
    multiple[4..6].copy_from_slice(&2u16.to_be_bytes());
    assert!(parse_dns_query(&multiple).is_none());
}

#[test]
fn test_parse_dns_query_rejects_reserved_name_prefixes_and_bad_pointers() {
    let mut reserved = make_dns_query_packet("example.com", 1);
    reserved[12] = 0x40;
    assert!(parse_dns_query(&reserved).is_none());

    let mut forward_pointer = make_dns_query_packet("example.com", 1);
    forward_pointer[12..14].copy_from_slice(&[0xc0, 0x20]);
    assert!(parse_dns_query(&forward_pointer).is_none());

    let mut header_pointer = make_dns_query_packet("example.com", 1);
    header_pointer[12..14].copy_from_slice(&[0xc0, 0x00]);
    assert!(parse_dns_query(&header_pointer).is_none());
}

#[test]
fn test_parse_dns_query_preserves_question_wire_and_non_utf8_bytes() {
    let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    packet.extend_from_slice(&[
        3, b'W', b'W', b'W', 7, b'E', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0xff, 0x01, 0, 1,
    ]);

    let query = parse_dns_query(&packet).expect("question must parse");
    assert_eq!(query.qname, "WWW.Example");
    assert_eq!(query.raw_qtype, 0xff01);
    assert_eq!(query.question_wire, packet[DNS_HEADER_SIZE..]);

    let response = build_dns_servfail(&query);
    assert_eq!(&response[DNS_HEADER_SIZE..], &packet[DNS_HEADER_SIZE..]);

    let mut non_utf8 = vec![0x56, 0x78, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    non_utf8.extend_from_slice(&[1, 0xff, 0, 0, 1, 0, 1]);
    let query = parse_dns_query(&non_utf8).expect("non-UTF-8 label must remain parseable");
    assert_eq!(&query.question_wire, &non_utf8[DNS_HEADER_SIZE..]);
    assert_eq!(&build_dns_servfail(&query)[DNS_HEADER_SIZE..], &non_utf8[DNS_HEADER_SIZE..]);
}

#[tokio::test]
async fn test_malformed_query_with_transaction_id_returns_servfail() {
    let pkt = [0x12, 0x34, 0x29, 0x10, 0, 0, 0, 0, 0, 0, 0, 0];
    let result = process_dns_query(&pkt, &DnsProxyConfig::default()).await.unwrap();
    assert_eq!(u16::from_be_bytes([result[0], result[1]]), 0x1234);
    assert_eq!(result[3] & 0x0f, DNS_RCODE_SERVFAIL);
    assert_eq!(u16::from_be_bytes([result[4], result[5]]), 0);
}

#[test]
fn test_build_dns_response_a() {
    let query = DnsQuery {
        id: 42,
        flags: 0x0100,
        qname: "test.com".into(),
        qname_wire: Vec::new(),
        qtype: DnsQType::A,
        raw_qtype: 1,
        qclass: 1,
        question_wire: Vec::new(),
    };
    let ips = vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)];
    let response = build_dns_response_a(&query, &ips);
    // Verify ID.
    assert_eq!(u16::from_be_bytes([response[0], response[1]]), 42);
    // Verify ANCOUNT = 2.
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 2);
}

#[test]
fn test_build_dns_nxdomain() {
    let query = DnsQuery {
        id: 99,
        flags: 0x0100,
        qname: "nonexistent.invalid".into(),
        qname_wire: Vec::new(),
        qtype: DnsQType::A,
        raw_qtype: 1,
        qclass: 1,
        question_wire: Vec::new(),
    };
    let response = build_dns_nxdomain(&query);
    assert_eq!(u16::from_be_bytes([response[0], response[1]]), 99);
    // RCODE = 3 (NXDOMAIN) in flags.
    assert_eq!(response[3] & 0x0F, 3);
}

#[test]
fn test_is_dns_query() {
    let pkt = make_dns_query_packet("example.com", 1);
    assert!(is_dns_query(&pkt));
    assert!(!is_dns_query(&[0, 1, 2]));
}

#[test]
fn test_dns_qtype_from_u16() {
    assert_eq!(DnsQType::from_u16(1), DnsQType::A);
    assert_eq!(DnsQType::from_u16(28), DnsQType::AAAA);
    assert_eq!(DnsQType::from_u16(999), DnsQType::Unknown);
}

#[test]
fn test_dns_proxy_config_default() {
    let config = DnsProxyConfig::default();
    assert!(!config.doh_endpoints.is_empty());
    assert!(!config.upstream_resolvers.is_empty());
    assert!(config.use_doh);
    assert_eq!(config.listen_port, 53);
}

#[test]
fn test_client_dns_proxy_config_prepares_ip_endpoint() {
    let config =
        DnsProxyConfig::for_client_endpoints(vec!["https://127.0.0.1/dns-query".to_string()])
            .expect("IP-based DoH endpoint should be valid");

    assert!(config.use_doh);
    assert!(config.upstream_resolvers.is_empty());
    assert!(config.doh_client.lock().is_some());
}

#[test]
fn test_client_dns_proxy_config_rejects_non_https_endpoint() {
    let result =
        DnsProxyConfig::for_client_endpoints(vec!["http://127.0.0.1/dns-query".to_string()]);

    assert!(matches!(result, Err(DnsProxyError::ConfigError(_))));
}

#[test]
fn test_client_dns_proxy_config_rejects_endpoint_credentials() {
    let result = DnsProxyConfig::for_client_endpoints(vec![
        "https://user:password@127.0.0.1/dns-query".to_string(),
    ]);

    assert!(matches!(result, Err(DnsProxyError::ConfigError(_))));
}

#[tokio::test]
async fn test_resolve_via_doh_rejects_invalid_endpoint() {
    // An invalid endpoint should return a DohError, not panic.
    let pkt = make_dns_query_packet("example.com", 1);
    let result = resolve_via_doh(&pkt, "https://invalid.localhost.invalid/dns-query").await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, DnsProxyError::DohError(_)));
}

#[tokio::test]
async fn test_resolve_via_doh_rejects_http_endpoint() {
    // The client is configured for HTTPS only; HTTP should fail.
    let pkt = make_dns_query_packet("example.com", 1);
    let result = resolve_via_doh(&pkt, "http://127.0.0.1:1/dns-query").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_build_doh_client_succeeds() {
    // The client builder must succeed with the canonical configuration.
    let client = build_doh_client();
    assert!(client.is_ok(), "build_doh_client should succeed");
}

#[tokio::test]
async fn test_resolve_via_doh_with_client_rejects_invalid_endpoint() {
    // Using a shared client, an invalid endpoint should still return a
    // DohError, not panic. This verifies the shared-client path.
    let pkt = make_dns_query_packet("example.com", 1);
    let client = build_doh_client().unwrap();
    let result =
        resolve_via_doh_with_client(&pkt, "https://invalid.localhost.invalid/dns-query", &client)
            .await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), DnsProxyError::DohError(_)));
}

#[tokio::test]
async fn test_resolve_via_doh_rejects_short_and_oversized_input_before_network() {
    let client = build_doh_client().expect("DoH client");
    let short = resolve_via_doh_with_client(
        &[0u8; DNS_HEADER_SIZE - 1],
        "https://127.0.0.1:1/dns-query",
        &client,
    )
    .await
    .expect_err("short query must be rejected before network I/O");
    assert!(matches!(short, DnsProxyError::QuerySize(DnsQuerySizeError::TooShort { .. })));

    let oversized = vec![0u8; DNS_MESSAGE_MAX_SIZE + 1];
    let large = resolve_via_doh_with_client(&oversized, "https://127.0.0.1:1/dns-query", &client)
        .await
        .expect_err("oversized query must be rejected before network I/O");
    assert!(matches!(large, DnsProxyError::QuerySize(DnsQuerySizeError::TooLarge { .. })));
}

#[tokio::test]
async fn doh_response_contract_accepts_valid_compressed_answer_and_edns() {
    let query = make_dns_query_packet("example.com", 1);
    let expected = valid_doh_response(&query);
    let actual = resolve_against_local_response(
        &query,
        expected.clone(),
        "200 OK",
        "application/dns-message; charset=binary",
    )
    .await
    .expect("valid DoH response");
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn doh_response_contract_rejects_semantic_and_transport_mismatches() {
    let query = make_dns_query_packet("example.com", 1);
    let wrong_name = make_dns_query_packet("wrong.example.com", 1);
    let wrong_type = make_dns_query_packet("example.com", 28);
    let mut wrong_class = make_dns_query_packet("example.com", 1);
    let class_start = wrong_class.len() - 2;
    wrong_class[class_start..].copy_from_slice(&3u16.to_be_bytes());

    let semantic_cases = [
        ("wrong-name", response_from_question_packet(&wrong_name, DNS_FLAG_QR | DNS_FLAG_RD)),
        ("wrong-type", response_from_question_packet(&wrong_type, DNS_FLAG_QR | DNS_FLAG_RD)),
        ("wrong-class", response_from_question_packet(&wrong_class, DNS_FLAG_QR | DNS_FLAG_RD)),
        ("qr-clear", response_from_question_packet(&query, DNS_FLAG_RD)),
        (
            "unsupported-opcode",
            response_from_question_packet(&query, DNS_FLAG_QR | DNS_FLAG_RD | 0x0800),
        ),
        ("multiple-questions", {
            let mut response = response_from_question_packet(&query, DNS_FLAG_QR | DNS_FLAG_RD);
            response[4..6].copy_from_slice(&2u16.to_be_bytes());
            response
        }),
        ("malformed-question", malformed_doh_response(&query)),
        ("wrong-id", {
            let mut response = valid_doh_response(&query);
            response[0..2].copy_from_slice(&54321u16.to_be_bytes());
            response
        }),
    ];

    for (label, response) in semantic_cases {
        let result =
            resolve_against_local_response(&query, response, "200 OK", "application/dns-message")
                .await;
        assert!(matches!(result, Err(DnsProxyError::DohError(_))), "case {label}");
    }

    let status = resolve_against_local_response(
        &query,
        valid_doh_response(&query),
        "500 Internal Server Error",
        "application/dns-message",
    )
    .await;
    assert!(matches!(status, Err(DnsProxyError::DohError(_))));

    let content_type = resolve_against_local_response(
        &query,
        valid_doh_response(&query),
        "200 OK",
        "application/json",
    )
    .await;
    assert!(matches!(content_type, Err(DnsProxyError::DohError(_))));

    let oversized = resolve_against_local_response(
        &query,
        vec![0u8; DNS_MESSAGE_MAX_SIZE + 1],
        "200 OK",
        "application/dns-message",
    )
    .await;
    assert!(matches!(
        oversized,
        Err(DnsProxyError::ResponseTooLarge { actual, maximum })
            if actual == (DNS_MESSAGE_MAX_SIZE + 1) as u64
                && maximum == DNS_MESSAGE_MAX_SIZE
    ));
}

#[test]
fn doh_response_body_is_bounded_for_content_length_and_chunks() {
    assert!(validate_doh_content_length(Some(DNS_MESSAGE_MAX_SIZE as u64)).is_ok());
    assert!(matches!(
        validate_doh_content_length(Some((DNS_MESSAGE_MAX_SIZE + 1) as u64)),
        Err(DnsProxyError::ResponseTooLarge { actual, maximum })
            if actual == (DNS_MESSAGE_MAX_SIZE + 1) as u64
                && maximum == DNS_MESSAGE_MAX_SIZE
    ));

    let mut body = Vec::new();
    append_bounded_dns_response(&mut body, &[0u8; DNS_MESSAGE_MAX_SIZE])
        .expect("body at the limit must be accepted");
    let error = append_bounded_dns_response(&mut body, &[0u8])
        .expect_err("body beyond the limit must be rejected");
    assert!(matches!(
        error,
        DnsProxyError::ResponseTooLarge { actual, maximum }
            if actual == (DNS_MESSAGE_MAX_SIZE + 1) as u64
                && maximum == DNS_MESSAGE_MAX_SIZE
    ));
}

#[test]
fn udp_forwarding_rejects_oversized_datagrams_without_truncation() {
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver bind");
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender bind");
    let payload = vec![0u8; DNS_MESSAGE_MAX_SIZE + 1];
    sender
        .send_to(&payload, receiver.local_addr().expect("receiver address"))
        .expect("oversized datagram send");

    let error = receive_dns_response(
        &receiver,
        sender.local_addr().expect("sender address"),
        &make_dns_query_packet("example.com", 1),
        Instant::now() + Duration::from_secs(1),
    )
    .expect_err("oversized datagram must be rejected");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

/// Drive `receive_dns_response` against datagrams delivered from the address it
/// trusts, so only question binding can distinguish them.
fn receive_from_upstream(query: &[u8], datagrams: &[Vec<u8>]) -> std::io::Result<Vec<u8>> {
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver bind");
    let upstream = std::net::UdpSocket::bind("127.0.0.1:0").expect("upstream bind");
    let receiver_addr = receiver.local_addr().expect("receiver address");
    for datagram in datagrams {
        upstream.send_to(datagram, receiver_addr).expect("datagram send");
    }
    receive_dns_response(
        &receiver,
        upstream.local_addr().expect("upstream address"),
        query,
        Instant::now() + Duration::from_secs(1),
    )
}

#[test]
fn udp_response_matching_the_outstanding_question_is_accepted() {
    let query = make_dns_query_packet("example.com", 1);
    let response = response_from_question_packet(&query, DNS_FLAG_QR | DNS_FLAG_RD);
    let received = receive_from_upstream(&query, std::slice::from_ref(&response))
        .expect("matching response must be accepted");
    assert_eq!(received, response);
}

#[test]
fn udp_responses_that_answer_a_different_question_are_rejected() {
    let query = make_dns_query_packet("example.com", 1);

    let mut stale_id = response_from_question_packet(&query, DNS_FLAG_QR | DNS_FLAG_RD);
    stale_id[0] ^= 0xFF;

    let wrong_name = response_from_question_packet(
        &make_dns_query_packet("attacker.example", 1),
        DNS_FLAG_QR | DNS_FLAG_RD,
    );
    let wrong_type = response_from_question_packet(
        &make_dns_query_packet("example.com", 28),
        DNS_FLAG_QR | DNS_FLAG_RD,
    );

    let mut wrong_class = response_from_question_packet(&query, DNS_FLAG_QR | DNS_FLAG_RD);
    let class_offset = wrong_class.len() - 2;
    wrong_class[class_offset..].copy_from_slice(&3u16.to_be_bytes());

    // A response without QR is a query, not an answer, and must not satisfy this one.
    let missing_qr = response_from_question_packet(&query, DNS_FLAG_RD);

    for (label, datagram) in [
        ("stale transaction id", stale_id),
        ("wrong question name", wrong_name),
        ("wrong question type", wrong_type),
        ("wrong question class", wrong_class),
        ("missing response flag", missing_qr),
        ("truncated header", vec![0u8; DNS_HEADER_SIZE - 1]),
    ] {
        // Saturate the rejection budget so the bounded loop terminates instead of
        // waiting out the deadline.
        let flood = vec![datagram; DNS_MAX_SPOOFED_REJECTIONS as usize];
        match receive_from_upstream(&query, &flood) {
            Ok(accepted) => panic!("{label} was accepted: {accepted:?}"),
            Err(error) => assert_eq!(
                error.kind(),
                std::io::ErrorKind::InvalidData,
                "{label} must be rejected as unmatched"
            ),
        }
    }
}

#[test]
fn udp_forwarding_accepts_the_real_answer_after_an_unmatched_one() {
    // The mismatch path must keep waiting under the same bounded budget: the
    // legitimate answer can still be in flight behind a stale datagram.
    let query = make_dns_query_packet("example.com", 1);
    let mut stale = response_from_question_packet(&query, DNS_FLAG_QR | DNS_FLAG_RD);
    stale[1] ^= 0xFF;
    let real = response_from_question_packet(&query, DNS_FLAG_QR | DNS_FLAG_RD);

    let received = receive_from_upstream(&query, &[stale, real.clone()])
        .expect("the matching answer must still be accepted");
    assert_eq!(received, real);
}

#[test]
fn unmatched_udp_responses_stay_within_the_rejection_budget() {
    let query = make_dns_query_packet("example.com", 1);
    let mut stale = response_from_question_packet(&query, DNS_FLAG_QR | DNS_FLAG_RD);
    stale[0] ^= 0xFF;
    let flood = vec![stale; DNS_MAX_SPOOFED_REJECTIONS as usize + 4];

    let error = receive_from_upstream(&query, &flood)
        .expect_err("a flood of unmatched responses must be bounded");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn expired_dns_deadline_is_rejected_before_socket_wait() {
    let error =
        remaining_until(Instant::now() - Duration::from_millis(1)).expect_err("expired deadline");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn fallback_deadlines_are_checked_before_each_transport() {
    let query = make_dns_query_packet("example.com", 1);
    let client = build_doh_client().expect("DoH client");
    let doh_result = resolve_via_doh_endpoints_until(
        &query,
        &["https://127.0.0.1:1/dns-query".to_string()],
        &client,
        tokio::time::Instant::now() - Duration::from_millis(1),
    )
    .await;
    assert!(matches!(doh_result, Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Doh))));

    let udp_result = resolve_via_dns_upstreams_until(
        &query,
        &[Ipv4Addr::LOCALHOST],
        Instant::now() - Duration::from_millis(1),
    );
    assert!(matches!(udp_result, Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Udp))));
}

#[tokio::test]
async fn plain_dns_blocking_boundary_returns_at_aggregate_deadline() {
    let started = Instant::now();
    let result = run_dns_blocking_with_deadline(Instant::now() + Duration::from_millis(40), || {
        std::thread::sleep(Duration::from_millis(200));
        Ok::<_, DnsProxyError>(())
    })
    .await;

    assert!(matches!(result, Err(DnsProxyError::DeadlineExceeded(DnsForwardingStage::Udp))));
    assert!(started.elapsed() < Duration::from_millis(180));
}

#[tokio::test]
async fn test_process_dns_query_with_no_resolvers_returns_servfail() {
    let pkt = make_dns_query_packet("example.com", 1);
    let config = DnsProxyConfig {
        doh_endpoints: vec![],
        upstream_resolvers: vec![],
        use_doh: false,
        ..Default::default()
    };
    let result = process_dns_query(&pkt, &config).await.unwrap();
    assert_eq!(result[3] & 0x0F, DNS_RCODE_SERVFAIL);
}

#[tokio::test]
async fn test_doh_client_is_cached_and_shared() {
    // The cached client must be built once and reused on subsequent
    // calls. After the first call the cache slot must be populated;
    // the second call must succeed without rebuilding.
    // Use a numeric endpoint so this cache-only test never enters the
    // host resolver. Endpoint hostname resolution remains a production
    // startup contract owned by `for_client_endpoints`.
    let config = DnsProxyConfig {
        doh_endpoints: vec!["https://127.0.0.1/dns-query".to_string()],
        upstream_resolvers: Vec::new(),
        use_doh: true,
        listen_port: 53,
        admission: DnsAdmissionConfig::client_default(),
        doh_client: Arc::new(parking_lot::Mutex::new(None)),
    };
    // Before first call: cache is empty.
    assert!(!config.doh_client_inner(), "cache must be empty initially");
    let _c1 = config.doh_client().unwrap();
    // After first call: cache is populated.
    assert!(config.doh_client_inner(), "cache must be populated after first call");
    // A cloned config must observe the same cache and reuse its client.
    let shared_config = config.clone();
    assert!(shared_config.doh_client_inner(), "cloned config must share the cache");
    let _c2 = shared_config.doh_client().unwrap();
    assert!(config.doh_client_inner(), "cache must remain populated");
}

#[tokio::test]
async fn test_process_dns_query_doh_failure_returns_servfail_not_nxdomain() {
    // When DoH is enabled but all endpoints fail, the proxy must return
    // SERVFAIL rather than fabricating a negative answer.
    let pkt = make_dns_query_packet("example.com", 1);
    let config = DnsProxyConfig {
        doh_endpoints: vec!["https://invalid.localhost.invalid/dns-query".to_string()],
        upstream_resolvers: vec![],
        use_doh: true,
        ..Default::default()
    };
    let result = process_dns_query(&pkt, &config).await;
    assert!(result.is_ok(), "DoH failure should return SERVFAIL, not error");
    let response = result.unwrap();
    assert_eq!(response[3] & 0x0F, DNS_RCODE_SERVFAIL, "response should be SERVFAIL");
}

#[test]
fn dns_admission_defaults_are_explicit_and_invalid_values_fail_closed() {
    let client = DnsAdmissionConfig::client_default();
    assert_eq!(client.max_in_flight, 2);
    assert_eq!(client.global_pps, 100);
    assert_eq!(client.max_identities, 4);
    assert!(client.validate().is_ok());

    let mut invalid = client;
    invalid.max_identities = 0;
    assert!(matches!(invalid.validate(), Err(DnsAdmissionConfigError::Zero("max_identities"))));
}

#[test]
fn dns_admission_prunes_idle_identity_with_explicit_clock() {
    let source = qf_common::time_source::test_support::ManualTimeSource::new(
        Instant::now(),
        std::time::SystemTime::UNIX_EPOCH,
    );
    let clock = ProtocolClock::from_source(source.clone());
    let mut config = DnsAdmissionConfig::client_default();
    config.idle_timeout = Duration::from_secs(2);
    let admission = DnsAdmission::try_new_with_clock(config, &clock).expect("admission config");
    let identity = DnsAdmissionIdentity::Session(7);
    let permit = admission.try_acquire(identity).expect("first DNS admission");
    drop(permit);
    assert_eq!(admission.snapshot().tracked_identities, 1);

    source.advance(Duration::from_secs(3));
    assert_eq!(admission.prune_idle(), 1);
    assert_eq!(admission.snapshot().tracked_identities, 0);
}
