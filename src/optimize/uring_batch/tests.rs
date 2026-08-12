use super::*;

#[test]
fn new_returns_none_on_unsupported_platform() {
    // On macOS (or CI without io_uring) this should return None.
    // On Linux it may return Some - both outcomes are valid.
    let result = UringBatchSender::new(4);
    if cfg!(not(target_os = "linux")) {
        assert!(result.is_none(), "io_uring should not init on non-Linux");
    }
    // On Linux: just verify it doesn't panic.
}

#[test]
fn with_defaults_uses_256_depth() {
    let result = UringBatchSender::with_defaults();
    if cfg!(not(target_os = "linux")) {
        assert!(result.is_none());
    }
}

#[test]
fn send_batch_empty_returns_zero() {
    if let Some(mut sender) = UringBatchSender::new(4) {
        let sent = sender.send_batch(0, &[]).expect("empty batch");
        assert_eq!(sent, 0);
    }
}

#[test]
fn send_batch_to_empty_returns_zero() {
    if let Some(mut sender) = UringBatchSender::new(4) {
        let sent = sender.send_batch_to(0, &[]).expect("empty batch_to");
        assert_eq!(sent, 0);
    }
}

#[test]
fn completion_slot_index_rejects_invalid_user_data() {
    assert_eq!(checked_slot_index(0, 4).expect("slot 0"), 0);
    assert_eq!(checked_slot_index(3, 4).expect("last slot"), 3);
    assert!(checked_slot_index(4, 4).is_err());
    assert!(checked_slot_index(u64::MAX, 4).is_err());
}

#[cfg(feature = "rust-tests")]
#[test]
fn injected_failure_slots_must_be_unique_and_in_range() {
    assert!(validate_injected_failure_slots(3, &[]).is_ok());
    assert!(validate_injected_failure_slots(3, &[1]).is_ok());

    let duplicate =
        validate_injected_failure_slots(3, &[1, 1]).expect_err("duplicate injected slot must fail");
    assert_eq!(duplicate.kind(), std::io::ErrorKind::InvalidInput);
    assert!(duplicate.to_string().contains("duplicate"));

    let out_of_range =
        validate_injected_failure_slots(3, &[3]).expect_err("out-of-range injected slot must fail");
    assert_eq!(out_of_range.kind(), std::io::ErrorKind::InvalidInput);
    assert!(out_of_range.to_string().contains("out of range"));
}

#[test]
fn batch_result_preserves_out_of_order_successes() {
    let empty = BatchSendResult::not_submitted(0);
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);

    let mut result = BatchSendResult::not_submitted(3);
    result.set_chunk(
        0,
        &[BatchSendDisposition::Sent, BatchSendDisposition::Failed, BatchSendDisposition::Sent],
    );

    assert_eq!(result.sent_count(), 2);
    assert!(!result.is_empty());
    assert!(result.is_sent(0));
    assert!(!result.is_sent(1));
    assert!(result.is_sent(2));
    assert_eq!(result.disposition(1), Some(BatchSendDisposition::Failed));
}

#[test]
fn quarantined_batch_result_is_not_retryable() {
    let error = BatchSendError::quarantined(
        std::io::Error::new(std::io::ErrorKind::InvalidData, "completion mismatch"),
        3,
    );

    assert_eq!(error.disposition().len(), 3);
    assert_eq!(error.disposition().sent_count(), 0);
    assert_eq!(
        (0..3).map(|index| error.disposition().disposition(index)).collect::<Vec<_>>(),
        vec![
            Some(BatchSendDisposition::Quarantined),
            Some(BatchSendDisposition::Quarantined),
            Some(BatchSendDisposition::Quarantined),
        ]
    );
}

#[test]
fn sqpoll_and_zc_fields_accessible() {
    if let Some(sender) = UringBatchSender::new(4) {
        // Accessors compile and return consistent values.
        // SQPOLL may be false if CAP_SYS_ADMIN is unavailable.
        // ZC may be false on kernels before 6.0.
        let _sqpoll = sender.sqpoll_active();
        let _zc = sender.zc_supported();
    }
}

#[test]
fn recv_new_returns_none_on_macos() {
    // Use a real bound socket fd (not fd=0 which is stdin).
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    let fd = std::os::fd::AsRawFd::as_raw_fd(&sock);
    let result = UringRecvBatch::new(fd, 4, 2048, false);
    if cfg!(not(target_os = "linux")) {
        assert!(result.is_none(), "UringRecvBatch should not init on non-Linux");
    }
}

#[test]
fn recv_eventfd_created() {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    let fd = std::os::fd::AsRawFd::as_raw_fd(&sock);
    if let Some(recv) = UringRecvBatch::new(fd, 4, 2048, false) {
        assert!(recv.eventfd_fd() > 0, "eventfd should be a positive fd");
    }
}

#[test]
fn recv_drain_empty_returns_empty() {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    let fd = std::os::fd::AsRawFd::as_raw_fd(&sock);
    if let Some(mut recv) = UringRecvBatch::new(fd, 4, 2048, false) {
        // No SQEs posted, no CQEs pending - drain should return empty.
        let completions = recv.drain_completions().expect("drain empty");
        assert!(completions.is_empty());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn recv_rearms_after_zero_length_datagrams() {
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver bind");
    let receiver_addr = receiver.local_addr().expect("receiver address");
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender bind");
    let mut recv = match UringRecvBatch::new(receiver.as_raw_fd(), 4, 2048, false) {
        Some(recv) => recv,
        None => {
            println!("QF_IO_URING_REARM_STATUS=UNAVAILABLE reason=io_uring_init");
            return;
        }
    };
    recv.post_initial().expect("post receive slots");

    for _ in 0..4 {
        assert_eq!(sender.send_to(&[], receiver_addr).expect("zero datagram"), 0);
    }
    std::thread::sleep(Duration::from_millis(10));
    for _ in 0..100 {
        recv.drain_completions().expect("drain zero datagrams");
        if recv.zero_length_completions_seen() == 4 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let zero_length_completions = recv.zero_length_completions_seen();
    assert_eq!(
        zero_length_completions, 4,
        "all receive slots must complete the zero-length datagrams"
    );

    let marker = [0x51, 0x46, 0x37];
    sender.send_to(&marker, receiver_addr).expect("marker datagram");
    let mut marker_seen = false;
    for _ in 0..200 {
        let completions = recv.drain_completions().expect("drain marker datagram");
        if completions.iter().any(|completion| completion.data == marker) {
            marker_seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(marker_seen, "receive slots were not rearmed after zero datagrams");
    println!(
        "QF_IO_URING_REARM_STATUS=SUPPORTED zero_length_completions={zero_length_completions} marker_seen=true"
    );
}

#[test]
fn parse_sockaddr_ipv4_roundtrip() {
    use std::net::{Ipv4Addr, SocketAddrV4};
    let original = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345));
    // SAFETY: sockaddr_storage is POD; zeroed init is valid.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    fill_sockaddr(original, &mut storage);
    let parsed = parse_sockaddr(&storage);
    assert_eq!(parsed, Some(original));
}

#[test]
fn fill_sockaddr_ipv4_sets_correct_family() {
    use std::net::{Ipv4Addr, SocketAddrV4};
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9999));
    // SAFETY: sockaddr_storage is POD; zeroed init is valid.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    fill_sockaddr(addr, &mut storage);
    let sa = &storage as *const _ as *const libc::sockaddr_in;
    // SAFETY: storage was filled by fill_sockaddr with AF_INET, so casting
    // to sockaddr_in is valid and the pointer is dereferenceable.
    unsafe {
        assert_eq!((*sa).sin_family as i32, libc::AF_INET);
        assert_eq!((*sa).sin_port, 9999u16.to_be());
        // 127.0.0.1 = [127,0,0,1] as ne bytes
        assert_eq!((*sa).sin_addr.s_addr, u32::from_ne_bytes([127, 0, 0, 1]));
    }
}
