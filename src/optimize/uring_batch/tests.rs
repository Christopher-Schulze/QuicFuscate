use super::*;

#[test]
fn env_flag_disables_only_on_explicit_falsy() {
    assert!(env_flag_disables(Some("0")));
    assert!(env_flag_disables(Some("off")));
    assert!(env_flag_disables(Some("false")));
    assert!(env_flag_disables(Some(" NO ")));
    assert!(!env_flag_disables(None));
    assert!(!env_flag_disables(Some("1")));
    assert!(!env_flag_disables(Some("on")));
    // Unparseable values retain the enabled default (same contract as
    // EnvSnapshot::flag).
    assert!(!env_flag_disables(Some("maybe")));
}

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

#[cfg(target_os = "linux")]
#[test]
fn recv_gro_preserves_segment_boundaries() {
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver bind");
    let receiver_addr = receiver.local_addr().expect("receiver address");
    if qf_transport_udp::enable_udp_gro_fd(receiver.as_raw_fd()).is_err() {
        println!("QF_IO_URING_GRO_STATUS=UNAVAILABLE reason=udp_gro_sockopt");
        return;
    }
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender bind");
    if !qf_transport_udp::probe_udp_gso(sender.as_raw_fd()) {
        println!("QF_IO_URING_GRO_STATUS=UNAVAILABLE reason=udp_gso_sockopt");
        return;
    }

    let mut recv = match UringRecvBatch::new(receiver.as_raw_fd(), 8, 65_535, false) {
        Some(recv) => recv,
        None => {
            println!("QF_IO_URING_GRO_STATUS=UNAVAILABLE reason=io_uring_init");
            return;
        }
    };
    recv.post_initial().expect("post receive slots");

    // One GSO sendmsg: three full segments plus a short tail. Whether the
    // kernel coalesces them back into one receive is timing-dependent; the
    // assertion only requires that boundaries and payload bytes survive.
    let payload: Vec<u8> = (0..1850u32).map(|i| (i % 251) as u8).collect();
    qf_transport_udp::send_udp_segment(sender.as_raw_fd(), receiver_addr, &payload, 600)
        .expect("gso sendmsg");

    let mut segments: Vec<Vec<u8>> = Vec::new();
    for _ in 0..500 {
        for completion in recv.drain_completions().expect("drain gro") {
            segments.push(completion.as_slice().to_vec());
        }
        if segments.iter().map(Vec::len).sum::<usize>() >= payload.len() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    let received: usize = segments.iter().map(Vec::len).sum();
    assert_eq!(received, payload.len(), "segment bytes lost or duplicated");
    let mut flat = Vec::with_capacity(received);
    for segment in &segments {
        assert!(segment.len() <= 600, "segment {} exceeds the GSO size", segment.len());
        flat.extend_from_slice(segment);
    }
    assert_eq!(flat, payload, "segment order or payload corrupted");
    println!("QF_IO_URING_GRO_STATUS=SUPPORTED segments={}", segments.len());
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

#[cfg(target_os = "linux")]
#[test]
fn recv_multishot_delivers_and_recycles_buffers() {
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver bind");
    let receiver_addr = receiver.local_addr().expect("receiver address");
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender bind");
    let mut recv = match crate::optimize::uring_batch::UringRecvMultishot::new(
        receiver.as_raw_fd(),
        8,
        2048,
    ) {
        Some(recv) => recv,
        None => {
            println!("QF_IO_URING_MULTISHOT_STATUS=UNAVAILABLE reason=init_or_buf_ring");
            return;
        }
    };
    recv.post_initial().expect("arm multishot recv");
    assert!(recv.is_armed(), "multishot request must be armed after post_initial");

    // Three waves of four datagrams over an eight-entry ring prove both
    // delivery and bid recycling: every wave needs the ring refilled.
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for wave in 0..3u8 {
        for seq in 0..4u8 {
            let payload = [0x51, 0x46, wave, seq];
            sender.send_to(&payload, receiver_addr).expect("send datagram");
        }
        for _ in 0..200 {
            for completion in recv.drain_completions().expect("drain multishot") {
                seen.push(completion.as_slice().to_vec());
            }
            if seen.iter().filter(|d| d.len() == 4 && d[2] == wave).count() == 4 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(seen.len(), 12, "expected 12 datagrams, got {}", seen.len());
    for wave in 0..3u8 {
        for seq in 0..4u8 {
            let expected = vec![0x51, 0x46, wave, seq];
            assert!(seen.contains(&expected), "missing payload wave={wave} seq={seq}");
        }
    }
    println!(
        "QF_IO_URING_MULTISHOT_STATUS=SUPPORTED delivered=12 starved={} armed={}",
        recv.ring_starved_total(),
        recv.is_armed()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn recv_multishot_zero_length_and_rearm() {
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver bind");
    let receiver_addr = receiver.local_addr().expect("receiver address");
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender bind");
    let mut recv = match crate::optimize::uring_batch::UringRecvMultishot::new(
        receiver.as_raw_fd(),
        8,
        2048,
    ) {
        Some(recv) => recv,
        None => {
            println!("QF_IO_URING_MULTISHOT_ZERO_STATUS=UNAVAILABLE reason=init");
            return;
        }
    };
    recv.post_initial().expect("arm multishot recv");

    for _ in 0..3 {
        sender.send_to(&[], receiver_addr).expect("zero datagram");
    }
    for _ in 0..200 {
        recv.drain_completions().expect("drain zero datagrams");
        if recv.zero_length_completions_seen() == 3 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(recv.zero_length_completions_seen(), 3);

    // After zero-length completions (and any request termination + re-arm the
    // kernel performed), a payload datagram must still be delivered.
    let marker = [0x51, 0x46, 0x37];
    sender.send_to(&marker, receiver_addr).expect("marker datagram");
    let mut marker_seen = false;
    for _ in 0..300 {
        let completions = recv.drain_completions().expect("drain marker");
        if completions.iter().any(|c| c.as_slice() == marker) {
            marker_seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(marker_seen, "multishot recv did not recover after zero datagrams");
}

/// Flood benchmark for TODO-1007: `UringRecvBatch` (per-slot RecvMsg re-arm,
/// with UDP_GRO) vs `UringRecvMultishot` (one RecvMulti SQE + provided-buffer
/// ring, no GRO possible). Measures drain calls per datagram (syscall
/// amortization proxy) and wall time for a fixed datagram count.
///
/// Gated behind `QF_URING_BENCH=1` and `#[ignore]` - it is a measurement,
/// not a correctness gate. Run on a quiet Linux host:
///   QF_URING_BENCH=1 cargo test --features rust-tests,io_uring \
///     recv_flood_bench -- --ignored --nocapture
#[cfg(target_os = "linux")]
#[test]
#[ignore]
fn recv_flood_bench_batch_vs_multishot() {
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    if std::env::var("QF_URING_BENCH").as_deref() != Ok("1") {
        println!("QF_URING_BENCH=1 not set - skipping flood bench");
        return;
    }

    const DATAGRAMS: usize = 20_000;
    const PAYLOAD: usize = 1_200;

    fn set_rcvbuf(fd: std::os::fd::RawFd, bytes: i32) {
        // SAFETY: setsockopt on a live fd with a plain i32 optval.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &bytes as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
        }
    }

    fn run_flood<Flood, Drain>(flood: Flood, mut drain: Drain) -> (usize, usize, Duration)
    where
        Flood: FnOnce() -> usize,
        Drain: FnMut() -> usize,
    {
        let started = Instant::now();
        let sent = flood();
        let mut received = 0usize;
        let mut drain_calls = 0usize;
        let deadline = started + Duration::from_secs(30);
        while received < sent && Instant::now() < deadline {
            received += drain();
            drain_calls += 1;
        }
        (received, drain_calls, started.elapsed())
    }

    // Shared sender: one thread floods `count` fixed-size datagrams.
    let flood = |addr: std::net::SocketAddr| {
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender bind");
        let payload = vec![0xabu8; PAYLOAD];
        let mut sent = 0usize;
        while sent < DATAGRAMS {
            match sender.send_to(&payload, addr) {
                Ok(_) => sent += 1,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::yield_now();
                }
                Err(e) => panic!("flood send failed: {e}"),
            }
        }
        sent
    };

    // --- Mode A: UringRecvBatch with UDP_GRO (the production default) ---
    let (a_recv, a_calls, a_time) = {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("A bind");
        let addr = receiver.local_addr().unwrap();
        set_rcvbuf(receiver.as_raw_fd(), 64 * 1024 * 1024);
        let _gro = qf_transport_udp::enable_udp_gro_fd(receiver.as_raw_fd());
        let mut recv = crate::optimize::uring_batch::UringRecvBatch::new(
            receiver.as_raw_fd(),
            64,
            65_535,
            false,
        )
        .expect("UringRecvBatch init");
        recv.post_initial().expect("A arm");
        let (tx_done, rx_done) = std::sync::mpsc::channel::<usize>();
        let flood_handle = std::thread::spawn(move || tx_done.send(flood(addr)).unwrap());
        let mut errs = 0u64;
        let result = run_flood(
            || rx_done.recv().unwrap_or(DATAGRAMS),
            || match recv.drain_completions() {
                Ok(c) => c.len(),
                Err(e) => {
                    errs += 1;
                    if errs <= 5 {
                        println!("batch drain error: {e}");
                    }
                    0
                }
            },
        );
        let _ = flood_handle.join();
        println!("batch_gro drain_errors={errs}");
        result
    };

    // --- Mode B: UringRecvMultishot (provided-buffer ring, no GRO) ---
    let (b_recv, b_calls, b_time) = {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("B bind");
        let addr = receiver.local_addr().unwrap();
        set_rcvbuf(receiver.as_raw_fd(), 64 * 1024 * 1024);
        let mut recv = crate::optimize::uring_batch::UringRecvMultishot::new(
            receiver.as_raw_fd(),
            256,
            65_535,
        )
        .expect("UringRecvMultishot init");
        recv.post_initial().expect("B arm");
        let (tx_done, rx_done) = std::sync::mpsc::channel::<usize>();
        let flood_handle = std::thread::spawn(move || tx_done.send(flood(addr)).unwrap());
        let mut errs = 0u64;
        let result = run_flood(
            || rx_done.recv().unwrap_or(DATAGRAMS),
            || match recv.drain_completions() {
                Ok(c) => c.len(),
                Err(e) => {
                    errs += 1;
                    if errs <= 5 {
                        println!("multishot drain error: {e}");
                    }
                    0
                }
            },
        );
        let _ = flood_handle.join();
        println!(
            "multishot drain_errors={errs} starved={} armed={}",
            recv.ring_starved_total(),
            recv.is_armed()
        );
        result
    };

    println!(
        "QF_URING_BENCH_RESULT batch_gro: datagrams={a_recv} drain_calls={a_calls} \
         per_datagram={:.3} wall_ms={} | multishot: datagrams={b_recv} drain_calls={b_calls} \
         per_datagram={:.3} wall_ms={}",
        a_calls as f64 / a_recv.max(1) as f64,
        a_time.as_millis(),
        b_calls as f64 / b_recv.max(1) as f64,
        b_time.as_millis(),
    );
}
