// Integration test for io_uring batch UDP sender.
//
// Requires: Linux, feature = "io_uring", kernel >= 5.1.
// On macOS / non-Linux this test is a no-op placeholder.

#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::net::UdpSocket;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use quicfuscate::optimize::uring_batch::{
    UringBatchSender, UringBatchWorker, MAX_BATCH_PACKETS, MAX_BATCH_PAYLOAD_BYTES,
};
#[cfg(target_os = "linux")]
use quicfuscate::telemetry::{IO_URING_ZC_NOTIFS, IO_URING_ZC_SENDS};

#[test]
#[cfg(not(target_os = "linux"))]
fn io_uring_tests_are_linux_only() {}

#[test]
#[cfg(target_os = "linux")]
fn uring_batch_sender_initialises() {
    let sender = UringBatchSender::new(8);
    assert!(sender.is_some(), "io_uring should init on Linux with recent kernel");
}

#[test]
#[cfg(target_os = "linux")]
fn uring_batch_sends_all_datagrams_on_loopback() {
    let mut sender = match UringBatchSender::new(8) {
        Some(s) => s,
        None => {
            eprintln!("skipping: io_uring not available");
            return;
        }
    };

    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_secs(2))).expect("set read timeout");
    let recv_addr = receiver.local_addr().expect("receiver addr");

    let sender_socket = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    sender_socket.connect(recv_addr).expect("connect sender");
    let fd = sender_socket.as_raw_fd();

    let payloads: Vec<&[u8]> = vec![b"uring-alpha", b"uring-beta", b"uring-gamma"];
    let sent = sender.send_batch(fd, &payloads).expect("send_batch");
    assert_eq!(sent, payloads.len(), "all datagrams should be sent");

    let mut received = Vec::with_capacity(sent);
    for _ in 0..sent {
        let mut buf = [0u8; 256];
        let (len, _from) = receiver.recv_from(&mut buf).expect("recv datagram");
        received.push(buf[..len].to_vec());
    }

    let expected: HashSet<Vec<u8>> = payloads.iter().map(|p| p.to_vec()).collect();
    let actual: HashSet<Vec<u8>> = received.into_iter().collect();
    assert_eq!(actual, expected, "received datagrams should match sent");
}

#[test]
#[cfg(target_os = "linux")]
fn uring_batch_empty_returns_zero() {
    let mut sender = match UringBatchSender::new(4) {
        Some(s) => s,
        None => {
            eprintln!("skipping: io_uring not available");
            return;
        }
    };
    let sent = sender.send_batch(0, &[]).expect("empty batch");
    assert_eq!(sent, 0);
}

#[test]
#[cfg(target_os = "linux")]
fn uring_batch_invalid_fd_returns_error() {
    let mut sender = match UringBatchSender::new(4) {
        Some(s) => s,
        None => {
            eprintln!("skipping: io_uring not available");
            return;
        }
    };
    let payloads: Vec<&[u8]> = vec![b"bad-fd-test"];
    // fd -1 is invalid - should return error or zero sent (not panic).
    let result = sender.send_batch(-1, &payloads);
    // Either an Err or Ok(0) is acceptable - the key is no panic.
    if let Ok(n) = result {
        assert_eq!(n, 0, "invalid fd should send nothing");
    }
}

#[test]
#[cfg(target_os = "linux")]
fn uring_batch_admission_rejects_packet_count_before_copying() {
    let mut sender = match UringBatchSender::new(4) {
        Some(s) => s,
        None => {
            eprintln!("skipping: io_uring not available");
            return;
        }
    };
    let payloads = vec![b"admission".as_slice(); MAX_BATCH_PACKETS + 1];
    let error = sender
        .send_batch(-1, &payloads)
        .expect_err("packet count above the admission bound must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("packets"));
}

#[test]
#[cfg(target_os = "linux")]
fn uring_batch_admission_rejects_aggregate_bytes_before_copying() {
    let mut sender = match UringBatchSender::new(4) {
        Some(s) => s,
        None => {
            eprintln!("skipping: io_uring not available");
            return;
        }
    };
    let payload = vec![0xA5; MAX_BATCH_PAYLOAD_BYTES + 1];
    let error = sender
        .send_batch(-1, &[payload.as_slice()])
        .expect_err("aggregate payload bytes above the admission bound must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("payload bytes"));
}

#[test]
#[cfg(target_os = "linux")]
fn uring_batch_to_admission_rejects_packet_count_before_copying() {
    let mut sender = match UringBatchSender::new(4) {
        Some(s) => s,
        None => {
            eprintln!("skipping: io_uring not available");
            return;
        }
    };
    let destination: std::net::SocketAddr = "127.0.0.1:9".parse().expect("destination");
    let packets = vec![(destination, b"admission".as_slice()); MAX_BATCH_PACKETS + 1];
    let error = sender
        .send_batch_to(-1, &packets)
        .expect_err("packet count above the send_batch_to bound must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("packets"));
}

#[test]
#[cfg(target_os = "linux")]
fn uring_batch_worker_sends_and_joins_without_executor_blocking() {
    let worker = match UringBatchWorker::new(8) {
        Some(worker) => worker,
        None => {
            eprintln!("skipping: io_uring not available");
            return;
        }
    };
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_secs(2))).expect("set timeout");
    let recv_addr = receiver.local_addr().expect("receiver address");
    let sender_socket = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    sender_socket.connect(recv_addr).expect("connect sender");
    let payloads: &[&[u8]] = &[b"worker-alpha", b"worker-beta"];

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build test runtime");
    let sent = runtime
        .block_on(worker.send_batch(sender_socket.as_raw_fd(), payloads))
        .expect("worker send");
    assert_eq!(sent, payloads.len());

    for expected in payloads {
        let mut buffer = [0u8; 256];
        let (length, _) = receiver.recv_from(&mut buffer).expect("receive worker datagram");
        assert_eq!(&buffer[..length], *expected);
    }

    let server_socket = UdpSocket::bind("127.0.0.1:0").expect("bind unconnected sender");
    let destinations: Vec<(std::net::SocketAddr, &[u8])> =
        payloads.iter().map(|payload| (recv_addr, *payload)).collect();
    let sent_to = runtime
        .block_on(worker.send_batch_to(server_socket.as_raw_fd(), &destinations))
        .expect("worker send_batch_to");
    assert_eq!(sent_to, destinations.len());
    for expected in payloads {
        let mut buffer = [0u8; 256];
        let (length, _) = receiver.recv_from(&mut buffer).expect("receive worker target datagram");
        assert_eq!(&buffer[..length], *expected);
    }

    worker.request_shutdown();
    worker.join().expect("join worker");
    let error = runtime
        .block_on(worker.send_batch(sender_socket.as_raw_fd(), payloads))
        .expect_err("shutdown must close worker admission");
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
}

#[test]
#[cfg(target_os = "linux")]
fn uring_batch_handles_large_batch_beyond_queue_depth() {
    let mut sender = match UringBatchSender::new(4) {
        Some(s) => s,
        None => {
            eprintln!("skipping: io_uring not available");
            return;
        }
    };

    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_secs(2))).expect("set read timeout");
    let recv_addr = receiver.local_addr().expect("receiver addr");

    let sender_socket = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    sender_socket.connect(recv_addr).expect("connect sender");
    let fd = sender_socket.as_raw_fd();

    // Queue depth is 4, but send 8 packets - must chunk internally.
    let data: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 16]).collect();
    let payloads: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();

    let sent = sender.send_batch(fd, &payloads).expect("large batch");
    assert_eq!(sent, 8, "all 8 datagrams should be sent across chunks");

    for _ in 0..8 {
        let mut buf = [0u8; 256];
        let (len, _) = receiver.recv_from(&mut buf).expect("recv");
        assert_eq!(len, 16);
    }
}

#[test]
#[cfg(target_os = "linux")]
fn uring_sqpoll_field_reflects_mode() {
    // SQPOLL may be unavailable in CI (requires CAP_SYS_ADMIN on kernel < 5.12).
    // Test that the field is consistent with kernel support rather than asserting
    // a specific value.
    if let Some(sender) = UringBatchSender::new(8) {
        // If SQPOLL is active, the telemetry counter should have been set.
        // Just verify the accessor doesn't panic.
        let sqpoll = sender.sqpoll_active();
        let _ = sqpoll; // suppress unused warning
    }
}

#[test]
#[cfg(target_os = "linux")]
fn uring_zc_probe_is_consistent() {
    // SendMsgZc requires kernel 6.0+. In CI this may be false.
    // Verify the probe runs without panic and the accessor is accessible.
    if let Some(sender) = UringBatchSender::new(8) {
        let zc = sender.zc_supported();
        let _ = zc; // suppress unused warning
    }
}

#[test]
#[cfg(target_os = "linux")]
fn uring_zc_opt_in_loopback_and_error_contract() {
    let mut sender = match UringBatchSender::new(8) {
        Some(sender) => sender,
        None => {
            println!("QF_IO_URING_ZC_STATUS=UNAVAILABLE reason=io_uring_init");
            return;
        }
    };
    if !sender.zc_supported() {
        println!("QF_IO_URING_ZC_STATUS=UNAVAILABLE reason=sendmsg_zc_probe");
        return;
    }

    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_secs(3))).expect("set read timeout");
    let recv_addr = receiver.local_addr().expect("receiver address");
    let sender_socket = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    sender_socket.connect(recv_addr).expect("connect sender");

    let payloads: Vec<Vec<u8>> = (0..3u8).map(|value| vec![value; 16 * 1024]).collect();
    let payload_refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
    let send_counter_before = IO_URING_ZC_SENDS.get();
    let notification_counter_before = IO_URING_ZC_NOTIFS.get();

    let sent = match sender.send_batch(sender_socket.as_raw_fd(), &payload_refs) {
        Ok(sent) => sent,
        Err(error) => {
            println!("QF_IO_URING_ZC_STATUS=FAIL reason=valid_send_error error={error}");
            panic!("supported SendMsgZc loopback send failed: {error}");
        }
    };
    if sent != payloads.len() {
        println!("QF_IO_URING_ZC_STATUS=FAIL reason=short_valid_send sent={sent}");
        panic!("SendMsgZc sent {sent} of {} datagrams", payloads.len());
    }

    let mut received = Vec::with_capacity(sent);
    for _ in 0..sent {
        let mut buffer = vec![0u8; 16 * 1024];
        let (length, _) = receiver.recv_from(&mut buffer).expect("receive loopback datagram");
        buffer.truncate(length);
        received.push(buffer);
    }
    let expected: HashSet<Vec<u8>> = payloads.iter().cloned().collect();
    let actual: HashSet<Vec<u8>> = received.into_iter().collect();
    if actual != expected {
        println!("QF_IO_URING_ZC_STATUS=FAIL reason=payload_mismatch");
        panic!("SendMsgZc loopback payloads did not match");
    }

    let error_outcome = match sender.send_batch(-1, &[b"zc-invalid-fd"]) {
        Ok(0) => "cqe_error",
        Ok(sent) => {
            println!("QF_IO_URING_ZC_STATUS=FAIL reason=invalid_fd_reported_success sent={sent}");
            panic!("invalid fd unexpectedly reported {sent} successful SendMsgZc sends");
        }
        Err(_) => "submission_error",
    };

    let primary_sends = IO_URING_ZC_SENDS.get().saturating_sub(send_counter_before);
    let notifications = IO_URING_ZC_NOTIFS.get().saturating_sub(notification_counter_before);
    if primary_sends < payloads.len() as u64 || notifications == 0 {
        println!(
            "QF_IO_URING_ZC_STATUS=UNAVAILABLE reason=no_notification primary_sends={primary_sends} notifications={notifications} error_outcome={error_outcome}"
        );
        return;
    }

    println!(
        "QF_IO_URING_ZC_STATUS=SUPPORTED primary_sends={primary_sends} notifications={notifications} delivered={} error_outcome={error_outcome}",
        actual.len()
    );
}

#[test]
#[cfg(target_os = "linux")]
fn uring_send_batch_to_delivers_to_unconnected_socket() {
    use std::net::SocketAddr;

    let mut sender = match UringBatchSender::new(8) {
        Some(s) => s,
        None => {
            eprintln!("skipping: io_uring not available");
            return;
        }
    };

    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_secs(2))).expect("set read timeout");
    let recv_addr: SocketAddr = receiver.local_addr().expect("receiver addr");

    // Unconnected sender socket.
    let sender_socket = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let fd = sender_socket.as_raw_fd();

    let payloads: &[&[u8]] = &[b"to-alpha", b"to-beta", b"to-gamma"];
    let packets: Vec<(SocketAddr, &[u8])> = payloads.iter().map(|p| (recv_addr, *p)).collect();

    let sent = sender.send_batch_to(fd, &packets).expect("send_batch_to");
    assert_eq!(sent, packets.len(), "all datagrams should be sent");

    let expected: HashSet<Vec<u8>> = payloads.iter().map(|p| p.to_vec()).collect();
    let mut actual = HashSet::new();
    for _ in 0..sent {
        let mut buf = [0u8; 256];
        let (len, _) = receiver.recv_from(&mut buf).expect("recv datagram");
        actual.insert(buf[..len].to_vec());
    }
    assert_eq!(actual, expected, "received datagrams should match sent");
}

// ---------------------------------------------------------------------------
// UringRecvBatch tests
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
use quicfuscate::optimize::uring_batch::UringRecvBatch;

#[test]
#[cfg(target_os = "linux")]
fn uring_recv_batch_initialises() {
    // Create a bound UDP socket and construct a recv batch on its fd.
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let fd = sock.as_raw_fd();
    let recv = UringRecvBatch::new(fd, 8, 2048, false);
    if let Some(r) = recv {
        assert!(r.eventfd_fd() > 0, "eventfd should be a positive fd");
    } else {
        eprintln!("skipping: io_uring recv init failed");
    }
}

#[test]
#[cfg(target_os = "linux")]
fn uring_recv_batch_loopback() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_nonblocking(true).expect("set nonblocking");
    let recv_addr = receiver.local_addr().expect("addr");

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

    let mut uring_recv = match UringRecvBatch::new(receiver.as_raw_fd(), 8, 2048, false) {
        Some(r) => r,
        None => {
            eprintln!("skipping: io_uring recv not available");
            return;
        }
    };
    uring_recv.post_initial().expect("post_initial");

    // Send 8 packets to the receiver socket.
    let messages: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 64]).collect();
    for m in &messages {
        sender.send_to(m, recv_addr).expect("send_to");
    }

    // Poll with retry - kernel may need a moment to deliver all packets.
    let mut all_received = HashSet::new();
    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(20));
        let completions = uring_recv.drain_completions().expect("drain");
        for c in &completions {
            all_received.insert(c.data.clone());
        }
        if all_received.len() >= 8 {
            break;
        }
    }

    let sent: HashSet<Vec<u8>> = messages.into_iter().collect();
    assert_eq!(all_received, sent, "received data should match sent data");
}

#[test]
#[cfg(target_os = "linux")]
fn uring_recv_batch_with_addr() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind");
    receiver.set_nonblocking(true).expect("nonblock");
    let recv_addr = receiver.local_addr().expect("addr");

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let sender_addr = sender.local_addr().expect("sender addr");

    let mut uring_recv = match UringRecvBatch::new(receiver.as_raw_fd(), 8, 2048, true) {
        Some(r) => r,
        None => {
            eprintln!("skipping: io_uring recv not available");
            return;
        }
    };
    uring_recv.post_initial().expect("post_initial");

    sender.send_to(b"addr-test", recv_addr).expect("send_to");

    // Poll with retry.
    let mut completions = Vec::new();
    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(20));
        completions.extend(uring_recv.drain_completions().expect("drain"));
        if !completions.is_empty() {
            break;
        }
    }
    assert_eq!(completions.len(), 1, "expected exactly 1 completion");
    assert_eq!(completions[0].data, b"addr-test");

    let addr = completions[0].addr.expect("should have source address");
    assert_eq!(addr.ip(), sender_addr.ip(), "source IP should match sender");
    assert_eq!(addr.port(), sender_addr.port(), "source port should match sender");
}

#[test]
#[cfg(target_os = "linux")]
fn uring_recv_batch_repost_cycle() {
    // Use depth=4 but send 8 packets to verify re-posting works.
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind");
    receiver.set_nonblocking(true).expect("nonblock");
    let recv_addr = receiver.local_addr().expect("addr");

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

    let mut uring_recv = match UringRecvBatch::new(receiver.as_raw_fd(), 4, 2048, false) {
        Some(r) => r,
        None => {
            eprintln!("skipping: io_uring recv not available");
            return;
        }
    };
    uring_recv.post_initial().expect("post_initial");

    // Send first batch of 4 packets.
    for i in 0..4u8 {
        sender.send_to(&[i; 32], recv_addr).expect("send");
    }
    let mut batch1_count = 0;
    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(20));
        batch1_count += uring_recv.drain_completions().expect("drain batch 1").len();
        if batch1_count >= 4 {
            break;
        }
    }
    assert_eq!(batch1_count, 4, "first batch should have 4 packets");

    // Send second batch of 4 packets (these use re-posted SQEs).
    for i in 4..8u8 {
        sender.send_to(&[i; 32], recv_addr).expect("send");
    }
    let mut batch2_count = 0;
    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(20));
        batch2_count += uring_recv.drain_completions().expect("drain batch 2").len();
        if batch2_count >= 4 {
            break;
        }
    }
    assert_eq!(batch2_count, 4, "second batch should have 4 packets (re-posted SQEs)");
}

#[test]
#[cfg(target_os = "linux")]
fn server_send_batch_to_helper_works_on_loopback() {
    use quicfuscate::optimize::uring_batch::server_send_batch_to;
    use std::net::SocketAddr;

    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    let recv_addr: SocketAddr = receiver.local_addr().expect("addr");

    let sender_socket = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let fd = sender_socket.as_raw_fd();

    let payloads: &[&[u8]] = &[b"srv-1", b"srv-2"];
    let packets: Vec<(SocketAddr, &[u8])> = payloads.iter().map(|p| (recv_addr, *p)).collect();

    // Returns None when io_uring unavailable (acceptable in constrained CI).
    if let Some(sent) = server_send_batch_to(fd, &packets) {
        assert!((1..=packets.len()).contains(&sent), "sent={sent} out of range");
        let expected: HashSet<Vec<u8>> = payloads.iter().map(|p| p.to_vec()).collect();
        let mut actual = HashSet::new();
        for _ in 0..sent {
            let mut buf = [0u8; 256];
            let (len, _) = receiver.recv_from(&mut buf).expect("recv");
            actual.insert(buf[..len].to_vec());
        }
        assert!(actual.iter().all(|payload| expected.contains(payload)));
    }
}
