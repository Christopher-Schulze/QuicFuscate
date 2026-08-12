use super::*;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

#[cfg(unix)]
#[test]
fn unix_raw_result_contract_rejects_zero_and_oversized_counts() {
    assert_eq!(validate_raw_read_result(8, 8, "read").unwrap(), 8);
    assert_eq!(validate_raw_write_progress(8, 8, "write").unwrap(), 8);

    let zero_read = validate_raw_read_result(0, 8, "read").expect_err("zero read must fail");
    assert_eq!(zero_read.kind(), io::ErrorKind::UnexpectedEof);
    let oversized_read =
        validate_raw_read_result(9, 8, "read").expect_err("oversized read must fail");
    assert_eq!(oversized_read.kind(), io::ErrorKind::InvalidData);
    let zero_write = validate_raw_write_progress(0, 8, "write").expect_err("zero write must fail");
    assert_eq!(zero_write.kind(), io::ErrorKind::WriteZero);
    let oversized_write =
        validate_raw_write_progress(9, 8, "write").expect_err("oversized write must fail");
    assert_eq!(oversized_write.kind(), io::ErrorKind::InvalidData);
}

#[cfg(unix)]
#[test]
fn unix_interface_name_parser_requires_bounded_terminated_utf8() {
    assert_eq!(parse_bounded_interface_name(b"utun4\0", 6).unwrap(), "utun4");
    for (bytes, reported_len) in
        [(&b"utun4\0"[..], 0), (&b"utun4\0"[..], 7), (&b"utun4x"[..], 6), (&[0xff, 0][..], 2)]
    {
        assert!(
            parse_bounded_interface_name(bytes, reported_len).is_err(),
            "malformed interface name must fail: bytes={bytes:?} len={reported_len}"
        );
    }

    #[cfg(target_os = "linux")]
    {
        let mut ifr_name = [0 as libc::c_char; 16];
        for (slot, byte) in ifr_name.iter_mut().zip(b"tun0\0") {
            *slot = *byte as libc::c_char;
        }
        assert_eq!(parse_kernel_interface_name(&ifr_name).unwrap(), "tun0");
        ifr_name.fill(b'x' as libc::c_char);
        assert!(parse_kernel_interface_name(&ifr_name).is_err());
    }
}

#[cfg(unix)]
#[test]
fn unix_close_failure_is_reported_and_descriptor_number_is_terminalized() {
    let mut fd = 42;
    let error = close_owned_fd_with(&mut fd, |_fd| Err(io::Error::from_raw_os_error(libc::EIO)))
        .expect_err("injected close failure must be observable");
    assert_eq!(error.raw_os_error(), Some(libc::EIO));
    assert_eq!(fd, -1);
    assert!(close_owned_fd_with(&mut fd, |_fd| {
        Err(io::Error::other("close must not be retried"))
    })
    .is_ok());
}

struct DummyTun {
    reads: Mutex<Vec<Vec<u8>>>,
    writes: AtomicUsize,
    last_write_len: AtomicUsize,
    mtu: AtomicU16,
    refuse_mtu_updates: bool,
    fail_reads: bool,
}

impl DummyTun {
    fn with_reads(reads: Vec<Vec<u8>>) -> Self {
        Self {
            reads: Mutex::new(reads),
            writes: AtomicUsize::new(0),
            last_write_len: AtomicUsize::new(0),
            mtu: AtomicU16::new(1500),
            refuse_mtu_updates: false,
            fail_reads: false,
        }
    }

    fn refusing_mtu_updates() -> Self {
        Self { refuse_mtu_updates: true, ..Self::with_reads(Vec::new()) }
    }

    fn failing_reads() -> Self {
        Self { fail_reads: true, ..Self::with_reads(Vec::new()) }
    }
}

impl TunDevice for DummyTun {
    fn name(&self) -> &str {
        "dummy"
    }

    fn mtu(&self) -> u16 {
        self.mtu.load(Ordering::Relaxed)
    }

    fn set_mtu(&self, mtu: u16) -> io::Result<()> {
        if self.refuse_mtu_updates {
            return Err(io::Error::other("dummy backend refused MTU update"));
        }
        self.mtu.store(mtu, Ordering::Relaxed);
        Ok(())
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.fail_reads {
            return Err(io::Error::other("dummy read failure"));
        }
        let mut reads = self.reads.lock().expect("dummy read lock poisoned");
        if reads.is_empty() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let data = reads.remove(0);
        let len = data.len().min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);
        Ok(len)
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.last_write_len.store(buf.len(), Ordering::Relaxed);
        Ok(buf.len())
    }
}

#[derive(Clone, Copy)]
enum FaultReadResult {
    Zero,
    Oversized,
}

#[derive(Clone, Copy)]
enum FaultWriteResult {
    Zero,
    Short(usize),
    Oversized,
}

/// Fault-injection backend representing a device returned by an external
/// factory. The wrapper, rather than the backend, owns result validation.
struct FaultTun {
    read_result: FaultReadResult,
    write_result: FaultWriteResult,
}

impl FaultTun {
    fn new(read_result: FaultReadResult, write_result: FaultWriteResult) -> Self {
        Self { read_result, write_result }
    }
}

impl TunDevice for FaultTun {
    fn name(&self) -> &str {
        "fault-injection"
    }

    fn mtu(&self) -> u16 {
        1500
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self.read_result {
            FaultReadResult::Zero => Ok(0),
            FaultReadResult::Oversized => Ok(buf.len().saturating_add(1)),
        }
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        match self.write_result {
            FaultWriteResult::Zero => Ok(0),
            FaultWriteResult::Short(len) => Ok(len.min(buf.len())),
            FaultWriteResult::Oversized => Ok(buf.len().saturating_add(1)),
        }
    }
}

#[test]
fn external_factory_read_result_contract_rejects_zero_and_oversized_lengths() {
    for (read_result, expected_kind) in [
        (FaultReadResult::Zero, io::ErrorKind::UnexpectedEof),
        (FaultReadResult::Oversized, io::ErrorKind::InvalidData),
    ] {
        let tun = TunInterface::from_device_for_test(
            Box::new(FaultTun::new(read_result, FaultWriteResult::Zero)),
            crate::optimize::global_pool(),
            false,
        );
        let error = match tun.read_block() {
            Err(error) => error,
            Ok((_block, _len)) => panic!("invalid external read result must fail"),
        };
        assert_eq!(error.kind(), expected_kind);
    }
}

#[test]
fn external_factory_write_result_contract_rejects_zero_short_and_oversized_results() {
    let packet = [0x45u8; 32];
    for (write_result, expected_kind) in [
        (FaultWriteResult::Zero, io::ErrorKind::WriteZero),
        (FaultWriteResult::Short(1), io::ErrorKind::WriteZero),
        (FaultWriteResult::Oversized, io::ErrorKind::InvalidData),
    ] {
        let tun = TunInterface::from_device_for_test(
            Box::new(FaultTun::new(FaultReadResult::Zero, write_result)),
            crate::optimize::global_pool(),
            false,
        );
        let error = tun.write(&packet).expect_err("invalid external write result must fail");
        assert_eq!(error.kind(), expected_kind);
    }
}

#[test]
fn write_packet_rejects_short_external_factory_result() {
    let mut tun = TunInterface::from_device_for_test(
        Box::new(FaultTun::new(FaultReadResult::Zero, FaultWriteResult::Short(1))),
        crate::optimize::global_pool(),
        false,
    );
    let error = tun
        .write_packet(&[0x45u8; 32])
        .expect_err("client write_packet must reject a short backend write");
    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
}

#[test]
fn owned_packet_constructor_rejects_oversized_length() {
    let block = PooledBlock::new(crate::optimize::global_pool());
    let capacity = block.len();
    let error = match TunPacket::new(block, capacity.saturating_add(1)) {
        Ok(_) => panic!("owned packet constructor must reject an oversized length"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn shared_config_rejects_incomplete_address_pairs_and_ipv6_floor() {
    let missing_netmask = TunConfig {
        ip: Some("10.8.0.1".parse().expect("valid test IPv4 address")),
        ..TunConfig::default()
    };
    assert!(matches!(validate_tun_config(&missing_netmask), Err(TunError::Config(_))));

    let missing_prefix =
        TunConfig { ip6: Some(Ipv6Addr::LOCALHOST), mtu: 1500, ..TunConfig::default() };
    assert!(matches!(validate_tun_config(&missing_prefix), Err(TunError::Config(_))));

    let low_ipv6_mtu = TunConfig {
        ip6: Some(Ipv6Addr::LOCALHOST),
        prefix6: Some(128),
        mtu: 1279,
        ..TunConfig::default()
    };
    assert!(matches!(validate_tun_config(&low_ipv6_mtu), Err(TunError::Config(_))));
}

#[cfg(any(
    target_os = "ios",
    all(target_os = "windows", not(feature = "tun-windows")),
    not(any(target_os = "linux", target_os = "macos", target_os = "windows", target_os = "ios"))
))]
#[test]
fn platform_without_native_tun_backend_fails_closed() {
    let result = open_platform_tun(&TunConfig::default());

    assert!(matches!(result, Err(TunError::Config(_)) | Err(TunError::Unsupported)));
}

#[test]
fn external_factory_mtu_is_reconciled_and_misreport_fails() {
    let device = DummyTun::with_reads(Vec::new());
    let verified = TunInterface::reconcile_device_mtu(&device, 1400, false)
        .expect("factory MTU update must be verified");
    assert_eq!(verified, 1400);
    assert_eq!(device.mtu(), 1400);

    let refusing = DummyTun::refusing_mtu_updates();
    assert!(matches!(
        TunInterface::reconcile_device_mtu(&refusing, 1400, false),
        Err(TunError::Io(_))
    ));
}

#[test]
fn read_block_returns_packet_payload() {
    let pool = crate::optimize::global_pool();
    let packet = vec![0x45, 0x00, 0x00, 0x20, 0xaa, 0xbb];
    let tun = TunInterface::from_device_for_test(
        Box::new(DummyTun::with_reads(vec![packet.clone()])),
        pool,
        false,
    );

    let (block, len) = tun.read_block().expect("read_block must succeed");
    assert_eq!(len, packet.len());
    assert_eq!(&block[..len], packet.as_slice());
}

#[test]
fn read_block_failure_returns_the_pool_block() {
    let pool = Arc::new(crate::optimize::MemoryPool::new(1, 2_048));
    let before = pool.accounting_snapshot();
    let tun = TunInterface::from_device_for_test(
        Box::new(DummyTun::failing_reads()),
        Arc::clone(&pool),
        false,
    );

    assert!(tun.read_block().is_err());
    assert_eq!(pool.accounting_snapshot(), before);
}

#[test]
fn custom_backend_defaults_to_owned_blocking_reader_contract() {
    let device = DummyTun::with_reads(Vec::new());
    assert_eq!(device.read_contract(), TunReadContract::Blocking);

    let tun =
        TunInterface::from_device_for_test(Box::new(device), crate::optimize::global_pool(), false);
    assert_eq!(tun.read_contract(), TunReadContract::Blocking);
}

#[test]
fn reader_loop_with_shutdown_exits_after_callback_requests_stop() {
    let pool = crate::optimize::global_pool();
    let shutdown = AtomicBool::new(false);
    let tun = TunInterface::from_device_for_test(
        Box::new(DummyTun::with_reads(vec![vec![0x45, 0, 0, 20]])),
        pool,
        false,
    );
    let mut packets = 0;

    tun.reader_loop_with_shutdown(&shutdown, |packet| {
        assert_eq!(packet, [0x45, 0, 0, 20]);
        packets += 1;
        shutdown.store(true, Ordering::Release);
    })
    .expect("reader must exit cleanly after shutdown");

    assert_eq!(packets, 1);
    assert!(shutdown.load(Ordering::Acquire));
}

#[test]
fn owned_reader_loop_transfers_pooled_packet_without_copying() {
    let pool = crate::optimize::global_pool();
    let shutdown = AtomicBool::new(false);
    let tun = TunInterface::from_device_for_test(
        Box::new(DummyTun::with_reads(vec![vec![0x45, 0, 0, 20]])),
        pool,
        false,
    );
    let mut packets = 0;

    tun.reader_loop_with_shutdown_owned(&shutdown, |packet| {
        assert_eq!(packet.as_slice(), [0x45, 0, 0, 20]);
        assert_eq!(packet.len(), 4);
        packets += 1;
        shutdown.store(true, Ordering::Release);
    })
    .expect("owned reader must exit cleanly after shutdown");

    assert_eq!(packets, 1);
    assert!(shutdown.load(Ordering::Acquire));
}

#[cfg(unix)]
struct PollWaitTun {
    read_fd: std::os::fd::RawFd,
    write_fd: std::os::fd::RawFd,
    ready: Arc<AtomicBool>,
}

#[cfg(unix)]
impl TunDevice for PollWaitTun {
    fn name(&self) -> &str {
        "poll-wait"
    }

    fn mtu(&self) -> u16 {
        1500
    }

    fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
        self.ready.store(true, Ordering::Release);
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    }

    fn write(&self, _buf: &[u8]) -> io::Result<usize> {
        Ok(0)
    }

    fn raw_fd(&self) -> Option<std::os::fd::RawFd> {
        Some(self.read_fd)
    }
}

#[cfg(unix)]
impl Drop for PollWaitTun {
    fn drop(&mut self) {
        // SAFETY: both descriptors were returned by one successful pipe
        // call and are owned exclusively by this test device.
        unsafe {
            libc::close(self.read_fd);
            libc::close(self.write_fd);
        }
    }
}

#[cfg(unix)]
#[test]
fn reader_loop_with_shutdown_interrupts_poll_wait() {
    let mut fds = [-1; 2];
    // SAFETY: `fds` points to storage for the two descriptors requested by
    // libc::pipe and remains valid for the duration of the call.
    let result = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(result, 0, "pipe must be created for poll shutdown test");

    let ready = Arc::new(AtomicBool::new(false));
    let shutdown = Arc::new(AtomicBool::new(false));
    let reader_shutdown = Arc::clone(&shutdown);
    let tun = TunInterface::from_device_for_test(
        Box::new(PollWaitTun { read_fd: fds[0], write_fd: fds[1], ready: Arc::clone(&ready) }),
        crate::optimize::global_pool(),
        false,
    );
    let reader =
        std::thread::spawn(move || tun.reader_loop_with_shutdown(&reader_shutdown, |_| {}));

    for _ in 0..1_000 {
        if ready.load(Ordering::Acquire) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(ready.load(Ordering::Acquire), "reader must reach the poll wait");
    shutdown.store(true, Ordering::Release);
    assert!(reader.join().expect("reader thread must join").is_ok());
}

#[test]
fn set_mtu_publishes_only_after_backend_success() {
    let pool = crate::optimize::global_pool();
    let tun =
        TunInterface::from_device_for_test(Box::new(DummyTun::with_reads(Vec::new())), pool, false);

    tun.set_mtu(1280).expect("dummy MTU update must succeed");

    assert_eq!(tun.mtu(), 1280);
}

#[test]
fn ipv6_rejects_subminimum_mtu_before_backend_mutation() {
    let pool = crate::optimize::global_pool();
    let tun = TunInterface::from_device_for_test_with_ipv6(
        Box::new(DummyTun::with_reads(Vec::new())),
        pool,
        false,
    );

    let error = tun.set_mtu(1279).expect_err("IPv6 MTU below 1280 must be rejected");

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(tun.mtu(), 1500);
}

#[test]
fn write_packet_direct_fallback_returns_device_length() {
    let pool = crate::optimize::global_pool();
    let tun_dev = DummyTun::with_reads(Vec::new());
    let expected_len = 64usize;
    let mut tun = TunInterface::from_device_for_test(Box::new(tun_dev), pool, false);
    let payload = vec![0u8; expected_len];
    let written = tun.write_packet(&payload).expect("write_packet must succeed");
    assert_eq!(written, expected_len);
}

#[test]
fn write_packet_accepts_intentionally_unaligned_ipv4_slice() {
    let pool = crate::optimize::global_pool();
    let mut tun =
        TunInterface::from_device_for_test(Box::new(DummyTun::with_reads(Vec::new())), pool, false);
    let mut backing = [0u8; 64];
    let base = backing.as_ptr() as usize;
    let offset = (1..4)
        .find(|candidate| !(base + *candidate).is_multiple_of(std::mem::align_of::<u32>()))
        .expect("an offset must produce an unaligned u32 address");
    let packet = &mut backing[offset..];
    packet[..20].copy_from_slice(&[
        0x45, 0x03, 0x00, 0x3c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 1,
    ]);
    let before =
        crate::optimize::telemetry::IP_V4_PACKETS.load(std::sync::atomic::Ordering::Relaxed);

    let written = tun.write_packet(packet).expect("unaligned packet must be writable");

    assert_eq!(written, packet.len());
    assert!(
        crate::optimize::telemetry::IP_V4_PACKETS.load(std::sync::atomic::Ordering::Relaxed)
            > before,
        "unaligned IPv4 packet must reach header telemetry"
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn bmi2_parser_accepts_intentionally_unaligned_ipv4_slice_when_supported() {
    if !is_x86_feature_detected!("bmi2") {
        eprintln!(
            "SIMD_SKIP test=bmi2_parser_accepts_intentionally_unaligned_ipv4_slice_when_supported required=bmi2"
        );
        return;
    }

    let pool = crate::optimize::global_pool();
    let tun =
        TunInterface::from_device_for_test(Box::new(DummyTun::with_reads(Vec::new())), pool, false);
    let mut backing = [0u8; 64];
    let base = backing.as_ptr() as usize;
    let offset = (1..4)
        .find(|candidate| !(base + *candidate).is_multiple_of(std::mem::align_of::<u32>()))
        .expect("an offset must produce an unaligned u32 address");
    let packet = &mut backing[offset..];
    packet[..20].copy_from_slice(&[
        0x45, 0x03, 0x00, 0x3c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 1,
    ]);

    // SAFETY: The runtime check above proves BMI2 support for this call,
    // and the parser uses an alignment-safe four-byte load.
    unsafe { tun.parse_ip_header_bmi2(packet) };
}

#[cfg(target_arch = "x86_64")]
#[test]
fn bmi2_dispatch_requires_profile_and_runtime_feature_intersection() {
    let selecting_profiles = [
        CpuProfile::X86_P0a,
        CpuProfile::X86_P0b,
        CpuProfile::X86_P1a,
        CpuProfile::X86_P1b,
        CpuProfile::X86_P1f,
        CpuProfile::X86_P2a,
        CpuProfile::X86_P2b,
        CpuProfile::X86_P3a,
        CpuProfile::X86_P3b,
        CpuProfile::X86_P3c,
        CpuProfile::X86_P3d,
        CpuProfile::X86_P3e,
        CpuProfile::X86_P4a,
        CpuProfile::X86_P4b,
    ];
    let without_bmi2 = CpuFeatures::default();
    let with_bmi2 = CpuFeatures { bmi2: true, ..CpuFeatures::default() };

    for profile in selecting_profiles {
        assert!(!bmi2_parser_is_allowed(profile, &without_bmi2));
        assert!(bmi2_parser_is_allowed(profile, &with_bmi2));
    }

    for profile in [
        CpuProfile::ARM_A0,
        CpuProfile::ARM_A1a,
        CpuProfile::ARM_A1b,
        CpuProfile::ARM_A1c,
        CpuProfile::ARM_A1d,
        CpuProfile::ARM_A2,
        CpuProfile::Apple_M,
        CpuProfile::RVV,
        CpuProfile::Scalar,
    ] {
        assert!(!bmi2_parser_is_allowed(profile, &with_bmi2));
    }
}

#[test]
fn fastpath_mode_space_is_off_auto_only() {
    assert_eq!(FastpathMode::parse("auto"), FastpathMode::Auto);
    assert_eq!(FastpathMode::parse("off"), FastpathMode::Off);
    assert_eq!(FastpathMode::parse("legacy-token"), FastpathMode::Auto);
}
