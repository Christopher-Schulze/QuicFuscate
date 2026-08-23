use super::*;
use crate::interface::TunConfig;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
const NATIVE_LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 253, 0, 1);
#[cfg(all(target_os = "windows", feature = "tun-windows"))]
const NATIVE_PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 253, 0, 2);
#[cfg(all(target_os = "windows", feature = "tun-windows"))]
const NATIVE_LOCAL_IP6: Ipv6Addr = Ipv6Addr::new(0xfd53, 0, 0, 0, 0, 0, 0, 1);
#[cfg(all(target_os = "windows", feature = "tun-windows"))]
const NATIVE_PEER_IP6: Ipv6Addr = Ipv6Addr::new(0xfd53, 0, 0, 0, 0, 0, 0, 2);
#[cfg(all(target_os = "windows", feature = "tun-windows"))]
const NATIVE_MTU: u16 = 1420;
#[cfg(all(target_os = "windows", feature = "tun-windows"))]
const NATIVE_TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(all(target_os = "windows", feature = "tun-windows"))]
const NATIVE_BLOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(750);

#[cfg(not(target_os = "windows"))]
#[test]
fn non_windows_returns_unsupported() {
    let cfg = TunConfig {
        name: Some("quicfuscate-test".to_string()),
        ip: Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
        netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
        mtu: 1500,
        ..TunConfig::default()
    };
    let res = WintunDevice::new(&cfg);
    assert!(
        matches!(res, Err(TunError::Unsupported)),
        "expected Unsupported on non-Windows, got {:?}",
        res
    );
}

#[test]
fn config_validation_rejects_low_mtu() {
    // MTU below the IPv4 minimum must be rejected before any DLL load is
    // attempted, so this is portable across platforms.
    let cfg = TunConfig {
        name: Some("quicfuscate-test".to_string()),
        ip: Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
        netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
        mtu: 500,
        ..TunConfig::default()
    };
    let res = WintunDevice::new(&cfg);
    assert!(
        matches!(res, Err(TunError::Config(_))),
        "expected Config error for low MTU, got {:?}",
        res
    );
}

/// Windows-only: the cleanup state type only exists on that target.
#[cfg(target_os = "windows")]
#[test]
fn wintun_cleanup_state_retains_failed_resources_for_retry() {
    let mut state = WintunCleanupState {
        shutdown_signaled: true,
        session_ended: true,
        adapter_closed: true,
        ..WintunCleanupState::default()
    };
    state.record_failure("shutdown event close", "ERROR_INVALID_HANDLE");
    state.record_failure("wintun.dll unload", "ERROR_MOD_NOT_FOUND");

    assert!(!state.is_complete());
    assert_eq!(state.pending_resources(), "shutdown event, wintun.dll");
    assert_eq!(state.last_error.as_deref(), Some("wintun.dll unload: ERROR_MOD_NOT_FOUND"));

    state.shutdown_event_closed = true;
    assert!(!state.is_complete());
    state.library_unloaded = true;
    assert!(state.is_complete());
    assert_eq!(state.pending_resources(), "none");
}

#[test]
fn wintun_device_send_sync_contract_is_compile_checked() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<WintunDevice>();
}

#[cfg(target_os = "windows")]
#[test]
fn dynamic_loading_fails_gracefully_without_dll() {
    let res = imp::load_missing_test_library();
    assert!(
        matches!(res, Err(TunError::Config(_))),
        "expected Config error for a guaranteed-missing DLL, got {:?}",
        res
    );
}

#[test]
fn ipv6_config_rejects_subminimum_mtu() {
    let cfg = TunConfig {
        ip6: Some(Ipv6Addr::LOCALHOST),
        prefix6: Some(128),
        mtu: 1279,
        ..TunConfig::default()
    };
    assert!(
        matches!(validate_config(&cfg), Err(TunError::Config(_))),
        "IPv6 Wintun configuration must reject MTUs below 1280"
    );
}

#[test]
fn adapter_name_rejects_interior_nul() {
    let cfg = TunConfig { name: Some("quicfuscate\0hidden".to_string()), ..TunConfig::default() };
    assert!(
        matches!(validate_config(&cfg), Err(TunError::Config(_))),
        "Wintun adapter names must reject interior NUL"
    );
}

#[test]
fn address_family_validation_rejects_ambiguous_config() {
    let ipv6_in_ipv4 =
        TunConfig { ip: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), ..TunConfig::default() };
    assert!(matches!(validate_config(&ipv6_in_ipv4), Err(TunError::Config(_))));

    let ipv6_netmask =
        TunConfig { netmask: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), ..TunConfig::default() };
    assert!(matches!(validate_config(&ipv6_netmask), Err(TunError::Config(_))));

    let orphan_prefix = TunConfig { prefix6: Some(64), ip6: None, ..TunConfig::default() };
    assert!(matches!(validate_config(&orphan_prefix), Err(TunError::Config(_))));

    let orphan_ipv4 =
        TunConfig { ip: Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))), ..TunConfig::default() };
    assert!(matches!(validate_config(&orphan_ipv4), Err(TunError::Config(_))));

    let non_contiguous_netmask = TunConfig {
        ip: Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
        netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 0, 255, 0))),
        ..TunConfig::default()
    };
    assert!(matches!(validate_config(&non_contiguous_netmask), Err(TunError::Config(_))));

    let orphan_ipv6 =
        TunConfig { ip6: Some(Ipv6Addr::LOCALHOST), mtu: 1280, ..TunConfig::default() };
    assert!(matches!(validate_config(&orphan_ipv6), Err(TunError::Config(_))));

    let invalid_prefix = TunConfig {
        ip6: Some(Ipv6Addr::LOCALHOST),
        prefix6: Some(129),
        mtu: 1280,
        ..TunConfig::default()
    };
    assert!(matches!(validate_config(&invalid_prefix), Err(TunError::Config(_))));
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
#[test]
fn interface_mtu_script_reads_the_nl_mtu_property() {
    let script = imp::interface_mtu_script("QuicFuscate-CI", "IPv4");

    assert!(script.contains("$interface.NlMtu)"));
    assert!(!script.contains("$interface.NlMtuBytes)"));
}

#[test]
fn ipv6_config_is_accepted_by_validation() {
    // A dual-stack config with a valid MTU must pass validation (the
    // unsupported/platform error, if any, comes from the backend, not from
    // MTU validation).
    let cfg = TunConfig {
        name: Some("quicfuscate-dual".to_string()),
        ip: Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
        netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
        ip6: Some(Ipv6Addr::new(0xfd, 0, 0, 0, 0, 0, 0, 1)),
        prefix6: Some(64),
        mtu: 1500,
        ..TunConfig::default()
    };
    let res = WintunDevice::new(&cfg);
    // Must not be a Config("MTU") rejection.
    if let Err(TunError::Config(msg)) = &res {
        assert!(
            !msg.contains("MTU"),
            "dual-stack config should not be rejected on MTU grounds: {}",
            msg
        );
    }
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
fn native_config(name: &str) -> TunConfig {
    TunConfig {
        name: Some(name.to_string()),
        ip: Some(IpAddr::V4(NATIVE_LOCAL_IP)),
        netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
        ip6: Some(NATIVE_LOCAL_IP6),
        prefix6: Some(64),
        mtu: NATIVE_MTU,
        ..TunConfig::default()
    }
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
fn powershell_succeeds(script: &str) -> bool {
    std::process::Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
fn powershell_output(script: &str) -> io::Result<std::process::Output> {
    std::process::Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
struct NativeFirewallRule {
    name: String,
    active: bool,
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
impl NativeFirewallRule {
    fn allow_udp(name: String, local_port: u16) -> Self {
        let escaped_name = name.replace('\'', "''");
        let script = format!(
            "$existing = Get-NetFirewallRule -DisplayName '{escaped_name}' \
                 -ErrorAction SilentlyContinue; \
             if ($null -ne $existing) {{ exit 1 }}; \
             New-NetFirewallRule -DisplayName '{escaped_name}' -Direction Inbound \
                 -Action Allow -Protocol UDP -LocalAddress '{NATIVE_LOCAL_IP}' \
                 -LocalPort {local_port} -Profile Any -Enabled True \
                 -ErrorAction Stop | Out-Null"
        );
        assert!(
            powershell_succeeds(&script),
            "failed to create the exact native Wintun test firewall permit"
        );
        Self { name, active: true }
    }

    fn remove(mut self) {
        assert!(
            self.remove_inner(),
            "failed to remove the exact native Wintun test firewall permit"
        );
        self.active = false;
    }

    fn remove_inner(&self) -> bool {
        let escaped_name = self.name.replace('\'', "''");
        let script = format!(
            "Get-NetFirewallRule -DisplayName '{escaped_name}' -ErrorAction SilentlyContinue | \
             Remove-NetFirewallRule -ErrorAction Stop"
        );
        powershell_succeeds(&script)
    }
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
impl Drop for NativeFirewallRule {
    fn drop(&mut self) {
        if self.active && !self.remove_inner() {
            eprintln!("failed to remove native Wintun test firewall permit '{}'", self.name);
        }
    }
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
fn wait_for_powershell(script: &str, expected_success: bool) {
    let deadline = std::time::Instant::now() + NATIVE_TEST_TIMEOUT;
    loop {
        let (succeeded, diagnostic) = match powershell_output(script) {
            Ok(output) => {
                let diagnostic = format!(
                    "status={:?}\nstdout={}\nstderr={}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stdout).trim(),
                    String::from_utf8_lossy(&output.stderr).trim()
                );
                (output.status.success(), diagnostic)
            }
            Err(error) => (false, format!("PowerShell execution failed: {error}")),
        };
        if succeeded == expected_success {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "PowerShell state did not converge before the native Wintun deadline:\n\
             {diagnostic}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
fn adapter_state_script(name: &str, mtu: u16) -> String {
    let escaped_name = name.replace('\'', "''");
    format!(
        "$adapter = Get-NetAdapter -Name '{escaped_name}' -IncludeHidden -ErrorAction SilentlyContinue; \
         if ($null -eq $adapter) {{ exit 1 }}; \
         $ipv4 = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 \
             -ErrorAction SilentlyContinue | Where-Object IPAddress -eq '{NATIVE_LOCAL_IP}'; \
         $ipv6 = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 \
             -ErrorAction SilentlyContinue | Where-Object IPAddress -eq '{NATIVE_LOCAL_IP6}'; \
         $interface4 = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 \
             -NlMtuBytes {mtu} -ErrorAction SilentlyContinue; \
         $interface6 = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 \
             -NlMtuBytes {mtu} -ErrorAction SilentlyContinue; \
         [ordered]@{{ \
             adapter = $null -ne $adapter; \
             if_index = if ($null -ne $adapter) {{ $adapter.ifIndex }} else {{ $null }}; \
             ipv4 = @($ipv4).Count; \
             ipv6 = @($ipv6).Count; \
             mtu4 = @($interface4).Count; \
             mtu6 = @($interface6).Count \
         }} | ConvertTo-Json -Compress | Write-Output; \
         if ($null -eq $ipv4 -or $null -eq $ipv6 -or $null -eq $interface4 -or \
             $null -eq $interface6) {{ exit 1 }}; exit 0"
    )
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
fn adapter_absent_script(name: &str) -> String {
    let escaped_name = name.replace('\'', "''");
    format!(
        "$adapter = Get-NetAdapter -Name '{escaped_name}' -IncludeHidden \
             -ErrorAction SilentlyContinue; \
         if ($null -eq $adapter) {{ exit 0 }} else {{ exit 1 }}"
    )
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (words, _) = header.as_chunks::<2>();
    for word in words {
        sum += u16::from_be_bytes(*word) as u32;
    }
    while sum > u16::MAX as u32 {
        sum = (sum & u16::MAX as u32) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
fn udp_ipv4_packet(
    source_ip: Ipv4Addr,
    source_port: u16,
    destination_ip: Ipv4Addr,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8usize + payload.len();
    let total_len = 20usize + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0x5146u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source_ip.octets());
    packet[16..20].copy_from_slice(&destination_ip.octets());
    let checksum = ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    packet
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
fn is_udp_ipv4_packet(
    packet: &[u8],
    source_ip: Ipv4Addr,
    source_port: u16,
    destination_ip: Ipv4Addr,
    destination_port: u16,
    payload: &[u8],
) -> bool {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return false;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 8 {
        return false;
    }
    let udp_len = usize::from(u16::from_be_bytes([packet[header_len + 4], packet[header_len + 5]]));
    if udp_len < 8 || packet.len() < header_len + udp_len {
        return false;
    }
    packet[12..16] == source_ip.octets()
        && packet[16..20] == destination_ip.octets()
        && packet[header_len..header_len + 2] == source_port.to_be_bytes()
        && packet[header_len + 2..header_len + 4] == destination_port.to_be_bytes()
        && packet[header_len + 8..header_len + udp_len] == *payload
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
fn is_udp_ipv6_packet(
    packet: &[u8],
    source_ip: Ipv6Addr,
    source_port: u16,
    destination_ip: Ipv6Addr,
    destination_port: u16,
    payload: &[u8],
) -> bool {
    if packet.len() < 48 || packet[0] >> 4 != 6 || packet[6] != 17 {
        return false;
    }
    let udp_len = usize::from(u16::from_be_bytes([packet[44], packet[45]]));
    if udp_len < 8 || packet.len() < 40 + udp_len {
        return false;
    }
    packet[8..24] == source_ip.octets()
        && packet[24..40] == destination_ip.octets()
        && packet[40..42] == source_port.to_be_bytes()
        && packet[42..44] == destination_port.to_be_bytes()
        && packet[48..40 + udp_len] == *payload
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
fn wait_for_native_packet(
    receiver: &std::sync::mpsc::Receiver<Vec<u8>>,
    timeout: std::time::Duration,
    predicate: impl Fn(&[u8]) -> bool,
) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match receiver.recv_timeout(remaining) {
            Ok(packet) if predicate(&packet) => return true,
            Ok(_) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return false,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("native Wintun capture reader disconnected")
            }
        }
    }
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
fn bind_native_udp(address: IpAddr) -> std::net::UdpSocket {
    let endpoint = std::net::SocketAddr::new(address, 0);
    let deadline = std::time::Instant::now() + NATIVE_TEST_TIMEOUT;
    loop {
        match std::net::UdpSocket::bind(endpoint) {
            Ok(socket) => return socket,
            Err(error)
                if error.kind() == io::ErrorKind::AddrNotAvailable
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => panic!("bind native WFP UDP probe at {endpoint}: {error}"),
        }
    }
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
fn assert_native_udp_blocked(
    socket: &std::net::UdpSocket,
    target: std::net::SocketAddr,
    payload: &[u8],
    receiver: &std::sync::mpsc::Receiver<Vec<u8>>,
    predicate: impl Fn(&[u8]) -> bool,
) {
    match socket.send_to(payload, target) {
        Ok(length) => {
            assert_eq!(length, payload.len());
            assert!(
                !wait_for_native_packet(receiver, NATIVE_BLOCK_TIMEOUT, predicate),
                "blocked UDP packet reached the Wintun ring"
            );
        }
        Err(error) => assert_eq!(
            error.kind(),
            io::ErrorKind::PermissionDenied,
            "WFP block returned an unrelated socket error: {error}"
        ),
    }
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
fn assert_native_udp_permitted(
    socket: &std::net::UdpSocket,
    target: std::net::SocketAddr,
    payload: &[u8],
    receiver: &std::sync::mpsc::Receiver<Vec<u8>>,
    predicate: impl Fn(&[u8]) -> bool,
) {
    assert_eq!(
        socket.send_to(payload, target).expect("permitted native UDP send failed"),
        payload.len()
    );
    assert!(
        wait_for_native_packet(receiver, NATIVE_TEST_TIMEOUT, predicate),
        "permitted UDP packet did not reach the Wintun ring"
    );
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
struct NativeKillSwitchCleanup;

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
impl Drop for NativeKillSwitchCleanup {
    fn drop(&mut self) {
        let _ = crate::native_wfp_test_support::KillSwitch::cleanup_stale_rules();
    }
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
#[test]
#[ignore = "requires an administrator and an integrity-checked upstream wintun.dll"]
fn native_adapter_packet_io_and_bounded_close() {
    use std::net::UdpSocket;
    use std::sync::{mpsc, Arc};
    use std::time::{Duration, Instant};

    const OUTBOUND_PORT: u16 = 35_801;
    const OUTBOUND_PAYLOAD: &[u8] = b"quicfuscate-wintun-outbound";
    const INBOUND_PAYLOAD: &[u8] = b"quicfuscate-wintun-inbound";

    let adapter_name = format!("QuicFuscate-CI-{}", std::process::id());
    let device = Arc::new(
        WintunDevice::new(&native_config(&adapter_name))
            .expect("verified Wintun must create the native adapter"),
    );
    assert_eq!(device.name(), adapter_name);
    assert_eq!(device.mtu(), NATIVE_MTU);
    assert_ne!(device.adapter_luid(), 0);

    let capabilities = crate::interface::tun_capabilities();
    assert!(capabilities.built_in);
    assert!(!capabilities.supports_zero_copy);
    assert!(!capabilities.supports_raw_fd);
    wait_for_powershell(&adapter_state_script(&adapter_name, NATIVE_MTU), true);
    device.set_mtu(1400).expect("native Wintun MTU update must succeed");
    assert_eq!(device.mtu(), 1400);
    wait_for_powershell(&adapter_state_script(&adapter_name, 1400), true);
    device.set_mtu(NATIVE_MTU).expect("native Wintun MTU restore must succeed");
    wait_for_powershell(&adapter_state_script(&adapter_name, NATIVE_MTU), true);

    let socket = UdpSocket::bind((NATIVE_LOCAL_IP, 0))
        .expect("native Wintun address must accept a UDP binding");
    socket
        .set_read_timeout(Some(NATIVE_TEST_TIMEOUT))
        .expect("UDP receive timeout must be configurable");
    let local_port = socket.local_addr().expect("UDP socket must expose its local address").port();
    let firewall_rule = NativeFirewallRule::allow_udp(
        format!("QuicFuscate-CI-Wintun-{}", std::process::id()),
        local_port,
    );

    let reader_device = Arc::clone(&device);
    let (outbound_tx, outbound_rx) = mpsc::sync_channel(1);
    let outbound_reader = std::thread::spawn(move || {
        let mut packet = [0u8; 65_535];
        loop {
            match reader_device.read(&mut packet) {
                Ok(length)
                    if is_udp_ipv4_packet(
                        &packet[..length],
                        NATIVE_LOCAL_IP,
                        local_port,
                        NATIVE_PEER_IP,
                        OUTBOUND_PORT,
                        OUTBOUND_PAYLOAD,
                    ) =>
                {
                    let _ = outbound_tx.send(Ok(()));
                    return;
                }
                Ok(_) => {}
                Err(error) => {
                    let _ = outbound_tx.send(Err(error));
                    return;
                }
            }
        }
    });
    socket
        .send_to(OUTBOUND_PAYLOAD, (NATIVE_PEER_IP, OUTBOUND_PORT))
        .expect("Windows must route the outbound UDP packet into Wintun");
    let outbound_result = outbound_rx.recv_timeout(NATIVE_TEST_TIMEOUT);
    if outbound_result.is_err() {
        device.close().expect("timed-out Wintun reader cleanup must succeed");
    }
    outbound_reader.join().expect("outbound reader panicked");
    outbound_result
        .expect("Wintun outbound packet capture timed out")
        .expect("Wintun outbound reader failed");

    let inbound = udp_ipv4_packet(
        NATIVE_PEER_IP,
        OUTBOUND_PORT,
        NATIVE_LOCAL_IP,
        local_port,
        INBOUND_PAYLOAD,
    );
    assert_eq!(device.write(&inbound).expect("Wintun inbound injection failed"), inbound.len());
    let mut received = [0u8; 256];
    let (received_len, source) =
        socket.recv_from(&mut received).expect("Windows UDP stack did not receive Wintun input");
    assert_eq!(&received[..received_len], INBOUND_PAYLOAD);
    assert_eq!(source.ip(), IpAddr::V4(NATIVE_PEER_IP));
    assert_eq!(source.port(), OUTBOUND_PORT);
    firewall_rule.remove();

    let blocked_device = Arc::clone(&device);
    let (blocked_tx, blocked_rx) = mpsc::sync_channel(1);
    let blocked_reader = std::thread::spawn(move || {
        let mut packet = [0u8; 65_535];
        loop {
            match blocked_device.read(&mut packet) {
                Ok(_) => continue,
                Err(error) => {
                    let _ = blocked_tx.send(error.kind());
                    return;
                }
            }
        }
    });
    std::thread::sleep(Duration::from_millis(100));
    let close_started = Instant::now();
    device.close().expect("Wintun close must succeed");
    assert!(
        device.cleanup_state_for_test().is_complete(),
        "successful close must release every Wintun owner"
    );
    assert!(
        close_started.elapsed() <= Duration::from_secs(3),
        "Wintun close exceeded its bounded deadline"
    );
    let close_error = blocked_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("blocked Wintun read was not released by close");
    assert!(
        matches!(close_error, io::ErrorKind::Interrupted | io::ErrorKind::BrokenPipe),
        "unexpected blocked-read close outcome: {close_error:?}"
    );
    blocked_reader.join().expect("blocked reader panicked");
    device.close().expect("Wintun close must be idempotent");
    assert_eq!(
        device.write(b"after-close").expect_err("write after close must fail").kind(),
        io::ErrorKind::Interrupted
    );
    drop(device);
    wait_for_powershell(&adapter_absent_script(&adapter_name), true);
    println!(
        "native Wintun lifecycle passed: adapter={adapter_name} mtu={NATIVE_MTU} \
         ipv4={NATIVE_LOCAL_IP} bidirectional_io=true bounded_close=true residue=false"
    );
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
#[test]
#[ignore = "requires an administrator and an integrity-checked upstream wintun.dll"]
fn wfp_native_packet_policy_and_cleanup() {
    use crate::firewall::FirewallBackend;
    use crate::native_wfp_test_support::{KillSwitch, VpnFirewallPolicy};
    use std::net::SocketAddr;
    use std::sync::{mpsc, Arc};

    const SERVER_PORT: u16 = 35_802;
    const OTHER_PORT: u16 = 35_803;
    const BLOCKED_V4: &[u8] = b"quicfuscate-wfp-block-v4";
    const BLOCKED_V6: &[u8] = b"quicfuscate-wfp-block-v6";
    const ENDPOINT_V4: &[u8] = b"quicfuscate-wfp-endpoint-v4";
    const ENDPOINT_V6: &[u8] = b"quicfuscate-wfp-endpoint-v6";
    const TUNNEL_V4: &[u8] = b"quicfuscate-wfp-tunnel-v4";
    const TUNNEL_V6: &[u8] = b"quicfuscate-wfp-tunnel-v6";
    const DISABLED_V4: &[u8] = b"quicfuscate-wfp-disabled-v4";
    const DISABLED_V6: &[u8] = b"quicfuscate-wfp-disabled-v6";
    const PERSISTED_V4: &[u8] = b"quicfuscate-wfp-persisted-v4";
    const PERSISTED_V6: &[u8] = b"quicfuscate-wfp-persisted-v6";
    const RECOVERED_V4: &[u8] = b"quicfuscate-wfp-recovered-v4";
    const RECOVERED_V6: &[u8] = b"quicfuscate-wfp-recovered-v6";

    KillSwitch::cleanup_stale_rules().expect("pre-test WFP cleanup");
    let _cleanup = NativeKillSwitchCleanup;
    let adapter_name = format!("QuicFuscate-CI-WFP-{}", std::process::id());
    let device = Arc::new(
        WintunDevice::new(&native_config(&adapter_name))
            .expect("verified Wintun must create the WFP test adapter"),
    );
    wait_for_powershell(&adapter_state_script(&adapter_name, NATIVE_MTU), true);

    let socket_v4 = bind_native_udp(IpAddr::V4(NATIVE_LOCAL_IP));
    let socket_v6 = bind_native_udp(IpAddr::V6(NATIVE_LOCAL_IP6));
    let source_port_v4 = socket_v4.local_addr().expect("IPv4 probe address").port();
    let source_port_v6 = socket_v6.local_addr().expect("IPv6 probe address").port();
    let server_v4 = SocketAddr::new(IpAddr::V4(NATIVE_PEER_IP), SERVER_PORT);
    let server_v6 = SocketAddr::new(IpAddr::V6(NATIVE_PEER_IP6), SERVER_PORT);
    let other_v4 = SocketAddr::new(IpAddr::V4(NATIVE_PEER_IP), OTHER_PORT);
    let other_v6 = SocketAddr::new(IpAddr::V6(NATIVE_PEER_IP6), OTHER_PORT);

    let reader_device = Arc::clone(&device);
    let (packet_sender, packet_receiver) = mpsc::sync_channel(64);
    let reader = std::thread::spawn(move || {
        let mut packet = [0u8; 65_535];
        while let Ok(length) = reader_device.read(&mut packet) {
            if packet_sender.send(packet[..length].to_vec()).is_err() {
                return;
            }
        }
    });

    let policy = VpnFirewallPolicy::new(
        adapter_name.clone(),
        server_v4,
        Some(IpAddr::V6(NATIVE_PEER_IP6)),
        [],
    )
    .expect("valid native WFP policy");
    let kill_switch = KillSwitch::new_with_backend(FirewallBackend::Iptables);
    kill_switch.enable().expect("install native WFP block policy");

    assert_native_udp_blocked(&socket_v4, server_v4, BLOCKED_V4, &packet_receiver, |packet| {
        is_udp_ipv4_packet(
            packet,
            NATIVE_LOCAL_IP,
            source_port_v4,
            NATIVE_PEER_IP,
            SERVER_PORT,
            BLOCKED_V4,
        )
    });
    assert_native_udp_blocked(&socket_v6, server_v6, BLOCKED_V6, &packet_receiver, |packet| {
        is_udp_ipv6_packet(
            packet,
            NATIVE_LOCAL_IP6,
            source_port_v6,
            NATIVE_PEER_IP6,
            SERVER_PORT,
            BLOCKED_V6,
        )
    });

    kill_switch.on_vpn_connecting(&policy).expect("install exact endpoint exceptions");
    assert_native_udp_permitted(&socket_v4, server_v4, ENDPOINT_V4, &packet_receiver, |packet| {
        is_udp_ipv4_packet(
            packet,
            NATIVE_LOCAL_IP,
            source_port_v4,
            NATIVE_PEER_IP,
            SERVER_PORT,
            ENDPOINT_V4,
        )
    });
    assert_native_udp_permitted(&socket_v6, server_v6, ENDPOINT_V6, &packet_receiver, |packet| {
        is_udp_ipv6_packet(
            packet,
            NATIVE_LOCAL_IP6,
            source_port_v6,
            NATIVE_PEER_IP6,
            SERVER_PORT,
            ENDPOINT_V6,
        )
    });
    assert_native_udp_blocked(&socket_v4, other_v4, BLOCKED_V4, &packet_receiver, |packet| {
        is_udp_ipv4_packet(
            packet,
            NATIVE_LOCAL_IP,
            source_port_v4,
            NATIVE_PEER_IP,
            OTHER_PORT,
            BLOCKED_V4,
        )
    });
    assert_native_udp_blocked(&socket_v6, other_v6, BLOCKED_V6, &packet_receiver, |packet| {
        is_udp_ipv6_packet(
            packet,
            NATIVE_LOCAL_IP6,
            source_port_v6,
            NATIVE_PEER_IP6,
            OTHER_PORT,
            BLOCKED_V6,
        )
    });

    kill_switch.on_vpn_connected(&policy).expect("install connected Wintun exceptions");
    assert_native_udp_permitted(&socket_v4, other_v4, TUNNEL_V4, &packet_receiver, |packet| {
        is_udp_ipv4_packet(
            packet,
            NATIVE_LOCAL_IP,
            source_port_v4,
            NATIVE_PEER_IP,
            OTHER_PORT,
            TUNNEL_V4,
        )
    });
    assert_native_udp_permitted(&socket_v6, other_v6, TUNNEL_V6, &packet_receiver, |packet| {
        is_udp_ipv6_packet(
            packet,
            NATIVE_LOCAL_IP6,
            source_port_v6,
            NATIVE_PEER_IP6,
            OTHER_PORT,
            TUNNEL_V6,
        )
    });

    kill_switch.on_vpn_disconnected().expect("restore fail-closed WFP policy");
    assert_native_udp_blocked(&socket_v4, server_v4, BLOCKED_V4, &packet_receiver, |packet| {
        is_udp_ipv4_packet(
            packet,
            NATIVE_LOCAL_IP,
            source_port_v4,
            NATIVE_PEER_IP,
            SERVER_PORT,
            BLOCKED_V4,
        )
    });
    assert_native_udp_blocked(&socket_v6, server_v6, BLOCKED_V6, &packet_receiver, |packet| {
        is_udp_ipv6_packet(
            packet,
            NATIVE_LOCAL_IP6,
            source_port_v6,
            NATIVE_PEER_IP6,
            SERVER_PORT,
            BLOCKED_V6,
        )
    });

    kill_switch.disable().expect("remove native WFP policy");
    assert_native_udp_permitted(&socket_v4, other_v4, DISABLED_V4, &packet_receiver, |packet| {
        is_udp_ipv4_packet(
            packet,
            NATIVE_LOCAL_IP,
            source_port_v4,
            NATIVE_PEER_IP,
            OTHER_PORT,
            DISABLED_V4,
        )
    });
    assert_native_udp_permitted(&socket_v6, other_v6, DISABLED_V6, &packet_receiver, |packet| {
        is_udp_ipv6_packet(
            packet,
            NATIVE_LOCAL_IP6,
            source_port_v6,
            NATIVE_PEER_IP6,
            OTHER_PORT,
            DISABLED_V6,
        )
    });

    drop(kill_switch);
    let child_status = std::process::Command::new(
        std::env::current_exe().expect("resolve native WFP test executable"),
    )
    .arg("interface::wintun::tests::wfp_native_install_block_and_exit")
    .arg("--ignored")
    .arg("--exact")
    .arg("--nocapture")
    .arg("--test-threads=1")
    .env("QUICFUSCATE_WFP_PERSISTENCE_CHILD", "1")
    .status()
    .expect("spawn native WFP persistence child");
    assert!(child_status.success(), "native WFP persistence child failed: {child_status}");
    assert_native_udp_blocked(&socket_v4, server_v4, PERSISTED_V4, &packet_receiver, |packet| {
        is_udp_ipv4_packet(
            packet,
            NATIVE_LOCAL_IP,
            source_port_v4,
            NATIVE_PEER_IP,
            SERVER_PORT,
            PERSISTED_V4,
        )
    });
    assert_native_udp_blocked(&socket_v6, server_v6, PERSISTED_V6, &packet_receiver, |packet| {
        is_udp_ipv6_packet(
            packet,
            NATIVE_LOCAL_IP6,
            source_port_v6,
            NATIVE_PEER_IP6,
            SERVER_PORT,
            PERSISTED_V6,
        )
    });
    KillSwitch::cleanup_stale_rules().expect("remove process-retained WFP policy");
    assert_native_udp_permitted(&socket_v4, other_v4, RECOVERED_V4, &packet_receiver, |packet| {
        is_udp_ipv4_packet(
            packet,
            NATIVE_LOCAL_IP,
            source_port_v4,
            NATIVE_PEER_IP,
            OTHER_PORT,
            RECOVERED_V4,
        )
    });
    assert_native_udp_permitted(&socket_v6, other_v6, RECOVERED_V6, &packet_receiver, |packet| {
        is_udp_ipv6_packet(
            packet,
            NATIVE_LOCAL_IP6,
            source_port_v6,
            NATIVE_PEER_IP6,
            OTHER_PORT,
            RECOVERED_V6,
        )
    });

    device.close().expect("close WFP test Wintun adapter");
    reader.join().expect("WFP test Wintun reader panicked");
    drop(device);
    wait_for_powershell(&adapter_absent_script(&adapter_name), true);
    KillSwitch::cleanup_stale_rules().expect("post-test WFP cleanup");
    println!(
        "native WFP policy passed: ipv4=true ipv6=true endpoint=true wintun_luid=true \
         disconnect=true disable=true process_exit=true stale_cleanup=true residue=false"
    );
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
#[test]
#[ignore = "invoked only by the elevated native WFP persistence parent"]
fn wfp_native_install_block_and_exit() {
    use crate::firewall::FirewallBackend;
    use crate::native_wfp_test_support::KillSwitch;

    assert!(
        matches!(std::env::var("QUICFUSCATE_WFP_PERSISTENCE_CHILD").as_deref(), Ok("1")),
        "native WFP persistence helper requires its parent marker"
    );
    KillSwitch::cleanup_stale_rules().expect("pre-child WFP cleanup");
    let kill_switch = KillSwitch::new_with_backend(FirewallBackend::Iptables);
    kill_switch.enable().expect("install process-persistent WFP block policy");
    drop(kill_switch);
    println!("native WFP persistence child exited with block policy retained");
}

#[cfg(all(target_os = "windows", feature = "tun-windows"))]
#[test]
#[ignore = "requires an administrator and an integrity-checked upstream wintun.dll"]
fn native_repeated_open_close_has_no_adapter_residue() {
    for iteration in 0..3 {
        let adapter_name = format!("QuicFuscate-CI-{}-{iteration}", std::process::id());
        let device = WintunDevice::new(&native_config(&adapter_name))
            .expect("verified Wintun must create the repeated-lifecycle adapter");
        assert_ne!(device.adapter_luid(), 0);
        wait_for_powershell(&adapter_state_script(&adapter_name, NATIVE_MTU), true);
        device.close().expect("repeated-lifecycle Wintun close must succeed");
        device.close().expect("repeated-lifecycle close must remain idempotent");
        drop(device);
        wait_for_powershell(&adapter_absent_script(&adapter_name), true);
    }
}
