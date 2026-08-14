use super::*;

#[test]
fn client_runtime_projects_dual_stack_tun_addresses() {
    let mut config = EngineConfig::default();
    config.interface.tun_ip = Some("10.20.30.40".parse().expect("IPv4 address"));
    config.interface.tun_netmask = Some("255.255.255.0".parse().expect("IPv4 netmask"));
    config.interface.tun_ip6 = Some("fd00::42".parse().expect("IPv6 address"));
    config.interface.tun_prefix6 = Some(64);

    let tun_config = client_tun_config(&config).expect("dual-stack projection");
    assert_eq!(tun_config.ip, Some("10.20.30.40".parse().expect("IPv4 address")));
    assert_eq!(tun_config.netmask, Some("255.255.255.0".parse().expect("IPv4 netmask")));
    assert_eq!(tun_config.ip6, Some("fd00::42".parse().expect("IPv6 address")));
    assert_eq!(tun_config.prefix6, Some(64));
    assert_eq!(tun_config.mtu, 1500);
}

#[test]
fn client_runtime_projects_ipv6_only_tun_addresses() {
    let mut config = EngineConfig::default();
    config.interface.tun_ip6 = Some("fd00::42".parse().expect("IPv6 address"));
    config.interface.tun_prefix6 = Some(64);

    let tun_config = client_tun_config(&config).expect("IPv6-only projection");
    assert_eq!(tun_config.ip, None);
    assert_eq!(tun_config.netmask, None);
    assert_eq!(tun_config.ip6, Some("fd00::42".parse().expect("IPv6 address")));
    assert_eq!(tun_config.prefix6, Some(64));
}

#[test]
fn client_runtime_projects_server_assignment_before_tun_open() {
    let assignment = crate::control_plane::ClientAssignment::enabled(
        7,
        3,
        Some(crate::control_plane::AssignedIpv4 {
            address: "10.8.0.2".parse().expect("IPv4 address"),
            prefix: 24,
        }),
        Some(crate::control_plane::AssignedIpv6 {
            address: "fd00::42".parse().expect("IPv6 address"),
            prefix: 64,
        }),
        1400,
        vec!["2001:4860:4860::8888".parse().expect("DNS address")],
    )
    .expect("assignment");
    let tun_config = tun_config_from_assignment(&assignment, Some("qf0".to_string()), true)
        .expect("assignment projection");
    assert_eq!(tun_config.name.as_deref(), Some("qf0"));
    assert_eq!(tun_config.ip, Some("10.8.0.2".parse().expect("IPv4 address")));
    assert_eq!(tun_config.netmask, Some("255.255.255.0".parse().expect("netmask")));
    assert_eq!(tun_config.ip6, Some("fd00::42".parse().expect("IPv6 address")));
    assert_eq!(tun_config.prefix6, Some(64));
    assert_eq!(tun_config.mtu, 1400);
}

#[test]
fn client_runtime_rejects_disabled_server_assignment_before_tun_open() {
    let assignment =
        crate::control_plane::ClientAssignment::disabled(7, 3).expect("disabled assignment");
    let error = tun_config_from_assignment(&assignment, None, true)
        .expect_err("disabled assignment must not open TUN");
    assert!(matches!(error, EngineError::Tun(_)));
}

#[test]
fn rotation_assignment_compatibility_ignores_session_generation_only() {
    let current = crate::control_plane::ClientAssignment::enabled(
        7,
        3,
        Some(crate::control_plane::AssignedIpv4 {
            address: "10.8.0.2".parse().expect("IPv4 address"),
            prefix: 24,
        }),
        None,
        1400,
        vec!["1.1.1.1".parse().expect("DNS address")],
    )
    .expect("current assignment");
    let mut replacement = current.clone();
    replacement.session_id = 8;
    replacement.generation = 4;
    replacement.mtu = 1500;
    assert!(assignments_share_tun_identity(&current, &replacement));

    replacement.ipv4 = Some(crate::control_plane::AssignedIpv4 {
        address: "10.8.0.3".parse().expect("IPv4 address"),
        prefix: 24,
    });
    assert!(!assignments_share_tun_identity(&current, &replacement));
}

#[test]
fn rotation_mtu_never_exceeds_active_path_or_replacement_assignment() {
    assert_eq!(conservative_replacement_tun_mtu(1400, 1350, 1380), 1350);
    assert_eq!(conservative_replacement_tun_mtu(1400, 1500, 1320), 1320);
    assert_eq!(conservative_replacement_tun_mtu(1400, 1500, 1450), 1400);
    assert_eq!(conservative_replacement_tun_mtu(1400, usize::MAX, 1450), 1400);
}

#[test]
fn test_client_runtime_new() {
    let config = EngineConfig::default();
    let runtime = ClientRuntime::new(config);
    assert!(runtime.is_ok());
}

#[test]
fn test_client_runtime_rejects_invalid_engine_projection() {
    let mut config = EngineConfig::default();
    config.stealth.padding_strategy = "invalid".to_string();
    let error = match ClientRuntime::new(config) {
        Ok(_) => panic!("invalid stealth must fail closed"),
        Err(error) => error,
    };
    assert!(matches!(error, EngineError::Config(_)));
}

#[test]
fn connect_udp_bind_failure_rolls_back_connection_and_transport_state() {
    let blocker =
        std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind UDP blocker");
    let blocked_addr = blocker.local_addr().expect("read UDP blocker address");
    let mut config = EngineConfig::default();
    config.connection.local = blocked_addr.to_string();

    let mut runtime = ClientRuntime::new(config).expect("client runtime");
    runtime.runtime = Some(
        runtime::create_shared_runtime(&runtime::RuntimeConfig::default())
            .expect("client runtime executor"),
    );
    runtime.state = ClientState::Running;

    let error = runtime.connect().expect_err("occupied UDP address must fail connect");
    assert!(matches!(error, EngineError::Io(message) if message.contains("UDP bind failed")));
    assert_eq!(runtime.state(), ClientState::Running);
    assert!(runtime.connection().is_none());
    assert!(runtime.socket.is_none());
    assert!(runtime.io_driver.is_none());
    assert!(runtime.io_handles.is_empty());

    let second_error = runtime.connect().expect_err("second bind must remain blocked");
    assert!(
        matches!(second_error, EngineError::Io(message) if message.contains("UDP bind failed"))
    );
    assert!(runtime.connection().is_none());
    assert!(runtime.io_handles.is_empty());

    runtime.stop().expect("failed connect must remain stoppable");
    assert_eq!(runtime.state(), ClientState::Stopped);
}

#[test]
fn updated_next_config_is_consumed_by_the_following_connect_attempt() {
    let blocker =
        std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind UDP blocker");
    let blocked_addr = blocker.local_addr().expect("read UDP blocker address");
    let mut config = EngineConfig::default();
    config.connection.local = blocked_addr.to_string();

    let mut runtime = ClientRuntime::new(EngineConfig::default()).expect("client runtime");
    runtime.update_next_config(&config).expect("update next connection config");
    runtime.runtime = Some(
        runtime::create_shared_runtime(&runtime::RuntimeConfig::default())
            .expect("client runtime executor"),
    );
    runtime.state = ClientState::Running;

    let error =
        runtime.connect().expect_err("the following connect must use the updated local address");
    assert!(matches!(error, EngineError::Io(message) if message.contains("UDP bind failed")));
    assert_eq!(runtime.state(), ClientState::Running);
    assert!(runtime.connection().is_none());
}

#[test]
fn connect_without_runtime_rolls_back_connection() {
    let mut runtime = ClientRuntime::new(EngineConfig::default()).expect("client runtime");
    runtime.state = ClientState::Running;

    let error = runtime.connect().expect_err("missing runtime must fail connect");
    assert!(
        matches!(error, EngineError::Internal(message) if message == "Runtime not initialized")
    );
    assert_eq!(runtime.state(), ClientState::Running);
    assert!(runtime.connection().is_none());
    assert!(runtime.socket.is_none());
    assert!(runtime.io_driver.is_none());
    assert!(runtime.io_handles.is_empty());
}

#[test]
fn loss_detector_prioritizes_remote_close_and_honors_timeout_boundary() {
    assert!(matches!(
        classify_connection_loss(
            true,
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(30)
        ),
        Some(DisconnectReason::RemoteClosed)
    ));
    assert!(classify_connection_loss(
        false,
        std::time::Duration::from_millis(999),
        std::time::Duration::from_secs(1)
    )
    .is_none());
    assert!(classify_connection_loss(
        false,
        std::time::Duration::from_secs(86_400),
        std::time::Duration::ZERO
    )
    .is_none());
    assert!(matches!(
        classify_connection_loss(
            false,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1)
        ),
        Some(DisconnectReason::Timeout)
    ));
}

// Note: TUN tests require root/admin privileges
// They are tested in integration tests
