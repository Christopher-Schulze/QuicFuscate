use super::*;

#[test]
fn test_subnet_calculation() {
    let mgr = RoutingManager::new(
        "qfserver0".to_string(),
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        "eth0".to_string(),
    );

    assert_eq!(mgr.calculate_subnet(), "10.8.0.0/24");
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn server_routing_platform_surface_is_explicitly_unsupported() {
    let manager = RoutingManager::new(
        "QuicFuscate".to_string(),
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        "Ethernet".to_string(),
    );
    assert!(matches!(manager.setup(), Err(RoutingError::UnsupportedPlatform)));
    assert!(matches!(manager.cleanup_stale(), Err(RoutingError::UnsupportedPlatform)));
    assert!(matches!(manager.teardown(), Err(RoutingError::UnsupportedPlatform)));
}

#[test]
fn durable_routing_state_rejects_unknown_fields() {
    let state = PersistedRoutingOwnership {
        schema: ROUTING_STATE_SCHEMA,
        tun_name: "qfserver0".to_string(),
        interface_index: 17,
        owner_boot_id: "boot-id".to_string(),
        owner_pid: 42,
        owner_start_time: 7,
        server_ipv4: "10.8.0.1".to_string(),
        netmask: "255.255.255.0".to_string(),
        wan_interface: "eth0".to_string(),
        server_ipv6: None,
        ipv6_prefix_len: 64,
        firewall_backend: crate::firewall::FirewallBackend::Iptables,
        firewall_owner_generation: firewall_owner_generation("qfserver0", "boot-id", 42, 7),
        client_to_client_enabled: false,
        ipv4_address: BoolMutation { before: false, after: true },
        ipv6_address: None,
        link_up: BoolMutation { before: false, after: true },
        ipv4_forwarding: TextMutation { before: "0\n".to_string(), after: "1".to_string() },
        ipv6_forwarding: None,
    };
    let encoded = serde_json::to_value(&state).expect("state serialization");
    let decoded: PersistedRoutingOwnership =
        serde_json::from_value(encoded.clone()).expect("state round trip");
    assert_eq!(decoded, state);
    let owner = RoutingManager::firewall_owner_from_state(&state);
    RoutingManager::validate_firewall_owner_shape(&owner).expect("firewall owner shape");
    assert_eq!(owner.owner_generation, state.firewall_owner_generation);

    let mut with_unknown = encoded;
    with_unknown
        .as_object_mut()
        .expect("state object")
        .insert("unexpected".to_string(), serde_json::Value::Bool(true));
    assert!(serde_json::from_value::<PersistedRoutingOwnership>(with_unknown).is_err());
}

#[test]
fn durable_firewall_generation_is_bound_to_tun_and_process_identity() {
    let first = firewall_owner_generation("qfserver0", "boot", 42, 7);
    let second_tun = firewall_owner_generation("qfserver1", "boot", 42, 7);
    let second_process = firewall_owner_generation("qfserver0", "boot", 42, 8);

    assert_ne!(first, second_tun);
    assert_ne!(first, second_process);
    assert_eq!(
        firewall_identity(crate::firewall::FirewallBackend::Iptables),
        "iptables:filter/QUICFUSCATE_RT,nat/QUICFUSCATE_NAT,ip6tables"
    );
    assert_eq!(
        firewall_identity(crate::firewall::FirewallBackend::Nftables),
        "nftables:inet/quicfuscate_rt"
    );
}

#[test]
fn firewall_claim_rejects_cross_tun_and_fixed_resource_collisions() {
    assert_eq!(
        firewall_claim_decision("qfserver0", Some("qfserver1"), false, false, false),
        FirewallClaimDecision::RejectForeignRoutingOwner
    );
    assert_eq!(
        firewall_claim_decision("qfserver0", Some("qfserver0"), true, true, false),
        FirewallClaimDecision::RejectActiveOwner
    );
    assert_eq!(
        firewall_claim_decision("qfserver0", Some("qfserver0"), false, true, false),
        FirewallClaimDecision::RejectStaleOwner
    );
    assert_eq!(
        firewall_claim_decision("qfserver0", None, false, false, true),
        FirewallClaimDecision::RejectExistingResource
    );
    assert_eq!(
        firewall_claim_decision("qfserver0", None, false, false, false),
        FirewallClaimDecision::Claim
    );
}

#[test]
fn durable_firewall_owner_shape_rejects_generation_tampering() {
    let mut owner = PersistedFirewallOwnership {
        schema: FIREWALL_OWNER_SCHEMA,
        owner_generation: firewall_owner_generation("qfserver0", "boot", 42, 7),
        tun_name: "qfserver0".to_string(),
        firewall_backend: crate::firewall::FirewallBackend::Nftables,
        firewall_identity: firewall_identity(crate::firewall::FirewallBackend::Nftables)
            .to_string(),
        owner_boot_id: "boot".to_string(),
        owner_pid: 42,
        owner_start_time: 7,
        server_ipv4: "10.8.0.1".to_string(),
        netmask: "255.255.255.0".to_string(),
        wan_interface: "eth0".to_string(),
        server_ipv6: None,
        ipv6_prefix_len: 64,
        client_to_client_enabled: false,
    };
    assert!(RoutingManager::validate_firewall_owner_shape(&owner).is_ok());
    owner.owner_generation.push('x');
    assert!(RoutingManager::validate_firewall_owner_shape(&owner).is_err());
}

#[test]
fn nftables_required_fragments_cover_fixed_server_rules() {
    let manager = RoutingManager::new(
        "qfserver0".to_string(),
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        "eth0".to_string(),
    );
    let fragments = manager.nftables_required_fragments("10.8.0.0/24");
    assert!(fragments.iter().any(|fragment| fragment.contains("masquerade")));
    assert!(fragments.iter().any(|fragment| fragment.contains("established,related")));
    let ruleset = manager.nftables_ruleset_with_owner("10.8.0.0/24", "generation");
    assert!(ruleset.contains("comment \"quicfuscate-owner-generation\""));
    assert_eq!(manager.nftables_expected_rule_count(), 5);
}

#[test]
fn durable_routing_recovery_is_conservative() {
    assert_eq!(recovery_decision(&false, &true, &false), RecoveryDecision::Noop);
    assert_eq!(recovery_decision(&false, &true, &true), RecoveryDecision::Restore);
    assert_eq!(recovery_decision(&"0", &"1", &"2"), RecoveryDecision::Conflict);
}

#[test]
fn durable_routing_owner_identity_rejects_live_and_reused_processes() {
    assert!(active_owner_matches("boot", "boot", 7, Some(7)));
    assert!(!active_owner_matches("boot", "boot", 7, Some(8)));
    assert!(!active_owner_matches("boot", "new-boot", 7, Some(7)));
    assert!(!active_owner_matches("boot", "boot", 7, None));
}

#[test]
fn durable_routing_state_filename_cannot_escape_its_directory() {
    let filename = routing_state_filename("../../tun/with spaces");
    assert!(!filename.contains('/'));
    assert!(!filename.contains('\\'));
    assert!(filename.ends_with(".json"));
    assert_ne!(filename, routing_state_filename("tun/with spaces"));
}

#[test]
fn test_parse_wan_interface_uses_dev_field() {
    let route = "default via 192.168.1.1 dev enp5s0 proto dhcp src 192.168.1.50 metric 100";
    assert_eq!(parse_wan_interface_from_default_route(route), Some("enp5s0".to_string()));
}

#[test]
fn test_parse_wan_interface_dev_field_covers_non_prefixed_name() {
    let route = "default dev ppp0 scope link";
    assert_eq!(parse_wan_interface_from_default_route(route), Some("ppp0".to_string()));
}

#[test]
fn test_parse_wan_interface_returns_none_for_invalid_output() {
    let route = "default via 10.0.0.1 proto static";
    assert_eq!(parse_wan_interface_from_default_route(route), None);
}

#[test]
fn test_parse_wan_interface_mock_matrix() {
    let cases = [
        ("default via 192.168.178.1 dev wlan0 proto dhcp metric 600", Some("wlan0")),
        ("default dev ppp0 scope link", Some("ppp0")),
        ("default via 10.0.0.1", None),
        ("", None),
    ];
    for (input, expected) in cases {
        assert_eq!(
            parse_wan_interface_from_default_route(input),
            expected.map(|v| v.to_string()),
            "route_output={input:?}"
        );
    }
}

// ------------------------------------------------------------------
// nftables routing rule generation tests
// ------------------------------------------------------------------

/// Verify that the nftables NAT ruleset contains the equivalent of the
/// iptables MASQUERADE + FORWARD rules.
#[cfg(target_os = "linux")]
#[test]
fn test_nftables_routing_ruleset_equivalent_to_iptables() {
    let mgr = RoutingManager::new(
        "qfserver0".to_string(),
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        "eth0".to_string(),
    );
    let subnet = mgr.calculate_subnet();

    // iptables equivalent rules (from setup_iptables)
    let iptables_masq =
        format!("-t nat -A POSTROUTING -s {} -o {} -j MASQUERADE", subnet, mgr.wan_interface);
    let iptables_fwd = format!("-A FORWARD -i {} -o {} -j ACCEPT", mgr.tun_name, mgr.wan_interface);
    let iptables_est = format!(
        "-A FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT",
        mgr.wan_interface, mgr.tun_name
    );

    // nftables equivalent rules
    let nft_masq = format!("ip saddr {} oifname \"{}\" masquerade", subnet, mgr.wan_interface);
    let nft_fwd = format!("iifname \"{}\" oifname \"{}\" accept", mgr.tun_name, mgr.wan_interface);
    let nft_est = format!(
        "iifname \"{}\" oifname \"{}\" ct state established,related accept",
        mgr.wan_interface, mgr.tun_name
    );

    // Both sets must reference the same subnet and interfaces.
    assert!(iptables_masq.contains(&subnet) && nft_masq.contains(&subnet));
    assert!(iptables_fwd.contains(&mgr.tun_name) && nft_fwd.contains(&mgr.tun_name));
    assert!(iptables_est.contains(&mgr.wan_interface) && nft_est.contains(&mgr.wan_interface));

    // MASQUERADE vs masquerade
    assert!(iptables_masq.contains("MASQUERADE"));
    assert!(nft_masq.contains("masquerade"));

    // ESTABLISHED state matching
    assert!(iptables_est.contains("RELATED,ESTABLISHED"));
    assert!(nft_est.contains("established,related"));
}

/// Verify the nftables routing table name constant.
#[cfg(target_os = "linux")]
#[test]
fn test_nft_rt_table_constant() {
    assert_eq!(RoutingManager::NFT_RT_TABLE, "quicfuscate_rt");
}

#[test]
fn test_routing_manager_retains_explicit_backend_for_setup_and_teardown() {
    let manager = RoutingManager::new(
        "qfserver0".to_string(),
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        "eth0".to_string(),
    )
    .with_firewall_backend(crate::firewall::FirewallBackend::Nftables);

    assert_eq!(manager.firewall_backend, crate::firewall::FirewallBackend::Nftables);
}

#[test]
fn test_nftables_ruleset_defaults_to_dual_stack_client_isolation() {
    let manager = RoutingManager::new_dual_stack(
        "qfserver0".to_string(),
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        "eth0".to_string(),
        "fd00::1".parse().unwrap(),
        64,
    );
    let rules = manager.nftables_ruleset("10.8.0.0/24");

    assert!(rules.contains("iifname \"qfserver0\" oifname \"qfserver0\" drop"));
    let fanout_v4 = rules
        .find("ip daddr { 255.255.255.255, 10.8.0.255, 224.0.0.0/4 } accept")
        .expect("IPv4 fan-out allowance");
    let fanout_v6 = rules.find("ip6 daddr ff00::/8 accept").expect("IPv6 fan-out allowance");
    let isolation =
        rules.find("iifname \"qfserver0\" oifname \"qfserver0\" drop").expect("default isolation");
    assert!(fanout_v4 < isolation);
    assert!(fanout_v6 < isolation);
    assert!(rules.contains("ip6 saddr fd00::/64 oifname \"eth0\" masquerade"));
}

#[test]
fn test_nftables_ruleset_requires_explicit_client_unicast_opt_in() {
    let manager = RoutingManager::new(
        "qfserver0".to_string(),
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        "eth0".to_string(),
    )
    .with_client_to_client(true);
    let rules = manager.nftables_ruleset("10.8.0.0/24");

    assert!(rules.contains("iifname \"qfserver0\" oifname \"qfserver0\" accept"));
    assert!(!rules.contains("iifname \"qfserver0\" oifname \"qfserver0\" drop"));
}

#[test]
fn test_iptables_ruleset_rebuilds_only_owned_chains() {
    let manager = RoutingManager::new(
        "qfserver0".to_string(),
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        "eth0".to_string(),
    );
    let rules = manager.iptables_ruleset("10.8.0.0/24", false, true, true);

    assert!(rules.contains(":QUICFUSCATE_NAT - [0:0]"));
    assert!(rules.contains(":QUICFUSCATE_RT - [0:0]"));
    assert!(rules.contains("-I POSTROUTING 1 -j QUICFUSCATE_NAT"));
    assert!(rules.contains("-I FORWARD 1 -j QUICFUSCATE_RT"));
    assert!(rules.contains("-A QUICFUSCATE_NAT -s 10.8.0.0/24 -o eth0 -j MASQUERADE"));
    assert!(rules.contains("-A QUICFUSCATE_RT -i qfserver0 -o qfserver0 -j DROP"));
    assert!(!rules.contains("-A POSTROUTING"));
    assert!(!rules.contains("-A FORWARD"));
}

#[test]
fn test_iptables_repeated_setup_omits_duplicate_parent_jumps() {
    let manager = RoutingManager::new(
        "qfserver0".to_string(),
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        "eth0".to_string(),
    );
    let rules = manager.iptables_ruleset("10.8.0.0/24", false, false, false);

    assert!(!rules.contains("-I POSTROUTING"));
    assert!(!rules.contains("-I FORWARD"));
    assert!(rules.contains(":QUICFUSCATE_NAT - [0:0]"));
    assert!(rules.contains(":QUICFUSCATE_RT - [0:0]"));
}

#[test]
fn test_ip6tables_ruleset_retains_multicast_before_isolation() {
    let manager = RoutingManager::new_dual_stack(
        "qfserver0".to_string(),
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        "eth0".to_string(),
        "fd00::1".parse().unwrap(),
        64,
    );
    let rules = manager.iptables_ruleset("fd00::/64", true, true, true);
    let multicast = rules.find("-d ff00::/8 -j ACCEPT").expect("multicast allowance");
    let isolation = rules.find("-i qfserver0 -o qfserver0 -j DROP").expect("client isolation");

    assert!(multicast < isolation);
    assert!(rules.contains("-A QUICFUSCATE_NAT -s fd00::/64 -o eth0 -j MASQUERADE"));
}

#[test]
fn test_nftables_initial_transaction_rejects_existing_table() {
    let manager = RoutingManager::new(
        "qfserver0".to_string(),
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        "eth0".to_string(),
    );
    let rules = manager.nftables_ruleset("10.8.0.0/24");
    let existing = RoutingManager::nftables_initial_transaction(&rules, true);
    let initial = RoutingManager::nftables_initial_transaction(&rules, false);

    assert!(existing.is_err());
    assert!(matches!(initial, Ok(value) if value == rules));
}

#[cfg(target_os = "macos")]
#[test]
fn test_pf_rules_keep_ipv4_and_ipv6_in_one_anchor_ruleset() {
    let manager = RoutingManager::new_dual_stack(
        "utun9".to_string(),
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        "en0".to_string(),
        "fd00::1".parse().unwrap(),
        64,
    );
    let rules = manager.pf_rules("10.8.0.0/24", Some("fd00::/64"));

    assert!(rules.contains("block drop quick on utun9 inet from 10.8.0.0/24"));
    assert!(rules.contains("block drop quick on utun9 inet6 from fd00::/64"));
    assert!(rules.contains("to { 255.255.255.255, 10.8.0.255, 224.0.0.0/4 }"));
    assert!(rules.contains("to ff00::/8 keep state"));
    assert!(rules.contains("nat on en0 from 10.8.0.0/24"));
    assert!(rules.contains("nat on en0 inet6 from fd00::/64"));
}

#[test]
fn test_windows_nat_script_is_ipv4_only_and_idempotent() {
    let manager = RoutingManager::new(
        "QuicFuscate".to_string(),
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        "Ethernet".to_string(),
    );
    let script = manager.windows_nat_script("10.8.0.0/24");

    assert!(script.contains("Get-NetNat -Name 'QuicFuscateNat'"));
    assert!(script.contains("Remove-NetNat -Name 'QuicFuscateNat'"));
    assert!(script.contains("InternalIPInterfaceAddressPrefix '10.8.0.0/24'"));
    assert!(!script.contains("_v6"));
}

#[test]
fn test_windows_dual_stack_nat_is_rejected_before_side_effects() {
    let manager = RoutingManager::new_dual_stack(
        "QuicFuscate".to_string(),
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        "Ethernet".to_string(),
        "fd00::1".parse().unwrap(),
        64,
    );

    assert!(matches!(
        manager.validate_windows_contract(),
        Err(RoutingError::UnsupportedConfiguration(_))
    ));
}
