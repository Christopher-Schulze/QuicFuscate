use core::{PathMtuManager, DEFAULT_MAX_MTU, DEFAULT_MIN_MTU, RFC_8899_MIN_MTU};

#[test]
fn constants_range() {
    assert!(DEFAULT_MIN_MTU >= RFC_8899_MIN_MTU);
    assert!(DEFAULT_MIN_MTU <= DEFAULT_MAX_MTU);
}

#[test]
fn probe_methods_exist() {
    let mut mgr = PathMtuManager::new();
    let id = mgr.send_probe(DEFAULT_MIN_MTU, false);
    mgr.handle_probe_response(id, true, false);
}

#[test]
fn enable_bidirectional() {
    let mut mgr = PathMtuManager::new();
    mgr.enable_bidirectional_discovery(true);
    assert!(mgr.is_bidirectional_discovery_enabled());
    let size = DEFAULT_MIN_MTU + 100;
    mgr.set_mtu_size(size, true);
    assert_eq!(mgr.get_outgoing_mtu(), size);
    assert_eq!(mgr.get_incoming_mtu(), size);
}
