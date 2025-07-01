use core::{PathMtuManager, DEFAULT_MAX_MTU, DEFAULT_MIN_MTU};

#[test]
fn constants_range() {
    assert!(DEFAULT_MIN_MTU >= 1200);
    assert!(DEFAULT_MIN_MTU <= DEFAULT_MAX_MTU);
}

#[test]
fn probe_methods_exist() {
    let mut mgr = PathMtuManager::new();
    let id = mgr.send_probe(1200, false);
    mgr.handle_probe_response(id, true, false);
}

#[test]
fn enable_bidirectional() {
    let mut mgr = PathMtuManager::new();
    mgr.enable_bidirectional_discovery(true);
    assert!(mgr.is_bidirectional_discovery_enabled());
    mgr.set_mtu_size(1300, true);
    assert_eq!(mgr.get_outgoing_mtu(), 1300);
    assert_eq!(mgr.get_incoming_mtu(), 1300);
}
