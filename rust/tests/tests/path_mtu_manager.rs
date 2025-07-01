use core::{MtuStatus, PathMtuManager, DEFAULT_MAX_MTU, DEFAULT_MIN_MTU};

#[test]
fn constants() {
    assert!(DEFAULT_MIN_MTU >= 1200);
    assert!(DEFAULT_MIN_MTU <= DEFAULT_MAX_MTU);
}

#[test]
fn reports_status() {
    let mut mgr = PathMtuManager::new();
    assert_eq!(mgr.get_mtu_status(false), MtuStatus::Disabled);
    mgr.update(0.0, 50);
    assert_eq!(mgr.get_mtu_status(false), MtuStatus::Searching);
    assert!(mgr.is_mtu_unstable());
}
