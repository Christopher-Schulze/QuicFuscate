use quicfuscate_core::{PathMtuManager, DEFAULT_MIN_MTU, DEFAULT_MAX_MTU};

#[test]
fn constants_range() {
    assert!(DEFAULT_MIN_MTU >= 1200);
    assert!(DEFAULT_MIN_MTU <= DEFAULT_MAX_MTU);
}

#[test]
fn probe_methods_exist() {
    let mgr = PathMtuManager::new();
    let id = mgr.send_probe(1200, false);
    mgr.handle_probe_response(id, true, false);
}
