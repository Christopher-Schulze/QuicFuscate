use core::PathMtuManager;

#[test]
fn has_probe_methods() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let mut mgr = PathMtuManager::new();
    let flag = Arc::new(AtomicBool::new(false));
    let flag_clone = flag.clone();
    mgr.set_mtu_change_callback(move |_| {
        flag_clone.store(true, Ordering::Relaxed);
    });
    let id = mgr.send_probe(1200, false);
    mgr.handle_probe_response(id, true, false);
    assert!(flag.load(Ordering::Relaxed));
}

#[test]
fn dynamic_update_changes_mtu() {
    let mut mgr = PathMtuManager::new();
    let before = mgr.get_outgoing_mtu();
    mgr.update(0.0, 50);
    assert!(mgr.get_outgoing_mtu() >= before);
}
