use core::PathMtuManager;

#[test]
fn has_probe_methods() {
    let mgr = PathMtuManager::new();
    mgr.send_probe();
    mgr.handle_probe_response();
}
