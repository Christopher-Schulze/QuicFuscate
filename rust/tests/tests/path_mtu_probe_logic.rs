use core::PathMtuManager;

#[test]
fn has_probe_methods() {
    let mgr = PathMtuManager::new();
    let id = mgr.send_probe(1200, false);
    mgr.handle_probe_response(id, true, false);
}
