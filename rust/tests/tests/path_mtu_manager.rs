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

#[test]
fn mtu_probe_and_blackhole() {
    let mut mgr = PathMtuManager::new();
    // Successful probe increases MTU
    let size = DEFAULT_INITIAL_MTU + DEFAULT_MTU_STEP_SIZE;
    let id = mgr.send_probe(size, false);
    mgr.handle_probe_response(id, true, false);
    assert_eq!(mgr.get_outgoing_mtu(), size);

    // Consecutive failures trigger blackhole detection
    for _ in 0..DEFAULT_PATH_BLACKHOLE_THRESHOLD {
        let id = mgr.send_probe(size, false);
        mgr.handle_probe_response(id, false, false);
    }
    assert_eq!(mgr.get_mtu_status(false), MtuStatus::Blackhole);
}

#[test]
fn high_loss_reduces_mtu() {
    let mut mgr = PathMtuManager::new();
    mgr.set_mtu_size(DEFAULT_MAX_MTU, false);
    let before = mgr.get_outgoing_mtu();
    mgr.update(0.5, 150);
    assert!(mgr.get_outgoing_mtu() < before);
}
