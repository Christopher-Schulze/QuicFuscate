use core::{DEFAULT_MAX_MTU, DEFAULT_MIN_MTU};

#[test]
fn constants() {
    assert!(DEFAULT_MIN_MTU >= 1200);
    assert!(DEFAULT_MIN_MTU <= DEFAULT_MAX_MTU);
}
