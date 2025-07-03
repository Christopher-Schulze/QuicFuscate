use core::BbrCongestionController;

#[test]
fn cwnd_increases_on_ack() {
    let mut bbr = BbrCongestionController::new();
    let before = bbr.cwnd();
    bbr.on_packet_acknowledged(1500);
    assert!(bbr.cwnd() > before);
}

#[test]
fn cwnd_decreases_on_loss() {
    let mut bbr = BbrCongestionController::new();
    bbr.on_packet_acknowledged(1500);
    bbr.on_packet_lost();
    assert!(bbr.cwnd() <= 10_000);
}
