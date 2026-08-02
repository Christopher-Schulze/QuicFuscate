use quicfuscate::stealth::MasqueManager;

#[test]
fn test_masque_tunnel_rejects_invalid_target() {
    let manager = MasqueManager::new();
    let err = manager.establish_tunnel("proxy.example", "invalid-target");
    assert!(err.is_err());
}

#[test]
fn test_masque_tunnel_tracks_send_and_receive_stats() {
    let manager = MasqueManager::new();
    let tunnel = manager
        .establish_tunnel("proxy.example", "cdn.example:443")
        .expect("valid CONNECT-UDP target should schedule tunnel");

    let before = manager.get_tunnel_stats(&tunnel).expect("tunnel stats should exist");
    assert_eq!(before.0, 0);
    assert_eq!(before.1, 0);

    manager
        .send_through_tunnel(&tunnel, b"hello-masque")
        .expect("data send should update counters and schedule async post");

    let payload = b"reply-datagram";
    let mut capsule = Vec::with_capacity(payload.len() + 2);
    capsule.push(0x00);
    capsule.push(payload.len() as u8);
    capsule.extend_from_slice(payload);
    let parsed = manager
        .process_incoming_capsule(&tunnel, &capsule)
        .expect("valid DATAGRAM capsule should parse");
    assert_eq!(parsed, payload);

    let after = manager.get_tunnel_stats(&tunnel).expect("tunnel stats should exist");
    assert!(after.0 >= b"hello-masque".len());
    assert!(after.1 >= payload.len());
}

#[test]
fn test_masque_send_missing_tunnel_returns_error() {
    let manager = MasqueManager::new();
    let err = manager.send_through_tunnel("missing", b"payload");
    assert!(err.is_err());
}
