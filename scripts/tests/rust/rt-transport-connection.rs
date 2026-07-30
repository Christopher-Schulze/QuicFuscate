#![cfg(feature = "rust-tests")]

use quicfuscate::error::ConnectionError;
use quicfuscate::transport::{
    packet, Config, ConnectionId, MigrationPolicy, MigrationProbeTarget, PathEvent,
    PROTOCOL_VERSION,
};

#[test]
fn connection_datagram_queues_and_thresholds() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    let local: std::net::SocketAddr = "127.0.0.1:0".parse().expect("local");
    let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().expect("peer");
    let scid = ConnectionId::from_ref(&[0u8; 8]);
    let mut conn = packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");

    conn.set_ack_eliciting_threshold(5);
    assert_eq!(conn.ack_eliciting_threshold(), 5);
    conn.set_external_pacing_for_test(true);
    assert!(conn.external_pacing_enabled());

    conn.enable_datagrams(0, 1);
    assert_eq!(conn.dgram_send_queue_len(), 0);
    conn.dgram_send(b"one").expect("dgram send");
    assert_eq!(conn.dgram_send_queue_len(), 1);

    let err = conn.dgram_send(b"two").expect_err("queue full");
    assert!(matches!(err, ConnectionError::DgramQueueFull));
}

#[test]
fn connection_migrate_emits_path_events_in_order() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    let local: std::net::SocketAddr = "127.0.0.1:0".parse().expect("local");
    let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().expect("peer");
    let scid = ConnectionId::from_ref(&[1u8; 8]);
    let mut conn = packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");

    let new_local: std::net::SocketAddr = "127.0.0.1:4444".parse().expect("new local");
    let new_peer: std::net::SocketAddr = "127.0.0.1:5555".parse().expect("new peer");
    let path_id = conn.migrate(new_local, new_peer).expect("migrate");
    assert!(path_id > 0);

    let ev1 = conn.path_event_next().expect("event 1");
    assert!(matches!(ev1, PathEvent::New(_, _)));
    assert!(conn.path_event_next().is_none());
    assert_eq!(conn.path_stats().next().expect("path stats").peer_addr, peer);

    let (_, pending_local, pending_peer, challenge) =
        conn.pending_path_validation_for_test().expect("pending validation");
    assert_eq!(pending_local, new_local);
    assert_eq!(pending_peer, new_peer);

    conn.receive_path_response_for_test(new_local, new_peer, challenge);

    let ev2 = conn.path_event_next().expect("event 2");
    let ev3 = conn.path_event_next().expect("event 3");
    assert!(matches!(ev2, PathEvent::Validated(_, _)));
    assert!(matches!(ev3, PathEvent::PeerMigrated(_, _)));
    assert!(conn.path_event_next().is_none());
    assert_eq!(conn.path_stats().next().expect("path stats").peer_addr, new_peer);
}

#[test]
fn connection_migrate_ignores_mismatched_path_response() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    let local: std::net::SocketAddr = "127.0.0.1:0".parse().expect("local");
    let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().expect("peer");
    let scid = ConnectionId::from_ref(&[3u8; 8]);
    let mut conn = packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");

    let new_local: std::net::SocketAddr = "127.0.0.1:4444".parse().expect("new local");
    let new_peer: std::net::SocketAddr = "127.0.0.1:5555".parse().expect("new peer");
    conn.migrate(new_local, new_peer).expect("migrate");
    let (_, pending_local, pending_peer, challenge) =
        conn.pending_path_validation_for_test().expect("pending validation");
    let mut wrong = challenge;
    wrong[0] ^= 0x5a;

    conn.receive_path_response_for_test(pending_local, pending_peer, wrong);

    assert!(conn.path_event_next().is_some());
    assert!(conn.path_event_next().is_none());
    assert_eq!(conn.path_stats().next().expect("path stats").peer_addr, peer);
    assert!(conn.pending_path_validation_for_test().is_some());
}

#[test]
fn connection_migrate_times_out_pending_validation() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    let local: std::net::SocketAddr = "127.0.0.1:0".parse().expect("local");
    let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().expect("peer");
    let scid = ConnectionId::from_ref(&[4u8; 8]);
    let mut conn = packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");

    let new_local: std::net::SocketAddr = "127.0.0.1:4444".parse().expect("new local");
    let new_peer: std::net::SocketAddr = "127.0.0.1:5555".parse().expect("new peer");
    conn.migrate(new_local, new_peer).expect("migrate");
    conn.expire_pending_path_validation_for_test();

    let ev1 = conn.path_event_next().expect("event 1");
    let ev2 = conn.path_event_next().expect("event 2");
    assert!(matches!(ev1, PathEvent::New(_, _)));
    assert!(matches!(ev2, PathEvent::FailedValidation(_, _)));
    assert!(conn.path_event_next().is_none());
    assert!(conn.pending_path_validation_for_test().is_none());
    assert_eq!(conn.path_stats().next().expect("path stats").peer_addr, peer);
}

#[test]
fn connection_migrate_enforces_post_validation_cooldown() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    let local: std::net::SocketAddr = "127.0.0.1:0".parse().expect("local");
    let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().expect("peer");
    let scid = ConnectionId::from_ref(&[5u8; 8]);
    let mut conn = packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");

    let first_local: std::net::SocketAddr = "127.0.0.1:4444".parse().expect("first local");
    let first_peer: std::net::SocketAddr = "127.0.0.1:5555".parse().expect("first peer");
    conn.migrate(first_local, first_peer).expect("migrate");
    let (_, pending_local, pending_peer, challenge) =
        conn.pending_path_validation_for_test().expect("pending validation");
    conn.receive_path_response_for_test(pending_local, pending_peer, challenge);

    let second_peer: std::net::SocketAddr = "127.0.0.1:6666".parse().expect("second peer");
    let err = conn
        .migrate(first_local, second_peer)
        .expect_err("cooldown should block immediate re-migration");
    assert!(matches!(err, ConnectionError::InvalidState));
}

#[test]
fn connection_migration_policy_reduces_port_rebinding_and_resets_new_ip_path() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    cfg.set_migration_policy(MigrationPolicy {
        port_rebinding_cwnd_factor: 0.5,
        cooldown: std::time::Duration::ZERO,
        probe_target: MigrationProbeTarget::PreviousWindow,
    })
    .expect("migration policy");
    let local: std::net::SocketAddr = "127.0.0.1:4000".parse().expect("local");
    let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().expect("peer");
    let scid = ConnectionId::from_ref(&[6u8; 8]);
    let mut conn = packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");
    let initial_cwnd = conn.cwnd();
    assert_eq!(initial_cwnd, 14_720);

    let rebound_local: std::net::SocketAddr = "127.0.0.1:4001".parse().expect("rebound local");
    let rebound_peer: std::net::SocketAddr = "127.0.0.1:4434".parse().expect("rebound peer");
    conn.migrate(rebound_local, rebound_peer).expect("port rebinding");
    assert_eq!(conn.cwnd(), initial_cwnd, "validation must precede activation");
    let (_, pending_local, pending_peer, challenge) =
        conn.pending_path_validation_for_test().expect("pending rebinding");
    conn.receive_path_response_for_test(pending_local, pending_peer, challenge);
    assert_eq!(conn.cwnd(), initial_cwnd / 2);

    let new_ip_peer: std::net::SocketAddr = "127.0.0.2:4434".parse().expect("new IP peer");
    conn.migrate(rebound_local, new_ip_peer).expect("new IP path");
    assert_eq!(conn.cwnd(), initial_cwnd / 2, "unvalidated IP path must not alter CC");
    let (_, pending_local, pending_peer, challenge) =
        conn.pending_path_validation_for_test().expect("pending new IP path");
    conn.receive_path_response_for_test(pending_local, pending_peer, challenge);
    assert_eq!(conn.cwnd(), initial_cwnd, "new IP path must reset to the initial window");
}

#[test]
fn connection_refuses_plaintext_short_header_send_without_aead() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    let local: std::net::SocketAddr = "127.0.0.1:0".parse().expect("local");
    let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().expect("peer");
    let scid = ConnectionId::from_ref(&[2u8; 8]);
    let mut conn = packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");

    conn.enable_datagrams(0, 1);
    conn.dgram_send(b"x").expect("queue datagram");

    let mut out = [0u8; 1500];
    let err = conn.send(&mut out).expect_err("send without AEAD must fail");
    assert!(matches!(err, ConnectionError::TlsError(_)));
}
