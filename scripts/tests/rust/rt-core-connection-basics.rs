#![cfg(feature = "rust-tests")]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Mutex, OnceLock};

use quicfuscate::core::QuicFuscateConnection;
use quicfuscate::fec::FecConfig;
use quicfuscate::optimize::OptimizeConfig;
use quicfuscate::stealth::{StealthConfig, StealthMode};
use quicfuscate::telemetry::PATH_MIGRATIONS;
use quicfuscate::transport::{Config, ConnectionId, MAX_CONN_ID_LEN, PROTOCOL_VERSION};

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

fn base_config() -> Config {
    Config::new_with_version(PROTOCOL_VERSION).expect("config")
}

struct EnvGuard {
    key: &'static str,
    prev: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var(key).ok();
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prev.as_deref() {
            Some(value) => unsafe {
                std::env::set_var(self.key, value);
            },
            None => unsafe {
                std::env::remove_var(self.key);
            },
        }
    }
}

fn acquire_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn new_client_sets_host_header_and_defaults() {
    let local = addr(4444);
    let peer = addr(4433);
    let config = base_config();
    let stealth = StealthConfig::default();
    let fec = FecConfig::default();
    let opt = OptimizeConfig::default();

    let mut conn = QuicFuscateConnection::new_client(
        "example.com",
        local,
        peer,
        config,
        stealth,
        fec,
        opt,
        None,
        None,
        false,
    )
    .expect("new_client");

    assert_eq!(conn.host_header(), "example.com");
    assert_eq!(conn.stealth_manager().mode(), StealthMode::Stealth);
    assert!(!conn.masque_flow_active());
    assert_eq!(conn.rtt_ms(), 0.0);
    assert_eq!(conn.loss_rate(), 0.0);

    conn.update_state();
    assert_eq!(conn.rtt_ms(), 0.0);
    assert_eq!(conn.loss_rate(), 0.0);
}

#[test]
fn new_server_constructs_without_network() {
    let local = addr(4445);
    let peer = addr(4446);
    let mut config = base_config();
    let stealth = StealthConfig::default();
    let fec = FecConfig::default();
    let opt = OptimizeConfig::default();
    let scid = ConnectionId::from_ref(&[0; MAX_CONN_ID_LEN]);

    let conn =
        QuicFuscateConnection::new_server(&scid, None, local, peer, &mut config, stealth, fec, opt)
            .expect("new_server");
    assert!(!conn.masque_flow_active());
    assert_eq!(conn.rtt_ms(), 0.0);
    assert_eq!(conn.loss_rate(), 0.0);
}

#[test]
fn update_state_applies_validated_path_migrations_and_updates_peer() {
    let local = addr(4450);
    let peer = addr(4451);
    let config = base_config();
    let stealth = StealthConfig::default();
    let fec = FecConfig::default();
    let opt = OptimizeConfig::default();

    let mut conn = QuicFuscateConnection::new_client(
        "example.com",
        local,
        peer,
        config,
        stealth,
        fec,
        opt,
        None,
        None,
        false,
    )
    .expect("new_client");

    let new_local = addr(4452);
    let new_peer = addr(4453);
    let before = PATH_MIGRATIONS.get();
    conn.conn.migrate(new_local, new_peer).expect("migrate");
    let (_, pending_local, pending_peer, challenge) =
        conn.conn.pending_path_validation_for_test().expect("pending validation");
    conn.conn.receive_path_response_for_test(pending_local, pending_peer, challenge);
    conn.update_state();
    let after = PATH_MIGRATIONS.get();

    assert!(after > before, "expected validated path migrations to increment");
    assert_eq!(conn.peer_addr, new_peer);
}

#[test]
fn update_state_keeps_ack_and_pacing_owned_outside_fec_when_brain_disabled() {
    let _env_lock = acquire_env_lock();
    let _brain = EnvGuard::set("QUICFUSCATE_BRAIN", "0");

    let local = addr(4454);
    let peer = addr(4455);
    let config = base_config();
    let stealth = StealthConfig::default();
    let fec = FecConfig::default();
    let opt = OptimizeConfig::default();

    let mut conn = QuicFuscateConnection::new_client(
        "example.com",
        local,
        peer,
        config,
        stealth,
        fec,
        opt,
        None,
        None,
        false,
    )
    .expect("new_client");

    conn.conn.set_ack_eliciting_threshold(9);
    conn.conn.set_external_pacing_for_test(true);

    conn.update_state();

    assert_eq!(conn.conn.ack_eliciting_threshold(), 9);
    assert!(conn.conn.external_pacing_enabled());
}
