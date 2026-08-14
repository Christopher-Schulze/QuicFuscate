use quicfuscate::engine::{
    EngineCommand, EngineCommandResult, EngineConfig, EngineState, FecPolicyCommandScope,
    QuicFuscateEngine,
};
use std::time::Duration;

fn tun_available() -> bool {
    let pool = quicfuscate::optimize::global_pool();
    let cfg = quicfuscate::interface::TunConfig {
        name: None,
        ip: None,
        netmask: None,
        mtu: 1500,
        zero_copy: true,
        ip6: None,
        prefix6: None,
    };
    quicfuscate::interface::TunInterface::open(cfg, pool).is_ok()
}

#[test]
fn test_control_plane_getters_and_runtime_setters() {
    let mut engine = QuicFuscateEngine::new(EngineConfig::default()).unwrap();

    match engine.apply_command(EngineCommand::GetState).unwrap() {
        EngineCommandResult::State(state) => assert_eq!(state, EngineState::Created),
        other => panic!("unexpected result for GetState: {:?}", other),
    }

    match engine.apply_command(EngineCommand::GetStats).unwrap() {
        EngineCommandResult::Stats(_stats) => {}
        other => panic!("unexpected result for GetStats: {:?}", other),
    }

    match engine.apply_command(EngineCommand::GetTunCapabilities).unwrap() {
        EngineCommandResult::TunCapabilities(_caps) => {}
        other => panic!("unexpected result for GetTunCapabilities: {:?}", other),
    }

    let current_stealth = engine.stealth_mode();
    match engine.apply_command(EngineCommand::SetStealthMode(current_stealth)).unwrap() {
        EngineCommandResult::State(state) => assert_eq!(state, EngineState::Created),
        other => panic!("unexpected result for SetStealthMode: {:?}", other),
    }

    let current_fec = engine.fec_mode();
    match engine.apply_command(EngineCommand::SetFecMode(current_fec)).unwrap() {
        EngineCommandResult::FecPolicy(result) => {
            assert_eq!(result.requested, current_fec);
            assert_eq!(result.configured, current_fec);
            assert_eq!(result.effective, None);
            assert_eq!(result.scope, FecPolicyCommandScope::NextConnection);
            assert_eq!(result.queued_sources_preserved, 0);
            assert_eq!(result.queued_repairs_discarded, 0);
        }
        other => panic!("unexpected result for SetFecMode: {:?}", other),
    }

    let current_cc = engine.cc_algorithm();
    match engine.apply_command(EngineCommand::SetCongestionControl(current_cc)).unwrap() {
        EngineCommandResult::State(state) => assert_eq!(state, EngineState::Created),
        other => panic!("unexpected result for SetCongestionControl: {:?}", other),
    }

    match engine.apply_command(EngineCommand::SetTrafficPadding(true)).unwrap() {
        EngineCommandResult::Ack => {}
        other => panic!("unexpected result for SetTrafficPadding: {:?}", other),
    }
    assert!(engine.config().stealth.enable_traffic_padding);

    match engine.apply_command(EngineCommand::SetTimingObfuscation(true)).unwrap() {
        EngineCommandResult::Ack => {}
        other => panic!("unexpected result for SetTimingObfuscation: {:?}", other),
    }
    assert!(engine.config().stealth.enable_timing_obfuscation);

    match engine.apply_command(EngineCommand::SetZeroRtt(false)).unwrap() {
        EngineCommandResult::Ack => {}
        other => panic!("unexpected result for SetZeroRtt: {:?}", other),
    }
    assert!(!engine.config().connection.enable_0rtt);
}

#[test]
fn test_control_plane_command_error_emits_event() {
    let mut engine = QuicFuscateEngine::new(EngineConfig::default()).unwrap();
    let rx = engine.subscribe_events();
    let result = engine.apply_command(EngineCommand::Connect);
    assert!(result.is_err(), "connect before start must fail");

    match rx.recv_timeout(Duration::from_millis(100)) {
        Ok(quicfuscate::engine::EngineEvent::Error { error: _ }) => {}
        Ok(other) => panic!("unexpected event variant: {:?}", other),
        Err(e) => panic!("expected error event after failed command, got recv error: {}", e),
    }
}

#[test]
fn circuit_replacement_commands_fail_closed_before_connection() {
    for command in [
        EngineCommand::PrebuildAlternateCircuit(EngineConfig::default()),
        EngineCommand::PromotePrebuiltAlternate,
        EngineCommand::RotateCircuit(EngineConfig::default()),
    ] {
        let mut engine = QuicFuscateEngine::new(EngineConfig::default()).unwrap();
        assert!(engine.apply_command(command).is_err());
        assert_eq!(engine.state(), EngineState::Created);
    }
}

#[test]
fn test_control_plane_start_stop_commands() {
    if !tun_available() {
        return;
    }

    let mut engine = QuicFuscateEngine::new(EngineConfig::default()).unwrap();

    match engine.apply_command(EngineCommand::Start).unwrap() {
        EngineCommandResult::State(state) => assert_eq!(state, EngineState::Running),
        other => panic!("unexpected result for Start: {:?}", other),
    }

    match engine.apply_command(EngineCommand::Stop).unwrap() {
        EngineCommandResult::State(state) => assert_eq!(state, EngineState::Stopped),
        other => panic!("unexpected result for Stop: {:?}", other),
    }
}

#[test]
fn test_control_plane_connect_disconnect_fail_closed() {
    if !tun_available() {
        return;
    }

    let mut cfg = EngineConfig::default();
    cfg.connection.remote = "127.0.0.1:4433".to_string();
    let mut engine = QuicFuscateEngine::new(cfg).unwrap();

    match engine.apply_command(EngineCommand::Start).unwrap() {
        EngineCommandResult::State(state) => assert_eq!(state, EngineState::Running),
        other => panic!("unexpected result for Start: {:?}", other),
    }

    match engine.apply_command(EngineCommand::Connect) {
        Ok(EngineCommandResult::State(state)) => {
            assert_eq!(state, EngineState::Connected);
            let off = engine
                .apply_command(EngineCommand::SetFecMode(quicfuscate::engine::FecMode::Off))
                .expect("active Off policy command");
            let EngineCommandResult::FecPolicy(off) = off else {
                panic!("active Off command must return a typed FEC acknowledgement");
            };
            assert_eq!(off.scope, FecPolicyCommandScope::ActiveConnection);
            assert_eq!(off.effective, Some(quicfuscate::engine::FecMode::Off));
            assert_eq!(engine.active_fec_mode(), Some(quicfuscate::engine::FecMode::Off));

            let auto = engine
                .apply_command(EngineCommand::SetFecMode(quicfuscate::engine::FecMode::Auto))
                .expect("active Auto policy command");
            let EngineCommandResult::FecPolicy(auto) = auto else {
                panic!("active Auto command must return a typed FEC acknowledgement");
            };
            assert_eq!(auto.scope, FecPolicyCommandScope::ActiveConnection);
            assert_eq!(auto.effective, Some(quicfuscate::engine::FecMode::Auto));
            assert_eq!(engine.active_fec_mode(), Some(quicfuscate::engine::FecMode::Auto));

            match engine.apply_command(EngineCommand::Disconnect).unwrap() {
                EngineCommandResult::State(state) => assert_eq!(state, EngineState::Running),
                other => panic!("unexpected result for Disconnect: {:?}", other),
            }
        }
        Ok(other) => panic!("unexpected result for Connect: {:?}", other),
        Err(_) => {
            // Without reachable server, connect must fail closed and engine must remain running.
            assert_eq!(engine.state(), EngineState::Running);
        }
    }

    match engine.apply_command(EngineCommand::Stop).unwrap() {
        EngineCommandResult::State(state) => assert_eq!(state, EngineState::Stopped),
        other => panic!("unexpected result for Stop: {:?}", other),
    }
}

#[test]
fn test_control_plane_server_mode_start_stop() {
    if !tun_available() {
        return;
    }

    let mut cfg = EngineConfig::default();
    cfg.engine.mode = quicfuscate::engine::EngineMode::Server;
    let mut engine = QuicFuscateEngine::new(cfg).unwrap();

    match engine.apply_command(EngineCommand::Start).unwrap() {
        EngineCommandResult::State(state) => assert_eq!(state, EngineState::Running),
        other => panic!("unexpected result for server Start: {:?}", other),
    }

    match engine.apply_command(EngineCommand::Stop).unwrap() {
        EngineCommandResult::State(state) => assert_eq!(state, EngineState::Stopped),
        other => panic!("unexpected result for server Stop: {:?}", other),
    }
}
