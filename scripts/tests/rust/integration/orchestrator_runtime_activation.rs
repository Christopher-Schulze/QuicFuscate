#![cfg(feature = "orchestrator")]

#[cfg(feature = "orchestrator")]
use quicfuscate::brain::{DeepIntegrationOrchestrator, StealthBrainConfig};

#[test]
fn test_orchestrator_runtime_activation_and_signal_flow() {
    let cfg = StealthBrainConfig::default();
    let orchestrator = DeepIntegrationOrchestrator::new(cfg, 1024, 65536);

    assert!(!orchestrator.server_push_enabled());
    orchestrator.enable_server_push(true);
    assert!(orchestrator.server_push_enabled());

    orchestrator.update_runtime_signals(
        60,         // 6.0% loss
        35,         // RTT ms
        20,         // jitter ms
        50_000_000, // bandwidth bps
        true,       // stealth active
    );

    let intensity = orchestrator.get_server_push_intensity();
    assert!(
        (0.0..=1.0).contains(&intensity),
        "server push intensity must remain normalized, got {}",
        intensity
    );
}

#[test]
fn test_orchestrator_trigger_matrix_loss_cpu_mem_bw() {
    let cfg = StealthBrainConfig::default();
    let orchestrator = DeepIntegrationOrchestrator::new(cfg, 1024, 65536);
    orchestrator.enable_server_push(true);

    orchestrator.update_runtime_signals(
        70,         // 7% loss
        35,         // cpu ok
        35,         // mem ok
        20_000_000, // bw ok
        true,
    );
    assert!(orchestrator.should_trigger_server_push());

    orchestrator.update_runtime_signals(
        70, // loss still high
        95, // cpu high
        35, 20_000_000, // bw ok
        true,
    );
    assert!(!orchestrator.should_trigger_server_push());

    orchestrator.update_runtime_signals(
        70, 35, 95,         // mem high
        20_000_000, // bw ok
        true,
    );
    assert!(!orchestrator.should_trigger_server_push());

    orchestrator.update_runtime_signals(
        10,        // low loss
        35,        // cpu ok
        35,        // mem ok
        1_000_000, // bw low
        true,
    );
    assert!(!orchestrator.should_trigger_server_push());
}
