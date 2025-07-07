use quicfuscate::fec::{AdaptiveFec, FecConfig, FecMode, ModeManager};
use quicfuscate::optimize::MemoryPool;
use std::collections::VecDeque;
use std::sync::Arc;
use rand::{SeedableRng, Rng};

fn make_packet(id: u64, val: u8, pool: &Arc<MemoryPool>) -> quicfuscate::fec::Packet {
    let mut buf = pool.alloc();
    for b in buf.iter_mut().take(8) { *b = val; }
    quicfuscate::fec::Packet {
        id,
        data: Some(buf),
        len: 8,
        is_systematic: true,
        coefficients: None,
        mem_pool: Arc::clone(pool),
    }
}

#[test]
fn cross_fade_packet_recovery() {
    quicfuscate::fec::init_gf_tables();
    let pool = Arc::new(MemoryPool::new(64, 64));
    let cfg = FecConfig {
        lambda: 0.01,
        burst_window: 50,
        hysteresis: 0.02,
        pid: quicfuscate::fec::PidConfig { kp: 1.0, ki: 0.0, kd: 0.0 },
        initial_mode: FecMode::Zero,
        kalman_enabled: false,
        kalman_q: 0.001,
        kalman_r: 0.01,
        window_sizes: FecConfig::default_windows(),
    };
    let mut sender = AdaptiveFec::new(cfg.clone(), Arc::clone(&pool));
    let mut receiver = AdaptiveFec::new(cfg, Arc::clone(&pool));

    sender.report_loss(10, 20);
    receiver.report_loss(10, 20);

    assert!(sender.is_transitioning());
    assert!(receiver.is_transitioning());

    let mut out = VecDeque::new();
    for i in 0..ModeManager::CROSS_FADE_LEN {
        let pkt = make_packet(i as u64, i as u8, &pool);
        sender.on_send(pkt, &mut out);
    }

    let mut rng = rand::rngs::StdRng::seed_from_u64(1234);
    let delivered: Vec<_> = out.into_iter().filter(|_| rng.gen::<f32>() > 0.3).collect();

    let mut recovered = Vec::new();
    for pkt in delivered {
        recovered.extend(receiver.on_receive(pkt).unwrap());
    }

    assert_eq!(recovered.len(), ModeManager::CROSS_FADE_LEN);
    for (i, p) in recovered.into_iter().enumerate() {
        assert_eq!(p.id, i as u64);
        assert_eq!(p.data.as_ref().unwrap()[0], i as u8);
    }

    assert!(!sender.is_transitioning());
    assert!(!receiver.is_transitioning());
}
