use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use quicfuscate::fec::{AdaptiveFec, FecConfig, FecMode, Packet};
use quicfuscate::optimize::MemoryPool;
use std::collections::VecDeque;
use std::sync::Arc;

fn bench_fec_modes(c: &mut Criterion) {
    let pool = Arc::new(MemoryPool::new(2048, 2048));
    let mut data_block = pool.alloc();
    for b in data_block.iter_mut() {
        *b = 0xAB;
    }
    let base_packet = Packet {
        id: 0,
        data: Some(data_block),
        len: 1024,
        is_systematic: true,
        coefficients: None,
        coeff_len: 0,
        mem_pool: Arc::clone(&pool),
    };

    for mode in [
        FecMode::Light,
        FecMode::Normal,
        FecMode::Medium,
        FecMode::Strong,
    ] {
        c.bench_with_input(
            BenchmarkId::new("send", format!("{:?}", mode)),
            &mode,
            |b, &m| {
                let mut cfg = FecConfig::default();
                cfg.initial_mode = m;
                let mut fec = AdaptiveFec::new(cfg, Arc::clone(&pool));
                let mut q = VecDeque::new();
                b.iter(|| {
                    let pkt = base_packet.clone_for_encoder(&pool);
                    fec.on_send(pkt, &mut q);
                    q.clear();
                });
            },
        );
    }
}

criterion_group!(fec_mode_benches, bench_fec_modes);
criterion_main!(fec_mode_benches);
