// Criterion benchmarks for the full FEC encode/decode pipeline (TODO-424).
//
// Unlike bench_fec_matrix_mul (which measures only GF(256) matrix multiply),
// these benchmarks measure the real AdaptiveFec hot paths:
//   - on_send() pipeline (ingest → window fill → repair generation → output)
//   - on_receive() pipeline (ingest → decoder → recovery → output)
//   - Mode transition overhead (cross-fade cost)
//   - Streaming repair emission
//   - Lazy decoder fast path (zero-loss skip)
//
// Run with: cargo bench --features benches -- fec_pipeline

use aligned_box::AlignedBox;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use quicfuscate::fec::{AdaptiveFec, FecConfig, FecMode, FecPacket};
use quicfuscate::optimize::global_pool;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helper: create a source packet (mirrors test_support::mk_src_packet)
// ---------------------------------------------------------------------------

fn mk_src_packet(id: u64, len: usize, pool: &Arc<quicfuscate::optimize::MemoryPool>) -> FecPacket {
    let mut buf = pool.alloc();
    if buf.len() < len {
        let mut exact = AlignedBox::<[u8]>::slice_from_default(len, 64).unwrap_or(buf);
        for (i, b) in exact.iter_mut().enumerate() {
            *b = (id as u8).wrapping_add(i as u8);
        }
        FecPacket::new(id, Some(exact), len, true, None, 0, Arc::clone(pool))
    } else {
        for (i, b) in buf.iter_mut().take(len).enumerate() {
            *b = (id as u8).wrapping_add(i as u8);
        }
        FecPacket::new(id, Some(buf), len, true, None, 0, Arc::clone(pool))
    }
}

fn config_with_mode(mode: FecMode) -> FecConfig {
    FecConfig { initial_mode: mode, ..FecConfig::default() }
}

// ---------------------------------------------------------------------------
// 1. FEC encode pipeline: on_send() per mode × packet size
// ---------------------------------------------------------------------------

fn bench_fec_encode_pipeline(c: &mut Criterion) {
    let modes = [
        ("zero", FecMode::Zero),
        ("light", FecMode::Light),
        ("normal", FecMode::Normal),
        ("medium", FecMode::Medium),
        ("strong", FecMode::Strong),
        ("streaming", FecMode::Streaming),
    ];
    let sizes: &[(usize, &str)] = &[(64, "64B"), (256, "256B"), (1400, "1400B"), (4096, "4KB")];

    for &(mode_name, mode) in &modes {
        let mut group = c.benchmark_group("fec_encode_pipeline");

        for &(size, size_label) in sizes {
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(
                BenchmarkId::new(mode_name, size_label),
                &(mode, size),
                |b, &(mode, size)| {
                    let pool = global_pool();
                    let config = config_with_mode(mode);
                    let mut fec = AdaptiveFec::new(config);
                    let mut id = 0u64;

                    b.iter(|| {
                        let pkt = mk_src_packet(id, size, &pool);
                        let output = fec.on_send(pkt);
                        black_box(&output);
                        id = id.wrapping_add(1);
                    });
                },
            );
        }
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// 2. FEC decode pipeline: on_receive() per mode × loss pattern
// ---------------------------------------------------------------------------

fn bench_fec_decode_pipeline(c: &mut Criterion) {
    let modes = [
        ("normal", FecMode::Normal),
        ("strong", FecMode::Strong),
        ("streaming", FecMode::Streaming),
    ];

    for &(mode_name, mode) in &modes {
        let mut group = c.benchmark_group("fec_decode_pipeline");

        // no_loss: feed all packets, measure decode overhead
        group.bench_function(BenchmarkId::new(mode_name, "no_loss"), |b| {
            let pool = global_pool();
            let config = config_with_mode(mode);
            let mut sender = AdaptiveFec::new(config.clone());
            let mut receiver = AdaptiveFec::new(config);
            let mut id = 0u64;

            b.iter(|| {
                let pkt = mk_src_packet(id, 1400, &pool);
                let output = sender.on_send(pkt);
                for p in output {
                    let _ = receiver.on_receive(p);
                }
                id = id.wrapping_add(1);
                black_box(&receiver);
            });
        });

        // random10pct: feed with 10% drop rate (deterministic LCG)
        group.bench_function(BenchmarkId::new(mode_name, "random10pct"), |b| {
            let pool = global_pool();
            let config = config_with_mode(mode);
            let mut sender = AdaptiveFec::new(config.clone());
            let mut receiver = AdaptiveFec::new(config);
            let mut id = 0u64;
            let mut lcg = 0xDEADBEEFu64;

            b.iter(|| {
                lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let drop = ((lcg >> 33) as f64) / ((1u64 << 31) as f64) < 0.10;

                let pkt = mk_src_packet(id, 1400, &pool);
                let output = sender.on_send(pkt);
                for p in output {
                    if drop && p.is_systematic {
                        continue;
                    }
                    let _ = receiver.on_receive(p);
                }
                id = id.wrapping_add(1);
                black_box(&receiver);
            });
        });

        group.finish();
    }
}

// ---------------------------------------------------------------------------
// 3. Mode transition overhead: measure cross-fade cost
// ---------------------------------------------------------------------------

fn bench_fec_mode_transition(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_mode_transition");

    group.throughput(Throughput::Elements(1));

    // Measure on_send during a transition from Zero → Normal
    group.bench_function("zero_to_normal", |b| {
        let pool = global_pool();
        let config = config_with_mode(FecMode::Zero);
        let mut fec = AdaptiveFec::new(config);
        let mut id = 0u64;

        // Pre-fill to steady state in Zero mode
        for _ in 0..100 {
            let pkt = mk_src_packet(id, 1400, &pool);
            let _ = fec.on_send(pkt);
            id = id.wrapping_add(1);
        }

        // Report loss to trigger escalation to Normal
        fec.report_loss(10, 100);

        b.iter(|| {
            let pkt = mk_src_packet(id, 1400, &pool);
            let output = fec.on_send(pkt);
            black_box(&output);
            id = id.wrapping_add(1);
        });
    });

    // Measure on_send during transition from Normal → Zero (de-escalation)
    group.bench_function("normal_to_zero", |b| {
        let pool = global_pool();
        let config = config_with_mode(FecMode::Normal);
        let mut fec = AdaptiveFec::new(config);
        let mut id = 0u64;

        // Pre-fill to steady state in Normal mode
        for _ in 0..200 {
            let pkt = mk_src_packet(id, 1400, &pool);
            let _ = fec.on_send(pkt);
            id = id.wrapping_add(1);
        }

        // Report zero loss to trigger de-escalation
        fec.report_loss(0, 100);

        b.iter(|| {
            let pkt = mk_src_packet(id, 1400, &pool);
            let output = fec.on_send(pkt);
            black_box(&output);
            id = id.wrapping_add(1);
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// 4. Streaming repair emission overhead
// ---------------------------------------------------------------------------

fn bench_fec_streaming_repair(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_streaming_repair");

    for size in [64, 256, 1400] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("stream_every_16", format!("{size}B")),
            &size,
            |b, &size| {
                let pool = global_pool();
                let config = FecConfig {
                    initial_mode: FecMode::Streaming,
                    configured_stream_every: Some(16),
                    ..FecConfig::default()
                };
                let mut fec = AdaptiveFec::new(config);
                let mut id = 0u64;

                b.iter(|| {
                    let pkt = mk_src_packet(id, size, &pool);
                    let output = fec.on_send(pkt);
                    black_box(&output);
                    id = id.wrapping_add(1);
                });
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// 5. Lazy decoder fast path: zero-loss on_receive overhead
// ---------------------------------------------------------------------------

fn bench_fec_lazy_fast_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_lazy_fast_path");

    // Zero mode: absolute passthrough (should be <5ns)
    group.bench_function("zero_mode_passthrough", |b| {
        let pool = global_pool();
        let config = config_with_mode(FecMode::Zero);
        let mut fec = AdaptiveFec::new(config);
        let mut id = 0u64;

        b.iter(|| {
            let pkt = mk_src_packet(id, 1400, &pool);
            let output = fec.on_send(pkt);
            // In Zero mode, output is just the systematic packet
            for p in output {
                let _ = fec.on_receive(p);
            }
            id = id.wrapping_add(1);
            black_box(&fec);
        });
    });

    // Normal mode with no loss: lazy decoder should skip quickly
    group.bench_function("normal_mode_no_loss", |b| {
        let pool = global_pool();
        let config = config_with_mode(FecMode::Normal);
        let mut sender = AdaptiveFec::new(config.clone());
        let mut receiver = AdaptiveFec::new(config);
        let mut id = 0u64;

        b.iter(|| {
            let pkt = mk_src_packet(id, 1400, &pool);
            let output = sender.on_send(pkt);
            for p in output {
                let _ = receiver.on_receive(p);
            }
            id = id.wrapping_add(1);
            black_box(&receiver);
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// 6. Window fill: measure cost as window fills (repair generation burst)
// ---------------------------------------------------------------------------

fn bench_fec_window_fill_burst(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_window_fill_burst");

    // Normal mode k=64: measure the packet that triggers repair generation
    group.bench_function("normal_k64_repair_burst", |b| {
        let pool = global_pool();

        b.iter_batched(
            || {
                // Fresh FEC for each measurement to get consistent window-fill behavior
                let config = config_with_mode(FecMode::Normal);
                let mut fec = AdaptiveFec::new(config);
                // Pre-fill 63 packets (window is 64)
                for id in 0..63u64 {
                    let pkt = mk_src_packet(id, 1400, &pool);
                    let _ = fec.on_send(pkt);
                }
                fec
            },
            |mut fec| {
                // This packet fills the window and triggers repair generation
                let pkt = mk_src_packet(63, 1400, &pool);
                let output = fec.on_send(pkt);
                black_box(&output);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    fec_pipeline_benches,
    bench_fec_encode_pipeline,
    bench_fec_decode_pipeline,
    bench_fec_mode_transition,
    bench_fec_streaming_repair,
    bench_fec_lazy_fast_path,
    bench_fec_window_fill_burst,
);

criterion_main!(fec_pipeline_benches);
