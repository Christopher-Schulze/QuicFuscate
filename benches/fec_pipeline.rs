// Criterion benchmarks for the full FEC encode/decode pipeline (TODO-424).
//
// Unlike bench_fec_matrix_mul (which measures only GF(256) matrix multiply),
// these benchmarks measure the real AdaptiveFec hot paths:
//   - on_send()/on_send_into() pipeline (ingest -> window fill -> repair generation -> output)
//   - on_receive() pipeline (ingest → decoder → recovery → output)
//   - Block-boundary mode transition overhead
//   - Streaming repair emission
//   - Lazy decoder fast path (zero-loss skip)
//   - Versioned wire envelope write/parse and coefficient regeneration
//
// Run with: cargo bench --features benches -- fec_pipeline

use aligned_box::AlignedBox;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use quicfuscate::fec::{
    wire, AdaptiveFec, FecConfig, FecControlPolicy, FecDecoder8, FecMode, FecPacket,
};
use quicfuscate::optimize::{global_pool, telemetry};
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
    let mut config = FecConfig::product_default();
    config.initial_mode = mode;
    config
}

fn window_size_for_mode(mode: FecMode) -> usize {
    let config = config_with_mode(mode);
    *config.window_sizes.get(&mode).expect("benchmark mode must have a configured FEC window")
}

const DECODE_BATCH_PACKETS: u64 = 128;

#[inline]
fn should_drop_decode_source(id: u64) -> bool {
    id % 10 == 3
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
// 1b. FEC systematic send cold-start path: fresh FEC state per packet
//
// This benchmark intentionally measures the cost of creating fresh AdaptiveFec
// state and sending one systematic packet. It is useful as a cold-path guard,
// but it is not the long-lived production send hot path.
// ---------------------------------------------------------------------------

fn bench_fec_systematic_hot_path(c: &mut Criterion) {
    let modes = [
        ("zero", FecMode::Zero),
        ("light", FecMode::Light),
        ("normal", FecMode::Normal),
        ("medium", FecMode::Medium),
        ("strong", FecMode::Strong),
        ("streaming", FecMode::Streaming),
    ];
    let sizes: &[(usize, &str)] = &[(64, "64B"), (256, "256B"), (1400, "1400B"), (4096, "4KB")];

    let mut group = c.benchmark_group("fec_systematic_hot_path");

    for &(mode_name, mode) in &modes {
        for &(size, size_label) in sizes {
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(
                BenchmarkId::new(mode_name, size_label),
                &(mode, size),
                |b, &(mode, size)| {
                    let pool = global_pool();

                    b.iter_batched(
                        || {
                            let config = config_with_mode(mode);
                            let fec = AdaptiveFec::new(config);
                            let output = Vec::with_capacity(8);
                            (fec, output)
                        },
                        |(mut fec, mut output)| {
                            let pkt = mk_src_packet(0, size, &pool);
                            fec.on_send_into(pkt, &mut output);
                            black_box(&output);
                        },
                        criterion::BatchSize::SmallInput,
                    );
                },
            );
        }
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 1c. FEC production send hot path: persistent FEC state + reusable output
// ---------------------------------------------------------------------------

fn bench_fec_send_reuse_hot_path(c: &mut Criterion) {
    let modes = [
        ("zero", FecMode::Zero),
        ("light", FecMode::Light),
        ("normal", FecMode::Normal),
        ("medium", FecMode::Medium),
        ("strong", FecMode::Strong),
        ("streaming", FecMode::Streaming),
    ];
    let sizes: &[(usize, &str)] = &[(64, "64B"), (256, "256B"), (1400, "1400B"), (4096, "4KB")];

    let mut group = c.benchmark_group("fec_send_reuse_hot_path");

    for &(mode_name, mode) in &modes {
        for &(size, size_label) in sizes {
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(
                BenchmarkId::new(mode_name, size_label),
                &(mode, size),
                |b, &(mode, size)| {
                    let pool = global_pool();
                    let config = config_with_mode(mode);
                    let mut fec = AdaptiveFec::new(config);
                    let mut output =
                        Vec::with_capacity(window_size_for_mode(mode).saturating_add(8));
                    let mut id = 0u64;

                    b.iter(|| {
                        let pkt = mk_src_packet(id, size, &pool);
                        fec.on_send_into(pkt, &mut output);
                        black_box(&output);
                        id = id.wrapping_add(1);
                    });
                },
            );
        }
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 1d. Operator-policy fast path: hard Off under loss vs clean Auto/Zero
// ---------------------------------------------------------------------------

fn bench_fec_off_policy_fast_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_off_policy_fast_path");
    group.throughput(Throughput::Bytes(1400));

    for &(name, control_policy, lost) in &[
        ("auto_zero_clean", FecControlPolicy::Auto, 0usize),
        ("off_under_total_loss", FecControlPolicy::Off, 1usize),
    ] {
        group.bench_function(name, |b| {
            let pool = global_pool();
            let config = FecConfig {
                control_policy,
                initial_mode: FecMode::Zero,
                ..FecConfig::product_default()
            };
            let mut fec = AdaptiveFec::new(config);
            let mut output = Vec::with_capacity(1);
            let mut id = 0u64;

            b.iter(|| {
                fec.report_loss(lost, 1);
                let packet = mk_src_packet(id, 1400, &pool);
                fec.on_send_into(packet, &mut output);
                black_box(&output);
                id = id.wrapping_add(1);
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 2. FEC decode pipeline: production-style on_receive_into() batches
// ---------------------------------------------------------------------------

fn bench_fec_decode_pipeline(c: &mut Criterion) {
    let modes = [
        ("normal", FecMode::Normal),
        ("strong", FecMode::Strong),
        ("streaming", FecMode::Streaming),
    ];

    for &(mode_name, mode) in &modes {
        let mut group = c.benchmark_group("fec_decode_pipeline");
        group.throughput(Throughput::Elements(DECODE_BATCH_PACKETS));

        for &(pattern_name, drop_sources) in
            &[("batch128_no_loss_reuse", false), ("batch128_10pct_reuse", true)]
        {
            group.bench_function(BenchmarkId::new(mode_name, pattern_name), |b| {
                let pool = global_pool();
                let send_capacity = window_size_for_mode(mode).saturating_add(8);

                b.iter_batched(
                    || {
                        let config = config_with_mode(mode);
                        let mut sender = AdaptiveFec::new(config.clone());
                        let mut receiver = AdaptiveFec::new(config);
                        let mut send_output = Vec::with_capacity(send_capacity);
                        let mut receive_output = Vec::with_capacity(8);

                        for id in 0..DECODE_BATCH_PACKETS {
                            let pkt = mk_src_packet(id, 1400, &pool);
                            sender.on_send_into(pkt, &mut send_output);
                            for p in send_output.drain(..) {
                                receiver
                                    .on_receive_into(p, &mut receive_output)
                                    .expect("prewarm packet must be accepted");
                                receive_output.clear();
                            }
                        }

                        (sender, receiver, send_output, receive_output, DECODE_BATCH_PACKETS)
                    },
                    |(mut sender, mut receiver, mut send_output, mut receive_output, start_id)| {
                        let mut emitted = 0usize;
                        for offset in 0..DECODE_BATCH_PACKETS {
                            let id = start_id + offset;
                            let pkt = mk_src_packet(id, 1400, &pool);
                            sender.on_send_into(pkt, &mut send_output);
                            for p in send_output.drain(..) {
                                if drop_sources
                                    && p.is_systematic
                                    && should_drop_decode_source(p.id)
                                {
                                    continue;
                                }
                                receiver
                                    .on_receive_into(p, &mut receive_output)
                                    .expect("benchmark packet must be accepted");
                                emitted = emitted.wrapping_add(receive_output.len());
                                receive_output.clear();
                            }
                        }
                        black_box(emitted);
                        black_box(&receiver);
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }

        group.finish();
    }
}

// ---------------------------------------------------------------------------
// 2b. FEC decode compatibility wrapper: allocation cost guard
// ---------------------------------------------------------------------------

fn bench_fec_decode_compat_alloc(c: &mut Criterion) {
    let modes = [("normal", FecMode::Normal), ("strong", FecMode::Strong)];

    let mut group = c.benchmark_group("fec_decode_compat_alloc");

    for &(mode_name, mode) in &modes {
        group.throughput(Throughput::Elements(1));
        group.bench_function(BenchmarkId::new(mode_name, "single_packet_on_receive"), |b| {
            let pool = global_pool();
            let config = config_with_mode(mode);
            let mut sender = AdaptiveFec::new(config.clone());
            let mut receiver = AdaptiveFec::new(config);
            let mut id = 0u64;

            b.iter(|| {
                let pkt = mk_src_packet(id, 1400, &pool);
                let mut output = Vec::with_capacity(window_size_for_mode(mode).saturating_add(8));
                sender.on_send_into(pkt, &mut output);
                for p in output.drain(..) {
                    let emitted =
                        receiver.on_receive(p).expect("benchmark packet must be accepted");
                    black_box(emitted);
                }
                id = id.wrapping_add(1);
                black_box(&receiver);
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 2c. Direct GF(2^8) peeling representation: k=256
//
// Repairs intentionally form 128 disjoint two-source equations. Feeding the
// first 128 sources then forces repeated full peeling passes while keeping the
// system underdetermined, isolating equation-store traversal from elimination.
// ---------------------------------------------------------------------------

const PEEL_BENCH_K: usize = 256;
const PEEL_BENCH_EQUATIONS: usize = PEEL_BENCH_K / 2;
const PEEL_BENCH_SYMBOL_LEN: usize = 64;

fn make_peeling_benchmark_batch(
    pool: &Arc<quicfuscate::optimize::MemoryPool>,
) -> (FecDecoder8, Vec<FecPacket>) {
    let decoder = FecDecoder8::new(PEEL_BENCH_K, Arc::clone(pool));
    let mut packets = Vec::with_capacity(PEEL_BENCH_EQUATIONS + PEEL_BENCH_EQUATIONS);

    for equation_index in 0..PEEL_BENCH_EQUATIONS {
        let mut data = pool.alloc();
        data[..PEEL_BENCH_SYMBOL_LEN].fill(equation_index as u8);
        let mut coefficients = pool.alloc();
        coefficients[..PEEL_BENCH_K].fill(0);
        coefficients[equation_index] = 1;
        coefficients[equation_index + PEEL_BENCH_EQUATIONS] = 1;
        packets.push(FecPacket::new(
            (PEEL_BENCH_K - 1) as u64,
            Some(data),
            PEEL_BENCH_SYMBOL_LEN,
            false,
            Some(coefficients),
            PEEL_BENCH_K,
            Arc::clone(pool),
        ));
    }

    for source_id in 0..PEEL_BENCH_EQUATIONS {
        let mut data = pool.alloc();
        data[..PEEL_BENCH_SYMBOL_LEN].fill(source_id as u8);
        packets.push(FecPacket::new(
            source_id as u64,
            Some(data),
            PEEL_BENCH_SYMBOL_LEN,
            true,
            None,
            0,
            Arc::clone(pool),
        ));
    }

    (decoder, packets)
}

fn bench_fec_peeling_k256(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_peeling");
    group.throughput(Throughput::Elements((PEEL_BENCH_EQUATIONS * 2) as u64));
    group.bench_function("gf8_k256_linear_equation_traversal", |b| {
        let pool = global_pool();
        let _ = AdaptiveFec::new(FecConfig::product_default());
        b.iter_batched(
            || make_peeling_benchmark_batch(&pool),
            |(mut decoder, packets)| {
                for packet in packets {
                    decoder.take_packet(packet);
                }
                black_box(decoder.poll_recovered().len());
            },
            criterion::BatchSize::SmallInput,
        );
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// 2d. Wiedemann scratch allocation profile: high-loss k=128/256
//
// Every repair equation has two non-zero coefficients, so it remains queued
// until the full system is available. Zero-valued payloads make the existing
// solver validation succeed without entering Gaussian fallback, isolating the
// Wiedemann byte-parallel path and its scratch ownership.
// ---------------------------------------------------------------------------

const WIEDEMANN_BENCH_SYMBOL_LEN: usize = 32;
const WIEDEMANN_BENCH_K_VALUES: [usize; 2] = [128, 256];

fn make_wiedemann_benchmark_batch(
    k: usize,
    pool: &Arc<quicfuscate::optimize::MemoryPool>,
) -> (FecDecoder8, Vec<FecPacket>) {
    let decoder = FecDecoder8::new_with_decoder_policy(k, Arc::clone(pool), "wiedemann");
    let mut packets = Vec::with_capacity(k);

    for equation_index in 0..k {
        let mut data = pool.alloc();
        data[..WIEDEMANN_BENCH_SYMBOL_LEN].fill(0);
        let mut coefficients = pool.alloc();
        coefficients[..k].fill(0);
        coefficients[equation_index] = 1;
        let next_index = (equation_index + 1) % k;
        coefficients[next_index] = if next_index == 0 { 2 } else { 1 };
        packets.push(FecPacket::new(
            (k - 1) as u64,
            Some(data),
            WIEDEMANN_BENCH_SYMBOL_LEN,
            false,
            Some(coefficients),
            k,
            Arc::clone(pool),
        ));
    }

    (decoder, packets)
}

fn run_wiedemann_benchmark_batch(k: usize, pool: &Arc<quicfuscate::optimize::MemoryPool>) -> usize {
    let (mut decoder, packets) = make_wiedemann_benchmark_batch(k, pool);
    for packet in packets {
        decoder.take_packet(packet);
    }
    decoder.poll_recovered().len()
}

fn bench_fec_wiedemann_allocations(c: &mut Criterion) {
    let pool = global_pool();
    let _ = AdaptiveFec::new(FecConfig::product_default());
    let mut group = c.benchmark_group("fec_wiedemann_allocations");

    for &k in &WIEDEMANN_BENCH_K_VALUES {
        let column_before = telemetry::WIEDEMANN_COLUMN_BUFFER_ALLOCS.get();
        let accumulator_before = telemetry::WIEDEMANN_SPMV_ACCUMULATOR_ALLOCS.get();
        let matrix_rhs_before = telemetry::WIEDEMANN_MATRIX_RHS_ALLOCS.get();
        let krylov_before = telemetry::WIEDEMANN_KRYLOV_ALLOCS.get();
        let iteration_before = telemetry::WIEDEMANN_ITERATION_ALLOCS.get();
        let candidate_before = telemetry::WIEDEMANN_CANDIDATE_ALLOCS.get();
        let amx_before = telemetry::WIEDEMANN_AMX_SCRATCH_ALLOCS.get();
        let usage_before = telemetry::WIEDEMANN_USAGE.get();
        let recovered = run_wiedemann_benchmark_batch(k, &pool);
        let column_after = telemetry::WIEDEMANN_COLUMN_BUFFER_ALLOCS.get();
        let accumulator_after = telemetry::WIEDEMANN_SPMV_ACCUMULATOR_ALLOCS.get();
        let matrix_rhs_after = telemetry::WIEDEMANN_MATRIX_RHS_ALLOCS.get();
        let krylov_after = telemetry::WIEDEMANN_KRYLOV_ALLOCS.get();
        let iteration_after = telemetry::WIEDEMANN_ITERATION_ALLOCS.get();
        let candidate_after = telemetry::WIEDEMANN_CANDIDATE_ALLOCS.get();
        let amx_after = telemetry::WIEDEMANN_AMX_SCRATCH_ALLOCS.get();
        let usage_after = telemetry::WIEDEMANN_USAGE.get();
        eprintln!(
            "fec_wiedemann_profile k={k} recovered={recovered} solver_calls={} column_buffers={} spmv_accumulators={} matrix_rhs={} krylov={} iterations={} candidates={} amx_scratch={}",
            usage_after - usage_before,
            column_after - column_before,
            accumulator_after - accumulator_before,
            matrix_rhs_after - matrix_rhs_before,
            krylov_after - krylov_before,
            iteration_after - iteration_before,
            candidate_after - candidate_before,
            amx_after - amx_before,
        );

        group.throughput(Throughput::Elements((k * WIEDEMANN_BENCH_SYMBOL_LEN) as u64));
        group.bench_with_input(BenchmarkId::new("high_loss", k), &k, |b, &k| {
            b.iter_batched(
                || make_wiedemann_benchmark_batch(k, &pool),
                |(mut decoder, packets)| {
                    for packet in packets {
                        decoder.take_packet(packet);
                    }
                    black_box(decoder.poll_recovered().len());
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 3. Mode transition overhead: measure block-boundary switch cost
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

    // Zero mode with production-style reusable send output scratch.
    group.bench_function("zero_mode_passthrough_reuse", |b| {
        let pool = global_pool();
        let config = config_with_mode(FecMode::Zero);
        let mut fec = AdaptiveFec::new(config);
        let mut output = Vec::with_capacity(1);
        let mut id = 0u64;

        b.iter(|| {
            let pkt = mk_src_packet(id, 1400, &pool);
            fec.on_send_into(pkt, &mut output);
            for p in output.drain(..) {
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

    // Normal mode with production-style reusable send and receive output scratch.
    group.bench_function("normal_mode_no_loss_reuse", |b| {
        let pool = global_pool();
        let config = config_with_mode(FecMode::Normal);
        let mut sender = AdaptiveFec::new(config.clone());
        let mut receiver = AdaptiveFec::new(config);
        let mut send_output = Vec::with_capacity(1);
        let mut receive_output = Vec::with_capacity(1);
        let mut id = 0u64;

        b.iter(|| {
            let pkt = mk_src_packet(id, 1400, &pool);
            sender.on_send_into(pkt, &mut send_output);
            for p in send_output.drain(..) {
                receiver
                    .on_receive_into(p, &mut receive_output)
                    .expect("receive must accept normal-mode source packet");
                receive_output.clear();
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

    let modes = [
        ("light", FecMode::Light),
        ("normal", FecMode::Normal),
        ("medium", FecMode::Medium),
        ("strong", FecMode::Strong),
    ];

    for &(mode_name, mode) in &modes {
        let window = window_size_for_mode(mode);
        group.throughput(Throughput::Bytes(1400));
        group.bench_with_input(
            BenchmarkId::new(mode_name, format!("k{window}_repair_burst")),
            &(mode, window),
            |b, &(mode, window)| {
                let pool = global_pool();

                b.iter_batched(
                    || {
                        // Fresh FEC for each measurement keeps the measured packet
                        // consistently positioned as the one that fills the window.
                        let config = config_with_mode(mode);
                        let mut fec = AdaptiveFec::new(config);
                        for id in 0..window.saturating_sub(1) as u64 {
                            let pkt = mk_src_packet(id, 1400, &pool);
                            let _ = fec.on_send(pkt);
                        }
                        (fec, window.saturating_sub(1) as u64)
                    },
                    |(mut fec, id)| {
                        let pkt = mk_src_packet(id, 1400, &pool);
                        let output = fec.on_send(pkt);
                        black_box(&output);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 7. Active-FEC wire envelope: MTU-sized write/parse and repair derivation
// ---------------------------------------------------------------------------

fn bench_fec_wire_envelope(c: &mut Criterion) {
    const OUTER_MTU: usize = 1400;
    const INNER_QUIC_LEN: usize = OUTER_MTU - wire::MAX_DATAGRAM_OVERHEAD;
    let profile = wire::WireProfile {
        epoch: 1,
        codec: wire::WireCodec::Gf8,
        source_count: 64,
        total_count: 80,
        interleave_depth: 4,
    };
    let meta = wire::WirePacketMeta {
        profile,
        window: 0,
        sequence: 0,
        repair_index: wire::SYSTEMATIC_REPAIR_INDEX,
        block_index: 0,
        systematic: true,
    };
    let payload = vec![0xA5; INNER_QUIC_LEN];
    let mut encoded = vec![0u8; OUTER_MTU];
    let encoded_len =
        wire::write_packet(meta, &payload, &mut encoded).expect("benchmark envelope must encode");

    let mut group = c.benchmark_group("fec_wire_envelope");
    group.throughput(Throughput::Bytes(INNER_QUIC_LEN as u64));
    group.bench_function("write_mtu1400", |b| {
        let mut output = vec![0u8; OUTER_MTU];
        b.iter(|| {
            let written = wire::write_packet(meta, black_box(&payload), &mut output)
                .expect("benchmark envelope must encode");
            black_box(&output[..written]);
        });
    });
    group.bench_function("parse_mtu1400", |b| {
        b.iter(|| {
            let parsed = wire::parse_packet(black_box(&encoded[..encoded_len]))
                .expect("benchmark envelope must parse");
            black_box(parsed);
        });
    });
    group.throughput(Throughput::Elements(profile.block_source_count() as u64));
    group.bench_function("derive_gf8_k16_repair_row", |b| {
        let mut coefficients = [0u8; 16];
        b.iter(|| {
            let written = wire::WireCodec::Gf8
                .write_repair_coefficients(
                    profile.block_source_count(),
                    black_box(3),
                    &mut coefficients,
                )
                .expect("benchmark coefficients must derive");
            black_box(&coefficients[..written]);
        });
    });
    group.finish();
}

criterion_group!(
    fec_pipeline_benches,
    bench_fec_encode_pipeline,
    bench_fec_systematic_hot_path,
    bench_fec_send_reuse_hot_path,
    bench_fec_off_policy_fast_path,
    bench_fec_decode_pipeline,
    bench_fec_decode_compat_alloc,
    bench_fec_peeling_k256,
    bench_fec_wiedemann_allocations,
    bench_fec_mode_transition,
    bench_fec_streaming_repair,
    bench_fec_lazy_fast_path,
    bench_fec_window_fill_burst,
    bench_fec_wire_envelope,
);

criterion_main!(fec_pipeline_benches);
