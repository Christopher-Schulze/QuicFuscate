// Criterion benchmarks for the ACK pipeline hot paths (TODO-956..961).
//
// Measures the steady-state paths that were made allocation-free:
//   - Recovery::on_ack_received (scratch-vector reuse + SmallVec outcomes)
//   - PktNumSpace ACK emission via peek_ack_at (inline AckRanges)
//   - frames::from_bytes ACK parse and to_bytes emit (inline AckRanges)
//   - Spill behaviour once a frame exceeds the 8-block inline capacity
//
// Run with: cargo bench --features benches -- ack_pipeline

use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use qf_transport_frames as frames;
use qf_transport_pn::pnspace::PktNumSpace;
use qf_transport_recovery::{PacketSpace, Recovery};
use qf_transport_types::protocol::PacketType;
use qf_transport_types::{AckRanges, Frame};
use std::time::{Duration, Instant};

const MSS: usize = 1200;
const CWND: usize = 4 * 1024 * 1024;

fn seeded_recovery(in_flight: u64, now: Instant) -> Recovery {
    let mut rec = Recovery::new(CWND, MSS);
    for pn in 0..in_flight {
        rec.on_packet_sent_in_space(
            PacketSpace::Application,
            pn,
            MSS,
            true,
            true,
            None,
            now,
        );
    }
    rec
}

fn ack_frame(blocks: u64) -> Frame<'static> {
    let ranges: AckRanges = (0..blocks).map(|i| (i * 2, i * 2 + 1)).collect();
    Frame::Ack { ack_delay: 100, ranges, ecn_counts: None }
}

/// Steady state: send one new packet, ACK the oldest — constant window,
/// exercises the scratch-reuse path that must not allocate.
fn bench_recovery_ack_steady(c: &mut Criterion) {
    let mut g = c.benchmark_group("recovery_ack_steady");
    for window in [8u64, 64, 256] {
        g.bench_with_input(BenchmarkId::from_parameter(window), &window, |b, &n| {
            let now = Instant::now();
            let mut rec = seeded_recovery(n, now);
            let mut next_pn = n;
            let mut base = 0u64;
            b.iter(|| {
                rec.on_packet_sent_in_space(
                    PacketSpace::Application,
                    next_pn,
                    MSS,
                    true,
                    true,
                    None,
                    now,
                );
                next_pn += 1;
                base += 1;
                let ranges = [(0u64, base)];
                let outcome = rec.on_ack_received(
                    PacketSpace::Application,
                    black_box(&ranges),
                    Duration::from_micros(50),
                    true,
                    false,
                    now,
                );
                black_box(&outcome);
            });
        });
    }
    g.finish();
}

/// Loss-heavy ACK: 64 packets in flight, only the highest acknowledged —
/// loss detection marks the remainder on a cold Recovery each iteration.
fn bench_recovery_ack_loss(c: &mut Criterion) {
    c.bench_function("recovery_ack_loss_64", |b| {
        let now = Instant::now();
        b.iter_batched(
            || seeded_recovery(64, now),
            |mut rec| {
                let ranges = [(63u64, 64)];
                let outcome = rec.on_ack_received(
                    PacketSpace::Application,
                    black_box(&ranges),
                    Duration::from_micros(50),
                    true,
                    false,
                    now,
                );
                black_box(&outcome);
            },
            BatchSize::SmallInput,
        );
    });
}

/// Emission side: PktNumSpace builds the ACK ranges the transport serializes.
/// 8 received blocks stay inside the inline AckRanges capacity; 64 spill.
fn bench_pnspace_ack_emit(c: &mut Criterion) {
    let mut g = c.benchmark_group("pnspace_ack_emit");
    for blocks in [8usize, 64] {
        g.bench_with_input(BenchmarkId::from_parameter(blocks), &blocks, |b, &n| {
            let now = Instant::now();
            let mut space = PktNumSpace::new();
            for i in 0..n as u64 {
                space.on_packet_recv(i * 2);
            }
            // The transport sets `ack_elicited` when an inbound packet demands
            // an ACK; without it peek_ack_at takes the None fast path.
            space.ack_elicited = true;
            b.iter(|| {
                let ack = space.peek_ack_at(3, black_box(now));
                black_box(&ack);
            });
        });
    }
    g.finish();
}

/// Wire parse: one ACK frame per iteration — inline vs spilled AckRanges.
fn bench_frame_ack_parse(c: &mut Criterion) {
    let mut g = c.benchmark_group("frame_ack_parse");
    for blocks in [1u64, 8, 64] {
        let frame = ack_frame(blocks);
        let mut wire = [0u8; 2048];
        let len = frames::to_bytes(&frame, &mut wire).expect("ack encode");
        g.bench_with_input(BenchmarkId::from_parameter(blocks), &len, |b, &len| {
            b.iter(|| {
                let (parsed, used) =
                    frames::from_bytes(black_box(&wire[..len]), PacketType::Short)
                        .expect("ack decode");
                black_box((&parsed, used));
            });
        });
    }
    g.finish();
}

/// Wire emit: serialize an ACK frame — inline vs spilled AckRanges.
fn bench_frame_ack_emit(c: &mut Criterion) {
    let mut g = c.benchmark_group("frame_ack_emit");
    for blocks in [1u64, 8, 64] {
        let frame = ack_frame(blocks);
        let mut wire = [0u8; 2048];
        g.bench_with_input(BenchmarkId::from_parameter(blocks), &frame, |b, frame| {
            b.iter(|| {
                let used = frames::to_bytes(black_box(frame), &mut wire).expect("ack encode");
                black_box(used);
            });
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_recovery_ack_steady,
    bench_recovery_ack_loss,
    bench_pnspace_ack_emit,
    bench_frame_ack_parse,
    bench_frame_ack_emit,
);
criterion_main!(benches);
