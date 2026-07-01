// Criterion benchmarks for CI regression detection (TODO-154).
//
// Covers the performance-critical hotpath operations:
// - AES-128 block encrypt (handshake crypto)
// - GHASH (GCM authentication)
// - AES-128-GCM seal (handshake AEAD)
// - MORUS encrypt/decrypt (data-plane AEAD)
// - Varint encode/decode (QUIC transport framing)
// - QUIC header validation (SIMD-routed)
// - Popcnt (ECN/bitmap ops)
// - Secure RNG fill (entropy path)

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

// ---------------------------------------------------------------------------
// AES-128 block encrypt
// ---------------------------------------------------------------------------
fn bench_aes_block(c: &mut Criterion) {
    use quicfuscate::crypto::aes::aes128_encrypt_block;

    let key = [0u8; 16];
    let block = [0u8; 16];

    let mut group = c.benchmark_group("aes128_block");
    group.throughput(Throughput::Bytes(16));
    group.bench_function("encrypt_1block", |b| {
        b.iter(|| {
            black_box(aes128_encrypt_block(black_box(&key), black_box(&block)));
        });
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// GHASH
// ---------------------------------------------------------------------------
fn bench_ghash(c: &mut Criterion) {
    use quicfuscate::crypto::aes::aes128_encrypt_block;
    use quicfuscate::crypto::gcm::ghash;

    let key = [0u8; 16];
    let zero = [0u8; 16];
    let h = aes128_encrypt_block(&key, &zero);

    for size in [64, 1024, 8192] {
        let ct = vec![0u8; size];
        let aad: [u8; 0] = [];
        let mut group = c.benchmark_group("ghash");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}B"), |b| {
            b.iter(|| {
                black_box(ghash(black_box(h), black_box(&aad), black_box(&ct)));
            });
        });
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// AES-128-GCM seal
// ---------------------------------------------------------------------------
fn bench_aes_gcm(c: &mut Criterion) {
    use quicfuscate::crypto::gcm::aes_gcm_seal;

    let key = [0u8; 16];
    let iv = [0u8; 12];
    let aad: [u8; 0] = [];

    for size in [64, 1024, 8192] {
        let pt = vec![0u8; size];
        let mut group = c.benchmark_group("aes_gcm_seal");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}B"), |b| {
            b.iter(|| {
                black_box(aes_gcm_seal(
                    black_box(&key),
                    black_box(&iv),
                    black_box(&aad),
                    black_box(&pt),
                ));
            });
        });
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// MORUS encrypt
// ---------------------------------------------------------------------------
fn bench_morus_encrypt(c: &mut Criterion) {
    use quicfuscate::crypto::MorusAead;

    let key = [0u8; 16];
    let iv = [0u8; 12];
    let nonce = [0u8; 16];
    let ad: [u8; 0] = [];
    let morus = MorusAead::new(&key, &iv);

    for size in [64, 1024, 8192] {
        let mut buffer = vec![0u8; size];
        let mut group = c.benchmark_group("morus_encrypt");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}B"), |b| {
            b.iter(|| {
                // Reset buffer content between iterations to avoid constant folding
                buffer.fill(0xAA);
                black_box(morus.encrypt_in_place(
                    black_box(&mut buffer),
                    black_box(&ad),
                    black_box(&nonce),
                ));
            });
        });
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// MORUS decrypt
// ---------------------------------------------------------------------------
fn bench_morus_decrypt(c: &mut Criterion) {
    use quicfuscate::crypto::MorusAead;

    let key = [0xA5u8; 16];
    let iv = [0x5Au8; 12];
    let nonce = [0u8; 16];
    let ad: [u8; 0] = [];
    let morus = MorusAead::new(&key, &iv);

    for size in [64, 1024, 8192] {
        let plaintext = vec![0u8; size];
        let mut ciphertext = plaintext.clone();
        let tag = morus.encrypt_in_place(&mut ciphertext, &ad, &nonce);
        let frozen_ct = ciphertext.clone();

        let mut group = c.benchmark_group("morus_decrypt");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}B"), |b| {
            let mut work = vec![0u8; size];
            b.iter(|| {
                work.copy_from_slice(&frozen_ct);
                let _ = black_box(morus.decrypt_in_place(
                    black_box(&mut work),
                    black_box(&tag),
                    black_box(&ad),
                    black_box(&nonce),
                ));
            });
        });
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// Varint encode + decode roundtrip
// ---------------------------------------------------------------------------
fn bench_varint(c: &mut Criterion) {
    use quicfuscate::simd::transport::{decode_varint, encode_varint};

    let corpus: [u64; 8] = [0, 1, 63, 64, 16_383, 16_384, (1u64 << 30) - 1, (1u64 << 62) - 1];

    let mut group = c.benchmark_group("varint");
    group.throughput(Throughput::Elements(corpus.len() as u64));
    group.bench_function("roundtrip_8vals", |b| {
        let mut buf = [0u8; 16];
        b.iter(|| {
            for &v in &corpus {
                let used = encode_varint(black_box(v), &mut buf);
                black_box(decode_varint(&buf[..used]));
            }
        });
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// QUIC header validation (SIMD-routed)
// ---------------------------------------------------------------------------
fn bench_header_validate(c: &mut Criterion) {
    use quicfuscate::simd::fec::validate_header;

    let short = [0x40u8, 0, 0, 0, 0];
    let long = [0xC0u8, 0, 0, 0, 0];

    let mut group = c.benchmark_group("header_validate");
    group.throughput(Throughput::Elements(2));
    group.bench_function("short_and_long", |b| {
        b.iter(|| {
            black_box(validate_header(black_box(&short)));
            black_box(validate_header(black_box(&long)));
        });
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Popcnt (ECN / bitmap operations)
// ---------------------------------------------------------------------------
fn bench_popcnt(c: &mut Criterion) {
    use quicfuscate::simd::core::popcnt;

    for size in [64, 1024, 8192] {
        let mut data = vec![0u8; size];
        for (i, v) in data.iter_mut().enumerate() {
            *v = (i as u8).wrapping_mul(7).wrapping_add(1);
        }

        let mut group = c.benchmark_group("popcnt");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}B"), |b| {
            b.iter(|| {
                black_box(popcnt(black_box(&data)));
            });
        });
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// Secure RNG fill
// ---------------------------------------------------------------------------
fn bench_rng_fill(c: &mut Criterion) {
    for size in [64, 1024, 8192] {
        let mut buf = vec![0u8; size];

        let mut group = c.benchmark_group("rng_fill");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}B"), |b| {
            b.iter(|| {
                quicfuscate::rng::fill_secure_or_abort(black_box(&mut buf), "bench::rng_fill");
            });
        });
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// FEC: GF(256) matrix multiply (core Reed-Solomon encoding operation)
// ---------------------------------------------------------------------------
fn bench_fec_matrix_mul(c: &mut Criterion) {
    use quicfuscate::fec::matrix_multiply_scalar;

    for dim in [4, 8, 16] {
        let a: Vec<Vec<u8>> = (0..dim)
            .map(|r| (0..dim).map(|col| ((r * dim + col) as u8).wrapping_mul(3)).collect())
            .collect();
        let b: Vec<Vec<u8>> = (0..dim)
            .map(|r| (0..dim).map(|col| ((r * dim + col) as u8).wrapping_add(17)).collect())
            .collect();
        let mut result: Vec<Vec<u8>> = (0..dim).map(|_| vec![0u8; dim]).collect();

        let mut group = c.benchmark_group("fec_matrix_mul");
        group.throughput(Throughput::Elements((dim * dim) as u64));
        group.bench_function(format!("{dim}x{dim}"), |bench| {
            bench.iter(|| {
                for row in result.iter_mut() {
                    row.fill(0);
                }
                matrix_multiply_scalar(&a, &b, &mut result);
                black_box(&result);
            });
        });
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// Stealth: TLS record padding
// ---------------------------------------------------------------------------
fn bench_padding_gen(c: &mut Criterion) {
    use quicfuscate::optimize::stealth::add_tls_padding;

    for size in [128, 512, 1400] {
        let mut group = c.benchmark_group("padding_gen");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("pad_to_{size}B"), |b| {
            let mut record = Vec::with_capacity(size);
            b.iter(|| {
                record.clear();
                record.extend_from_slice(&[0xAA; 64]); // 64-byte payload
                add_tls_padding(black_box(&mut record), black_box(size), 0x00);
                black_box(&record);
            });
        });
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// Transport: QUIC stealth padding decision logic
// ---------------------------------------------------------------------------
fn bench_transport_stealth_padding_decision(c: &mut Criterion) {
    use quicfuscate::transport::bench_paired_1rtt_connections;

    let mut group = c.benchmark_group("transport_stealth_padding_decision");
    group.throughput(Throughput::Elements(1));

    for (name, enabled, strategy, rate, granularity, mimic_bias) in [
        ("disabled", false, 0u8, 100u8, 64u16, 3u8),
        ("adaptive_0pct", true, 3u8, 0u8, 64u16, 3u8),
        ("adaptive_100pct", true, 3u8, 100u8, 64u16, 3u8),
        ("browser_mimic_100pct", true, 4u8, 100u8, 64u16, 3u8),
        ("random_50pct", true, 1u8, 50u8, 64u16, 3u8),
    ] {
        group.bench_function(name, |bench| {
            let mut pair = bench_paired_1rtt_connections();
            pair.client.bench_set_stealth_padding(
                enabled,
                strategy,
                256,
                rate,
                granularity,
                mimic_bias,
            );
            let mut cur_pt_len = 64usize;

            bench.iter(|| {
                cur_pt_len = cur_pt_len.wrapping_add(37);
                let current = 64 + (cur_pt_len & 1023);
                black_box(pair.client.bench_compute_stealth_padding(black_box(current), 256));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Transport: packet number encode
// ---------------------------------------------------------------------------
fn bench_pkt_num_encode(c: &mut Criterion) {
    use quicfuscate::transport::packet::encode_pkt_num;

    let mut group = c.benchmark_group("packet_number");
    group.throughput(Throughput::Elements(4));
    group.bench_function("encode_all_lengths", |b| {
        let mut out = [0u8; 4];
        b.iter(|| {
            for pn_len in 1..=4usize {
                let _ = encode_pkt_num(black_box(0x1234_5678u64), black_box(pn_len), &mut out);
            }
            black_box(&out);
        });
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Optimization: SIMD sort (u32)
// ---------------------------------------------------------------------------
fn bench_sort(c: &mut Criterion) {
    use quicfuscate::optimize::sort::sort_u32;

    for size in [256, 1024, 8192] {
        let template: Vec<u32> = (0..size)
            .map(|i| (i as u32).wrapping_mul(2654435761)) // Knuth multiplicative hash
            .collect();

        let mut group = c.benchmark_group("sort_simd");
        group.throughput(Throughput::Elements(size as u64));
        group.bench_function(format!("{size}_elems"), |b| {
            let mut data = template.clone();
            b.iter(|| {
                data.copy_from_slice(&template);
                sort_u32(black_box(&mut data));
            });
        });
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// Optimization: Fisher-Yates shuffle (SIMD-accelerated)
// ---------------------------------------------------------------------------
fn bench_shuffle_op(c: &mut Criterion) {
    use quicfuscate::optimize::random::shuffle;

    for size in [256, 1024, 8192] {
        let mut data: Vec<u32> = (0..size).collect();

        let mut group = c.benchmark_group("shuffle_simd");
        group.throughput(Throughput::Elements(size as u64));
        group.bench_function(format!("{size}_elems"), |b| {
            b.iter(|| {
                shuffle(black_box(&mut data));
            });
        });
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// Optimization: cache-aware matrix transpose
// ---------------------------------------------------------------------------
fn bench_transpose(c: &mut Criterion) {
    use quicfuscate::optimize::memory::transpose_matrix;

    for dim in [64, 256] {
        let template: Vec<u32> = (0..dim * dim).map(|i| i as u32).collect();

        let mut group = c.benchmark_group("memory_transpose");
        group.throughput(Throughput::Elements((dim * dim) as u64));
        group.bench_function(format!("{dim}x{dim}"), |b| {
            let mut data = template.clone();
            b.iter(|| {
                transpose_matrix(black_box(&mut data), dim, dim);
            });
        });
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// Connection 1-RTT send/recv loop (TODO-399)
// ---------------------------------------------------------------------------
fn bench_connection_1rtt_send_recv(c: &mut Criterion) {
    use quicfuscate::error::ConnectionError;
    use quicfuscate::transport::{bench_paired_1rtt_connections, BenchConnectionPair};

    let mut group = c.benchmark_group("connection_1rtt_send_recv");
    for payload_len in [256usize, 1024, 1400] {
        let payload = vec![0x5Au8; payload_len];
        group.throughput(Throughput::Bytes((payload_len * 2) as u64));
        group.bench_function(format!("payload_{payload_len}B"), |b| {
            b.iter(|| {
                let BenchConnectionPair { mut client, mut server, recv_info } =
                    bench_paired_1rtt_connections();
                let mut wire = [0u8; 2048];
                black_box(client.stream_send(0, black_box(&payload), false)).expect("stream_send");
                let (sent, _) = black_box(client.send(&mut wire)).expect("send");
                if sent == 0 {
                    panic!("expected encrypted 1-RTT packet");
                }
                match black_box(server.recv(&mut wire[..sent], &recv_info)) {
                    Ok(_) => {}
                    Err(ConnectionError::Done) => {}
                    Err(e) => panic!("recv failed: {e:?}"),
                }
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// ACK sent-byte accounting under N in-flight PNs (TODO-400)
// ---------------------------------------------------------------------------
fn bench_ack_sent_byte_accounting(c: &mut Criterion) {
    use quicfuscate::transport::{bench_paired_1rtt_connections, BenchConnectionPair};

    let mut group = c.benchmark_group("ack_sent_byte_accounting");
    for inflight in [32u64, 128, 512, 1024, 2048, 10240] {
        group.throughput(Throughput::Elements(inflight));
        group.bench_function(format!("{inflight}_inflight_ack_all"), |b| {
            b.iter(|| {
                let BenchConnectionPair { mut client, .. } = bench_paired_1rtt_connections();
                client.bench_seed_sent_bytes_by_pn(inflight, 1200);
                let ranges = [(0u64, inflight)];
                client.bench_account_ack_ranges(black_box(&ranges));
                black_box(());
            });
        });
        group.bench_function(format!("{inflight}_inflight_ack_half"), |b| {
            b.iter(|| {
                let half = inflight / 2;
                let BenchConnectionPair { mut client, .. } = bench_paired_1rtt_connections();
                client.bench_seed_sent_bytes_by_pn(inflight, 1200);
                let ranges = [(0u64, half)];
                client.bench_account_ack_ranges(black_box(&ranges));
                black_box(());
            });
        });
    }

    // Sparse ACK ranges (every 4th PN) to stress range iteration vs map size.
    for inflight in [512u64, 2048, 10240] {
        group.bench_function(format!("{inflight}_inflight_ack_sparse"), |b| {
            b.iter(|| {
                let BenchConnectionPair { mut client, .. } = bench_paired_1rtt_connections();
                client.bench_seed_sent_bytes_by_pn(inflight, 1200);
                let mut ranges = Vec::with_capacity((inflight / 4) as usize);
                let mut start = 0u64;
                while start < inflight {
                    let end = (start + 1).min(inflight);
                    ranges.push((start, end));
                    start += 4;
                }
                client.bench_account_ack_ranges(black_box(&ranges));
                black_box(());
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Stealth on vs off on the same 1-RTT workload (TODO-401)
// ---------------------------------------------------------------------------
fn bench_connection_1rtt_stealth_compare(c: &mut Criterion) {
    use quicfuscate::error::ConnectionError;
    use quicfuscate::transport::{bench_paired_1rtt_connections_stealth, BenchConnectionPair};

    let payload = vec![0x5Au8; 1024];
    let mut group = c.benchmark_group("connection_1rtt_stealth_compare");
    group.throughput(Throughput::Bytes((payload.len() * 2) as u64));
    for (label, stealth_on) in [("stealth_off", false), ("stealth_on", true)] {
        group.bench_function(label, |b| {
            b.iter(|| {
                let BenchConnectionPair { mut client, mut server, recv_info } =
                    bench_paired_1rtt_connections_stealth(stealth_on);
                let mut wire = [0u8; 2048];
                black_box(client.stream_send(0, black_box(&payload), false)).expect("stream_send");
                let (sent, _) = black_box(client.send(&mut wire)).expect("send");
                if sent == 0 {
                    panic!("expected encrypted 1-RTT packet");
                }
                match black_box(server.recv(&mut wire[..sent], &recv_info)) {
                    Ok(_) => {}
                    Err(ConnectionError::Done) => {}
                    Err(e) => panic!("recv failed: {e:?}"),
                }
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Brain: TransportObserver policy application
// ---------------------------------------------------------------------------
fn bench_brain_apply_policy(c: &mut Criterion) {
    use quicfuscate::brain::{StealthBrain, StealthBrainConfig};
    use quicfuscate::transport::{
        bench_paired_1rtt_connections, BrainRuntimePermissions, TransportObserver,
    };

    #[derive(Clone, Copy)]
    struct BrainCase {
        name: &'static str,
        intelligent_runtime: bool,
        policy_cooldown_ms: u64,
        ack_delay: u64,
        ect0: u64,
        ce: u64,
    }

    let mut group = c.benchmark_group("brain_apply_policy");
    group.throughput(Throughput::Elements(1));

    for case in [
        BrainCase {
            name: "clean_observer",
            intelligent_runtime: false,
            policy_cooldown_ms: 300,
            ack_delay: 900,
            ect0: 10_000,
            ce: 0,
        },
        BrainCase {
            name: "intelligent_clean",
            intelligent_runtime: true,
            policy_cooldown_ms: 300,
            ack_delay: 900,
            ect0: 10_000,
            ce: 0,
        },
        BrainCase {
            name: "intelligent_pressure_actuating",
            intelligent_runtime: true,
            policy_cooldown_ms: 0,
            ack_delay: 18_000,
            ect0: 9_400,
            ce: 600,
        },
    ] {
        group.bench_function(case.name, |bench| {
            let mut pair = bench_paired_1rtt_connections();
            pair.client.bench_set_brain_runtime(
                case.intelligent_runtime,
                BrainRuntimePermissions::default(),
            );

            let brain = StealthBrain::new(StealthBrainConfig {
                policy_cooldown_ms: case.policy_cooldown_ms,
                explore_prob: 0.0,
                ..Default::default()
            });
            for pn in 0..256u64 {
                brain.on_packet_recv(pn, 64 + ((pn as usize * 37) & 1023));
            }
            let ranges = [(1u64, 16u64)];

            bench.iter(|| {
                brain.on_ack(black_box(case.ack_delay), black_box(&ranges));
                brain.on_ecn_update(black_box(case.ect0), black_box(0), black_box(case.ce));
                brain.apply_policy(black_box(&mut pair.client));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Group registration
// ---------------------------------------------------------------------------
criterion_group!(
    crypto_benches,
    bench_aes_block,
    bench_ghash,
    bench_aes_gcm,
    bench_morus_encrypt,
    bench_morus_decrypt,
);

criterion_group!(
    transport_benches,
    bench_varint,
    bench_header_validate,
    bench_popcnt,
    bench_rng_fill,
    bench_pkt_num_encode,
    bench_transport_stealth_padding_decision,
    bench_connection_1rtt_send_recv,
    bench_ack_sent_byte_accounting,
    bench_connection_1rtt_stealth_compare,
    bench_brain_apply_policy,
);

criterion_group!(fec_benches, bench_fec_matrix_mul,);

criterion_group!(stealth_benches, bench_padding_gen,);

criterion_group!(optimization_benches, bench_sort, bench_shuffle_op, bench_transpose,);

criterion_main!(
    crypto_benches,
    transport_benches,
    fec_benches,
    stealth_benches,
    optimization_benches
);
