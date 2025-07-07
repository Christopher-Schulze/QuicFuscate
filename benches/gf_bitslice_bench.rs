use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use quicfuscate::fec::gf_tables::{gf_mul, gf_mul_table, init_gf_tables};

fn gf_bitslice_bench(c: &mut Criterion) {
    init_gf_tables();
    let a: Vec<u8> = (0..1024).map(|i| i as u8).collect();
    let b: Vec<u8> = (0..1024).map(|i| (255 - i) as u8).collect();

    let mut group = c.benchmark_group("gf_bitslice_vs_table");
    group.bench_function(BenchmarkId::new("bitsliced", 0), |bencher| {
        bencher.iter(|| {
            let mut acc = 0u8;
            for i in 0..a.len() {
                acc ^= gf_mul(black_box(a[i]), black_box(b[i]));
            }
            black_box(acc);
        });
    });

    group.bench_function(BenchmarkId::new("table", 0), |bencher| {
        bencher.iter(|| {
            let mut acc = 0u8;
            for i in 0..a.len() {
                acc ^= gf_mul_table(black_box(a[i]), black_box(b[i]));
            }
            black_box(acc);
        });
    });
    group.finish();
}

criterion_group!(benches, gf_bitslice_bench);
criterion_main!(benches);
