use criterion::{black_box, criterion_group, criterion_main, Criterion};
use quicfuscate::fec::gf_tables::{gf_mul, init_gf_tables};

fn bench_gf_bitslice(c: &mut Criterion) {
    init_gf_tables();
    let a: Vec<u8> = (0..1024).map(|i| i as u8).collect();
    let b: Vec<u8> = (0..1024).map(|i| (255 - i) as u8).collect();

    c.bench_function("gf_mul bitslice", |bencher| {
        bencher.iter(|| {
            let mut acc = 0u8;
            for i in 0..a.len() {
                acc ^= gf_mul(black_box(a[i]), black_box(b[i]));
            }
            black_box(acc);
        });
    });
}

criterion_group!(benches, bench_gf_bitslice);
criterion_main!(benches);
