use criterion::{criterion_group, criterion_main, Criterion};
use quicfuscate::fec::gf_mul;

fn bench_gf_mul(c: &mut Criterion) {
    c.bench_function("gf_mul", |b| {
        b.iter(|| {
            let mut acc = 0u8;
            for a in 1u8..=10 {
                for b_ in 1u8..=10 {
                    acc ^= gf_mul(a, b_);
                }
            }
            criterion::black_box(acc);
        })
    });
}

criterion_group!(benches, bench_gf_mul);
criterion_main!(benches);
