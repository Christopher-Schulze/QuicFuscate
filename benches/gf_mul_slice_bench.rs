use criterion::{black_box, criterion_group, criterion_main, Criterion};
use quicfuscate::fec::gf_tables::{gf_mul_slice, init_gf_tables};

fn bench_gf_mul_slice(c: &mut Criterion) {
    init_gf_tables();
    let a: Vec<u8> = (0..1024).map(|i| i as u8).collect();
    let b: Vec<u8> = (0..1024).map(|i| (255 - i) as u8).collect();
    let mut out = vec![0u8; a.len()];

    c.bench_function("gf_mul_slice", |bencher| {
        bencher.iter(|| {
            gf_mul_slice(black_box(&a), black_box(&b), black_box(&mut out));
        });
    });
}

criterion_group!(benches, bench_gf_mul_slice);
criterion_main!(benches);
