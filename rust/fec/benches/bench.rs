use criterion::{criterion_group, criterion_main, Criterion};
use fec::{EncoderCore, FecAlgorithm};

fn bench_encode(c: &mut Criterion) {
    let data = vec![0u8; 4096];
    let enc = EncoderCore::new(FecAlgorithm::StripeXor);
    c.bench_function("stripe_xor", |b| b.iter(|| enc.encode(&data, 1)));
}

criterion_group!(benches, bench_encode);
criterion_main!(benches);
