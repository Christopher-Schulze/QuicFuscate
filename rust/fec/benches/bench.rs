use criterion::{criterion_group, criterion_main, Criterion};
use fec::{EncoderCore, FecAlgorithm};

fn bench_encode(c: &mut Criterion) {
    let data = vec![0u8; 4096];
    for algo in [FecAlgorithm::StripeXor, FecAlgorithm::SparseRlnc, FecAlgorithm::Cm256, FecAlgorithm::ReedSolomon] {
        let enc = EncoderCore::new(algo);
        let name = format!("{:?}", algo);
        c.bench_function(&name, |b| b.iter(|| enc.encode(&data, 1)));
    }
}

criterion_group!(benches, bench_encode);
criterion_main!(benches);
