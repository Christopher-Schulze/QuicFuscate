use criterion::{criterion_group, criterion_main, Criterion};
use quicfuscate::optimize::MemoryPool;

fn bench_pool_alloc(c: &mut Criterion) {
    let pool = MemoryPool::new(1024, 1024);
    c.bench_function("memory_pool alloc/free", |b| {
        b.iter(|| {
            let block = pool.alloc();
            pool.free(block);
        });
    });
}

criterion_group!(benches, bench_pool_alloc);
criterion_main!(benches);
