use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use quicfuscate::fec::gf_tables::{
    gf_mul,
    gf_mul_table,
    init_gf_tables,
    
    #[cfg(target_arch = "x86_64")]
    gf_mul_bitsliced_avx2,
    #[cfg(target_arch = "x86_64")]
    gf_mul_bitsliced_avx512,
    #[cfg(target_arch = "aarch64")]
    gf_mul_bitsliced_neon,
};

fn gf_bitslice_bench(c: &mut Criterion) {
    init_gf_tables();
    let a: Vec<u8> = (0..1024).map(|i| i as u8).collect();
    let b: Vec<u8> = (0..1024).map(|i| (255 - i) as u8).collect();

    let mut group = c.benchmark_group("gf_bitslice_vs_table");
    group.bench_function(BenchmarkId::new("dispatch", 0), |bencher| {
        bencher.iter(|| {
            let mut acc = 0u8;
            for i in 0..a.len() {
                acc ^= gf_mul(black_box(a[i]), black_box(b[i]));
            }
            black_box(acc);
        });
    });

    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("pclmulqdq") {
            group.bench_function(BenchmarkId::new("avx2", 0), |bencher| {
                bencher.iter(|| {
                    let mut acc = 0u8;
                    for i in 0..a.len() {
                        unsafe { acc ^= gf_mul_bitsliced_avx2(black_box(a[i]), black_box(b[i])); }
                    }
                    black_box(acc);
                });
            });
        }
        if std::is_x86_feature_detected!("avx512f")
            && std::is_x86_feature_detected!("avx512vbmi")
            && std::is_x86_feature_detected!("pclmulqdq")
        {
            group.bench_function(BenchmarkId::new("avx512", 0), |bencher| {
                bencher.iter(|| {
                    let mut acc = 0u8;
                    for i in 0..a.len() {
                        unsafe {
                            acc ^= gf_mul_bitsliced_avx512(black_box(a[i]), black_box(b[i]));
                        }
                    }
                    black_box(acc);
                });
            });
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("pmull") {
            group.bench_function(BenchmarkId::new("neon", 0), |bencher| {
                bencher.iter(|| {
                    let mut acc = 0u8;
                    for i in 0..a.len() {
                        unsafe {
                            acc ^= gf_mul_bitsliced_neon(black_box(a[i]), black_box(b[i]));
                        }
                    }
                    black_box(acc);
                });
            });
        }
    }

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
