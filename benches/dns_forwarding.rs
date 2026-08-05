use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use quicfuscate::dns::{build_dns_servfail_from_packet, DNS_HEADER_SIZE, DNS_MESSAGE_MAX_SIZE};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct CountingAllocator;

static COUNT_ALLOCATIONS: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNT_ALLOCATIONS.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNT_ALLOCATIONS.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

const MEASUREMENT_ITERATIONS: usize = 10_000;

fn measure_allocations<F, T>(mut operation: F) -> usize
where
    F: FnMut() -> T,
{
    black_box(operation());
    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNT_ALLOCATIONS.store(true, Ordering::SeqCst);
    for _ in 0..MEASUREMENT_ITERATIONS {
        black_box(operation());
    }
    COUNT_ALLOCATIONS.store(false, Ordering::SeqCst);
    ALLOCATIONS.load(Ordering::Relaxed)
}

fn doh_request_body(query: &[u8]) -> Vec<u8> {
    query.to_vec()
}

fn doh_response_body(chunks: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::with_capacity(DNS_HEADER_SIZE);
    for chunk in chunks {
        assert!(body.len() + chunk.len() <= DNS_MESSAGE_MAX_SIZE);
        body.extend_from_slice(chunk);
    }
    body
}

fn udp_receive_buffer() -> Vec<u8> {
    vec![0u8; DNS_MESSAGE_MAX_SIZE + 1]
}

fn synthetic_servfail(query: &[u8]) -> Vec<u8> {
    build_dns_servfail_from_packet(query).expect("measurement query contains a transaction ID")
}

fn benchmark_dns_forwarding(c: &mut Criterion) {
    let query = [0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
    let response_chunk_a = [0u8; 32];
    let response_chunk_b = [0u8; 32];
    let response_chunks = [&response_chunk_a[..], &response_chunk_b[..]];

    let evidence = [
        ("client_doh_query_body", measure_allocations(|| doh_request_body(&query))),
        ("client_doh_response_body", measure_allocations(|| doh_response_body(&response_chunks))),
        ("server_udp_receive_buffer", measure_allocations(udp_receive_buffer)),
        ("synthetic_servfail_response", measure_allocations(|| synthetic_servfail(&query))),
    ];
    for (name, allocations) in evidence {
        eprintln!(
            "dns allocation evidence: {name}: {allocations} allocations/{MEASUREMENT_ITERATIONS} iterations"
        );
        assert!(allocations > 0, "{name} allocation measurement was empty");
    }

    let mut group = c.benchmark_group("dns_forwarding");
    group.throughput(Throughput::Elements(1));
    group.bench_function("client_doh_query_body", |b| {
        b.iter(|| black_box(doh_request_body(black_box(&query))))
    });
    group.bench_function("client_doh_response_body", |b| {
        b.iter(|| black_box(doh_response_body(black_box(&response_chunks))))
    });
    group.bench_function("server_udp_receive_buffer", |b| {
        b.iter(|| black_box(udp_receive_buffer()))
    });
    group.bench_function("synthetic_servfail_response", |b| {
        b.iter(|| black_box(synthetic_servfail(black_box(&query))))
    });
    group.finish();
}

criterion_group!(dns_forwarding_benches, benchmark_dns_forwarding);
criterion_main!(dns_forwarding_benches);
