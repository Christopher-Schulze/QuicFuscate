use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use quicfuscate::stealth::{OsFingerprintProfile, PacketNormalizer};
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

fn ipv4_udp_packet() -> [u8; 64] {
    let mut packet = [0u8; 64];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&64u16.to_be_bytes());
    packet[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    packet[8] = 37;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
    packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
    packet
}

fn ipv4_tcp_syn_packet() -> [u8; 64] {
    let mut packet = [0u8; 64];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&64u16.to_be_bytes());
    packet[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    packet[8] = 37;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
    packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
    packet[20..22].copy_from_slice(&40_000u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443u16.to_be_bytes());
    packet[32] = 11 << 4;
    packet[33] = 0x02;
    packet[34..36].copy_from_slice(&8192u16.to_be_bytes());
    packet[40..64].copy_from_slice(&[
        2, 4, 0x05, 0xb4, 4, 2, 1, 3, 3, 7, 1, 1, 8, 10, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 1, 1,
    ]);
    packet
}

fn assert_zero_hot_path_allocations() {
    let udp_template = ipv4_udp_packet();
    let syn_template = ipv4_tcp_syn_packet();
    let normalizer = PacketNormalizer::new(OsFingerprintProfile::MacOS);
    let mut packet = [0u8; 68];

    packet[..64].copy_from_slice(&udp_template);
    black_box(normalizer.normalize_with_capacity(&mut packet, 64));
    packet[..64].copy_from_slice(&syn_template);
    black_box(normalizer.normalize_with_capacity(&mut packet, 64));

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNT_ALLOCATIONS.store(true, Ordering::SeqCst);
    for index in 0..100_000 {
        let template = if index & 1 == 0 { &udp_template } else { &syn_template };
        packet[..64].copy_from_slice(template);
        black_box(normalizer.normalize_with_capacity(&mut packet, 64));
    }
    COUNT_ALLOCATIONS.store(false, Ordering::SeqCst);

    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 0, "fingerprint normalizer hot path allocated");
}

fn benchmark_fingerprint_normalizer(c: &mut Criterion) {
    assert_zero_hot_path_allocations();

    let template = ipv4_udp_packet();
    let normalizer = PacketNormalizer::new(OsFingerprintProfile::Linux);
    let mut group = c.benchmark_group("fingerprint_normalizer");
    group.throughput(Throughput::Bytes(template.len() as u64));
    group.bench_function("ipv4_udp_hot_path", |b| {
        let mut packet = template;
        b.iter(|| {
            packet.copy_from_slice(black_box(&template));
            black_box(normalizer.normalize(&mut packet))
        });
    });
    group.finish();
}

criterion_group!(fingerprint_normalizer_benches, benchmark_fingerprint_normalizer);
criterion_main!(fingerprint_normalizer_benches);
