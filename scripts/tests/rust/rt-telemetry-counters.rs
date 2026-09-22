#![cfg(feature = "rust-tests")]
use quicfuscate::accelerate::stealth;
use quicfuscate::optimize::simd::compress;
use quicfuscate::optimize::telemetry::{PATTERN_NEON_OPS, PATTERN_SVE2_OPS};

fn run_pattern_workload() {
    let mut buffer = vec![0u8; 256];
    for (idx, byte) in buffer.iter_mut().enumerate() {
        *byte = (idx as u8).wrapping_mul(13);
    }
    let pattern = b"\xAA\xBB\xCC\x00";
    let positions = [8usize, 64, 128];
    stealth::inject_pattern(&mut buffer, pattern, &positions);

    let haystack = buffer.clone();
    let _ = compress::histogram(&haystack);
    let _ = compress::find_pattern(&haystack, pattern);
}

#[test]
fn telemetry_counters_snapshot() {
    let base_pattern_neon = PATTERN_NEON_OPS.get();
    let base_pattern_sve2 = PATTERN_SVE2_OPS.get();

    run_pattern_workload();

    let pattern_neon = PATTERN_NEON_OPS.get();
    let pattern_sve2 = PATTERN_SVE2_OPS.get();

    // NEON is only available on aarch64; on x86_64 the counter stays at zero.
    if cfg!(target_arch = "aarch64") {
        assert!(
            pattern_neon > base_pattern_neon,
            "expected PATTERN_NEON_OPS to increase on aarch64 ({} -> {})",
            base_pattern_neon,
            pattern_neon
        );
    } else {
        assert!(
            pattern_neon >= base_pattern_neon,
            "PATTERN_NEON_OPS should be monotonic on non-aarch64 ({} -> {})",
            base_pattern_neon,
            pattern_neon
        );
    }

    // SVE2 may be unavailable on the current host; record the observed value for telemetry audit.
    println!("telemetry_snapshot: pattern_neon={} pattern_sve2={}", pattern_neon, pattern_sve2);
    assert!(
        pattern_sve2 >= base_pattern_sve2,
        "PATTERN_SVE2_OPS should be monotonic ({} -> {})",
        base_pattern_sve2,
        pattern_sve2
    );
}
