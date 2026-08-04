#![cfg(feature = "rust-tests")]

#[cfg(target_arch = "aarch64")]
use quicfuscate::accelerate::random;

#[test]
#[cfg(target_arch = "aarch64")]
fn optimize_random_helpers_provide_nonsecurity_words_and_scalars() {
    let mut words = [0u32; 16];
    random::random_array_u32(&mut words);
    assert!(
        words.iter().any(|&word| word != 0),
        "random_array_u32 must produce non-zero-looking output"
    );

    let a = random::random_u64();
    let b = random::random_u64();
    assert_ne!(a, b, "non-security helper should advance its per-thread PRNG state");
}

#[cfg(not(target_arch = "aarch64"))]
#[test]
#[ignore = "SKIP: target requires aarch64"]
fn skip_random_aes_ctr_on_non_aarch64() {}
