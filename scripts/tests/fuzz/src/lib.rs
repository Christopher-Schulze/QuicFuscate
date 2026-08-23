//! Stable deterministic fuzz verification for the six retained targets.
//!
//! Each target drives a public packet/frame/codec/AEAD surface with arbitrary bytes and must
//! accept or reject each input without a panic or a memory-unsafety abort. This crate replaces
//! the previous nightly-only `cargo-fuzz` + AddressSanitizer lane with a stable, reproducible
//! corpus + generated-input runner executed via `cargo test`. Coverage-guided mutation is out of
//! scope for the stable lane; crash regression over the curated seeds and a deterministic byte
//! generator remains in scope.

pub mod targets;

#[cfg(test)]
use std::path::PathBuf;

/// Canonical six targets, kept in sorted order to mirror the historical inventory.
pub const TARGETS: [&str; 6] = [
    "connection_handling",
    "crypto_operations",
    "fec_encoding",
    "frame_decoding",
    "packet_parsing",
    "varint_parsing",
];

#[cfg(test)]
fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[cfg(test)]
fn seeds_dir(target: &str) -> PathBuf {
    crate_root().join("seeds").join(target)
}

/// Load the curated seed corpus for `target`. A missing directory yields no seeds so the runner
/// stays resilient on a freshly cloned tree before seeds are materialized.
#[cfg(test)]
fn load_seeds(target: &str) -> Vec<Vec<u8>> {
    let dir = seeds_dir(target);
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        let mut paths: Vec<_> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
        paths.sort();
        for path in paths {
            if path.is_file() {
                if let Ok(bytes) = std::fs::read(&path) {
                    out.push(bytes);
                }
            }
        }
    }
    out
}

/// A small seedable xorshift32 generator so the generated input stream is deterministic and
/// reproducible across hosts and CI runs.
#[cfg(test)]
struct Rng(u32);

#[cfg(test)]
impl Rng {
    fn new(seed: u32) -> Self {
        // Avoid the degenerate all-zero state.
        Self(if seed == 0 { 0x9E37_79B9 } else { seed })
    }
    fn next_u32(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }
    fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i + 4 <= buf.len() {
            let v = self.next_u32().to_le_bytes();
            buf[i..i + 4].copy_from_slice(&v);
            i += 4;
        }
        if i < buf.len() {
            let v = self.next_u32().to_le_bytes();
            for (j, b) in buf[i..].iter_mut().enumerate() {
                *b = v[j];
            }
        }
    }
}

/// Deterministic generated inputs: fixed byte patterns plus seeded random buffers across a set
#[cfg(test)]
fn generated_inputs() -> Vec<Vec<u8>> {
    let lengths = [
        0usize, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 44, 45, 63, 64, 127, 128, 255, 256, 511, 512,
        1023, 1024, 4096,
    ];
    let mut out = Vec::new();
    for &len in &lengths {
        out.push(vec![0u8; len]);
        out.push(vec![0xFFu8; len]);
        out.push((0..len).map(|i| i as u8).collect());
        out.push((0..len).map(|i| 255 - i as u8).collect());
        out.push((0..len).map(|i| i.wrapping_mul(131) as u8).collect());
        let mut rng = Rng::new(len as u32 ^ 0xA5A5_A5A5);
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf);
        out.push(buf);
    }
    // Prefix truncation probes of a 512-byte random buffer so header edges stay covered.
    let mut rng = Rng::new(0x00C0_FFEE);
    let mut base = vec![0u8; 512];
    rng.fill(&mut base);
    for &take in &[1usize, 2, 4, 8, 16, 32, 64, 128] {
        out.push(base[..take].to_vec());
    }
    out
}

/// All inputs for a target: curated seeds, prefix truncations of every seed, then the
#[cfg(test)]
fn all_inputs(target: &str) -> Vec<Vec<u8>> {
    let mut out = load_seeds(target);
    for seed in load_seeds(target) {
        for &take in &[1usize, 2, 4, 8, 16] {
            if take <= seed.len() {
                out.push(seed[..take].to_vec());
            }
        }
    }
    out.extend(generated_inputs());
    out
}

/// Dispatch `data` to the named target's exercise function.
#[cfg(test)]
fn dispatch(target: &str, data: &[u8]) {
    match target {
        "connection_handling" => targets::connection_handling::exercise(data),
        "crypto_operations" => targets::crypto_operations::exercise(data),
        "fec_encoding" => targets::fec_encoding::exercise(data),
        "frame_decoding" => targets::frame_decoding::exercise(data),
        "packet_parsing" => targets::packet_parsing::exercise(data),
        "varint_parsing" => targets::varint_parsing::exercise(data),
        _ => panic!("unknown fuzz target: {target}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_target(target: &str) {
        let inputs = all_inputs(target);
        assert!(!inputs.is_empty(), "{target} produced no inputs");
        for data in &inputs {
            // A panic or abort inside `exercise` fails this test. The test harness catches the
            // unwind; `catch_unwind` would mask real aborts and is intentionally avoided.
            dispatch(target, data);
        }
    }

    #[test]
    fn connection_handling_stable() {
        run_target("connection_handling");
    }

    #[test]
    fn crypto_operations_stable() {
        run_target("crypto_operations");
    }

    #[test]
    fn fec_encoding_stable() {
        run_target("fec_encoding");
    }

    #[test]
    fn frame_decoding_stable() {
        run_target("frame_decoding");
    }

    #[test]
    fn packet_parsing_stable() {
        run_target("packet_parsing");
    }

    #[test]
    fn varint_parsing_stable() {
        run_target("varint_parsing");
    }

    /// The declared inventory must stay sorted and hold exactly six targets.
    #[test]
    fn target_inventory_matches() {
        let actual: Vec<&str> = TARGETS.iter().copied().collect();
        let mut sorted = actual.clone();
        sorted.sort();
        assert_eq!(actual, sorted, "TARGETS must stay sorted");
        assert_eq!(actual.len(), 6);
    }
}
