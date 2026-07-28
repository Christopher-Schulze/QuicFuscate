use super::FeatureDetector;

// ========================================================================
// CORE OPS - Generic SIMD operations used across modules
// ========================================================================
/// Core SIMD operations: XOR blocks, population count, CRC32, repeating-key XOR.
pub mod core;

// ========================================================================
// GALOIS FIELD OPS - For FEC (Reed-Solomon, etc.)
// ========================================================================
/// Galois field GF(2^8) multiplication with SIMD dispatch for FEC codecs.
pub mod galois;

// ========================================================================
// CRYPTO OPS - For AEGIS, AES, ChaCha, etc.
// ========================================================================
/// Cryptographic SIMD operations: AES rounds, ChaCha20 keystream generation (x4/x16).
pub mod crypto;

// ========================================================================
// PATTERN OPS - For stealth pattern matching
// ========================================================================
/// SIMD-accelerated byte pattern search for stealth protocol detection.
pub mod pattern;

// ========================================================================
// NEURAL OPS - For brain AI operations
// ========================================================================
/// SIMD-accelerated dot product for the stealth brain neural network.
pub mod neural;

// ========================================================================
// COMPRESSION OPS - For zstd, entropy coding
// ========================================================================
/// SIMD-accelerated histogram and pattern search for compression heuristics.
pub mod compress;

#[cfg(test)]
mod tests;
