//! x86 SIMD helpers for QUIC header validation

/// AVX-512 fast-path header validation
/// Checks QUIC fixed bit and basic length guards.
#[target_feature(enable = "avx512f")]
pub(super) unsafe fn validate_header_avx512(header: &[u8]) -> bool {
    if header.is_empty() {
        return false;
    }
    // For now, the fixed-bit check dominates; widening here keeps the door
    // open for extended validations (e.g., DCID/SCID bounds) without branches.
    // SAFETY: The `header.is_empty()` guard above ensures `header.len() >= 1`,
    // so index 0 is within bounds. `get_unchecked` avoids redundant bounds check.
    let first = *header.get_unchecked(0);
    (first & 0x40) != 0
}
