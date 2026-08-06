//! x86 SIMD helpers for QUIC header validation

/// AVX-512 fast-path header validation
/// Checks the QUIC fixed bit and short-header reserved bits.
#[target_feature(enable = "avx512f")]
/// # Safety
///
/// The caller must provide AVX-512F support and a valid immutable `header`
/// slice for the duration of the call. The implementation checks non-emptiness
/// before its unchecked first-byte access.
pub(super) unsafe fn validate_header_avx512(header: &[u8]) -> bool {
    if header.is_empty() {
        return false;
    }
    // SAFETY: The `header.is_empty()` guard above ensures `header.len() >= 1`,
    // so index 0 is within bounds. `get_unchecked` avoids redundant bounds check.
    let first = *header.get_unchecked(0);
    (first & 0x40) != 0 && ((first & 0x80) != 0 || (first & 0x18) == 0)
}
