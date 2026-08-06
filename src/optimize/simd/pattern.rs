//! optimize::simd::pattern (TODO-563).

/// String search with the authoritative scalar matcher.
///
/// The former x86 entry points were scalar bodies behind target-feature cfg
/// gates. Keeping them exposed as SIMD dispatch made telemetry and compile
/// contracts claim acceleration that did not exist.
#[inline(always)]
pub fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    find_pattern_scalar(haystack, needle)
}

/// Scalar pattern search fallback
fn find_pattern_scalar(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}
