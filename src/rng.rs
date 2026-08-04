use std::io;

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static TEST_FORCE_SECURE_ENTROPY_FAILURE: Cell<bool> = const { Cell::new(false) };
}

/// Fill a buffer with cryptographically secure random bytes from the OS.
///
/// Returns an error when the entropy source is unavailable.
#[inline(always)]
pub fn fill_secure(buf: &mut [u8]) -> io::Result<()> {
    #[cfg(test)]
    if TEST_FORCE_SECURE_ENTROPY_FAILURE.with(Cell::get) {
        return Err(io::Error::other("forced secure entropy failure"));
    }

    getrandom::getrandom(buf).map_err(|e| io::Error::other(e.to_string()))
}

/// Fill a buffer with cryptographically secure random bytes.
///
/// On entropy source failure this fails closed by aborting the process.
#[inline(always)]
pub fn fill_secure_or_abort(buf: &mut [u8], context: &str) {
    if let Err(err) = fill_secure(buf) {
        log::error!("secure entropy source unavailable for {}: {}", context, err);
        std::process::abort();
    }
}

/// Append a single byte as two lowercase hex characters to `out`.
#[inline(always)]
pub fn push_hex_byte(out: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
}

/// Produce lowercase hex from secure random bytes.
#[inline(always)]
pub fn secure_hex(bytes_len: usize, context: &str) -> String {
    let mut bytes = vec![0u8; bytes_len];
    fill_secure_or_abort(&mut bytes, context);
    let mut out = String::with_capacity(bytes_len * 2);
    for b in bytes {
        push_hex_byte(&mut out, b);
    }
    out
}

#[cfg(test)]
pub fn test_force_secure_entropy_failure(enabled: bool) -> bool {
    TEST_FORCE_SECURE_ENTROPY_FAILURE.with(|state| state.replace(enabled))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_secure_reports_forced_failure() {
        let prev = test_force_secure_entropy_failure(true);
        let mut buf = [0u8; 8];
        let res = fill_secure(&mut buf);
        test_force_secure_entropy_failure(prev);
        assert!(res.is_err(), "forced secure entropy failure must return error");
    }

    #[test]
    fn secure_hex_returns_expected_length() {
        let prev = test_force_secure_entropy_failure(false);
        let hex = secure_hex(16, "rng::tests::secure_hex_returns_expected_length");
        test_force_secure_entropy_failure(prev);
        assert_eq!(hex.len(), 32);
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }
}
