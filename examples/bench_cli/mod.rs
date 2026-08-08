//! Shared argument contract for the benchmark and probe examples.
//!
//! These examples are operational tools whose output is treated as evidence, so the
//! two failure modes that matter are a panic on a typo and a green exit with no
//! measurement. Both used to be reachable: numeric parsing went through `unwrap`, unit
//! multiplication and workload products were unchecked, unknown options were ignored,
//! and a zero-iteration run still printed a record.
//!
//! Every helper here returns a typed message instead of panicking, bounds the request
//! before anything is allocated or multiplied, and treats zero work as an error.

#![allow(dead_code)]

/// Largest single buffer a benchmark may request, in bytes.
///
/// One GiB is far above any real measurement here and far below what would push a
/// machine into swap, which is what an unbounded `usize` from the command line could
/// do before this bound existed.
pub const MAX_BENCH_BYTES: usize = 1 << 30;

/// Largest iteration count a benchmark may request.
pub const MAX_BENCH_ITERS: u64 = 1_000_000_000;

/// Largest total workload, as bytes multiplied by iterations.
///
/// The individual bounds are not enough on their own: a legal buffer times a legal
/// iteration count can still overflow the product that every throughput figure is
/// computed from, which turns a measurement into a wrapped number.
pub const MAX_BENCH_WORKLOAD_BYTES: u128 = 1u128 << 42;

/// Parse a byte size with an optional `B`, `KiB`, or `MiB` suffix.
pub fn parse_size(label: &str, raw: &str) -> Result<usize, String> {
    let (digits, multiplier) = if let Some(stripped) = raw.strip_suffix("MiB") {
        (stripped, 1024 * 1024usize)
    } else if let Some(stripped) = raw.strip_suffix("KiB") {
        (stripped, 1024usize)
    } else if let Some(stripped) = raw.strip_suffix('B') {
        (stripped, 1usize)
    } else {
        (raw, 1usize)
    };
    let value: usize = digits
        .trim()
        .parse()
        .map_err(|error| format!("{label}: {raw:?} is not a byte size: {error}"))?;
    let bytes = value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("{label}: {raw:?} overflows a byte size"))?;
    if bytes == 0 {
        return Err(format!("{label} must be greater than zero"));
    }
    if bytes > MAX_BENCH_BYTES {
        return Err(format!("{label}: {bytes} exceeds the {MAX_BENCH_BYTES}-byte budget"));
    }
    Ok(bytes)
}

/// Parse an iteration count. Zero is rejected: a run with no iterations produces a
/// record that looks like a measurement and contains none.
pub fn parse_iters(label: &str, raw: &str) -> Result<u64, String> {
    let value: u64 =
        raw.trim().parse().map_err(|error| format!("{label}: {raw:?} is not a count: {error}"))?;
    if value == 0 {
        return Err(format!("{label} must be greater than zero; a zero-work run measures nothing"));
    }
    if value > MAX_BENCH_ITERS {
        return Err(format!("{label}: {value} exceeds the {MAX_BENCH_ITERS} iteration budget"));
    }
    Ok(value)
}

/// Parse a bounded integer in an inclusive range.
pub fn parse_in_range(label: &str, raw: &str, min: u64, max: u64) -> Result<u64, String> {
    let value: u64 = raw
        .trim()
        .parse()
        .map_err(|error| format!("{label}: {raw:?} is not an integer: {error}"))?;
    if value < min || value > max {
        return Err(format!("{label}: {value} is outside {min}..={max}"));
    }
    Ok(value)
}

/// Parse a ratio that must be finite and within `[0, 1]`.
pub fn parse_ratio(label: &str, raw: &str) -> Result<f64, String> {
    let value: f64 =
        raw.trim().parse().map_err(|error| format!("{label}: {raw:?} is not a number: {error}"))?;
    if !value.is_finite() {
        return Err(format!("{label}: {value} is not finite"));
    }
    if !(0.0..=1.0).contains(&value) {
        return Err(format!("{label}: {value} is outside 0.0..=1.0"));
    }
    Ok(value)
}

/// Reject a workload whose byte-times-iteration product cannot be reported honestly.
pub fn checked_workload(label: &str, bytes: usize, iters: u64) -> Result<u128, String> {
    let total = (bytes as u128)
        .checked_mul(iters as u128)
        .ok_or_else(|| format!("{label}: {bytes} bytes x {iters} iterations overflows"))?;
    if total > MAX_BENCH_WORKLOAD_BYTES {
        return Err(format!(
            "{label}: {total} total bytes exceeds the {MAX_BENCH_WORKLOAD_BYTES}-byte budget"
        ));
    }
    Ok(total)
}

/// Report a usage error on stderr and exit nonzero.
///
/// Examples call this instead of returning from `main` with a printed message, which
/// is how invalid input used to produce exit code zero.
pub fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("error: {message}");
    std::process::exit(2)
}
