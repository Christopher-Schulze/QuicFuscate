//! Drives the FEC input boundaries that accept caller-controlled data.
//!
//! Proof boundary: this target drives the public GF(2^8) block path, the public wire parser, and
//! the public matrix helper with arbitrary bytes. Every one of them must either succeed or return
//! a typed error. A panic, an abort, or an out-of-bounds access is a finding. The target does not
//! prove recovery correctness, does not reach the private Fountain codec, and does not exercise
//! pool exhaustion or mode transitions, which stay with their own owners.

use std::sync::Arc;

use quicfuscate::fec::{matrix_multiply_scalar, wire, Encoder8, FecDecoder8, FecPacket};
use quicfuscate::optimize::MemoryPool;

/// Split `data` into three roughly equal slices so each surface sees independent bytes.
fn split_thirds(data: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let third = data.len() / 3;
    let (first, rest) = data.split_at(third);
    let (second, third_slice) = rest.split_at(third);
    (first, second, third_slice)
}

/// Drive the systematic GF(2^8) block path. Malformed metadata must be rejected by `try_new`
/// rather than panicking, so no result is unwrapped here.
fn fuzz_block_path(data: &[u8], pool: &Arc<MemoryPool>) {
    if data.is_empty() {
        return;
    }

    let mut encoder = Encoder8::new(4, 6);
    let mut offset = 0usize;
    for id in 0..4u64 {
        let len = ((data[offset % data.len()] as usize) % 64).max(1);
        let slice = if offset + len <= data.len() {
            &data[offset..offset + len]
        } else {
            &data[..len.min(data.len())]
        };
        offset = offset.saturating_add(len);

        // Declare a length taken from the fuzz input rather than the true slice length, so
        // overstated and understated metadata both reach the constructor's validation.
        let declared_len = data[offset % data.len()] as usize;
        let packet = FecPacket::try_new(
            id,
            Some(pool.alloc_from_slice(slice)),
            declared_len,
            true,
            None,
            0,
            Arc::clone(pool),
        );
        match packet {
            Ok(packet) => encoder.take_packet(packet),
            Err(_) => continue,
        }
    }

    let repair = encoder.generate_repair_packet(0, pool);
    let mut decoder = FecDecoder8::new(4, Arc::clone(pool));
    if let Some(packet) = repair {
        decoder.take_packet(packet);
    }
    let _ = decoder.poll_recovered();
}

/// The wire parser is the only FEC surface that sees raw peer bytes. Arbitrary datagrams,
/// including truncated headers and impossible profiles, must return `WireError`.
fn fuzz_wire_parser(data: &[u8]) {
    let _ = wire::parse_packet(data);

    // Also probe prefixes so truncation at every header offset is covered, not just the full
    // length the fuzzer happened to produce.
    for take in [1usize, 2, 4, 8, 16] {
        if take <= data.len() {
            let _ = wire::parse_packet(&data[..take]);
        }
    }
}

/// The public matrix helper accepts caller-built shapes. Ragged rows, mismatched inner
/// dimensions, and empty inputs must produce `MatrixError` instead of indexing out of bounds.
fn fuzz_matrix_helper(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    // Derive small, deliberately inconsistent shapes from the input.
    let rows = (data[0] % 5) as usize;
    let inner = (data[1] % 5) as usize;
    let cols = (data[2] % 5) as usize;
    let ragged = data[3].is_multiple_of(2);

    let mut a: Vec<Vec<u8>> = (0..rows)
        .map(|row| {
            let width = if ragged && row % 2 == 1 { inner.saturating_add(1) } else { inner };
            (0..width).map(|col| data[(row + col) % data.len()]).collect()
        })
        .collect();
    let b: Vec<Vec<u8>> = (0..inner)
        .map(|row| (0..cols).map(|col| data[(row * 3 + col) % data.len()]).collect())
        .collect();
    let mut result: Vec<Vec<u8>> = (0..rows).map(|_| vec![0u8; cols]).collect();

    let _ = matrix_multiply_scalar(&a, &b, &mut result);

    // Mismatched result geometry must be rejected too.
    let mut short_result: Vec<Vec<u8>> =
        (0..rows.saturating_sub(1)).map(|_| vec![0u8; cols]).collect();
    let _ = matrix_multiply_scalar(&a, &b, &mut short_result);

    // An empty first row is the documented `EmptyInput` boundary.
    if let Some(first) = a.first_mut() {
        first.clear();
        let _ = matrix_multiply_scalar(&a, &b, &mut result);
    }
}

pub fn exercise(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let pool = Arc::new(MemoryPool::new(16, 512));
    let (block_bytes, wire_bytes, matrix_bytes) = split_thirds(data);

    fuzz_block_path(block_bytes, &pool);
    fuzz_wire_parser(wire_bytes);
    fuzz_matrix_helper(matrix_bytes);
}
