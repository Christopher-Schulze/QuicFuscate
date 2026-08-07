#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;

use quicfuscate::fec::{Encoder8, FecDecoder8, FecPacket};
use quicfuscate::optimize::MemoryPool;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let pool = Arc::new(MemoryPool::new(16, 512));
    let mut enc = Encoder8::new(4, 6);
    let mut offset = 0usize;
    for id in 0..4u64 {
        let len = ((data[offset % data.len()] as usize) % 64).max(1);
        let slice = if offset + len <= data.len() {
            &data[offset..offset + len]
        } else {
            &data[..len.min(data.len())]
        };
        offset = offset.saturating_add(len);
        let pkt = FecPacket::try_new(
            id,
            Some(pool.alloc_from_slice(slice)),
            slice.len(),
            true,
            None,
            0,
            Arc::clone(&pool),
        )
        .unwrap();
        enc.take_packet(pkt);
    }
    let repair = enc.generate_repair_packet(0, &pool);
    let mut dec = FecDecoder8::new(4, Arc::clone(&pool));
    if let Some(pkt) = repair {
        dec.take_packet(pkt);
    }
    let _ = dec.poll_recovered();
});
