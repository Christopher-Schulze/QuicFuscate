use quicfuscate::fec::{Decoder16, Encoder16};
use quicfuscate::optimize::MemoryPool;
use std::sync::Arc;

fn make_packet(id: u64, val: u8, pool: &Arc<MemoryPool>) -> quicfuscate::fec::Packet {
    let mut buf = pool.alloc();
    for b in buf.iter_mut().take(8) {
        *b = val;
    }
    quicfuscate::fec::Packet {
        id,
        data: Some(buf),
        len: 8,
        is_systematic: true,
        coefficients: None,
        mem_pool: Arc::clone(pool),
    }
}

#[test]
fn wiedemann_high_loss() {
    quicfuscate::fec::init_gf_tables();
    let pool = Arc::new(MemoryPool::new(600, 64));
    let k = 300;
    let n = k + 20;
    let mut enc = Encoder16::new(k, n);
    let mut pkts = Vec::new();
    for i in 0..k {
        let p = make_packet(i as u64, (i % 255) as u8, &pool);
        enc.add_source_packet(p.clone());
        pkts.push(p);
    }
    let mut repairs = Vec::new();
    for i in 0..(n - k) {
        repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
    }
    let mut dec = Decoder16::new(k, Arc::clone(&pool));
    for (i, p) in pkts.into_iter().enumerate() {
        if i % 5 == 0 {
            dec.add_packet(p).unwrap();
        }
    }
    for (i, r) in repairs.into_iter().enumerate() {
        if i % 2 == 0 {
            dec.add_packet(r).unwrap();
        }
    }
    assert!(dec.is_decoded);
    let out = dec.get_decoded_packets();
    assert_eq!(out.len(), k);
    for i in 0..k {
        assert_eq!(out[i].data.as_ref().unwrap()[0], (i % 255) as u8);
    }
}

