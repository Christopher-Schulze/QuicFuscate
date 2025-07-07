use quicfuscate::fec::{AdaptiveFec, Decoder, Decoder16, Encoder, Encoder16, FecConfig, FecMode};
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
fn gf8_encode_decode() {
    quicfuscate::fec::init_gf_tables();
    let pool = Arc::new(MemoryPool::new(32, 64));
    let k = 4;
    let n = 6;
    let mut enc = Encoder::new(k, n);
    let mut packets = Vec::new();
    for i in 0..k {
        let p = make_packet(i as u64, i as u8, &pool);
        enc.add_source_packet(p.clone());
        packets.push(p);
    }
    let mut repairs = Vec::new();
    for i in 0..(n - k) {
        repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
    }
    let mut dec = Decoder::new(k, Arc::clone(&pool));
    dec.add_packet(packets[0].clone()).unwrap();
    dec.add_packet(packets[2].clone()).unwrap();
    dec.add_packet(packets[3].clone()).unwrap();
    for r in repairs {
        dec.add_packet(r).unwrap();
    }
    assert!(dec.is_decoded);
    let out = dec.get_decoded_packets();
    assert_eq!(out.len(), k);
    for i in 0..k {
        assert_eq!(out[i].data.as_ref().unwrap()[0], i as u8);
    }
}

#[test]
fn gf16_encode_decode() {
    quicfuscate::fec::init_gf_tables();
    let pool = Arc::new(MemoryPool::new(128, 64));
    let k = 8;
    let n = k + 4;
    let mut enc = Encoder16::new(k, n);
    let mut packets = Vec::new();
    for i in 0..k {
        let p = make_packet(i as u64, (i % 255) as u8, &pool);
        enc.add_source_packet(p.clone());
        packets.push(p);
    }
    let mut repairs = Vec::new();
    for i in 0..(n - k) {
        repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
    }
    let mut dec = Decoder16::new(k, Arc::clone(&pool));
    for pkt in packets.into_iter().skip(1) {
        dec.add_packet(pkt).unwrap();
    }
    for r in repairs {
        dec.add_packet(r).unwrap();
    }
    assert!(dec.is_decoded);
    let out = dec.get_decoded_packets();
    assert_eq!(out.len(), k);
    for i in 0..k {
        assert_eq!(out[i].data.as_ref().unwrap()[0], (i % 255) as u8);
    }
}

#[test]
fn adaptive_mode_switch_high_loss() {
    quicfuscate::fec::init_gf_tables();
    let pool = Arc::new(MemoryPool::new(32, 64));
    let cfg = FecConfig::default();
    let mut fec = AdaptiveFec::new(cfg, Arc::clone(&pool));
    fec.report_loss(40, 50);
    assert_eq!(fec.current_mode(), FecMode::Extreme);
}

#[test]
fn gf8_large_window() {
    quicfuscate::fec::init_gf_tables();
    let pool = Arc::new(MemoryPool::new(4096, 64));
    let k = 1024;
    let n = k + 8;
    let mut enc = Encoder::new(k, n);
    let mut packets = Vec::new();
    for i in 0..k {
        let p = make_packet(i as u64, (i % 256) as u8, &pool);
        enc.add_source_packet(p.clone());
        packets.push(p);
    }
    let mut repairs = Vec::new();
    for i in 0..(n - k) {
        repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
    }
    let mut dec = Decoder::new(k, Arc::clone(&pool));
    for (idx, pkt) in packets.into_iter().enumerate() {
        if idx % 3 != 0 {
            dec.add_packet(pkt).unwrap();
        }
    }
    for r in repairs {
        dec.add_packet(r).unwrap();
    }
    assert!(dec.is_decoded);
    let out = dec.get_decoded_packets();
    assert_eq!(out.len(), k);
    for i in 0..k {
        assert_eq!(out[i].data.as_ref().unwrap()[0], (i % 256) as u8);
    }
}

#[test]
fn gf16_large_window() {
    quicfuscate::fec::init_gf_tables();
    let pool = Arc::new(MemoryPool::new(8192, 64));
    let k = 512;
    let n = k + 8;
    let mut enc = Encoder16::new(k, n);
    let mut packets = Vec::new();
    for i in 0..k {
        let p = make_packet(i as u64, (i % 255) as u8, &pool);
        enc.add_source_packet(p.clone());
        packets.push(p);
    }
    let mut repairs = Vec::new();
    for i in 0..(n - k) {
        repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
    }
    let mut dec = Decoder16::new(k, Arc::clone(&pool));
    for (idx, pkt) in packets.into_iter().enumerate() {
        if idx % 3 != 0 {
            dec.add_packet(pkt).unwrap();
        }
    }
    for r in repairs {
        dec.add_packet(r).unwrap();
    }
    assert!(dec.is_decoded);
    let out = dec.get_decoded_packets();
    assert_eq!(out.len(), k);
    for i in 0..k {
        assert_eq!(out[i].data.as_ref().unwrap()[0], (i % 255) as u8);
    }
}

#[test]
fn gf8_window_512() {
    quicfuscate::fec::init_gf_tables();
    let pool = Arc::new(MemoryPool::new(2048, 64));
    let k = 512;
    let n = k + 4;
    let mut enc = Encoder::new(k, n);
    let mut packets = Vec::new();
    for i in 0..k {
        let p = make_packet(i as u64, (i % 256) as u8, &pool);
        enc.add_source_packet(p.clone());
        packets.push(p);
    }
    let mut repairs = Vec::new();
    for i in 0..(n - k) {
        repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
    }
    let mut dec = Decoder::new(k, Arc::clone(&pool));
    for (idx, pkt) in packets.into_iter().enumerate() {
        if idx % 2 == 0 {
            dec.add_packet(pkt).unwrap();
        }
    }
    for r in repairs {
        dec.add_packet(r).unwrap();
    }
    assert!(dec.is_decoded);
    let out = dec.get_decoded_packets();
    assert_eq!(out.len(), k);
    for i in 0..k {
        assert_eq!(out[i].data.as_ref().unwrap()[0], (i % 256) as u8);
    }
}

#[test]
fn gf16_window_1024() {
    quicfuscate::fec::init_gf_tables();
    let pool = Arc::new(MemoryPool::new(16384, 64));
    let k = 1024;
    let n = k + 8;
    let mut enc = Encoder16::new(k, n);
    let mut packets = Vec::new();
    for i in 0..k {
        let p = make_packet(i as u64, (i % 255) as u8, &pool);
        enc.add_source_packet(p.clone());
        packets.push(p);
    }
    let mut repairs = Vec::new();
    for i in 0..(n - k) {
        repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
    }
    let mut dec = Decoder16::new(k, Arc::clone(&pool));
    for (idx, pkt) in packets.into_iter().enumerate() {
        if idx % 2 == 0 {
            dec.add_packet(pkt).unwrap();
        }
    }
    for r in repairs {
        dec.add_packet(r).unwrap();
    }
    assert!(dec.is_decoded);
    let out = dec.get_decoded_packets();
    assert_eq!(out.len(), k);
    for i in 0..k {
        assert_eq!(out[i].data.as_ref().unwrap()[0], (i % 255) as u8);
    }
}

#[test]
fn adaptive_transitions_all_modes() {
    use std::thread::sleep;
    use std::time::Duration;

    quicfuscate::fec::init_gf_tables();
    let pool = Arc::new(MemoryPool::new(32, 64));
    let mut cfg = FecConfig::default();
    cfg.lambda = 1.0;
    cfg.pid = quicfuscate::fec::PidConfig {
        kp: 1.0,
        ki: 0.0,
        kd: 0.0,
    };
    let mut fec = AdaptiveFec::new(cfg, Arc::clone(&pool));

    let steps = [
        (0, 100, FecMode::Zero),     // 0 %
        (2, 100, FecMode::Light),    // 2 %
        (10, 100, FecMode::Normal),  // 10 %
        (25, 100, FecMode::Medium),  // 25 %
        (45, 100, FecMode::Strong),  // 45 %
        (60, 100, FecMode::Extreme), // 60 %
    ];

    for (lost, total, mode) in steps.iter() {
        fec.report_loss(*lost, *total);
        sleep(Duration::from_millis(600));
        assert_eq!(fec.current_mode(), *mode);
    }
}

#[test]
fn bitsliced_mul_matches_table() {
    quicfuscate::fec::init_gf_tables();
    for a in 0u8..=255 {
        for b in 0u8..=255 {
            let table = quicfuscate::fec::gf_tables::gf_mul_table(a, b);
            let bs = quicfuscate::fec::gf_tables::gf_mul(a, b);
            assert_eq!(table, bs, "a={} b={} mismatch", a, b);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn avx2_kernel_matches_table() {
    if !std::is_x86_feature_detected!("avx2") || !std::is_x86_feature_detected!("pclmulqdq") {
        return;
    }
    quicfuscate::fec::init_gf_tables();
    for a in 0u8..=255 {
        for b in 0u8..=255 {
            let table = quicfuscate::fec::gf_tables::gf_mul_table(a, b);
            let bs = unsafe { quicfuscate::fec::gf_tables::gf_mul_bitsliced_avx2(a, b) };
            assert_eq!(table, bs, "a={} b={} mismatch", a, b);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn avx512_kernel_matches_table() {
    if !(std::is_x86_feature_detected!("avx512f")
        && std::is_x86_feature_detected!("avx512vbmi")
        && std::is_x86_feature_detected!("pclmulqdq"))
    {
        return;
    }
    quicfuscate::fec::init_gf_tables();
    for a in 0u8..=255 {
        for b in 0u8..=255 {
            let table = quicfuscate::fec::gf_tables::gf_mul_table(a, b);
            let bs = unsafe { quicfuscate::fec::gf_tables::gf_mul_bitsliced_avx512(a, b) };
            assert_eq!(table, bs, "a={} b={} mismatch", a, b);
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn neon_kernel_matches_table() {
    if !std::arch::is_aarch64_feature_detected!("pmull") {
        return;
    }
    quicfuscate::fec::init_gf_tables();
    for a in 0u8..=255 {
        for b in 0u8..=255 {
            let table = quicfuscate::fec::gf_tables::gf_mul_table(a, b);
            let bs = unsafe { quicfuscate::fec::gf_tables::gf_mul_bitsliced_neon(a, b) };
            assert_eq!(table, bs, "a={} b={} mismatch", a, b);
        }
    }
}
