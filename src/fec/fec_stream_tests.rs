use super::test_support::*;
use super::*;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

#[test]
fn stream_raw_roundtrip_systematic() {
    let pool = crate::optimize::global_pool();
    // Build a systematic packet
    let mut data = pool.alloc();
    let n = 123;
    for (i, b) in data.iter_mut().take(n).enumerate() {
        *b = (i as u8).wrapping_mul(3).wrapping_add(7);
    }
    let pkt = FecPacket::new(42, Some(data), n, true, None, 0, Arc::clone(&pool));
    // Serialize
    let mut buf = vec![0u8; 2 + 1 + 8 + 8 + 2 + n];
    let used = pkt.to_stream_raw(&mut buf[..]).expect("serialize");
    buf.truncate(used);
    // Parse
    let p2 = FecPacket::from_stream_raw(&buf[..], Arc::clone(&pool)).expect("parse");
    assert!(p2.is_systematic);
    assert_eq!(p2.id, 42);
    assert_eq!(p2.coeff_len, 0);
    assert!(p2.coefficients.is_none());
    assert_eq!(p2.data_len, n);
    let d2 = p2.payload_slice().expect("payload");
    for (i, &b) in d2.iter().take(n).enumerate() {
        assert_eq!(b, (i as u8).wrapping_mul(3).wrapping_add(7));
    }
}

#[test]
fn stream_raw_roundtrip_repair() {
    let pool = crate::optimize::global_pool();
    // Build a repair packet with coefficients
    let mut data = pool.alloc();
    let n = 200;
    for (i, b) in data.iter_mut().take(n).enumerate() {
        *b = (i as u8).wrapping_mul(17);
    }
    let mut coeffs = pool.alloc();
    let k = 10usize;
    for (j, b) in coeffs.iter_mut().take(k).enumerate() {
        *b = (j as u8).wrapping_add(1);
    }
    let pkt = FecPacket::new(1000, Some(data), n, false, Some(coeffs), k, Arc::clone(&pool));
    // Serialize
    let mut buf = vec![0u8; 2 + 1 + 8 + 8 + 2 + k + n];
    let used = pkt.to_stream_raw(&mut buf[..]).expect("serialize");
    buf.truncate(used);
    // Parse
    let p2 = FecPacket::from_stream_raw(&buf[..], Arc::clone(&pool)).expect("parse");
    assert!(!p2.is_systematic);
    assert_eq!(p2.id, 1000);
    assert_eq!(p2.coeff_len, k);
    assert!(p2.coefficients.is_some());
    let c2 = p2.coefficients.as_ref().unwrap();
    for (j, &b) in c2.iter().take(k).enumerate() {
        assert_eq!(b, (j as u8).wrapping_add(1));
    }
    assert_eq!(p2.data_len, n);
    let d2 = p2.payload_slice().expect("payload");
    for (i, &b) in d2.iter().take(n).enumerate() {
        assert_eq!(b, (i as u8).wrapping_mul(17));
    }
}

#[test]
fn to_raw_is_payload_only() {
    let pool = crate::optimize::global_pool();
    let mut data = pool.alloc();
    let n = 64;
    for (i, b) in data.iter_mut().take(n).enumerate() {
        *b = i as u8;
    }
    let pkt = FecPacket::new(7, Some(data), n, true, None, 0, Arc::clone(&pool));
    let mut out = vec![0u8; n];
    let used = pkt.to_raw(&mut out[..]).expect("to_raw");
    assert_eq!(used, n);
    for (i, &b) in out.iter().take(n).enumerate() {
        assert_eq!(b, i as u8);
    }
}

#[test]
fn test_zero_cpu_fast_path() {
    let pool = crate::optimize::global_pool();
    let config = FecConfig { initial_mode: FecMode::Zero, ..Default::default() };
    let mut fec = AdaptiveFec::new(config);

    // Simulate zero loss to keep in Zero mode
    fec.report_loss(0, 1000);
    assert_eq!(fec.current_mode(), FecMode::Zero);

    let mut data = pool.alloc();
    let n = 100;
    for (i, b) in data.iter_mut().take(n).enumerate() {
        *b = (i as u8).wrapping_mul(7);
    }
    let pkt = FecPacket::new(42, Some(data), n, true, None, 0, Arc::clone(&pool));

    let output = fec.on_send(pkt);
    assert_eq!(output.len(), 1, "Zero mode should output exactly 1 packet (the original)");
    assert!(output[0].is_systematic, "Output should be the original systematic packet");
    assert_eq!(output[0].id, 42);
    assert_eq!(output[0].data_len, n);

    // Verify data integrity
    let out_data = output[0].payload_slice().expect("output payload");
    for (i, &b) in out_data.iter().take(n).enumerate() {
        assert_eq!(b, (i as u8).wrapping_mul(7));
    }
}

#[test]
fn test_normal_block_encoder_emits_repairs() {
    let pool = make_pool();

    let mut windows = HashMap::new();
    windows.insert(FecMode::Normal, 8);

    let cfg =
        FecConfig { initial_mode: FecMode::Normal, window_sizes: windows, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);

    // Verify the production GF8 block encoder emits repair symbols.
    let mut q = VecDeque::new();
    for i in 0..8u64 {
        let pkt = mk_src_packet(100 + i, 100, &pool);
        for pkt in fec.on_send(pkt) {
            q.push_back(pkt);
        }
    }

    let repairs = drain_repairs(&mut q);
    assert!(!repairs.is_empty(), "Normal block mode should generate repairs");
    for rp in repairs {
        assert!(!rp.is_systematic);
        assert!(rp.coefficients.is_some());
    }
}

#[test]
fn test_medium_block_encoder_emits_repairs() {
    let pool = make_pool();

    let mut windows = HashMap::new();
    windows.insert(FecMode::Medium, 8);

    let cfg =
        FecConfig { initial_mode: FecMode::Medium, window_sizes: windows, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);

    // Send multiple complete source blocks.
    let mut q = VecDeque::new();
    for batch in 0..2 {
        for i in 0..32u64 {
            let pkt = mk_src_packet(batch * 32 + i, 100, &pool);
            for pkt in fec.on_send(pkt) {
                q.push_back(pkt);
            }
        }
    }

    let repairs = drain_repairs(&mut q);
    assert!(!repairs.is_empty(), "Medium block mode should generate repairs");
}

#[test]
fn test_strong_block_repair_structure() {
    let pool = make_pool();

    let mut windows = HashMap::new();
    windows.insert(FecMode::Strong, 16);

    let cfg =
        FecConfig { initial_mode: FecMode::Strong, window_sizes: windows, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);

    // Send multiple complete source blocks.
    let mut q = VecDeque::new();
    for i in 0..64u64 {
        let pkt = mk_src_packet(200 + i, 100, &pool);
        for pkt in fec.on_send(pkt) {
            q.push_back(pkt);
        }
    }

    let repairs = drain_repairs(&mut q);
    assert!(!repairs.is_empty(), "Strong block mode should generate repairs");

    // Verify repairs have proper structure
    for rp in repairs {
        assert!(!rp.is_systematic);
        assert!(rp.coefficients.is_some());
        assert!(rp.coeff_len > 0);
    }
}

#[test]
fn test_normal_block_decoder_compatibility() {
    let pool = make_pool();

    let mut windows = HashMap::new();
    windows.insert(FecMode::Normal, 8);

    let cfg =
        FecConfig { initial_mode: FecMode::Normal, window_sizes: windows, ..Default::default() };

    let mut sender = AdaptiveFec::new(cfg.clone());
    let mut receiver = AdaptiveFec::new(cfg);

    // Send systematic packets
    let mut tx_q = VecDeque::new();
    let mut source_ids = Vec::new();
    for i in 0..8u64 {
        let id = 300 + i;
        source_ids.push(id);
        let pkt = mk_src_packet(id, 100, &pool);
        for pkt in sender.on_send(pkt) {
            tx_q.push_back(pkt);
        }
    }

    // Separate systematic and repair packets
    let mut systematics = VecDeque::new();
    let mut repairs = VecDeque::new();
    while let Some(pkt) = tx_q.pop_front() {
        if pkt.is_systematic {
            systematics.push_back(pkt);
        } else {
            repairs.push_back(pkt);
        }
    }

    // Send most systematics to receiver (simulate one loss)
    let missing_id = source_ids[3]; // Drop packet 303
    for pkt in systematics {
        if pkt.id != missing_id {
            let _ = receiver.on_receive(pkt).expect("receive systematic");
        }
    }

    // Send repair packets to recover missing
    let mut recovered = Vec::new();
    for repair in repairs {
        if let Ok(result) = receiver.on_receive(repair) {
            recovered.extend(result);
        }
    }

    // Verify recovery of missing packet
    let has_missing = recovered.iter().any(|p| p.id == missing_id);
    assert!(has_missing, "GF8 decoder should recover missing packet {}", missing_id);
}
