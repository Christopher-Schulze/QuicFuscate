use super::test_support::*;
use super::*;
use aligned_box::AlignedBox;
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

#[test]
fn stream_parser_returns_coefficient_guard_when_payload_is_oversized() {
    let pool = Arc::new(crate::optimize::MemoryPool::new(2, 2_048));
    let before = pool.accounting_snapshot();
    let coefficient_len = 8usize;
    let payload_len = pool.block_size() + 1;
    let header_len = 2 + 1 + 8 + 8 + 2;
    let mut input = vec![0u8; header_len + coefficient_len + payload_len];
    input[..2].copy_from_slice(&[0xF1, 0xEC]);
    input[19..21].copy_from_slice(&(coefficient_len as u16).to_be_bytes());

    let error = match FecPacket::from_stream_raw(&input, Arc::clone(&pool)) {
        Ok(_) => panic!("oversized payload must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error, "DataBufferTooSmall");
    assert_eq!(pool.accounting_snapshot(), before);
}

#[test]
fn stream_parser_rejects_unknown_flags_and_inconsistent_metadata() {
    let pool = Arc::new(crate::optimize::MemoryPool::new(2, 2_048));
    let mut input = vec![0u8; 2 + 1 + 8 + 8 + 2 + 1];
    input[..2].copy_from_slice(&[0xF1, 0xEC]);
    input[2] = 2;
    assert!(matches!(
        FecPacket::from_stream_raw(&input, Arc::clone(&pool)),
        Err(error) if error == "UnsupportedFlags"
    ));

    input[2] = 1;
    input[19..21].copy_from_slice(&1u16.to_be_bytes());
    assert!(matches!(
        FecPacket::from_stream_raw(&input, Arc::clone(&pool)),
        Err(error) if error == "CoefficientMetadataInvalid"
    ));
}

#[test]
fn pooled_packet_rejects_overstated_lengths_without_consuming_buffers() {
    let pool = Arc::new(crate::optimize::MemoryPool::new(2, 2_048));
    let before = pool.accounting_snapshot();
    let data = PooledBlock::new(Arc::clone(&pool));
    let coefficients = PooledBlock::new(Arc::clone(&pool));

    let error = match FecPacket::from_pooled_blocks(
        77,
        Some(data),
        pool.block_size() + 1,
        false,
        Some(coefficients),
        pool.block_size() + 1,
        Arc::clone(&pool),
    ) {
        Ok(_) => panic!("declared lengths must be rejected"),
        Err(error) => error,
    };
    assert!(error.contains("data block"));
    assert_eq!(pool.accounting_snapshot(), before);
}

#[test]
fn decoder_known_storage_returns_pool_blocks_on_teardown() {
    let pool = Arc::new(crate::optimize::MemoryPool::new(2, 2_048));
    let before = pool.accounting_snapshot();

    {
        let mut decoder = Decoder8::new(1, Arc::clone(&pool));
        decoder.take_packet(FecPacket::from_block(1, &[1, 2, 3, 4], Arc::clone(&pool)));
        assert_eq!(pool.accounting_snapshot().1, before.1 + 1);
    }
    assert_eq!(pool.accounting_snapshot(), before);

    {
        let mut decoder = Decoder4::new(1, Arc::clone(&pool));
        decoder.take_packet(FecPacket::from_block(2, &[1, 2, 3, 4], Arc::clone(&pool)));
        assert_eq!(pool.accounting_snapshot().1, before.1 + 1);
    }
    assert_eq!(pool.accounting_snapshot(), before);

    {
        let mut decoder = Decoder16::new(1, Arc::clone(&pool));
        decoder.take_packet(FecPacket::from_block(3, &[1, 2, 3, 4], Arc::clone(&pool)));
        assert_eq!(pool.accounting_snapshot().1, before.1 + 1);
    }
    assert_eq!(pool.accounting_snapshot(), before);
}

fn oversized_source_packet(id: u64, pool: &Arc<crate::optimize::MemoryPool>) -> FecPacket {
    let length = pool.block_size() + 64;
    let mut data = AlignedBox::<[u8]>::slice_from_default(64, length).expect("test buffer");
    data[0] = id as u8;
    FecPacket::new(id, Some(data), length, true, None, 0, Arc::clone(pool))
}

#[test]
fn block_generators_fail_closed_before_pool_transfer_for_oversized_symbols() {
    let pool = Arc::new(crate::optimize::MemoryPool::new(2, 2_048));
    let before = pool.accounting_snapshot();

    {
        let mut encoder = Encoder8::new(1, 2);
        encoder.take_packet(oversized_source_packet(10, &pool));
        assert!(encoder.generate_repair_packet(0, &pool).is_none());
    }
    {
        let mut encoder = Encoder4::new(1, 2);
        encoder.take_packet(oversized_source_packet(11, &pool));
        assert!(encoder.generate_repair_packet(0, &pool).is_none());
    }
    {
        let mut encoder = Encoder16::new(1, 2);
        encoder.take_packet(oversized_source_packet(12, &pool));
        assert!(encoder.generate_repair_packet(0, &pool).is_none());
    }

    let invalid_index = u16::MAX as usize + 1;
    {
        let mut encoder = Encoder8::new(1, 2);
        encoder.take_packet(FecPacket::from_block(13, &[1, 2, 3, 4], Arc::clone(&pool)));
        assert!(encoder.generate_repair_packet(invalid_index, &pool).is_none());
    }
    {
        let mut encoder = Encoder16::new(1, 2);
        encoder.take_packet(FecPacket::from_block(14, &[1, 2, 3, 4], Arc::clone(&pool)));
        assert!(encoder.generate_repair_packet(invalid_index, &pool).is_none());
    }

    assert_eq!(pool.accounting_snapshot(), before);
}

#[test]
fn oversized_coefficient_clone_preserves_a_valid_declared_length() {
    let pool = Arc::new(crate::optimize::MemoryPool::new(2, 2_048));
    let before = pool.accounting_snapshot();
    let data = pool.alloc();
    let coefficient_len = pool.block_size() * 2;
    let mut coefficients =
        AlignedBox::<[u8]>::slice_from_default(64, coefficient_len).expect("test coefficients");
    coefficients[0] = 0xA5;
    let packet = FecPacket::new(
        13,
        Some(data),
        1,
        false,
        Some(coefficients),
        coefficient_len,
        Arc::clone(&pool),
    );
    let clone = packet.clone();
    assert_eq!(clone.coeff_len, pool.block_size());
    assert_eq!(clone.coefficients.as_ref().map(|value| value.len()), Some(pool.block_size()));
    drop(clone);
    drop(packet);
    assert_eq!(pool.accounting_snapshot(), before);
}

#[test]
fn direct_decoders_reject_overlong_coefficient_vectors() {
    let pool = Arc::new(crate::optimize::MemoryPool::new(4, 2_048));
    let mut data = pool.alloc();
    data[0] = 0xA5;
    let mut coefficients = pool.alloc();
    coefficients[..2].copy_from_slice(&[1, 0]);

    let packet = FecPacket::new(10, Some(data), 1, false, Some(coefficients), 2, Arc::clone(&pool));
    let mut decoder8 = Decoder8::new(1, Arc::clone(&pool));
    decoder8.take_packet(packet.clone());
    assert!(decoder8.get_partial_result().is_empty());

    let mut decoder4 = Decoder4::new(1, Arc::clone(&pool));
    decoder4.take_packet(packet);
    assert!(decoder4.get_partial_result().is_empty());
}

#[test]
fn checked_decoder_constructor_rejects_invalid_dimensions() {
    let pool = Arc::new(crate::optimize::MemoryPool::new(2, 2_048));
    assert!(matches!(
        FecDecoder8::try_new(0, Arc::clone(&pool)),
        Err(FecDecoderConfigError::ZeroSourceCount)
    ));
    assert!(matches!(
        FecDecoder8::try_new(256, Arc::clone(&pool)),
        Err(FecDecoderConfigError::FieldSourceLimit { max: 255 })
    ));
}

#[test]
fn gf16_completion_requires_active_window_membership() {
    let pool = Arc::new(crate::optimize::MemoryPool::new(4, 2_048));
    let mut decoder = Decoder16::new(2, Arc::clone(&pool));
    decoder.take_packet(FecPacket::from_block(100, &[1], Arc::clone(&pool)));
    decoder.take_packet(FecPacket::from_block(101, &[2], Arc::clone(&pool)));

    let data = pool.alloc();
    let mut coefficients = pool.alloc();
    coefficients[..4].copy_from_slice(&[0, 0, 0, 0]);
    decoder.take_packet(FecPacket::new(
        10,
        Some(data),
        1,
        false,
        Some(coefficients),
        4,
        Arc::clone(&pool),
    ));

    assert!(decoder.get_result().is_none());
}
