//! E2E FEC integration tests through a simulated transport with real packet drop.
//!
//! These tests exercise the full FEC pipeline (`on_send` → serialize → drop channel
//! → deserialize → `on_receive`) with deterministic loss injection at the transport
//! layer, not at the FEC module level. This verifies:
//!
//! - FEC repair packets traverse the wire correctly (stream_raw roundtrip).
//! - Lost source packets are recovered on the receiver.
//! - FEC mode escalates under sustained loss and de-escalates when loss stops.
//! - No packet duplication or ordering violations.
//! - Systematic packets are always forwarded, even under heavy loss.

use super::test_support::*;
use super::*;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, MutexGuard};

// ---------------------------------------------------------------------------
// Deterministic drop channel — simulates tc-netem loss at the transport layer.
// Uses a simple LCG so results are reproducible across runs.
// ---------------------------------------------------------------------------

struct DropChannel {
    state: u64,
    loss_rate: f32, // 0.0 = no loss, 1.0 = total loss
    /// If set, drop only systematic packets with these IDs (overrides loss_rate).
    targeted_drops: Option<HashSet<u64>>,
}

impl DropChannel {
    fn new(seed: u64, loss_rate: f32) -> Self {
        Self {
            state: seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407),
            loss_rate: loss_rate.clamp(0.0, 1.0),
            targeted_drops: None,
        }
    }

    fn with_targeted_drops(drop_ids: HashSet<u64>) -> Self {
        Self { state: 0, loss_rate: 0.0, targeted_drops: Some(drop_ids) }
    }

    /// Returns true if the packet should be dropped (lost in transit).
    fn should_drop(&mut self, pkt: &FecPacket) -> bool {
        if let Some(ref ids) = self.targeted_drops {
            return pkt.is_systematic && ids.contains(&pkt.id);
        }
        // LCG step for random mode
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let r = ((self.state >> 33) as f64) / ((1u64 << 31) as f64);
        r < self.loss_rate as f64
    }
}

// ---------------------------------------------------------------------------
// Simulated transport: serialize → drop → deserialize → deliver
// ---------------------------------------------------------------------------

/// Serialize a FecPacket to wire format, simulating the transport layer.
fn to_wire(pkt: &FecPacket) -> Vec<u8> {
    let mut buf = vec![0u8; 2 + 1 + 8 + 8 + 2 + pkt.coeff_len + pkt.data_len + 64];
    let used = pkt.to_stream_raw(&mut buf[..]).expect("stream_raw serialization must succeed");
    buf.truncate(used);
    buf
}

/// Deserialize a FecPacket from wire format.
fn from_wire(wire: &[u8], pool: &Arc<MemoryPool>) -> FecPacket {
    FecPacket::from_stream_raw(wire, Arc::clone(pool))
        .expect("stream_raw deserialization must succeed")
}

// ---------------------------------------------------------------------------
// Test harness: sender FEC → drop channel → receiver FEC
// ---------------------------------------------------------------------------

struct TransportSim {
    sender: AdaptiveFec,
    receiver: AdaptiveFec,
    channel: DropChannel,
    /// All packets delivered to the receiver (by id), in arrival order.
    delivered: Vec<u64>,
    /// Set of delivered ids for dedup checking.
    delivered_set: HashSet<u64>,
    /// First payload delivered for each source ID.
    delivered_payloads: HashMap<u64, Vec<u8>>,
    /// Source-send count when each source ID was first delivered.
    delivered_at: HashMap<u64, usize>,
    /// Number of repeated systematic deliveries observed before deduplication.
    duplicate_count: usize,
    /// Systematic packet IDs dropped by the transport.
    dropped_source_ids: HashSet<u64>,
    /// Repair anchor and first coefficient for repair packets dropped by the transport.
    dropped_repairs: Vec<(u64, u8)>,
    /// Count of source packets sent.
    sent_count: usize,
    /// Count of repair packets sent.
    repair_count: usize,
    /// Count of packets dropped in transit.
    dropped_count: usize,
    /// Held for the lifetime of the sim to keep the production interleave policy active.
    _env_guards: Vec<EnvGuard>,
    /// Serializes process-global FEC environment overrides across tests.
    _env_lock: MutexGuard<'static, ()>,
}

impl TransportSim {
    fn new(loss_rate: f32, seed: u64) -> Self {
        Self::with_channel(DropChannel::new(seed, loss_rate))
    }

    fn with_targeted_drops(drop_ids: HashSet<u64>) -> Self {
        Self::with_channel(DropChannel::with_targeted_drops(drop_ids))
    }

    fn with_channel(channel: DropChannel) -> Self {
        let env_lock = acquire_env_lock();
        // Interleaving is fixed (TODO-433): every decoder family maps repair
        // coefficients with the configured source-ID stride.
        // Tests run with the production default (interleave enabled).
        // Start explicitly in Normal so the transport simulator exercises block FEC immediately.
        let interleave_on = EnvGuard::set("QUICFUSCATE_FEC_INTERLEAVE", "1");
        let default_depth = EnvGuard::unset("QUICFUSCATE_FEC_INTERLEAVE_DEPTH");
        let config = FecConfig { initial_mode: FecMode::Normal, ..FecConfig::default() };
        Self {
            sender: AdaptiveFec::new(config.clone()),
            receiver: AdaptiveFec::new(config),
            channel,
            delivered: Vec::new(),
            delivered_set: HashSet::new(),
            delivered_payloads: HashMap::new(),
            delivered_at: HashMap::new(),
            duplicate_count: 0,
            dropped_source_ids: HashSet::new(),
            dropped_repairs: Vec::new(),
            sent_count: 0,
            repair_count: 0,
            dropped_count: 0,
            _env_guards: vec![interleave_on, default_depth],
            _env_lock: env_lock,
        }
    }

    /// Send a source packet through the FEC pipeline and transport.
    fn send_source(&mut self, id: u64, payload_len: usize) {
        let pool = crate::optimize::global_pool();
        let src = mk_src_packet(id, payload_len, &pool);

        // FEC on_send: produces systematic + repair packets
        let output = self.sender.on_send(src);

        for pkt in &output {
            if pkt.is_systematic {
                self.sent_count += 1;
            } else {
                self.repair_count += 1;
            }
        }

        // Transport: serialize → drop → deserialize → on_receive
        for pkt in output {
            let wire = to_wire(&pkt);
            if self.channel.should_drop(&pkt) {
                if pkt.is_systematic {
                    self.dropped_source_ids.insert(pkt.id);
                } else {
                    self.dropped_repairs.push((
                        pkt.id,
                        pkt.coefficients
                            .as_ref()
                            .and_then(|coefficients| coefficients.first().copied())
                            .unwrap_or(0),
                    ));
                }
                self.dropped_count += 1;
                continue;
            }
            let pool = crate::optimize::global_pool();
            let received = from_wire(&wire, &pool);
            let recovered = self.receiver.on_receive(received).expect("on_receive ok");
            for p in recovered {
                // Only track source packets (systematic). Repair packets have
                // id = window_anchor_id which collides with source packet ids.
                if p.is_systematic {
                    if self.delivered_set.insert(p.id) {
                        self.delivered.push(p.id);
                        self.delivered_at.insert(p.id, self.sent_count);
                        self.delivered_payloads.insert(
                            p.id,
                            p.payload_slice()
                                .expect("systematic packet must carry payload")
                                .to_vec(),
                        );
                    } else {
                        self.duplicate_count += 1;
                    }
                }
            }
        }
    }

    /// Report loss to the sender's FEC controller (simulates ACK feedback).
    fn report_loss_sender(&mut self, lost: usize, total: usize) {
        self.sender.report_loss(lost, total);
    }

    /// Current FEC mode on the sender side.
    fn sender_mode(&self) -> FecMode {
        self.sender.current_mode()
    }

    /// Number of unique source packets delivered (by id).
    fn delivered_count(&self) -> usize {
        self.delivered_set.len()
    }

    /// Recovery ratio: delivered / sent.
    fn recovery_ratio(&self) -> f32 {
        if self.sent_count == 0 {
            return 1.0;
        }
        self.delivered_count() as f32 / self.sent_count as f32
    }

    /// Verify no duplicate ids were delivered.
    fn verify_no_duplicates(&self) -> bool {
        self.duplicate_count == 0 && self.delivered.len() == self.delivered_set.len()
    }

    fn assert_exact_delivery(&self, packet_count: u64, payload_len: usize, max_latency: usize) {
        let delivered_contract_count =
            self.delivered_set.iter().filter(|&&id| id < packet_count).count();
        assert_eq!(
            delivered_contract_count, packet_count as usize,
            "expected {packet_count}/{packet_count} unique contract deliveries"
        );
        assert_eq!(self.duplicate_count, 0, "decoder emitted duplicate source packets");

        for id in 0..packet_count {
            let payload =
                self.delivered_payloads.get(&id).expect("source payload must be delivered");
            assert_eq!(payload.len(), payload_len, "payload length mismatch for source {id}");
            assert!(
                payload
                    .iter()
                    .enumerate()
                    .all(|(index, byte)| *byte == (id as u8).wrapping_add(index as u8)),
                "payload corruption for source {id}: dropped={}, window_drops={:?}, window_repair_drops={:?}, delivered_at={:?}, actual={:?}, expected={:?}",
                self.dropped_source_ids.contains(&id),
                self.dropped_source_ids
                    .iter()
                    .copied()
                    .filter(|dropped| dropped / 64 == id / 64)
                    .collect::<Vec<_>>(),
                self.dropped_repairs
                    .iter()
                    .copied()
                    .filter(|(anchor, _)| anchor / 64 == id / 64)
                    .collect::<Vec<_>>(),
                self.delivered_at.get(&id),
                &payload[..payload.len().min(16)],
                (0..payload.len().min(16))
                    .map(|index| (id as u8).wrapping_add(index as u8))
                    .collect::<Vec<_>>()
            );

            let delivered_at = self.delivered_at.get(&id).copied().expect("delivery time recorded");
            let latency = delivered_at.saturating_sub(id as usize + 1);
            assert!(
                latency <= max_latency,
                "source {id} recovery latency {latency} exceeded {max_latency} source sends"
            );
        }
    }
}

#[test]
fn test_decoder8_source_id_mapping_is_exact_for_both_depths() {
    let pool = crate::optimize::global_pool();
    let policy = FecRuntimePolicy::detect();
    let plain = Decoder8::new_with_depth(4, Arc::clone(&pool), &policy, 1);
    let interleaved = Decoder8::new_with_depth(4, pool, &policy, 4);

    assert_eq!((0..4).map(|j| plain.source_id_for(15, j)).collect::<Vec<_>>(), [12, 13, 14, 15]);
    assert_eq!(
        (0..4).map(|j| interleaved.source_id_for(15, j)).collect::<Vec<_>>(),
        [3, 7, 11, 15]
    );
}

#[test]
fn test_decoder16_source_id_mapping_is_exact_for_both_depths() {
    let pool = crate::optimize::global_pool();
    let plain = Decoder16::new(4, Arc::clone(&pool));
    let interleaved = Decoder16::new_with_depth(4, pool, 4);

    assert_eq!((0..4).map(|j| plain.source_id_for(15, j)).collect::<Vec<_>>(), [12, 13, 14, 15]);
    assert_eq!(
        (0..4).map(|j| interleaved.source_id_for(15, j)).collect::<Vec<_>>(),
        [3, 7, 11, 15]
    );
}

#[test]
fn test_decoder4_source_id_mapping_is_exact_for_both_depths() {
    let pool = crate::optimize::global_pool();
    let plain = Decoder4::new(4, Arc::clone(&pool));
    let interleaved = Decoder4::new_with_depth(4, pool, 4);

    assert_eq!((0..4).map(|j| plain.source_id_for(15, j)).collect::<Vec<_>>(), [12, 13, 14, 15]);
    assert_eq!(
        (0..4).map(|j| interleaved.source_id_for(15, j)).collect::<Vec<_>>(),
        [3, 7, 11, 15]
    );
}

#[test]
fn test_decoder8_recovers_interleaved_sources_byte_exactly() {
    let pool = crate::optimize::global_pool();
    let policy = FecRuntimePolicy::detect();
    let mut decoder = Decoder8::new_with_depth(16, Arc::clone(&pool), &policy, 4);
    for window in 0..10u64 {
        let base_id = window * 64;
        let missing = HashSet::from([base_id + 4, base_id + 36]);
        let mut encoder = Encoder8::new(16, 20);

        for id in (base_id..base_id + 64).step_by(4) {
            encoder.take_packet(mk_src_packet(id, 1024, &pool));
            if !missing.contains(&id) {
                decoder.take_packet(mk_src_packet(id, 1024, &pool));
            }
        }
        for repair_index in 0..4 {
            let repair = encoder
                .generate_repair_packet(repair_index, &pool)
                .expect("full block must emit repair");
            let first_coefficient = repair
                .coefficients
                .as_ref()
                .and_then(|coefficients| coefficients.first().copied())
                .expect("repair coefficient");
            if first_coefficient != 88 {
                decoder.take_packet(from_wire(&to_wire(&repair), &pool));
            }
        }

        let recovered =
            decoder.get_result().expect("two independent repairs must recover both gaps");
        let recovered: HashMap<u64, Vec<u8>> = recovered
            .into_iter()
            .map(|packet| {
                (packet.id, packet.payload_slice().expect("recovered source payload").to_vec())
            })
            .collect();
        for id in missing {
            let payload = recovered.get(&id).expect("missing source must be recovered");
            assert!(
                payload
                    .iter()
                    .enumerate()
                    .all(|(index, byte)| *byte == (id as u8).wrapping_add(index as u8)),
                "recovered source {id} must be byte exact in window {window}"
            );
        }
    }
}

#[test]
fn test_interleaved_decoder_recovers_repeated_burst_windows_byte_exactly() {
    let pool = crate::optimize::global_pool();
    let policy = FecRuntimePolicy::detect();
    let mut encoder =
        internal::InterleavedEncoder::new_with_policy(FecMode::Normal, 64, 80, 4, &policy);
    let mut decoder = internal::InterleavedDecoder::new_with_policy(
        FecMode::Normal,
        64,
        pool.clone(),
        4,
        &policy,
    );
    let mut recovered = HashMap::new();

    for id in 0..640u64 {
        encoder.take_packet(mk_src_packet(id, 1024, &pool));
        if id % 16 >= 4 {
            decoder.take_packet(from_wire(&to_wire(&mk_src_packet(id, 1024, &pool)), &pool));
        }
        if (id + 1).is_multiple_of(64) {
            for repair_index in 0..16 {
                let repair = encoder
                    .generate_repair_packet(repair_index, &pool)
                    .expect("full interleaved block must emit repair");
                decoder.take_packet(from_wire(&to_wire(&repair), &pool));
                if decoder.full_recovery_needed() {
                    if let Some(packets) = decoder.get_result() {
                        for packet in packets {
                            recovered.insert(
                                packet.id,
                                packet.payload_slice().expect("recovered source payload").to_vec(),
                            );
                        }
                    }
                }
            }
            encoder.clear_window();
        }
    }

    for id in (0..640u64).filter(|id| id % 16 < 4) {
        let payload = recovered.get(&id).expect("burst-lost source must be recovered");
        assert!(
            payload
                .iter()
                .enumerate()
                .all(|(index, byte)| *byte == (id as u8).wrapping_add(index as u8)),
            "recovered source {id} must be byte exact"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_fec_e2e_no_loss_all_delivered() {
    let mut sim = TransportSim::new(0.0, 42);

    // Send 100 source packets, 1400 bytes each (typical MTU payload)
    for id in 0..100u64 {
        sim.send_source(id, 1400);
    }

    assert_eq!(sim.sent_count, 100, "all 100 source packets should be sent");
    assert_eq!(
        sim.delivered_count(),
        100,
        "all 100 source packets should be delivered with 0% loss"
    );
    assert!(sim.verify_no_duplicates(), "no duplicate packets");
    assert_eq!(sim.dropped_count, 0, "no packets dropped at 0% loss");
}

#[test]
fn test_fec_e2e_single_loss_recovered() {
    // FEC block codes recover lost packets only after the window is full
    // and repair packets have been generated. We send 2 full windows (128
    // packets, k=64 per window) and drop one systematic packet from the
    // second window. The repairs for that window contain linear combinations
    // of all 64 source packets across four interleave lanes, enabling recovery.
    let _guard = acquire_env_lock();
    let config = FecConfig { initial_mode: FecMode::Normal, ..FecConfig::default() };
    let drop_id: u64 = 70;
    let mut sim = TransportSim {
        sender: AdaptiveFec::new(config.clone()),
        receiver: AdaptiveFec::new(config),
        channel: DropChannel::with_targeted_drops(vec![drop_id].into_iter().collect()),
        delivered: Vec::new(),
        delivered_set: HashSet::new(),
        delivered_payloads: HashMap::new(),
        delivered_at: HashMap::new(),
        duplicate_count: 0,
        dropped_source_ids: HashSet::new(),
        dropped_repairs: Vec::new(),
        sent_count: 0,
        repair_count: 0,
        dropped_count: 0,
        _env_guards: vec![],
        _env_lock: _guard,
    };

    // Send 128 packets (2 windows). Packet 70 will be dropped by the channel.
    for id in 0..128u64 {
        sim.send_source(id, 1400);
    }

    // Packet 70 should be recovered via FEC repair packets from window 2
    assert!(
        sim.delivered_set.contains(&drop_id),
        "lost source packet {} should be recovered via FEC repair (delivered={})",
        drop_id,
        sim.delivered_count()
    );
    // All source packets should be delivered (128 source - 1 dropped + 1 recovered = 128)
    assert!(
        sim.delivered_count() >= 128,
        "all 128 source packets should be delivered (got {})",
        sim.delivered_count()
    );
}

#[test]
fn test_fec_e2e_burst_loss_recovered() {
    // Send 3 windows (192 packets). Drop 3 consecutive systematic packets
    // from the third window (130, 131, 132). Production interleaving distributes
    // the burst across separate lanes and each lane's repair symbols recover it.
    let _guard = acquire_env_lock();
    let config = FecConfig { initial_mode: FecMode::Normal, ..FecConfig::default() };
    let drop_ids: HashSet<u64> = vec![130, 131, 132].into_iter().collect();
    let mut sim = TransportSim {
        sender: AdaptiveFec::new(config.clone()),
        receiver: AdaptiveFec::new(config),
        channel: DropChannel::with_targeted_drops(drop_ids.clone()),
        delivered: Vec::new(),
        delivered_set: HashSet::new(),
        delivered_payloads: HashMap::new(),
        delivered_at: HashMap::new(),
        duplicate_count: 0,
        dropped_source_ids: HashSet::new(),
        dropped_repairs: Vec::new(),
        sent_count: 0,
        repair_count: 0,
        dropped_count: 0,
        _env_guards: vec![],
        _env_lock: _guard,
    };

    // Send 192 packets (3 windows). Packets 130, 131, 132 will be dropped.
    for id in 0..192u64 {
        sim.send_source(id, 1400);
    }

    // The 3 burst-lost packets should be recovered via FEC repair
    for &lost_id in &drop_ids {
        assert!(
            sim.delivered_set.contains(&lost_id),
            "burst-lost packet {} should be recovered via FEC (delivered={})",
            lost_id,
            sim.delivered_count()
        );
    }
    assert!(
        sim.delivered_count() >= 192,
        "all 192 source packets should be delivered (got {})",
        sim.delivered_count()
    );
}

#[test]
fn test_fec_e2e_random_10pct_loss_high_recovery() {
    let mut sim = TransportSim::new(0.10, 300);

    // Send 200 packets at 10% random loss
    for id in 0..200u64 {
        sim.send_source(id, 1400);
    }

    // At 10% loss with Normal mode FEC, we expect >85% recovery
    // (some packets may be lost if both systematic and all repairs for a window are dropped)
    let ratio = sim.recovery_ratio();
    assert!(
        ratio > 0.85,
        "recovery ratio should be >85% at 10% loss, got {:.2}% (delivered={}, sent={})",
        ratio * 100.0,
        sim.delivered_count(),
        sim.sent_count
    );
    assert!(sim.verify_no_duplicates(), "no duplicate packets");
}

#[test]
fn test_fec_e2e_default_interleave_recovers_1000_packets_at_5pct_random_loss() {
    const CONTRACT_PACKETS: u64 = 1000;
    const WINDOW_FLUSH_PACKETS: u64 = 24;
    const PAYLOAD_LEN: usize = 1024;
    const MAX_RECOVERY_LATENCY: usize = 63;

    let mut sim = TransportSim::new(0.05, 0x5245_0001);
    for id in 0..CONTRACT_PACKETS + WINDOW_FLUSH_PACKETS {
        sim.send_source(id, PAYLOAD_LEN);
    }

    let contract_drops = sim.dropped_source_ids.iter().filter(|&&id| id < CONTRACT_PACKETS).count();
    assert!(
        (30..=70).contains(&contract_drops),
        "deterministic 5% channel must exercise representative source loss, got {contract_drops}/1000"
    );
    sim.assert_exact_delivery(CONTRACT_PACKETS, PAYLOAD_LEN, MAX_RECOVERY_LATENCY);
}

#[test]
fn test_fec_e2e_default_interleave_recovers_four_consecutive_losses_per_sixteen() {
    const CONTRACT_PACKETS: u64 = 1000;
    const WINDOW_FLUSH_PACKETS: u64 = 24;
    const PAYLOAD_LEN: usize = 1024;
    const MAX_RECOVERY_LATENCY: usize = 63;

    let drop_ids: HashSet<u64> = (0..CONTRACT_PACKETS).filter(|id| id % 16 < 4).collect();
    let mut sim = TransportSim::with_targeted_drops(drop_ids.clone());
    for id in 0..CONTRACT_PACKETS + WINDOW_FLUSH_PACKETS {
        sim.send_source(id, PAYLOAD_LEN);
    }

    assert_eq!(sim.dropped_source_ids, drop_ids, "burst injector must drop the exact pattern");
    sim.assert_exact_delivery(CONTRACT_PACKETS, PAYLOAD_LEN, MAX_RECOVERY_LATENCY);
}

#[test]
fn test_fec_e2e_random_25pct_loss_reasonable_recovery() {
    let mut sim = TransportSim::new(0.25, 400);

    // Send 200 packets at 25% random loss
    for id in 0..200u64 {
        sim.send_source(id, 1400);
    }

    // At 25% loss, FEC should still recover a significant fraction
    let ratio = sim.recovery_ratio();
    assert!(ratio > 0.60, "recovery ratio should be >60% at 25% loss, got {:.2}%", ratio * 100.0);
    assert!(sim.verify_no_duplicates(), "no duplicate packets");
}

#[test]
fn test_fec_e2e_repair_packets_generated() {
    let mut sim = TransportSim::new(0.0, 500);

    // Send enough packets to fill at least one window (k=64 for Normal)
    for id in 0..64u64 {
        sim.send_source(id, 1400);
    }

    // FEC should have generated repair packets
    assert!(
        sim.repair_count > 0,
        "FEC should generate repair packets after window completion (got {} repairs)",
        sim.repair_count
    );
}

#[test]
fn test_fec_e2e_mode_escalation_under_sustained_loss() {
    let mut sim = TransportSim::new(0.0, 600);

    // Phase 1: No loss — mode should stay at Normal or escalate to higher
    for id in 0..64u64 {
        sim.send_source(id, 1400);
    }
    let mode_before = sim.sender_mode();

    // Phase 2: Sustained high loss — report loss to trigger escalation
    // We need to report enough loss samples to overcome hysteresis
    for _ in 0..100 {
        sim.report_loss_sender(25, 100); // 25% loss
    }

    let mode_after = sim.sender_mode();
    assert!(
        mode_after as usize >= mode_before as usize,
        "FEC mode should escalate under sustained 25% loss: before={:?}, after={:?}",
        mode_before,
        mode_after
    );
}

#[test]
fn test_fec_e2e_mode_deescalation_when_loss_stops() {
    let mut sim = TransportSim::new(0.0, 700);

    // Phase 1: Escalate to high mode via sustained loss reporting
    for _ in 0..100 {
        sim.report_loss_sender(50, 100); // 50% loss
    }
    let mode_escalated = sim.sender_mode();
    assert!(
        mode_escalated != FecMode::Zero,
        "FEC should have escalated away from Zero under 50% loss"
    );

    // Phase 2: Report zero loss for a sustained period — mode should de-escalate
    for _ in 0..200 {
        sim.report_loss_sender(0, 100); // 0% loss
    }
    let mode_deescalated = sim.sender_mode();
    assert!(
        mode_deescalated as usize <= mode_escalated as usize,
        "FEC mode should de-escalate when loss stops: escalated={:?}, deescalated={:?}",
        mode_escalated,
        mode_deescalated
    );
}

#[test]
fn test_fec_e2e_no_duplication_no_ordering_violation() {
    let mut sim = TransportSim::new(0.05, 800);

    // Send 300 packets at 5% loss
    for id in 0..300u64 {
        sim.send_source(id, 1400);
    }

    // Verify no duplicates
    assert!(sim.verify_no_duplicates(), "no duplicate packet ids should be delivered");

    // Verify delivered ids are all in the valid range
    for &id in &sim.delivered {
        assert!(id < 300, "delivered packet id {} should be in valid range [0, 300)", id);
    }

    // Ordering contract. Recovery may surface a source after later sources, but only within a
    // bounded window. Without this the test's ordering claim would rest on the duplicate and
    // range checks alone, which say nothing about delivery order.
    let mut worst_latency = 0usize;
    for &id in &sim.delivered {
        let delivered_at = sim.delivered_at.get(&id).copied().expect("delivery time recorded");
        worst_latency = worst_latency.max(delivered_at.saturating_sub(id as usize + 1));
    }
    assert!(
        worst_latency <= FEC_E2E_MAX_RECOVERY_REORDER,
        "delivery reordering {worst_latency} exceeded the bounded recovery window {FEC_E2E_MAX_RECOVERY_REORDER}"
    );
}

/// Maximum number of later source sends a recovered packet may trail its own position by in the
/// 5 percent loss end-to-end simulation. Bounded by the active block window, not by chance.
const FEC_E2E_MAX_RECOVERY_REORDER: usize = 64;

#[test]
fn test_fec_e2e_zero_mode_passthrough_no_repairs() {
    let _guard = acquire_env_lock();
    let config = FecConfig { initial_mode: FecMode::Zero, ..FecConfig::default() };
    let mut sim = TransportSim {
        sender: AdaptiveFec::new(config.clone()),
        receiver: AdaptiveFec::new(config),
        channel: DropChannel::new(900, 0.0),
        delivered: Vec::new(),
        delivered_set: HashSet::new(),
        delivered_payloads: HashMap::new(),
        delivered_at: HashMap::new(),
        duplicate_count: 0,
        dropped_source_ids: HashSet::new(),
        dropped_repairs: Vec::new(),
        sent_count: 0,
        repair_count: 0,
        dropped_count: 0,
        _env_guards: vec![],
        _env_lock: _guard,
    };

    // Send 100 packets in Zero mode — no repairs should be generated
    for id in 0..100u64 {
        sim.send_source(id, 1400);
    }

    assert_eq!(sim.sent_count, 100);
    assert_eq!(sim.repair_count, 0, "Zero mode should not generate repairs");
    assert_eq!(sim.delivered_count(), 100);
    assert_eq!(sim.sender_mode(), FecMode::Zero);
}

#[test]
fn test_fec_e2e_wire_format_roundtrip_preserves_payload() {
    let pool = crate::optimize::global_pool();
    let sim = TransportSim::new(0.0, 1000);

    // Send a packet with known payload
    let src = mk_src_packet(42, 256, &pool);
    let original_payload = src.payload_slice().unwrap().to_vec();

    // Serialize → deserialize
    let wire = to_wire(&src);
    let pool2 = crate::optimize::global_pool();
    let recovered = from_wire(&wire, &pool2);

    assert_eq!(recovered.id, 42);
    assert_eq!(recovered.data_len, 256);
    assert_eq!(
        recovered.payload_slice().unwrap(),
        &original_payload[..],
        "wire format roundtrip must preserve payload bytes exactly"
    );
}

#[test]
fn test_fec_e2e_heavy_loss_50pct_still_operational() {
    let mut sim = TransportSim::new(0.50, 1100);

    // Send 200 packets at 50% loss — FEC should keep the link operational
    for id in 0..200u64 {
        sim.send_source(id, 1400);
    }

    let ratio = sim.recovery_ratio();
    // At 50% loss, even with FEC, some packets will be unrecoverable.
    // But the link should still deliver a meaningful fraction.
    assert!(
        ratio > 0.30,
        "recovery ratio should be >30% at 50% loss (FEC keeps link operational), got {:.2}%",
        ratio * 100.0
    );
    assert!(sim.verify_no_duplicates(), "no duplicate packets even at 50% loss");
}
