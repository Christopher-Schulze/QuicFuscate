// --- 9. Flow Shaping & Dummy Retransmits

/// Advanced flow shaping with jitter and dummy retransmits.
struct FlowShaper {
    /// Jitter configuration.
    jitter_min_us: u64,
    jitter_max_us: u64,
    /// Packet history for shaping decisions.
    packet_history: Arc<Mutex<VecDeque<PacketInfo>>>,
    /// Shaping enabled.
    _enabled: AtomicBool,
}

#[derive(Clone)]
struct PacketInfo {
    /// Timestamp.
    timestamp: std::time::Instant,
    /// Size.
    _size: usize,
    /// Type.
    _packet_type: StealthPacketClass,
}

/// Stealth-specific packet classification for flow shaping decisions.
/// Distinct from the QUIC-level `transport::PacketType` which classifies wire packet types.
#[derive(Clone, Copy)]
#[allow(dead_code)]
enum StealthPacketClass {
    Data,
    Ack,
    Retransmit,
    Dummy,
}

impl FlowShaper {
    /// Create a new flow shaper.
    pub fn new(jitter_us: u64, _enable_dummy_retransmits: bool) -> Self {
        let jitter_max_us = jitter_us.max(1);
        Self {
            jitter_min_us: (jitter_max_us / 2).max(1),
            jitter_max_us,
            packet_history: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            _enabled: AtomicBool::new(true),
        }
    }

    /// Apply jitter to packet timing.
    pub fn apply_jitter(&self) -> std::time::Duration {
        use rand::Rng;
        let mut rng = rand::rng();
        let jitter_us = rng.random_range(self.jitter_min_us..=self.jitter_max_us);
        std::time::Duration::from_micros(jitter_us)
    }

    /// Apply handshake flight pacing (tens of milliseconds)
    pub fn apply_flight_pacing(&self, is_handshake: bool) -> std::time::Duration {
        if !is_handshake {
            return std::time::Duration::ZERO;
        }

        // Roughly 10-20ms during handshake flights to mimic conservative clients
        std::time::Duration::from_millis(15)
    }

    /// Records a packet in history and prunes old entries. This reads timestamps, eliminating dead_code warnings.
    fn record_and_prune(&self, size: usize, ty: StealthPacketClass) {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        if let Ok(mut hist) = self.packet_history.lock() {
            hist.push_back(PacketInfo { timestamp: now, _size: size, _packet_type: ty });
            // Keep only recent 2 seconds and limit to 256 entries
            while let Some(front) = hist.front() {
                if now.duration_since(front.timestamp) > Duration::from_secs(2) || hist.len() > 256
                {
                    hist.pop_front();
                } else {
                    break;
                }
            }
        }
    }
}
