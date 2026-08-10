// --- 9. Active Probing Detection & Response

use log::{error, warn};
use std::sync::{Arc, Mutex};

/// Detects and responds to active probing attempts.
pub struct ActiveProbeDetector {
    /// Monotonic clock owned by the connection's stealth manager.
    clock: qf_common::time_source::ProtocolClock,
    /// Probe patterns database.
    patterns: Vec<ProbePattern>,
    /// Bounded matching-probe timestamps retained for the detector threshold.
    history: Arc<Mutex<std::collections::VecDeque<std::time::Instant>>>,
    /// Detection threshold.
    threshold: usize,
    /// Maximum number of matching timestamps retained at once.
    history_limit: usize,
    /// Response mode.
    response_mode: ProbeResponseMode,
}

#[derive(Clone)]
struct ProbePattern {
    /// Pattern name.
    name: String,
    /// Pattern bytes to match.
    pattern: Vec<u8>,
    /// Pattern mask (for wildcard matching).
    mask: Option<Vec<u8>>,
    /// Severity level (1-10).
    _severity: u8,
}

/// Action to take when an active probe is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResponseMode {
    /// Ignore the probe.
    Ignore,
    /// Send fake response.
    Fake,
    /// Switch to higher stealth mode.
    Switch,
    /// Block the source.
    Block,
}

impl ActiveProbeDetector {
    /// Create a new probe detector.
    pub fn new(threshold: usize, response_mode: ProbeResponseMode) -> Self {
        Self::new_with_clock(
            threshold,
            response_mode,
            &qf_common::time_source::ProtocolClock::default(),
        )
    }

    #[doc(hidden)]
    pub fn new_with_clock(
        threshold: usize,
        response_mode: ProbeResponseMode,
        clock: &qf_common::time_source::ProtocolClock,
    ) -> Self {
        let history_limit = threshold.max(1);
        Self {
            clock: clock.clone(),
            patterns: Self::load_probe_patterns(),
            history: Arc::new(Mutex::new(std::collections::VecDeque::with_capacity(history_limit))),
            threshold,
            history_limit,
            response_mode,
        }
    }

    fn load_probe_patterns() -> Vec<ProbePattern> {
        vec![
            // GFW active probing patterns
            ProbePattern {
                name: "GFW_TLS_Probe".to_string(),
                pattern: vec![0x16, 0x03, 0x01, 0x00, 0x00],
                mask: None,
                _severity: 8,
            },
            // DPI_QUIC_Scan pattern removed: it matched byte[0]==0xc0 && byte[4]==0x01,
            // which is the exact signature of a legitimate QUICv1 Initial packet
            // (long header 0xc0, version 0x00000001, DCID length 0x01). This caused
            // false positives on every real client's Initial, triggering probe
            // response mode and corrupting the handshake. A censor's QUIC probe is
            // indistinguishable from a legitimate Initial at the byte pattern level;
            // active probe detection must instead rely on connection-level heuristics
            // (unknown source, retry behavior, etc.) not raw packet matching.
            // Port_Scan_SYN pattern removed: raw TCP SYN packets (TCP flags byte 0x02) cannot
            // appear as valid QUIC payloads because RFC 9000 mandates the Fixed Bit (bit 6 = 0x40)
            // in every QUIC short-header and bit 7 (0x80) in every QUIC long-header. A payload
            // starting with 0x00 therefore cannot be a QUIC packet and is rejected at a lower
            // layer before the probe detector is ever reached. The generic 4-byte unmasked pattern
            // produced false positives when any non-QUIC UDP traffic touched the port.
        ]
    }

    /// Check if packet is an active probe.
    pub fn check_packet(
        &self,
        packet: &[u8],
        source: std::net::SocketAddr,
    ) -> Option<ProbeResponseMode> {
        for pattern in &self.patterns {
            if self.matches_pattern(packet, pattern) {
                warn!("Active probe detected: {} from {}", pattern.name, source);

                let timestamp = self.clock.now();

                if let Ok(mut history) = self.history.lock() {
                    record_probe_timestamp(&mut history, timestamp, self.history_limit);

                    let recent_count = history.len();

                    if recent_count >= self.threshold {
                        error!("Active probing threshold exceeded! Count: {}", recent_count);
                        return Some(ProbeResponseMode::Switch);
                    }
                }

                return Some(self.response_mode);
            }
        }
        None
    }

    fn matches_pattern(&self, packet: &[u8], pattern: &ProbePattern) -> bool {
        if packet.len() < pattern.pattern.len() {
            return false;
        }

        if let Some(mask) = &pattern.mask {
            for i in 0..pattern.pattern.len() {
                if (packet[i] & mask[i]) != (pattern.pattern[i] & mask[i]) {
                    return false;
                }
            }
        } else if !packet.starts_with(&pattern.pattern) {
            return false;
        }

        true
    }

    /// Generate fake response for probe.
    pub fn generate_fake_response(&self, probe_type: &str) -> Vec<u8> {
        match probe_type {
            "GFW_TLS_Probe" => {
                // TLS Cover alert
                vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]
            }
            "DPI_QUIC_Scan" => {
                // Keep the legacy response selector for callers that still name the removed
                // detector pattern; the pattern itself is intentionally not matched anymore.
                vec![0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            }
            _ => {
                // Generic error response
                vec![0x00, 0x00, 0x00, 0x00]
            }
        }
    }
}

const PROBE_HISTORY_RETENTION: std::time::Duration = std::time::Duration::from_secs(60);

fn prune_probe_history(
    history: &mut std::collections::VecDeque<std::time::Instant>,
    now: std::time::Instant,
) {
    history.retain(|timestamp| now.saturating_duration_since(*timestamp) < PROBE_HISTORY_RETENTION);
}

fn record_probe_timestamp(
    history: &mut std::collections::VecDeque<std::time::Instant>,
    timestamp: std::time::Instant,
    history_limit: usize,
) {
    let history_limit = history_limit.max(1);
    prune_probe_history(history, timestamp);
    if history.len() >= history_limit {
        let _ = history.pop_front();
    }
    history.push_back(timestamp);
}

#[cfg(test)]
mod probe_detector_tests {
    use super::{record_probe_timestamp, ActiveProbeDetector, ProbeResponseMode};
    use std::collections::VecDeque;
    use std::time::{Duration, Instant};

    fn probe_packet() -> [u8; 6] {
        [0x16, 0x03, 0x01, 0x00, 0x00, 0xff]
    }

    fn source() -> std::net::SocketAddr {
        "127.0.0.1:4433".parse().expect("valid probe source")
    }

    #[test]
    fn sustained_matching_probes_are_bounded_by_threshold() {
        let detector = ActiveProbeDetector::new(3, ProbeResponseMode::Fake);

        for _ in 0..128 {
            let _ = detector.check_packet(&probe_packet(), source());
        }

        let history = detector.history.lock().expect("probe history lock");
        assert_eq!(history.len(), 3);
    }

    #[test]
    fn history_evicts_oldest_timestamp_at_limit() {
        let base = Instant::now();
        let mut history = VecDeque::new();

        for offset in 0..4 {
            record_probe_timestamp(&mut history, base + Duration::from_secs(offset), 3);
        }

        let expected = VecDeque::from([
            base + Duration::from_secs(1),
            base + Duration::from_secs(2),
            base + Duration::from_secs(3),
        ]);
        assert_eq!(history, expected);
    }

    #[test]
    fn history_prunes_expired_timestamps_before_insertion() {
        let now = Instant::now();
        let mut history =
            VecDeque::from([now - Duration::from_secs(61), now - Duration::from_secs(59)]);

        record_probe_timestamp(&mut history, now, 3);

        let expected = VecDeque::from([now - Duration::from_secs(59), now]);
        assert_eq!(history, expected);
    }

    #[test]
    fn zero_threshold_switches_on_first_match() {
        let detector = ActiveProbeDetector::new(0, ProbeResponseMode::Ignore);

        assert_eq!(
            detector.check_packet(&probe_packet(), source()),
            Some(ProbeResponseMode::Switch)
        );
    }

    #[test]
    fn benign_packets_do_not_enter_history() {
        let detector = ActiveProbeDetector::new(3, ProbeResponseMode::Fake);
        let benign = [0x40, 0x01, 0x02, 0x03, 0x04, 0x05];

        assert_eq!(detector.check_packet(&benign, source()), None);
        assert!(detector.history.lock().expect("probe history lock").is_empty());
    }
}
