// --- 9. Active Probing Detection & Response

/// Detects and responds to active probing attempts.
pub struct ActiveProbeDetector {
    /// Probe patterns database.
    patterns: Vec<ProbePattern>,
    /// Detection history.
    history: Arc<Mutex<Vec<ProbeEvent>>>,
    /// Detection threshold.
    threshold: usize,
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

#[derive(Clone)]
struct ProbeEvent {
    /// Timestamp.
    _timestamp: std::time::Instant,
    /// Source address.
    _source: std::net::SocketAddr,
    /// Detected pattern.
    _pattern: String,
    /// Response taken.
    _response: ProbeResponseMode,
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
        Self {
            patterns: Self::load_probe_patterns(),
            history: Arc::new(Mutex::new(Vec::with_capacity(100))),
            threshold,
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

                // Record event
                let event = ProbeEvent {
                    _timestamp: std::time::Instant::now(),
                    _source: source,
                    _pattern: pattern.name.clone(),
                    _response: self.response_mode,
                };

                if let Ok(mut history) = self.history.lock() {
                    history.retain(|e| e._timestamp.elapsed().as_secs() < 60);
                    history.push(event);

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
