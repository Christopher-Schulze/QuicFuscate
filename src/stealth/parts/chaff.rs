// --- 9b. Chaff (Dummy Packet) Generator (TODO-455) ---

/// QUIC PING frame type byte (RFC 9000 §19.2). A single varint 0x01 with no payload.
const CHAFF_PING_FRAME_BYTE: u8 = 0x01;
/// QUIC PADDING frame byte (RFC 9000 §19.1). Each zero byte in the plaintext is a
/// distinct PADDING frame, so a run of N zero bytes encodes N PADDING frames.
const CHAFF_PADDING_FRAME_BYTE: u8 = 0x00;

/// Generates dummy ("chaff") QUIC packets at a configurable rate to defend against
/// timing- and volume-based traffic analysis (TODO-455).
///
/// A chaff packet is a **real** QUIC 1-RTT packet: it is encrypted with the same
/// 1-RTT keys, uses the same short-header format, carries a PING frame (so the peer
/// ACKs it, producing bidirectional cover traffic) followed by PADDING frames to
/// reach the target size. To an outside observer it is indistinguishable from a
/// real data packet of the same size.
///
/// The injection cadence is jittered by ±10% around the base interval
/// (`1 / chaff_rate_pps`) so the chaff blends with real traffic timing rather than
/// producing a mechanically periodic pattern.
pub struct ChaffGenerator {
    /// Target chaff emission rate in packets per second. 0 = disabled.
    rate_pps: u32,
    /// Target total chaff packet size in bytes (header + plaintext + AEAD tag).
    /// The generator produces a plaintext of `target_plaintext_len` bytes; the
    /// caller is responsible for sizing the buffer so that header + plaintext + tag
    /// equals this target.
    chaff_size_bytes: u32,
    /// When true, chaff packets include a PING frame (ack-eliciting) so the peer
    /// generates ACKs, producing symmetric bidirectional cover traffic.
    ack_eliciting: bool,
    /// Time of the last chaff emission (or construction time if none sent yet).
    last_chaff: std::time::Instant,
    /// Time of the last real-traffic send. Used to skip chaff that would collide
    /// with real packets and to support future soft-stop ramp-down.
    last_real_traffic: std::time::Instant,
    /// Jittered interval for the *next* chaff emission. Recomputed after each tick
    /// so every interval gets an independent ±10% perturbation.
    next_interval: std::time::Duration,
}

impl ChaffGenerator {
    /// Creates a new chaff generator.
    ///
    /// - `rate_pps`: target packets per second (0 disables; `should_chaff` always
    ///   returns false).
    /// - `chaff_size_bytes`: target total packet size in bytes.
    /// - `ack_eliciting`: include a PING frame so the peer ACKs the chaff.
    pub fn new(rate_pps: u32, chaff_size_bytes: u32, ack_eliciting: bool) -> Self {
        let now = std::time::Instant::now();
        let base = Self::base_interval(rate_pps);
        Self {
            rate_pps,
            chaff_size_bytes,
            ack_eliciting,
            last_chaff: now,
            last_real_traffic: now,
            next_interval: Self::jitter_interval(base),
        }
    }

    /// Base (unjittered) inter-chaff interval for `rate_pps`.
    /// Returns `ZERO` when disabled (rate 0).
    pub fn base_interval(rate_pps: u32) -> std::time::Duration {
        if rate_pps == 0 {
            return std::time::Duration::ZERO;
        }
        std::time::Duration::from_nanos(1_000_000_000 / rate_pps as u64)
    }

    /// Applies a ±10% uniform jitter to `base`, returning the jittered interval.
    /// A fresh jitter is drawn per interval so the emission pattern is not
    /// mechanically periodic.
    fn jitter_interval(base: std::time::Duration) -> std::time::Duration {
        if base.is_zero() {
            return base;
        }
        use rand::Rng;
        let mut rng = rand::rng();
        // Factor in [0.9, 1.1]
        let factor: f64 = rng.random_range(0.9..=1.1);
        let ns = base.as_nanos() as f64 * factor;
        std::time::Duration::from_nanos(ns.round() as u64)
    }

    /// Returns the jittered interval to use for the next chaff emission tick.
    pub fn next_interval(&self) -> std::time::Duration {
        self.next_interval
    }

    /// Returns true if a chaff packet should be emitted at `now`.
    ///
    /// Returns false when the generator is disabled (`rate_pps == 0`). When real
    /// traffic was sent within the current interval, chaff is suppressed to avoid
    /// colliding with a real packet (the real packet already "covers" the slot).
    pub fn should_chaff(&mut self, now: std::time::Instant, has_real_traffic: bool) -> bool {
        if self.rate_pps == 0 {
            return false;
        }
        if has_real_traffic {
            // A real packet was just sent; reset the chaff clock so the next chaff
            // is scheduled one interval out, blending with real traffic.
            self.last_chaff = now;
            self.last_real_traffic = now;
            self.next_interval = Self::jitter_interval(Self::base_interval(self.rate_pps));
            return false;
        }
        if now.duration_since(self.last_chaff) >= self.next_interval {
            self.last_chaff = now;
            // Draw a fresh jittered interval for the next tick.
            self.next_interval = Self::jitter_interval(Self::base_interval(self.rate_pps));
            true
        } else {
            false
        }
    }

    /// Record that a real packet was sent at `now`. Resets the idle/chaff clock so
    /// chaff is deferred for one interval after real activity.
    pub fn record_real_traffic(&mut self, now: std::time::Instant) {
        self.last_real_traffic = now;
        self.last_chaff = now;
        self.next_interval = Self::jitter_interval(Self::base_interval(self.rate_pps));
    }

    /// Generate the chaff packet **plaintext** (frames payload, before AEAD).
    ///
    /// The plaintext is `target_plaintext_len` bytes long and consists of:
    /// - one PING frame (a single `0x01` byte) when `ack_eliciting` is true, else
    ///   nothing,
    /// - followed by PADDING frames (zero bytes) filling the remainder.
    ///
    /// The caller seals this plaintext into a 1-RTT short-header packet using the
    /// same keys, header, and packet-number space as real traffic, making the
    /// resulting ciphertext indistinguishable from a real packet.
    ///
    /// `target_plaintext_len` should be `chaff_size_bytes - header_len - tag_len`,
    /// computed by the caller. If `target_plaintext_len` is too small to hold the
    /// PING frame, the PING is omitted and the whole plaintext is padding.
    pub fn generate_chaff(&self, target_plaintext_len: usize) -> Vec<u8> {
        // Every byte in the plaintext region is a PADDING frame (0x00).
        let mut out = vec![CHAFF_PADDING_FRAME_BYTE; target_plaintext_len];
        if target_plaintext_len == 0 {
            return out;
        }
        if self.ack_eliciting && target_plaintext_len >= 1 {
            out[0] = CHAFF_PING_FRAME_BYTE;
            // Remaining bytes stay 0x00 = PADDING frames.
        }
        // When not ack_eliciting, the entire plaintext is PADDING frames (0x00).
        out
    }

    /// Convenience: generate chaff plaintext sized for the configured
    /// `chaff_size_bytes` given the per-packet header and AEAD-tag overhead.
    /// `header_len` is the short-header + PN length; `tag_len` is the AEAD tag
    /// (typically 16 for AES-GCM/ChaCha20-Poly1305).
    pub fn generate_chaff_sized(&self, header_len: usize, tag_len: usize) -> Vec<u8> {
        let target = self.chaff_size_bytes as usize;
        let pt_len = target.saturating_sub(header_len).saturating_sub(tag_len);
        self.generate_chaff(pt_len)
    }

    /// Returns the configured chaff rate in packets per second.
    pub fn rate_pps(&self) -> u32 {
        self.rate_pps
    }

    /// Returns the configured target chaff packet size in bytes.
    pub fn chaff_size_bytes(&self) -> u32 {
        self.chaff_size_bytes
    }

    /// Returns whether chaff packets are ack-eliciting (include a PING frame).
    pub fn ack_eliciting(&self) -> bool {
        self.ack_eliciting
    }

    /// Returns true if chaffing is disabled (rate 0).
    pub fn is_disabled(&self) -> bool {
        self.rate_pps == 0
    }

    /// Build a `tokio::time::Interval` ticking at the jittered chaff cadence.
    ///
    /// The interval starts immediately and ticks every `base_interval` (unjittered);
    /// per-tick jitter is applied by [`should_chaff`](Self::should_chaff) which
    /// independently draws a fresh ±10% factor each emission. This gives callers a
    /// simple timer-driven injection loop:
    ///
    /// ```ignore
    /// let mut interval = chaff.chaff_tokio_interval();
    /// loop {
    ///     interval.tick().await;
    ///     if chaff.should_chaff(Instant::now(), false) {
    ///         let pt = chaff.generate_chaff_sized(hdr, tag);
    ///         // ... seal and send as a 1-RTT packet ...
    ///     }
    /// }
    /// ```
    pub fn chaff_tokio_interval(&self) -> tokio::time::Interval {
        let base = Self::base_interval(self.rate_pps);
        tokio::time::interval(if base.is_zero() {
            std::time::Duration::from_secs(3600)
        } else {
            base
        })
    }
}

impl std::fmt::Debug for ChaffGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChaffGenerator")
            .field("rate_pps", &self.rate_pps)
            .field("chaff_size_bytes", &self.chaff_size_bytes)
            .field("ack_eliciting", &self.ack_eliciting)
            .field("next_interval", &self.next_interval)
            .finish()
    }
}
