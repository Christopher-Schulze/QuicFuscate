// --- 9b. Chaff (Dummy Packet) Generator (TODO-455) ---

/// QUIC PING frame type byte (RFC 9000 §19.2). A single varint 0x01 with no payload.
const CHAFF_PING_FRAME_BYTE: u8 = 0x01;
/// QUIC PADDING frame byte (RFC 9000 §19.1). Each zero byte in the plaintext is a
/// distinct PADDING frame, so a run of N zero bytes encodes N PADDING frames.
const CHAFF_PADDING_FRAME_BYTE: u8 = 0x00;

/// Traffic-analysis scheduler phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficAnalysisPhase {
    /// Full configured cadence while recent real traffic keeps the defense active.
    Active,
    /// Cadence is progressively reduced after the idle soft-stop boundary.
    RampDown,
    /// No timer is armed until real traffic reactivates the scheduler.
    Stopped,
    /// Terminal connection shutdown permanently disarmed the scheduler.
    Cancelled,
}

/// Owns traffic-analysis deadlines and the single bounded chaff pending slot.
///
/// A chaff packet is a **real** QUIC 1-RTT packet: it is encrypted with the same
/// 1-RTT keys, uses the same short-header format, carries a PING frame (so the peer
/// ACKs it, producing bidirectional cover traffic) followed by PADDING frames to
/// reach the target size. To an outside observer it is indistinguishable from a
/// real data packet of the same size.
///
/// Idle chaff uses independent ±10% interval jitter. Constant-rate defense uses an
/// exact interval so its idle wire cadence is deterministic and capture-verifiable.
/// Missed deadlines never create catch-up bursts: at most one pending slot exists.
pub struct TrafficAnalysisScheduler {
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
    /// Whether this is fixed-cadence constant-rate defense rather than idle chaff.
    constant_rate: bool,
    /// Time of the last real-traffic send. Drives soft-stop and reactivation.
    last_real_traffic: std::time::Instant,
    /// Full-rate window before ramp-down starts.
    idle_timeout: std::time::Duration,
    /// Duration over which the interval expands before the scheduler stops.
    ramp_down: std::time::Duration,
    /// Interval selected for the next deadline.
    next_interval: std::time::Duration,
    /// One transport-owned timer deadline.
    next_deadline: Option<std::time::Instant>,
    /// Bounded queue: false or one due chaff packet, never more.
    pending: bool,
    phase: TrafficAnalysisPhase,
}

impl TrafficAnalysisScheduler {
    /// Default full-rate idle window.
    pub const DEFAULT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    /// Default gradual soft-stop window.
    pub const DEFAULT_RAMP_DOWN: std::time::Duration = std::time::Duration::from_secs(5);

    /// Creates a new chaff generator.
    ///
    /// - `rate_pps`: target packets per second (0 disables; `should_chaff` always
    ///   returns false).
    /// - `chaff_size_bytes`: target total packet size in bytes.
    /// - `ack_eliciting`: include a PING frame so the peer ACKs the chaff.
    pub fn new(rate_pps: u32, chaff_size_bytes: u32, ack_eliciting: bool) -> Self {
        Self::with_lifecycle(
            rate_pps,
            chaff_size_bytes,
            ack_eliciting,
            false,
            Self::DEFAULT_IDLE_TIMEOUT,
            Self::DEFAULT_RAMP_DOWN,
        )
    }

    /// Creates a lifecycle-owned scheduler with explicit cadence and soft-stop bounds.
    pub fn with_lifecycle(
        rate_pps: u32,
        chaff_size_bytes: u32,
        ack_eliciting: bool,
        constant_rate: bool,
        idle_timeout: std::time::Duration,
        ramp_down: std::time::Duration,
    ) -> Self {
        let now = std::time::Instant::now();
        let base = Self::base_interval(rate_pps);
        let next_interval =
            if constant_rate { base } else { Self::jitter_interval(base) };
        let phase =
            if rate_pps == 0 { TrafficAnalysisPhase::Stopped } else { TrafficAnalysisPhase::Active };
        Self {
            rate_pps,
            chaff_size_bytes,
            ack_eliciting,
            constant_rate,
            last_real_traffic: now,
            idle_timeout,
            ramp_down,
            next_interval,
            next_deadline: (rate_pps > 0).then_some(now + next_interval),
            pending: false,
            phase,
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

    /// Returns the currently armed transport deadline.
    pub fn next_deadline(&self) -> Option<std::time::Instant> {
        self.next_deadline
    }

    /// Returns the current lifecycle phase.
    pub fn phase(&self) -> TrafficAnalysisPhase {
        self.phase
    }

    /// Returns whether the single bounded chaff slot is due.
    pub fn has_pending_chaff(&self) -> bool {
        self.pending
    }

    fn base_or_jittered_interval(&self) -> std::time::Duration {
        let base = Self::base_interval(self.rate_pps);
        if self.constant_rate {
            base
        } else {
            Self::jitter_interval(base)
        }
    }

    fn phase_locked_deadline(
        deadline: std::time::Instant,
        now: std::time::Instant,
        interval: std::time::Duration,
    ) -> std::time::Instant {
        let interval_ns = interval.as_nanos().max(1);
        let elapsed_ns = now.saturating_duration_since(deadline).as_nanos();
        let intervals = elapsed_ns / interval_ns + 1;
        let advance_ns = interval_ns.saturating_mul(intervals).min(u64::MAX as u128) as u64;
        deadline
            .checked_add(std::time::Duration::from_nanos(advance_ns))
            .unwrap_or_else(|| now + interval)
    }

    fn cadence_for(&self, now: std::time::Instant) -> Option<(TrafficAnalysisPhase, std::time::Duration)> {
        if self.rate_pps == 0 || self.phase == TrafficAnalysisPhase::Cancelled {
            return None;
        }
        let idle = now.saturating_duration_since(self.last_real_traffic);
        if idle < self.idle_timeout || self.ramp_down.is_zero() {
            return (idle < self.idle_timeout)
                .then(|| (TrafficAnalysisPhase::Active, self.base_or_jittered_interval()));
        }
        let ramp_elapsed = idle.saturating_sub(self.idle_timeout);
        if ramp_elapsed >= self.ramp_down {
            return None;
        }

        // Expand the interval smoothly from 1x to at most 16x. Integer math
        // keeps the state machine deterministic and avoids floating-point drift.
        let ramp_ns = self.ramp_down.as_nanos().max(1);
        let elapsed_ns = ramp_elapsed.as_nanos().min(ramp_ns);
        let multiplier = 1u128 + elapsed_ns.saturating_mul(15) / ramp_ns;
        let base_ns = self.base_or_jittered_interval().as_nanos();
        let interval_ns = base_ns.saturating_mul(multiplier).min(u64::MAX as u128) as u64;
        Some((
            TrafficAnalysisPhase::RampDown,
            std::time::Duration::from_nanos(interval_ns.max(1)),
        ))
    }

    /// Advances the lifecycle timer and fills at most one pending chaff slot.
    ///
    /// Callers invoke this only when the connection wakeup deadline expires.
    /// Congestion deferral leaves the pending slot intact and never accumulates
    /// additional packets or catch-up debt.
    pub fn on_timer(&mut self, now: std::time::Instant) {
        if self.phase == TrafficAnalysisPhase::Cancelled {
            return;
        }
        let Some(deadline) = self.next_deadline else {
            return;
        };
        if now < deadline {
            return;
        }
        let Some((phase, interval)) = self.cadence_for(now) else {
            self.phase = TrafficAnalysisPhase::Stopped;
            self.next_deadline = None;
            self.pending = false;
            return;
        };
        self.phase = phase;
        self.pending = true;
        self.next_interval = interval;
        self.next_deadline = Some(if self.constant_rate {
            Self::phase_locked_deadline(deadline, now, interval)
        } else {
            now + interval
        });
    }

    /// Marks the pending chaff slot successfully sealed and emitted.
    pub fn record_chaff_emitted(&mut self) {
        self.pending = false;
    }

    /// Records a non-chaff packet that can cover a due cadence slot.
    ///
    /// ACK, control, recovery, and PMTU packets consume a pending slot without
    /// extending the real-traffic idle window. Application STREAM or DATAGRAM
    /// traffic additionally reactivates the lifecycle and rebases an otherwise
    /// idle deadline.
    pub fn record_cover_packet(&mut self, now: std::time::Instant, has_real_traffic: bool) {
        if self.phase == TrafficAnalysisPhase::Cancelled {
            return;
        }
        self.pending = false;
        if !has_real_traffic {
            return;
        }

        self.last_real_traffic = now;
        if self.rate_pps == 0 {
            self.phase = TrafficAnalysisPhase::Stopped;
            self.next_deadline = None;
            return;
        }
        self.phase = TrafficAnalysisPhase::Active;
        self.next_interval = self.base_or_jittered_interval();
        self.next_deadline = Some(now + self.next_interval);
    }

    /// Returns true if a chaff packet should be emitted at `now`.
    ///
    /// Returns false when the generator is disabled (`rate_pps == 0`). When real
    /// traffic was sent within the current interval, chaff is suppressed to avoid
    /// colliding with a real packet (the real packet already "covers" the slot).
    pub fn should_chaff(&mut self, now: std::time::Instant, has_real_traffic: bool) -> bool {
        if has_real_traffic {
            self.record_real_traffic(now);
            return false;
        }
        self.on_timer(now);
        if self.pending {
            self.record_chaff_emitted();
            return true;
        }
        false
    }

    /// Record that a real packet was sent at `now`. Resets the idle/chaff clock so
    /// chaff is deferred for one interval after real activity.
    pub fn record_real_traffic(&mut self, now: std::time::Instant) {
        self.record_cover_packet(now, true);
    }

    /// Permanently disarms deadlines and clears the pending slot.
    pub fn cancel(&mut self) {
        self.pending = false;
        self.next_deadline = None;
        self.phase = TrafficAnalysisPhase::Cancelled;
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
}

impl std::fmt::Debug for TrafficAnalysisScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChaffGenerator/TrafficAnalysisScheduler")
            .field("rate_pps", &self.rate_pps)
            .field("chaff_size_bytes", &self.chaff_size_bytes)
            .field("ack_eliciting", &self.ack_eliciting)
            .field("constant_rate", &self.constant_rate)
            .field("next_interval", &self.next_interval)
            .field("next_deadline", &self.next_deadline)
            .field("pending", &self.pending)
            .field("phase", &self.phase)
            .finish()
    }
}

/// Backward-compatible name for callers that only generate chaff plaintext.
pub type ChaffGenerator = TrafficAnalysisScheduler;

#[cfg(test)]
mod traffic_analysis_scheduler_tests {
    use super::{TrafficAnalysisPhase, TrafficAnalysisScheduler};
    use std::time::{Duration, Instant};

    #[test]
    fn constant_rate_owns_one_pending_slot_without_catch_up() {
        let mut scheduler = TrafficAnalysisScheduler::with_lifecycle(
            100,
            1280,
            true,
            true,
            Duration::from_secs(30),
            Duration::from_secs(5),
        );
        let first = scheduler.next_deadline().expect("deadline");
        scheduler.on_timer(first + Duration::from_secs(1));
        assert!(scheduler.has_pending_chaff());
        let advanced = scheduler.next_deadline().expect("advanced deadline");
        assert_eq!(advanced, first + Duration::from_secs(1) + Duration::from_millis(10));

        scheduler.on_timer(advanced + Duration::from_secs(1));
        assert!(scheduler.has_pending_chaff(), "pending queue must remain bounded to one slot");
        scheduler.record_chaff_emitted();
        assert!(!scheduler.has_pending_chaff());
    }

    #[test]
    fn constant_rate_cadence_is_exact_across_ten_seconds() {
        let mut scheduler = TrafficAnalysisScheduler::with_lifecycle(
            100,
            1280,
            true,
            true,
            Duration::from_secs(30),
            Duration::from_secs(5),
        );
        let start = scheduler.next_deadline().expect("deadline");
        let mut deadline = start;

        for _ in 0..1_000 {
            scheduler.on_timer(deadline);
            assert!(scheduler.has_pending_chaff());
            scheduler.record_chaff_emitted();
            let next = scheduler.next_deadline().expect("next deadline");
            assert_eq!(next.duration_since(deadline), Duration::from_millis(10));
            deadline = next;
        }

        assert_eq!(deadline.duration_since(start), Duration::from_secs(10));
    }

    #[test]
    fn constant_rate_lateness_does_not_accumulate_or_create_catch_up() {
        let mut scheduler = TrafficAnalysisScheduler::with_lifecycle(
            100,
            1280,
            true,
            true,
            Duration::from_secs(30),
            Duration::from_secs(5),
        );
        let first = scheduler.next_deadline().expect("deadline");
        scheduler.on_timer(first + Duration::from_millis(3));
        assert!(scheduler.has_pending_chaff());
        assert_eq!(scheduler.next_deadline(), Some(first + Duration::from_millis(10)));
        scheduler.record_chaff_emitted();

        scheduler.on_timer(first + Duration::from_millis(27));
        assert!(scheduler.has_pending_chaff());
        assert_eq!(scheduler.next_deadline(), Some(first + Duration::from_millis(30)));
    }

    #[test]
    fn idle_chaff_jitter_stays_bounded_across_ten_seconds() {
        let mut scheduler = TrafficAnalysisScheduler::with_lifecycle(
            10,
            1280,
            true,
            false,
            Duration::from_secs(30),
            Duration::from_secs(5),
        );
        let start = scheduler.next_deadline().expect("deadline");
        let mut deadline = start;
        let end = start + Duration::from_secs(10);
        let mut emitted = 0;

        while deadline < end {
            scheduler.on_timer(deadline);
            assert!(scheduler.has_pending_chaff());
            scheduler.record_chaff_emitted();
            let next = scheduler.next_deadline().expect("next deadline");
            let interval = next.duration_since(deadline);
            assert!(
                (Duration::from_millis(90)..=Duration::from_millis(110)).contains(&interval)
            );
            emitted += 1;
            deadline = next;
        }

        assert!((90..=112).contains(&emitted), "unexpected 10-second count: {emitted}");
    }

    #[test]
    fn soft_stop_ramps_down_then_real_traffic_reactivates() {
        let mut scheduler = TrafficAnalysisScheduler::with_lifecycle(
            10,
            1280,
            true,
            true,
            Duration::from_secs(1),
            Duration::from_millis(500),
        );
        let start = scheduler.last_real_traffic;
        scheduler.on_timer(start + Duration::from_millis(1100));
        assert_eq!(scheduler.phase(), TrafficAnalysisPhase::RampDown);
        scheduler.record_chaff_emitted();

        scheduler.on_timer(start + Duration::from_millis(1600));
        assert_eq!(scheduler.phase(), TrafficAnalysisPhase::Stopped);
        assert!(scheduler.next_deadline().is_none());

        let resumed = start + Duration::from_secs(2);
        scheduler.record_real_traffic(resumed);
        assert_eq!(scheduler.phase(), TrafficAnalysisPhase::Active);
        assert_eq!(scheduler.next_deadline(), Some(resumed + Duration::from_millis(100)));
    }

    #[test]
    fn ack_cover_consumes_due_slot_without_extending_idle_lifecycle() {
        let mut scheduler = TrafficAnalysisScheduler::with_lifecycle(
            10,
            1280,
            true,
            true,
            Duration::from_secs(1),
            Duration::from_millis(500),
        );
        let start = scheduler.last_real_traffic;
        let due = scheduler.next_deadline().expect("deadline");
        scheduler.on_timer(due);
        assert!(scheduler.has_pending_chaff());

        scheduler.record_cover_packet(due, false);
        assert!(!scheduler.has_pending_chaff());
        scheduler.on_timer(start + Duration::from_millis(1600));

        assert_eq!(scheduler.phase(), TrafficAnalysisPhase::Stopped);
        assert!(scheduler.next_deadline().is_none());
    }

    #[test]
    fn cancellation_is_terminal() {
        let mut scheduler = TrafficAnalysisScheduler::new(10, 1280, true);
        scheduler.cancel();
        assert_eq!(scheduler.phase(), TrafficAnalysisPhase::Cancelled);
        assert!(scheduler.next_deadline().is_none());
        scheduler.record_real_traffic(Instant::now());
        assert_eq!(scheduler.phase(), TrafficAnalysisPhase::Cancelled);
    }
}
