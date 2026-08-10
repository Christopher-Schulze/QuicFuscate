// =============================================================================
// Gradual Stealth Escalation State (TODO-416)
// =============================================================================

const PROBE_WINDOW_L1_MS: u64 = 60_000;
const PROBE_WINDOW_L2_MS: u64 = 120_000;
const MAX_PROBE_TIMESTAMP_BUCKETS: usize = 120_001;

#[derive(Clone, Copy)]
struct ProbeTimestampBucket {
    timestamp: u64,
    count: u32,
    in_l1_window: bool,
}

struct ProbeHistory {
    buckets: VecDeque<ProbeTimestampBucket>,
    count_60s: u32,
    count_120s: u32,
}

impl ProbeHistory {
    fn new() -> Self {
        Self {
            buckets: VecDeque::with_capacity(32),
            count_60s: 0,
            count_120s: 0,
        }
    }

    fn record(&mut self, now: u64) {
        self.prune(now);

        if let Some(bucket) = self.buckets.back_mut() {
            if bucket.timestamp == now {
                bucket.count = bucket.count.saturating_add(1);
                self.count_60s = self.count_60s.saturating_add(1);
                self.count_120s = self.count_120s.saturating_add(1);
                return;
            }
        }

        if self.buckets.len() >= MAX_PROBE_TIMESTAMP_BUCKETS {
            self.remove_oldest();
        }

        self.buckets.push_back(ProbeTimestampBucket {
            timestamp: now,
            count: 1,
            in_l1_window: true,
        });
        self.count_60s = self.count_60s.saturating_add(1);
        self.count_120s = self.count_120s.saturating_add(1);
    }

    fn prune(&mut self, now: u64) {
        let cutoff_120s = now.saturating_sub(PROBE_WINDOW_L2_MS);
        while let Some(&bucket) = self.buckets.front() {
            if bucket.timestamp < cutoff_120s {
                self.remove_oldest();
            } else {
                break;
            }
        }

        let cutoff_60s = now.saturating_sub(PROBE_WINDOW_L1_MS);
        let mut expired_60s: u32 = 0;
        for bucket in &mut self.buckets {
            if bucket.timestamp >= cutoff_60s {
                break;
            }
            if bucket.in_l1_window {
                expired_60s = expired_60s.saturating_add(bucket.count);
                bucket.in_l1_window = false;
            }
        }
        self.count_60s = self.count_60s.saturating_sub(expired_60s);
    }

    fn remove_oldest(&mut self) {
        if let Some(bucket) = self.buckets.pop_front() {
            self.count_120s = self.count_120s.saturating_sub(bucket.count);
            if bucket.in_l1_window {
                self.count_60s = self.count_60s.saturating_sub(bucket.count);
            }
        }
    }

    #[cfg(test)]
    fn clear(&mut self) {
        self.buckets.clear();
        self.count_60s = 0;
        self.count_120s = 0;
    }
}

/// Probe-count-based escalation state machine for Intelligent stealth mode.
///
/// Tracks probe detection timestamps in a sliding window and escalates/de-escalates
/// the stealth level based on configurable thresholds:
/// - Level 0 → 1: requires ≥ `threshold_l1` probes within 60 seconds.
/// - Level 1 → 2: requires ≥ `threshold_l2` probes within 120 seconds.
/// - De-escalation: after `quiet_period_secs` with zero probe detections.
///
/// This complements the brain's pressure-based hysteresis by providing
/// probe-count-driven escalation that matches the TODO-416 acceptance criteria.
struct EscalationState {
    /// Current escalation level (0=Performance, 1=Stealth, 2=AntiDpi).
    current_level: AtomicU8,
    /// Bounded millisecond buckets for the independent 60/120-second windows.
    probe_timestamps: Mutex<ProbeHistory>,
    /// Time of the last probe detection (epoch millis, 0 = none).
    last_probe_detection_time: AtomicU64,
    /// Time of the last level change (epoch millis, 0 = none).
    last_level_change_time: AtomicU64,
    /// Connection-local level state shared with the Brain.
    level_hints: Arc<qf_transport_types::IntelligentLevelHints>,
    /// Threshold for L0→L1 escalation (default: 3 probes in 60s).
    threshold_l1: u32,
    /// Threshold for L1→L2 escalation (default: 8 probes in 120s).
    threshold_l2: u32,
    /// Quiet period before de-escalation (default: 300 seconds).
    quiet_period_secs: u64,
}

impl EscalationState {
    fn new(
        level_hints: Arc<qf_transport_types::IntelligentLevelHints>,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Self {
        let threshold_l1 = environment
            .parse::<u32>("QUICFUSCATE_STEALTH_ESCALATION_PROBE_THRESHOLD_L1")
            .unwrap_or(3)
            .max(1);
        let threshold_l2 = environment
            .parse::<u32>("QUICFUSCATE_STEALTH_ESCALATION_PROBE_THRESHOLD_L2")
            .unwrap_or(8)
            .max(threshold_l1);
        Self {
            current_level: AtomicU8::new(0),
            probe_timestamps: Mutex::new(ProbeHistory::new()),
            last_probe_detection_time: AtomicU64::new(0),
            last_level_change_time: AtomicU64::new(0),
            level_hints,
            threshold_l1,
            threshold_l2,
            quiet_period_secs: environment
                .parse::<u64>("QUICFUSCATE_STEALTH_DEESCALATION_QUIET_PERIOD_SEC")
                .unwrap_or(300),
        }
    }

    #[inline]
    fn now_millis() -> u64 {
        crate::time_source::now_system()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Current escalation level.
    fn current_level(&self) -> u8 {
        self.current_level.load(Ordering::Relaxed)
    }

    /// Record a probe detection and check if escalation thresholds are met.
    /// Returns the new level if escalation occurred, None if no change.
    fn record_probe(&self) -> Option<u8> {
        let now = Self::now_millis();
        self.last_probe_detection_time.store(now, Ordering::Relaxed);

        let mut history = self.probe_timestamps.lock().unwrap_or_else(|p| p.into_inner());
        history.record(now);

        let count_120s = history.count_120s;
        let count_60s = history.count_60s;

        let current = self.current_level.load(Ordering::Relaxed);
        let new_level = match current {
            0 if count_60s >= self.threshold_l1 => 1u8,
            1 if count_120s >= self.threshold_l2 => 2u8,
            _ => return None,
        };

        if new_level > current {
            self.current_level.store(new_level, Ordering::Relaxed);
            self.last_level_change_time.store(now, Ordering::Relaxed);
            self.level_hints.set_probe_level(new_level);
            return Some(new_level);
        }
        None
    }

    /// Check if the quiet period has elapsed and de-escalate if so.
    /// Returns the new level if de-escalation occurred, None if no change.
    fn check_de_escalation(&self) -> Option<u8> {
        let current = self.current_level.load(Ordering::Relaxed);
        if current == 0 {
            return None;
        }

        let last_probe = self.last_probe_detection_time.load(Ordering::Relaxed);
        if last_probe == 0 {
            return None;
        }

        let last_level_change = self.last_level_change_time.load(Ordering::Relaxed);
        let quiet_reference = last_probe.max(last_level_change);
        let now = Self::now_millis();
        let quiet_ms = self.quiet_period_secs.saturating_mul(1000);
        if now.saturating_sub(quiet_reference) < quiet_ms {
            return None;
        }

        // Quiet period elapsed — de-escalate by one level.
        let new_level = current - 1;
        self.current_level.store(new_level, Ordering::Relaxed);
        // Keep the actual probe timestamp intact. The next check should measure
        // quiet time from the last real probe, not from the previous level drop.
        self.last_level_change_time.store(now, Ordering::Relaxed);
        self.level_hints.set_probe_level(new_level);
        Some(new_level)
    }

    /// Force-set the level (used by explicit mode transitions).
    #[allow(dead_code)]
    fn set_level(&self, level: u8) {
        self.current_level.store(level, Ordering::Relaxed);
        self.level_hints.set_probe_level(level);
    }

    /// Reset to level 0 and clear probe history (test-only).
    #[cfg(test)]
    fn reset(&self) {
        self.current_level.store(0, Ordering::Relaxed);
        self.last_probe_detection_time.store(0, Ordering::Relaxed);
        self.last_level_change_time.store(0, Ordering::Relaxed);
        self.level_hints.set_probe_level(0);
        let mut history = self.probe_timestamps.lock().unwrap_or_else(|p| p.into_inner());
        history.clear();
    }

    /// Number of probes in the 60-second window (test-only).
    #[cfg(test)]
    fn probe_count_60s(&self) -> u32 {
        let now = Self::now_millis();
        let mut history = self.probe_timestamps.lock().unwrap_or_else(|p| p.into_inner());
        history.prune(now);
        history.count_60s
    }
}

#[cfg(test)]
mod escalation_history_tests {
    use super::{ProbeHistory, MAX_PROBE_TIMESTAMP_BUCKETS};

    #[test]
    fn same_millisecond_probes_share_one_bucket_and_preserve_count() {
        let mut history = ProbeHistory::new();

        for _ in 0..1024 {
            history.record(10_000);
        }

        assert_eq!(history.buckets.len(), 1);
        assert_eq!(history.buckets.front().expect("probe bucket").count, 1024);
        assert_eq!(history.count_60s, 1024);
        assert_eq!(history.count_120s, 1024);
    }

    #[test]
    fn timestamp_bucket_storage_has_a_fixed_hard_bound() {
        let mut history = ProbeHistory::new();

        for timestamp in 0..(MAX_PROBE_TIMESTAMP_BUCKETS as u64 + 256) {
            history.record(timestamp);
            assert!(history.buckets.len() <= MAX_PROBE_TIMESTAMP_BUCKETS);
        }

        assert_eq!(history.buckets.len(), MAX_PROBE_TIMESTAMP_BUCKETS);
    }

    #[test]
    fn l1_and_l2_counts_expire_at_their_independent_boundaries() {
        let mut history = ProbeHistory::new();
        let now = 200_000;

        history.record(now - 60_001);
        history.record(now - 59_999);
        history.record(now);

        assert_eq!(history.count_60s, 2);
        assert_eq!(history.count_120s, 3);
    }
}
