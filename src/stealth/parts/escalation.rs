// =============================================================================
// Gradual Stealth Escalation State (TODO-416)
// =============================================================================

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
    /// Sliding window of probe detection timestamps (epoch millis).
    probe_timestamps: Mutex<VecDeque<u64>>,
    /// Time of the last probe detection (epoch millis, 0 = none).
    last_probe_detection_time: AtomicU64,
    /// Time of the last level change (epoch millis, 0 = none).
    last_level_change_time: AtomicU64,
    /// Connection-local level state shared with the Brain.
    level_hints: Arc<crate::brain::IntelligentLevelHints>,
    /// Threshold for L0→L1 escalation (default: 3 probes in 60s).
    threshold_l1: u32,
    /// Threshold for L1→L2 escalation (default: 8 probes in 120s).
    threshold_l2: u32,
    /// Quiet period before de-escalation (default: 300 seconds).
    quiet_period_secs: u64,
}

impl EscalationState {
    fn new(level_hints: Arc<crate::brain::IntelligentLevelHints>) -> Self {
        let threshold_l1 = crate::env_utils::env_parse::<u32>(
            "QUICFUSCATE_STEALTH_ESCALATION_PROBE_THRESHOLD_L1",
        )
        .unwrap_or(3)
        .max(1);
        let threshold_l2 = crate::env_utils::env_parse::<u32>(
            "QUICFUSCATE_STEALTH_ESCALATION_PROBE_THRESHOLD_L2",
        )
        .unwrap_or(8)
        .max(threshold_l1);
        Self {
            current_level: AtomicU8::new(0),
            probe_timestamps: Mutex::new(VecDeque::with_capacity(32)),
            last_probe_detection_time: AtomicU64::new(0),
            last_level_change_time: AtomicU64::new(0),
            level_hints,
            threshold_l1,
            threshold_l2,
            quiet_period_secs: crate::env_utils::env_parse::<u64>(
                "QUICFUSCATE_STEALTH_DEESCALATION_QUIET_PERIOD_SEC",
            )
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

        let mut timestamps = self.probe_timestamps.lock().unwrap_or_else(|p| p.into_inner());
        timestamps.push_back(now);

        // Prune entries older than 120 seconds (the L2 window).
        let cutoff_120s = now.saturating_sub(120_000);
        while let Some(&front) = timestamps.front() {
            if front < cutoff_120s {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        let count_120s = timestamps.len() as u32;
        // Count probes within the 60-second window for L1 threshold.
        let cutoff_60s = now.saturating_sub(60_000);
        let count_60s = timestamps.iter().filter(|&&t| t >= cutoff_60s).count() as u32;

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
        let mut timestamps = self.probe_timestamps.lock().unwrap_or_else(|p| p.into_inner());
        timestamps.clear();
    }

    /// Number of probes in the 60-second window (test-only).
    #[cfg(test)]
    fn probe_count_60s(&self) -> u32 {
        let now = Self::now_millis();
        let cutoff = now.saturating_sub(60_000);
        let timestamps = self.probe_timestamps.lock().unwrap_or_else(|p| p.into_inner());
        timestamps.iter().filter(|&&t| t >= cutoff).count() as u32
    }
}
