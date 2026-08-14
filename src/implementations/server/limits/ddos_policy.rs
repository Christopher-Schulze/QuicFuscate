use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::time_source::ProtocolClock;

/// Default EWMA smoothing factor (α). Higher α reacts faster to changes.
pub const DEFAULT_EWMA_ALPHA: f64 = 0.1;
/// Default spike multiplier: current rate must exceed 3× the EWMA.
pub const DEFAULT_SPIKE_MULTIPLIER: f64 = 3.0;

/// Validated sustained-anomaly and enhanced-admission policy.
#[derive(Clone, Debug, PartialEq)]
pub struct DdosPolicyConfig {
    pub enabled: bool,
    pub sample_interval: Duration,
    pub activation_window: Duration,
    pub clear_window: Duration,
    pub ewma_alpha: f64,
    pub spike_multiplier: f64,
    pub clear_factor: f64,
    pub enhanced_packet_cost: u64,
    pub retry_enabled: bool,
    pub retry_token_lifetime: Duration,
}

impl Default for DdosPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_interval: Duration::from_secs(1),
            activation_window: Duration::from_secs(5),
            clear_window: Duration::from_secs(15),
            ewma_alpha: DEFAULT_EWMA_ALPHA,
            spike_multiplier: DEFAULT_SPIKE_MULTIPLIER,
            clear_factor: 1.5,
            enhanced_packet_cost: 2,
            retry_enabled: true,
            retry_token_lifetime: Duration::from_secs(10),
        }
    }
}

impl DdosPolicyConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.sample_interval.is_zero()
            || self.activation_window.is_zero()
            || self.clear_window.is_zero()
            || self.retry_token_lifetime.is_zero()
        {
            return Err(
                "DDoS sample, activation, clear, and Retry-token durations must be greater than zero"
                    .to_string(),
            );
        }
        if !self.ewma_alpha.is_finite() || self.ewma_alpha <= 0.0 || self.ewma_alpha > 1.0 {
            return Err("DDoS EWMA alpha must be finite and within (0, 1]".to_string());
        }
        if !self.spike_multiplier.is_finite() || self.spike_multiplier <= 1.0 {
            return Err("DDoS spike multiplier must be finite and greater than 1".to_string());
        }
        if !self.clear_factor.is_finite()
            || self.clear_factor <= 0.0
            || self.clear_factor >= self.spike_multiplier
        {
            return Err(
                "DDoS clear factor must be finite, greater than zero, and below the spike multiplier"
                    .to_string(),
            );
        }
        if self.enhanced_packet_cost < 2 {
            return Err("DDoS enhanced packet cost must be at least 2".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DdosTransition {
    Unchanged,
    Activated,
    Cleared,
}

#[derive(Debug, Default)]
struct AnomalyTimingState {
    last_now: Duration,
    activation_since: Option<Duration>,
    activation_baseline: f64,
    clear_since: Option<Duration>,
}

/// EWMA-based DDoS/anomaly detector.
#[allow(dead_code)]
pub struct EwmaAnomalyDetector {
    ewma_pps: AtomicU64,
    current_pps: AtomicU64,
    pub(super) anomaly_active: AtomicBool,
    config: DdosPolicyConfig,
    anchor: Instant,
    clock: ProtocolClock,
    timing: parking_lot::Mutex<AnomalyTimingState>,
}

#[allow(dead_code)]
impl EwmaAnomalyDetector {
    /// Create a detector with the given smoothing and spike threshold.
    pub fn new(alpha: f64, spike_multiplier: f64) -> Self {
        Self::new_with_clock(alpha, spike_multiplier, &ProtocolClock::default())
    }

    /// Create a detector bound to an explicit protocol clock.
    #[allow(clippy::expect_used)]
    pub fn new_with_clock(alpha: f64, spike_multiplier: f64, clock: &ProtocolClock) -> Self {
        let config =
            DdosPolicyConfig { ewma_alpha: alpha, spike_multiplier, ..DdosPolicyConfig::default() };
        Self::with_config_and_clock(config, clock)
            .expect("legacy DDoS detector parameters must be valid")
    }

    pub fn with_config(config: DdosPolicyConfig) -> Result<Self, String> {
        Self::with_config_and_clock(config, &ProtocolClock::default())
    }

    pub fn with_config_and_clock(
        config: DdosPolicyConfig,
        clock: &ProtocolClock,
    ) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            ewma_pps: AtomicU64::new(0f64.to_bits()),
            current_pps: AtomicU64::new(0),
            anomaly_active: AtomicBool::new(false),
            config,
            anchor: clock.now(),
            clock: clock.clone(),
            timing: parking_lot::Mutex::new(AnomalyTimingState::default()),
        })
    }

    /// Create a detector with sensible defaults (α=0.1, spike=3×).
    #[allow(clippy::expect_used)]
    pub fn with_defaults() -> Self {
        Self::with_config(DdosPolicyConfig::default()).expect("default DDoS policy must be valid")
    }

    /// Record an observed PPS sample at the detector's monotonic clock.
    pub fn record_pps(&self, pps: u64) -> DdosTransition {
        self.record_pps_at(pps, self.clock.elapsed_since(self.anchor))
    }

    /// Record a deterministic monotonic sample.
    pub fn record_pps_at(&self, pps: u64, now: Duration) -> DdosTransition {
        self.current_pps.store(pps, Ordering::Relaxed);

        let prev_ewma = f64::from_bits(self.ewma_pps.load(Ordering::Relaxed));
        let mut prev_bits = self.ewma_pps.load(Ordering::Relaxed);
        loop {
            let prev = f64::from_bits(prev_bits);
            let next = if prev == 0.0 {
                pps as f64
            } else {
                self.config.ewma_alpha * pps as f64 + (1.0 - self.config.ewma_alpha) * prev
            };
            match self.ewma_pps.compare_exchange(
                prev_bits,
                next.to_bits(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => prev_bits = actual,
            }
        }

        let mut timing = self.timing.lock();
        timing.last_now = timing.last_now.max(now);
        let now = timing.last_now;
        if !self.config.enabled {
            let was_active = self.anomaly_active.swap(false, Ordering::AcqRel);
            timing.activation_since = None;
            timing.clear_since = None;
            timing.activation_baseline = 0.0;
            return if was_active { DdosTransition::Cleared } else { DdosTransition::Unchanged };
        }

        if self.anomaly_active.load(Ordering::Acquire) {
            let clear_threshold = self.config.clear_factor * timing.activation_baseline;
            if pps as f64 <= clear_threshold {
                let clear_since = *timing.clear_since.get_or_insert(now);
                if now.saturating_sub(clear_since) >= self.config.clear_window {
                    self.anomaly_active.store(false, Ordering::Release);
                    timing.activation_since = None;
                    timing.clear_since = None;
                    timing.activation_baseline = 0.0;
                    return DdosTransition::Cleared;
                }
            } else {
                timing.clear_since = None;
            }
            return DdosTransition::Unchanged;
        }

        let baseline =
            if timing.activation_since.is_some() { timing.activation_baseline } else { prev_ewma };
        let spike = baseline > 0.0 && pps as f64 > self.config.spike_multiplier * baseline;
        if !spike {
            timing.activation_since = None;
            timing.activation_baseline = 0.0;
            return DdosTransition::Unchanged;
        }

        if timing.activation_since.is_none() {
            timing.activation_since = Some(now);
            timing.activation_baseline = prev_ewma;
        }
        let activation_since = timing.activation_since.unwrap_or(now);
        if now.saturating_sub(activation_since) >= self.config.activation_window {
            self.anomaly_active.store(true, Ordering::Release);
            timing.clear_since = None;
            return DdosTransition::Activated;
        }
        DdosTransition::Unchanged
    }

    pub fn sample_interval(&self) -> Duration {
        self.config.sample_interval
    }

    pub fn enhanced_packet_cost(&self) -> u64 {
        if self.is_anomaly() {
            self.config.enhanced_packet_cost
        } else {
            1
        }
    }

    pub fn is_anomaly(&self) -> bool {
        self.anomaly_active.load(Ordering::Relaxed)
    }

    pub fn limit_multiplier(&self) -> f64 {
        if self.is_anomaly() {
            0.5
        } else {
            1.0
        }
    }

    pub fn ewma(&self) -> f64 {
        f64::from_bits(self.ewma_pps.load(Ordering::Relaxed))
    }

    pub fn current_pps(&self) -> u64 {
        self.current_pps.load(Ordering::Relaxed)
    }

    pub fn clear(&self) {
        self.anomaly_active.store(false, Ordering::Relaxed);
        let mut timing = self.timing.lock();
        timing.activation_since = None;
        timing.clear_since = None;
        timing.activation_baseline = 0.0;
    }
}
