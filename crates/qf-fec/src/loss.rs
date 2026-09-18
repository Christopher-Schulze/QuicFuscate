//! Connection-local loss smoothing and burst classification.

use crate::kalman::KalmanFilter;
use crate::target::FOUNTAIN_LOSS_THRESHOLD;
use std::collections::VecDeque;

const FOUNTAIN_MIN_RECENT_OBSERVATIONS: u64 = 32;
/// Consecutive qualifying reports required before the fountain rescue tier may
/// engage. A single lossy batch (e.g. in-flight packets declared lost after a
/// settle gap) must not escalate on its own.
const FOUNTAIN_SUSTAINED_REPORTS: u32 = 3;

/// Bounded EMA, burst-window, Kalman, and change-point loss estimator.
#[doc(hidden)]
pub struct LossEstimator {
    ema_loss_rate: f32,
    lambda: f32,
    burst_window: VecDeque<bool>,
    burst_capacity: usize,
    kalman: Option<KalmanFilter>,
    total_seen: u64,
    total_lost: u64,
    auto_tune: bool,
    mean: f32,
    m2: f32,
    count: u64,
    cusum_pos: f32,
    cusum_neg: f32,
    cusum_thresh: f32,
    stable_ctr: u32,
    base_lambda: f32,
    clean_streak: u32,
    fountain_streak: u32,
    projected_carry: f32,
}

impl LossEstimator {
    /// Create with bounded defaults.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn new() -> Self {
        Self::from_parameters(0.2, 128, false, 0.01, 0.1)
    }

    /// Create from validated product-policy values and ambient Kalman overrides.
    #[doc(hidden)]
    pub fn from_parameters(
        lambda: f32,
        burst_capacity: usize,
        kalman_enabled: bool,
        kalman_q: f32,
        kalman_r: f32,
    ) -> Self {
        let kalman = kalman_enabled.then(|| KalmanFilter::new(kalman_q, kalman_r));
        Self {
            ema_loss_rate: 0.0,
            lambda,
            burst_window: VecDeque::with_capacity(burst_capacity),
            burst_capacity,
            kalman,
            total_seen: 0,
            total_lost: 0,
            auto_tune: true,
            mean: 0.0,
            m2: 0.0,
            count: 0,
            cusum_pos: 0.0,
            cusum_neg: 0.0,
            cusum_thresh: 0.05,
            stable_ctr: 0,
            base_lambda: lambda,
            clean_streak: 0,
            fountain_streak: 0,
            projected_carry: 0.0,
        }
    }

    /// Report aggregate observation (lost of total).
    pub fn report(&mut self, lost: usize, total: usize) {
        if total == 0 {
            return;
        }
        let bounded_lost = lost.min(total);
        let loss_now = bounded_lost as f32 / total as f32;
        self.report_rate(loss_now, total, bounded_lost);
        self.report_actual_observation(total.saturating_sub(bounded_lost), bounded_lost);
    }

    /// Report actual ACK/loss evidence, preserving clean-link proof semantics.
    #[doc(hidden)]
    pub fn report_actual_observation(&mut self, acknowledged: usize, lost: usize) {
        if lost > 0 {
            self.clean_streak = 0;
        } else if acknowledged > 0 {
            self.clean_streak =
                self.clean_streak.saturating_add(acknowledged.min(u32::MAX as usize) as u32);
            if self.clean_streak >= 32 {
                self.burst_window.clear();
            }
        }
    }

    /// Report a pre-smoothed loss signal with its observation weight.
    #[doc(hidden)]
    pub fn report_smoothed_rate(&mut self, loss_rate: f32, observation_weight: usize) {
        if observation_weight == 0 {
            return;
        }
        let loss_rate = if loss_rate.is_finite() { loss_rate.clamp(0.0, 1.0) } else { 0.0 };
        let estimated_lost = (loss_rate * observation_weight as f32).round() as usize;
        self.report_rate(loss_rate, observation_weight, estimated_lost);
    }

    fn report_rate(&mut self, mut loss_now: f32, total: usize, lost: usize) {
        if let Some(kalman) = self.kalman.as_mut() {
            loss_now = kalman.update(loss_now);
        }
        self.count += 1;
        let delta = loss_now - self.mean;
        self.mean += delta / self.count as f32;
        let delta2 = loss_now - self.mean;
        self.m2 += delta * delta2;
        let variance = if self.count > 1 { self.m2 / (self.count - 1) as f32 } else { 0.0 };
        let k_cusum = (variance.sqrt() * 0.5).clamp(0.005, 0.1);
        self.cusum_pos = (self.cusum_pos + (loss_now - self.mean) - k_cusum).max(0.0);
        self.cusum_neg = (self.cusum_neg - (loss_now - self.mean) - k_cusum).max(0.0);
        let change_detected =
            self.cusum_pos > self.cusum_thresh || self.cusum_neg > self.cusum_thresh;
        if self.auto_tune {
            if change_detected {
                self.lambda = 0.85f32.max(self.lambda);
                if let Some(kalman) = self.kalman.as_mut() {
                    kalman.scale_process_noise(1.5, 1e-6, 0.25);
                }
                self.cusum_pos = 0.0;
                self.cusum_neg = 0.0;
                self.stable_ctr = 0;
                self.mean = loss_now;
                self.m2 = 0.0;
                self.count = 1;
            } else {
                self.stable_ctr = self.stable_ctr.saturating_add(1);
                if self.stable_ctr > 128 {
                    self.lambda = (self.lambda * 0.9 + self.base_lambda * 0.1).clamp(0.05, 0.85);
                    if let Some(kalman) = self.kalman.as_mut() {
                        kalman.scale_process_noise(0.9, 1e-8, 0.1);
                    }
                    self.stable_ctr = 0;
                }
            }
        }
        self.ema_loss_rate = self.lambda * loss_now + (1.0 - self.lambda) * self.ema_loss_rate;
        self.total_seen = self.total_seen.saturating_add(total as u64);
        self.total_lost = self.total_lost.saturating_add(lost as u64);
        // A single report may project at most an eighth of the recent window:
        // the loss rate carried here is a smoothed sample, so recent evidence
        // must accumulate across reports instead of being flooded by one batch.
        // The fractional carry keeps small slot counts unbiased (25% of 2 slots
        // must average to one lost slot every other report, not 50% per report).
        let sample_slots = total.min((self.burst_capacity / 8).max(1)).max(1);
        let projected = self.projected_carry + sample_slots as f32 * loss_now;
        let projected_loss_slots = projected.min(sample_slots as f32) as usize;
        self.projected_carry =
            (projected - projected_loss_slots as f32).clamp(0.0, sample_slots as f32);
        for index in 0..sample_slots {
            if self.burst_window.len() == self.burst_capacity {
                self.burst_window.pop_front();
            }
            self.burst_window.push_back(index < projected_loss_slots);
        }
        if self.ema_loss_rate >= FOUNTAIN_LOSS_THRESHOLD
            && self.recent_loss_rate() >= FOUNTAIN_LOSS_THRESHOLD
        {
            self.fountain_streak = self.fountain_streak.saturating_add(1);
        } else {
            self.fountain_streak = 0;
        }
    }

    /// Return the conservative smoothed point estimate.
    pub fn smoothed_loss(&self) -> f32 {
        if self.clean_link_confirmed() {
            return 0.0;
        }
        self.ema_loss_rate.max(self.recent_loss_rate())
    }

    fn recent_loss_rate(&self) -> f32 {
        if self.burst_window.is_empty() {
            0.0
        } else {
            let lost = self.burst_window.iter().filter(|&&value| value).count();
            lost as f32 / self.burst_window.len() as f32
        }
    }

    /// Whether the estimator has enough sustained evidence for fountain recovery.
    ///
    /// Requires the qualification condition (EMA and recent loss at or above the
    /// fountain threshold) to hold across several consecutive reports and the
    /// recent window to be saturated — a single lossy batch must never engage
    /// the rescue tier.
    #[doc(hidden)]
    pub fn fountain_ready(&self) -> bool {
        self.fountain_streak >= FOUNTAIN_SUSTAINED_REPORTS
            && self.total_seen >= FOUNTAIN_MIN_RECENT_OBSERVATIONS
            && self.burst_window.len() >= self.burst_capacity
            && self.ema_loss_rate >= FOUNTAIN_LOSS_THRESHOLD
            && self.recent_loss_rate() >= FOUNTAIN_LOSS_THRESHOLD
    }

    /// Whether a significant change or burst was detected recently.
    pub fn disturbance_detected(&self) -> bool {
        if self.clean_link_confirmed() {
            return false;
        }
        self.cusum_pos > self.cusum_thresh
            || self.cusum_neg > self.cusum_thresh
            || self.stable_ctr == 0
    }

    /// Return a normalized burst variance estimate in `[0.0, 1.0]`.
    pub fn burst_variance(&self) -> f32 {
        if self.burst_window.len() < 8 {
            return 0.0;
        }
        let mut runs = Vec::new();
        let mut current_run = 0u32;
        for &lost in &self.burst_window {
            if lost {
                if current_run > 0 {
                    runs.push(current_run);
                }
                current_run = 0;
            } else {
                current_run += 1;
            }
        }
        if runs.is_empty() {
            return 0.0;
        }
        let count = runs.len() as f32;
        let mean = runs.iter().map(|&run| run as f32).sum::<f32>() / count;
        let variance = runs.iter().map(|&run| (run as f32 - mean).powi(2)).sum::<f32>() / count;
        (variance / (mean * mean + 1.0)).min(1.0)
    }

    /// Whether the clean-link proof has been reached.
    #[doc(hidden)]
    pub fn clean_link_confirmed(&self) -> bool {
        self.clean_streak >= 32
    }

    /// Current clean-link ACK streak for operator-facing adaptation diagnostics.
    #[doc(hidden)]
    pub fn clean_streak(&self) -> u32 {
        self.clean_streak
    }
}

#[cfg(any(test, feature = "rust-tests"))]
impl Default for LossEstimator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::LossEstimator;
    use crate::target::FOUNTAIN_LOSS_THRESHOLD;

    /// Production estimator parameters (`FecConfig::product_default`).
    fn prod_estimator() -> LossEstimator {
        LossEstimator::from_parameters(0.15, 16, true, 0.001, 0.01)
    }

    /// A single lossy batch — e.g. in-flight packets declared lost after a
    /// settle gap — must not qualify the fountain rescue tier on its own.
    #[test]
    fn single_loss_batch_does_not_arm_fountain() {
        let mut est = prod_estimator();
        for _ in 0..40 {
            est.report_smoothed_rate(0.0, 4);
            est.report_actual_observation(4, 0);
        }
        assert!(est.clean_link_confirmed());
        // One large lossy batch and its spiked companion rate, then clean flow.
        est.report_actual_observation(0, 8);
        est.report_smoothed_rate(1.0, 8);
        for _ in 0..16 {
            est.report_smoothed_rate(0.0, 4);
            est.report_actual_observation(4, 0);
            assert!(!est.fountain_ready());
        }
    }

    /// Sustained ≥25% loss across multiple reports must engage the rescue tier.
    #[test]
    fn sustained_loss_arms_fountain() {
        let mut est = prod_estimator();
        let mut armed = false;
        for _ in 0..200 {
            est.report_smoothed_rate(0.40, 4);
            est.report_actual_observation(3, 2);
            if est.fountain_ready() {
                armed = true;
                break;
            }
        }
        assert!(armed, "sustained 40% loss must arm the fountain tier");
    }

    /// A long stable era starves Kalman process noise to its floor; once the
    /// link turns clean the innovation path must restore responsiveness so the
    /// estimate cannot stay pinned above the rescue threshold and re-emerge
    /// after an isolated late loss resets the clean-link proof.
    #[test]
    fn frozen_kalman_does_not_reemerge_after_late_loss() {
        let mut est = prod_estimator();
        for _ in 0..20_000 {
            est.report_smoothed_rate(0.40, 2);
            est.report_actual_observation(1, 1);
        }
        for _ in 0..200 {
            est.report_smoothed_rate(0.0, 2);
            est.report_actual_observation(2, 0);
        }
        assert!(est.clean_link_confirmed());
        est.report_actual_observation(0, 1);
        for _ in 0..8 {
            est.report_smoothed_rate(0.0, 2);
            assert!(
                est.smoothed_loss() < FOUNTAIN_LOSS_THRESHOLD,
                "stale estimate must not re-emerge above the rescue threshold"
            );
            assert!(!est.fountain_ready());
        }
    }

    /// The fractional projection carry keeps the bounded per-report slot
    /// injection unbiased: 25% smoothed loss must average to 25% of the
    /// recent window, not quantize up to 50%.
    #[test]
    fn projected_slots_track_fractional_loss() {
        let mut est = prod_estimator();
        for _ in 0..64 {
            est.report_smoothed_rate(0.25, 8);
        }
        let smoothed = est.smoothed_loss();
        assert!(
            (0.15..=0.35).contains(&smoothed),
            "recent window should converge near 25% loss, got {smoothed}"
        );
        assert!(!est.fountain_ready(), "25% boundary loss must not arm fountain");
    }
}
