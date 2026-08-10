//! Adaptive FEC mode and window management.
//!
//! This controller consumes only the shared FEC policy and target contracts.
//! Product-specific packet orchestration remains in the root adapter.

use crate::policy::FecRuntimePolicy;
use crate::target::{
    continuous_fec_target, mode_for_target, target_from_mode, target_rank, FecBackendFamily,
    FecProtectionTarget,
};
use crate::{wire, FecMode};
use qf_common::time_source::now_instant;
use std::collections::VecDeque;
use std::time::Duration;

#[doc(hidden)]
pub struct ModeManager {
    current_mode: FecMode,
    loss_history: VecDeque<f32>,
    window_size: usize,
    window_history: VecDeque<usize>,
    switch_threshold: f32,
    switch_min_up_ms: u64,
    switch_min_down_ms: u64,
    auto_gf4_enabled: bool,
    last_switch_time: std::time::Instant,
}

impl ModeManager {
    /// Create a test mode manager with auto-detected policy.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn with_switch_threshold(initial_mode: FecMode, switch_threshold: f32) -> Self {
        let policy = FecRuntimePolicy::detect();
        Self::with_runtime_policy(initial_mode, switch_threshold, &policy)
    }

    /// Create a mode manager with explicit runtime policy overrides.
    pub fn with_runtime_policy(
        initial_mode: FecMode,
        switch_threshold: f32,
        policy: &FecRuntimePolicy,
    ) -> Self {
        Self {
            current_mode: initial_mode,
            loss_history: VecDeque::with_capacity(100),
            window_size: Self::params_for(initial_mode, 64).0,
            window_history: VecDeque::with_capacity(10),
            switch_threshold: policy
                .switch_threshold_override
                .unwrap_or(switch_threshold)
                .clamp(0.0, 1.0),
            switch_min_up_ms: policy.switch_min_up_ms,
            switch_min_down_ms: policy.switch_min_down_ms,
            auto_gf4_enabled: policy.auto_gf4_enabled,
            last_switch_time: now_instant(),
        }
    }

    #[inline]
    fn target_for_loss(avg_loss: f32, auto_gf4: bool) -> FecProtectionTarget {
        continuous_fec_target(avg_loss, auto_gf4, false, 2048, 1024, 0, 0.0)
    }

    #[inline]
    fn min_switch_interval_ms(
        &self,
        current: FecProtectionTarget,
        target: FecProtectionTarget,
    ) -> u64 {
        if current.family == FecBackendFamily::Zero {
            return 0;
        }
        if target_rank(target) > target_rank(current) {
            self.switch_min_up_ms
        } else {
            self.switch_min_down_ms
        }
    }

    /// Resolve (mode, k, n) parameters from a continuous protection target.
    pub fn params_for_target(
        target: FecProtectionTarget,
        default_window: usize,
        auto_gf4: bool,
    ) -> (FecMode, usize, usize) {
        let mode = mode_for_target(target, auto_gf4);
        let k = if target.family == FecBackendFamily::Zero {
            0
        } else if target.effective_window > 0 {
            target.effective_window
        } else if default_window > 0 {
            default_window
        } else {
            target_from_mode(mode, default_window).effective_window
        };
        let n = if k == 0 {
            0
        } else if target.redundancy.is_finite() && target.redundancy >= 0.0 {
            ((k as f32) * target.redundancy).ceil().min(wire::MAX_TOTAL_COUNT as f32).max(0.0)
                as usize
        } else {
            // NaN and infinity must not silently become the maximum repair budget. `f32::min`
            // returns the other operand for NaN, so the previous clamp turned a non-finite
            // redundancy into `MAX_TOTAL_COUNT`, the most expensive possible answer. Fall back to
            // systematic-only instead, which `n.max(k)` below turns into exactly `k`.
            log::warn!(
                "FEC redundancy {} is not a usable finite ratio; falling back to systematic-only",
                target.redundancy
            );
            0
        };
        (mode, k, n.max(k))
    }

    /// Resolve (k, n) window parameters for a given FEC mode.
    pub fn params_for(mode: FecMode, default_window: usize) -> (usize, usize) {
        let target = target_from_mode(mode, default_window);
        let (_, k, n) = Self::params_for_target(target, default_window, false);
        (k, n)
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn overhead_for(mode: FecMode) -> f32 {
        target_from_mode(mode, 0).redundancy
    }

    /// Feed a new loss observation and return the previous (mode, window) if a switch occurred.
    pub fn update(&mut self, loss_rate: f32) -> Option<(FecMode, usize)> {
        let loss_rate = if loss_rate.is_finite() { loss_rate.clamp(0.0, 1.0) } else { 0.0 };
        self.loss_history.push_back(loss_rate);
        if self.loss_history.len() > 100 {
            self.loss_history.pop_front();
        }

        let avg_loss = if self.loss_history.len() >= 10 {
            self.loss_history.iter().rev().take(10).sum::<f32>() / 10.0
        } else {
            loss_rate
        };

        let auto_gf4 = self.auto_gf4_enabled;
        let current_target = target_from_mode(self.current_mode, self.window_size);
        let target = Self::target_for_loss(avg_loss, auto_gf4);
        let target_mode = mode_for_target(target, auto_gf4);

        let now = now_instant();
        let min_ms = self.min_switch_interval_ms(current_target, target);
        let time_ok = now.checked_duration_since(self.last_switch_time).unwrap_or_default()
            >= Duration::from_millis(min_ms);
        let last_avg = if self.loss_history.len() >= 2 {
            let mut sum = 0.0f32;
            let mut count = 0;
            for value in self.loss_history.iter().rev().skip(1).take(10) {
                sum += *value;
                count += 1;
            }
            if count > 0 {
                sum / count as f32
            } else {
                avg_loss
            }
        } else {
            avg_loss
        };
        let current_rank = target_rank(current_target);
        let target_rank_value = target_rank(target);
        let hysteresis = self.switch_threshold.max(0.0025);
        let diff_ok = if target_rank_value > current_rank {
            (avg_loss - last_avg) >= hysteresis
        } else if target_rank_value < current_rank {
            (last_avg - avg_loss) >= hysteresis * 1.5
        } else {
            false
        };
        let stable_needed = if target_rank_value < current_rank { 4 } else { 3 };
        let stable_hits = self
            .loss_history
            .iter()
            .rev()
            .take(stable_needed)
            .filter(|value| {
                let stable_target = Self::target_for_loss(**value, auto_gf4);
                stable_target.family == target.family
                    && target_rank(stable_target) == target_rank_value
            })
            .count();
        let stable_ok = stable_hits >= stable_needed;
        let (_, target_window, _) = Self::params_for_target(target, self.window_size, auto_gf4);
        let switch_ok =
            if target_rank_value < current_rank { stable_ok } else { diff_ok || stable_ok };
        let state_changes = self.current_mode != target_mode || self.window_size != target_window;
        if state_changes && time_ok && switch_ok {
            let old_mode = self.current_mode;
            let old_window = self.window_size;
            self.current_mode = target_mode;
            self.last_switch_time = now;
            self.window_size = target_window;
            self.window_history.push_back(target_window);
            if self.window_history.len() > 10 {
                self.window_history.pop_front();
            }
            Some((old_mode, old_window))
        } else {
            None
        }
    }

    /// Return the currently selected FEC mode.
    pub fn current_mode(&self) -> FecMode {
        self.current_mode
    }

    /// Return the current source block window size.
    pub fn current_window(&self) -> usize {
        self.window_size
    }

    /// Force a specific mode and window, bypassing hysteresis and cooldown.
    pub fn force_state(&mut self, mode: FecMode, window: usize) {
        self.current_mode = mode;
        self.window_size = if mode == FecMode::Zero {
            0
        } else {
            window.max(1).min(wire::MAX_SOURCE_COUNT as usize)
        };
        self.last_switch_time = now_instant();
        self.window_history.push_back(self.window_size);
        if self.window_history.len() > 10 {
            self.window_history.pop_front();
        }
    }
}
