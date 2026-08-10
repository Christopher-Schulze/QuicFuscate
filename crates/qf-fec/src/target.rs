//! Pure adaptive FEC target selection shared by the product controller and backend dispatch.

use crate::codecs::FecMode;

#[doc(hidden)]
pub const GF4_LIGHT_REDUNDANCY: f32 = 16.0 / 15.0;
#[doc(hidden)]
pub const FOUNTAIN_LOSS_THRESHOLD: f32 = 0.25;
#[doc(hidden)]
pub const DEFAULT_FOUNTAIN_WINDOW: usize = 128;
#[doc(hidden)]
pub const MAX_FOUNTAIN_WINDOW: usize = 128;

#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecBackendFamily {
    Zero,
    LowCostBlock,
    HeavyBlock,
    Streaming,
    Fountain,
}

#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct FecProtectionPressure {
    pub total: f32,
    pub loss: f32,
}

impl FecProtectionPressure {
    #[doc(hidden)]
    pub fn new(loss: f32, burst: f32) -> Self {
        let loss = loss.clamp(0.0, 1.0);
        let burst = burst.clamp(0.0, 1.0);
        let total = (loss * 0.8 + burst * 0.2).clamp(0.0, 1.0);
        Self { total, loss }
    }
}

#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct FecProtectionTarget {
    #[doc(hidden)]
    pub family: FecBackendFamily,
    #[doc(hidden)]
    pub redundancy: f32,
    #[doc(hidden)]
    pub effective_window: usize,
    #[doc(hidden)]
    pub stream_every: Option<usize>,
}

impl FecProtectionTarget {
    fn for_clean_link() -> Self {
        Self {
            family: FecBackendFamily::Zero,
            redundancy: 1.0,
            effective_window: 0,
            stream_every: None,
        }
    }

    #[doc(hidden)]
    pub fn with_window(mut self, effective_window: usize) -> Self {
        self.effective_window = effective_window;
        self
    }
}

#[doc(hidden)]
pub fn fec_backend_family(mode: FecMode) -> FecBackendFamily {
    match mode {
        FecMode::Zero => FecBackendFamily::Zero,
        FecMode::Light | FecMode::Normal => FecBackendFamily::LowCostBlock,
        FecMode::Medium | FecMode::Strong | FecMode::Extreme | FecMode::Ultra => {
            FecBackendFamily::HeavyBlock
        }
        FecMode::Streaming => FecBackendFamily::Streaming,
        FecMode::Fountain => FecBackendFamily::Fountain,
    }
}

#[doc(hidden)]
pub fn mode_for_target(target: FecProtectionTarget, auto_gf4: bool) -> FecMode {
    match target.family {
        FecBackendFamily::Zero => FecMode::Zero,
        FecBackendFamily::LowCostBlock => {
            if auto_gf4 && target.effective_window <= 15 && target.redundancy <= 1.10 {
                FecMode::Light
            } else {
                FecMode::Normal
            }
        }
        FecBackendFamily::HeavyBlock => {
            if target.redundancy >= 3.0 {
                FecMode::Ultra
            } else if target.effective_window >= 512 {
                FecMode::Extreme
            } else if target.redundancy >= 1.5 || target.effective_window > 64 {
                FecMode::Strong
            } else {
                FecMode::Medium
            }
        }
        FecBackendFamily::Streaming => FecMode::Streaming,
        FecBackendFamily::Fountain => FecMode::Fountain,
    }
}

#[doc(hidden)]
pub fn target_from_mode(mode: FecMode, default_window: usize) -> FecProtectionTarget {
    let effective_window = if default_window > 0 {
        default_window
    } else {
        match mode {
            FecMode::Zero => 0,
            FecMode::Light => 15,
            FecMode::Normal | FecMode::Streaming => 64,
            FecMode::Medium | FecMode::Strong => 128,
            FecMode::Extreme => 512,
            FecMode::Ultra => 1024,
            FecMode::Fountain => DEFAULT_FOUNTAIN_WINDOW,
        }
    };
    let stream_every = (mode == FecMode::Streaming).then_some(2);
    FecProtectionTarget {
        family: fec_backend_family(mode),
        redundancy: match mode {
            FecMode::Zero => 1.0,
            FecMode::Light => GF4_LIGHT_REDUNDANCY,
            FecMode::Normal => 1.25,
            FecMode::Medium => 1.5,
            FecMode::Strong => 2.0,
            FecMode::Extreme => 2.0,
            FecMode::Streaming => 1.2,
            FecMode::Ultra => 3.0,
            FecMode::Fountain => 5.0,
        },
        effective_window,
        stream_every,
    }
}

#[doc(hidden)]
pub fn low_cost_block_uses_gf4(target: FecProtectionTarget) -> bool {
    target.family == FecBackendFamily::LowCostBlock
        && target.redundancy <= 1.10
        && target.effective_window <= 15
}

#[doc(hidden)]
pub fn target_rank(target: FecProtectionTarget) -> u8 {
    match target.family {
        FecBackendFamily::Zero => 0,
        FecBackendFamily::LowCostBlock => {
            if low_cost_block_uses_gf4(target) {
                1
            } else {
                2
            }
        }
        FecBackendFamily::HeavyBlock => {
            if target.redundancy >= 3.0 {
                6
            } else if target.redundancy >= 2.0 {
                5
            } else {
                4
            }
        }
        FecBackendFamily::Streaming => 3,
        FecBackendFamily::Fountain => 7,
    }
}

#[doc(hidden)]
pub fn continuous_fec_target(
    average_loss: f32,
    auto_gf4: bool,
    disturbance: bool,
    fountain_window: usize,
    extreme_window: usize,
    rtt_ms: u32,
    burst_variance: f32,
) -> FecProtectionTarget {
    if average_loss < 0.001 && !disturbance {
        return FecProtectionTarget::for_clean_link();
    }
    let burst =
        if disturbance { (average_loss.max(0.15) * 1.5).clamp(0.0, 1.0) } else { average_loss };
    let pressure = FecProtectionPressure::new(average_loss, burst);
    let family = if pressure.loss >= FOUNTAIN_LOSS_THRESHOLD {
        FecBackendFamily::Fountain
    } else if (disturbance && pressure.loss >= 0.15)
        || (pressure.loss >= 0.05 && pressure.loss < 0.15 && burst_variance > 0.3)
    {
        FecBackendFamily::Streaming
    } else if pressure.total < 0.10 {
        FecBackendFamily::LowCostBlock
    } else {
        FecBackendFamily::HeavyBlock
    };
    let redundancy = match family {
        FecBackendFamily::Zero => 1.0,
        FecBackendFamily::LowCostBlock => {
            if pressure.total < 0.02 {
                GF4_LIGHT_REDUNDANCY
            } else {
                1.25
            }
        }
        FecBackendFamily::HeavyBlock => {
            if pressure.total < 0.22 {
                1.5
            } else if pressure.total < 0.30 {
                2.0
            } else {
                3.0
            }
        }
        FecBackendFamily::Streaming => 1.2,
        FecBackendFamily::Fountain => 5.0,
    };
    let effective_window = match family {
        FecBackendFamily::Zero => 0,
        FecBackendFamily::LowCostBlock => {
            if pressure.total < 0.02 && auto_gf4 {
                15
            } else {
                64
            }
        }
        FecBackendFamily::HeavyBlock => {
            if pressure.total < 0.22 {
                128
            } else if pressure.total < 0.30 {
                512
            } else {
                1024
            }
        }
        FecBackendFamily::Streaming => extreme_window,
        FecBackendFamily::Fountain => fountain_window,
    };
    let stream_every = match family {
        FecBackendFamily::Streaming => {
            let base = if pressure.total >= 0.22 {
                1
            } else if pressure.total >= 0.18 {
                2
            } else if pressure.total >= 0.15 {
                3
            } else {
                4
            };
            let scale = if rtt_ms > 0 { (rtt_ms as f32 / 100.0).clamp(0.5, 3.0) } else { 1.0 };
            Some(((base as f32 * scale).round() as usize).clamp(1, 18))
        }
        _ => None,
    };
    FecProtectionTarget { family, redundancy, effective_window, stream_every }
}
