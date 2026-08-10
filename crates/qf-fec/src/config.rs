use crate::codecs::{FecControlPolicy, FecMode};
use crate::target::{DEFAULT_FOUNTAIN_WINDOW, MAX_FOUNTAIN_WINDOW};
use crate::wire::MAX_SOURCE_COUNT;
use std::collections::HashMap;

/// Minimal engine-facing mode contract used by the FEC compatibility adapter.
pub trait EngineFecMode {
    /// Returns true when the engine requests adaptive FEC operation.
    fn adaptive_requested(self) -> bool;
}

/// Engine configuration projection required to build the runtime FEC policy.
pub trait EngineFecSection {
    /// Returns true when the engine mode is adaptive rather than disabled.
    fn mode_is_auto(&self) -> bool;
    /// Window size for excellent link quality.
    fn window_excellent(&self) -> usize;
    /// Window size for good link quality.
    fn window_good(&self) -> usize;
    /// Window size for fair link quality.
    fn window_fair(&self) -> usize;
    /// Window size for poor link quality.
    fn window_poor(&self) -> usize;
    /// Whether mode hysteresis is enabled.
    fn enable_hysteresis(&self) -> bool;
    /// Whether Kalman smoothing is enabled.
    fn enable_kalman(&self) -> bool;
    /// Streaming emission period.
    fn stream_every(&self) -> usize;
}

/// Configuration for adaptive FEC behavior and controller settings.
#[derive(Debug, Clone)]
pub struct FecConfig {
    /// Operator-owned control policy. This is never inferred from the active codec mode.
    pub control_policy: FecControlPolicy,
    /// FEC window size per mode (source packets per block).
    pub window_sizes: HashMap<FecMode, usize>,
    /// EMA smoothing factor for loss estimation (0..1).
    pub lambda: f32,
    /// Sliding window capacity for burst-loss detection.
    pub burst_window: usize,
    /// Minimum loss delta required to trigger a mode switch.
    pub hysteresis: f32,
    /// FEC mode to use at startup before adaptation kicks in.
    pub initial_mode: FecMode,
    /// When true, FEC will never downshift to `Zero`.
    pub force_on: bool,
    /// Enable Kalman filter for loss rate smoothing.
    pub kalman_enabled: bool,
    /// Kalman process noise covariance.
    pub kalman_q: f32,
    /// Kalman measurement noise covariance.
    pub kalman_r: f32,
    /// Override for streaming repair emission interval (packets between repairs).
    pub configured_stream_every: Option<usize>,
}

impl FecConfig {
    fn default_windows() -> HashMap<FecMode, usize> {
        use FecMode::*;
        let mut windows = HashMap::new();
        windows.insert(Zero, 0);
        windows.insert(Light, 15);
        windows.insert(Normal, 64);
        windows.insert(Medium, 128);
        windows.insert(Strong, 512);
        windows.insert(Extreme, 1024);
        windows.insert(Ultra, 1024);
        windows.insert(Fountain, DEFAULT_FOUNTAIN_WINDOW);
        windows.insert(Streaming, 64);
        windows
    }

    fn product_windows<S: EngineFecSection>(section: &S) -> HashMap<FecMode, usize> {
        let mut windows = Self::default_windows();
        windows.insert(FecMode::Zero, 0);
        if section.window_excellent() > 0 {
            windows.insert(FecMode::Light, section.window_excellent());
        }
        windows.insert(FecMode::Normal, section.window_good().max(1));
        windows.insert(FecMode::Medium, section.window_fair().max(section.window_good()).max(1));
        windows.insert(FecMode::Strong, section.window_poor().max(1));
        windows.insert(
            FecMode::Extreme,
            section.window_poor().saturating_mul(2).max(section.window_poor()).max(1),
        );
        windows.insert(FecMode::Ultra, 1024);
        windows.insert(FecMode::Fountain, DEFAULT_FOUNTAIN_WINDOW);
        windows.insert(FecMode::Streaming, section.window_fair().max(1));
        windows
    }

    /// Build FEC config from an engine-owned `[fec]` section.
    pub fn from_engine_section<S: EngineFecSection>(section: &S) -> Self {
        let initial_mode = FecMode::Zero;
        Self {
            control_policy: if section.mode_is_auto() {
                FecControlPolicy::Auto
            } else {
                FecControlPolicy::Off
            },
            window_sizes: Self::product_windows(section),
            lambda: 0.15,
            burst_window: 16,
            hysteresis: if section.enable_hysteresis() { 0.1 } else { 0.0 },
            initial_mode,
            force_on: false,
            kalman_enabled: section.enable_kalman(),
            kalman_q: 0.001,
            kalman_r: 0.01,
            configured_stream_every: Some(section.stream_every().max(1)),
        }
    }

    /// Return the production-default FEC configuration.
    pub fn product_default() -> Self {
        let windows = [
            (FecMode::Zero, 0),
            (FecMode::Light, 15),
            (FecMode::Normal, 10),
            (FecMode::Medium, 30),
            (FecMode::Strong, 50),
            (FecMode::Extreme, 100),
            (FecMode::Ultra, 1024),
            (FecMode::Fountain, DEFAULT_FOUNTAIN_WINDOW),
            (FecMode::Streaming, 30),
        ]
        .into_iter()
        .collect();
        Self {
            control_policy: FecControlPolicy::Auto,
            window_sizes: windows,
            lambda: 0.15,
            burst_window: 16,
            hysteresis: 0.1,
            initial_mode: FecMode::Zero,
            force_on: false,
            kalman_enabled: true,
            kalman_q: 0.001,
            kalman_r: 0.01,
            configured_stream_every: Some(5),
        }
    }

    /// Override operator policy and its compatible bootstrap mode.
    pub fn apply_engine_mode<M: EngineFecMode>(&mut self, mode: M) {
        if mode.adaptive_requested() {
            self.control_policy = FecControlPolicy::Auto;
            self.initial_mode = FecMode::Zero;
        } else {
            self.control_policy = FecControlPolicy::Off;
            self.initial_mode = FecMode::Zero;
        }
        self.force_on = false;
    }

    /// Parse FEC configuration from a TOML string containing `[adaptive_fec]`.
    pub fn from_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Root {
            adaptive_fec: Adaptive,
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Adaptive {
            #[serde(alias = "policy")]
            control_policy: Option<String>,
            lambda: Option<f32>,
            burst_window: Option<usize>,
            hysteresis: Option<f32>,
            kalman_enabled: Option<bool>,
            kalman_q: Option<f32>,
            kalman_r: Option<f32>,
            stream_every: Option<usize>,
            initial_mode: Option<String>,
            modes: Option<Vec<ModeSection>>,
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ModeSection {
            name: String,
            w0: usize,
        }

        let raw: Root = toml::from_str(s)?;
        let af = raw.adaptive_fec;
        let mut windows = Self::default_windows();
        if let Some(modes) = af.modes {
            for mode_section in modes {
                let mode = parse_fec_mode_name(&mode_section.name, "modes[].name")?;
                windows.insert(mode, mode_section.w0);
            }
        }
        let initial_mode = af.initial_mode.as_deref().unwrap_or("auto").trim();
        let initial_mode = match initial_mode.to_ascii_lowercase().as_str() {
            "auto" | "off" => FecMode::Zero,
            "on" => FecMode::Normal,
            _ => parse_fec_mode_name(initial_mode, "initial_mode")?,
        };
        let control_policy = match af.control_policy.as_deref().map(str::trim) {
            None | Some("") | Some("auto") => FecControlPolicy::Auto,
            Some("off") => FecControlPolicy::Off,
            Some(value) => {
                return Err(format!(
                    "adaptive_fec.control_policy must be 'off' or 'auto', got '{value}'"
                )
                .into());
            }
        };
        Ok(Self {
            control_policy,
            lambda: af.lambda.unwrap_or(0.1),
            burst_window: af.burst_window.unwrap_or(20),
            hysteresis: af.hysteresis.unwrap_or(0.02),
            initial_mode,
            force_on: false,
            kalman_enabled: af.kalman_enabled.unwrap_or(false),
            kalman_q: af.kalman_q.unwrap_or(0.001),
            kalman_r: af.kalman_r.unwrap_or(0.01),
            configured_stream_every: af.stream_every,
            window_sizes: windows,
        })
    }

    /// Load FEC configuration from a TOML file on disk.
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    /// Validate all configuration parameters, returning an error message on invalid values.
    pub fn validate(&self) -> Result<(), String> {
        if self.control_policy == FecControlPolicy::Off && self.force_on {
            return Err("force_on cannot be enabled while FEC control policy is off".into());
        }
        if !(0.0..=1.0).contains(&self.lambda) {
            return Err("lambda must be between 0 and 1".into());
        }
        if self.burst_window == 0 || self.burst_window > MAX_SOURCE_COUNT as usize {
            return Err(format!("burst_window must be between 1 and {}", MAX_SOURCE_COUNT));
        }
        if !self.hysteresis.is_finite() || self.hysteresis < 0.0 || self.hysteresis >= 1.0 {
            return Err("hysteresis must be between 0 (inclusive) and 1".into());
        }
        if !(1e-8f32..=1.0f32).contains(&self.kalman_q) {
            return Err("kalman_q must be between 1e-8 and 1.0".into());
        }
        if !(1e-8f32..=1.0f32).contains(&self.kalman_r) {
            return Err("kalman_r must be between 1e-8 and 1.0".into());
        }
        if matches!(self.configured_stream_every, Some(0)) {
            return Err("configured_stream_every must be > 0".into());
        }
        for (mode, window) in &self.window_sizes {
            if *window > MAX_SOURCE_COUNT as usize {
                return Err(format!("window_sizes.{mode:?} must be <= {}", MAX_SOURCE_COUNT));
            }
            if *mode == FecMode::Zero {
                if *window != 0 {
                    return Err("window_sizes.Zero must be 0".into());
                }
            } else if *window == 0 {
                return Err(format!("window_sizes.{mode:?} must be > 0"));
            }
            if *mode == FecMode::Fountain && *window > MAX_FOUNTAIN_WINDOW {
                return Err(format!("window_sizes.Fountain must be <= {}", MAX_FOUNTAIN_WINDOW));
            }
        }
        Ok(())
    }
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            control_policy: FecControlPolicy::Auto,
            lambda: 0.1,
            burst_window: 20,
            hysteresis: 0.02,
            initial_mode: FecMode::Zero,
            force_on: false,
            kalman_enabled: false,
            kalman_q: 0.001,
            kalman_r: 0.01,
            configured_stream_every: None,
            window_sizes: Self::default_windows(),
        }
    }
}

fn parse_fec_mode_name(raw: &str, field: &str) -> Result<FecMode, std::io::Error> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "zero" => Ok(FecMode::Zero),
        "light" => Ok(FecMode::Light),
        "normal" => Ok(FecMode::Normal),
        "medium" => Ok(FecMode::Medium),
        "strong" => Ok(FecMode::Strong),
        "extreme" => Ok(FecMode::Extreme),
        "ultra" => Ok(FecMode::Ultra),
        "fountain" => Ok(FecMode::Fountain),
        "streaming" => Ok(FecMode::Streaming),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "adaptive_fec.{field} contains unsupported FEC mode '{raw}' (expected zero, light, normal, medium, strong, extreme, ultra, fountain, or streaming)"
            ),
        )),
    }
}
