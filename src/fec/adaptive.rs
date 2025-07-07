use super::decoder::DecoderVariant;
use super::encoder::{EncoderVariant, Packet, PidConfig};
use super::gf_tables::init_gf_tables;
use crate::optimize::MemoryPool;
use crate::telemetry;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
// --- Core Data Structures ---

use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, ValueEnum)]
pub enum FecMode {
    Zero,
    Light,
    Normal,
    Medium,
    Strong,
    Extreme,
}

impl std::str::FromStr for FecMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "0" | "zero" => Ok(FecMode::Zero),
            "1" | "light" | "leicht" => Ok(FecMode::Light),
            "2" | "normal" => Ok(FecMode::Normal),
            "3" | "medium" | "mittel" => Ok(FecMode::Medium),
            "4" | "strong" | "stark" => Ok(FecMode::Strong),
            "5" | "extreme" => Ok(FecMode::Extreme),
            _ => Err(()),
        }
    }
}

/// Represents a packet in the FEC system, using an aligned buffer for the payload.
#[derive(Debug)]
// --- Loss Estimator & Mode Management ---

/// Estimates packet loss using an Exponential Moving Average and a burst detection window.
pub struct LossEstimator {
    ema_loss_rate: f32,
    lambda: f32,                  // Smoothing factor for EMA
    burst_window: VecDeque<bool>, // true for lost, false for received
    burst_capacity: usize,
    kalman: Option<KalmanFilter>,
}

impl LossEstimator {
    fn new(lambda: f32, burst_capacity: usize, kalman: Option<KalmanFilter>) -> Self {
        Self {
            ema_loss_rate: 0.0,
            lambda,
            burst_window: VecDeque::with_capacity(burst_capacity),
            burst_capacity,
            kalman,
        }
    }

    fn report_loss(&mut self, lost: usize, total: usize) {
        let mut current_loss_rate = if total > 0 {
            lost as f32 / total as f32
        } else {
            0.0
        };
        if let Some(kf) = self.kalman.as_mut() {
            current_loss_rate = kf.update(current_loss_rate);
        }
        self.ema_loss_rate =
            (self.lambda * current_loss_rate) + (1.0 - self.lambda) * self.ema_loss_rate;

        for _ in 0..lost {
            if self.burst_window.len() == self.burst_capacity {
                self.burst_window.pop_front();
            }
            self.burst_window.push_back(true);
        }
        for _ in 0..(total - lost) {
            if self.burst_window.len() == self.burst_capacity {
                self.burst_window.pop_front();
            }
            self.burst_window.push_back(false);
        }
    }

    /// Returns the estimated loss, considering both long-term average and recent bursts.
    fn get_estimated_loss(&self) -> f32 {
        let burst_loss = if self.burst_window.is_empty() {
            0.0
        } else {
            self.burst_window.iter().filter(|&&l| l).count() as f32 / self.burst_window.len() as f32
        };
        // The final estimate is the maximum of the long-term average and recent burst rate.
        self.ema_loss_rate.max(burst_loss)
    }
}

/// Manages the FEC mode using a PID controller for dynamic redundancy adjustment.
pub struct ModeManager {
    current_mode: FecMode,
    pid: PidController,
    mode_thresholds: HashMap<FecMode, f32>,
    window_sizes: HashMap<FecMode, usize>,
    last_mode_change: Instant,
    min_dwell_time: Duration,
    hysteresis: f32,
    current_window: usize,
}

impl ModeManager {
    const CROSS_FADE_LEN: usize = 32;
    const ALPHA_K: f32 = 0.5;

    fn initial_window(&self, mode: FecMode) -> usize {
        self.window_sizes
            .get(&mode)
            .copied()
            .unwrap_or_else(|| *FecConfig::default_windows().get(&mode).unwrap_or(&0))
    }

    fn window_range(mode: FecMode) -> (usize, usize) {
        match mode {
            FecMode::Zero => (0, 0),
            FecMode::Light => (8, 32),
            FecMode::Normal => (32, 128),
            FecMode::Medium => (64, 256),
            FecMode::Strong => (256, 1024),
            FecMode::Extreme => (1024, 4096),
        }
    }

    fn overhead_ratio(mode: FecMode) -> f32 {
        match mode {
            FecMode::Zero => 1.0,
            // Overhead targets from PLAN.txt
            FecMode::Light => 1.05,
            FecMode::Normal => 1.15,
            FecMode::Medium => 1.30,
            FecMode::Strong => 1.50,
            // Extreme mode behaves rateless with an unbounded window. A
            // conservative ratio keeps arithmetic reasonable.
            FecMode::Extreme => 2.0,
        }
    }

    pub fn params_for(mode: FecMode, window: usize) -> (usize, usize) {
        let ratio = Self::overhead_ratio(mode);
        let n = ((window as f32) * ratio).ceil() as usize;
        (window, n)
    }
    fn new(
        pid_config: PidConfig,
        hysteresis: f32,
        initial_mode: FecMode,
        window_sizes: HashMap<FecMode, usize>,
    ) -> Self {
        let mut mode_thresholds = HashMap::new();
        mode_thresholds.insert(FecMode::Zero, 0.01);
        mode_thresholds.insert(FecMode::Light, 0.05);
        mode_thresholds.insert(FecMode::Normal, 0.15);
        mode_thresholds.insert(FecMode::Medium, 0.30);
        mode_thresholds.insert(FecMode::Strong, 0.50);
        mode_thresholds.insert(FecMode::Extreme, 1.0); // Effectively a catch-all

        let current_mode = initial_mode;
        let current_window = window_sizes.get(&current_mode).copied().unwrap_or_else(|| {
            *FecConfig::default_windows()
                .get(&current_mode)
                .unwrap_or(&0)
        });

        Self {
            current_mode,
            pid: PidController::new(pid_config),
            mode_thresholds,
            window_sizes,
            last_mode_change: Instant::now(),
            min_dwell_time: Duration::from_millis(500),
            hysteresis,
            current_window,
        }
    }

    /// Updates the FEC mode and window based on the current estimated loss rate.
    /// Returns the new mode, window and an optional previous (mode, window) if a
    /// cross-fade should start.
    fn update(&mut self, estimated_loss: f32) -> (FecMode, usize, Option<(FecMode, usize)>) {
        // Emergency override for sudden loss spikes
        if estimated_loss > self.mode_thresholds[&FecMode::Strong] + self.hysteresis {
            let prev = (self.current_mode, self.current_window);
            self.current_mode = FecMode::Extreme;
            self.current_window = self.initial_window(self.current_mode);
            self.last_mode_change = Instant::now();
            return (self.current_mode, self.current_window, Some(prev));
        }

        if self.last_mode_change.elapsed() < self.min_dwell_time {
            return (self.current_mode, self.current_window, None);
        }

        let target_loss_for_current_mode = self.mode_thresholds[&self.current_mode];
        let output = self
            .pid
            .update(estimated_loss, target_loss_for_current_mode);

        let mut new_mode = self.current_mode;

        // Simplified logic: PID output suggests more (positive) or less (negative) redundancy
        if output > 0.1 {
            // Needs more redundancy
            new_mode = self.next_mode(self.current_mode);
        } else if output < -0.1 {
            // Needs less redundancy
            new_mode = self.prev_mode(self.current_mode);
        }

        let prev_mode = self.current_mode;
        let prev_window = self.current_window;

        if new_mode != self.current_mode {
            self.current_mode = new_mode;
            self.last_mode_change = Instant::now();
            self.current_window = self.initial_window(new_mode);
        }

        // Dynamic window update according to PLAN
        let target_loss_for_mode = self.mode_thresholds[&self.current_mode];
        let alpha = 1.0 + Self::ALPHA_K * (estimated_loss - target_loss_for_mode);
        let range = Self::window_range(self.current_mode);
        let mut new_window = ((self.current_window as f32) * alpha).round() as usize;
        new_window = new_window.clamp(range.0, range.1);
        self.current_window = new_window;

        if prev_mode != self.current_mode || prev_window != self.current_window {
            info!(
                "FEC mode change: {:?} -> {:?}, window {} -> {}, loss {:.2}%",
                prev_mode,
                self.current_mode,
                prev_window,
                self.current_window,
                estimated_loss * 100.0
            );
            telemetry::FEC_MODE.set(self.current_mode as i64);
            telemetry::LOSS_RATE.set((estimated_loss * 100.0) as i64);
            telemetry::FEC_MODE_SWITCHES.inc();
            telemetry::FEC_WINDOW.set(self.current_window as i64);
            return (
                self.current_mode,
                self.current_window,
                Some((prev_mode, prev_window)),
            );
        }

        telemetry::FEC_WINDOW.set(self.current_window as i64);

        (self.current_mode, self.current_window, None)
    }

    fn next_mode(&self, mode: FecMode) -> FecMode {
        match mode {
            FecMode::Zero => FecMode::Light,
            FecMode::Light => FecMode::Normal,
            FecMode::Normal => FecMode::Medium,
            FecMode::Medium => FecMode::Strong,
            FecMode::Strong | FecMode::Extreme => FecMode::Extreme,
        }
    }

    fn prev_mode(&self, mode: FecMode) -> FecMode {
        match mode {
            FecMode::Extreme => FecMode::Strong,
            FecMode::Strong => FecMode::Medium,
            FecMode::Medium => FecMode::Normal,
            FecMode::Normal => FecMode::Light,
            FecMode::Light | FecMode::Zero => FecMode::Zero,
        }
    }
}

// --- PID Controller ---

pub struct PidConfig {
    pub kp: f32,
    pub ki: f32,
    pub kd: f32,
}

struct PidController {
    config: PidConfig,
    integral: f32,
    previous_error: f32,
    last_time: Instant,
}

impl PidController {
    fn new(config: PidConfig) -> Self {
        Self {
            config,
            integral: 0.0,
            previous_error: 0.0,
            last_time: Instant::now(),
        }
    }

    fn update(&mut self, current_value: f32, setpoint: f32) -> f32 {
        let now = Instant::now();
        let dt = now.duration_since(self.last_time).as_secs_f32();
        self.last_time = now;

        if dt <= 0.0 {
            return 0.0;
        }

        let error = setpoint - current_value;
        self.integral += error * dt;
        let derivative = (error - self.previous_error) / dt;
        self.previous_error = error;

        (self.config.kp * error) + (self.config.ki * self.integral) + (self.config.kd * derivative)
    }
}

pub struct AdaptiveFec {
    estimator: Arc<Mutex<LossEstimator>>,
    mode_mgr: Arc<Mutex<ModeManager>>,
    encoder: EncoderVariant,
    decoder: DecoderVariant,
    transition_encoder: Option<EncoderVariant>,
    transition_decoder: Option<DecoderVariant>,
    transition_left: usize,
    mem_pool: Arc<MemoryPool>,
    config: FecConfig,
}

#[derive(Clone)]
pub struct FecConfig {
    pub lambda: f32,
    pub burst_window: usize,
    pub hysteresis: f32,
    pub pid: PidConfig,
    pub initial_mode: FecMode,
    pub kalman_enabled: bool,
    pub kalman_q: f32,
    pub kalman_r: f32,
    pub window_sizes: HashMap<FecMode, usize>,
}

impl FecConfig {
    pub fn default_windows() -> HashMap<FecMode, usize> {
        use FecMode::*;
        let mut m = HashMap::new();
        m.insert(Zero, 0);
        m.insert(Light, 16);
        m.insert(Normal, 64);
        m.insert(Medium, 128);
        m.insert(Strong, 512);
        m.insert(Extreme, 1024);
        m
    }

    pub fn from_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        #[derive(serde::Deserialize)]
        struct Root {
            adaptive_fec: Adaptive,
        }

        #[derive(serde::Deserialize)]
        struct Adaptive {
            lambda: Option<f32>,
            burst_window: Option<usize>,
            hysteresis: Option<f32>,
            pid: Option<PidSection>,
            kalman_enabled: Option<bool>,
            kalman_q: Option<f32>,
            kalman_r: Option<f32>,
            modes: Option<Vec<ModeSection>>,
        }

        #[derive(serde::Deserialize)]
        struct PidSection {
            kp: f32,
            ki: f32,
            kd: f32,
        }

        #[derive(serde::Deserialize)]
        struct ModeSection {
            name: String,
            w0: usize,
        }

        let raw: Root = toml::from_str(s)?;
        let af = raw.adaptive_fec;
        let pid = af.pid.unwrap_or(PidSection {
            kp: 1.2,
            ki: 0.5,
            kd: 0.1,
        });
        let mut windows = FecConfig::default_windows();
        if let Some(modes) = af.modes {
            for msec in modes {
                if let Ok(mode) = msec.name.parse() {
                    windows.insert(mode, msec.w0);
                }
            }
        }
        Ok(FecConfig {
            lambda: af.lambda.unwrap_or(0.1),
            burst_window: af.burst_window.unwrap_or(20),
            hysteresis: af.hysteresis.unwrap_or(0.02),
            pid: PidConfig {
                kp: pid.kp,
                ki: pid.ki,
                kd: pid.kd,
            },
            initial_mode: FecMode::Zero,
            kalman_enabled: af.kalman_enabled.unwrap_or(false),
            kalman_q: af.kalman_q.unwrap_or(0.001),
            kalman_r: af.kalman_r.unwrap_or(0.01),
            window_sizes: windows,
        })
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            lambda: 0.1,
            burst_window: 20,
            hysteresis: 0.02,
            pid: PidConfig {
                kp: 1.2,
                ki: 0.5,
                kd: 0.1,
            },
            initial_mode: FecMode::Zero,
            kalman_enabled: false,
            kalman_q: 0.001,
            kalman_r: 0.01,
            window_sizes: FecConfig::default_windows(),
        }
    }
}

impl AdaptiveFec {
    pub fn new(config: FecConfig, mem_pool: Arc<MemoryPool>) -> Self {
        init_gf_tables();
        let mode_mgr = ModeManager::new(
            config.pid.clone(),
            config.hysteresis,
            config.initial_mode,
            config.window_sizes.clone(),
        );
        let (k, n) = ModeManager::params_for(mode_mgr.current_mode, mode_mgr.current_window);

        let this = Self {
            estimator: Arc::new(Mutex::new(LossEstimator::new(
                config.lambda,
                config.burst_window,
                config
                    .kalman_enabled
                    .then(|| KalmanFilter::new(config.kalman_q, config.kalman_r)),
            ))),
            mode_mgr: Arc::new(Mutex::new(mode_mgr)),
            encoder: EncoderVariant::new(mode_mgr.current_mode, k, n),
            decoder: DecoderVariant::new(mode_mgr.current_mode, k, Arc::clone(&mem_pool)),
            transition_encoder: None,
            transition_decoder: None,
            transition_left: 0,
            mem_pool,
            config,
        };
        telemetry::FEC_WINDOW.set(mode_mgr.current_window as i64);
        this
    }

    pub fn current_mode(&self) -> FecMode {
        let mgr = self.mode_mgr.lock().unwrap();
        mgr.current_mode
    }

    pub fn is_transitioning(&self) -> bool {
        self.transition_left > 0
    }

    /// Processes an outgoing packet, adding it to the FEC window and pushing
    /// resulting systematic and repair packets into the outgoing queue.
    pub fn on_send(&mut self, pkt: Packet, outgoing_queue: &mut VecDeque<Packet>) {
        if let Some(enc) = self.transition_encoder.as_mut() {
            enc.add_source_packet(pkt.clone_for_encoder(&self.mem_pool));
        }
        // The original systematic packet is always sent.
        self.encoder
            .add_source_packet(pkt.clone_for_encoder(&self.mem_pool));
        outgoing_queue.push_back(pkt);
        crate::telemetry::ENCODED_PACKETS.inc();

        if self.transition_left > ModeManager::CROSS_FADE_LEN / 2 {
            if let Some(enc) = self.transition_encoder.as_mut() {
                Self::emit_repairs(enc, &self.mem_pool, outgoing_queue);
            }
        }

        Self::emit_repairs(&mut self.encoder, &self.mem_pool, outgoing_queue);

        if self.transition_left > 0 {
            self.transition_left -= 1;
            if self.transition_left == ModeManager::CROSS_FADE_LEN / 2 {
                self.transition_encoder = None;
                self.transition_decoder = None;
            }
        }
    }

    fn emit_repairs(
        encoder: &mut EncoderVariant,
        mem_pool: &Arc<MemoryPool>,
        outgoing_queue: &mut VecDeque<Packet>,
    ) {
        let (k, n) = match encoder {
            EncoderVariant::G8(e) => (e.k, e.n),
            EncoderVariant::G16(e) => (e.k, e.n),
        };
        let num_repair = n.saturating_sub(k);
        for i in 0..num_repair {
            if let Some(repair_packet) = encoder.generate_repair_packet(i, mem_pool) {
                outgoing_queue.push_back(repair_packet);
                crate::telemetry::ENCODED_PACKETS.inc();
            }
        }
    }

    /// Processes an incoming packet, adding it to the decoder and attempting recovery.
    /// Returns a list of recovered packets if decoding is successful.
    pub fn on_receive(&mut self, pkt: Packet) -> Result<Vec<Packet>, &'static str> {
        let mut recovered = Vec::new();
        let was_decoded = self.decoder.is_decoded();
        let pkt_clone = if self.transition_left > ModeManager::CROSS_FADE_LEN / 2 {
            Some(pkt.clone_for_encoder(&self.mem_pool))
        } else {
            None
        };

        match self.decoder.add_packet(pkt) {
            Ok(is_now_decoded) => {
                if !was_decoded && is_now_decoded {
                    recovered.extend(self.decoder.get_decoded_packets());
                    crate::telemetry::DECODED_PACKETS.inc_by(recovered.len() as u64);
                }
            }
            Err(e) => return Err(e),
        }

        if let (Some(trans_dec), Some(clone_pkt)) = (self.transition_decoder.as_mut(), pkt_clone) {
            let was_dec = trans_dec.is_decoded();
            match trans_dec.add_packet(clone_pkt) {
                Ok(now) => {
                    if !was_dec && now {
                        recovered.extend(trans_dec.get_decoded_packets());
                        crate::telemetry::DECODED_PACKETS.inc_by(recovered.len() as u64);
                    }
                }
                Err(e) => return Err(e),
            }
        }

        Ok(recovered)
    }

    /// Reports packet loss statistics to update the adaptive logic.
    pub fn report_loss(&mut self, lost: usize, total: usize) {
        let mut estimator = self.estimator.lock().unwrap();
        estimator.report_loss(lost, total);
        let estimated_loss = estimator.get_estimated_loss();
        drop(estimator);
        crate::telemetry::LOSS_RATE.set((estimated_loss * 100.0) as i64);

        let mut mode_mgr = self.mode_mgr.lock().unwrap();
        let (new_mode, new_window, prev) = mode_mgr.update(estimated_loss);
        let (k, n) = ModeManager::params_for(new_mode, new_window);

        if let Some((old_mode, old_window)) = prev {
            let (ok, _) = ModeManager::params_for(old_mode, old_window);
            // Keep the previous encoder/decoder for the cross-fade phase and
            // immediately switch to the new configuration.
            self.transition_encoder = Some(std::mem::replace(
                &mut self.encoder,
                EncoderVariant::new(new_mode, k, n),
            ));
            self.transition_decoder = Some(std::mem::replace(
                &mut self.decoder,
                DecoderVariant::new(new_mode, k, Arc::clone(&self.mem_pool)),
            ));
            self.transition_left = ModeManager::CROSS_FADE_LEN;
        } else {
            self.encoder = EncoderVariant::new(new_mode, k, n);
            self.decoder = DecoderVariant::new(new_mode, k, Arc::clone(&self.mem_pool));
        }
    }
}

// [Die Tests wurden oben nicht verändert und bleiben wie im Input – ebenfalls konfliktfrei!]
//
//     * Neither the name of the copyright holder nor the names of its
//       contributors may be used to endorse or promote products derived from
//       this

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn make_packet(id: u64, val: u8, pool: &Arc<MemoryPool>) -> Packet {
        let mut buf = pool.alloc();
        for b in buf.iter_mut().take(8) {
            *b = val;
        }
        Packet {
            id,
            data: Some(buf),
            len: 8,
            is_systematic: true,
            coefficients: None,
            mem_pool: Arc::clone(pool),
        }
    }

    #[test]
    fn gaussian_path_decodes() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(32, 64));
        let k = 4;
        let n = 6;
        let mut enc = Encoder::new(k, n);
        let mut packets = Vec::new();
        for i in 0..k {
            let p = make_packet(i as u64, i as u8, &pool);
            enc.add_source_packet(p.clone());
            packets.push(p);
        }
        let mut repairs = Vec::new();
        for i in 0..(n - k) {
            repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
        }

        let mut dec = Decoder::new(k, Arc::clone(&pool));
        // drop packet 2
        dec.add_packet(packets[0].clone()).unwrap();
        dec.add_packet(packets[1].clone()).unwrap();
        dec.add_packet(packets[3].clone()).unwrap();
        for r in repairs {
            dec.add_packet(r).unwrap();
        }
        assert!(dec.is_decoded);
        let out = dec.get_decoded_packets();
        assert_eq!(out.len(), k);
        for i in 0..k {
            assert_eq!(out[i].data.as_ref().unwrap()[0], i as u8);
        }
    }

    #[test]
    fn wiedemann_path_decodes() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(600, 64));
        let k = 260;
        let n = k + 4;
        let mut enc = Encoder::new(k, n);
        let mut packets = Vec::new();
        for i in 0..k {
            let p = make_packet(i as u64, (i % 256) as u8, &pool);
            enc.add_source_packet(p.clone());
            packets.push(p);
        }
        let mut repairs = Vec::new();
        for i in 0..(n - k) {
            repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
        }

        let mut dec = Decoder::new(k, Arc::clone(&pool));
        // Drop one packet
        for i in 1..k {
            if i != 5 {
                dec.add_packet(packets[i].clone()).unwrap();
            }
        }
        for r in repairs {
            dec.add_packet(r).unwrap();
        }
        assert!(dec.is_decoded);
        let out = dec.get_decoded_packets();
        assert_eq!(out.len(), k);
        for i in 0..k {
            assert_eq!(out[i].data.as_ref().unwrap()[0], (i % 256) as u8);
        }
    }

    #[test]
    fn extreme_mode_trigger() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(32, 64));
        let cfg = FecConfig {
            lambda: 0.01,
            burst_window: 50,
            hysteresis: 0.02,
            pid: PidConfig {
                kp: 1.0,
                ki: 0.0,
                kd: 0.0,
            },
            initial_mode: FecMode::Zero,
            kalman_enabled: false,
            kalman_q: 0.001,
            kalman_r: 0.01,
            window_sizes: FecConfig::default_windows(),
        };
        let mut fec = AdaptiveFec::new(cfg, Arc::clone(&pool));
        fec.report_loss(18, 20);
        assert_eq!(fec.current_mode(), FecMode::Extreme);
    }

    #[test]
    fn cross_fade_transition() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(32, 64));
        let cfg = FecConfig {
            lambda: 0.01,
            burst_window: 50,
            hysteresis: 0.02,
            pid: PidConfig {
                kp: 1.0,
                ki: 0.0,
                kd: 0.0,
            },
            initial_mode: FecMode::Zero,
            kalman_enabled: false,
            kalman_q: 0.001,
            kalman_r: 0.01,
            window_sizes: FecConfig::default_windows(),
        };
        let mut fec = AdaptiveFec::new(cfg, Arc::clone(&pool));
        fec.report_loss(10, 20);
        assert!(fec.is_transitioning());
        for i in 0..ModeManager::CROSS_FADE_LEN {
            let pkt = make_packet(i as u64, i as u8, &pool);
            let mut out = VecDeque::new();
            fec.on_send(pkt, &mut out);
        }
        assert!(!fec.is_transitioning());
    }

    #[test]
    fn parse_config_toml() {
        let cfg_str = r#"
            [adaptive_fec]
            lambda = 0.05
            burst_window = 30
            hysteresis = 0.01
            pid = { kp = 1.5, ki = 0.2, kd = 0.1 }
            kalman_enabled = true
            kalman_q = 0.002
            kalman_r = 0.02

            [[adaptive_fec.modes]]
            name = "light"
            w0 = 20

            [[adaptive_fec.modes]]
            name = "extreme"
            w0 = 2048
        "#;
        let cfg = FecConfig::from_toml(cfg_str).unwrap();
        assert_eq!(cfg.pid.kp, 1.5);
        assert_eq!(cfg.window_sizes[&FecMode::Light], 20);
        assert_eq!(cfg.window_sizes[&FecMode::Extreme], 2048);
        assert_eq!(cfg.lambda, 0.05);
        assert_eq!(cfg.burst_window, 30);
        assert!(cfg.kalman_enabled);
        assert!((cfg.kalman_q - 0.002).abs() < 1e-6);
        assert!((cfg.kalman_r - 0.02).abs() < 1e-6);
    }

    #[test]
    fn adaptive_transition_from_toml() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(32, 64));
        let cfg_str = r#"
            [adaptive_fec]
            lambda = 0.1
            burst_window = 10
            hysteresis = 0.02
            pid = { kp = 1.0, ki = 0.0, kd = 0.0 }

            [[adaptive_fec.modes]]
            name = "extreme"
            w0 = 1024
        "#;
        let cfg = FecConfig::from_toml(cfg_str).unwrap();
        let mut fec = AdaptiveFec::new(cfg, Arc::clone(&pool));
        fec.report_loss(15, 20);
        assert_eq!(fec.current_mode(), FecMode::Extreme);
    }

    #[test]
    fn recovery_low_loss() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(64, 64));
        let k = 10;
        let n = 12;
        let mut enc = Encoder::new(k, n);
        let mut packets = Vec::new();
        for i in 0..k {
            let p = make_packet(i as u64, i as u8, &pool);
            enc.add_source_packet(p.clone());
            packets.push(p);
        }
        let mut repairs = Vec::new();
        for i in 0..(n - k) {
            repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
        }
        let mut dec = Decoder::new(k, Arc::clone(&pool));
        for (idx, pkt) in packets.into_iter().enumerate() {
            if idx != 3 {
                dec.add_packet(pkt).unwrap();
            }
        }
        for r in repairs {
            dec.add_packet(r).unwrap();
        }
        assert!(dec.is_decoded);
    }

    #[test]
    fn recovery_high_loss() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(128, 64));
        let k = 16;
        let n = 32;
        let mut enc = Encoder::new(k, n);
        let mut packets = Vec::new();
        for i in 0..k {
            let p = make_packet(i as u64, (i % 255) as u8, &pool);
            enc.add_source_packet(p.clone());
            packets.push(p);
        }
        let mut repairs = Vec::new();
        for i in 0..(n - k) {
            repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
        }
        let mut dec = Decoder::new(k, Arc::clone(&pool));
        for (idx, pkt) in packets.into_iter().enumerate() {
            if idx % 2 == 0 {
                dec.add_packet(pkt).unwrap();
            }
        }
        for (i, r) in repairs.into_iter().enumerate() {
            if i % 3 != 0 {
                dec.add_packet(r).unwrap();
            }
        }
        assert!(dec.is_decoded);
    }

    #[test]
    fn extreme_mode_recovery() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(2048, 64));
        let k = 64;
        let n = k + 16;
        let mut enc = Encoder16::new(k, n);
        let mut packets = Vec::new();
        for i in 0..k {
            let p = make_packet(i as u64, (i % 255) as u8, &pool);
            enc.add_source_packet(p.clone());
            packets.push(p);
        }
        let mut repairs = Vec::new();
        for i in 0..(n - k) {
            repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
        }
        let mut dec = Decoder16::new(k, Arc::clone(&pool));
        for (idx, pkt) in packets.into_iter().enumerate() {
            if idx % 3 != 0 {
                dec.add_packet(pkt).unwrap();
            }
        }
        for r in repairs {
            dec.add_packet(r).unwrap();
        }
        assert!(dec.is_decoded);
        let out = dec.get_decoded_packets();
        assert_eq!(out.len(), k);
        for i in 0..k {
            assert_eq!(out[i].data.as_ref().unwrap()[0], (i % 255) as u8);
        }
    }

    #[test]
    fn very_large_window_recovery() {
        init_gf_tables();
        let pool = Arc::new(MemoryPool::new(4096, 64));
        let k = 1024;
        let n = k + 8;
        let mut enc = Encoder::new(k, n);
        let mut packets = Vec::new();
        for i in 0..k {
            let p = make_packet(i as u64, (i % 256) as u8, &pool);
            enc.add_source_packet(p.clone());
            packets.push(p);
        }
        let mut repairs = Vec::new();
        for i in 0..(n - k) {
            repairs.push(enc.generate_repair_packet(i, &pool).unwrap());
        }
        let mut dec = Decoder::new(k, Arc::clone(&pool));
        for (idx, pkt) in packets.into_iter().enumerate() {
            if idx % 5 != 0 {
                dec.add_packet(pkt).unwrap();
            }
        }
        for r in repairs {
            dec.add_packet(r).unwrap();
        }
        assert!(dec.is_decoded);
        let out = dec.get_decoded_packets();
        assert_eq!(out.len(), k);
        for i in 0..k {
            assert_eq!(out[i].data.as_ref().unwrap()[0], (i % 256) as u8);
        }
    }
}
