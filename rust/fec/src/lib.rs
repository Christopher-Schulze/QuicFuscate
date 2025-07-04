//! Forward Error Correction utilities.

use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use std::ptr;
use std::sync::Mutex;
use thiserror::Error;
use quicfuscate_error::QuicFuscateError;

#[derive(Debug, Error)]
pub enum FECError {
    #[error("mutex poisoned")]
    LockPoisoned,
    #[error("reed-solomon error: {0}")]
    ReedSolomon(String),
}

impl QuicFuscateError for FECError {}

pub type Result<T> = std::result::Result<T, FECError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FecState {
    Off,
    LowLoss,
    MidLoss,
    HighLoss,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FecMode {
    Adaptive,
    AlwaysOn,
    Performance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FecAlgorithm {
    StripeXor,
    SparseRlnc,
    Cm256,
    ReedSolomon,
}

impl FECError {
    fn code(&self) -> i32 {
        match self {
            FECError::LockPoisoned => -1,
            FECError::ReedSolomon(_) => -2,
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct FECConfig {
    pub redundancy_ratio: f64,
    pub enable_simd: bool,
    pub mode: FecMode,
    pub target_latency_ms: f32,
}

impl Default for FECConfig {
    fn default() -> Self {
        Self {
            redundancy_ratio: 0.1,
            enable_simd: true,
            mode: FecMode::Adaptive,
            target_latency_ms: 50.0,
        }
    }
}

pub struct NetworkMetrics {
    pub packet_loss_rate: f64,
    pub rtt_variation_ms: f64,
    pub bandwidth_mbps: f64,
}

impl Default for NetworkMetrics {
    fn default() -> Self {
        Self {
            packet_loss_rate: 0.0,
            rtt_variation_ms: 0.0,
            bandwidth_mbps: 0.0,
        }
    }
}

pub struct FECPacket {
    pub sequence_number: u32,
    pub is_repair: bool,
    pub data: Vec<u8>,
}


#[derive(Clone, Copy, Default)]
pub struct Statistics {
    pub packets_encoded: u64,
    pub packets_decoded: u64,
    pub repair_packets_generated: u64,
}

pub enum HwPath {
    Vaes512,
    Avx2,
    Sse2,
    Neon,
    Scalar,
}

pub struct HwDispatch;

impl HwDispatch {
    pub fn detect() -> HwPath {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::is_x86_feature_detected!("vaes") {
                return HwPath::Vaes512;
            }
            if std::is_x86_feature_detected!("avx2") {
                return HwPath::Avx2;
            }
            if std::is_x86_feature_detected!("sse2") {
                return HwPath::Sse2;
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("neon") {
                return HwPath::Neon;
            }
        }
        HwPath::Scalar
    }
}

pub struct MetricsSample {
    pub loss: f32,
    pub rtt: f32,
}

pub struct MetricsSampler {
    window: std::collections::VecDeque<MetricsSample>,
}

impl MetricsSampler {
    pub fn new() -> Self {
        Self {
            window: std::collections::VecDeque::with_capacity(32),
        }
    }

    pub fn push(&mut self, loss: f32, rtt: f32) {
        if self.window.len() >= 32 {
            self.window.pop_front();
        }
        self.window.push_back(MetricsSample { loss, rtt });
    }

    pub fn avg_loss(&self) -> f32 {
        if self.window.is_empty() {
            return 0.0;
        }
        let sum: f32 = self.window.iter().map(|s| s.loss).sum();
        sum / self.window.len() as f32
    }
}

pub struct StrategyController {
    state: FecState,
    good_ticks: u32,
}

impl StrategyController {
    pub fn new() -> Self {
        Self {
            state: FecState::Off,
            good_ticks: 0,
        }
    }

    pub fn state(&self) -> FecState {
        self.state
    }

    pub fn update(&mut self, loss: f32, rtt_var: f32, bandwidth: f32) -> FecState {
        const LOSS_ENTER_MID: f32 = 0.05;
        const LOSS_ENTER_HIGH: f32 = 0.25;
        const LOSS_EXIT_MID: f32 = 0.03;
        const LOSS_EXIT_LOW: f32 = 0.01;
        const LOSS_REENABLE: f32 = 0.02;
        const RTT_GOOD: f32 = 5.0;
        const BW_GOOD: f32 = 50.0;
        const GOOD_TICKS: u32 = 30;

        let mut new_state = match (self.state, loss) {
            (FecState::Off, l) if l > LOSS_ENTER_MID => FecState::MidLoss,
            (FecState::LowLoss, l) if l > LOSS_ENTER_HIGH => FecState::HighLoss,
            (FecState::LowLoss, l) if l < LOSS_EXIT_LOW => FecState::Off,
            (FecState::MidLoss, l) if l < LOSS_EXIT_MID => FecState::LowLoss,
            (FecState::HighLoss, l) if l < LOSS_ENTER_HIGH => FecState::MidLoss,
            _ => self.state,
        };

        if loss < LOSS_EXIT_LOW && rtt_var < RTT_GOOD && bandwidth > BW_GOOD {
            self.good_ticks += 1;
            if self.good_ticks >= GOOD_TICKS {
                new_state = FecState::Off;
            }
        } else {
            self.good_ticks = 0;
        }

        if new_state == FecState::Off && self.good_ticks == 0 {
            if loss > LOSS_REENABLE || rtt_var >= RTT_GOOD || bandwidth <= BW_GOOD {
                new_state = if loss > LOSS_ENTER_MID { FecState::MidLoss } else { FecState::LowLoss };
            }
        }

        self.state = new_state;
        self.state
    }
}

pub trait FecScheme {
    fn encode(&self, data: &[u8], seq: u32) -> Result<Vec<FECPacket>>;
    fn decode(&self, packets: &[FECPacket]) -> Result<Vec<u8>>;
}

pub struct StripeXor;

impl FecScheme for StripeXor {
    fn encode(&self, data: &[u8], seq: u32) -> Result<Vec<FECPacket>> {
        let mut parity = vec![0u8; data.len()];
        for (d, p) in data.iter().zip(parity.iter_mut()) {
            *p = *d;
        }
        Ok(vec![
            FECPacket {
                sequence_number: seq,
                is_repair: false,
                data: data.to_vec(),
            },
            FECPacket {
                sequence_number: seq,
                is_repair: true,
                data: parity,
            },
        ])
    }

    fn decode(&self, packets: &[FECPacket]) -> Result<Vec<u8>> {
        if let Some(p) = packets.iter().find(|p| !p.is_repair) {
            return Ok(p.data.clone());
        }
        Ok(Vec::new())
    }
}

pub struct Cm256Scheme;

impl FecScheme for Cm256Scheme {
    fn encode(&self, data: &[u8], seq: u32) -> Result<Vec<FECPacket>> {
        let size = ((data.len() + 63) / 64) * 64;
        let mut shards = vec![vec![0u8; size], vec![0u8; size]];
        shards[0][..data.len()].copy_from_slice(data);
        leopard_codec::encode(&mut shards[..], 1)
            .map_err(|e| FECError::ReedSolomon(format!("{e}")))?;
        Ok(vec![
            FECPacket {
                sequence_number: seq,
                is_repair: false,
                data: shards[0][..data.len()].to_vec(),
            },
            FECPacket {
                sequence_number: seq,
                is_repair: true,
                data: shards[1].clone(),
            },
        ])
    }

    fn decode(&self, packets: &[FECPacket]) -> Result<Vec<u8>> {
        if let Some(p) = packets.iter().find(|p| !p.is_repair) {
            return Ok(p.data.clone());
        }
        Ok(Vec::new())
    }
}

pub struct RlncScheme;

impl FecScheme for RlncScheme {
    fn encode(&self, data: &[u8], seq: u32) -> Result<Vec<FECPacket>> {
        let mut encoder = rlnc::full::encoder::Encoder::new(data.to_vec(), 1)
            .map_err(|e| FECError::ReedSolomon(format!("{e:?}")))?;
        let repair = encoder.code(&mut rand09::rng());
        Ok(vec![
            FECPacket {
                sequence_number: seq,
                is_repair: false,
                data: data.to_vec(),
            },
            FECPacket {
                sequence_number: seq,
                is_repair: true,
                data: repair,
            },
        ])
    }

    fn decode(&self, packets: &[FECPacket]) -> Result<Vec<u8>> {
        if let Some(p) = packets.iter().find(|p| !p.is_repair) {
            return Ok(p.data.clone());
        }
        if let Some(p) = packets.iter().find(|p| p.is_repair) {
            let piece_len = p.data.len() - 1;
            let mut decoder = rlnc::full::decoder::Decoder::new(piece_len, 1)
                .map_err(|e| FECError::ReedSolomon(format!("{e:?}")))?;
            decoder
                .decode(&p.data)
                .map_err(|e| FECError::ReedSolomon(format!("{e:?}")))?;
            return decoder
                .get_decoded_data()
                .map_err(|e| FECError::ReedSolomon(format!("{e:?}")));
        }
        Ok(Vec::new())
    }
}

pub struct RsScheme;

impl FecScheme for RsScheme {
    fn encode(&self, data: &[u8], seq: u32) -> Result<Vec<FECPacket>> {
        let r = ReedSolomon::new(1, 1).map_err(|e| FECError::ReedSolomon(e.to_string()))?;
        let mut shards = vec![data.to_vec(), vec![0u8; data.len()]];
        r.encode(&mut shards)
            .map_err(|e| FECError::ReedSolomon(e.to_string()))?;
        Ok(vec![
            FECPacket {
                sequence_number: seq,
                is_repair: false,
                data: shards[0].clone(),
            },
            FECPacket {
                sequence_number: seq,
                is_repair: true,
                data: shards[1].clone(),
            },
        ])
    }

    fn decode(&self, packets: &[FECPacket]) -> Result<Vec<u8>> {
        if let Some(p) = packets.iter().find(|p| !p.is_repair) {
            return Ok(p.data.clone());
        }
        Ok(Vec::new())
    }
}

pub struct EncoderCore {
    scheme: Box<dyn FecScheme + Send + Sync>,
}

impl EncoderCore {
    pub fn new(algo: FecAlgorithm) -> Self {
        let scheme: Box<dyn FecScheme + Send + Sync> = match algo {
            FecAlgorithm::StripeXor => Box::new(StripeXor),
            FecAlgorithm::SparseRlnc => Box::new(RlncScheme),
            FecAlgorithm::Cm256 => Box::new(Cm256Scheme),
            FecAlgorithm::ReedSolomon => Box::new(RsScheme),
        };
        Self { scheme }
    }

    pub fn encode(&self, data: &[u8], seq: u32) -> Result<Vec<FECPacket>> {
        self.scheme.encode(data, seq)
    }

    pub fn set_algorithm(&mut self, algo: FecAlgorithm) {
        self.scheme = match algo {
            FecAlgorithm::StripeXor => Box::new(StripeXor),
            FecAlgorithm::SparseRlnc => Box::new(RlncScheme),
            FecAlgorithm::Cm256 => Box::new(Cm256Scheme),
            FecAlgorithm::ReedSolomon => Box::new(RsScheme),
        };
    }
}

pub struct DecoderCore {
    scheme: Box<dyn FecScheme + Send + Sync>,
}

impl DecoderCore {
    pub fn new(algo: FecAlgorithm) -> Self {
        let scheme: Box<dyn FecScheme + Send + Sync> = match algo {
            FecAlgorithm::StripeXor => Box::new(StripeXor),
            FecAlgorithm::SparseRlnc => Box::new(RlncScheme),
            FecAlgorithm::Cm256 => Box::new(Cm256Scheme),
            FecAlgorithm::ReedSolomon => Box::new(RsScheme),
        };
        Self { scheme }
    }

    pub fn decode(&self, packets: &[FECPacket]) -> Result<Vec<u8>> {
        self.scheme.decode(packets)
    }

    pub fn set_algorithm(&mut self, algo: FecAlgorithm) {
        self.scheme = match algo {
            FecAlgorithm::StripeXor => Box::new(StripeXor),
            FecAlgorithm::SparseRlnc => Box::new(RlncScheme),
            FecAlgorithm::Cm256 => Box::new(Cm256Scheme),
            FecAlgorithm::ReedSolomon => Box::new(RsScheme),
        };
    }
}

pub struct GaloisField;

impl GaloisField {
    fn multiply(a: u8, b: u8) -> u8 {
        GF_LOG.with(|log| {
            GF_EXP.with(|exp| {
                if a == 0 || b == 0 {
                    0
                } else {
                    let la = log[a as usize];
                    let lb = log[b as usize];
                    exp[((la as u16 + lb as u16) % 255) as usize]
                }
            })
        })
    }

    fn multiply_vector_scalar(dst: &mut [u8], src: &[u8], scalar: u8) {
        if scalar == 0 {
            for d in dst.iter_mut() {
                *d = 0;
            }
            return;
        }
        if scalar == 1 {
            dst.copy_from_slice(src);
            return;
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            if is_x86_feature_detected!("avx2") {
                return multiply_vector_scalar_avx2(dst, src, scalar);
            }
        }
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        unsafe {
            return multiply_vector_scalar_neon(dst, src, scalar);
        }
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d = Self::multiply(*s, scalar);
        }
    }

    fn inverse(a: u8) -> u8 {
        if a == 0 {
            0
        } else {
            GF_LOG.with(|log| GF_EXP.with(|exp| exp[(255 - log[a as usize]) as usize]))
        }
    }
}

thread_local! {
    static GF_EXP: [u8;256] = {
        let mut exp = [0u8;256];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            x <<= 1;
            if x & 0x100 != 0 { x ^= 0x11d; }
        }
        exp[255] = exp[0];
        exp
    };
    static GF_LOG: [u8;256] = {
        let mut log = [0u8;256];
        let mut x: u16 = 1;
        for i in 0..255 {
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 { x ^= 0x11d; }
        }
        log
    };
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn multiply_vector_scalar_avx2(dst: &mut [u8], src: &[u8], scalar: u8) {
    use std::arch::x86_64::*;
    let len = dst.len();
    let mut i = 0;
    while i + 32 <= len {
        let mut buf = [0u8; 32];
        ptr::copy_nonoverlapping(src.as_ptr().add(i), buf.as_mut_ptr(), 32);
        for j in 0..32 {
            buf[j] = GaloisField::multiply(buf[j], scalar);
        }
        let v = _mm256_loadu_si256(buf.as_ptr() as *const __m256i);
        _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, v);
        i += 32;
    }
    for j in i..len {
        dst[j] = GaloisField::multiply(src[j], scalar);
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
unsafe fn multiply_vector_scalar_neon(dst: &mut [u8], src: &[u8], scalar: u8) {
    use std::arch::aarch64::*;
    let len = dst.len();
    let mut i = 0;
    while i + 16 <= len {
        let mut buf = [0u8; 16];
        ptr::copy_nonoverlapping(src.as_ptr().add(i), buf.as_mut_ptr(), 16);
        for j in 0..16 {
            buf[j] = GaloisField::multiply(buf[j], scalar);
        }
        let v = vld1q_u8(buf.as_ptr());
        vst1q_u8(dst.as_mut_ptr().add(i), v);
        i += 16;
    }
    for j in i..len {
        dst[j] = GaloisField::multiply(src[j], scalar);
    }
}

pub struct FECModule {
    config: FECConfig,
    stats: Mutex<Statistics>,
    encoder: EncoderCore,
    decoder: DecoderCore,
    controller: StrategyController,
    hw: HwPath,
    state: FecState,
}

impl FECModule {
    pub fn new(config: FECConfig) -> Self {
        let hw = HwDispatch::detect();
        let algo = FecAlgorithm::StripeXor;
        Self {
            config,
            stats: Mutex::new(Statistics::default()),
            encoder: EncoderCore::new(algo),
            decoder: DecoderCore::new(algo),
            controller: StrategyController::new(),
            hw,
            state: FecState::Off,
        }
    }

    fn algorithm_for_state(&self, state: FecState) -> FecAlgorithm {
        match state {
            FecState::Off => FecAlgorithm::StripeXor,
            FecState::LowLoss => FecAlgorithm::StripeXor,
            FecState::MidLoss => FecAlgorithm::SparseRlnc,
            FecState::HighLoss => match self.hw {
                HwPath::Scalar => FecAlgorithm::ReedSolomon,
                _ => FecAlgorithm::Cm256,
            },
        }
    }

    fn set_state(&mut self, state: FecState) {
        self.state = state;
        let algo = self.algorithm_for_state(state);
        self.encoder.set_algorithm(algo);
        self.decoder.set_algorithm(algo);
    }

    pub fn encode_packet(&self, data: &[u8], sequence_number: u32) -> Result<Vec<FECPacket>> {
        let mut stats = self.stats.lock().map_err(|_| FECError::LockPoisoned)?;
        stats.packets_encoded += 1;
        let repairs = match self.state {
            FecState::Off => 0,
            FecState::LowLoss => 1,
            FecState::MidLoss => 2,
            FecState::HighLoss => 3,
        };
        if repairs == 0 {
            return Ok(vec![FECPacket {
                sequence_number,
                is_repair: false,
                data: data.to_vec(),
            }]);
        }
        let mut packets = Vec::with_capacity(1 + repairs);
        let mut first = self.encoder.encode(data, sequence_number)?;
        packets.push(first.remove(0));
        packets.extend(first.into_iter().filter(|p| p.is_repair));
        for _ in 1..repairs {
            let mut extra = self.encoder.encode(data, sequence_number)?;
            if let Some(rp) = extra.into_iter().find(|p| p.is_repair) {
                packets.push(rp);
            }
        }
        stats.repair_packets_generated += repairs as u64;
        Ok(packets)
    }

    pub fn decode(&self, packets: &[FECPacket]) -> Result<Vec<u8>> {
        if packets.is_empty() {
            return Ok(Vec::new());
        }
        let mut stats = self.stats.lock().map_err(|_| FECError::LockPoisoned)?;
        stats.packets_decoded += 1;
        self.decoder.decode(packets)
    }

    pub fn update_network_metrics(&mut self, metrics: NetworkMetrics) {
        let mut state = match self.config.mode {
            FecMode::Performance => FecState::Off,
            FecMode::AlwaysOn => FecState::LowLoss,
            FecMode::Adaptive => self.controller.update(
                metrics.packet_loss_rate as f32,
                metrics.rtt_variation_ms as f32,
                metrics.bandwidth_mbps as f32,
            ),
        };
        self.set_state(state);
        self.config.redundancy_ratio = match self.state {
            FecState::Off => 0.0,
            FecState::LowLoss => 0.2,
            FecState::MidLoss => 0.5,
            FecState::HighLoss => 1.0,
        };
    }

    pub fn get_statistics(&self) -> Result<Statistics> {
        Ok(*self.stats.lock().map_err(|_| FECError::LockPoisoned)?)
    }
}

