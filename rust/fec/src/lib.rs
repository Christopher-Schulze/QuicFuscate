use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use serde::{Deserialize, Serialize};
use reed_solomon_erasure::galois_8::ReedSolomon;
use rand::Rng;

#[derive(Debug, Error)]
pub enum FECError {
    #[error("mutex poisoned")]
    LockPoisoned,
    #[error("reed-solomon error: {0}")]
    ReedSolomon(String),
}

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
    pub memory_pool_block_size: usize,
    pub memory_pool_initial_blocks: usize,
    pub mode: FecMode,
    pub target_latency_ms: f32,
}

impl Default for FECConfig {
    fn default() -> Self {
        Self {
            redundancy_ratio: 0.1,
            enable_simd: true,
            memory_pool_block_size: 2048,
            memory_pool_initial_blocks: 32,
            mode: FecMode::Adaptive,
            target_latency_ms: 50.0,
        }
    }
}

pub struct NetworkMetrics {
    pub packet_loss_rate: f64,
}

impl Default for NetworkMetrics {
    fn default() -> Self {
        Self {
            packet_loss_rate: 0.0,
        }
    }
}

pub struct FECPacket {
    pub sequence_number: u32,
    pub is_repair: bool,
    pub data: Vec<u8>,
}

pub struct MemoryPool {
    block_size: usize,
    free: Mutex<Vec<Vec<u8>>>,
}

impl MemoryPool {
    pub fn new(block_size: usize, initial: usize) -> Self {
        let mut blocks = Vec::with_capacity(initial);
        for _ in 0..initial {
            blocks.push(vec![0u8; block_size]);
        }
        Self {
            block_size,
            free: Mutex::new(blocks),
        }
    }

    pub fn allocate(&self) -> Result<Vec<u8>> {
        let mut guard = self.free.lock().map_err(|_| FECError::LockPoisoned)?;
        Ok(guard.pop().unwrap_or_else(|| vec![0u8; self.block_size]))
    }

    pub fn deallocate(&self, mut block: Vec<u8>) -> Result<()> {
        block.clear();
        let mut guard = self.free.lock().map_err(|_| FECError::LockPoisoned)?;
        guard.push(block);
        Ok(())
    }
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
        Self { window: std::collections::VecDeque::with_capacity(32) }
    }

    pub fn push(&mut self, loss: f32, rtt: f32) {
        if self.window.len() >= 32 {
            self.window.pop_front();
        }
        self.window.push_back(MetricsSample { loss, rtt });
    }

    pub fn avg_loss(&self) -> f32 {
        if self.window.is_empty() { return 0.0; }
        let sum: f32 = self.window.iter().map(|s| s.loss).sum();
        sum / self.window.len() as f32
    }
}

pub struct StrategyController {
    state: FecState,
}

impl StrategyController {
    pub fn new() -> Self {
        Self { state: FecState::Off }
    }

    pub fn state(&self) -> FecState { self.state }

    pub fn update(&mut self, loss: f32) -> FecState {
        const LOSS_ENTER_MID: f32 = 0.05;
        const LOSS_ENTER_HIGH: f32 = 0.25;
        const LOSS_EXIT_MID: f32 = 0.03;
        const LOSS_EXIT_LOW: f32 = 0.01;
        self.state = match (self.state, loss) {
            (FecState::Off, l) if l > LOSS_ENTER_MID => FecState::MidLoss,
            (FecState::LowLoss, l) if l > LOSS_ENTER_HIGH => FecState::HighLoss,
            (FecState::LowLoss, l) if l < LOSS_EXIT_LOW => FecState::Off,
            (FecState::MidLoss, l) if l < LOSS_EXIT_MID => FecState::LowLoss,
            (FecState::HighLoss, l) if l < LOSS_ENTER_HIGH => FecState::MidLoss,
            _ => self.state,
        };
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
            FECPacket { sequence_number: seq, is_repair: false, data: data.to_vec() },
            FECPacket { sequence_number: seq, is_repair: true, data: parity },
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
        let r = ReedSolomon::new(1, 1).map_err(|e| FECError::ReedSolomon(e.to_string()))?;
        let mut shards = vec![data.to_vec(), vec![0u8; data.len()]];
        r.encode(&mut shards).map_err(|e| FECError::ReedSolomon(e.to_string()))?;
        Ok(vec![
            FECPacket { sequence_number: seq, is_repair: false, data: shards[0].clone() },
            FECPacket { sequence_number: seq, is_repair: true, data: shards[1].clone() },
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
        let coeff: u8 = rand::thread_rng().gen_range(1..=255);
        let mut repair = vec![0u8; data.len()];
        GaloisField::multiply_vector_scalar(&mut repair, data, coeff);
        let mut repair_packet = Vec::with_capacity(data.len() + 1);
        repair_packet.push(coeff);
        repair_packet.extend_from_slice(&repair);
        Ok(vec![
            FECPacket { sequence_number: seq, is_repair: false, data: data.to_vec() },
            FECPacket { sequence_number: seq, is_repair: true, data: repair_packet },
        ])
    }

    fn decode(&self, packets: &[FECPacket]) -> Result<Vec<u8>> {
        if let Some(p) = packets.iter().find(|p| !p.is_repair) {
            return Ok(p.data.clone());
        }
        if let Some(p) = packets.iter().find(|p| p.is_repair) {
            if p.data.is_empty() {
                return Ok(Vec::new());
            }
            let coeff = p.data[0];
            if coeff == 0 {
                return Ok(Vec::new());
            }
            let inv = GaloisField::inverse(coeff);
            let mut out = vec![0u8; p.data.len() - 1];
            GaloisField::multiply_vector_scalar(&mut out, &p.data[1..], inv);
            return Ok(out);
        }
        Ok(Vec::new())
    }
}

pub struct RsScheme;

impl FecScheme for RsScheme {
    fn encode(&self, data: &[u8], seq: u32) -> Result<Vec<FECPacket>> {
        let r = ReedSolomon::new(1, 1).map_err(|e| FECError::ReedSolomon(e.to_string()))?;
        let mut shards = vec![data.to_vec(), vec![0u8; data.len()]];
        r.encode(&mut shards).map_err(|e| FECError::ReedSolomon(e.to_string()))?;
        Ok(vec![
            FECPacket { sequence_number: seq, is_repair: false, data: shards[0].clone() },
            FECPacket { sequence_number: seq, is_repair: true, data: shards[1].clone() },
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
    pool: Arc<MemoryPool>,
    stats: Mutex<Statistics>,
    encoder: EncoderCore,
    decoder: DecoderCore,
    controller: StrategyController,
    hw: HwPath,
    state: FecState,
}

impl FECModule {
    pub fn new(config: FECConfig) -> Self {
        let pool = Arc::new(MemoryPool::new(
            config.memory_pool_block_size,
            config.memory_pool_initial_blocks,
        ));
        let hw = HwDispatch::detect();
        let algo = FecAlgorithm::StripeXor;
        Self {
            config,
            pool,
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

    pub fn encode_packet(
        &self,
        data: &[u8],
        sequence_number: u32,
    ) -> Result<Vec<FECPacket>> {
        let mut stats = self.stats.lock().map_err(|_| FECError::LockPoisoned)?;
        stats.packets_encoded += 1;
        if self.state == FecState::Off {
            return Ok(vec![FECPacket { sequence_number, is_repair: false, data: data.to_vec() }]);
        }
        self.encoder.encode(data, sequence_number)
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
            FecMode::Adaptive => self.controller.update(metrics.packet_loss_rate as f32),
        };
        self.set_state(state);
    }

    pub fn get_statistics(&self) -> Result<Statistics> {
        Ok(*self.stats.lock().map_err(|_| FECError::LockPoisoned)?)
    }
}

// --- FFI ---

#[no_mangle]
pub extern "C" fn fec_module_init() -> *mut FECModule {
    Box::into_raw(Box::new(FECModule::new(FECConfig::default())))
}

#[no_mangle]
pub extern "C" fn fec_module_cleanup(handle: *mut FECModule) {
    if handle.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(handle)); }
}

#[no_mangle]
pub extern "C" fn fec_module_encode(
    handle: *mut FECModule,
    data: *const u8,
    len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if handle.is_null() || data.is_null() {
        return ptr::null_mut();
    }
    let mod_ref = unsafe { &mut *handle };
    let slice = unsafe { slice::from_raw_parts(data, len) };
    if let Ok(packets) = mod_ref.encode_packet(slice, 0) {
        if let Some(pkt) = packets.first() {
            unsafe {
                *out_len = pkt.data.len();
            }
            if let Ok(mut buf) = mod_ref.pool.allocate() {
                let size = pkt.data.len();
                buf.resize(size, 0);
                buf[..size].copy_from_slice(&pkt.data);
                let ptr = buf.as_mut_ptr();
                std::mem::forget(buf);
                return ptr;
            }
        }
    }
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn fec_module_decode(
    handle: *mut FECModule,
    data: *const u8,
    len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if handle.is_null() || data.is_null() {
        return ptr::null_mut();
    }
    let mod_ref = unsafe { &mut *handle };
    let slice = unsafe { slice::from_raw_parts(data, len) };
    let pkt = FECPacket {
        sequence_number: 0,
        is_repair: false,
        data: slice.to_vec(),
    };
    if let Ok(result) = mod_ref.decode(&[pkt]) {
        unsafe {
            *out_len = result.len();
        }
        if let Ok(mut buf) = mod_ref.pool.allocate() {
            let size = result.len();
            buf.resize(size, 0);
            buf[..size].copy_from_slice(&result);
            let ptr = buf.as_mut_ptr();
            std::mem::forget(buf);
            return ptr;
        }
    }
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn fec_module_free(handle: *mut FECModule, ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    if handle.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, len, len);
        }
        return;
    }
    let mod_ref = unsafe { &mut *handle };
    let cap = mod_ref.config.memory_pool_block_size;
    unsafe {
        let buf = Vec::from_raw_parts(ptr, len, cap);
        let _ = mod_ref.pool.deallocate(buf);
    }
}

#[no_mangle]
pub extern "C" fn fec_module_set_redundancy(handle: *mut FECModule, r: f64) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let mod_ref = unsafe { &mut *handle };
    mod_ref.config.redundancy_ratio = r;
    0
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct StatFFI {
    packets_encoded: u64,
    packets_decoded: u64,
    repair_packets_generated: u64,
}

#[no_mangle]
pub extern "C" fn fec_module_get_statistics(handle: *mut FECModule, buf: *mut StatFFI) -> i32 {
    if handle.is_null() || buf.is_null() {
        return -1;
    }
    let mod_ref = unsafe { &mut *handle };
    if let Ok(stats) = mod_ref.get_statistics() {
        unsafe {
            *buf = StatFFI {
                packets_encoded: stats.packets_encoded,
                packets_decoded: stats.packets_decoded,
                repair_packets_generated: stats.repair_packets_generated,
            };
        }
        return 0;
    }
    -1
}


pub fn fec_module_init_stub() -> *mut FECModule {
    std::ptr::null_mut()
}

pub fn fec_module_cleanup_stub(_handle: *mut FECModule) {}

pub fn fec_module_encode_stub(
    _handle: *mut FECModule,
    data: &[u8],
) -> Vec<u8> {
    data.to_vec()
}

pub fn fec_module_decode_stub(
    _handle: *mut FECModule,
    data: &[u8],
) -> Vec<u8> {
    data.to_vec()
}

pub fn fec_module_free_stub(_handle: *mut FECModule, _ptr: *mut u8, _len: usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_via_ffi() {
        let handle = fec_module_init();
        assert!(!handle.is_null());
        let msg = b"hello";
        let mut out_len = 0usize;
        let enc_ptr = fec_module_encode(handle, msg.as_ptr(), msg.len(), &mut out_len as *mut usize);
        assert!(!enc_ptr.is_null());
        let enc_slice = unsafe { std::slice::from_raw_parts(enc_ptr, out_len) };
        let enc = enc_slice.to_vec();
        fec_module_free(handle, enc_ptr, out_len);
        let mut dec_len = 0usize;
        let dec_ptr = fec_module_decode(handle, enc.as_ptr(), enc.len(), &mut dec_len as *mut usize);
        let dec_slice = unsafe { std::slice::from_raw_parts(dec_ptr, dec_len) };
        let dec = dec_slice.to_vec();
        fec_module_free(handle, dec_ptr, dec_len);
        fec_module_cleanup(handle);
        assert_eq!(dec, msg);
    }
}
