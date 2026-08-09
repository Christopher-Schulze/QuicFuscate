use crate::env_utils::EnvSnapshot;
use crate::optimize::compress::classify as classify_bytes;
use crate::optimize::{CpuProfile, FeatureDetector, MemoryPool, PooledBlock};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use zstd::stream::raw::CParameter;

/// Configuration parameters for the zstd compression pipeline.
pub struct CompressionConfig {
    /// Minimum payload size in bytes to consider for compression.
    pub min_len: usize,
    /// Maximum zstd compression level (higher = better ratio, more CPU).
    pub max_level: i32,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self { min_len: 256, max_level: 5 }
    }
}

/// Manages zstd compression/decompression with link-aware heuristics and SIMD entropy gating.
pub struct CompressionManager {
    cfg: CompressionConfig,
}

/// Statistical analysis of payload byte distribution for compression decisions.
#[derive(Clone, Debug, Default)]
pub struct CompressionAnalysis {
    /// Total analyzed byte count.
    pub len: usize,
    /// Count of printable ASCII bytes (0x20..0x7E).
    pub ascii_bytes: u32,
    /// Count of newline (0x0A) bytes.
    pub newline_bytes: u32,
    /// Count of carriage return (0x0D) bytes.
    pub carriage_bytes: u32,
    /// Count of tab (0x09) bytes.
    pub tab_bytes: u32,
    /// Count of null (0x00) bytes.
    pub null_bytes: u32,
    /// Count of high bytes (0x80..0xFF).
    pub high_bytes: u32,
    /// Shannon entropy in bits per byte (0.0 = uniform, 8.0 = maximum).
    pub entropy_bits_per_byte: f64,
    /// Total 64-byte chunks analyzed.
    pub chunk_total: u32,
    /// Number of consecutive repeated chunk hashes.
    pub chunk_repeated: u32,
    /// Highest frequency in the 8-bin chunk hash histogram.
    pub chunk_max_bin: u32,
}

impl CompressionAnalysis {
    /// Fraction of bytes that are printable ASCII.
    pub fn ascii_ratio(&self) -> f32 {
        if self.len == 0 {
            return 0.0;
        }
        self.ascii_bytes as f32 / self.len as f32
    }

    /// Fraction of bytes that are newline or carriage return characters.
    pub fn newline_ratio(&self) -> f32 {
        if self.len == 0 {
            return 0.0;
        }
        (self.newline_bytes + self.carriage_bytes) as f32 / self.len as f32
    }

    /// Fraction of bytes that are null (0x00).
    pub fn null_ratio(&self) -> f32 {
        if self.len == 0 {
            return 0.0;
        }
        self.null_bytes as f32 / self.len as f32
    }

    /// Fraction of bytes in the high range (0x80..0xFF).
    pub fn high_ratio(&self) -> f32 {
        if self.len == 0 {
            return 0.0;
        }
        self.high_bytes as f32 / self.len as f32
    }

    /// Fraction of consecutive chunk pairs with identical hashes.
    pub fn chunk_repeat_ratio(&self) -> f32 {
        if self.chunk_total == 0 {
            return 0.0;
        }
        self.chunk_repeated as f32 / self.chunk_total as f32
    }

    /// Ratio of the most frequent hash bin to total chunks (measures distribution skew).
    pub fn chunk_skew(&self) -> f32 {
        if self.chunk_total == 0 {
            return 0.0;
        }
        self.chunk_max_bin as f32 / self.chunk_total as f32
    }

    /// Returns true if the byte distribution suggests text-like content (compressible).
    pub fn is_textual(&self) -> bool {
        if self.len == 0 {
            return false;
        }
        let ascii = self.ascii_ratio();
        if ascii >= 0.75 {
            return true;
        }
        let entropy = self.entropy_bits_per_byte;
        let newline = self.newline_ratio();
        let high = self.high_ratio();

        (entropy <= 7.0 && ascii >= 0.55 && high <= 0.35)
            || (newline >= 0.01 && ascii >= 0.5 && high <= 0.4)
    }

    /// Emit telemetry counters for this analysis (preprocessing statistics).
    pub fn record_telemetry(&self) {
        use crate::optimize::telemetry;

        telemetry::COMPRESS_PREPROC_CALLS.inc();
        telemetry::COMPRESS_PREPROC_ASCII_BYTES.inc_by(self.ascii_bytes as u64);
        telemetry::COMPRESS_PREPROC_NEWLINES
            .inc_by((self.newline_bytes + self.carriage_bytes) as u64);
        telemetry::COMPRESS_PREPROC_NULLS.inc_by(self.null_bytes as u64);
        telemetry::COMPRESS_PREPROC_HIGH_BYTES.inc_by(self.high_bytes as u64);
        telemetry::COMPRESS_PREPROC_CHUNKS.inc_by(self.chunk_total as u64);
        telemetry::COMPRESS_PREPROC_CHUNK_REPEATS.inc_by(self.chunk_repeated as u64);

        if self.is_textual() {
            telemetry::COMPRESS_PREPROC_TEXTUAL.inc();
        } else {
            telemetry::COMPRESS_PREPROC_BINARY.inc();
        }
    }

    /// Analyze up to `sample_len` bytes from the beginning of `data` (no chunk metrics).
    pub fn from_sample(data: &[u8], sample_len: usize) -> Self {
        let slice = if data.len() > sample_len { &data[..sample_len] } else { data };
        Self::from_slice(slice, false)
    }

    /// Analyze the full payload including chunk repetition metrics.
    pub fn from_full(data: &[u8]) -> Self {
        Self::from_slice(data, true)
    }

    fn from_slice(data: &[u8], compute_chunks: bool) -> Self {
        if data.is_empty() {
            return Self::default();
        }

        let counters = classify_bytes(data);
        let entropy = estimate_entropy_bits_per_byte(data);
        let (chunk_total, chunk_repeated, chunk_max_bin) =
            if compute_chunks { compute_chunk_metrics(data) } else { (0, 0, 0) };

        CompressionAnalysis {
            len: counters.len,
            ascii_bytes: counters.ascii_printable,
            newline_bytes: counters.newline,
            carriage_bytes: counters.carriage_return,
            tab_bytes: counters.tab,
            null_bytes: counters.nulls,
            high_bytes: counters.high_bytes,
            entropy_bits_per_byte: entropy,
            chunk_total,
            chunk_repeated,
            chunk_max_bin,
        }
    }
}

impl CompressionManager {
    /// Create a new compression manager with the given configuration.
    pub fn new(cfg: CompressionConfig) -> Self {
        Self { cfg }
    }

    /// Heuristic: compress only if size >= min_len and link conditions favor it.
    /// Note: Entropy checks require access to payload bytes; callers may use
    /// `looks_textual()` prior to calling when data is available.
    pub fn should_compress(&self, len: usize, rtt_ms: f32, loss: f32, bw_bps: u64) -> bool {
        crate::optimize::telemetry::COMPRESS_DECISIONS_TOTAL.inc();
        if len < self.cfg.min_len {
            crate::optimize::telemetry::COMPRESS_DECISIONS_SKIP_LEN.inc();
            return false;
        }
        // Prefer compression on slower links or high RTT, avoid on high loss.
        let slow_link = bw_bps > 0 && bw_bps < 10_000_000; // <10 Mbps
        let high_rtt = rtt_ms > 80.0;
        let loss_gate = loss < 0.15; // save CPU on very lossy links
        if !loss_gate {
            crate::optimize::telemetry::COMPRESS_DECISIONS_SKIP_LOSS.inc();
            return false;
        }
        let allow = slow_link || high_rtt;
        if allow {
            crate::optimize::telemetry::COMPRESS_DECISIONS_ALLOW.inc();
            true
        } else {
            crate::optimize::telemetry::COMPRESS_DECISIONS_SKIP_PROFILE.inc();
            false
        }
    }

    /// Lightweight textuality heuristic with centralized SIMD entropy calculation.
    pub fn looks_textual(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let analysis = CompressionAnalysis::from_sample(data, 1024);
        if analysis.is_textual() {
            crate::optimize::telemetry::ENTROPY_TEXTUAL_SEEN.inc();
            true
        } else {
            crate::optimize::telemetry::ENTROPY_SKIP.inc();
            false
        }
    }

    /// Compress using zstd (multi-threaded when available) into a pooled block.
    ///
    /// The returned block is an RAII owner and is returned to `pool` on drop, including when a
    /// caller propagates an error after receiving it.
    pub fn compress_to_pool(
        &self,
        pool: &Arc<MemoryPool>,
        data: &[u8],
    ) -> Option<(PooledBlock, usize)> {
        crate::optimize::telemetry::COMPRESS_ATTEMPTS.inc();
        let analysis = CompressionAnalysis::from_full(data);
        analysis.record_telemetry();
        let mut out = PooledBlock::new(Arc::clone(pool));
        crate::optimize::telemetry::BODY_POOL_ALLOCS.inc();
        // Reserve space for a simple header: 1 byte magic + 4 bytes orig len
        if out.len() < 5 {
            return None;
        }
        out[0] = 0x5A; // 'Z'
        let orig_len = data.len() as u32;
        crate::optimize::telemetry::COMPRESS_BYTES_IN.inc_by(orig_len as u64);
        out[1..5].copy_from_slice(&orig_len.to_be_bytes());
        let mut compressor = match zstd::bulk::Compressor::new(self.cfg.max_level) {
            Ok(compressor) => compressor,
            Err(_) => return None,
        };
        tune_compressor_with_analysis(&mut compressor, data.len(), &analysis, self.cfg.max_level);
        let compressed_len = match compressor.compress_to_buffer(data, &mut out[5..]) {
            Ok(len) => len,
            Err(_) => return None,
        };
        crate::optimize::telemetry::COMPRESS_SUCCESS.inc();
        crate::optimize::telemetry::COMPRESS_BYTES_OUT.inc_by(compressed_len as u64);
        Some((out, 5 + compressed_len))
    }

    /// Decompress a pooled buffer created by [`Self::compress_to_pool`].
    ///
    /// The returned block is an RAII owner and is returned to `pool` on drop.
    pub fn decompress_to_pool(
        &self,
        pool: &Arc<MemoryPool>,
        data: &[u8],
    ) -> Option<(PooledBlock, usize)> {
        if data.len() < 5 || data[0] != 0x5A {
            return None;
        }
        let mut len_buf = [0u8; 4];
        len_buf.copy_from_slice(&data[1..5]);
        let orig_len = u32::from_be_bytes(len_buf) as usize;
        let mut out = PooledBlock::new(Arc::clone(pool));
        if out.len() < orig_len {
            return None;
        }
        let n = zstd::bulk::decompress_to_buffer(&data[5..], &mut out[..orig_len]).ok()?;
        (n == orig_len).then_some((out, n))
    }
}

fn tune_compressor_with_analysis(
    compressor: &mut zstd::bulk::Compressor<'_>,
    input_len: usize,
    analysis: &CompressionAnalysis,
    max_level: i32,
) {
    fn set_param_best_effort(
        compressor: &mut zstd::bulk::Compressor<'_>,
        parameter: CParameter,
        label: &'static str,
    ) {
        if let Err(e) = compressor.set_parameter(parameter) {
            log::debug!("Zstd encoder parameter '{}' rejected: {}", label, e);
        }
    }

    let threads = std::thread::available_parallelism().map(|v| v.get()).unwrap_or(1);
    if threads > 1 && input_len >= 64 * 1024 {
        let workers = threads.min(8) as u32;
        set_param_best_effort(compressor, CParameter::NbWorkers(workers), "NbWorkers");
    }

    let textual = analysis.is_textual();
    if input_len >= 128 * 1024 || analysis.chunk_repeat_ratio() >= 0.35 {
        set_param_best_effort(
            compressor,
            CParameter::EnableLongDistanceMatching(true),
            "EnableLongDistanceMatching",
        );
    }

    let profile = FeatureDetector::instance().profile();
    match profile {
        CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => {
            // Wider vectors benefit from larger target block sizes
            set_param_best_effort(compressor, CParameter::TargetLength(8192), "TargetLength");
        }
        CpuProfile::X86_P2a | CpuProfile::X86_P2b => {
            let target = if textual { 4096 } else { 6144 };
            set_param_best_effort(compressor, CParameter::TargetLength(target), "TargetLength");
        }
        CpuProfile::ARM_A2 | CpuProfile::Apple_M => {
            let target = if textual { 3072 } else { 4096 };
            set_param_best_effort(compressor, CParameter::TargetLength(target), "TargetLength");
        }
        _ => {
            let target = if textual { 2048 } else { 3072 };
            set_param_best_effort(compressor, CParameter::TargetLength(target), "TargetLength");
        }
    }

    if textual && analysis.null_ratio() < 0.01 {
        set_param_best_effort(
            compressor,
            CParameter::CompressionLevel(max_level.max(6)),
            "CompressionLevel",
        );
    }
}

/// Policy controlling which payloads are compressed and at what level.
#[derive(Clone, Debug)]
pub struct CompressionPolicy {
    /// Master switch for compression.
    pub enabled: bool,
    /// Minimum payload size to attempt compression.
    pub min_len: usize,
    /// Zstd compression level.
    pub level: i32,
    /// MIME type patterns allowed for compression (e.g. "text/*").
    pub allow: Vec<String>,
    /// MIME type patterns denied from compression (e.g. "image/*").
    pub deny: Vec<String>,
}

impl Default for CompressionPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            min_len: 256,
            level: 5,
            allow: vec!["text/*".into(), "application/json".into()],
            deny: vec![
                "image/*".into(),
                "video/*".into(),
                "audio/*".into(),
                "application/zip".into(),
            ],
        }
    }
}

static GLOBAL_POLICY: OnceLock<Mutex<CompressionPolicy>> = OnceLock::new();

/// Return the global compression policy (lazily initialized from environment).
pub fn global_policy() -> CompressionPolicy {
    let environment = EnvSnapshot::capture();
    global_policy_with_snapshot(&environment)
}

/// Return the global compression policy using the caller's immutable environment generation.
pub(crate) fn global_policy_with_snapshot(environment: &EnvSnapshot) -> CompressionPolicy {
    GLOBAL_POLICY
        .get_or_init(|| Mutex::new(CompressionPolicy::from_env_with_snapshot(environment)))
        .lock()
        .unwrap_or_else(|p| {
            // Recover from poisoned mutex
            p.into_inner()
        })
        .clone()
}

/// Replace the global compression policy at runtime.
pub fn set_global_policy(pol: CompressionPolicy) {
    if let Some(m) = GLOBAL_POLICY.get() {
        if let Ok(mut g) = m.lock() {
            *g = pol;
        }
    } else if GLOBAL_POLICY.set(Mutex::new(pol)).is_err() {
        log::debug!("Global compression policy already initialized");
    }
}

impl CompressionPolicy {
    /// Return whether a content type is eligible for compression.
    ///
    /// A missing content type remains eligible for the caller's textuality
    /// fallback. Explicit content types must match an allow pattern and must
    /// not match a deny pattern; deny always wins.
    pub fn allows_content_type(&self, content_type: Option<&str>) -> bool {
        let Some(content_type) = content_type else {
            return true;
        };
        let allowed = self.allow.iter().any(|pattern| mime_matches(pattern, content_type));
        let denied = self.deny.iter().any(|pattern| mime_matches(pattern, content_type));
        allowed && !denied
    }

    /// Build a compression policy from QUICFUSCATE_COMPRESS_* environment variables.
    pub fn from_env() -> Self {
        let environment = EnvSnapshot::capture();
        Self::from_env_with_snapshot(&environment)
    }

    /// Build a compression policy from one immutable environment generation.
    pub(crate) fn from_env_with_snapshot(environment: &EnvSnapshot) -> Self {
        let mut p = CompressionPolicy::default();
        p.enabled = environment.flag("QUICFUSCATE_COMPRESS", p.enabled);
        if let Some(n) = environment.parse::<usize>("QUICFUSCATE_COMPRESS_MIN") {
            p.min_len = n;
        }
        if let Some(level) = environment.parse::<i32>("QUICFUSCATE_COMPRESS_LEVEL") {
            if (1..=22).contains(&level) {
                p.level = level;
            } else {
                log::warn!(
                    "QUICFUSCATE_COMPRESS_LEVEL must be between 1 and 22; retaining default {}",
                    p.level
                );
            }
        }
        if let Some(raw) = environment.first(["QUICFUSCATE_COMPRESS_ALLOW"]) {
            p.allow = raw
                .split(',')
                .filter_map(|s| {
                    let trimmed = s.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_owned())
                    }
                })
                .collect();
        }
        if let Some(raw) = environment.first(["QUICFUSCATE_COMPRESS_DENY"]) {
            p.deny = raw
                .split(',')
                .filter_map(|s| {
                    let trimmed = s.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_owned())
                    }
                })
                .collect();
        }
        p
    }
}

// -------------------- Persona + ContentClass Mapping --------------------

/// Broad content classification for dictionary-based compression tuning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ContentClass {
    /// JSON payloads.
    Json,
    /// HTML documents.
    Html,
    /// CSS stylesheets.
    Css,
    /// JavaScript code.
    Js,
    /// Generic text content.
    Text,
}

#[derive(Clone, Debug)]
struct PersonaState {
    name: String,
}

static PERSONA: OnceLock<Mutex<PersonaState>> = OnceLock::new();

/// Set the active stealth persona for dictionary selection.
pub fn set_current_persona(name: &str) {
    load_all_dicts_from_dir();
    if let Some(m) = PERSONA.get() {
        if let Ok(mut p) = m.lock() {
            p.name.clear();
            p.name.push_str(name);
            return;
        }
    }
    if PERSONA.set(Mutex::new(PersonaState { name: name.to_owned() })).is_err() {
        log::debug!("Persona state already initialized");
    }
}

fn current_persona() -> String {
    PERSONA
        .get_or_init(|| Mutex::new(PersonaState { name: "default".into() }))
        .lock()
        .map(|p| p.name.clone())
        .unwrap_or_else(|_| "default".into())
}

/// Map a Content-Type header string to a broad content classification.
pub fn classify_content_type(ct: &str) -> ContentClass {
    let lc = ct.to_ascii_lowercase();
    if lc.contains("application/json") {
        return ContentClass::Json;
    }
    if lc.contains("text/html") {
        return ContentClass::Html;
    }
    if lc.contains("text/css") {
        return ContentClass::Css;
    }
    if lc.contains("application/javascript") || lc.contains("text/javascript") {
        return ContentClass::Js;
    }
    ContentClass::Text
}

// -------------------- Dictionary Registry --------------------

#[derive(Default)]
struct DictEntry {
    dict: Option<Vec<u8>>, // trained dict bytes
    version: u32,
    samples: std::collections::VecDeque<Vec<u8>>, // training samples reservoir
}

type DictKey = (String, ContentClass);
static DICT_REG: OnceLock<Mutex<HashMap<DictKey, DictEntry>>> = OnceLock::new();
type DictId = (u16, u16); // (hash, version)
static DICT_INDEX: OnceLock<Mutex<HashMap<DictId, Vec<u8>>>> = OnceLock::new();

fn dicts() -> std::sync::MutexGuard<'static, HashMap<DictKey, DictEntry>> {
    DICT_REG.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap_or_else(|p| p.into_inner())
}

fn dict_index() -> std::sync::MutexGuard<'static, HashMap<DictId, Vec<u8>>> {
    DICT_INDEX.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap_or_else(|p| p.into_inner())
}

/// Submit a payload sample for dictionary training (capped at 4096 bytes per sample).
pub fn submit_sample(ct: &str, data: &[u8]) {
    let class = classify_content_type(ct);
    let persona = current_persona();
    let mut reg = dicts();
    let e = reg.entry((persona, class)).or_default();
    // Cap sample size per entry.
    let take = data.len().min(4096);
    e.samples.push_back(data[..take].to_vec());
    if e.samples.len() > 200 {
        e.samples.pop_front();
    }
}

/// Train a zstd dictionary from collected samples if the reservoir threshold is met.
pub fn maybe_train(ct: &str) {
    let class = classify_content_type(ct);
    let persona = current_persona();
    let mut reg = dicts();
    if let Some(e) = reg.get_mut(&(persona, class)) {
        if e.dict.is_some() {
            return;
        }
        if e.samples.len() < 40 {
            return;
        }
        let dict_size = 32 * 1024; // 32KiB
                                   // zstd::dict::from_samples API (best-effort)
        let samples: Vec<&[u8]> = e.samples.iter().map(|v| v.as_slice()).collect();
        match zstd::dict::from_samples(&samples, dict_size) {
            Ok(bytes) => {
                let mut hash: u16 = 0u16;
                for b in bytes.iter().take(64) {
                    hash = hash.wrapping_mul(257).wrapping_add(*b as u16);
                }
                e.dict = Some(bytes.clone());
                e.version = e.version.wrapping_add(1);
                dict_index().insert((hash, e.version as u16), bytes.clone());
                if let Err(err) = persist_dict(&current_persona(), class, e.version, &bytes, hash) {
                    log::debug!("Failed to persist trained dictionary: {}", err);
                }
                e.samples.clear();
            }
            Err(_) => { /* Training failed; retry later. */ }
        }
    }
}

/// Retrieve the trained dictionary and version for the given content type, if available.
pub fn get_dict(ct: &str) -> Option<(Vec<u8>, u32)> {
    let class = classify_content_type(ct);
    let persona = current_persona();
    let reg = dicts();
    reg.get(&(persona, class)).and_then(|e| e.dict.as_ref().map(|d| (d.clone(), e.version)))
}

/// Look up a dictionary by its (hash, version) identifier pair.
pub fn get_dict_by_id(hash: u16, version: u16) -> Option<Vec<u8>> {
    dict_index().get(&(hash, version)).cloned()
}

/// Calculate entropy from histogram using Shannon formula
fn calculate_entropy_from_histogram(histogram: &[u32; 256], total_len: usize) -> f64 {
    if total_len == 0 {
        return 0.0;
    }

    let mut entropy = 0.0;
    let total = total_len as f64;

    for &count in histogram.iter() {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Fallback entropy estimation for compatibility
pub(crate) fn estimate_entropy_bits_per_byte(data: &[u8]) -> f64 {
    // Use the central SIMD histogram implementation
    let histogram = crate::optimize::simd::compress::histogram(data);
    calculate_entropy_from_histogram(&histogram, data.len())
}

fn compute_chunk_metrics(data: &[u8]) -> (u32, u32, u32) {
    const CHUNK: usize = 64;
    if data.is_empty() {
        return (0, 0, 0);
    }

    let mut bins = [0u32; 8];
    let mut total = 0u32;
    let mut repeated = 0u32;
    let mut prev_hash = None;

    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + CHUNK).min(data.len());
        let mut hash: u32 = 0x811C_9DC5;
        for &byte in &data[offset..end] {
            hash = hash.rotate_left(5) ^ (byte as u32);
        }
        let bin = (hash & 7) as usize;
        bins[bin] = bins[bin].saturating_add(1);
        if let Some(prev) = prev_hash {
            if prev == hash {
                repeated = repeated.saturating_add(1);
            }
        }
        prev_hash = Some(hash);
        total = total.saturating_add(1);
        offset += CHUNK;
    }

    let max_bin = bins.into_iter().max().unwrap_or(0);
    (total, repeated, max_bin)
}

// -------------------- Zstd with dictionary --------------------

/// Compress payload using a pre-trained zstd dictionary into a pooled buffer.
///
/// The returned block is an RAII owner and is returned to `pool` on drop.
pub fn compress_with_dict(
    pool: &Arc<MemoryPool>,
    data: &[u8],
    level: i32,
    dict_bytes: &[u8],
    dict_version: u32,
) -> Option<(PooledBlock, usize)> {
    crate::optimize::telemetry::COMPRESS_ATTEMPTS.inc();
    let analysis = CompressionAnalysis::from_full(data);
    analysis.record_telemetry();
    let mut out = PooledBlock::new(Arc::clone(pool));
    crate::optimize::telemetry::BODY_POOL_ALLOCS.inc();
    // Header: 1 byte magic (0x5D) + 2 bytes dict id hash + 2 bytes version + 4 bytes orig len
    if out.len() < 9 {
        return None;
    }
    out[0] = 0x5D; // ']' marker
                   // naive id-hash (not security-critical):
    let mut hash: u16 = 0u16;
    for b in dict_bytes.iter().take(64) {
        hash = hash.wrapping_mul(257).wrapping_add(*b as u16);
    }
    out[1..3].copy_from_slice(&hash.to_be_bytes());
    out[3..5].copy_from_slice(&(dict_version as u16).to_be_bytes());
    let orig_len = data.len() as u32;
    out[5..9].copy_from_slice(&orig_len.to_be_bytes());
    let mut compressor = zstd::bulk::Compressor::with_dictionary(level, dict_bytes).ok()?;
    tune_compressor_with_analysis(&mut compressor, data.len(), &analysis, level);
    let n = compressor.compress_to_buffer(data, &mut out[9..]).ok()?;
    crate::optimize::telemetry::COMPRESS_SUCCESS.inc();
    crate::optimize::telemetry::COMPRESS_DICT_USED.inc();
    crate::optimize::telemetry::COMPRESS_BYTES_IN.inc_by(orig_len as u64);
    crate::optimize::telemetry::COMPRESS_BYTES_OUT.inc_by(n as u64);
    Some((out, 9 + n))
}

/// Decompress a dictionary-compressed buffer (magic 0x5D) into a pooled buffer.
///
/// The pool block must be at least as large as the declared original payload length. The decoder
/// writes into exactly that declared-length slice and rejects any result whose length differs, so
/// an undersized block or malformed frame returns `None` instead of exposing a truncated payload.
/// The returned block is an RAII owner and is returned to `pool` on drop.
pub fn decompress_with_dict(
    pool: &Arc<MemoryPool>,
    data: &[u8],
    dict_bytes: &[u8],
) -> Option<(PooledBlock, usize)> {
    if data.len() < 9 || data[0] != 0x5D {
        return None;
    }
    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&data[5..9]);
    let orig_len = u32::from_be_bytes(len_buf) as usize;
    let mut dec = zstd::bulk::Decompressor::with_dictionary(dict_bytes).ok()?;
    let mut out = PooledBlock::new(Arc::clone(pool));
    if out.len() < orig_len {
        return None;
    }
    let n = dec.decompress_to_buffer(&data[9..], &mut out[..orig_len]).ok()?;
    (n == orig_len).then_some((out, n))
}

// -------------------- Large Body Pool --------------------

static BODY_POOL: OnceLock<Arc<MemoryPool>> = OnceLock::new();
/// Return the global large-body memory pool for compression buffers.
pub fn body_pool() -> Arc<MemoryPool> {
    BODY_POOL
        .get_or_init(|| {
            let environment = EnvSnapshot::capture();
            let cap = environment.parse_positive_usize("QUICFUSCATE_BODYPOOL_CAP").unwrap_or(256);
            let blk =
                environment.parse_positive_usize("QUICFUSCATE_BODYPOOL_BLOCK").unwrap_or(64 * 1024);
            let pool = Arc::new(MemoryPool::new_with_snapshot(cap, blk, &environment));
            crate::optimize::telemetry::BODY_POOL_BLOCK_SIZE
                .store(pool.block_size() as u64, std::sync::atomic::Ordering::Relaxed);
            crate::optimize::telemetry::BODY_POOL_CAPACITY
                .store(cap as u64, std::sync::atomic::Ordering::Relaxed);
            pool
        })
        .clone()
}

// -------------------- Persistenz: Dictionaries auf Disk --------------------

use std::path::PathBuf;
static DICT_DIR: OnceLock<PathBuf> = OnceLock::new();

fn dict_dir() -> PathBuf {
    DICT_DIR
        .get_or_init(|| {
            EnvSnapshot::capture()
                .first(["QUICFUSCATE_DICT_DIR"])
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("dict_cache"))
        })
        .clone()
}

fn class_str(c: ContentClass) -> &'static str {
    match c {
        ContentClass::Json => "json",
        ContentClass::Html => "html",
        ContentClass::Css => "css",
        ContentClass::Js => "js",
        ContentClass::Text => "text",
    }
}

fn persist_dict(
    persona: &str,
    class: ContentClass,
    version: u32,
    bytes: &[u8],
    hash: u16,
) -> std::io::Result<()> {
    use std::fs;
    let dir = dict_dir();
    fs::create_dir_all(&dir)?;
    let fname = format!(
        "{}_{}_v{}_h{:04x}.zdict",
        persona.replace('/', "-"),
        class_str(class),
        version,
        hash
    );
    let path = dir.join(fname);
    fs::write(path, bytes)
}

static DICT_LOADED: OnceLock<()> = OnceLock::new();
fn load_all_dicts_from_dir() {
    DICT_LOADED.get_or_init(|| {
        use std::fs;
        let dir = dict_dir();
        if let Ok(rd) = fs::read_dir(&dir) {
            for e in rd.flatten() {
                if let Ok(md) = e.metadata() {
                    if !md.is_file() {
                        continue;
                    }
                }
                let p = e.path();
                if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                    // pattern: persona_class_v{ver}_h{hash}.zdict
                    if let Some((ver, hash)) = parse_ver_hash(name) {
                        if let Ok(bytes) = fs::read(&p) {
                            dict_index().insert((hash, ver), bytes);
                        }
                    }
                }
            }
        }
    });
}

fn parse_ver_hash(name: &str) -> Option<(u16, u16)> {
    // find segments v#### (decimal) and h#### (hex) in name
    let mut v_opt: Option<u16> = None;
    let mut h_opt: Option<u16> = None;
    for part in name.split('_') {
        if let Some(rest) = part.strip_prefix('v') {
            if let Ok(n) = rest.trim_end_matches(|c: char| !c.is_ascii_digit()).parse::<u16>() {
                v_opt = Some(n);
            }
        } else if let Some(rest) = part.strip_prefix('h') {
            let cleaned = rest.trim_end_matches(|c: char| !c.is_ascii_hexdigit());
            if let Ok(n) = u16::from_str_radix(cleaned, 16) {
                h_opt = Some(n);
            }
        }
    }
    match (v_opt, h_opt) {
        (Some(v), Some(h)) => Some((v, h)),
        _ => None,
    }
}

/// Check if a MIME type `value` matches a `pattern` (supports wildcard subtypes).
#[inline]
pub fn mime_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.split(';').next().unwrap_or(pattern).trim();
    let value = value.split(';').next().unwrap_or(value).trim();
    if let Some(pos) = pattern.find('/') {
        let (pt, ps) = pattern.split_at(pos);
        let ps = &ps[1..];
        if let Some(pos2) = value.find('/') {
            let (vt, vs) = value.split_at(pos2);
            let vs = &vs[1..];
            return (pt.eq_ignore_ascii_case(vt) || pt == "*")
                && (ps.eq_ignore_ascii_case(vs)
                    || ps == "*"
                    || (ps.ends_with('*')
                        && vs.get(..ps.len() - 1).is_some_and(|prefix| {
                            prefix.eq_ignore_ascii_case(&ps[..ps.len() - 1])
                        })));
        }
    }
    pattern.eq_ignore_ascii_case(value)
}

// -------------------- Entropy estimator --------------------
// DUPLICATE REMOVED - estimate_entropy_bits_per_byte is already defined earlier.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_gating_text_vs_binary() {
        let text = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\nHello World!";
        assert!(CompressionManager::looks_textual(text));
        let mut bin = [0u8; 256];
        for (i, byte) in bin.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(37).rotate_left(1);
        }
        assert!(!CompressionManager::looks_textual(&bin));
    }

    #[test]
    fn config_default_values() {
        let cfg = CompressionConfig::default();
        assert_eq!(cfg.min_len, 256);
        assert_eq!(cfg.max_level, 5);
    }

    #[test]
    fn analysis_ratios_empty_data() {
        let a = CompressionAnalysis::default();
        assert_eq!(a.ascii_ratio(), 0.0);
        assert_eq!(a.newline_ratio(), 0.0);
        assert_eq!(a.null_ratio(), 0.0);
        assert_eq!(a.high_ratio(), 0.0);
        assert_eq!(a.chunk_repeat_ratio(), 0.0);
        assert_eq!(a.chunk_skew(), 0.0);
        assert!(!a.is_textual());
    }

    #[test]
    fn analysis_ascii_text_is_textual() {
        let a = CompressionAnalysis {
            len: 100,
            ascii_bytes: 80,
            newline_bytes: 5,
            carriage_bytes: 0,
            tab_bytes: 0,
            null_bytes: 0,
            high_bytes: 5,
            entropy_bits_per_byte: 5.0,
            chunk_total: 0,
            chunk_repeated: 0,
            chunk_max_bin: 0,
        };
        assert!(a.ascii_ratio() >= 0.75);
        assert!(a.is_textual());
    }

    #[test]
    fn analysis_binary_not_textual() {
        let a = CompressionAnalysis {
            len: 100,
            ascii_bytes: 10,
            newline_bytes: 0,
            carriage_bytes: 0,
            tab_bytes: 0,
            null_bytes: 30,
            high_bytes: 60,
            entropy_bits_per_byte: 7.9,
            chunk_total: 0,
            chunk_repeated: 0,
            chunk_max_bin: 0,
        };
        assert!(!a.is_textual());
    }

    #[test]
    fn analysis_chunk_ratios() {
        let a = CompressionAnalysis {
            len: 640,
            ascii_bytes: 0,
            newline_bytes: 0,
            carriage_bytes: 0,
            tab_bytes: 0,
            null_bytes: 0,
            high_bytes: 0,
            entropy_bits_per_byte: 0.0,
            chunk_total: 10,
            chunk_repeated: 3,
            chunk_max_bin: 5,
        };
        assert!((a.chunk_repeat_ratio() - 0.3).abs() < 0.01);
        assert!((a.chunk_skew() - 0.5).abs() < 0.01);
    }

    #[test]
    fn compress_to_pool_roundtrip_uses_zstd_frame() {
        let pool = Arc::new(MemoryPool::new(4, 16 * 1024));
        let manager = CompressionManager::new(CompressionConfig::default());
        let mut payload = Vec::new();
        for _ in 0..64 {
            payload.extend_from_slice(b"content-type: text/plain\r\nhello hello hello\r\n");
        }

        let (compressed, used) = manager.compress_to_pool(&pool, &payload).expect("compress");
        assert_eq!(compressed[0], 0x5A);
        assert_eq!(&compressed[1..5], &(payload.len() as u32).to_be_bytes());
        assert!(used > 5);
        assert!(used <= compressed.len());

        let (decompressed, decompressed_len) =
            manager.decompress_to_pool(&pool, &compressed[..used]).expect("decompress");
        assert_eq!(decompressed_len, payload.len());
        assert_eq!(&decompressed[..decompressed_len], payload.as_slice());
    }

    #[test]
    fn compress_with_dict_roundtrip_uses_pool_buffer() {
        let pool = Arc::new(MemoryPool::new(4, 16 * 1024));
        let dict = b"header:value\ncontent-type:text/plain\nhello hello hello\n";
        let mut payload = Vec::new();
        for _ in 0..48 {
            payload
                .extend_from_slice(b"header:value\ncontent-type:text/plain\nhello hello hello\n");
        }

        let (compressed, used) =
            compress_with_dict(&pool, &payload, 5, dict, 7).expect("compress with dict");
        assert_eq!(compressed[0], 0x5D);
        assert_eq!(&compressed[5..9], &(payload.len() as u32).to_be_bytes());
        assert!(used > 9);
        assert!(used <= compressed.len());

        let (decompressed, decompressed_len) =
            decompress_with_dict(&pool, &compressed[..used], dict).expect("decompress with dict");
        assert_eq!(decompressed_len, payload.len());
        assert_eq!(&decompressed[..decompressed_len], payload.as_slice());
    }

    #[test]
    fn compress_with_dict_roundtrip_handles_payload_larger_than_64k() {
        let pool = Arc::new(MemoryPool::new(2, 128 * 1024));
        assert_eq!(pool.block_size(), 128 * 1024);
        let dict = b"header:value\ncontent-type:text/plain\nhello hello hello\n";
        let mut payload = Vec::with_capacity(96 * 1024);
        for index in 0..1024 {
            payload.extend_from_slice(
                format!(
                    "header:value\ncontent-type:text/plain\nrecord={index:04}\nhello hello hello\n"
                )
                .as_bytes(),
            );
        }

        assert!(payload.len() > 64 * 1024);
        let (compressed, used) =
            compress_with_dict(&pool, &payload, 5, dict, 7).expect("compress large payload");
        let (decompressed, decompressed_len) =
            decompress_with_dict(&pool, &compressed[..used], dict)
                .expect("decompress large payload");

        assert_eq!(decompressed_len, payload.len());
        assert_eq!(&decompressed[..decompressed_len], payload.as_slice());
    }

    #[test]
    fn compression_policy_enforces_allow_and_deny_patterns() {
        let policy = CompressionPolicy::default();

        assert!(policy.allows_content_type(Some("text/css; charset=utf-8")));
        assert!(policy.allows_content_type(Some("application/json; charset=utf-8")));
        assert!(!policy.allows_content_type(Some("image/png")));
        assert!(!policy.allows_content_type(Some("application/zip")));
        assert!(!policy.allows_content_type(Some("application/octet-stream")));
        assert!(policy.allows_content_type(None));

        let deny_precedence = CompressionPolicy {
            allow: vec!["image/*".into()],
            deny: vec!["image/png".into()],
            ..policy
        };
        assert!(!deny_precedence.allows_content_type(Some("IMAGE/PNG")));
    }

    #[test]
    fn compression_policy_snapshot_warns_and_retains_safe_defaults() {
        let environment = crate::env_utils::EnvSnapshot::from_pairs([
            ("QUICFUSCATE_COMPRESS", "maybe"),
            ("QUICFUSCATE_COMPRESS_MIN", " 512 "),
            ("QUICFUSCATE_COMPRESS_LEVEL", "99"),
            ("QUICFUSCATE_COMPRESS_ALLOW", " text/*, "),
            ("QUICFUSCATE_COMPRESS_DENY", " image/*, "),
        ]);
        let policy = CompressionPolicy::from_env_with_snapshot(&environment);
        let defaults = CompressionPolicy::default();

        assert_eq!(policy.enabled, defaults.enabled);
        assert_eq!(policy.min_len, 512);
        assert_eq!(policy.level, defaults.level);
        assert_eq!(policy.allow, vec!["text/*"]);
        assert_eq!(policy.deny, vec!["image/*"]);
    }

    #[test]
    fn decompression_rejects_payload_length_mismatch() {
        let pool = Arc::new(MemoryPool::new(4, 16 * 1024));
        let manager = CompressionManager::new(CompressionConfig::default());
        let payload = b"compression length contract".repeat(64);
        let (compressed, used) = manager.compress_to_pool(&pool, &payload).expect("compress");

        let mut wrong_header = compressed[..used].to_vec();
        wrong_header[1..5].copy_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
        assert!(manager.decompress_to_pool(&pool, &wrong_header).is_none());
    }

    #[test]
    fn compression_output_buffer_failure_returns_the_pool_block() {
        let pool = Arc::new(MemoryPool::new(1, 2_048));
        let before = pool.accounting_snapshot();
        let manager = CompressionManager::new(CompressionConfig { min_len: 0, max_level: 5 });
        let data: Vec<u8> = (0..32 * 1024)
            .scan(0x1234_5678u32, |state, _| {
                *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                Some((*state >> 24) as u8)
            })
            .collect();

        assert!(manager.compress_to_pool(&pool, &data).is_none());
        assert_eq!(pool.accounting_snapshot(), before);
    }

    #[test]
    fn decompression_failure_returns_the_pool_block() {
        let pool = Arc::new(MemoryPool::new(1, 2_048));
        let before = pool.accounting_snapshot();
        let manager = CompressionManager::new(CompressionConfig::default());
        let malformed = [0x5A, 0, 0, 0, 32, 0x01, 0x02, 0x03];

        assert!(manager.decompress_to_pool(&pool, &malformed).is_none());
        assert_eq!(pool.accounting_snapshot(), before);
    }

    #[test]
    fn dictionary_compression_output_buffer_failure_returns_the_pool_block() {
        let pool = Arc::new(MemoryPool::new(1, 2_048));
        let before = pool.accounting_snapshot();
        let data: Vec<u8> = (0..32 * 1024)
            .scan(0x8765_4321u32, |state, _| {
                *state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                Some((*state >> 24) as u8)
            })
            .collect();

        assert!(compress_with_dict(&pool, &data, 5, b"dict", 1).is_none());
        assert_eq!(pool.accounting_snapshot(), before);
    }

    #[test]
    fn dictionary_decompression_failure_returns_the_pool_block() {
        let pool = Arc::new(MemoryPool::new(1, 2_048));
        let before = pool.accounting_snapshot();
        let malformed = [0x5D, 0, 0, 0, 1, 0, 0, 0, 16, 0x01, 0x02, 0x03];

        assert!(decompress_with_dict(&pool, &malformed, b"dict").is_none());
        assert_eq!(pool.accounting_snapshot(), before);
    }

    #[test]
    fn body_pool_telemetry_reports_the_effective_block_size() {
        let pool = body_pool();
        let reported = crate::optimize::telemetry::BODY_POOL_BLOCK_SIZE
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(reported as usize, pool.block_size());

        let block = pool.alloc();
        assert_eq!(block.len(), reported as usize);
        pool.free(block);
    }
}
