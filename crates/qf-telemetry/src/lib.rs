use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

/// Telemetry and metrics configuration projected from the engine boundary.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Enable telemetry collection.
    pub enabled: bool,
    /// Export interval in seconds.
    pub export_interval: u64,
    /// Collect packet statistics.
    pub collect_packet_stats: bool,
    /// Collect stream statistics.
    pub collect_stream_stats: bool,
    /// Collect congestion statistics.
    pub collect_congestion_stats: bool,
    /// Collect FEC statistics.
    pub collect_fec_stats: bool,
    /// Collect stealth statistics.
    pub collect_stealth_stats: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            export_interval: 60,
            collect_packet_stats: true,
            collect_stream_stats: true,
            collect_congestion_stats: true,
            collect_fec_stats: true,
            collect_stealth_stats: true,
        }
    }
}

impl TelemetryConfig {
    /// Validate the operator-facing collection and export bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.export_interval == 0 {
            return Err("telemetry.export_interval must be > 0 when telemetry is enabled".into());
        }
        Ok(())
    }
}

/// TLS provider gauge: 0 = rustls-only, 1 = rustls+tls-cover (unified).
pub static TLS_PROVIDER_KIND: SafeGauge = SafeGauge::new();
/// rustls Handshake key installs negotiated as TLS_AES_128_GCM_SHA256.
pub static QUIC_HANDSHAKE_AES128_KEY_INSTALLS: Counter = Counter::new();
/// rustls Handshake key installs negotiated as TLS_AES_256_GCM_SHA384.
pub static QUIC_HANDSHAKE_AES256_KEY_INSTALLS: Counter = Counter::new();
/// rustls 1-RTT key installs negotiated as TLS_AES_128_GCM_SHA256.
pub static QUIC_ONE_RTT_AES128_KEY_INSTALLS: Counter = Counter::new();
/// rustls 1-RTT key installs negotiated as TLS_AES_256_GCM_SHA384.
pub static QUIC_ONE_RTT_AES256_KEY_INSTALLS: Counter = Counter::new();

/// Total HTTP/3 frames processed.
pub static H3_FRAMES: AtomicU64 = AtomicU64::new(0);
/// Total HTTP/3 header blocks processed.
pub static H3_HEADERS: AtomicU64 = AtomicU64::new(0);
/// Total HTTP/3 DATA frame bytes transferred.
pub static H3_DATA_BYTES: AtomicU64 = AtomicU64::new(0);
/// Total HTTP/3 errors encountered.
pub static H3_ERRORS: AtomicU64 = AtomicU64::new(0);

/// MASQUE state gauge: 0 = inactive, 1 = active (CONNECT-UDP established).
pub static MASQUE_ACTIVE: AtomicU64 = AtomicU64::new(0);

/// AEGIS plan gauge: 0=MORUS, 1=AEGIS-128L, 4=AEGIS-128X4, 8=AEGIS-128X8.
pub static AEGIS_PLAN: AtomicU64 = AtomicU64::new(0);

/// Brain MASQUE hint: 0 = no preference, 1 = prefer MASQUE path.
/// Last MASQUE preference any connection's brain computed.
///
/// Observability only. This used to be the channel through which a brain told the stealth manager
/// its preference, which meant one connection's telemetry flipped every other connection's MASQUE
/// preference. The policy value is now connection-owned in `IntelligentLevelHints`, and nothing
/// reads this back.
pub static MASQUE_HINT: AtomicU64 = AtomicU64::new(0);

/// Total IPv4 packets processed through TUN device.
pub static IP_V4_PACKETS: AtomicU64 = AtomicU64::new(0);
/// Total IPv6 packets processed through TUN device.
pub static IP_V6_PACKETS: AtomicU64 = AtomicU64::new(0);
/// Cumulative IP ToS/DSCP field values (for averaging).
pub static IP_TOS_SUM: AtomicU64 = AtomicU64::new(0);
/// Number of IP ToS samples collected.
pub static IP_TOS_SAMPLES: AtomicU64 = AtomicU64::new(0);
/// Total TUN fast-path write attempts.
pub static TUN_FASTPATH_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
/// TUN writes completed via direct path.
pub static TUN_FASTPATH_DIRECT_WRITES: AtomicU64 = AtomicU64::new(0);
/// TUN operations rejected due to unmet requirements.
pub static TUN_REQUIREMENT_REJECTS: AtomicU64 = AtomicU64::new(0);
/// TUN operations rejected due to configuration mismatch.
pub static TUN_CONFIG_REJECTS: AtomicU64 = AtomicU64::new(0);
/// TUN operations rejected due to insufficient permissions.
pub static TUN_PERMISSION_REJECTS: AtomicU64 = AtomicU64::new(0);

/// RTT spike signals observed for Intelligent stealth escalation.
pub static STEALTH_SIGNAL_RTT_SPIKES: AtomicU64 = AtomicU64::new(0);
/// ECN Congestion Experienced marks detected for stealth escalation.
pub static STEALTH_SIGNAL_ECN_CE: AtomicU64 = AtomicU64::new(0);
/// Connection reset signals for stealth escalation.
pub static STEALTH_SIGNAL_RST: AtomicU64 = AtomicU64::new(0);
/// ToS anomaly signals for stealth escalation.
pub static STEALTH_SIGNAL_TOS_ANOM: AtomicU64 = AtomicU64::new(0);
/// Other unclassified stealth escalation signals.
pub static STEALTH_SIGNAL_OTHER: AtomicU64 = AtomicU64::new(0);
/// Total server-push cover traffic bursts emitted.
pub static SERVER_PUSH_BURSTS_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Total bytes of server-push cover traffic sent.
pub static SERVER_PUSH_TOTAL_COVER_BYTES: AtomicU64 = AtomicU64::new(0);
/// Server-push cover bursts emitted in the last minute.
pub static SERVER_PUSH_BURSTS_LAST_MINUTE: AtomicU64 = AtomicU64::new(0);
/// Current server-push intensity in parts-per-million.
pub static SERVER_PUSH_CURRENT_INTENSITY_PPM: AtomicU64 = AtomicU64::new(0);
/// Server-push bursts triggered by loss detection.
pub static SERVER_PUSH_TRIGGER_LOSS_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Server-push bursts triggered by time-based schedule.
pub static SERVER_PUSH_TRIGGER_TIME_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Server-push bursts triggered by gating logic.
pub static SERVER_PUSH_TRIGGER_GATING_TOTAL: AtomicU64 = AtomicU64::new(0);

// Per-category telemetry export gates (controlled by [telemetry] config flags).
// Default: all enabled. Set to false to suppress that category from /telemetry output.
use std::sync::atomic::AtomicBool;
/// Whether packet-level stats are included in telemetry export.
pub static COLLECT_PACKET_STATS: AtomicBool = AtomicBool::new(true);
/// Whether stream-level stats are included in telemetry export.
pub static COLLECT_STREAM_STATS: AtomicBool = AtomicBool::new(true);
/// Whether congestion/plan stats are included in telemetry export.
pub static COLLECT_CONGESTION_STATS: AtomicBool = AtomicBool::new(true);
/// Whether FEC stats are included in telemetry export.
pub static COLLECT_FEC_STATS: AtomicBool = AtomicBool::new(true);
/// Whether stealth stats are included in telemetry export.
pub static COLLECT_STEALTH_STATS: AtomicBool = AtomicBool::new(true);

mod export;
pub use export::export_telemetry_text;

/// Thread-safe gauge backed by an `AtomicI64` for signed metric values.
pub struct SafeGauge(AtomicI64);
impl SafeGauge {
    /// Create a new gauge initialized to zero.
    pub const fn new() -> Self {
        Self(AtomicI64::new(0))
    }
    /// Store a new gauge value (relaxed ordering).
    pub fn set(&self, val: i64) {
        self.0.store(val, Ordering::Relaxed);
    }
    /// Read the current gauge value (relaxed ordering).
    pub fn get(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}
impl Default for SafeGauge {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe monotonic counter backed by an `AtomicU64`.
pub struct Counter(AtomicU64);
impl Counter {
    /// Create a new counter initialized to zero.
    pub const fn new() -> Self {
        Counter(AtomicU64::new(0))
    }
    /// Increment by one (relaxed ordering).
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    /// Increment by an arbitrary amount (relaxed ordering).
    pub fn inc_by(&self, val: u64) {
        self.0.fetch_add(val, Ordering::Relaxed);
    }
    /// Read the current counter value (relaxed ordering).
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}
impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

/// Unsafe memory pools created.
pub static UNSAFE_POOL_CREATED: Counter = Counter::new();
/// Current capacity of the unsafe memory pool.
pub static UNSAFE_POOL_CAPACITY: AtomicU64 = AtomicU64::new(0);
/// Total allocation calls through unsafe pool.
pub static UNSAFE_ALLOC_CALLS: Counter = Counter::new();
/// Total free calls through unsafe pool.
pub static UNSAFE_FREE_CALLS: Counter = Counter::new();
/// Allocations served from the synchronized UnsafeMemoryPool available cache.
/// The symbol name is retained for telemetry compatibility with older releases.
pub static UNSAFE_TLS_HITS: Counter = Counter::new();
/// Retained compatibility counter for the removed atomic global-pool path.
pub static UNSAFE_GLOBAL_HITS: Counter = Counter::new();
/// Allocations that fell back to the system allocator.
pub static UNSAFE_FALLBACK_ALLOCS: Counter = Counter::new();
/// Total deallocations through unsafe pool.
pub static UNSAFE_DEALLOCS: Counter = Counter::new();

/// SIMD Galois field operations performed.
pub static SIMD_GF_OPS: Counter = Counter::new();
/// SIMD XOR operations performed.
pub static SIMD_XOR_OPS: Counter = Counter::new();
/// SIMD prefetch operations issued.
pub static SIMD_PREFETCH_OPS: Counter = Counter::new();

/// Total unsafe compression calls.
pub static UNSAFE_COMPRESS_CALLS: Counter = Counter::new();
/// Failed unsafe compression attempts.
pub static UNSAFE_COMPRESS_FAILURES: Counter = Counter::new();
/// Bytes fed into unsafe compression.
pub static UNSAFE_COMPRESS_BYTES_IN: Counter = Counter::new();
/// Bytes produced by unsafe compression.
pub static UNSAFE_COMPRESS_BYTES_OUT: Counter = Counter::new();

/// Total entropy calculations performed.
pub static ENTROPY_CALCULATIONS: Counter = Counter::new();
/// Entropy calculations accelerated via SIMD.
pub static ENTROPY_SIMD_USED: Counter = Counter::new();

/// Zero-copy send operations completed.
pub static ZERO_COPY_SENDS: Counter = Counter::new();
/// Zero-copy receive operations completed.
pub static ZERO_COPY_RECVS: Counter = Counter::new();
/// IoSlice scatter/gather operations performed.
pub static IOSLICE_OPERATIONS: Counter = Counter::new();

/// FEC encoding operations accelerated via SIMD.
pub static FEC_SIMD_ENCODE: Counter = Counter::new();
/// FEC decoding operations accelerated via SIMD.
pub static FEC_SIMD_DECODE: Counter = Counter::new();
/// FEC operations using AVX2 backend.
pub static FEC_AVX2_OPS: Counter = Counter::new();
/// Brain histogram computations via AVX-512.
pub static BRAIN_HISTOGRAM_AVX512_OPS: Counter = Counter::new();
/// Brain histogram computations via AVX2.
pub static BRAIN_HISTOGRAM_AVX2_OPS: Counter = Counter::new();
/// Brain histogram computations via SSE.
pub static BRAIN_HISTOGRAM_SSE_OPS: Counter = Counter::new();
/// Brain histogram computations via NEON.
pub static BRAIN_HISTOGRAM_NEON_OPS: Counter = Counter::new();
/// Brain histogram computations via SVE2.
pub static BRAIN_HISTOGRAM_SVE2_OPS: Counter = Counter::new();
/// Brain histogram computations via scalar fallback.
pub static BRAIN_HISTOGRAM_SCALAR_OPS: Counter = Counter::new();

/// Total AEAD plan selection decisions made.
pub static PLAN_DECISIONS_TOTAL: Counter = Counter::new();
/// Plan selections that chose the default backend.
pub static PLAN_DECISIONS_DEFAULT: Counter = Counter::new();
/// Plan selections based on payload length heuristic.
pub static PLAN_DECISIONS_LEN: Counter = Counter::new();
/// Plan selections that chose AEGIS-128L.
pub static PLAN_DECISIONS_L: Counter = Counter::new();
/// Plan selections that chose AEGIS-128X4 (4-way unrolled).
pub static PLAN_DECISIONS_X4: Counter = Counter::new();
/// Plan selections that chose AEGIS-128X8 (8-way unrolled).
pub static PLAN_DECISIONS_X8: Counter = Counter::new();
/// Plan selections that chose AEGIS-128L on NEON.
pub static PLAN_DECISIONS_NEON_L: Counter = Counter::new();
/// Plan selections that chose MORUS fallback.
pub static PLAN_DECISIONS_MORUS: Counter = Counter::new();
/// Data-plane AEAD operations using AEGIS-128L backend.
pub static DATA_AEAD_BACKEND_AEGIS_L_TOTAL: Counter = Counter::new();
/// Data-plane AEAD operations using AEGIS-128X4 backend.
pub static DATA_AEAD_BACKEND_AEGIS_X4_TOTAL: Counter = Counter::new();
/// Data-plane AEAD operations using AEGIS-128X8 backend.
pub static DATA_AEAD_BACKEND_AEGIS_X8_TOTAL: Counter = Counter::new();
/// Data-plane AEAD operations using MORUS fallback backend.
pub static DATA_AEAD_BACKEND_MORUS_TOTAL: Counter = Counter::new();
/// MORUS-1280 operations via scalar backend.
pub static MORUS1280_SCALAR_OPS: Counter = Counter::new();
/// MORUS-1280 operations via SSE2 backend.
pub static MORUS1280_SSE2_OPS: Counter = Counter::new();
/// MORUS-1280 operations via SSSE3 backend.
pub static MORUS1280_SSSE3_OPS: Counter = Counter::new();
/// MORUS-1280 operations via SSE4.1 backend.
pub static MORUS1280_SSE41_OPS: Counter = Counter::new();
/// MORUS-1280 operations via SSE4.2 backend.
pub static MORUS1280_SSE42_OPS: Counter = Counter::new();
/// MORUS-1280 operations via NEON backend.
pub static MORUS1280_NEON_OPS: Counter = Counter::new();

/// Accepted 0-RTT early data attempts.
pub static ZERO_RTT_ACCEPT_TOTAL: Counter = Counter::new();
/// Rejected 0-RTT replays caught by the strike register.
pub static ZERO_RTT_REPLAY_REJECT_TOTAL: Counter = Counter::new();

/// Total compression eligibility decisions.
pub static COMPRESS_DECISIONS_TOTAL: Counter = Counter::new();
/// Compression decisions that allowed compression.
pub static COMPRESS_DECISIONS_ALLOW: Counter = Counter::new();
/// Compression skipped due to payload length threshold.
pub static COMPRESS_DECISIONS_SKIP_LEN: Counter = Counter::new();
/// Compression skipped due to high loss rate.
pub static COMPRESS_DECISIONS_SKIP_LOSS: Counter = Counter::new();
/// Compression skipped due to incompatible stealth profile.
pub static COMPRESS_DECISIONS_SKIP_PROFILE: Counter = Counter::new();

/// Total calls to GHASH scalar fallback path.
pub static GHASH_SCALAR_CALLS: Counter = Counter::new();
/// Total bytes processed by GHASH scalar fallback.
pub static GHASH_SCALAR_BYTES: Counter = Counter::new();
/// FEC operations using AVX-512 backend.
pub static FEC_AVX512_OPS: Counter = Counter::new();
/// FEC GF(2^16) operations using VBMI2 instructions.
pub static FEC_GF16_VBMI2_OPS: Counter = Counter::new();
/// FEC operations using NEON backend.
pub static FEC_NEON_OPS: Counter = Counter::new();
/// FEC operations using SVE2 backend.
pub static FEC_SVE2_OPS: Counter = Counter::new();
/// FEC Berlekamp-Massey solver operations using SVE2.
pub static FEC_BERLEKAMP_SVE2_OPS: Counter = Counter::new();

/// General AVX-512 SIMD operations performed.
pub static AVX512_OPS: Counter = Counter::new();
/// General AVX2 SIMD operations performed.
pub static AVX2_OPS: Counter = Counter::new();
// SSE2_OPS removed - baseline is SSE4.2
/// General NEON SIMD operations performed.
pub static NEON_OPS: Counter = Counter::new();
/// General SVE2 SIMD operations performed.
pub static SVE2_OPS: Counter = Counter::new();
/// General scalar (non-SIMD) fallback operations performed.
pub static SCALAR_OPS: Counter = Counter::new();

/// AES block operations via AES-NI (x86).
pub static AES_BLOCK_AESNI_OPS: Counter = Counter::new();
/// AES block operations via VAES (x86 wide).
pub static AES_BLOCK_VAES_OPS: Counter = Counter::new();
/// AES block operations via AESE (ARM).
pub static AES_BLOCK_AESE_OPS: Counter = Counter::new();
/// AES block operations via SSSE3 software table.
pub static AES_BLOCK_SSSE3_OPS: Counter = Counter::new();
/// AES block operations via SVE (ARM).
pub static AES_BLOCK_SVE_OPS: Counter = Counter::new();
/// AES block operations via NEON table lookup.
pub static AES_BLOCK_NEON_TABLE_OPS: Counter = Counter::new();
/// AES block operations via scalar fallback.
pub static AES_BLOCK_SCALAR_OPS: Counter = Counter::new();
/// SHA-256 operations via AVX2 backend.
pub static SHA256_AVX2_OPS: Counter = Counter::new();
/// SHA-256 operations via VNNI backend.
pub static SHA256_VNNI_OPS: Counter = Counter::new();
/// SHA-256 operations via NEON backend.
pub static SHA256_NEON_OPS: Counter = Counter::new();
/// SHA-256 operations via SVE2 backend.
pub static SHA256_SVE2_OPS: Counter = Counter::new();
/// SHA-256 operations via scalar fallback.
pub static SHA256_SCALAR_OPS: Counter = Counter::new();
/// HMAC-SHA256 operations via AVX2 backend.
pub static HMAC_SHA256_AVX2_OPS: Counter = Counter::new();
/// HMAC-SHA256 operations via VNNI backend.
pub static HMAC_SHA256_VNNI_OPS: Counter = Counter::new();
/// HMAC-SHA256 operations via NEON backend.
pub static HMAC_SHA256_NEON_OPS: Counter = Counter::new();
/// HMAC-SHA256 operations via SVE2 backend.
pub static HMAC_SHA256_SVE2_OPS: Counter = Counter::new();
/// HMAC-SHA256 operations via scalar fallback.
pub static HMAC_SHA256_SCALAR_OPS: Counter = Counter::new();

/// GHASH operations via PCLMULQDQ (x86).
pub static GHASH_PCLMUL_OPS: Counter = Counter::new();
/// GHASH operations via VPCLMULQDQ (x86 wide).
pub static GHASH_VPCLMUL_OPS: Counter = Counter::new();
/// GHASH operations via PMULL (ARM).
pub static GHASH_PMULL_OPS: Counter = Counter::new();
/// GHASH operations via NEON backend.
pub static GHASH_NEON_OPS: Counter = Counter::new();
/// GHASH operations via SSE backend.
pub static GHASH_SSE_OPS: Counter = Counter::new();
/// GHASH operations via scalar fallback.
pub static GHASH_SCALAR_OPS: Counter = Counter::new();

/// ChaCha20 4-way parallel operations via AVX2.
pub static CHACHA20_X4_AVX2_OPS: Counter = Counter::new();
/// ChaCha20 4-way parallel operations via AVX.
pub static CHACHA20_X4_AVX_OPS: Counter = Counter::new();
/// ChaCha20 4-way parallel operations via SSE4.1.
pub static CHACHA20_X4_SSE41_OPS: Counter = Counter::new();
/// ChaCha20 4-way parallel operations via NEON.
pub static CHACHA20_X4_NEON_OPS: Counter = Counter::new();
/// ChaCha20 4-way parallel operations via scalar fallback.
pub static CHACHA20_X4_SCALAR_OPS: Counter = Counter::new();

/// CRC32 operations via SSE4.2 hardware.
pub static CRC32_SSE42_OPS: Counter = Counter::new();
/// CRC32 operations via ARM CRC32 hardware.
pub static CRC32_ARM_OPS: Counter = Counter::new();
/// CRC32 operations via scalar fallback.
pub static CRC32_SCALAR_OPS: Counter = Counter::new();

/// FEC Galois field operations via AVX2 path.
pub static FEC_AVX2_GF_OPS: Counter = Counter::new();
/// FEC operations via SSSE3 path.
pub static FEC_SSSE3_OPS: Counter = Counter::new();
/// FEC operations via GFNI (Galois Field New Instructions).
pub static FEC_GFNI_OPS: Counter = Counter::new();

/// GF(2^16) multiplication via VPCLMULQDQ for Extreme/Ultra FEC.
pub static GF16_VPCLMUL_OPS: Counter = Counter::new();
/// GF(2^16) multiplication via PCLMULQDQ for Extreme/Ultra FEC.
pub static GF16_PCLMUL_OPS: Counter = Counter::new();
/// Pattern matching operations via AVX-512 VBMI2.
pub static PATTERN_AVX512_VBMI2_OPS: Counter = Counter::new();
/// Pattern matching operations via AVX-512.
pub static PATTERN_AVX512_OPS: Counter = Counter::new();
/// Pattern matching operations via AVX2.
pub static PATTERN_AVX2_OPS: Counter = Counter::new();
/// Pattern matching operations via NEON.
pub static PATTERN_NEON_OPS: Counter = Counter::new();
/// Pattern matching operations via SVE2.
pub static PATTERN_SVE2_OPS: Counter = Counter::new();
/// Pattern matching operations via scalar fallback.
pub static PATTERN_SCALAR_OPS: Counter = Counter::new();

/// Estimated speedup factor from unsafe optimizations (reserved).
pub static UNSAFE_SPEEDUP_FACTOR: AtomicU64 = AtomicU64::new(100);
/// Estimated latency reduction in microseconds from unsafe path (reserved).
pub static UNSAFE_LATENCY_REDUCTION_US: AtomicU64 = AtomicU64::new(0);
/// Estimated throughput in Gbps from unsafe path (reserved).
pub static UNSAFE_THROUGHPUT_GBPS: AtomicU64 = AtomicU64::new(0);
/// Active crypto profile identifier (maps to CpuProfile enum).
pub static CRYPTO_PROFILE: AtomicU64 = AtomicU64::new(0);

/// Total AEGIS batched encrypt/decrypt operations.
pub static AEGIS_BATCH_OPS: AtomicU64 = AtomicU64::new(0);

/// Whether XDP fast path is currently active (0/1 gauge).
pub static XDP_ACTIVE: AtomicU64 = AtomicU64::new(0);
/// XDP operations that fell back to kernel network stack.
pub static XDP_FALLBACKS: Counter = Counter::new();
/// Total bytes sent via XDP fast path.
pub static XDP_BYTES_SENT: Counter = Counter::new();
/// Total bytes received via XDP fast path.
pub static XDP_BYTES_RECEIVED: Counter = Counter::new();
/// Cumulative XDP send latency (microseconds).
pub static XDP_SEND_LATENCY: Counter = Counter::new();
/// Cumulative XDP receive latency (microseconds).
pub static XDP_RECV_LATENCY: Counter = Counter::new();
/// Current XDP throughput gauge.
pub static XDP_THROUGHPUT: SafeGauge = SafeGauge::new();

/// Total capacity of the memory pool in blocks.
pub static MEM_POOL_CAPACITY: AtomicU64 = AtomicU64::new(0);
/// Memory pool block size in bytes.
pub static MEM_POOL_BLOCK_SIZE: AtomicU64 = AtomicU64::new(0);
/// Number of memory pool blocks currently in use.
pub static MEM_POOL_IN_USE: AtomicU64 = AtomicU64::new(0);
/// Total memory pool usage in bytes.
pub static MEM_POOL_USAGE_BYTES: AtomicU64 = AtomicU64::new(0);
/// Memory pool fragmentation metric.
pub static MEM_POOL_FRAGMENTATION: AtomicU64 = AtomicU64::new(0);
/// Memory pool utilization as a percentage.
pub static MEM_POOL_UTILIZATION: AtomicU64 = AtomicU64::new(0);
/// NUMA allocation policy: 0=Local, 1=Preferred, 2=Interleave.
pub static MEM_POOL_NUMA_POLICY: AtomicU64 = AtomicU64::new(0);

/// Whether any SIMD acceleration is active (0/1 gauge).
pub static SIMD_ACTIVE: AtomicU64 = AtomicU64::new(0);
/// Cumulative AVX2 usage counter across all subsystems.
pub static SIMD_USAGE_AVX2: AtomicU64 = AtomicU64::new(0);
/// Cumulative AVX-512 usage counter across all subsystems.
pub static SIMD_USAGE_AVX512: AtomicU64 = AtomicU64::new(0);
/// Cumulative AVX10/256 usage counter.
pub static SIMD_USAGE_AVX10_256: AtomicU64 = AtomicU64::new(0);
/// Cumulative AVX10/512 usage counter.
pub static SIMD_USAGE_AVX10_512: AtomicU64 = AtomicU64::new(0);
/// Legacy SSE2 usage counter (compatibility).
pub static SIMD_USAGE_SSE2: AtomicU64 = AtomicU64::new(0);
/// Cumulative NEON usage counter.
pub static SIMD_USAGE_NEON: AtomicU64 = AtomicU64::new(0);
/// Cumulative SVE2 usage counter.
pub static SIMD_USAGE_SVE2: AtomicU64 = AtomicU64::new(0);
/// Cumulative scalar fallback usage counter.
pub static SIMD_USAGE_SCALAR: AtomicU64 = AtomicU64::new(0);
/// Cumulative RISC-V Vector usage counter.
pub static SIMD_USAGE_RVV: AtomicU64 = AtomicU64::new(0);
/// Argsort operations via AVX2.
pub static ARGSORT_AVX2_OPS: Counter = Counter::new();
/// Argsort operations via NEON.
pub static ARGSORT_NEON_OPS: Counter = Counter::new();
/// Argsort operations via scalar fallback.
pub static ARGSORT_FALLBACK_OPS: Counter = Counter::new();
/// Moving average computations via AVX-512.
pub static MOVING_AVG_AVX512_OPS: Counter = Counter::new();
/// Moving average computations via AVX2.
pub static MOVING_AVG_AVX2_OPS: Counter = Counter::new();
/// Moving average computations via NEON.
pub static MOVING_AVG_NEON_OPS: Counter = Counter::new();
/// Moving average computations via SSE.
pub static MOVING_AVG_SSE_OPS: Counter = Counter::new();
/// Moving average computations via scalar fallback.
pub static MOVING_AVG_SCALAR_OPS: Counter = Counter::new();
/// TLS-cover layer ChaCha20 cipher operations.
pub static FAKETLS_CHACHA_OPS: Counter = Counter::new();
/// TLS-cover layer AES-GCM cipher operations.
pub static FAKETLS_AES_GCM_OPS: Counter = Counter::new();
/// TLS-cover layer cipher operation failures.
pub static FAKETLS_CIPHER_FAILURES: Counter = Counter::new();
/// AES-CTR operations via AES-NI (x86).
pub static AES_CTR_AESNI_OPS: Counter = Counter::new();
/// AES-CTR operations via AESE (ARM).
pub static AES_CTR_AESE_OPS: Counter = Counter::new();
/// AES-CTR operations via SVE (ARM).
pub static AES_CTR_SVE_OPS: Counter = Counter::new();
/// AES-CTR operations via SSSE3 software table.
pub static AES_CTR_SSSE3_OPS: Counter = Counter::new();
/// AES-CTR operations via scalar fallback.
pub static AES_CTR_SCALAR_OPS: Counter = Counter::new();
/// Poly1305 MAC operations via AVX-512.
pub static POLY1305_AVX512_OPS: Counter = Counter::new();
/// Poly1305 MAC operations via AVX2.
pub static POLY1305_AVX2_OPS: Counter = Counter::new();
/// Poly1305 MAC operations via SSE2.
pub static POLY1305_SSE2_OPS: Counter = Counter::new();
/// Poly1305 MAC operations via SVE.
pub static POLY1305_SVE_OPS: Counter = Counter::new();
/// Poly1305 MAC operations via NEON.
pub static POLY1305_NEON_OPS: Counter = Counter::new();
/// Poly1305 MAC operations via scalar fallback.
pub static POLY1305_SCALAR_OPS: Counter = Counter::new();
/// f32 SIMD sum reductions via AVX-512.
pub static ITER_SUM_F32_AVX512_OPS: Counter = Counter::new();
/// f32 SIMD sum reductions via AVX2.
pub static ITER_SUM_F32_AVX2_OPS: Counter = Counter::new();
/// f32 SIMD sum reductions via SSE.
pub static ITER_SUM_F32_SSE_OPS: Counter = Counter::new();
/// f32 SIMD sum reductions via NEON.
pub static ITER_SUM_F32_NEON_OPS: Counter = Counter::new();
/// f32 SIMD sum reductions via SVE.
pub static ITER_SUM_F32_SVE_OPS: Counter = Counter::new();
/// f32 SIMD sum reductions via RISC-V Vector.
pub static ITER_SUM_F32_RVV_OPS: Counter = Counter::new();
/// f32 sum reductions via scalar fallback.
pub static ITER_SUM_F32_SCALAR_OPS: Counter = Counter::new();
/// u32 SIMD sum reductions via AVX-512.
pub static ITER_SUM_U32_AVX512_OPS: Counter = Counter::new();
/// u32 SIMD sum reductions via AVX2.
pub static ITER_SUM_U32_AVX2_OPS: Counter = Counter::new();
/// u32 SIMD sum reductions via SSE.
pub static ITER_SUM_U32_SSE_OPS: Counter = Counter::new();
/// u32 SIMD sum reductions via NEON.
pub static ITER_SUM_U32_NEON_OPS: Counter = Counter::new();
/// u32 SIMD sum reductions via SVE.
pub static ITER_SUM_U32_SVE_OPS: Counter = Counter::new();
/// u32 SIMD sum reductions via RISC-V Vector.
pub static ITER_SUM_U32_RVV_OPS: Counter = Counter::new();
/// u32 sum reductions via scalar fallback.
pub static ITER_SUM_U32_SCALAR_OPS: Counter = Counter::new();
/// u64 SIMD sum reductions via AVX-512.
pub static ITER_SUM_U64_AVX512_OPS: Counter = Counter::new();
/// u64 SIMD sum reductions via AVX2.
pub static ITER_SUM_U64_AVX2_OPS: Counter = Counter::new();
/// u64 SIMD sum reductions via SSE.
pub static ITER_SUM_U64_SSE_OPS: Counter = Counter::new();
/// u64 SIMD sum reductions via NEON.
pub static ITER_SUM_U64_NEON_OPS: Counter = Counter::new();
/// u64 SIMD sum reductions via SVE.
pub static ITER_SUM_U64_SVE_OPS: Counter = Counter::new();
/// u64 SIMD sum reductions via RISC-V Vector.
pub static ITER_SUM_U64_RVV_OPS: Counter = Counter::new();
/// u64 sum reductions via scalar fallback.
pub static ITER_SUM_U64_SCALAR_OPS: Counter = Counter::new();

/// Bitmask of detected CPU features (see CPU_MASK_* constants).
pub static CPU_FEATURE_MASK: AtomicI64 = AtomicI64::new(0);
/// Total IO driver copy operations.
pub static IO_DRIVER_COPY_OPS: AtomicU64 = AtomicU64::new(0);
/// Total bytes copied by the IO driver.
pub static IO_DRIVER_COPY_BYTES: AtomicU64 = AtomicU64::new(0);
/// Packets drained in IO driver batch operations.
pub static IO_DRIVER_BATCH_DRAIN_PACKETS: AtomicU64 = AtomicU64::new(0);
/// Total sendmmsg() system calls made by IO driver.
pub static IO_DRIVER_SENDMMSG_CALLS: AtomicU64 = AtomicU64::new(0);
/// Total packets sent via sendmmsg() batching.
pub static IO_DRIVER_SENDMMSG_PACKETS: AtomicU64 = AtomicU64::new(0);
/// Total io_uring submit_and_wait() calls.
pub static IO_URING_SUBMIT_CALLS: Counter = Counter::new();
/// Total packets sent via io_uring batching.
pub static IO_URING_SUBMIT_PACKETS: Counter = Counter::new();
/// io_uring send failures that fell back to sendmmsg.
pub static IO_URING_FALLBACKS: Counter = Counter::new();
/// Whether io_uring SQPOLL mode is active (0 = standard mode, 1 = SQPOLL active).
pub static IO_URING_SQPOLL_ACTIVE: AtomicU64 = AtomicU64::new(0);
/// Total packets sent via io_uring zero-copy SendMsgZc path.
pub static IO_URING_ZC_SENDS: Counter = Counter::new();
/// Total zero-copy buffer-release notifications received from the kernel.
pub static IO_URING_ZC_NOTIFS: Counter = Counter::new();
/// Total io_uring submit calls from the server outbound path.
pub static IO_URING_SERVER_SUBMIT_CALLS: Counter = Counter::new();
/// Total packets sent via the server io_uring batch path.
pub static IO_URING_SERVER_PACKETS: Counter = Counter::new();
/// Total io_uring recv drain cycles (CQ drain batches).
pub static IO_URING_RECV_BATCHES: Counter = Counter::new();
/// Total packets received via the io_uring recv path.
pub static IO_URING_RECV_PACKETS: Counter = Counter::new();
/// Whether io_uring recv is active (0 = inactive, 1 = active).
pub static IO_URING_RECV_ACTIVE: AtomicU64 = AtomicU64::new(0);

/// Process memory usage in bytes (updated periodically).
pub static MEMORY_USAGE_BYTES: AtomicU64 = AtomicU64::new(0);
/// Total bytes sent across all transports.
pub static BYTES_SENT: Counter = Counter::new();
/// Total bytes received across all transports.
pub static BYTES_RECEIVED: Counter = Counter::new();

/// Last FEC decoding time in milliseconds.
pub static DECODING_TIME_MS: AtomicU64 = AtomicU64::new(0);
/// Sent-packet records evicted because a packet-number space hit its retention budget.
///
/// A non-zero value means loss detection lost visibility of the oldest unacknowledged packets in
/// that space, which is a signal that the in-flight window or the ACK pattern is abnormal.
pub static RECOVERY_SENT_RETENTION_EVICTIONS: Counter = Counter::new();
/// Wiedemann solver invocations for FEC recovery.
pub static WIEDEMANN_USAGE: Counter = Counter::new();
/// Wiedemann solver operations via a verified AMX arithmetic backend.
///
/// The current production path deliberately keeps this at zero until TODO-818
/// supplies a real AMX GF(256) kernel and compiler/runtime proof.
pub static WIEDEMANN_AMX_OPS: Counter = Counter::new();
/// Wiedemann solver operations via scalar fallback.
pub static WIEDEMANN_SCALAR_OPS: Counter = Counter::new();
/// Logical column-vector scratch allocations for Wiedemann scalar SpMV.
pub static WIEDEMANN_COLUMN_BUFFER_ALLOCS: Counter = Counter::new();
/// Logical accumulator scratch allocations for Wiedemann scalar SpMV.
pub static WIEDEMANN_SPMV_ACCUMULATOR_ALLOCS: Counter = Counter::new();
/// Logical matrix and RHS scratch allocations in the per-byte solve.
pub static WIEDEMANN_MATRIX_RHS_ALLOCS: Counter = Counter::new();
/// Logical Krylov-vector scratch allocations in a solve.
pub static WIEDEMANN_KRYLOV_ALLOCS: Counter = Counter::new();
/// Logical per-iteration vector allocations in a solve.
pub static WIEDEMANN_ITERATION_ALLOCS: Counter = Counter::new();
/// Logical candidate and temporary-result allocations in a solve.
pub static WIEDEMANN_CANDIDATE_ALLOCS: Counter = Counter::new();
/// Logical AMX matrix/vector scratch allocations in a solve.
///
/// Reserved for the verified AMX backend; the current scalar fallback does not
/// allocate or report AMX scratch.
pub static WIEDEMANN_AMX_SCRATCH_ALLOCS: Counter = Counter::new();
/// Stable public FEC codec mode mapping used by every telemetry export.
pub const FEC_MODE_MAPPING: [(u8, &str); 9] = [
    (0, "zero"),
    (1, "light"),
    (2, "normal"),
    (3, "medium"),
    (4, "strong"),
    (5, "extreme"),
    (6, "ultra"),
    (7, "fountain"),
    (8, "streaming"),
];
/// Active FEC connections per stable codec mode ID in this process.
pub static FEC_ACTIVE_CONNECTIONS_BY_MODE: [AtomicU64; FEC_MODE_MAPPING.len()] =
    [const { AtomicU64::new(0) }; FEC_MODE_MAPPING.len()];
/// Total active FEC connections in this process.
pub static FEC_ACTIVE_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
/// Sum of effective source-window sizes across active FEC connections.
pub static FEC_ACTIVE_WINDOW_SUM: AtomicU64 = AtomicU64::new(0);
/// Total FEC mode transitions.
pub static FEC_MODE_SWITCHES: AtomicU64 = AtomicU64::new(0);
/// FEC mode switches triggered by adaptive controller.
pub static FEC_SWITCH_REASON_ADAPTIVE: AtomicU64 = AtomicU64::new(0);
/// FEC mode switches triggered by force-on policy.
pub static FEC_SWITCH_REASON_FORCE_ON: AtomicU64 = AtomicU64::new(0);
/// FEC mode switches triggered by extreme loss detection.
pub static FEC_SWITCH_REASON_EXTREME: AtomicU64 = AtomicU64::new(0);
/// FEC mode switches triggered by network disturbance.
pub static FEC_SWITCH_REASON_DISTURBANCE: AtomicU64 = AtomicU64::new(0);
/// FEC mode switches triggered by an explicit streaming hint.
pub static FEC_SWITCH_REASON_STREAMING_HINT: AtomicU64 = AtomicU64::new(0);
/// Accepted active operator-policy transitions.
pub static FEC_POLICY_TRANSITIONS: AtomicU64 = AtomicU64::new(0);
/// Packets included in process-wide FEC loss observations.
pub static FEC_OBSERVED_PACKETS: Counter = Counter::new();
/// Lost packets included in process-wide FEC loss observations.
pub static FEC_OBSERVED_LOST_PACKETS: Counter = Counter::new();
/// Source datagrams serialized into the network-facing output buffer.
pub static FEC_SOURCE_PACKETS_SENT: Counter = Counter::new();
/// Repair datagrams serialized into the network-facing output buffer.
pub static FEC_REPAIR_PACKETS_SENT: Counter = Counter::new();
/// Original QUIC payload bytes represented by sent source datagrams.
pub static FEC_SOURCE_PAYLOAD_BYTES_SENT: Counter = Counter::new();
/// Source wire bytes serialized for transmission.
pub static FEC_SOURCE_WIRE_BYTES_SENT: Counter = Counter::new();
/// Repair wire bytes serialized for transmission.
pub static FEC_REPAIR_WIRE_BYTES_SENT: Counter = Counter::new();
/// Accepted source datagrams received from the network.
pub static FEC_SOURCE_PACKETS_RECEIVED: Counter = Counter::new();
/// Accepted repair datagrams received from the network.
pub static FEC_REPAIR_PACKETS_RECEIVED: Counter = Counter::new();
/// Original QUIC payload bytes represented by received source datagrams.
pub static FEC_SOURCE_PAYLOAD_BYTES_RECEIVED: Counter = Counter::new();
/// Accepted wire bytes received for source datagrams.
pub static FEC_SOURCE_WIRE_BYTES_RECEIVED: Counter = Counter::new();
/// Accepted wire bytes received for repair datagrams.
pub static FEC_REPAIR_WIRE_BYTES_RECEIVED: Counter = Counter::new();
/// Source packets delivered to the QUIC decoder, originals plus recoveries.
pub static FEC_DECODED_PACKETS: Counter = Counter::new();
/// Source packets reconstructed from repair data.
pub static FEC_RECOVERED_PACKETS: Counter = Counter::new();
/// Original QUIC payload bytes reconstructed from repair data.
pub static FEC_RECOVERED_PAYLOAD_BYTES: Counter = Counter::new();
/// Repair equations admitted to a decoder backend.
pub static FEC_DECODER_EQUATIONS: Counter = Counter::new();
/// Full GF(256)/GF(65536) solver attempts.
pub static FEC_DECODER_SOLVE_ATTEMPTS: Counter = Counter::new();
/// Solver attempts that produced a complete recovered solution.
pub static FEC_DECODER_SOLVE_SUCCESSES: Counter = Counter::new();
/// Cumulative wall-clock time spent in full solver attempts, in nanoseconds.
pub static FEC_DECODER_SOLVE_TIME_NS: Counter = Counter::new();
/// Receive-window repair dedup entries evicted at the bounded FIFO limit.
pub static FEC_DECODER_DEDUP_EVICTIONS: Counter = Counter::new();
/// Fountain decoder equations evicted at the bounded FIFO limit.
pub static FEC_FOUNTAIN_DECODER_EVICTIONS: Counter = Counter::new();
/// Fountain repair symbols rejected by decoder state or admission limits.
pub static FEC_FOUNTAIN_DECODER_ADMISSION_REJECTIONS: Counter = Counter::new();
/// Fountain decoder dependency entries examined during propagation.
pub static FEC_FOUNTAIN_DECODER_PROPAGATION_WORK: Counter = Counter::new();

fn atomic_saturating_sub(value: &AtomicU64, decrement: u64) {
    let _ = value.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(decrement))
    });
}

fn fec_wire_overhead_ppm(source_payload_bytes: u64, wire_bytes: u64) -> u64 {
    if source_payload_bytes == 0 {
        return 0;
    }
    let overhead_bytes = wire_bytes.saturating_sub(source_payload_bytes);
    (overhead_bytes as u128)
        .saturating_mul(1_000_000)
        .checked_div(source_payload_bytes as u128)
        .unwrap_or(0)
        .min(u64::MAX as u128) as u64
}

/// Register one telemetry-enabled FEC connection in the process aggregate.
pub fn fec_instance_opened(mode_id: u8, effective_window: usize) {
    let Some(mode_count) = FEC_ACTIVE_CONNECTIONS_BY_MODE.get(mode_id as usize) else {
        return;
    };
    mode_count.fetch_add(1, Ordering::Relaxed);
    FEC_ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    FEC_ACTIVE_WINDOW_SUM.fetch_add(effective_window as u64, Ordering::Relaxed);
}

/// Remove one telemetry-enabled FEC connection from the process aggregate.
pub fn fec_instance_closed(mode_id: u8, effective_window: usize) {
    let Some(mode_count) = FEC_ACTIVE_CONNECTIONS_BY_MODE.get(mode_id as usize) else {
        return;
    };
    atomic_saturating_sub(mode_count, 1);
    atomic_saturating_sub(&FEC_ACTIVE_CONNECTIONS, 1);
    atomic_saturating_sub(&FEC_ACTIVE_WINDOW_SUM, effective_window as u64);
}

/// Move one active connection between exact process-aggregate mode/window buckets.
pub fn fec_instance_transition(
    old_mode_id: u8,
    old_effective_window: usize,
    new_mode_id: u8,
    new_effective_window: usize,
) {
    let Some(old_mode_count) = FEC_ACTIVE_CONNECTIONS_BY_MODE.get(old_mode_id as usize) else {
        return;
    };
    let Some(new_mode_count) = FEC_ACTIVE_CONNECTIONS_BY_MODE.get(new_mode_id as usize) else {
        return;
    };
    if old_mode_id != new_mode_id {
        atomic_saturating_sub(old_mode_count, 1);
        new_mode_count.fetch_add(1, Ordering::Relaxed);
    }
    if old_effective_window != new_effective_window {
        atomic_saturating_sub(&FEC_ACTIVE_WINDOW_SUM, old_effective_window as u64);
        FEC_ACTIVE_WINDOW_SUM.fetch_add(new_effective_window as u64, Ordering::Relaxed);
    }
}

/// Add one loss-controller sample to the process aggregate.
pub fn fec_observe_loss(lost_packets: u64, observed_packets: u64) {
    FEC_OBSERVED_LOST_PACKETS.inc_by(lost_packets.min(observed_packets));
    FEC_OBSERVED_PACKETS.inc_by(observed_packets);
}

/// Add independently timed transport send/loss callback deltas to the process aggregate.
pub fn fec_observe_transport_loss(lost_packets: u64, sent_packets: u64) {
    FEC_OBSERVED_LOST_PACKETS.inc_by(lost_packets);
    FEC_OBSERVED_PACKETS.inc_by(sent_packets);
}

/// Record one datagram only after the network-facing serializer accepts it.
pub fn fec_observe_wire_send(systematic: bool, source_payload_bytes: u64, wire_bytes: u64) {
    if systematic {
        FEC_SOURCE_PACKETS_SENT.inc();
        FEC_SOURCE_PAYLOAD_BYTES_SENT.inc_by(source_payload_bytes);
        FEC_SOURCE_WIRE_BYTES_SENT.inc_by(wire_bytes);
    } else {
        FEC_REPAIR_PACKETS_SENT.inc();
        FEC_REPAIR_WIRE_BYTES_SENT.inc_by(wire_bytes);
    }
}

/// Record one accepted network datagram and its decoder output.
#[allow(clippy::too_many_arguments)]
pub fn fec_observe_wire_receive(
    systematic: bool,
    source_payload_bytes: u64,
    wire_bytes: u64,
    decoded_packets: u64,
    recovered_packets: u64,
    recovered_payload_bytes: u64,
) {
    if systematic {
        FEC_SOURCE_PACKETS_RECEIVED.inc();
        FEC_SOURCE_PAYLOAD_BYTES_RECEIVED.inc_by(source_payload_bytes);
        FEC_SOURCE_WIRE_BYTES_RECEIVED.inc_by(wire_bytes);
    } else {
        FEC_REPAIR_PACKETS_RECEIVED.inc();
        FEC_REPAIR_WIRE_BYTES_RECEIVED.inc_by(wire_bytes);
    }
    FEC_DECODED_PACKETS.inc_by(decoded_packets);
    FEC_RECOVERED_PACKETS.inc_by(recovered_packets);
    FEC_RECOVERED_PAYLOAD_BYTES.inc_by(recovered_payload_bytes);
}

/// FEC buffer overflow events.
pub static FEC_OVERFLOWS: AtomicU64 = AtomicU64::new(0);
/// Total DNS resolution errors.
pub static DNS_ERRORS: AtomicU64 = AtomicU64::new(0);
/// Current FEC emitted-packet queue depth.
pub static FEC_EMITTED_QUEUE: AtomicU64 = AtomicU64::new(0);
/// Fountain code recovery progress (scaled by 1,000,000).
pub static FOUNTAIN_PROGRESS: AtomicU64 = AtomicU64::new(0);
/// Current fountain code symbol size in bytes.
pub static FOUNTAIN_SYMBOL_SIZE: AtomicU64 = AtomicU64::new(0);
/// Unique FEC repair symbols emitted.
pub static FEC_EMITTED_UNIQUE: AtomicU64 = AtomicU64::new(0);
/// FEC emission reordering depth.
pub static FEC_EMITTED_ORDER_DEPTH: AtomicU64 = AtomicU64::new(0);

/// FEC lazy decoding repairs skipped (no loss detected).
pub static FEC_LAZY_SKIPPED: AtomicU64 = AtomicU64::new(0);
/// FEC repair symbols generated across interleaved blocks.
pub static FEC_INTERLEAVE_REPAIRS: AtomicU64 = AtomicU64::new(0);
/// Ultra-Zero-Mode upgrades from zero encoder to real FEC on loss.
pub static ZERO_MODE_UPGRADES: AtomicU64 = AtomicU64::new(0);

/// DNS-over-HTTPS queries routed through stealth path.
pub static STEALTH_DOH: AtomicU64 = AtomicU64::new(0);
/// Domain fronting operations performed.
pub static STEALTH_FRONTING: AtomicU64 = AtomicU64::new(0);
/// XOR obfuscation operations applied.
pub static STEALTH_XOR: AtomicU64 = AtomicU64::new(0);
/// Stealth padding operations via GFNI instructions.
pub static STEALTH_PADDING_GFNI_OPS: Counter = Counter::new();
/// HTTP/3 server push promises sent for cover traffic.
pub static STEALTH_PUSH_PROMISES: Counter = Counter::new();
/// Total bytes sent via HTTP/3 server push cover traffic.
pub static STEALTH_PUSH_BYTES: AtomicU64 = AtomicU64::new(0);
/// Congestion aggregation batches via VNNI.
pub static CONGESTION_VNNI_BATCHES: Counter = Counter::new();
/// Congestion aggregation batches via AVX2.
pub static CONGESTION_AVX2_BATCHES: Counter = Counter::new();
/// Congestion aggregation batches via NEON.
pub static CONGESTION_NEON_BATCHES: Counter = Counter::new();

/// Total bytes sent through MASQUE tunnel.
pub static MASQUE_BYTES_SENT: Counter = Counter::new();
/// Total bytes received through MASQUE tunnel.
pub static MASQUE_BYTES_RECEIVED: Counter = Counter::new();
/// MASQUE capsule type 0x00 (DATAGRAM) messages processed.
pub static MASQUE_CAPSULE_00: Counter = Counter::new();
/// MASQUE capsule type 0x21 (REGISTER_DATA_CONTEXT) messages processed.
pub static MASQUE_CAPSULE_21: Counter = Counter::new();
/// MASQUE capsule type 0x22 (CLOSE_DATA_CONTEXT) messages processed.
pub static MASQUE_CAPSULE_22: Counter = Counter::new();
/// Total bytes in MASQUE capsule type 0x00 messages.
pub static MASQUE_CAPSULE_00_BYTES: Counter = Counter::new();
/// Total bytes in MASQUE capsule type 0x21 messages.
pub static MASQUE_CAPSULE_21_BYTES: Counter = Counter::new();
/// Total bytes in MASQUE capsule type 0x22 messages.
pub static MASQUE_CAPSULE_22_BYTES: Counter = Counter::new();

/// Active stealth browser fingerprint profile identifier.
pub static STEALTH_BROWSER_PROFILE: SafeGauge = SafeGauge::new();
/// Active stealth OS fingerprint profile identifier.
pub static STEALTH_OS_PROFILE: SafeGauge = SafeGauge::new();

/// Most recent ACK delay in microseconds.
pub static ACK_DELAY_LAST_US: AtomicU64 = AtomicU64::new(0);
/// ACK delays in the <= 1ms histogram bucket.
pub static ACK_DELAY_BUCKET_LE_1MS: Counter = Counter::new();
/// ACK delays in the <= 4ms histogram bucket.
pub static ACK_DELAY_BUCKET_LE_4MS: Counter = Counter::new();
/// ACK delays in the <= 16ms histogram bucket.
pub static ACK_DELAY_BUCKET_LE_16MS: Counter = Counter::new();
/// ACK delays in the <= 64ms histogram bucket.
pub static ACK_DELAY_BUCKET_LE_64MS: Counter = Counter::new();
/// ACK delays in the <= 256ms histogram bucket.
pub static ACK_DELAY_BUCKET_LE_256MS: Counter = Counter::new();
/// ACK delays exceeding 256ms.
pub static ACK_DELAY_BUCKET_GT_256MS: Counter = Counter::new();

/// Cumulative stealth choke/pacing sleep time in milliseconds.
pub static CHOKE_SLEEP_MS: Counter = Counter::new();
/// Total bytes delayed by stealth choke/pacing.
pub static CHOKED_BYTES: Counter = Counter::new();

/// Total compression attempts.
pub static COMPRESS_ATTEMPTS: Counter = Counter::new();
/// Successful compression operations.
pub static COMPRESS_SUCCESS: Counter = Counter::new();
/// Compressed outputs that were truncated to fit buffer.
pub static COMPRESS_TRUNCATIONS: Counter = Counter::new();
/// Compression operations that used a shared dictionary.
pub static COMPRESS_DICT_USED: Counter = Counter::new();
/// Total bytes output from compression.
pub static COMPRESS_BYTES_OUT: Counter = Counter::new();
/// Total bytes input to compression.
pub static COMPRESS_BYTES_IN: Counter = Counter::new();
/// Payloads classified as textual by entropy analysis.
pub static ENTROPY_TEXTUAL_SEEN: Counter = Counter::new();
/// Compression skipped due to high entropy (incompressible).
pub static ENTROPY_SKIP: Counter = Counter::new();
/// Compression preprocessor invocations.
pub static COMPRESS_PREPROC_CALLS: Counter = Counter::new();
/// Preprocessor payloads classified as textual.
pub static COMPRESS_PREPROC_TEXTUAL: Counter = Counter::new();
/// Preprocessor payloads classified as binary.
pub static COMPRESS_PREPROC_BINARY: Counter = Counter::new();
/// ASCII bytes seen by compression preprocessor.
pub static COMPRESS_PREPROC_ASCII_BYTES: Counter = Counter::new();
/// High-byte (non-ASCII) bytes seen by preprocessor.
pub static COMPRESS_PREPROC_HIGH_BYTES: Counter = Counter::new();
/// Newline characters seen by preprocessor.
pub static COMPRESS_PREPROC_NEWLINES: Counter = Counter::new();
/// Null bytes seen by preprocessor.
pub static COMPRESS_PREPROC_NULLS: Counter = Counter::new();
/// Chunks emitted by preprocessor.
pub static COMPRESS_PREPROC_CHUNKS: Counter = Counter::new();
/// Repeated chunks detected by preprocessor.
pub static COMPRESS_PREPROC_CHUNK_REPEATS: Counter = Counter::new();

/// HTTP body pool block size in bytes.
pub static BODY_POOL_BLOCK_SIZE: AtomicU64 = AtomicU64::new(0);
/// HTTP body pool total capacity in blocks.
pub static BODY_POOL_CAPACITY: AtomicU64 = AtomicU64::new(0);
/// Total allocations from the HTTP body pool.
pub static BODY_POOL_ALLOCS: Counter = Counter::new();

/// Last Reed-Solomon encoding time in nanoseconds.
pub static RS_ENC_TIME_NS: AtomicU64 = AtomicU64::new(0);
/// Last Reed-Solomon decoding time in nanoseconds.
pub static RS_DEC_TIME_NS: AtomicU64 = AtomicU64::new(0);
/// Total RS repair symbols emitted.
pub static RS_REPAIR_EMITTED: AtomicU64 = AtomicU64::new(0);
/// Total RS packets recovered from repair data.
pub static RS_RECOVERED: AtomicU64 = AtomicU64::new(0);
/// RS overhead ratio (n-k)/k in parts-per-million.
pub static RS_OVERHEAD_PPM: AtomicU64 = AtomicU64::new(0);
/// Current RS window data symbol count (k).
pub static RS_WINDOW_K: AtomicU64 = AtomicU64::new(0);
/// Current RS window total symbol count (n = k + repair).
pub static RS_WINDOW_N: AtomicU64 = AtomicU64::new(0);
/// Current Galois field size used by RS codec.
pub static RS_GF_SIZE: AtomicU64 = AtomicU64::new(0);

/// Memory pool allocations served from thread-local slab.
pub static MEM_POOL_HITS_TLS: Counter = Counter::new();
/// Memory pool allocations served from shared queue.
pub static MEM_POOL_HITS_QUEUE: Counter = Counter::new();
/// Memory pool grow events (capacity expansion).
pub static MEM_POOL_ALLOC_GROW: Counter = Counter::new();
/// Memory pool ephemeral (one-shot) allocations.
pub static MEM_POOL_ALLOC_EPHEMERAL: Counter = Counter::new();

mod profile_mask;
pub use profile_mask::{cpu_profile_mask_for_id, publish_cpu_profile_mask_for_id, CpuProfileId};
#[cfg(test)]
pub(crate) use profile_mask::{
    CPU_MASK_AVX10_512, CPU_MASK_AVX2, CPU_MASK_AVX512, CPU_MASK_GFNI, CPU_MASK_NEON, CPU_MASK_RVV,
    CPU_MASK_SCALAR, CPU_MASK_SSE2,
};

/// Total QUIC packets sent.
pub static PACKETS_SENT: Counter = Counter::new();
/// Total QUIC packets received.
pub static PACKETS_RECEIVED: Counter = Counter::new();
/// Total QUIC packets detected as lost.
pub static PACKETS_LOST: Counter = Counter::new();
/// Total QUIC connection path migrations.
pub static PATH_MIGRATIONS: Counter = Counter::new();
/// Total stealth-encoded packets produced.
pub static ENCODED_PACKETS: Counter = Counter::new();
/// Total stealth-decoded packets consumed.
pub static DECODED_PACKETS: Counter = Counter::new();
/// Partially decoded packets (incomplete recovery).
pub static DECODED_PARTIAL_PACKETS: Counter = Counter::new();
/// QPACK header pool fallbacks to heap allocation.
pub static STEALTH_QPACK_POOL_FALLBACKS: Counter = Counter::new();
/// Stealth HTTP headers generated for cover traffic.
pub static STEALTH_HEADERS_GENERATED: Counter = Counter::new();
/// Probing attempts detected by stealth engine.
pub static STEALTH_PROBE_DETECTED: Counter = Counter::new();
/// Stealth mode switches triggered by probe detection.
pub static STEALTH_PROBE_SWITCH: Counter = Counter::new();
/// Fake responses sent to detected probes.
pub static STEALTH_PROBE_FAKE: Counter = Counter::new();
/// Probing connections blocked by stealth engine.
pub static STEALTH_PROBE_BLOCK: Counter = Counter::new();
/// Stealth mode escalations (lower to higher stealth).
pub static STEALTH_MODE_ESCALATED: Counter = Counter::new();
/// Total Intelligent-mode stealth transitions.
pub static STEALTH_INTELLIGENT_TRANSITIONS_TOTAL: Counter = Counter::new();
/// Intelligent escalations triggered by packet loss.
pub static STEALTH_INTELLIGENT_REASON_LOSS: Counter = Counter::new();
/// Intelligent escalations triggered by jitter.
pub static STEALTH_INTELLIGENT_REASON_JITTER: Counter = Counter::new();
/// Intelligent escalations triggered by connection timeout.
pub static STEALTH_INTELLIGENT_REASON_TIMEOUT: Counter = Counter::new();
/// Intelligent escalations triggered by retransmission spike.
pub static STEALTH_INTELLIGENT_REASON_RETRANSMIT: Counter = Counter::new();
/// Intelligent escalations triggered by probe detection.
pub static STEALTH_INTELLIGENT_REASON_PROBE: Counter = Counter::new();
/// Total Intelligent-mode de-escalations (back to lower stealth).
pub static STEALTH_INTELLIGENT_DEESCALATIONS_TOTAL: Counter = Counter::new();
/// ASCII validation bytes processed via AVX2 SIMD.
pub static STEALTH_ASCII_SIMD_AVX2_BYTES: Counter = Counter::new();
/// ASCII validation bytes processed via SSE2 SIMD.
pub static STEALTH_ASCII_SIMD_SSE2_BYTES: Counter = Counter::new();
/// ASCII validation bytes processed via NEON SIMD.
pub static STEALTH_ASCII_SIMD_NEON_BYTES: Counter = Counter::new();
/// ASCII validation bytes processed via scalar fallback.
pub static STEALTH_ASCII_SCALAR_BYTES: Counter = Counter::new();
/// Admin API requests rejected due to CSRF token mismatch.
pub static ADMIN_CSRF_REJECT_TOTAL: Counter = Counter::new();
/// Admin API requests rejected due to origin header mismatch.
pub static ADMIN_ORIGIN_REJECT_TOTAL: Counter = Counter::new();
/// QKey path rebind events (client address change).
pub static QKEY_PATH_REBIND_TOTAL: Counter = Counter::new();
/// Engine handshake timeouts.
pub static ENGINE_HANDSHAKE_TIMEOUT_TOTAL: Counter = Counter::new();
/// Total packets sent via XDP fast path.
pub static XDP_PACKETS_SENT: Counter = Counter::new();
/// Total packets received via XDP fast path.
pub static XDP_PACKETS_RECEIVED: Counter = Counter::new();

const RESOURCE_REFRESH_INTERVAL_MS: u64 = 1_000;
const RESOURCE_REFRESH_UNSET: u64 = u64::MAX;
static RESOURCE_REFRESH_EPOCH: OnceLock<Instant> = OnceLock::new();
static LAST_RESOURCE_REFRESH_MS: AtomicU64 = AtomicU64::new(RESOURCE_REFRESH_UNSET);

fn publish_memory_usage_bytes(memory_bytes: u64) {
    MEMORY_USAGE_BYTES.store(memory_bytes, Ordering::Relaxed);
}

fn claim_resource_refresh(last_refresh_ms: &AtomicU64, now_ms: u64) -> bool {
    let mut observed = last_refresh_ms.load(Ordering::Relaxed);
    loop {
        if observed != RESOURCE_REFRESH_UNSET
            && now_ms.saturating_sub(observed) < RESOURCE_REFRESH_INTERVAL_MS
        {
            return false;
        }
        match last_refresh_ms.compare_exchange_weak(
            observed,
            now_ms,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(actual) => observed = actual,
        }
    }
}

fn resource_refresh_due() -> bool {
    let epoch = RESOURCE_REFRESH_EPOCH.get_or_init(Instant::now);
    let elapsed_ms = epoch.elapsed().as_millis().min(u64::MAX as u128) as u64;
    claim_resource_refresh(&LAST_RESOURCE_REFRESH_MS, elapsed_ms)
}

/// Refresh the `MEMORY_USAGE_BYTES` gauge from the OS process stats.
pub fn update_memory_usage() {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate};

    let Ok(pid) = sysinfo::get_current_pid() else {
        return;
    };
    let mut system = sysinfo::System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_memory().without_tasks(),
    );
    if let Some(process) = system.process(pid) {
        publish_memory_usage_bytes(process.memory());
    }
}

/// Function pointer used by the owner crate to republish subsystem resource gauges.
pub type ResourceMetricsRefreshHook = fn();

static RESOURCE_METRICS_REFRESH_HOOK: OnceLock<ResourceMetricsRefreshHook> = OnceLock::new();

/// Register the owner callback that republishes subsystem resource metrics.
///
/// Telemetry must not depend on the optimizer crate merely to observe its pool. The root adapter
/// installs this hook once during pool initialization; repeated registration is rejected so the
/// process has one authoritative refresh owner.
pub fn register_resource_metrics_refresh_hook(hook: ResourceMetricsRefreshHook) -> bool {
    RESOURCE_METRICS_REFRESH_HOOK.set(hook).is_ok()
}

fn refresh_resource_metrics() {
    update_memory_usage();
    // The owner callback is optional until the optimizer publishes its pool. This preserves the
    // no-side-effect observation contract while keeping the telemetry child independent.
    if let Some(hook) = RESOURCE_METRICS_REFRESH_HOOK.get() {
        hook();
    }
}

/// Refresh process-wide resource metrics at most once per interval.
pub fn refresh_resource_metrics_if_due() {
    if TELEMETRY_ENABLED.load(Ordering::Relaxed) && resource_refresh_due() {
        refresh_resource_metrics();
    }
}

/// Flush telemetry: refresh memory usage and pool metrics if telemetry is enabled.
pub fn flush() {
    if TELEMETRY_ENABLED.load(Ordering::Relaxed) {
        refresh_resource_metrics();
    }
}

/// Global flag controlling whether telemetry collection is active.
pub static TELEMETRY_ENABLED: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
mod tests;
