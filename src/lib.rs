// QuicFuscate Core Library
//
// This library contains the core modules for QUIC connection
// management, optimization, cryptography, forward error correction,
// and stealth techniques, consolidated into a single crate.

pub mod core;
pub mod crypto;
pub mod fec;
pub mod optimize;
pub mod app_config {
    use crate::fec::FecConfig;
    use crate::optimize::OptimizeConfig;
    use crate::stealth::StealthConfig;
    use std::path::Path;

    /// Unified configuration structure parsed from a TOML file.
    #[derive(Clone)]
    pub struct AppConfig {
        pub fec: FecConfig,
        pub stealth: StealthConfig,
        pub optimize: OptimizeConfig,
    }

    impl AppConfig {
        /// Load configuration from a TOML string.
        pub fn from_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self {
                fec: FecConfig::from_toml(s).unwrap_or_default(),
                stealth: StealthConfig::from_toml(s).unwrap_or_default(),
                optimize: OptimizeConfig::from_toml(s).unwrap_or_default(),
            })
        }

        /// Load configuration from a file path.
        pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
            let contents = std::fs::read_to_string(path)?;
            Self::from_toml(&contents)
        }

        /// Validate all sub-configurations.
        pub fn validate(&self) -> Result<(), String> {
            self.fec.validate()?;
            self.stealth.validate()?;
            self.optimize.validate()?;
            Ok(())
        }
    }
}
pub mod stealth;
pub use crate::core::xdp_socket;
pub use crate::stealth::fake_tls;
pub use crate::stealth::tls_ffi;
pub mod telemetry {
    //! Telemetry metrics used throughout QuicFuscate.
    //!
    //! Currently exported metrics:
    //! - `encoded_packets_total`: Number of packets encoded by the FEC engine.
    //! - `decoded_packets_total`: Number of packets successfully decoded.
    //! - `loss_rate_percent`: Current estimated loss rate multiplied by 100.
    //! - `fec_mode`: Active FEC mode as numeric value.
    //! - `fec_mode_switch_total`: Number of FEC mode transitions.
    //! - `fec_window_size`: Current FEC window size.
    //! - `decoding_time_ms`: Time spent in the last decode run in milliseconds.
    //! - `fec_overflow_total`: Number of times the FEC memory pool had to allocate
    //!   a new block because the pool was exhausted.
    //! - `dns_errors_total`: Number of DNS resolution errors.
    //! - `bytes_sent_total`: UDP bytes sent via the core.
    //! - `bytes_received_total`: UDP bytes received via the core.
    //! - `xdp_bytes_sent_total`: Total bytes sent over XDP.
    //! - `xdp_bytes_received_total`: Total bytes received over XDP.
    //! - `xdp_fallback_total`: Number of times XDP fell back to UDP.
    //! - `xdp_active`: Gauge whether XDP is currently active.
    //! - `mem_pool_capacity`: Current capacity of the memory pool.
    //! - `mem_pool_in_use`: Number of blocks currently checked out from the pool.
    //! - `cpu_feature_mask`: Bitmask of detected CPU features.
    //! - `path_migrations_total`: Successful connection migrations.

    use lazy_static::lazy_static;
    use log::{error, warn};
    use prometheus::{
        register_int_counter, register_int_gauge, Encoder, IntCounter, IntGauge, TextEncoder,
    };
    use std::sync::atomic::AtomicBool;

    /// Global switch controlling whether telemetry metrics are recorded.
    pub static TELEMETRY_ENABLED: AtomicBool = AtomicBool::new(false);

    /// Executes the given expression only when telemetry is enabled.
    #[macro_export]
    macro_rules! telemetry {
        ($e:expr) => {
            if $crate::telemetry::TELEMETRY_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                $e;
            }
        };
    }

    /// No‑panic wrappers around Prometheus counters/gauges. If registration fails,
    /// they degrade to no‑op metric objects while preserving the same method API.
    #[derive(Clone)]
    pub struct SafeCounter(Option<IntCounter>);

    impl SafeCounter {
        fn new(inner: Option<IntCounter>) -> Self {
            Self(inner)
        }
        pub fn inc(&self) {
            if let Some(c) = self.0.as_ref() { c.inc(); }
        }
        pub fn inc_by(&self, v: u64) {
            if let Some(c) = self.0.as_ref() { c.inc_by(v); }
        }
        pub fn get(&self) -> u64 {
            self.0.as_ref().map(|c| c.get()).unwrap_or(0)
        }
    }

    #[derive(Clone)]
    pub struct SafeGauge(Option<IntGauge>);

    impl SafeGauge {
        fn new(inner: Option<IntGauge>) -> Self {
            Self(inner)
        }
        pub fn set(&self, v: i64) {
            if let Some(g) = self.0.as_ref() { g.set(v); }
        }
        pub fn get(&self) -> i64 {
            self.0.as_ref().map(|g| g.get()).unwrap_or(0)
        }
    }

    lazy_static! {
        pub static ref ENCODED_PACKETS: SafeCounter =
            safe_register_int_counter("encoded_packets_total", "Total encoded packets");
        pub static ref DECODED_PACKETS: SafeCounter =
            safe_register_int_counter("decoded_packets_total", "Total decoded packets");
        pub static ref LOSS_RATE: SafeGauge =
            safe_register_int_gauge("loss_rate_percent", "Current loss rate * 100");
        pub static ref FEC_MODE: SafeGauge =
            safe_register_int_gauge("fec_mode", "Current FEC mode");
        pub static ref FEC_MODE_SWITCHES: SafeCounter =
            safe_register_int_counter("fec_mode_switch_total", "FEC mode transitions");
        pub static ref FEC_WINDOW: SafeGauge =
            safe_register_int_gauge("fec_window_size", "Current FEC window size");
        pub static ref DECODING_TIME_MS: SafeGauge =
            safe_register_int_gauge("decoding_time_ms", "Last decoder runtime in ms");
        pub static ref FEC_OVERFLOWS: SafeCounter =
            safe_register_int_counter("fec_overflow_total", "FEC memory pool overflows");
        pub static ref DNS_ERRORS: SafeCounter =
            safe_register_int_counter("dns_errors_total", "Number of DNS resolution errors");
        pub static ref BYTES_SENT: SafeCounter =
            safe_register_int_counter("bytes_sent_total", "Total UDP bytes sent");
        pub static ref BYTES_RECEIVED: SafeCounter =
            safe_register_int_counter("bytes_received_total", "Total UDP bytes received");
        pub static ref XDP_BYTES_SENT: SafeCounter =
            safe_register_int_counter("xdp_bytes_sent_total", "Total XDP bytes sent");
        pub static ref XDP_BYTES_RECEIVED: SafeCounter =
            safe_register_int_counter("xdp_bytes_received_total", "Total XDP bytes received");
        pub static ref XDP_FALLBACKS: SafeCounter = safe_register_int_counter(
            "xdp_fallback_total",
            "Number of times XDP fell back to UDP",
        );
        pub static ref XDP_ACTIVE: SafeGauge =
            safe_register_int_gauge("xdp_active", "XDP enabled status");
        pub static ref XDP_SEND_LATENCY: SafeCounter = safe_register_int_counter(
            "xdp_send_latency_us_total",
            "Total microseconds spent sending via XDP",
        );
        pub static ref XDP_RECV_LATENCY: SafeCounter = safe_register_int_counter(
            "xdp_recv_latency_us_total",
            "Total microseconds spent receiving via XDP",
        );
        pub static ref XDP_THROUGHPUT: SafeGauge =
            safe_register_int_gauge("xdp_throughput_mbps", "Current XDP throughput in Mbps",);
        pub static ref MEM_POOL_CAPACITY: SafeGauge =
            safe_register_int_gauge("mem_pool_capacity", "Memory pool capacity");
        pub static ref MEM_POOL_BLOCK_SIZE: SafeGauge =
            safe_register_int_gauge("mem_pool_block_size", "Memory pool block size");
        pub static ref MEM_POOL_IN_USE: SafeGauge =
            safe_register_int_gauge("mem_pool_in_use", "Memory pool blocks in use");
        pub static ref MEM_POOL_USAGE_BYTES: SafeGauge =
            safe_register_int_gauge("mem_pool_usage_bytes", "Memory pool bytes in use",);
        pub static ref MEM_POOL_FRAGMENTATION: SafeGauge = safe_register_int_gauge(
            "mem_pool_fragmentation",
            "Memory pool fragmentation in blocks",
        );
        pub static ref MEM_POOL_UTILIZATION: SafeGauge = safe_register_int_gauge(
            "mem_pool_utilization_percent",
            "Memory pool utilization percentage",
        );
        pub static ref CPU_FEATURE_MASK: SafeGauge =
            safe_register_int_gauge("cpu_feature_mask", "Detected CPU features bitmask");
        pub static ref SIMD_ACTIVE: SafeGauge =
            safe_register_int_gauge("simd_active_policy", "Active SIMD policy");
        pub static ref MEMORY_USAGE_BYTES: SafeGauge =
            safe_register_int_gauge("memory_usage_bytes", "Resident memory usage of the process",);
        pub static ref SIMD_USAGE_AVX512: SafeCounter =
            safe_register_int_counter("simd_usage_avx512_total", "SIMD AVX512 dispatches",);
        pub static ref SIMD_USAGE_AVX2: SafeCounter =
            safe_register_int_counter("simd_usage_avx2_total", "SIMD AVX2 dispatches",);
        pub static ref SIMD_USAGE_SSE2: SafeCounter =
            safe_register_int_counter("simd_usage_sse2_total", "SIMD SSE2 dispatches",);
        pub static ref SIMD_USAGE_NEON: SafeCounter =
            safe_register_int_counter("simd_usage_neon_total", "SIMD NEON dispatches",);
        pub static ref SIMD_USAGE_SCALAR: SafeCounter =
            safe_register_int_counter("simd_usage_scalar_total", "Scalar dispatches",);
        pub static ref WIEDEMANN_USAGE: SafeCounter =
            safe_register_int_counter("wiedemann_usage_total", "Wiedemann algorithm invocations",);
        pub static ref STEALTH_BROWSER_PROFILE: SafeGauge =
            safe_register_int_gauge("stealth_browser_profile", "Active browser profile",);
        pub static ref STEALTH_OS_PROFILE: SafeGauge =
            safe_register_int_gauge("stealth_os_profile", "Active OS profile");
        pub static ref PATH_MIGRATIONS: SafeCounter =
            safe_register_int_counter("path_migrations_total", "Successful connection migrations",);
        pub static ref FEC_LAMBDA: SafeGauge =
            safe_register_int_gauge("fec_lambda_scaled", "FEC lambda * 1000");
        pub static ref FEC_BURST_WINDOW: SafeGauge =
            safe_register_int_gauge("fec_burst_window", "FEC burst window");
        pub static ref FEC_HYSTERESIS: SafeGauge =
            safe_register_int_gauge("fec_hysteresis_scaled", "FEC hysteresis * 1000",);
        pub static ref FEC_KALMAN: SafeGauge =
            safe_register_int_gauge("fec_kalman_enabled", "Kalman filter enabled");
        pub static ref STEALTH_DOH: SafeGauge =
            safe_register_int_gauge("stealth_doh", "DNS-over-HTTPS enabled");
        pub static ref STEALTH_FRONTING: SafeGauge =
            safe_register_int_gauge("stealth_fronting", "Domain fronting enabled");
        pub static ref STEALTH_XOR: SafeGauge =
            safe_register_int_gauge("stealth_xor", "XOR obfuscation enabled");
    }

    /// Register an IntCounter safely; returns a no-op wrapper on failure.
    fn safe_register_int_counter(name: &str, help: &str) -> SafeCounter {
        match register_int_counter!(name, help) {
            Ok(c) => SafeCounter::new(Some(c)),
            Err(e) => {
                warn!("Failed to register counter {}: {}", name, e);
                match IntCounter::new(name, help) {
                    Ok(c2) => SafeCounter::new(Some(c2)),
                    Err(e2) => {
                        warn!(
                            "Failed to create counter {} (name invalid?): {} — using no-op",
                            name, e2
                        );
                        SafeCounter::new(None)
                    }
                }
            }
        }
    }

    /// Register an IntGauge safely; returns a no-op wrapper on failure.
    fn safe_register_int_gauge(name: &str, help: &str) -> SafeGauge {
        match register_int_gauge!(name, help) {
            Ok(g) => SafeGauge::new(Some(g)),
            Err(e) => {
                warn!("Failed to register gauge {}: {}", name, e);
                match IntGauge::new(name, help) {
                    Ok(g2) => SafeGauge::new(Some(g2)),
                    Err(e2) => {
                        warn!(
                            "Failed to create gauge {} (name invalid?): {} — using no-op",
                            name, e2
                        );
                        SafeGauge::new(None)
                    }
                }
            }
        }
    }

    pub fn update_memory_usage() {
        use sysinfo::ProcessesToUpdate;
        let mut sys = sysinfo::System::new_all();
        if let Ok(pid) = sysinfo::get_current_pid() {
            sys.refresh_processes(ProcessesToUpdate::All, true);
            if let Some(proc_) = sys.process(pid) {
                let mem = proc_.memory();
                telemetry!(MEMORY_USAGE_BYTES.set(mem as i64 * 1024));
            }
        }
    }

    pub fn serve(addr: &str) {
        use std::io::Write;
        use std::net::TcpListener;
        let listener = match TcpListener::bind(addr) {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind telemetry endpoint at {}: {}", addr, e);
                return;
            }
        };
        std::thread::spawn(move || {
            let encoder = TextEncoder::new();
            for mut s in listener.incoming().flatten() {
                let metrics = prometheus::gather();
                let mut buf = Vec::new();
                if let Err(e) = encoder.encode(&metrics, &mut buf) {
                    warn!("Failed to encode Prometheus metrics: {}", e);
                    continue;
                }
                if let Err(e) = s.write_all(&buf) {
                    warn!("Failed to write metrics to client: {}", e);
                }
            }
        });
    }

    pub fn flush() {
        let encoder = TextEncoder::new();
        let metrics = prometheus::gather();
        let mut buf = Vec::new();
        if encoder.encode(&metrics, &mut buf).is_ok() {
            log::info!("\n{}", String::from_utf8_lossy(&buf));
        }
    }
}
pub mod error {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum ConnectionError {
        #[error("quiche error: {0}")]
        Quiche(#[from] quiche::Error),
        #[error("http3 error: {0}")]
        H3(#[from] quiche::h3::Error),
        #[error("fec error: {0}")]
        Fec(String),
    }

    impl From<&'static str> for ConnectionError {
        fn from(s: &'static str) -> Self {
            ConnectionError::Fec(s.to_string())
        }
    }

    impl From<String> for ConnectionError {
        fn from(s: String) -> Self {
            ConnectionError::Fec(s)
        }
    }
}
#[cfg(feature = "pq")]
pub use crate::core::pq;

pub use optimize::{CpuFeature, FeatureDetector};

/// Provides global access to detected CPU features.
pub fn cpu_features() -> &'static FeatureDetector {
    FeatureDetector::instance()
}
