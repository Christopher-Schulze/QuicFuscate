//! Telemetry metrics used throughout QuicFuscate.
//!
//! Currently exported metrics:
//! - `encoded_packets_total`: Number of packets encoded by the FEC engine.
//! - `decoded_packets_total`: Number of packets successfully decoded.
//! - `loss_rate_percent`: Current estimated loss rate multiplied by 100.
//! - `fec_mode`: Active FEC mode as numeric value.
//! - `fec_mode_switch_total`: Number of FEC mode transitions.
//! - `fec_overflow_total`: Number of times the FEC memory pool had to allocate
//!   a new block because the pool was exhausted.
//! - `dns_errors_total`: Number of DNS resolution errors.
//! - `bytes_sent_total`: UDP bytes sent via the core.
//! - `bytes_received_total`: UDP bytes received via the core.
//! - `mem_pool_capacity`: Current capacity of the memory pool.
//! - `mem_pool_in_use`: Number of blocks currently checked out from the pool.
//! - `cpu_feature_mask`: Bitmask of detected CPU features.
//! - `path_migrations_total`: Successful connection migrations.

use prometheus::{
    register_int_counter, register_int_gauge, Encoder, IntCounter, IntGauge, TextEncoder,
};
use sysinfo::{PidExt, SystemExt};

lazy_static! {
    pub static ref ENCODED_PACKETS: IntCounter =
        register_int_counter!("encoded_packets_total", "Total encoded packets").unwrap();
    pub static ref DECODED_PACKETS: IntCounter =
        register_int_counter!("decoded_packets_total", "Total decoded packets").unwrap();
    pub static ref LOSS_RATE: IntGauge =
        register_int_gauge!("loss_rate_percent", "Current loss rate * 100").unwrap();
    pub static ref FEC_MODE: IntGauge =
        register_int_gauge!("fec_mode", "Current FEC mode").unwrap();
    pub static ref FEC_MODE_SWITCHES: IntCounter =
        register_int_counter!("fec_mode_switch_total", "FEC mode transitions").unwrap();
    pub static ref FEC_OVERFLOWS: IntCounter =
        register_int_counter!("fec_overflow_total", "FEC memory pool overflows").unwrap();
    pub static ref DNS_ERRORS: IntCounter =
        register_int_counter!("dns_errors_total", "Number of DNS resolution errors").unwrap();
    pub static ref BYTES_SENT: IntCounter =
        register_int_counter!("bytes_sent_total", "Total UDP bytes sent").unwrap();
    pub static ref BYTES_RECEIVED: IntCounter =
        register_int_counter!("bytes_received_total", "Total UDP bytes received").unwrap();
    pub static ref XDP_BYTES_SENT: IntCounter =
        register_int_counter!("xdp_bytes_sent_total", "Total XDP bytes sent").unwrap();
    pub static ref XDP_BYTES_RECEIVED: IntCounter =
        register_int_counter!("xdp_bytes_received_total", "Total XDP bytes received").unwrap();
    pub static ref XDP_FALLBACKS: IntCounter =
        register_int_counter!("xdp_fallback_total", "Number of times XDP fell back to UDP")
            .unwrap();
    pub static ref XDP_ACTIVE: IntGauge =
        register_int_gauge!("xdp_active", "XDP enabled status").unwrap();
    pub static ref MEM_POOL_CAPACITY: IntGauge =
        register_int_gauge!("mem_pool_capacity", "Memory pool capacity").unwrap();
    pub static ref MEM_POOL_IN_USE: IntGauge =
        register_int_gauge!("mem_pool_in_use", "Memory pool blocks in use").unwrap();
    pub static ref MEM_POOL_USAGE_BYTES: IntGauge =
        register_int_gauge!("mem_pool_usage_bytes", "Memory pool bytes in use").unwrap();
    pub static ref MEM_POOL_FRAGMENTATION: IntGauge = register_int_gauge!(
        "mem_pool_fragmentation",
        "Memory pool fragmentation in blocks"
    )
    .unwrap();
    pub static ref MEM_POOL_UTILIZATION: IntGauge = register_int_gauge!(
        "mem_pool_utilization_percent",
        "Memory pool utilization percentage"
    )
    .unwrap();
    pub static ref CPU_FEATURE_MASK: IntGauge =
        register_int_gauge!("cpu_feature_mask", "Detected CPU features bitmask").unwrap();
    pub static ref SIMD_ACTIVE: IntGauge =
        register_int_gauge!("simd_active_policy", "Active SIMD policy").unwrap();
    pub static ref MEMORY_USAGE_BYTES: IntGauge =
        register_int_gauge!("memory_usage_bytes", "Resident memory usage of the process").unwrap();
    pub static ref SIMD_USAGE_AVX512: IntCounter =
        register_int_counter!("simd_usage_avx512_total", "SIMD AVX512 dispatches").unwrap();
    pub static ref SIMD_USAGE_AVX2: IntCounter =
        register_int_counter!("simd_usage_avx2_total", "SIMD AVX2 dispatches").unwrap();
    pub static ref SIMD_USAGE_SSE2: IntCounter =
        register_int_counter!("simd_usage_sse2_total", "SIMD SSE2 dispatches").unwrap();
    pub static ref SIMD_USAGE_NEON: IntCounter =
        register_int_counter!("simd_usage_neon_total", "SIMD NEON dispatches").unwrap();
    pub static ref SIMD_USAGE_SCALAR: IntCounter =
        register_int_counter!("simd_usage_scalar_total", "Scalar dispatches").unwrap();
    pub static ref PATH_MIGRATIONS: IntCounter =
        register_int_counter!("path_migrations_total", "Successful connection migrations").unwrap();
}

pub fn update_memory_usage() {
    let mut sys = sysinfo::System::new();
    sys.refresh_process(sysinfo::get_current_pid().unwrap());
    if let Some(proc) = sys.process(sysinfo::get_current_pid().unwrap()) {
        MEMORY_USAGE_BYTES.set(proc.memory() as i64 * 1024);
    }
}

pub fn serve(addr: &str) {
    use std::io::Write;
    use std::net::TcpListener;
    let listener = TcpListener::bind(addr).expect("bind metrics");
    std::thread::spawn(move || {
        let encoder = TextEncoder::new();
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                let metrics = prometheus::gather();
                let mut buf = Vec::new();
                encoder.encode(&metrics, &mut buf).unwrap();
                let _ = s.write_all(&buf);
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
