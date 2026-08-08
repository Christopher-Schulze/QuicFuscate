//! QuicFuscate - Forked stealth transport and VPN runtime.
//!
//! This crate provides the core engine and protocol building blocks for the forked
//! QuicFuscate runtime. It is not a drop-in upstream QUIC implementation.
//!
//! # Features
//! - **Forked Transport/Crypto Stack**: custom transport and AEAD posture for this fork
//! - **CPU-Aware Acceleration**: SIMD and hardware-dispatched fast paths where the runtime uses them
//! - **UDP/io_uring Fastpath**: compatibility-oriented fastpath surface, with XDP kept experimental/test-only
//! - **Adaptive FEC**: runtime-owned adaptive FEC with burst-protection and explicit policy snapshots
//! - **Stealth Features**: canonical stealth runtime plus compatibility-only retained surfaces where documented

// Unstable stdarch/core_intrinsics features removed for stable toolchain compatibility.
// Required for deeply nested macro expansions in crypto/FEC SIMD code
#![recursion_limit = "1024"]

/// CPU feature detection and hardware-accelerated dispatch (SIMD, AES-NI, VAES, NEON).
pub mod accelerate;
/// Core QUIC connection state machine, packet processing, and stream management.
pub mod core;
/// AEAD cipher selection, key derivation, and header protection.
pub mod crypto;
/// Canonical environment variable parsing utilities (flags, typed parse, multi-name lookup).
pub mod env_utils;
/// Unified error types for the QuicFuscate runtime.
pub mod error {
    pub use qf_error::*;

    impl From<crate::crypto::aead::KeyMaterialError> for qf_error::ConnectionError {
        fn from(error: crate::crypto::aead::KeyMaterialError) -> Self {
            Self::CryptoError(error.to_string())
        }
    }

    impl From<crate::transport::h3::Error> for qf_error::ConnectionError {
        fn from(error: crate::transport::h3::Error) -> Self {
            match error {
                crate::transport::h3::Error::Done => Self::Done,
                other => Self::Transport(format!("H3 error: {:?}", other)),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::ConnectionError;

        #[test]
        fn h3_done_maps_to_terminal_connection_done() {
            let error: ConnectionError = crate::transport::h3::Error::Done.into();
            assert_eq!(error, ConnectionError::Done);
        }

        #[test]
        fn h3_nonterminal_error_retains_transport_context() {
            let error: ConnectionError = crate::transport::h3::Error::IdError.into();
            assert!(matches!(
                error,
                ConnectionError::Transport(message) if message == "H3 error: IdError"
            ));
        }
    }
}
/// Adaptive decision engine for runtime parameter tuning (FEC, stealth, transport).
pub mod brain;
/// Packet compression utilities (LZ4/zstd integration for payload reduction).
pub mod compress;
/// Versioned authenticated control-plane payloads for the canonical MASQUE carrier.
pub mod control_plane {
    pub use qf_control_plane::*;
}
/// Forward Error Correction - adaptive Reed-Solomon with PID controller and Kalman filter.
pub mod fec;
/// Firewall backend abstraction (iptables / nftables) for kill switch and NAT routing.
pub mod firewall;
/// Test harness utilities for integration and property-based testing.
pub mod harness;
/// Tracing and span instrumentation for runtime observability.
pub mod instrumentation {
    pub use qf_instrumentation::*;
}
/// TUN/TAP interface management and platform-specific network device abstraction.
pub mod interface;
/// Production logging: structured JSON, size-rotating file appender, and RFC 5424 syslog.
pub mod logging;
/// Shared server startup policy for process and pooled-buffer memory locking.
#[doc(hidden)]
pub mod memory_lock;
/// Runtime metrics collection - counters, gauges, and histograms for all subsystems.
pub mod metrics;
/// Performance optimization subsystem - memory pools, crypto planning, transport tuning.
#[doc(hidden)]
#[cfg(any(test, feature = "rust-tests"))]
/// Browser/OS TLS fingerprint profile definitions (test-only).
pub mod profile;
/// TLS provider system - rustls integration with custom ClientHello and ALPN handling.
pub mod qftls;
/// REALITY fallback reverse proxy for censorship-resistant server fronting.
pub mod reality;
/// Cryptographically secure random number generation with hardware entropy sources.
pub mod rng;
mod secret;
/// Centralized SIMD dispatch - x86 (SSE/AVX/AVX-512) and ARM (NEON) fast paths.
pub mod simd;
/// Stealth and obfuscation engine - traffic shaping, protocol mimicry, fingerprint rotation.
pub mod stealth;
/// Monotonic time source abstraction for consistent timing across platforms.
pub mod time_source;
/// QUIC transport layer - frames, packets, congestion control, recovery, and fast UDP paths.
pub mod transport;

/// Unified engine API - configuration, lifecycle, and high-level connection management.
pub mod engine;

/// Production client and server implementations with platform-specific backends.
pub mod implementations;

/// Performance optimization - CPU detection, SIMD dispatch, memory pools, telemetry counters.
pub mod optimize;

/// Privilege management - post-bind privilege dropping (TODO-441).
pub mod privilege {
    pub use qf_privilege::*;
}

/// Security audit logging - hash-chained, SIEM-compatible (TODO-439).
pub mod audit;

/// Production PKI - CA hierarchy, cert generation, chain validation (TODO-434).
pub mod pki {
    pub use qf_pki::*;
}

/// DNS through tunnel - DoH proxy, DNS forwarding, leak prevention (TODO-435).
pub mod dns;

// TLS Provider System (consolidated)
// Compatibility aliases for existing paths.

pub use crate::stealth::tls_cover;
// Telemetry module - consolidated from previous scattered modules
pub mod telemetry {
    pub use crate::optimize::telemetry::*;
}

// Global functions moved to optimize::telemetry module
pub use crate::optimize::telemetry::{flush, update_memory_usage};

// Re-export main types
pub use core::QuicFuscateConnection;
pub use error::ConnectionError;
// FEC types are re-exported from the fec module
pub use optimize::{OptimizationManager, OptimizeConfig};
pub use stealth::{StealthConfig, StealthManager};

// ConnectionError is already defined in error module, no need to redefine

// Re-export app_config from interface module
pub use crate::interface::app_config;

// Re-export EngineConfig for convenient access
pub use crate::engine::EngineConfig;

// Re-export QuicFuscateEngine for convenient access
pub use crate::engine::QuicFuscateEngine;

#[cfg(all(test, unix))]
pub(crate) mod test_support {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    static UMASK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    pub(crate) struct UmaskGuard {
        previous: libc::mode_t,
        _lock: MutexGuard<'static, ()>,
    }

    pub(crate) fn permissive_umask() -> UmaskGuard {
        let lock = UMASK_LOCK.get_or_init(|| Mutex::new(()));
        let guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = unsafe { libc::umask(0) };
        UmaskGuard { previous, _lock: guard }
    }

    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            unsafe {
                libc::umask(self.previous);
            }
        }
    }
}
