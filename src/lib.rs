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
// GitHub's x86_64 matrix checks compile coverage for broad architecture helper
// surfaces that are runtime-dispatched and intentionally not always referenced.
#![cfg_attr(target_arch = "x86_64", allow(warnings))]
// Experimental SIMD/unsafe CI lanes check compile coverage across architecture
// helpers; production/default lint strictness stays on for non-x86 local gates.
#![cfg_attr(
    any(feature = "internal_wiedemann", feature = "unsafe_rust", feature = "simd-selfcheck"),
    allow(warnings)
)]

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
    use std::fmt;

    #[derive(Debug, Clone, PartialEq)]
    pub enum ConnectionError {
        CryptoError(String),
        ProtocolViolation,
        InvalidState,
        Timeout,
        InvalidFrame,
        Done,
        TlsError(String),
        TlsAlert(u64),
        BufferTooShort,
        PeerCertificateUnsupported,
        InvalidPacket,
        InvalidStreamState(u64),
        FinalSize,
        InternalError,
        Fec(String),
        Transport(String),
        StreamReset,
        StreamStopped,
        IdLimit,
        FlowControl,
        ApplicationError(u64),
        StreamLimit,
        ApplicationProtoError,
        VersionMismatch,
        FrameEncoding,
        InvalidToken,
        CryptoBufferExceeded,
        KeyUpdateError,
        AeadLimitReached,
        NoViablePath,
        ConnectionRefused,
        InvalidStreamId,
        /// QUIC DATAGRAM send queue is at capacity; the caller should apply
        /// backpressure and retry rather than drop the packet.
        DgramQueueFull,
        /// The local endpoint closed the transport connection.
        LocalConnectionClosed {
            error_code: u64,
            frame_type: u64,
            reason: Vec<u8>,
        },
        /// The local endpoint closed the application connection.
        LocalApplicationClosed {
            error_code: u64,
            reason: Vec<u8>,
        },
        /// The peer closed the transport connection.
        PeerConnectionClosed {
            error_code: u64,
            frame_type: u64,
            reason: Vec<u8>,
        },
        /// The peer closed the application connection.
        PeerApplicationClosed {
            error_code: u64,
            reason: Vec<u8>,
        },
    }

    impl fmt::Display for ConnectionError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ConnectionError::InvalidPacket => write!(f, "Invalid packet"),
                ConnectionError::InvalidFrame => write!(f, "Invalid frame"),
                ConnectionError::InvalidStreamId => write!(f, "Invalid stream ID"),
                ConnectionError::InvalidStreamState(_) => write!(f, "Invalid stream state"),
                ConnectionError::FlowControl => write!(f, "Flow control violation"),
                ConnectionError::StreamLimit => write!(f, "Stream limit exceeded"),
                ConnectionError::FinalSize => write!(f, "Final size error"),
                ConnectionError::FrameEncoding => write!(f, "Frame encoding error"),
                ConnectionError::ProtocolViolation => write!(f, "Protocol violation"),
                ConnectionError::InvalidToken => write!(f, "Invalid token"),
                ConnectionError::ApplicationError(code) => write!(f, "Application error: {}", code),
                ConnectionError::CryptoBufferExceeded => write!(f, "Crypto buffer exceeded"),
                ConnectionError::KeyUpdateError => write!(f, "Key update error"),
                ConnectionError::AeadLimitReached => write!(f, "AEAD limit reached"),
                ConnectionError::NoViablePath => write!(f, "No viable path"),
                ConnectionError::InternalError => write!(f, "Internal error"),
                ConnectionError::ConnectionRefused => write!(f, "Connection refused"),
                ConnectionError::Timeout => write!(f, "Timeout"),
                ConnectionError::Transport(msg) => write!(f, "Transport error: {}", msg),
                ConnectionError::TlsAlert(code) => write!(f, "TLS alert: {}", code),
                ConnectionError::PeerCertificateUnsupported => {
                    write!(f, "Peer certificate unsupported")
                }
                ConnectionError::Done => write!(f, "Connection done"),
                ConnectionError::BufferTooShort => write!(f, "Buffer too short"),
                ConnectionError::InvalidState => write!(f, "Invalid state"),
                ConnectionError::Fec(ref msg) => write!(f, "FEC error: {}", msg),
                ConnectionError::StreamReset => write!(f, "Stream reset"),
                ConnectionError::StreamStopped => write!(f, "Stream stopped"),
                ConnectionError::IdLimit => write!(f, "ID limit exceeded"),
                ConnectionError::LocalConnectionClosed { error_code, frame_type, reason } => {
                    write!(
                        f,
                        "Local connection closed: code={} frame_type={} reason={}",
                        error_code,
                        frame_type,
                        String::from_utf8_lossy(reason)
                    )
                }
                ConnectionError::LocalApplicationClosed { error_code, reason } => write!(
                    f,
                    "Local application closed: code={} reason={}",
                    error_code,
                    String::from_utf8_lossy(reason)
                ),
                ConnectionError::PeerConnectionClosed { error_code, frame_type, reason } => write!(
                    f,
                    "Peer connection closed: code={} frame_type={} reason={}",
                    error_code,
                    frame_type,
                    String::from_utf8_lossy(reason)
                ),
                ConnectionError::PeerApplicationClosed { error_code, reason } => write!(
                    f,
                    "Peer application closed: code={} reason={}",
                    error_code,
                    String::from_utf8_lossy(reason)
                ),
                ConnectionError::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
                ConnectionError::TlsError(msg) => write!(f, "TLS error: {}", msg),
                ConnectionError::ApplicationProtoError => write!(f, "Application protocol error"),
                ConnectionError::VersionMismatch => write!(f, "Version mismatch"),
                ConnectionError::DgramQueueFull => write!(f, "DATAGRAM send queue full"),
            }
        }
    }

    impl std::error::Error for ConnectionError {}

    impl From<String> for ConnectionError {
        fn from(s: String) -> Self {
            ConnectionError::Transport(s)
        }
    }
    impl From<&str> for ConnectionError {
        fn from(s: &str) -> Self {
            ConnectionError::Transport(s.to_string())
        }
    }
    impl From<crate::crypto::aead::KeyMaterialError> for ConnectionError {
        fn from(error: crate::crypto::aead::KeyMaterialError) -> Self {
            ConnectionError::CryptoError(error.to_string())
        }
    }
    impl From<crate::transport::h3::Error> for ConnectionError {
        fn from(e: crate::transport::h3::Error) -> Self {
            match e {
                crate::transport::h3::Error::Done => ConnectionError::Done,
                other => ConnectionError::Transport(format!("H3 error: {:?}", other)),
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
/// Forward Error Correction - adaptive Reed-Solomon with PID controller and Kalman filter.
pub mod fec;
/// Firewall backend abstraction (iptables / nftables) for kill switch and NAT routing.
pub mod firewall;
/// Test harness utilities for integration and property-based testing.
pub mod harness;
/// Tracing and span instrumentation for runtime observability.
pub mod instrumentation;
/// TUN/TAP interface management and platform-specific network device abstraction.
pub mod interface;
/// Production logging: structured JSON, size-rotating file appender, and RFC 5424 syslog.
pub mod logging;
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
pub mod privilege;

/// Security audit logging - hash-chained, SIEM-compatible (TODO-439).
pub mod audit;

/// Production PKI - CA hierarchy, cert generation, chain validation (TODO-434).
pub mod pki;

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
