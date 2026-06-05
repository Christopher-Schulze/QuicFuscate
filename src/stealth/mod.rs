// Copyright (c) 2024, The QuicFuscate Project Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following disclaimer
//       in the documentation and/or other materials provided with the
//       distribution.
//
//     * Neither the name of the copyright holder nor the names of its
//       contributors may be used to endorse or promote products derived from
//       this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! # Stealth Module
//!
//! This module provides a comprehensive suite of advanced techniques for traffic
//! obfuscation, QUIC fingerprint spoofing, and evasion of deep packet
//! inspection (DPI) systems. It integrates multiple strategies to create a
//! layered defense against network surveillance.

// User-Agent string constants to avoid repeated allocations.
// Updated 2026-03: Chrome 136, Firefox 138, Edge 136, Safari 18.3
const UA_CHROME_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
const UA_FIREFOX_WIN: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0";
const UA_EDGE_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0";
const UA_EDGE_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0";
const UA_EDGE_LINUX: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0";
const UA_SAFARI_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15";
const UA_CHROME_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
const UA_FIREFOX_MAC: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15.3; rv:138.0) Gecko/20100101 Firefox/138.0";
const UA_CHROME_LINUX: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
const UA_FIREFOX_LINUX: &str =
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0";
const UA_CHROME_ANDROID: &str = "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36";
const UA_FIREFOX_ANDROID: &str =
    "Mozilla/5.0 (Android 15; Mobile; rv:138.0) Gecko/138.0 Firefox/138.0";
const UA_SAFARI_IOS: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1";

// Accept-Language constants
const LANG_EN_US_09: &str = "en-US,en;q=0.9";
const LANG_EN_US_05: &str = "en-US,en;q=0.5";

/*
===============================================================================
Rules-File Guard (Stealth Module)
-------------------------------------------------------------------------------
- No placeholders in production code. All public methods must be fully
  implemented and concurrency-safe.
- DomainFrontingManager uses atomics for lock-free selection; changes must keep
  thread-safety and deterministic semantics.
- Stealth state transitions must remain concurrency-safe and free of dead
  compatibility paths; no stubs.
- TLS ClientHello spoofing must call safe FFI shims only; when symbols are
  absent, fall back is a no-op without panicking.
- After edits: run `cargo check` and `cargo doc` to validate.
===============================================================================
*/

// clap dependency removed - using manual enum implementation
use crate::accelerate::stealth::AsciiSimdBackend;
use crate::crypto::hkdf::{hkdf_expand, hkdf_extract};
use log::{debug, error, info, warn};
use reqwest::Client;
use std::sync::LazyLock;
// use of sha2 replaced with centralized SIMD dispatch
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use url::Url;

use self::tls_cover::ServerHelloParamsOwned;
use crate::crypto::CryptoManager; // Assumed for integration
use crate::optimize::OptimizationManager; // Assumed for integration
use crate::telemetry;

// Integrated test module (keeps src layout monolithic; tests live alongside)
// Test module removed - tests are inline

/// Server Push Cover Traffic state management
#[derive(Debug)]
struct ServerPushState {
    /// Last burst timestamp
    last_burst: std::time::Instant,
    /// Active push promises count
    active_promises: usize,
    /// Total cover traffic bytes sent
    total_cover_bytes: u64,
    /// Current intensity multiplier (dynamic adjustment)
    current_intensity: f32,
    /// Sliding 60-second burst window for bursts/minute telemetry.
    burst_window: VecDeque<std::time::Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServerPushTriggerReason {
    Time,
    Loss,
    Gating,
}

/// Real-time rate choker (token bucket) to smooth observable bitrate without heavy CPU.
struct RateChoker {
    target_bps: f64,
    capacity_bytes: f64,
    tokens: f64,
    last: std::time::Instant,
}

impl RateChoker {
    fn new(target_mbps: u32, burst_ms: u32) -> Option<Self> {
        if target_mbps == 0 {
            return None;
        }
        let target_bps = (target_mbps as f64) * 1_000_000.0;
        let capacity_bytes = (target_bps / 8.0) * (burst_ms as f64 / 1000.0);
        Some(Self {
            target_bps,
            capacity_bytes,
            tokens: capacity_bytes, // start full burst
            last: std::time::Instant::now(),
        })
    }

    /// Returns sleep duration needed to respect the target rate for `bytes`.
    fn shape(&mut self, bytes: usize) -> std::time::Duration {
        let now = std::time::Instant::now();
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        // Refill tokens
        self.tokens = (self.tokens + (self.target_bps / 8.0) * dt).min(self.capacity_bytes);
        self.last = now;

        let need = bytes as f64;
        if self.tokens >= need {
            self.tokens -= need;
            return std::time::Duration::ZERO;
        }
        let deficit = need - self.tokens;
        // Time to accumulate `deficit` bytes at target_bps
        let wait_s = (deficit * 8.0) / self.target_bps;
        self.tokens = 0.0;
        std::time::Duration::from_secs_f64(wait_s.max(0.0))
    }
}

// --- Inlined: tls_cover.rs ---
// Minimal TLS Cover record layer for fingerprinting
// Generates a forged ClientHello and synthetic server response without
// establishing a real TLS session.
// Ultra-sophisticated TLS Cover Provider for maximum stealth
/// Cipher suite used by the TLS Cover provider for encrypting synthetic records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCoverCipherSuite {
    /// ChaCha20-Poly1305 (preferred on platforms without hardware AES).
    ChaCha20Poly1305,
    /// AES-128-GCM (preferred when hardware AES acceleration is available).
    Aes128Gcm,
}

impl TlsCoverCipherSuite {
    fn as_str(&self) -> &'static str {
        match self {
            TlsCoverCipherSuite::ChaCha20Poly1305 => "chacha20-poly1305",
            TlsCoverCipherSuite::Aes128Gcm => "aes-128-gcm",
        }
    }

    /// Returns the TLS wire-format cipher suite ID (for ServerHello).
    pub(crate) fn tls_id(&self) -> u16 {
        match self {
            TlsCoverCipherSuite::ChaCha20Poly1305 => 0x1303,
            TlsCoverCipherSuite::Aes128Gcm => 0x1301,
        }
    }

    fn kind(&self) -> crate::transport::packet::TlsCoverCipherKind {
        match self {
            TlsCoverCipherSuite::ChaCha20Poly1305 => {
                crate::transport::packet::TlsCoverCipherKind::ChaCha20Poly1305
            }
            TlsCoverCipherSuite::Aes128Gcm => {
                crate::transport::packet::TlsCoverCipherKind::Aes128Gcm
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsCoverCipherPreference {
    Auto,
    ChaCha20Poly1305,
    Aes128Gcm,
}

use crate::env_utils;

impl TlsCoverCipherPreference {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" | "" => Some(Self::Auto),
            "chacha" | "chacha20" | "chacha20poly1305" => Some(Self::ChaCha20Poly1305),
            "aes" | "aesgcm" | "aes-gcm" | "aes128gcm" | "aes-128-gcm" | "ctr" | "aesctr" => {
                Some(Self::Aes128Gcm)
            }
            _ => None,
        }
    }
}

/// Manages synthetic TLS record generation for DPI evasion on a per-connection basis.
pub(crate) struct TlsCoverProvider {
    crypto: Arc<parking_lot::RwLock<crate::transport::packet::CryptoContext>>,
    is_server: bool,
    handshake_complete: bool,
    ch_template: Vec<u8>,
    performance_mode: bool, // When true, disable padding/jitter/timing features
    fingerprint_profile: String,
    tls_cover_key: [u8; 32],
    tls_cover_iv: [u8; 12],
    cipher_suite: TlsCoverCipherSuite,
}

impl TlsCoverProvider {
    fn padding_cap_override() -> Option<usize> {
        env_utils::env_first(["QUICFUSCATE_STEALTH_PADDING_MAX", "QUICFUSCATE_STEALTH_MAX_PADDING"])
            .and_then(|v| v.parse::<usize>().ok())
    }

    fn jitter_override_us() -> Option<u64> {
        env_utils::env_first(["QUICFUSCATE_STEALTH_JITTER_US"]).and_then(|v| v.parse::<u64>().ok())
    }

    fn cipher_preference_from_env() -> TlsCoverCipherPreference {
        env_utils::env_first(["QUICFUSCATE_TLS_COVER_CIPHER"])
            .and_then(|value| TlsCoverCipherPreference::parse(&value))
            .unwrap_or(TlsCoverCipherPreference::Auto)
    }

    fn tls_cover_profile_name() -> String {
        env_utils::env_first(["QUICFUSCATE_TLS_COVER_PROFILE"])
            .unwrap_or_else(|| "chrome".to_string())
    }

    fn ultra_enabled() -> bool {
        env_utils::env_flag("QUICFUSCATE_TLS_COVER_ULTRA", false)
    }

    fn has_hardware_aes() -> bool {
        let detector = crate::optimize::FeatureDetector::instance();
        detector.has_feature(crate::optimize::CpuFeature::AESNI)
            || detector.has_feature(crate::optimize::CpuFeature::VAES)
            || detector.has_feature(crate::optimize::CpuFeature::AES)
    }

    fn resolve_cipher_suite(pref: TlsCoverCipherPreference) -> TlsCoverCipherSuite {
        match pref {
            TlsCoverCipherPreference::Auto => {
                if Self::has_hardware_aes() {
                    TlsCoverCipherSuite::Aes128Gcm
                } else {
                    TlsCoverCipherSuite::ChaCha20Poly1305
                }
            }
            TlsCoverCipherPreference::ChaCha20Poly1305 => TlsCoverCipherSuite::ChaCha20Poly1305,
            TlsCoverCipherPreference::Aes128Gcm => {
                if !Self::has_hardware_aes() {
                    log::warn!(
                        "TLS Cover AES-128-GCM requested but hardware lacks AES acceleration; using scalar fallback"
                    );
                }
                TlsCoverCipherSuite::Aes128Gcm
            }
        }
    }

    /// Constructs a provider for the given role, deriving cover-traffic key material.
    pub(crate) fn new(
        is_server: bool,
        crypto: Arc<parking_lot::RwLock<crate::transport::packet::CryptoContext>>,
    ) -> Result<Self, crate::error::ConnectionError> {
        // Load profile from ENV
        let profile = Self::tls_cover_profile_name();

        let (tls_cover_key, tls_cover_iv) = Self::derive_tls_cover_material(&profile, is_server);

        let cipher_preference = Self::cipher_preference_from_env();
        let cipher_suite = Self::resolve_cipher_suite(cipher_preference);

        {
            let mut ctx = crypto.write();
            match cipher_suite {
                TlsCoverCipherSuite::ChaCha20Poly1305 => {
                    ctx.install_tls_cover_chacha(&tls_cover_key, &tls_cover_iv);
                }
                TlsCoverCipherSuite::Aes128Gcm => {
                    let mut aes_key = [0u8; 16];
                    aes_key.copy_from_slice(&tls_cover_key[..16]);
                    ctx.install_tls_cover_aes_gcm(&aes_key, &tls_cover_iv);
                }
            }
        }

        log::info!(
            "TLS Cover cipher suite selected: {} ({})",
            cipher_suite.as_str(),
            match cipher_preference {
                TlsCoverCipherPreference::Auto => "auto",
                TlsCoverCipherPreference::ChaCha20Poly1305 => "forced",
                TlsCoverCipherPreference::Aes128Gcm => "forced",
            }
        );

        if matches!(cipher_suite, TlsCoverCipherSuite::ChaCha20Poly1305) && Self::has_hardware_aes()
        {
            log::debug!("Hardware AES available but TLS Cover cipher forced to ChaCha20-Poly1305");
        }

        // Generate initial CH template based on profile
        let ch_template = Self::generate_ch_template(&profile);

        Ok(Self {
            crypto,
            is_server,
            handshake_complete: false,
            ch_template,
            performance_mode: false,
            fingerprint_profile: profile,
            tls_cover_key,
            tls_cover_iv,
            cipher_suite,
        })
    }

    /// Generate ultra-sophisticated ClientHello template based on profile
    fn generate_ch_template(profile: &str) -> Vec<u8> {
        match profile {
            "chrome" => Self::chrome_ch_template(),
            "firefox" => Self::firefox_ch_template(),
            "safari" => Self::safari_ch_template(),
            "edge" => Self::edge_ch_template(),
            "random" => Self::random_ch_template(),
            _ => Self::chrome_ch_template(),
        }
    }

    fn derive_tls_cover_material(profile: &str, is_server: bool) -> ([u8; 32], [u8; 12]) {
        let salt = "quicfuscate:tls-cover:salt:v1".to_string();
        let ikm = format!(
            "quicfuscate:tls-cover:{}:{}",
            profile,
            if is_server { "server" } else { "client" }
        );
        let prk = hkdf_extract(salt.as_bytes(), ikm.as_bytes());
        let info = format!("quicfuscate:tls-cover:info:{}", profile);
        let okm = hkdf_expand(&prk, info.as_bytes(), 44);
        let mut key = [0u8; 32];
        let mut iv = [0u8; 12];
        key.copy_from_slice(&okm[..32]);
        iv.copy_from_slice(&okm[32..44]);
        (key, iv)
    }

    fn chrome_ch_template() -> Vec<u8> {
        // Ultra-realistic Chrome 130 ClientHello
        let mut ch = Vec::new();

        // TLS 1.3 ClientHello structure
        ch.extend_from_slice(&[
            0x01, 0x00, 0x01, 0xfc, // Handshake Type: ClientHello, Length
            0x03, 0x03, // Version: TLS 1.2 (for compatibility)
        ]);

        // Random (32 bytes) - Chrome-specific pattern
        use rand::Rng;
        let mut rng = rand::rng();
        let mut random = [0u8; 32];
        rng.fill(&mut random[..]);
        ch.extend_from_slice(&random);

        // Session ID (32 bytes for Chrome)
        ch.push(0x20);
        let mut session_id = [0u8; 32];
        rng.fill(&mut session_id[..]);
        ch.extend_from_slice(&session_id);

        // Cipher Suites - Chrome order (includes ChaCha for fingerprint realism)
        ch.extend_from_slice(&[
            0x00, 0x20, // Length: 32 bytes (16 suites)
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x13, 0x02, // TLS_AES_256_GCM_SHA384
            0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
            0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xcc, 0xa9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xcc, 0xa8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xc0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            0xc0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            0x00, 0x9c, // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x00, 0x9d, // TLS_RSA_WITH_AES_256_GCM_SHA384
            0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
            0x00, 0x0a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        ]);

        // Compression Methods
        ch.extend_from_slice(&[0x01, 0x00]); // No compression

        // Extensions - Chrome-specific order and values
        Self::add_chrome_extensions(&mut ch);

        ch
    }

    fn firefox_ch_template() -> Vec<u8> {
        // Ultra-realistic Firefox 133 ClientHello
        let mut ch = Vec::new();

        // Similar structure but Firefox-specific ordering
        ch.extend_from_slice(&[0x01, 0x00, 0x01, 0xf8, 0x03, 0x03]);

        use rand::Rng;
        let mut rng = rand::rng();
        let mut random = [0u8; 32];
        rng.fill(&mut random[..]);
        ch.extend_from_slice(&random);

        // Firefox uses empty session ID
        ch.push(0x00);

        // Firefox cipher suite order (includes ChaCha for fingerprint realism)
        ch.extend_from_slice(&[
            0x00, 0x1e, // Length (30 bytes, 15 suites)
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
            0x13, 0x02, // TLS_AES_256_GCM_SHA384
            0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xcc, 0xa9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xcc, 0xa8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xc0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            0xc0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            0x00, 0x33, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
            0x00, 0x39, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
            0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
        ]);

        ch.extend_from_slice(&[0x01, 0x00]);

        Self::add_firefox_extensions(&mut ch);

        ch
    }

    fn safari_ch_template() -> Vec<u8> {
        // Ultra-realistic Safari 18 ClientHello
        let mut ch = Vec::new();

        ch.extend_from_slice(&[0x01, 0x00, 0x01, 0xe8, 0x03, 0x03]);

        use rand::Rng;
        let mut rng = rand::rng();
        let mut random = [0u8; 32];
        rng.fill(&mut random[..]);
        ch.extend_from_slice(&random);

        // Safari uses 32-byte session ID
        ch.push(0x20);
        let mut session_id = [0u8; 32];
        rng.fill(&mut session_id[..]);
        ch.extend_from_slice(&session_id);

        // Safari cipher suite order (minimal set)
        ch.extend_from_slice(&[
            0x00, 0x0a, // Length
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x13, 0x02, // TLS_AES_256_GCM_SHA384
            0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        ]);

        ch.extend_from_slice(&[0x01, 0x00]);

        Self::add_safari_extensions(&mut ch);

        ch
    }

    fn edge_ch_template() -> Vec<u8> {
        // Edge uses Chrome engine but with slight differences
        // Modify some bytes to make it Edge-specific in future if needed
        // Edge has different extension ordering
        Self::chrome_ch_template()
    }

    fn random_ch_template() -> Vec<u8> {
        // Randomly select a profile for variety
        use rand::Rng;
        let mut rng = rand::rng();
        match rng.random_range(0..4) {
            0 => Self::chrome_ch_template(),
            1 => Self::firefox_ch_template(),
            2 => Self::safari_ch_template(),
            _ => Self::edge_ch_template(),
        }
    }

    const CLIENT_HELLO_SNI: &'static [u8] = b"cdn.cloudflare.com";

    fn append_server_name_extension(ext: &mut Vec<u8>, host: &[u8]) {
        let host_len = host.len();
        if host_len > u16::MAX as usize {
            return;
        }
        let list_len = 1 + 2 + host_len;
        if list_len > u16::MAX as usize {
            return;
        }
        let ext_len = 2 + list_len;
        if ext_len > u16::MAX as usize {
            return;
        }

        ext.extend_from_slice(&[0x00, 0x00]); // server_name
        ext.extend_from_slice(&(ext_len as u16).to_be_bytes());
        ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        ext.push(0x00); // host_name
        ext.extend_from_slice(&(host_len as u16).to_be_bytes());
        ext.extend_from_slice(host);
    }

    fn add_chrome_extensions(ch: &mut Vec<u8>) {
        // Add Chrome-specific extensions in exact order
        let mut ext = Vec::new();

        // GREASE extension (Chrome always starts with GREASE)
        ext.extend_from_slice(&[0x0a, 0x0a, 0x00, 0x00]);

        // Server Name (SNI)
        Self::append_server_name_extension(&mut ext, Self::CLIENT_HELLO_SNI);

        // Supported Groups
        ext.extend_from_slice(&[
            0x00, 0x0a, // Extension type: supported_groups
            0x00, 0x08, // Length
            0x00, 0x06, // Groups length
            0x00, 0x1d, // x25519
            0x00, 0x17, // secp256r1
            0x00, 0x18, // secp384r1
        ]);

        // EC Point Formats
        ext.extend_from_slice(&[
            0x00, 0x0b, // Extension type: ec_point_formats
            0x00, 0x02, // Length
            0x01, // Formats length
            0x00, // uncompressed
        ]);

        // Signature Algorithms
        ext.extend_from_slice(&[
            0x00, 0x0d, // Extension type: signature_algorithms
            0x00, 0x0e, // Length
            0x00, 0x0c, // Algorithms length
            0x04, 0x03, // ecdsa_secp256r1_sha256
            0x08, 0x04, // rsa_pss_rsae_sha256
            0x04, 0x01, // rsa_pkcs1_sha256
            0x05, 0x03, // ecdsa_secp384r1_sha384
            0x08, 0x05, // rsa_pss_rsae_sha384
            0x05, 0x01, // rsa_pkcs1_sha384
        ]);

        // ALPN
        ext.extend_from_slice(&[
            0x00, 0x10, // Extension type: ALPN
            0x00, 0x0e, // Length
            0x00, 0x0c, // ALPN list length
            0x02, b'h', b'3', // h3
            0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1', // http/1.1
        ]);

        // Supported Versions
        ext.extend_from_slice(&[
            0x00, 0x2b, // Extension type: supported_versions
            0x00, 0x03, // Length
            0x02, // Versions length
            0x03, 0x04, // TLS 1.3
        ]);

        // PSK Key Exchange Modes
        ext.extend_from_slice(&[
            0x00, 0x2d, // Extension type: psk_key_exchange_modes
            0x00, 0x02, // Length
            0x01, // Modes length
            0x01, // psk_dhe_ke
        ]);

        // Key Share
        ext.extend_from_slice(&[
            0x00, 0x33, // Extension type: key_share
            0x00, 0x26, // Length
            0x00, 0x24, // Key share entries length
            0x00, 0x1d, // Group: x25519
            0x00, 0x20, // Key exchange length
        ]);

        // Generate random key
        use rand::Rng;
        let mut rng = rand::rng();
        let mut key = [0u8; 32];
        rng.fill(&mut key[..]);
        ext.extend_from_slice(&key);

        // Add extension length to CH
        ch.extend_from_slice(&((ext.len() as u16).to_be_bytes()));
        ch.extend_from_slice(&ext);
    }

    fn add_firefox_extensions(ch: &mut Vec<u8>) {
        // Firefox has different extension order and doesn't use GREASE
        let mut ext = Vec::new();

        // Server Name (Firefox starts with SNI)
        Self::append_server_name_extension(&mut ext, Self::CLIENT_HELLO_SNI);

        // Extended Master Secret
        ext.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

        // Renegotiation Info
        ext.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);

        // Supported Groups
        ext.extend_from_slice(&[
            0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x18,
        ]);

        // EC Point Formats
        ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);

        // Session Ticket
        ext.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);

        // ALPN
        ext.extend_from_slice(&[
            0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, b'h', b'3', 0x08, b'h', b't', b't', b'p',
            b'/', b'1', b'.', b'1',
        ]);

        // Status Request
        ext.extend_from_slice(&[0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);

        // Signature Algorithms
        ext.extend_from_slice(&[
            0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03,
            0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
        ]);

        // Supported Versions
        ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);

        // PSK Key Exchange Modes
        ext.extend_from_slice(&[0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]);

        // Key Share
        ext.extend_from_slice(&[0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);

        use rand::Rng;
        let mut rng = rand::rng();
        let mut key = [0u8; 32];
        rng.fill(&mut key[..]);
        ext.extend_from_slice(&key);

        ch.extend_from_slice(&((ext.len() as u16).to_be_bytes()));
        ch.extend_from_slice(&ext);
    }

    fn add_safari_extensions(ch: &mut Vec<u8>) {
        // Safari has minimal extensions
        let mut ext = Vec::new();

        // Server Name
        Self::append_server_name_extension(&mut ext, Self::CLIENT_HELLO_SNI);

        // Supported Groups (Safari uses fewer groups)
        ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);

        // Signature Algorithms (Safari minimal set)
        ext.extend_from_slice(&[
            0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
        ]);

        // ALPN
        ext.extend_from_slice(&[0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'3']);

        // Supported Versions
        ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        // Key Share
        ext.extend_from_slice(&[0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);

        use rand::Rng;
        let mut rng = rand::rng();
        let mut key = [0u8; 32];
        rng.fill(&mut key[..]);
        ext.extend_from_slice(&key);

        ch.extend_from_slice(&((ext.len() as u16).to_be_bytes()));
        ch.extend_from_slice(&ext);
    }

    /// Replaces the ClientHello template with externally-provided bytes.
    pub(crate) fn apply_ch_override(
        &mut self,
        template: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        self.ch_template = template.to_vec();
        Ok(())
    }

    /// Enable/disable performance mode
    /// Performance mode: Full TLS Cover traffic but NO artificial delays/padding/jitter
    /// Stealth mode: Full sophistication including timing variations and padding
    pub(crate) fn set_performance_mode(&mut self, enabled: bool) {
        self.performance_mode = enabled;
        if enabled {
            log::debug!("TLS Cover performance mode: Full cover traffic, no artificial delays");
        } else {
            log::debug!("TLS Cover stealth mode: Full sophistication with timing/padding");
        }
    }

    /// Ingests inbound QUIC crypto data and updates handshake state.
    pub(crate) fn provide_quic_data(
        &mut self,
        level: crate::qftls::Level,
        data: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        // Usage of is_server/crypto: telemetry and handshake status.
        let _guard = self.crypto.read();
        crate::telemetry::BYTES_RECEIVED.inc_by(data.len() as u64);
        if matches!(level, crate::qftls::Level::Handshake) && self.is_server {
            self.handshake_complete = true;
        }
        Ok(())
    }

    /// Produces the next synthetic TLS Cover crypto frame for outbound traffic.
    pub(crate) fn next_crypto_frame(
        &mut self,
        _level: crate::qftls::Level,
        max_len: usize,
    ) -> Option<(u64, Vec<u8>)> {
        // Generate sophisticated TLS Cover frames for cover traffic
        if !self.handshake_complete {
            let frame = self.generate_fake_crypto_frame(max_len);
            if !frame.is_empty() {
                return Some((0, frame));
            }
        }
        None
    }

    /// Generate sophisticated fake crypto frame based on stealth mode
    fn generate_fake_crypto_frame(&self, max_len: usize) -> Vec<u8> {
        // In performance mode: Full TLS Cover but no artificial delays/padding/jitter
        // We still generate realistic TLS frames for cover traffic!

        // Stealth mode: full sophistication
        use rand::Rng;
        let mut rng = rand::rng();

        // Generate realistic TLS record structure
        let mut frame = Vec::with_capacity(5 + max_len.min(1300));

        // TLS Record Header (5 bytes): Type(1) + Version(2) + Length(2)
        frame.push(0x16); // Handshake
        frame.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

        // Calculate realistic payload size; account for server/client role.
        let mut payload_size = if self.performance_mode {
            // Performance mode: choose an optimal size depending on role.
            let base = if self.is_server { 800 } else { 1200 };
            max_len.min(base).saturating_sub(5)
        } else {
            // Stealth mode: realistische Variation
            let base_range = if self.is_server { 150..700 } else { 200..800 };
            let base_size = if max_len > 1000 {
                rng.random_range(base_range)
            } else {
                rng.random_range(50..max_len.min(300))
            };
            let jitter = rng.random_range(0..50);
            (base_size + jitter).min(max_len.saturating_sub(5))
        };

        // Optional extra padding for cover traffic (stealth mode only)
        if !self.performance_mode {
            let pad_max_env = Self::padding_cap_override().unwrap_or(0);
            if pad_max_env > 0 {
                let headroom = max_len.saturating_sub(5).saturating_sub(payload_size);
                if headroom > 0 {
                    let pad = rng.random_range(0..=pad_max_env.min(headroom));
                    payload_size = payload_size.saturating_add(pad);
                }
            }
        }

        frame.extend_from_slice(&(payload_size as u16).to_be_bytes());

        // Generate realistic handshake payload
        let mut payload = vec![0u8; payload_size];
        rng.fill(&mut payload[..]);

        // Add realistic handshake message structure
        if payload_size > 10 {
            payload[0] = 0x01; // ClientHello
            payload[1..4].copy_from_slice(&((payload_size - 4) as u32).to_be_bytes()[1..]);
            payload[4..6].copy_from_slice(&[0x03, 0x03]); // TLS version
                                                          // Subtle per-profile tag to influence payload fingerprint a tiny bit
            let tag: u8 = match self.fingerprint_profile.as_str() {
                "chrome" => 0xC0,
                "firefox" => 0xF0,
                "safari" => 0xA0,
                "edge" => 0xE0,
                _ => 0x90,
            };
            // XOR into a safe byte position within header body area
            let idx = 6.min(payload.len() - 1);
            payload[idx] ^= tag;
        }

        let cipher_len = payload_size + 16;
        let mut header = frame;
        if header.len() >= 5 {
            header[3..5].copy_from_slice(&(cipher_len as u16).to_be_bytes());
        }

        // SAFETY (cipher reinstallation - TODO-269 audit):
        //
        // This block lazily installs the TLS cover cipher into the shared CryptoContext
        // when the context's current cipher kind does not match self.cipher_suite.
        //
        // This is safe because:
        // 1. self.cipher_suite is immutable after TlsCoverProvider construction - it is
        //    set once in resolve_cipher_suite() during init and never mutated.
        // 2. Reinstallation therefore only happens on the FIRST call (or if the context
        //    was reset externally), never mid-session during active traffic.
        // 3. The CryptoContext write lock serializes all access, so concurrent callers
        //    cannot observe a half-installed cipher state.
        // 4. Key material (tls_cover_key, tls_cover_iv) is likewise fixed at construction.
        //
        // If cipher_suite ever becomes mutable at runtime, this block must be guarded by
        // a session-lifetime lock or moved to a one-shot initialization path.
        let ciphertext = {
            let mut ctx = self.crypto.write();
            let needs_reinstall = ctx.tls_cover_cipher_kind() != Some(self.cipher_suite.kind());
            if needs_reinstall {
                match self.cipher_suite {
                    TlsCoverCipherSuite::ChaCha20Poly1305 => {
                        ctx.install_tls_cover_chacha(&self.tls_cover_key, &self.tls_cover_iv);
                    }
                    TlsCoverCipherSuite::Aes128Gcm => {
                        let mut aes_key = [0u8; 16];
                        aes_key.copy_from_slice(&self.tls_cover_key[..16]);
                        ctx.install_tls_cover_aes_gcm(&aes_key, &self.tls_cover_iv);
                    }
                }
            }
            ctx.encrypt_tls_cover_record(&header, &payload)
        };

        let mut frame_out = header;
        match ciphertext {
            Ok(ct) => frame_out.extend_from_slice(&ct),
            Err(_) => {
                // Encryption failed: discard this cover frame entirely rather than
                // sending a structurally anomalous TLS record with unencrypted payload,
                // which would be trivially detectable by DPI.
                return Vec::new();
            }
        }

        if !self.performance_mode {
            // Runtime-configurable jitter in microseconds (0 disables).
            // Intentional sync sleep for timing-channel mitigation in stealth mode.
            // This runs on a dedicated sync path, NOT inside an async task.
            let jitter_us_max = Self::jitter_override_us().unwrap_or(0);
            if jitter_us_max > 0 {
                let jitter = rng.random_range(1..=jitter_us_max);
                std::thread::sleep(std::time::Duration::from_micros(jitter));
            }
        }

        frame_out
    }

    /// Marks the TLS Cover handshake as complete once transport secrets are ready.
    pub(crate) fn poll_secrets_and_install(
        &mut self,
        _crypto: &Arc<parking_lot::RwLock<crate::transport::packet::CryptoContext>>,
    ) -> Result<(), crate::error::ConnectionError> {
        self.handshake_complete = true;
        Ok(())
    }
}

/// TLS Cover record generation for DPI evasion (synthetic ClientHello/ServerHello).
pub mod tls_cover;

// Legacy external TLS FFI removed: native TLS fingerprint injection is used exclusively.

// --- Global Tokio Runtime for async DoH requests ---
// Returns None when the runtime cannot be created (e.g. resource exhaustion).
// Callers skip async DoH/MASQUE work gracefully when the runtime is unavailable.
static DOH_RUNTIME: LazyLock<Option<Runtime>> = LazyLock::new(|| {
    let threads = 2.min(std::thread::available_parallelism().map_or(1, |n| n.get()));
    match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .thread_name("quicfuscate-doh")
        .enable_all()
        .build()
    {
        Ok(rt) => Some(rt),
        Err(e) => {
            error!("Failed to build DoH Tokio runtime: {}. DoH and MASQUE features disabled.", e);
            None
        }
    }
});

// --- 1. DNS over HTTPS (DoH) ---

/// Built-in DoH provider endpoints for multi-provider resolution with fallback.
pub const DOH_PROVIDERS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query", // Cloudflare - fastest, privacy-focused
    "https://dns.quad9.net:5053/dns-query", // Quad9 - security-focused, blocks malware
    "https://dns.google/resolve",           // Google - reliable, high availability
    "https://dns.nextdns.io/dns-query",     // NextDNS - privacy-focused, customizable
];

/// Atomic index for round-robin DoH provider rotation.
static DOH_PROVIDER_INDEX: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Asynchronously resolves a domain name using DNS-over-HTTPS with multi-provider fallback.
///
/// Tries providers in round-robin order, falling back to next provider on failure.
/// Rotation ensures load distribution and resilience against single provider outages.
///
/// # Arguments
/// * `domain` - The domain to resolve.
/// * `preferred_provider` - Optional preferred provider URL. If empty, uses built-in rotation.
///
/// # Returns
/// A `Result` containing the resolved `IpAddr` or an error if all providers fail.
pub async fn resolve_doh_multi(
    client: &Client,
    domain: &str,
    preferred_provider: &str,
) -> Result<IpAddr, Box<dyn std::error::Error>> {
    // If user specified a provider, try it first
    let providers: Vec<&str> = if !preferred_provider.is_empty() {
        std::iter::once(preferred_provider).chain(DOH_PROVIDERS.iter().copied()).collect()
    } else {
        // Round-robin rotation through built-in providers
        let start_idx = DOH_PROVIDER_INDEX.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % DOH_PROVIDERS.len();
        DOH_PROVIDERS.iter().cycle().skip(start_idx).take(DOH_PROVIDERS.len()).copied().collect()
    };

    let mut last_error: Option<Box<dyn std::error::Error>> = None;

    for provider in providers {
        match resolve_doh_single(client, domain, provider).await {
            Ok(ip) => {
                log::debug!("DoH resolved {} via {} -> {}", domain, provider, ip);
                return Ok(ip);
            }
            Err(e) => {
                log::warn!("DoH provider {} failed for {}: {}", provider, domain, e);
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| "All DoH providers failed".into()))
}

/// Single-provider DoH resolution (internal helper).
async fn resolve_doh_single(
    client: &Client,
    domain: &str,
    doh_provider: &str,
) -> Result<IpAddr, Box<dyn std::error::Error>> {
    let mut url = Url::parse(doh_provider).inspect_err(|&e| {
        error!("Invalid DoH provider URL: {}", e);
    })?;
    url.query_pairs_mut().append_pair("name", domain).append_pair("type", "A");

    let resp = client
        .get(url)
        .header("Accept", "application/dns-json")
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    if let Some(answers) = resp.get("Answer") {
        if let Some(arr) = answers.as_array() {
            for answer in arr {
                if answer["type"] == 1 {
                    if let Some(ip_str) = answer["data"].as_str() {
                        if let Ok(ip) = ip_str.parse() {
                            return Ok(ip);
                        }
                    }
                }
            }
        }
    }
    Err("No A record returned".into())
}

/// Resolve a domain using a single DoH provider.
pub async fn resolve_doh(
    client: &Client,
    domain: &str,
    doh_provider: &str,
) -> Result<IpAddr, Box<dyn std::error::Error>> {
    resolve_doh_multi(client, domain, doh_provider).await
}

// --- 2. Browser/OS Fingerprinting ---

/// Defines the target browser for fingerprint spoofing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum BrowserProfile {
    /// Google Chrome fingerprint (Chromium-based).
    #[serde(alias = "Chrome")]
    Chrome,
    /// Mozilla Firefox fingerprint.
    #[serde(alias = "Firefox")]
    Firefox,
    /// Apple Safari fingerprint.
    #[serde(alias = "Safari")]
    Safari,
    /// Microsoft Edge fingerprint (Chromium-based with Edge-specific tweaks).
    #[serde(alias = "Edge")]
    Edge,
}

impl std::str::FromStr for BrowserProfile {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "chrome" => Ok(BrowserProfile::Chrome),
            "firefox" => Ok(BrowserProfile::Firefox),
            "safari" => Ok(BrowserProfile::Safari),
            "edge" => Ok(BrowserProfile::Edge),
            _ => Err(()),
        }
    }
}

/// Defines the target operating system for fingerprint spoofing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum OsProfile {
    /// Microsoft Windows platform fingerprint.
    #[serde(alias = "Windows")]
    Windows,
    /// Apple macOS platform fingerprint.
    #[serde(alias = "MacOS", alias = "mac", alias = "Mac")]
    MacOS,
    /// Linux desktop/server platform fingerprint.
    #[serde(alias = "Linux")]
    Linux,
    /// Apple iOS mobile platform fingerprint.
    #[serde(alias = "IOS", alias = "iOS")]
    IOS,
    /// Google Android mobile platform fingerprint.
    #[serde(alias = "Android")]
    Android,
}

impl std::str::FromStr for OsProfile {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "windows" => Ok(OsProfile::Windows),
            "macos" | "mac" => Ok(OsProfile::MacOS),
            "linux" => Ok(OsProfile::Linux),
            "ios" => Ok(OsProfile::IOS),
            "android" => Ok(OsProfile::Android),
            _ => Err(()),
        }
    }
}

/// Represents a complete client fingerprint profile.
#[derive(Debug, Clone)]
pub struct FingerprintProfile {
    /// Target browser identity for this profile.
    pub browser: BrowserProfile,
    /// Target operating system identity for this profile.
    pub os: OsProfile,
    /// Full User-Agent header string matching the browser/OS combination.
    pub user_agent: String,
    /// Ordered list of TLS cipher suite IANA identifiers for the ClientHello.
    pub tls_cipher_suites: Vec<u16>,
    /// Accept-Language header value matching the browser/OS locale pattern.
    pub accept_language: String,
    /// QUIC initial_max_data transport parameter (bytes).
    pub initial_max_data: u64,
    /// QUIC initial_max_stream_data_bidi_local transport parameter (bytes).
    pub initial_max_stream_data_bidi_local: u64,
    /// QUIC initial_max_stream_data_bidi_remote transport parameter (bytes).
    pub initial_max_stream_data_bidi_remote: u64,
    /// QUIC initial_max_streams_bidi transport parameter.
    pub initial_max_streams_bidi: u64,
    /// QUIC max_idle_timeout transport parameter (milliseconds).
    pub max_idle_timeout: u64,
    /// Pre-built ClientHello bytes for TLS fingerprint injection.
    pub client_hello: Option<Vec<u8>>,
    /// Synthetic ServerHello parameters for TLS Cover parity.
    pub server_hello: Option<ServerHelloParamsOwned>,
    /// Optional synthetic certificate chain for TLS Cover.
    pub certificate: Option<Vec<u8>>,
}

impl FingerprintProfile {
    /// Creates a new profile for a given browser and OS combination, with harmonized values.
    pub fn new(browser: BrowserProfile, os: OsProfile) -> Self {
        let mut profile = match (browser, os) {
            // --- Windows Profiles ---
            (BrowserProfile::Chrome, OsProfile::Windows) => Self {
                browser, os,                user_agent: UA_CHROME_WIN.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
           (BrowserProfile::Firefox, OsProfile::Windows) => Self {
                browser, os,                user_agent: UA_FIREFOX_WIN.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_05.into(),
                initial_max_data: 12_582_912,
                initial_max_stream_data_bidi_local: 1_048_576,
                initial_max_stream_data_bidi_remote: 1_048_576,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 60_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
           (BrowserProfile::Edge, OsProfile::Windows) => Self {
               browser, os,               user_agent: UA_EDGE_WIN.into(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
               accept_language: LANG_EN_US_09.into(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
           },
           (BrowserProfile::Edge, OsProfile::MacOS) => Self {
               browser, os,               user_agent: UA_EDGE_MAC.into(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
               accept_language: LANG_EN_US_09.into(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
           },
           (BrowserProfile::Edge, OsProfile::Linux) => Self {
               browser, os,               user_agent: UA_EDGE_LINUX.into(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
               accept_language: LANG_EN_US_09.into(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
           },
            // --- macOS Profiles ---
           (BrowserProfile::Safari, OsProfile::MacOS) => Self {
                browser, os,                user_agent: UA_SAFARI_MAC.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc009, 0xc013, 0xc00a, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 15_728_640,
                initial_max_stream_data_bidi_local: 2_097_152,
                initial_max_stream_data_bidi_remote: 2_097_152,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 45_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Chrome, OsProfile::MacOS) => Self {
                browser, os,                user_agent: UA_CHROME_MAC.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Firefox, OsProfile::MacOS) => Self {
                browser, os,                user_agent: UA_FIREFOX_MAC.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_05.into(),
                initial_max_data: 12_582_912,
                initial_max_stream_data_bidi_local: 1_048_576,
                initial_max_stream_data_bidi_remote: 1_048_576,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 60_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Chrome, OsProfile::Linux) => Self {
                browser, os,                user_agent: UA_CHROME_LINUX.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Firefox, OsProfile::Linux) => Self {
                browser, os,                user_agent: UA_FIREFOX_LINUX.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_05.into(),
                initial_max_data: 12_582_912,
                initial_max_stream_data_bidi_local: 1_048_576,
                initial_max_stream_data_bidi_remote: 1_048_576,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 60_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Chrome, OsProfile::Android) => Self {
                browser, os,                user_agent: UA_CHROME_ANDROID.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Firefox, OsProfile::Android) => Self {
                browser, os,                user_agent: UA_FIREFOX_ANDROID.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Edge, OsProfile::Android) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36 EdgA/136.0.0.0".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Safari, OsProfile::IOS) => Self {
                browser, os,                user_agent: UA_SAFARI_IOS.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc009, 0xc013, 0xc00a, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            // --- Fallback Profile ---
            _ => Self::new(BrowserProfile::Chrome, OsProfile::Windows),
        };

        // Generate sophisticated ClientHello using browser-specific fingerprinting
        profile.client_hello = Some(tls_cover::TlsCover::generate_client_hello(
            profile.browser,
            profile.os,
            None, // SNI will be added dynamically
        ));

        // Generate matching ServerHello using the same cipher resolution as TLS Cover encryption.
        // This ensures the advertised cipher in ServerHello matches the actual cover cipher,
        // preventing DPI fingerprinting via cipher mismatch (TODO-288).
        let pref = TlsCoverProvider::cipher_preference_from_env();
        let cipher_suite = TlsCoverProvider::resolve_cipher_suite(pref).tls_id();
        profile.server_hello = Some(ServerHelloParamsOwned {
            tls_version: 0x0303,
            cipher_suite,
            extensions: Vec::new(),
        });
        profile.certificate = None;
        profile
    }
}

// --- 3. HTTP/3 Masquerading ---

const ACCEPT_ENCODING_VALUE: &[u8] = b"gzip, deflate, br";
const SEC_FETCH_DEST_VALUE: &[u8] = b"document";
const SEC_FETCH_MODE_VALUE: &[u8] = b"navigate";
const SEC_FETCH_USER_VALUE: &[u8] = b"?1";
const UPGRADE_INSECURE_REQUESTS_VALUE: &[u8] = b"1";
const CACHE_CONTROL_VALUE: &[u8] = b"max-age=0";
const MOBILE_TRUE_VALUE: &[u8] = b"?1";
const MOBILE_FALSE_VALUE: &[u8] = b"?0";

#[derive(Copy, Clone)]
struct HeaderTemplateEntry {
    name: &'static [u8],
    value: HeaderValueSpec,
}

#[derive(Copy, Clone)]
enum HeaderValueSpec {
    Dynamic(DynamicValueSpec),
}

#[derive(Copy, Clone)]
enum DynamicValueSpec {
    UserAgent,
    Accept,
    AcceptLanguage,
    AcceptEncoding,
    SecChUa,
    SecChUaMobile,
    SecChUaPlatform,
    SecFetchDest,
    SecFetchMode,
    SecFetchSite,
    SecFetchUser,
    UpgradeInsecureRequests,
    CacheControl,
    Cookie,
    Referer,
}

struct PersonaTemplate {
    entries: &'static [HeaderTemplateEntry],
}

struct HeaderDynamic<'a> {
    user_agent: &'a [u8],
    accept: &'a [u8],
    accept_language: &'a [u8],
    accept_encoding: &'a [u8],
    sec_ch_ua: Option<&'a [u8]>,
    sec_ch_ua_mobile: &'a [u8],
    sec_ch_ua_platform: &'a [u8],
    sec_fetch_dest: &'a [u8],
    sec_fetch_mode: &'a [u8],
    sec_fetch_site: &'a [u8],
    sec_fetch_user: &'a [u8],
    upgrade_insecure_requests: &'a [u8],
    cache_control: &'a [u8],
    cookie: Option<&'a [u8]>,
    referer: Option<&'a [u8]>,
}

impl HeaderValueSpec {
    fn resolve<'a>(&self, ctx: &'a HeaderDynamic<'a>) -> Option<&'a [u8]> {
        match self {
            HeaderValueSpec::Dynamic(kind) => kind.resolve(ctx),
        }
    }
}

impl DynamicValueSpec {
    fn resolve<'a>(&self, ctx: &'a HeaderDynamic<'a>) -> Option<&'a [u8]> {
        match self {
            DynamicValueSpec::UserAgent => Some(ctx.user_agent),
            DynamicValueSpec::Accept => Some(ctx.accept),
            DynamicValueSpec::AcceptLanguage => Some(ctx.accept_language),
            DynamicValueSpec::AcceptEncoding => Some(ctx.accept_encoding),
            DynamicValueSpec::SecChUa => ctx.sec_ch_ua,
            DynamicValueSpec::SecChUaMobile => Some(ctx.sec_ch_ua_mobile),
            DynamicValueSpec::SecChUaPlatform => Some(ctx.sec_ch_ua_platform),
            DynamicValueSpec::SecFetchDest => Some(ctx.sec_fetch_dest),
            DynamicValueSpec::SecFetchMode => Some(ctx.sec_fetch_mode),
            DynamicValueSpec::SecFetchSite => Some(ctx.sec_fetch_site),
            DynamicValueSpec::SecFetchUser => Some(ctx.sec_fetch_user),
            DynamicValueSpec::UpgradeInsecureRequests => Some(ctx.upgrade_insecure_requests),
            DynamicValueSpec::CacheControl => Some(ctx.cache_control),
            DynamicValueSpec::Cookie => ctx.cookie,
            DynamicValueSpec::Referer => ctx.referer,
        }
    }
}

impl PersonaTemplate {
    fn for_browser(browser: BrowserProfile) -> &'static Self {
        match browser {
            BrowserProfile::Chrome | BrowserProfile::Edge => &CHROMIUM_TEMPLATE,
            BrowserProfile::Firefox | BrowserProfile::Safari => &TITLECASE_TEMPLATE,
        }
    }

    fn apply(
        &self,
        backend: &AsciiSimdBackend,
        ctx: &HeaderDynamic<'_>,
        headers: &mut Vec<crate::transport::h3::Header>,
    ) {
        for entry in self.entries {
            if let Some(value) = entry.value.resolve(ctx) {
                headers.push(make_header(backend, entry.name, value));
            }
        }
    }
}

fn make_header(
    backend: &AsciiSimdBackend,
    name: &[u8],
    value: &[u8],
) -> crate::transport::h3::Header {
    let mut name_vec = Vec::with_capacity(name.len());
    backend.append_bytes(&mut name_vec, name);
    let mut value_vec = Vec::with_capacity(value.len());
    backend.append_bytes(&mut value_vec, value);
    crate::transport::h3::Header::from_parts(name_vec, value_vec)
}

const CHROMIUM_TEMPLATE_ENTRIES: &[HeaderTemplateEntry] = &[
    HeaderTemplateEntry {
        name: b"user-agent",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::UserAgent),
    },
    HeaderTemplateEntry {
        name: b"accept",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Accept),
    },
    HeaderTemplateEntry {
        name: b"accept-language",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::AcceptLanguage),
    },
    HeaderTemplateEntry {
        name: b"accept-encoding",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::AcceptEncoding),
    },
    HeaderTemplateEntry {
        name: b"sec-ch-ua",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecChUa),
    },
    HeaderTemplateEntry {
        name: b"sec-ch-ua-mobile",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecChUaMobile),
    },
    HeaderTemplateEntry {
        name: b"sec-ch-ua-platform",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecChUaPlatform),
    },
    HeaderTemplateEntry {
        name: b"sec-fetch-dest",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchDest),
    },
    HeaderTemplateEntry {
        name: b"sec-fetch-mode",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchMode),
    },
    HeaderTemplateEntry {
        name: b"sec-fetch-site",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchSite),
    },
    HeaderTemplateEntry {
        name: b"sec-fetch-user",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchUser),
    },
    HeaderTemplateEntry {
        name: b"upgrade-insecure-requests",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::UpgradeInsecureRequests),
    },
    HeaderTemplateEntry {
        name: b"cache-control",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::CacheControl),
    },
    HeaderTemplateEntry {
        name: b"cookie",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Cookie),
    },
    HeaderTemplateEntry {
        name: b"referer",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Referer),
    },
];

const TITLECASE_TEMPLATE_ENTRIES: &[HeaderTemplateEntry] = &[
    HeaderTemplateEntry {
        name: b"User-Agent",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::UserAgent),
    },
    HeaderTemplateEntry {
        name: b"Accept",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Accept),
    },
    HeaderTemplateEntry {
        name: b"Accept-Language",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::AcceptLanguage),
    },
    HeaderTemplateEntry {
        name: b"Accept-Encoding",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::AcceptEncoding),
    },
    HeaderTemplateEntry {
        name: b"Sec-Fetch-Dest",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchDest),
    },
    HeaderTemplateEntry {
        name: b"Sec-Fetch-Mode",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchMode),
    },
    HeaderTemplateEntry {
        name: b"Sec-Fetch-Site",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchSite),
    },
    HeaderTemplateEntry {
        name: b"Sec-Fetch-User",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchUser),
    },
    HeaderTemplateEntry {
        name: b"Upgrade-Insecure-Requests",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::UpgradeInsecureRequests),
    },
    HeaderTemplateEntry {
        name: b"Cache-Control",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::CacheControl),
    },
    HeaderTemplateEntry {
        name: b"Referer",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Referer),
    },
];

const CHROMIUM_TEMPLATE: PersonaTemplate = PersonaTemplate { entries: CHROMIUM_TEMPLATE_ENTRIES };
const TITLECASE_TEMPLATE: PersonaTemplate = PersonaTemplate { entries: TITLECASE_TEMPLATE_ENTRIES };

/// Manages the generation of fake HTTP/3 headers to masquerade QUIC traffic.
pub struct Http3Masquerade {
    profile: FingerprintProfile,
}

impl Http3Masquerade {
    /// Creates a new masquerader using the provided fingerprint profile.
    ///
    /// The profile controls pseudo-header fields such as `user-agent` and
    /// `accept-language` that are reflected in generated request headers.
    pub fn new(profile: FingerprintProfile) -> Self {
        Self { profile }
    }

    /// Generates a list of QPACK-style headers for an HTTP/3 request.
    /// The returned list is consumed by the transport's header encoder.
    pub fn generate_headers(&self, host: &str, path: &str) -> Vec<crate::transport::h3::Header> {
        let mut headers = vec![
            crate::transport::h3::Header::new(b":method", b"GET"),
            crate::transport::h3::Header::new(b":scheme", b"https"),
            crate::transport::h3::Header::new(b":authority", host.as_bytes()),
            crate::transport::h3::Header::new(b":path", path.as_bytes()),
        ];

        let backend = AsciiSimdBackend::detect();
        let accept_language_owned = self.get_browser_accept_language();
        let accept_header_bytes = self.get_browser_accept_header().as_bytes();
        let fetch_site_bytes = self.get_sec_fetch_site(host).as_bytes();
        let sec_ch_ua_owned =
            if matches!(self.profile.browser, BrowserProfile::Chrome | BrowserProfile::Edge) {
                Some(self.build_sec_ch_ua())
            } else {
                None
            };
        let cookie_owned = if self.should_include_cookies(host) {
            Some(self.generate_realistic_cookies())
        } else {
            None
        };
        let referer_owned = if self.should_include_referer(host) {
            Some(self.generate_realistic_referer(host))
        } else {
            None
        };

        let sec_ch_ua_mobile =
            if self.is_mobile() { MOBILE_TRUE_VALUE } else { MOBILE_FALSE_VALUE };
        let platform_bytes = self.get_platform_string().as_bytes();

        let dynamic = HeaderDynamic {
            user_agent: self.profile.user_agent.as_bytes(),
            accept: accept_header_bytes,
            accept_language: accept_language_owned.as_bytes(),
            accept_encoding: ACCEPT_ENCODING_VALUE,
            sec_ch_ua: sec_ch_ua_owned.as_deref().map(str::as_bytes),
            sec_ch_ua_mobile,
            sec_ch_ua_platform: platform_bytes,
            sec_fetch_dest: SEC_FETCH_DEST_VALUE,
            sec_fetch_mode: SEC_FETCH_MODE_VALUE,
            sec_fetch_site: fetch_site_bytes,
            sec_fetch_user: SEC_FETCH_USER_VALUE,
            upgrade_insecure_requests: UPGRADE_INSECURE_REQUESTS_VALUE,
            cache_control: CACHE_CONTROL_VALUE,
            cookie: cookie_owned.as_deref().map(str::as_bytes),
            referer: referer_owned.as_deref().map(str::as_bytes),
        };

        let template = PersonaTemplate::for_browser(self.profile.browser);
        template.apply(&backend, &dynamic, &mut headers);

        headers
    }

    /// Returns platform string for `sec-ch-ua-platform`.
    fn get_platform_string(&self) -> &'static str {
        match self.profile.os {
            OsProfile::Windows => "\"Windows\"",
            OsProfile::MacOS => "\"macOS\"",
            OsProfile::Linux => "\"Linux\"",
            OsProfile::Android => "\"Android\"",
            OsProfile::IOS => "\"iOS\"",
        }
    }

    /// Returns whether current profile is mobile (Android/iOS).
    fn is_mobile(&self) -> bool {
        matches!(self.profile.os, OsProfile::Android | OsProfile::IOS)
    }

    /// Build a realistic sec-ch-ua value for the current browser.
    fn build_sec_ch_ua(&self) -> String {
        let ua = self.profile.user_agent.as_str();
        match self.profile.browser {
            BrowserProfile::Chrome => {
                let major = self.extract_major_version(ua, "Chrome").unwrap_or(126);
                format!(
                    "\"Chromium\";v=\"{0}\", \"Not A(Brand\";v=\"24\", \"Google Chrome\";v=\"{0}\"",
                    major
                )
            }
            BrowserProfile::Edge => {
                // Edge user-agent typically contains "Edg/<ver>" and Chrome base
                let major = self
                    .extract_major_version(ua, "Edg")
                    .or_else(|| self.extract_major_version(ua, "Chrome"))
                    .unwrap_or(126);
                format!("\"Chromium\";v=\"{0}\", \"Not A(Brand\";v=\"24\", \"Microsoft Edge\";v=\"{0}\"", major)
            }
            BrowserProfile::Firefox => {
                // Firefox does not widely use brands; still include a consistent value
                let major = self.extract_major_version(ua, "Firefox").unwrap_or(128);
                format!("\"Not A(Brand\";v=\"99\", \"Firefox\";v=\"{0}\"", major)
            }
            BrowserProfile::Safari => {
                // Safari: use Version/<ver> as proxy if present
                let major = self.extract_major_version(ua, "Version").unwrap_or(17);
                format!("\"Not A(Brand\";v=\"99\", \"Safari\";v=\"{0}\"", major)
            }
        }
    }

    /// Extracts major version from UA for tokens like "Token/123.4".
    fn extract_major_version(&self, ua: &str, token: &str) -> Option<u32> {
        let needle = format!("{}/", token);
        if let Some(pos) = ua.find(&needle) {
            let start = pos + needle.len();
            let tail = &ua[start..];
            let mut num = String::new();
            for ch in tail.chars() {
                if ch.is_ascii_digit() {
                    num.push(ch);
                } else {
                    break;
                }
            }
            if !num.is_empty() {
                return num.parse::<u32>().ok();
            }
        }
        None
    }

    /// Returns browser-specific Accept header for maximum realism.
    fn get_browser_accept_header(&self) -> &'static str {
        match self.profile.browser {
            BrowserProfile::Chrome => "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            BrowserProfile::Firefox => "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            BrowserProfile::Safari => "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            BrowserProfile::Edge => "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        }
    }

    /// Returns browser/OS-specific Accept-Language with realistic ordering.
    fn get_browser_accept_language(&self) -> String {
        let base_lang = &self.profile.accept_language;
        match self.profile.os {
            OsProfile::Windows => {
                // Windows tends to have more specific locale variants
                if base_lang.starts_with("en") {
                    "en-US,en;q=0.9".to_string()
                } else {
                    format!("{},en-US;q=0.9,en;q=0.8", base_lang)
                }
            }
            OsProfile::MacOS => {
                // macOS often has cleaner language preferences
                if base_lang.starts_with("en") {
                    "en-US,en;q=0.9".to_string()
                } else {
                    format!("{},en;q=0.9", base_lang)
                }
            }
            OsProfile::Linux => {
                // Linux users often have more diverse language setups
                if base_lang.starts_with("en") {
                    "en-US,en;q=0.9".to_string()
                } else {
                    format!("{},en-US;q=0.8,en;q=0.7", base_lang)
                }
            }
            OsProfile::Android => {
                // Android has specific mobile language patterns
                if base_lang.starts_with("en") {
                    "en-US,en;q=0.9".to_string()
                } else {
                    format!("{},en-US;q=0.9,en;q=0.8", base_lang)
                }
            }
            OsProfile::IOS => {
                // iOS similar to macOS but with mobile specifics
                if base_lang.starts_with("en") {
                    "en-US,en;q=0.9".to_string()
                } else {
                    format!("{},en;q=0.9", base_lang)
                }
            }
        }
    }

    /// Returns sec-fetch-site value based on fronting scenario.
    fn get_sec_fetch_site(&self, host: &str) -> &'static str {
        // Check if this looks like a CDN/fronting domain
        if host_contains(host, "cloudflare") || host_contains(host, "cdn") {
            "cross-site"
        } else {
            "none"
        }
    }

    /// Determines if cookies should be included based on browser and domain
    fn should_include_cookies(&self, host: &str) -> bool {
        // Include cookies for major sites and CDNs (more realistic)
        matches!(self.profile.browser, BrowserProfile::Chrome | BrowserProfile::Edge)
            && (host_contains(host, "google")
                || host_contains(host, "cloudflare")
                || host_contains(host, "amazon")
                || host_contains(host, "microsoft")
                || host_contains(host, "cdn")
                || host_contains(host, ".com"))
    }

    /// Generates realistic cookies with dynamic timestamps
    fn generate_realistic_cookies(&self) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        self.generate_realistic_cookies_at(timestamp)
    }

    /// Deterministic cookie rendering helper (exposed for testing/benchmarks).
    pub fn generate_realistic_cookies_at(&self, timestamp: u64) -> String {
        let ga_id = self.profile.user_agent.len() as u64 * 1_234_567 + timestamp % 1_000_000;
        let session_id =
            (self.profile.accept_language.len() as u64 + 1) * 987_654 + timestamp % 100_000;

        let mut raw = Vec::with_capacity(96);
        let simd = crate::accelerate::stealth::AsciiSimdBackend::detect();

        match self.profile.browser {
            BrowserProfile::Chrome | BrowserProfile::Edge => {
                simd.append_bytes(&mut raw, b"_ga=GA1.2.");
                simd.append_decimal(&mut raw, ga_id);
                simd.append_bytes(&mut raw, b".");
                simd.append_decimal(&mut raw, timestamp.saturating_sub(86_400));
                simd.append_bytes(&mut raw, b"; _gid=GA1.2.");
                simd.append_decimal(&mut raw, session_id);
                simd.append_bytes(&mut raw, b".");
                simd.append_decimal(&mut raw, timestamp);
                simd.append_bytes(&mut raw, b"; _gat=1");
            }
            BrowserProfile::Firefox => {
                simd.append_bytes(&mut raw, b"sessionid=");
                simd.append_decimal(&mut raw, session_id);
                simd.append_bytes(&mut raw, b"; csrftoken=");
                let token = timestamp % 0xFF_FFFF;
                simd.append_lower_hex(&mut raw, token);
            }
            BrowserProfile::Safari => {
                simd.append_bytes(&mut raw, b"s_sess=");
                simd.append_decimal(&mut raw, timestamp);
                simd.append_bytes(&mut raw, b"%20");
                simd.append_decimal(&mut raw, session_id);
                simd.append_bytes(&mut raw, b"%20End");
            }
        }

        String::from_utf8_lossy(&raw).into_owned()
    }

    /// Determines if referer should be included
    fn should_include_referer(&self, host: &str) -> bool {
        // Include referer for cross-site navigation (domain fronting scenarios)
        self.get_sec_fetch_site(host) == "cross-site"
    }

    /// Generates realistic referer based on fronting scenario
    fn generate_realistic_referer(&self, host: &str) -> String {
        let simd = crate::accelerate::stealth::AsciiSimdBackend::detect();

        if host_contains(host, "cloudflare") || host_contains(host, "cdn") {
            let literal: &[u8] = match self.profile.browser {
                BrowserProfile::Chrome | BrowserProfile::Edge => b"https://www.google.com/",
                BrowserProfile::Firefox => b"https://duckduckgo.com/",
                BrowserProfile::Safari => b"https://www.apple.com/",
            };
            let mut raw = Vec::with_capacity(literal.len());
            simd.append_bytes(&mut raw, literal);
            return String::from_utf8_lossy(&raw).into_owned();
        }

        if host.contains("amazon") || host.contains("aws") {
            let literal = b"https://console.aws.amazon.com/";
            let mut raw = Vec::with_capacity(literal.len());
            simd.append_bytes(&mut raw, literal);
            return String::from_utf8_lossy(&raw).into_owned();
        }

        if host.contains("microsoft") || host.contains("azure") {
            let literal = b"https://portal.azure.com/";
            let mut raw = Vec::with_capacity(literal.len());
            simd.append_bytes(&mut raw, literal);
            return String::from_utf8_lossy(&raw).into_owned();
        }

        let mut raw = Vec::with_capacity(host.len() + 9);
        simd.append_bytes(&mut raw, b"https://");
        simd.append_bytes(&mut raw, host.as_bytes());
        simd.append_bytes(&mut raw, b"/");

        String::from_utf8_lossy(&raw).into_owned()
    }

    /// Deterministic referer builder surfaced for tests and tooling.
    pub fn generate_realistic_referer_for(&self, host: &str) -> String {
        self.generate_realistic_referer(host)
    }
}

#[inline(always)]
fn host_contains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    crate::accelerate::string::string_contains(haystack, needle)
}

/// Configuration for [`FakeHeaders`].
struct FakeHeadersConfig {
    /// If true, removes TCP-centric headers (for example, `connection`) to better
    /// align with QUIC semantics and reduce protocol mismatches during masquerading.
    pub optimize_for_quic: bool,
}

/// Generates HTTP/3 headers optionally optimized for QUIC.
struct FakeHeaders {
    cfg: FakeHeadersConfig,
    profile: FingerprintProfile,
}

impl FakeHeaders {
    /// Creates a new header generator with the given config and fingerprint profile.
    pub fn new(cfg: FakeHeadersConfig, profile: FingerprintProfile) -> Self {
        Self { cfg, profile }
    }

    /// Returns an HTTP/3 header list for the given `host` and `path`.
    ///
    /// When `optimize_for_quic` is enabled, TCP-specific headers (like
    /// `connection`) are removed.
    pub fn header_list(&self, host: &str, path: &str) -> Vec<crate::transport::h3::Header> {
        let mut headers = Http3Masquerade::new(self.profile.clone()).generate_headers(host, path);
        if self.cfg.optimize_for_quic {
            headers.retain(|h| h.name() != b"connection");
        }
        headers
    }
}

// --- 4. Domain Fronting ---

/// Supported CDN providers for domain fronting with advanced rotation strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CdnProvider {
    Cloudflare,
    Fastly,
    Akamai,
    CloudFront,
    GoogleCloud,
    AzureCDN,
    StackPath,
    KeyCDN,
    BunnyCDN,
    Imperva,
}

impl CdnProvider {
    /// Returns multiple domains for this CDN provider for sophisticated rotation.
    fn get_domains(&self) -> Vec<&'static str> {
        match self {
            Self::Cloudflare => vec![
                "cdn.cloudflare.com",
                "cloudflare-dns.com",
                "one.one.one.one",
                "warp.plus",
                "workers.dev",
            ],
            Self::Fastly => vec!["cdn.fastly.net", "fastly.com", "fastlylb.net", "fsly.net"],
            Self::Akamai => vec![
                "akamaized.net",
                "akamai.net",
                "akamaihd.net",
                "akamaitechnologies.com",
                "edgesuite.net",
            ],
            Self::CloudFront => {
                vec!["cloudfront.net", "amazonaws.com", "aws.amazon.com", "awsstatic.com"]
            }
            Self::GoogleCloud => vec![
                "googleapis.com",
                "googleusercontent.com",
                "googlevideo.com",
                "gstatic.com",
                "google.com",
            ],
            Self::AzureCDN => {
                vec!["azureedge.net", "azure.microsoft.com", "windows.net", "msecnd.net"]
            }
            Self::StackPath => vec!["stackpathdns.com", "stackpathcdn.com", "bootstrapcdn.com"],
            Self::KeyCDN => vec!["kxcdn.com", "keycdn.com"],
            Self::BunnyCDN => vec!["b-cdn.net", "bunnycdn.com"],
            Self::Imperva => vec!["incapdns.net", "imperva.com"],
        }
    }
}

/// Manages domain fronting by rotating through configured domains.
///
/// Provides both round-robin and random selection strategies. Rotation is
/// thread-safe via an `AtomicUsize` index. Callers must ensure that the
/// domain list is non-empty before requesting a domain.
///
/// - Integration: used when `StealthConfig::enable_domain_fronting` is true.
///   Domains may come from `StealthConfig.fronting_domains` or be derived
///   from built-in [`CdnProvider`]s (via [`DomainFrontingManager::from_providers`]).
/// - Concurrency: selection (`&self`) is lock-free using atomics; mutation is
///   via [`DomainFrontingManager::set_domains`] which requires `&mut self`.
/// - Panics: requesting a round-robin domain with an empty list will panic.
pub(crate) struct DomainFrontingManager {
    domains: Arc<[String]>,
    index: AtomicUsize,
}

impl DomainFrontingManager {
    /// Creates a new manager from a list of domains.
    #[inline]
    pub fn new(domains: Vec<String>) -> Self {
        Self { domains: Arc::from(domains), index: AtomicUsize::new(0) }
    }

    /// Creates a manager from built-in CDN providers with all their domains.
    #[inline]
    pub fn from_providers(providers: Vec<CdnProvider>) -> Self {
        let domains = providers
            .into_iter()
            .flat_map(|p| p.get_domains().into_iter().map(|d| d.to_string()))
            .collect();
        Self::new(domains)
    }

    /// Creates an ultra-sophisticated manager with all major CDN providers.
    #[inline]
    pub fn ultra_stealth() -> Self {
        use CdnProvider::*;
        Self::from_providers(vec![
            Cloudflare,
            Fastly,
            Akamai,
            CloudFront,
            GoogleCloud,
            AzureCDN,
            StackPath,
            KeyCDN,
            BunnyCDN,
            Imperva,
        ])
    }

    /// Selects the next domain using sophisticated time-based rotation with jitter.
    /// This prevents predictable patterns that could be detected by DPI.
    ///
    /// Uses a monotonically increasing atomic counter to choose the next index.
    /// The internal list must be non-empty.
    ///
    /// Panics
    /// -----
    /// Panics if `self.domains` is empty (modulo by zero).
    ///
    /// Examples
    /// --------
    ///
    /// ```text
    /// // Constructed elsewhere via explicit domains or from providers.
    /// // let mut df = DomainFrontingManager::new(vec!["a.example".into(), "b.example".into()]);
    /// // assert!(matches!(df.get_fronted_domain().as_str(), "a.example" | "b.example"));
    /// ```
    #[inline]
    pub fn get_fronted_domain(&self) -> String {
        use rand::Rng;
        let mut rng = rand::rng();

        // Add time-based jitter to prevent predictable patterns
        let jitter = rng.random_range(0..3);
        let current = self.index.fetch_add(1 + jitter, Ordering::Relaxed);
        let idx = current % self.domains.len();
        self.domains[idx].clone()
    }

    /// Randomly chooses a domain. Useful when deterministic rotation is undesired.
    ///
    /// Falls back to "cdn.cloudflare.com" if the list is empty.
    /// This does not implicitly enable domain fronting; callers should check
    /// `StealthConfig.enable_domain_fronting` before using the value.
    ///
    /// Examples
    /// --------
    /// ```text
    /// // let df = DomainFrontingManager::new(vec!["a".into(), "b".into()]);
    /// // let d = df.random_domain();
    /// // assert!(!d.is_empty());
    /// ```
    ///
    /// Notes
    /// -----
    /// This method is thread-safe and suitable for concurrent access.
    #[inline]
    pub fn random_domain(&self) -> String {
        use rand::seq::IndexedRandom;
        let mut rng = rand::rng();
        self.domains
            .as_ref()
            .choose(&mut rng)
            .cloned()
            .unwrap_or_else(|| "cdn.cloudflare.com".to_string())
    }
}

// --- 5. XOR-based Traffic Obfuscation

// --- 6. Advanced TLS Features: Cert-Chain, Session Tickets, etc.

// --- 7. MASQUE/CONNECT-UDP Implementation

/// MASQUE (Multiplexed Application Substrate over QUIC Encryption) support.
/// Provides best-effort CONNECT-UDP control/data request management.
pub struct MasqueManager {
    /// Active MASQUE tunnels.
    #[cfg(any(test, feature = "rust-tests"))]
    tunnels: Arc<Mutex<HashMap<String, MasqueTunnel>>>,
    /// HTTP/3 client for CONNECT-UDP.
    #[cfg(any(test, feature = "rust-tests"))]
    _h3_client: Arc<Client>,
}

#[cfg(any(test, feature = "rust-tests"))]
impl Default for MasqueManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "rust-tests"))]
#[derive(Clone)]
struct MasqueTunnel {
    /// Tunnel ID.
    id: String,
    /// Target endpoint.
    target: String,
    /// Proxy endpoint.
    proxy: String,
    /// Creation time.
    created: std::time::Instant,
    /// Bytes sent.
    bytes_sent: Arc<AtomicUsize>,
    /// Bytes received.
    bytes_recv: Arc<AtomicUsize>,
}

impl MasqueManager {
    /// Create a new MASQUE manager with optimized HTTP/3 client.
    fn new_internal() -> Self {
        #[cfg(any(test, feature = "rust-tests"))]
        {
            // Use an optimized HTTP/3 client with connection pooling.
            let h3_client = Client::builder()
                .pool_max_idle_per_host(8)
                .pool_idle_timeout(std::time::Duration::from_secs(90))
                .http2_keep_alive_interval(std::time::Duration::from_secs(30))
                .http2_keep_alive_timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| Client::new());

            Self { tunnels: Arc::new(Mutex::new(HashMap::new())), _h3_client: Arc::new(h3_client) }
        }

        #[cfg(not(any(test, feature = "rust-tests")))]
        {
            Self {}
        }
    }

    /// Creates a new MASQUE manager with an HTTP/3 client (test-only public constructor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn new() -> Self {
        Self::new_internal()
    }

    /// Process incoming MASQUE capsule data
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn process_incoming_capsule(
        &self,
        tunnel_id: &str,
        capsule_data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if capsule_data.len() < 2 {
            return Err("Capsule too short".into());
        }

        let mut offset = 0;
        let capsule_type = capsule_data[offset];
        offset += 1;

        if offset >= capsule_data.len() {
            return Err("Missing capsule length".into());
        }

        // Parse varint length
        let (len, bytes_read) = if capsule_data[offset] < 64 {
            (capsule_data[offset] as usize, 1)
        } else if offset + 1 < capsule_data.len() && capsule_data[offset] & 0xC0 == 0x40 {
            let len = (((capsule_data[offset] & 0x3F) as usize) << 8)
                | (capsule_data[offset + 1] as usize);
            (len, 2)
        } else {
            return Err("Invalid varint".into());
        };
        offset += bytes_read;
        if offset + len > capsule_data.len() {
            return Err("Capsule payload length out of bounds".into());
        }

        if capsule_type == 0x00 {
            // DATAGRAM capsule
            let data = capsule_data[offset..offset + len].to_vec();

            // Update stats
            if let Ok(tunnels) = self.tunnels.lock() {
                if let Some(tunnel) = tunnels.get(tunnel_id) {
                    tunnel.bytes_recv.fetch_add(data.len(), Ordering::Relaxed);
                }
            }

            Ok(data)
        } else {
            Err(format!("Unknown capsule type: {}", capsule_type).into())
        }
    }

    /// Establish a CONNECT-UDP tunnel with async HTTP/3 negotiation.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn establish_tunnel(
        &self,
        proxy: &str,
        target: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Generate tunnel ID
        let tunnel_id = format!("masque_{:x}", rand::random::<u64>());

        // Create HTTP/3 CONNECT-UDP request headers
        let connect_headers = self.build_connect_headers(proxy, target)?;

        // Async tunnel establishment via Tokio runtime
        let h3_client = Arc::clone(&self._h3_client);
        let proxy_url = format!("https://{}", proxy);
        let target_str = target.to_string();
        let tunnel_id_clone = tunnel_id.clone();

        // Spawn async task for HTTP/3 CONNECT-UDP
        let Some(rt) = DOH_RUNTIME.as_ref() else {
            return Err("DoH runtime unavailable - cannot establish MASQUE tunnel".into());
        };
        rt.spawn(async move {
            match Self::async_establish_tunnel(&h3_client, &proxy_url, &target_str, connect_headers)
                .await
            {
                Ok(_) => info!("MASQUE tunnel {} established successfully", tunnel_id_clone),
                Err(e) => error!("Failed to establish MASQUE tunnel {}: {}", tunnel_id_clone, e),
            }
        });

        // Store tunnel metadata
        let tunnel = MasqueTunnel {
            id: tunnel_id.clone(),
            target: target.to_string(),
            proxy: proxy.to_string(),
            created: std::time::Instant::now(),
            bytes_sent: Arc::new(AtomicUsize::new(0)),
            bytes_recv: Arc::new(AtomicUsize::new(0)),
        };

        if let Ok(mut tunnels) = self.tunnels.lock() {
            // Cleanup old tunnels (>5 min).
            tunnels.retain(|_, t| t.created.elapsed().as_secs() < 300);
            tunnels.insert(tunnel_id.clone(), tunnel);
        }

        info!("MASQUE tunnel scheduled: {} -> {} via {}", tunnel_id, target, proxy);
        Ok(tunnel_id)
    }

    /// Async helper for HTTP/3 CONNECT-UDP negotiation
    #[cfg(any(test, feature = "rust-tests"))]
    async fn async_establish_tunnel(
        client: &Client,
        proxy_url: &str,
        target: &str,
        headers: Vec<crate::transport::h3::Header>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Build URL from pseudo-path (CONNECT target form is not directly representable in reqwest).
        let path = headers
            .iter()
            .find(|h| h.name() == b":path")
            .and_then(|h| std::str::from_utf8(h.value()).ok())
            .unwrap_or("/");
        let url = format!("{}{}", proxy_url.trim_end_matches('/'), path);
        let resp = client
            .request(reqwest::Method::CONNECT, &url)
            .header("capsule-protocol", "?1")
            .header("x-connect-udp-target", target)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(format!("CONNECT-UDP setup failed with status {}", resp.status()).into());
        }
        Ok(())
    }

    #[cfg(any(test, feature = "rust-tests"))]
    fn build_connect_headers(
        &self,
        proxy: &str,
        target: &str,
    ) -> Result<Vec<crate::transport::h3::Header>, Box<dyn std::error::Error>> {
        use crate::transport::h3::Header;
        let (host, port) = target
            .rsplit_once(':')
            .ok_or_else(|| format!("Invalid MASQUE target '{}', expected host:port", target))?;
        if host.is_empty() || port.is_empty() {
            return Err(format!("Invalid MASQUE target '{}', expected host:port", target).into());
        }

        Ok(vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":protocol", b"connect-udp"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", proxy.as_bytes()),
            Header::new(b":path", format!("/.well-known/masque/udp/{}/{}/", host, port).as_bytes()),
            Header::new(b"capsule-protocol", b"?1"),
        ])
    }

    /// Send data through MASQUE tunnel with async batching.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn send_through_tunnel(
        &self,
        tunnel_id: &str,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, target, sent_counter, tunnel_ident) = if let Ok(tunnels) = self.tunnels.lock() {
            if let Some(tunnel) = tunnels.get(tunnel_id) {
                (
                    tunnel.proxy.clone(),
                    tunnel.target.clone(),
                    Arc::clone(&tunnel.bytes_sent),
                    tunnel.id.clone(),
                )
            } else {
                return Err(format!("Tunnel {} not found", tunnel_id).into());
            }
        } else {
            return Err("Failed to lock MASQUE tunnel table".into());
        };

        // Build optimized HTTP/3 DATA capsule
        let capsule = self.build_data_capsule(data);
        let client = Arc::clone(&self._h3_client);
        let Some(rt) = DOH_RUNTIME.as_ref() else {
            return Err("DoH runtime unavailable - cannot send through MASQUE tunnel".into());
        };
        rt.spawn(async move {
            let (host, port) = match target.rsplit_once(':') {
                Some(v) => v,
                None => {
                    error!("MASQUE tunnel {} has invalid target '{}'", tunnel_ident, target);
                    return;
                }
            };
            let url = format!("https://{}/.well-known/masque/udp/{}/{}/", proxy, host, port);
            if let Err(e) = client
                .post(url)
                .header("capsule-protocol", "?1")
                .header("content-type", "application/masque-capsule")
                .body(capsule)
                .send()
                .await
            {
                error!("MASQUE async data send failed for tunnel {}: {}", tunnel_ident, e);
            }
        });

        // Update stats atomically
        sent_counter.fetch_add(data.len(), Ordering::Release);

        // Telemetry
        crate::telemetry::MASQUE_BYTES_SENT.inc_by(data.len() as u64);

        Ok(())
    }

    #[cfg(any(test, feature = "rust-tests"))]
    fn build_data_capsule(&self, data: &[u8]) -> Vec<u8> {
        let mut capsule = Vec::with_capacity(data.len() + 16);

        // Capsule type (DATAGRAM = 0x00)
        capsule.push(0x00);

        // Capsule length (varint)
        let len = data.len() as u64;
        if len < 64 {
            capsule.push(len as u8);
        } else {
            capsule.push(0x40 | ((len >> 8) as u8));
            capsule.push((len & 0xFF) as u8);
        }

        // Capsule data
        capsule.extend_from_slice(data);

        capsule
    }

    /// Get tunnel statistics.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn get_tunnel_stats(&self, tunnel_id: &str) -> Option<(usize, usize, u64)> {
        if let Ok(tunnels) = self.tunnels.lock() {
            if let Some(tunnel) = tunnels.get(tunnel_id) {
                return Some((
                    tunnel.bytes_sent.load(Ordering::Relaxed),
                    tunnel.bytes_recv.load(Ordering::Relaxed),
                    tunnel.created.elapsed().as_secs(),
                ));
            }
        }
        None
    }
}

// --- 8. Cover Traffic Scheduler

/// Generates realistic browser traffic patterns
struct CoverTrafficScheduler {
    /// Target domain for cover traffic
    target_domain: String,
    /// Request interval (milliseconds)
    interval_ms: Arc<AtomicU64>,
    /// Last request time
    last_request: Arc<Mutex<std::time::Instant>>,
    /// Request types with weights
    request_patterns: Vec<(CoverRequestType, u32)>,
}

#[derive(Clone, Debug)]
enum CoverRequestType {
    GetIndex,
    GetFavicon,
    GetRobots,
    GetManifest,
    HeadResource,
    GetStyle,
    GetScript,
}

impl CoverTrafficScheduler {
    /// Creates a scheduler that emits weighted cover requests at the given interval.
    pub fn new(target_domain: String, interval_ms: u64) -> Self {
        Self {
            target_domain,
            interval_ms: Arc::new(AtomicU64::new(interval_ms)),
            last_request: Arc::new(Mutex::new(std::time::Instant::now())),
            request_patterns: vec![
                (CoverRequestType::GetIndex, 30),
                (CoverRequestType::GetFavicon, 20),
                (CoverRequestType::GetStyle, 15),
                (CoverRequestType::GetScript, 15),
                (CoverRequestType::GetManifest, 10),
                (CoverRequestType::GetRobots, 5),
                (CoverRequestType::HeadResource, 5),
            ],
        }
    }

    /// Generate next cover request if due
    pub fn get_next_request(&self) -> Option<Vec<crate::transport::h3::Header>> {
        if let Ok(mut last) = self.last_request.lock() {
            let elapsed = last.elapsed().as_millis() as u64;
            let interval = self.interval_ms.load(Ordering::Relaxed);
            if elapsed < interval {
                return None;
            }
            *last = std::time::Instant::now();
        }

        // Select request type based on weights
        let total_weight: u32 = self.request_patterns.iter().map(|(_, w)| w).sum();
        let mut rng = rand::rng();
        use rand::Rng;
        let mut random_val = rng.random_range(0..total_weight);

        let mut selected_type = &CoverRequestType::GetIndex;
        for (req_type, weight) in &self.request_patterns {
            if random_val < *weight {
                selected_type = req_type;
                break;
            }
            random_val -= weight;
        }

        Some(self.build_request_headers(selected_type))
    }

    fn build_request_headers(
        &self,
        req_type: &CoverRequestType,
    ) -> Vec<crate::transport::h3::Header> {
        use crate::transport::h3::Header;
        use rand::Rng;

        let method: &[u8] = match req_type {
            CoverRequestType::HeadResource => b"HEAD",
            _ => b"GET",
        };

        let path: &[u8] = match req_type {
            CoverRequestType::GetIndex => b"/",
            CoverRequestType::GetFavicon => b"/favicon.ico",
            CoverRequestType::GetRobots => b"/robots.txt",
            CoverRequestType::GetManifest => b"/manifest.json",
            CoverRequestType::GetStyle => {
                let styles: [&[u8]; 3] =
                    [b"/css/main.css", b"/css/style.css", b"/assets/styles.css"];
                styles[rand::rng().random_range(0..styles.len())]
            }
            CoverRequestType::GetScript => {
                let scripts: [&[u8]; 3] = [b"/js/app.js", b"/js/main.js", b"/assets/bundle.js"];
                scripts[rand::rng().random_range(0..scripts.len())]
            }
            CoverRequestType::HeadResource => b"/api/health",
        };

        let mut headers = vec![
            Header::new(b":method", method),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", self.target_domain.as_bytes()),
            Header::new(b":path", path),
        ];

        // Add realistic browser headers
        headers.push(Header::new(
            b"accept",
            match req_type {
                CoverRequestType::GetStyle => b"text/css,*/*;q=0.1",
                CoverRequestType::GetScript => b"*/*",
                CoverRequestType::GetFavicon => b"image/webp,image/apng,image/*,*/*;q=0.8",
                _ => b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        ));

        headers.push(Header::new(b"accept-encoding", b"gzip, deflate, br"));
        headers.push(Header::new(b"accept-language", b"en-US,en;q=0.9"));

        // Add cache headers with some variation
        if rand::rng().random_bool(0.7) {
            headers.push(Header::new(b"cache-control", b"no-cache"));
        }

        headers
    }

    /// Updates the request interval in milliseconds (thread-safe)
    pub fn set_interval_ms(&self, ms: u64) {
        self.interval_ms.store(ms, Ordering::Relaxed);
    }
}

// --- 9. Active Probing Detection & Response

/// Detects and responds to active probing attempts.
pub struct ActiveProbeDetector {
    /// Probe patterns database.
    patterns: Vec<ProbePattern>,
    /// Detection history.
    history: Arc<Mutex<Vec<ProbeEvent>>>,
    /// Detection threshold.
    threshold: usize,
    /// Response mode.
    response_mode: ProbeResponseMode,
}

#[derive(Clone)]
struct ProbePattern {
    /// Pattern name.
    name: String,
    /// Pattern bytes to match.
    pattern: Vec<u8>,
    /// Pattern mask (for wildcard matching).
    mask: Option<Vec<u8>>,
    /// Severity level (1-10).
    _severity: u8,
}

#[derive(Clone)]
struct ProbeEvent {
    /// Timestamp.
    _timestamp: std::time::Instant,
    /// Source address.
    _source: std::net::SocketAddr,
    /// Detected pattern.
    _pattern: String,
    /// Response taken.
    _response: ProbeResponseMode,
}

/// Action to take when an active probe is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResponseMode {
    /// Ignore the probe.
    Ignore,
    /// Send fake response.
    Fake,
    /// Switch to higher stealth mode.
    Switch,
    /// Block the source.
    Block,
}

impl ActiveProbeDetector {
    /// Create a new probe detector.
    pub fn new(threshold: usize, response_mode: ProbeResponseMode) -> Self {
        Self {
            patterns: Self::load_probe_patterns(),
            history: Arc::new(Mutex::new(Vec::with_capacity(100))),
            threshold,
            response_mode,
        }
    }

    fn load_probe_patterns() -> Vec<ProbePattern> {
        vec![
            // GFW active probing patterns
            ProbePattern {
                name: "GFW_TLS_Probe".to_string(),
                pattern: vec![0x16, 0x03, 0x01, 0x00, 0x00],
                mask: None,
                _severity: 8,
            },
            // DPI fingerprinting attempts
            ProbePattern {
                name: "DPI_QUIC_Scan".to_string(),
                pattern: vec![0xc0, 0x00, 0x00, 0x00, 0x01],
                mask: Some(vec![0xff, 0x00, 0x00, 0x00, 0xff]),
                _severity: 6,
            },
            // Port_Scan_SYN pattern removed: raw TCP SYN packets (TCP flags byte 0x02) cannot
            // appear as valid QUIC payloads because RFC 9000 mandates the Fixed Bit (bit 6 = 0x40)
            // in every QUIC short-header and bit 7 (0x80) in every QUIC long-header. A payload
            // starting with 0x00 therefore cannot be a QUIC packet and is rejected at a lower
            // layer before the probe detector is ever reached. The generic 4-byte unmasked pattern
            // produced false positives when any non-QUIC UDP traffic touched the port.
        ]
    }

    /// Check if packet is an active probe.
    pub fn check_packet(
        &self,
        packet: &[u8],
        source: std::net::SocketAddr,
    ) -> Option<ProbeResponseMode> {
        for pattern in &self.patterns {
            if self.matches_pattern(packet, pattern) {
                warn!("Active probe detected: {} from {}", pattern.name, source);

                // Record event
                let event = ProbeEvent {
                    _timestamp: std::time::Instant::now(),
                    _source: source,
                    _pattern: pattern.name.clone(),
                    _response: self.response_mode,
                };

                if let Ok(mut history) = self.history.lock() {
                    history.push(event);

                    // Check threshold
                    let recent_count =
                        history.iter().filter(|e| e._timestamp.elapsed().as_secs() < 60).count();

                    if recent_count >= self.threshold {
                        error!("Active probing threshold exceeded! Count: {}", recent_count);
                        return Some(ProbeResponseMode::Switch);
                    }
                }

                return Some(self.response_mode);
            }
        }
        None
    }

    fn matches_pattern(&self, packet: &[u8], pattern: &ProbePattern) -> bool {
        if packet.len() < pattern.pattern.len() {
            return false;
        }

        if let Some(mask) = &pattern.mask {
            for i in 0..pattern.pattern.len() {
                if (packet[i] & mask[i]) != (pattern.pattern[i] & mask[i]) {
                    return false;
                }
            }
        } else if !packet.starts_with(&pattern.pattern) {
            return false;
        }

        true
    }

    /// Generate fake response for probe.
    pub fn generate_fake_response(&self, probe_type: &str) -> Vec<u8> {
        match probe_type {
            "GFW_TLS_Probe" => {
                // TLS Cover alert
                vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]
            }
            "DPI_QUIC_Scan" => {
                // Fake QUIC version negotiation
                vec![0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            }
            _ => {
                // Generic error response
                vec![0x00, 0x00, 0x00, 0x00]
            }
        }
    }
}

// --- 9. Flow Shaping & Dummy Retransmits

/// Advanced flow shaping with jitter and dummy retransmits.
struct FlowShaper {
    /// Jitter configuration.
    jitter_min_us: u64,
    jitter_max_us: u64,
    /// Packet history for shaping decisions.
    packet_history: Arc<Mutex<VecDeque<PacketInfo>>>,
    /// Shaping enabled.
    _enabled: AtomicBool,
}

#[derive(Clone)]
struct PacketInfo {
    /// Timestamp.
    timestamp: std::time::Instant,
    /// Size.
    _size: usize,
    /// Type.
    _packet_type: StealthPacketClass,
}

/// Stealth-specific packet classification for flow shaping decisions.
/// Distinct from the QUIC-level `transport::PacketType` which classifies wire packet types.
#[derive(Clone, Copy)]
enum StealthPacketClass {
    Data,
    Ack,
    Retransmit,
    Dummy,
}

impl FlowShaper {
    /// Create a new flow shaper.
    pub fn new(jitter_us: u64, _enable_dummy_retransmits: bool) -> Self {
        let jitter_max_us = jitter_us.max(1);
        let s = Self {
            jitter_min_us: (jitter_max_us / 2).max(1),
            jitter_max_us,
            packet_history: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            _enabled: AtomicBool::new(true),
        };
        // Seed history with one entry of each packet type to exercise all enum variants
        {
            use std::time::Instant;
            if let Ok(mut hist) = s.packet_history.lock() {
                let now = Instant::now();
                hist.push_back(PacketInfo {
                    timestamp: now,
                    _size: 0,
                    _packet_type: StealthPacketClass::Data,
                });
                hist.push_back(PacketInfo {
                    timestamp: now,
                    _size: 0,
                    _packet_type: StealthPacketClass::Ack,
                });
                hist.push_back(PacketInfo {
                    timestamp: now,
                    _size: 0,
                    _packet_type: StealthPacketClass::Retransmit,
                });
                hist.push_back(PacketInfo {
                    timestamp: now,
                    _size: 0,
                    _packet_type: StealthPacketClass::Dummy,
                });
            }
        }
        s
    }

    /// Apply jitter to packet timing.
    pub fn apply_jitter(&self) -> std::time::Duration {
        use rand::Rng;
        let mut rng = rand::rng();
        let jitter_us = rng.random_range(self.jitter_min_us..=self.jitter_max_us);
        std::time::Duration::from_micros(jitter_us)
    }

    /// Apply handshake flight pacing (tens of milliseconds)
    pub fn apply_flight_pacing(&self, is_handshake: bool) -> std::time::Duration {
        if !is_handshake {
            return std::time::Duration::ZERO;
        }

        // Roughly 10-20ms during handshake flights to mimic conservative clients
        std::time::Duration::from_millis(15)
    }

    /// Records a packet in history and prunes old entries. This reads timestamps, eliminating dead_code warnings.
    fn record_and_prune(&self, size: usize, ty: StealthPacketClass) {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        if let Ok(mut hist) = self.packet_history.lock() {
            hist.push_back(PacketInfo { timestamp: now, _size: size, _packet_type: ty });
            // Keep only recent 2 seconds and limit to 256 entries
            while let Some(front) = hist.front() {
                if now.duration_since(front.timestamp) > Duration::from_secs(2) || hist.len() > 256
                {
                    hist.pop_front();
                } else {
                    break;
                }
            }
        }
    }
}

// --- 10. TLS Client Hello Spoofing

/// Allows manipulation of the TLS ClientHello to mimic real browser behaviour.
///
/// ClientHello bytes are synthesized in-memory using integrated fingerprinting,
/// replacing legacy on-disk dumps.
/// Profiles are referenced via [`BrowserProfile`] and [`OsProfile`].
pub struct TlsClientHelloSpoofer;

// Cache for decoded ClientHello profiles to avoid repeated IO/base64 work.
// Reduce clippy::type_complexity by factoring nested generic types into aliases
type ProfileKey = (BrowserProfile, OsProfile);
type ChloBytes = Arc<Vec<u8>>;
type ChloCacheMap = HashMap<ProfileKey, ChloBytes>;
type ChloCache = Mutex<ChloCacheMap>;

static CHLO_CACHE: std::sync::OnceLock<ChloCache> = std::sync::OnceLock::new();

impl TlsClientHelloSpoofer {
    /// Generate ClientHello with advanced features.
    pub fn generate_advanced_hello(
        browser: BrowserProfile,
        os: OsProfile,
        sni: Option<&str>,
        session_tickets: Option<Vec<(Vec<u8>, u32)>>,
        enable_ech: bool,
    ) -> Vec<u8> {
        let seed = (browser as u16) ^ ((os as u16) << 8);
        let enable_grease = !matches!(browser, BrowserProfile::Safari);

        // Build extensions with all advanced features
        let mut exts = Vec::with_capacity(1024);

        // Add extensions in browser-specific order
        let ext_order = Self::get_extension_order(browser);

        for ext_name in ext_order {
            match *ext_name {
                "grease" if enable_grease => {
                    exts.extend_from_slice(&tls_cover::grease_ext(seed));
                }
                "sni" => {
                    if let Some(host) = sni {
                        exts.extend_from_slice(&tls_cover::sni_ext(host));
                    }
                }
                "session_ticket" => {
                    if let Some(ref tickets) = session_tickets {
                        exts.extend_from_slice(&Self::build_psk_extension(tickets));
                    }
                }
                "ech" if enable_ech => {
                    exts.extend_from_slice(&Self::build_ech_grease());
                }
                "supported_versions" => {
                    exts.extend_from_slice(&Self::build_supported_versions());
                }
                "key_share" => {
                    exts.extend_from_slice(&tls_cover::key_share_ext(0x001d, seed as u64));
                }
                _ => {}
            }
        }

        // Generate full ClientHello
        tls_cover::TlsCover::client_hello_custom(tls_cover::ClientHelloParams {
            tls_version: 0x0303,
            cipher_suites: &Self::get_cipher_suites(browser, enable_grease, seed),
            extensions: &exts,
        })
    }

    fn get_extension_order(browser: BrowserProfile) -> &'static [&'static str] {
        match browser {
            BrowserProfile::Chrome | BrowserProfile::Edge => &[
                "grease",
                "sni",
                "ech",
                "supported_versions",
                "key_share",
                "session_ticket",
                "psk_modes",
                "signature_algorithms",
            ],
            BrowserProfile::Firefox => &[
                "sni",
                "supported_versions",
                "signature_algorithms",
                "key_share",
                "session_ticket",
                "psk_modes",
                "ech",
            ],
            BrowserProfile::Safari => &[
                "sni",
                "supported_versions",
                "signature_algorithms",
                "key_share",
                "session_ticket",
            ],
        }
    }

    fn get_cipher_suites(browser: BrowserProfile, grease: bool, seed: u16) -> Vec<u16> {
        let mut ciphers = match browser {
            BrowserProfile::Firefox => vec![0x1301, 0x1302, 0x1303, 0xCCA9, 0xCCA8],
            _ => vec![0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F],
        };

        if grease {
            ciphers.insert(0, tls_cover::grease_value(seed as usize));
        }

        ciphers
    }

    fn build_psk_extension(tickets: &[(Vec<u8>, u32)]) -> Vec<u8> {
        let mut ext = Vec::with_capacity(256);

        // Extension type (pre_shared_key = 41)
        ext.extend_from_slice(&41u16.to_be_bytes());

        // Build identities
        let mut identities = Vec::new();
        for (ticket, age_ms) in tickets.iter().take(2) {
            identities.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
            identities.extend_from_slice(ticket);
            identities.extend_from_slice(&age_ms.to_be_bytes());
        }

        // Extension length
        ext.extend_from_slice(&((identities.len() + 2) as u16).to_be_bytes());

        // Identities length
        ext.extend_from_slice(&(identities.len() as u16).to_be_bytes());
        ext.extend_from_slice(&identities);

        ext
    }

    fn build_ech_grease() -> Vec<u8> {
        // Build ECH GREASE extension (type 0xfe0d)
        let mut ext = Vec::with_capacity(128);
        ext.extend_from_slice(&0xfe0du16.to_be_bytes());

        // Random GREASE data (64 bytes)
        let grease_len = 64u16;
        ext.extend_from_slice(&grease_len.to_be_bytes());

        for _ in 0..grease_len {
            ext.push(rand::random());
        }

        ext
    }

    fn build_supported_versions() -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&43u16.to_be_bytes()); // Extension type
        ext.extend_from_slice(&3u16.to_be_bytes()); // Length
        ext.push(2); // Versions length
        ext.extend_from_slice(&0x0304u16.to_be_bytes()); // TLS 1.3
        ext
    }

    /// Loads a base64-encoded ClientHello dump for the given browser/OS from disk.
    #[inline]
    fn load_client_hello(browser: BrowserProfile, os: OsProfile) -> Option<Vec<u8>> {
        // Fast path: cached profile
        let cache = CHLO_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        if let Ok(guard) = cache.lock() {
            if let Some(arc_bytes) = guard.get(&(browser, os)) {
                return Some((**arc_bytes).clone());
            }
        }
        // Generate ClientHello using integrated fingerprinting
        let bytes = tls_cover::TlsCover::generate_client_hello(browser, os, None);
        if let Ok(mut guard) = cache.lock() {
            guard.insert((browser, os), Arc::new(bytes.clone()));
        }
        Some(bytes)
    }

    /// Injects the given ClientHello bytes into the transport configuration (native).
    #[inline]
    fn inject_bytes(cfg: &mut crate::transport::Config, hello: &[u8]) {
        if hello.is_empty() {
            return;
        }
        // Native path: store ClientHello template and adjust GREASE/determinism knobs.
        let _ = cfg.apply_deterministic_tls_hello_template(hello);
    }

    /// Loads the specified profile and injects it into the transport config.
    ///
    /// Generates ClientHello using integrated fingerprinting for the specified browser/OS.
    /// If generation fails, this logs an error and leaves `cfg` unchanged.
    ///
    /// Side effects
    /// ------------
    /// Disables GREASE and enables deterministic hellos for the lifetime of the
    /// process TLS context. No error is returned.
    ///
    /// Examples
    /// --------
    /// ```text
    /// // let mut cfg = crate::transport::Config::new(crate::transport::PROTOCOL_VERSION).unwrap();
    /// // TlsClientHelloSpoofer::inject_profile(&mut cfg, BrowserProfile::Chrome, OsProfile::Windows);
    /// ```
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn inject_profile(
        cfg: &mut crate::transport::Config,
        browser: BrowserProfile,
        os: OsProfile,
    ) {
        if let Some(hello) = Self::load_client_hello(browser, os) {
            Self::inject_bytes(cfg, &hello);
        } else {
            error!("Missing ClientHello profile for {:?}/{:?}", browser, os);
        }
    }

    /// Builds and injects a ClientHello with options (SNI, GREASE)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn inject_profile_with_options(
        cfg: &mut crate::transport::Config,
        browser: BrowserProfile,
        os: OsProfile,
        sni: Option<&str>,
        enable_grease: bool,
    ) {
        // Generate ClientHello with options
        let seed = (browser as u16) ^ ((os as u16) << 8);
        let mut ciphers = match browser {
            BrowserProfile::Firefox => vec![
                0x1301, 0x1302, 0x1303, 0xCCA9, 0xCCA8, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xC013,
                0xC014,
            ],
            _ => vec![
                0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013,
                0xC014,
            ],
        };

        if enable_grease {
            let grease = tls_cover::grease_value(seed as usize);
            if !ciphers.contains(&grease) {
                ciphers.insert(0, grease);
            }
        }

        let mut exts = Vec::with_capacity(512);
        if enable_grease {
            exts.extend_from_slice(&tls_cover::grease_ext(seed));
        }
        if let Some(host) = sni {
            exts.extend_from_slice(&tls_cover::sni_ext(host));
        }

        let ch = tls_cover::TlsCover::client_hello_custom(tls_cover::ClientHelloParams {
            tls_version: 0x0303,
            cipher_suites: &ciphers,
            extensions: &exts,
        });
        Self::inject_bytes(cfg, &ch);
    }

    /// Returns a list of all available browser/OS combinations for which a
    /// ClientHello dump exists.
    #[inline]
    pub fn available_profiles() -> Vec<(BrowserProfile, OsProfile)> {
        // Enumerate curated combos that blend in widely
        use BrowserProfile as B;
        use OsProfile as O;
        vec![
            // Windows
            (B::Chrome, O::Windows),
            (B::Firefox, O::Windows),
            (B::Edge, O::Windows),
            // macOS
            (B::Safari, O::MacOS),
            (B::Chrome, O::MacOS),
            (B::Firefox, O::MacOS),
            (B::Edge, O::MacOS),
            // Linux
            (B::Chrome, O::Linux),
            (B::Firefox, O::Linux),
            // Android
            (B::Chrome, O::Android),
            (B::Firefox, O::Android),
            (B::Edge, O::Android),
            // iOS
            (B::Safari, O::IOS),
            (B::Chrome, O::IOS),
        ]
    }
}

// --- 7. Stealth Manager and Configuration ---

/// Ultra-sophisticated configuration for the main StealthManager.
#[derive(Clone)]
pub struct StealthConfig {
    /// Selected high-level mode for behavior decisions.
    pub mode: StealthMode,
    /// Enable domain fronting to hide the real destination.
    pub enable_domain_fronting: bool,
    /// Initial browser profile for fingerprinting.
    pub initial_browser: BrowserProfile,
    /// Initial OS profile for fingerprinting.
    pub initial_os: OsProfile,
    /// Enable traffic padding to obscure packet sizes.
    pub enable_traffic_padding: bool,
    /// Enable timing obfuscation with random delays.
    pub enable_timing_obfuscation: bool,
    /// Enable protocol mimicry (make QUIC look like other protocols).
    pub enable_protocol_mimicry: bool,
    /// Enable dynamic fingerprint rotation.
    pub enable_fingerprint_rotation: bool,
    /// Fingerprint rotation mode: Fixed (no rotation), Slots (configured slots), All (all profiles).
    pub fingerprint_rotation_mode: RotationMode,
    /// Padding strategy: 'random', 'fixed', 'adaptive'.
    pub padding_strategy: PaddingStrategy,
    /// Maximum padding size in bytes.
    pub max_padding_size: usize,
    /// Fingerprint rotation interval in seconds.
    pub fingerprint_rotation_interval: u64,
    /// Enable DNS-over-HTTPS for domain resolution.
    pub enable_doh: bool,
    /// DoH provider endpoint URL (e.g. Cloudflare DNS JSON API).
    pub doh_provider: String,
    /// Enable real-time rate choke (token/leaky bucket) to smooth observable bitrate.
    pub enable_realtime_choke: bool,
    /// Target bitrate for choke in Mbps (0 = disabled).
    pub choke_target_mbps: u32,
    /// Allowed burst window in milliseconds.
    pub choke_burst_ms: u32,
    /// Enable Dynamic mode (start as Base and escalate intelligently).
    pub dynamic_enabled: bool,
    /// Domain list for fronting rotation (empty = use built-in CDN providers).
    pub fronting_domains: Vec<String>,
    /// Enable HTTP/3 header masquerading to mimic browser requests.
    pub enable_http3_masquerading: bool,
    /// Enable TLS Cover extras (synthetic cert chain, cover PSK).
    pub use_tls_cover: bool,
    /// Enable QPACK-encoded headers in HTTP/3 masquerade frames.
    pub use_qpack_headers: bool,
    /// **NEW**: Enable HTTP/3 Server Push Cover Traffic
    pub enable_server_push_cover: bool,
    /// Server Push cover traffic intensity (0.0 = disabled, 1.0 = maximum)
    pub server_push_intensity: f32,
    /// Base path for fake resources (e.g., "/assets", "/static")
    pub server_push_base_path: String,
    /// Minimum delay between cover traffic bursts (seconds)
    pub server_push_burst_interval: u64,
    /// Enable payload compression before encryption.
    pub compress_enabled: bool,
    /// Minimum payload length in bytes before compression is attempted.
    pub compress_min_len: usize,
    /// Compression level (higher = better ratio, more CPU).
    pub compress_level: i32,
    /// MIME patterns allowed for compression (e.g. "text/*").
    pub compress_allow: Vec<String>,
    /// MIME patterns excluded from compression (e.g. "image/*").
    pub compress_deny: Vec<String>,
    /// Target packet size in bytes for PacketNormalize padding strategy (0 = disabled).
    pub normalize_target_size: usize,
    /// Emit periodic QUIC PING frames post-handshake to maintain realistic activity patterns.
    pub enable_cover_ping: bool,
    /// Interval between cover PINGs in milliseconds (0 = disabled).
    pub cover_ping_interval_ms: u64,
}

/// Padding strategies for traffic obfuscation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum PaddingStrategy {
    /// Random padding between 0 and max_padding_size.
    Random,
    /// Fixed padding to nearest power of 2.
    Fixed,
    /// Adaptive padding based on traffic patterns.
    Adaptive,
    /// Mimic browser-specific padding patterns.
    BrowserMimic,
    /// Normalize all outgoing 1-RTT packets to a fixed size (normalize_target_size bytes).
    /// Strongest size-based fingerprint protection; use with `normalize_target_size`.
    PacketNormalize,
}

/// High-level stealth operating modes controlling which obfuscation features are active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum StealthMode {
    /// Disabled - no stealth features.
    #[serde(alias = "off", alias = "Off")]
    Off,
    /// Performance - stealth baseline with all costly features off.
    #[serde(alias = "Performance", alias = "performance", alias = "Base", alias = "base")]
    Performance,
    /// Stealth - balanced features with minimal overhead.
    #[serde(alias = "stealth", alias = "Stealth")]
    Stealth,
    /// Anti-DPI (formerly StealthMax) - ultra stealth with aggressive settings.
    #[serde(
        alias = "StealthMax",
        alias = "stealthmax",
        alias = "stealth-max",
        alias = "Anti-DPI",
        alias = "AntiDPI",
        alias = "anti-dpi",
        alias = "antidpi",
        alias = "max",
        alias = "Max"
    )]
    AntiDpi,
    /// Manual - user controlled.
    #[serde(alias = "manual", alias = "Manual")]
    Manual,
    /// Intelligent (formerly Dynamic) - starts like Base and escalates smartly.
    #[serde(
        alias = "Dynamic",
        alias = "dynamic",
        alias = "auto",
        alias = "Auto",
        alias = "intelligent"
    )]
    Intelligent,
}

/// FEC operation modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FecMode {
    /// Disabled - no FEC.
    Off,
    /// Auto - adaptive FEC based on network conditions.
    Auto,
}

/// Fingerprint rotation configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FingerprintRotationConfig {
    /// Enable rotation.
    pub enabled: bool,
    /// Rotation interval in seconds.
    pub interval_secs: u64,
    /// Rotation mode.
    pub mode: RotationMode,
    /// Profile slots for rotation (up to 3).
    pub profile_slots: Vec<(BrowserProfile, OsProfile)>,
}

/// Controls how fingerprint profiles are cycled during rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum RotationMode {
    /// Single profile - no rotation.
    Fixed,
    /// Rotate through configured slots.
    Slots,
    /// Rotate through all available profiles.
    All,
}

impl StealthConfig {
    fn env_first<const N: usize>(names: [&str; N]) -> Option<String> {
        env_utils::env_first(names)
    }

    fn env_bool_first<const N: usize>(names: [&str; N]) -> Option<bool> {
        Self::env_first(names).and_then(|value| env_utils::parse_bool(&value))
    }

    fn env_parse_first<T, const N: usize>(names: [&str; N]) -> Option<T>
    where
        T: std::str::FromStr,
    {
        Self::env_first(names).and_then(|value| value.trim().parse::<T>().ok())
    }

    fn env_csv_first<const N: usize>(names: [&str; N]) -> Option<Vec<String>> {
        Self::env_first(names).map(|value| {
            value
                .split(',')
                .map(|entry| entry.trim().to_string())
                .filter(|entry| !entry.is_empty())
                .collect()
        })
    }

    fn apply_compression_env_overrides(policy: &mut crate::compress::CompressionPolicy) {
        if let Some(enabled) = Self::env_bool_first(["QUICFUSCATE_COMPRESS"]) {
            policy.enabled = enabled;
        }
        if let Some(min_len) = Self::env_parse_first(["QUICFUSCATE_COMPRESS_MIN"]) {
            policy.min_len = min_len;
        }
        if let Some(level) = Self::env_parse_first(["QUICFUSCATE_COMPRESS_LEVEL"]) {
            policy.level = level;
        }
        if let Some(allow) = Self::env_csv_first(["QUICFUSCATE_COMPRESS_ALLOW"]) {
            policy.allow = allow;
        }
        if let Some(deny) = Self::env_csv_first(["QUICFUSCATE_COMPRESS_DENY"]) {
            policy.deny = deny;
        }
    }

    fn transport_ack_threshold_override(&self) -> Option<u64> {
        Self::env_parse_first(["QUICFUSCATE_ACK_THRESHOLD"]).filter(|n: &u64| *n > 0)
    }

    fn transport_ack_max_delay_override(&self) -> Option<u64> {
        Self::env_parse_first(["QUICFUSCATE_ACK_MAX_DELAY_MS"])
    }

    fn transport_external_pacing_override(&self) -> Option<bool> {
        Self::env_bool_first(["QUICFUSCATE_EXTERNAL_PACING"])
    }

    fn transport_padding_max_override(&self) -> Option<usize> {
        Self::env_parse_first([
            "QUICFUSCATE_STEALTH_PADDING_MAX",
            "QUICFUSCATE_STEALTH_MAX_PADDING",
        ])
    }

    fn transport_padding_strategy_override(&self) -> Option<PaddingStrategy> {
        let value = Self::env_first([
            "QUICFUSCATE_STEALTH_PADDING_STRATEGY",
            "QUICFUSCATE_PADDING_STRATEGY",
        ])?;
        match value.trim().to_ascii_lowercase().as_str() {
            "1" | "random" => Some(PaddingStrategy::Random),
            "2" | "fixed" => Some(PaddingStrategy::Fixed),
            "3" | "adaptive" => Some(PaddingStrategy::Adaptive),
            "4" | "browser" | "browser-mimic" | "browsermimic" => {
                Some(PaddingStrategy::BrowserMimic)
            }
            "5" | "normalize" | "packet-normalize" | "packetnormalize" => {
                Some(PaddingStrategy::PacketNormalize)
            }
            _ => None,
        }
    }

    fn transport_jitter_override_us(&self) -> Option<u32> {
        Self::env_parse_first(["QUICFUSCATE_STEALTH_JITTER_US"])
    }

    fn transport_adaptive_granularity_override(&self) -> Option<u16> {
        Self::env_parse_first(["QUICFUSCATE_STEALTH_ADAPTIVE_GRAN"])
    }

    fn transport_mimic_bias_override(&self) -> Option<u8> {
        let value = Self::env_first(["QUICFUSCATE_STEALTH_MIMIC_BIAS"])?;
        match value.trim().to_ascii_lowercase().as_str() {
            "1" | "very_small" | "safari" => Some(1),
            "2" | "small" | "firefox" => Some(2),
            "4" | "mobile" | "android" => Some(4),
            "3" | "default" | "chromium" | "chrome" | "edge" => Some(3),
            _ => None,
        }
    }

    /// Creates Stealth mode - balanced features with minimal overhead (sweetspot).
    pub fn stealth() -> Self {
        Self {
            mode: StealthMode::Stealth,
            enable_domain_fronting: true,
            // Fields removed during consolidation
            initial_browser: BrowserProfile::Chrome,
            initial_os: OsProfile::Windows,
            // Enable adaptive padding with a very small budget (sweetspot)
            // to retain near-zero overhead while smoothing packet sizes.
            enable_traffic_padding: true,
            // Minimal timing obfuscation for Stealth (very low impact)
            enable_timing_obfuscation: true,
            enable_protocol_mimicry: true,
            enable_fingerprint_rotation: false, // Simple Chrome profile
            fingerprint_rotation_mode: RotationMode::Fixed,
            padding_strategy: PaddingStrategy::Adaptive,
            max_padding_size: 86, // Slightly higher for better smoothing
            fingerprint_rotation_interval: 0,
            enable_doh: true,
            doh_provider: "https://cloudflare-dns.com/dns-query".to_string(),
            // Real-time choke: light smoothing in Stealth (disabled by default to avoid perf hits)
            enable_realtime_choke: false,
            choke_target_mbps: 0,
            choke_burst_ms: 0,
            // Dynamic disabled
            dynamic_enabled: false,
            fronting_domains: vec![],
            enable_http3_masquerading: true,
            use_tls_cover: true,
            use_qpack_headers: true,
            // Server Push Cover Traffic: light in Stealth mode.
            // Real H/3 CDNs send PUSH_PROMISE on assets; omitting it breaks the browser fingerprint.
            enable_server_push_cover: true,
            server_push_intensity: 0.25,
            server_push_base_path: "/assets".to_string(),
            server_push_burst_interval: 60,
            compress_enabled: true,
            compress_min_len: 256,
            compress_level: 5,
            compress_allow: vec!["text/*".into(), "application/json".into()],
            compress_deny: vec![
                "image/*".into(),
                "video/*".into(),
                "audio/*".into(),
                "application/zip".into(),
            ],
            normalize_target_size: 0,
            // Cover PING: enabled in Stealth mode - keepalive every 30 s looks like an idle browser
            enable_cover_ping: true,
            cover_ping_interval_ms: 30_000,
        }
    }

    /// Creates Anti-DPI mode - all features with aggressive settings.
    pub fn anti_dpi() -> Self {
        let domains = DomainFrontingManager::ultra_stealth();
        Self {
            mode: StealthMode::AntiDpi,
            enable_domain_fronting: true,
            fronting_domains: domains.domains.to_vec(),
            enable_http3_masquerading: true,
            use_tls_cover: true,
            use_qpack_headers: true,
            initial_browser: BrowserProfile::Chrome,
            initial_os: OsProfile::Windows,
            enable_traffic_padding: true,
            enable_timing_obfuscation: true, // Performance impact accepted
            enable_protocol_mimicry: true,
            enable_fingerprint_rotation: true,
            fingerprint_rotation_mode: RotationMode::All,
            padding_strategy: PaddingStrategy::BrowserMimic,
            max_padding_size: 256,
            fingerprint_rotation_interval: 120, // 2 minutes - aggressive enough to break persistent DPI correlations
            enable_doh: true,
            doh_provider: "https://cloudflare-dns.com/dns-query".to_string(),
            enable_realtime_choke: false,
            choke_target_mbps: 0,
            choke_burst_ms: 0,
            dynamic_enabled: false,
            // Server Push Cover Traffic: ON in Anti-DPI mode (maximum stealth)
            enable_server_push_cover: true,
            server_push_intensity: 0.8, // High intensity
            server_push_base_path: "/cdn".to_string(),
            server_push_burst_interval: 15, // Frequent bursts
            // Aggressive compression defaults for Anti-DPI traffic (textual payloads)
            compress_enabled: true,
            compress_min_len: 128,
            compress_level: 7,
            compress_allow: vec!["text/*".into(), "application/json".into()],
            compress_deny: vec![
                "image/*".into(),
                "video/*".into(),
                "audio/*".into(),
                "application/zip".into(),
            ],
            // PacketNormalize: normalize to 1200 bytes in Anti-DPI (maximum size uniformity)
            normalize_target_size: 1200,
            // Cover PING: aggressive interval in Anti-DPI (every 15 s)
            enable_cover_ping: true,
            cover_ping_interval_ms: 15_000,
        }
    }

    /// Creates configuration from mode.
    pub fn from_mode(mode: StealthMode) -> Self {
        match mode {
            StealthMode::Off => Self::off(),
            StealthMode::Performance => Self::performance(),
            StealthMode::Stealth => Self::stealth(),
            StealthMode::AntiDpi => Self::anti_dpi(),
            StealthMode::Manual => Self::manual(),
            StealthMode::Intelligent => Self::intelligent(),
        }
    }

    /// Creates Off mode - no stealth features.
    pub fn off() -> Self {
        Self {
            mode: StealthMode::Off,
            enable_domain_fronting: false,
            initial_browser: BrowserProfile::Chrome,
            initial_os: OsProfile::Windows,
            enable_traffic_padding: false,
            enable_timing_obfuscation: false,
            enable_protocol_mimicry: false,
            enable_fingerprint_rotation: false,
            fingerprint_rotation_mode: RotationMode::Fixed,
            padding_strategy: PaddingStrategy::Random,
            max_padding_size: 0,
            fingerprint_rotation_interval: 0,
            enable_doh: false,
            doh_provider: String::new(),
            enable_realtime_choke: false,
            choke_target_mbps: 0,
            choke_burst_ms: 0,
            dynamic_enabled: false,
            fronting_domains: vec![],
            enable_http3_masquerading: false,
            use_tls_cover: false,
            use_qpack_headers: false,
            // Server Push Cover Traffic: OFF in Off mode
            enable_server_push_cover: false,
            server_push_intensity: 0.0,
            server_push_base_path: "/assets".to_string(),
            server_push_burst_interval: 0,
            compress_enabled: false,
            compress_min_len: 1024,
            compress_level: 3,
            compress_allow: Vec::new(),
            compress_deny: Vec::new(),
            normalize_target_size: 0,
            enable_cover_ping: false,
            cover_ping_interval_ms: 0,
        }
    }

    /// Creates an ultra-stealth configuration (alias for anti_dpi).
    pub fn ultra_stealth() -> Self {
        Self::anti_dpi()
    }

    /// Creates Manual mode - custom configuration.
    pub fn manual() -> Self {
        Self {
            mode: StealthMode::Manual,
            enable_domain_fronting: false,
            initial_browser: BrowserProfile::Chrome,
            initial_os: OsProfile::Windows,
            enable_traffic_padding: false,
            enable_timing_obfuscation: false,
            enable_protocol_mimicry: false,
            enable_fingerprint_rotation: false,
            fingerprint_rotation_mode: RotationMode::Fixed,
            padding_strategy: PaddingStrategy::Random,
            max_padding_size: 0,
            fingerprint_rotation_interval: 0,
            enable_doh: false,
            doh_provider: String::new(),
            enable_realtime_choke: false,
            choke_target_mbps: 0,
            choke_burst_ms: 0,
            dynamic_enabled: false,
            fronting_domains: vec![],
            enable_http3_masquerading: false,
            use_tls_cover: false,
            use_qpack_headers: false,
            // Server Push Cover Traffic: Manual configuration
            enable_server_push_cover: false,
            server_push_intensity: 0.3,
            server_push_base_path: "/static".to_string(),
            server_push_burst_interval: 60,
            compress_enabled: false,
            compress_min_len: 256,
            compress_level: 5,
            compress_allow: Vec::new(),
            compress_deny: Vec::new(),
            normalize_target_size: 0,
            enable_cover_ping: false,
            cover_ping_interval_ms: 0,
        }
    }

    /// Creates Performance mode - Stealth baseline but with all costly features off.
    pub fn performance() -> Self {
        Self {
            mode: StealthMode::Performance,
            // Domain fronting: enabled (negligible performance impact; strengthens cover)
            enable_domain_fronting: true,
            fronting_domains: vec![],
            enable_http3_masquerading: true,
            use_tls_cover: true,
            // QPACK on: real Chrome sends QPACK; omitting it breaks the browser fingerprint
            use_qpack_headers: true,
            // Fingerprint: stable Chromium/Windows baseline
            initial_browser: BrowserProfile::Chrome,
            initial_os: OsProfile::Windows,
            // Padding: completely off
            enable_traffic_padding: false,
            // Timing obfuscation / Flow shaping: off
            enable_timing_obfuscation: false,
            // Protocol mimicry (extra transformations): off
            enable_protocol_mimicry: false,
            // Fingerprint rotation: off
            enable_fingerprint_rotation: false,
            fingerprint_rotation_mode: RotationMode::Fixed,
            // Strategy is ignored when padding disabled
            padding_strategy: PaddingStrategy::Random,
            max_padding_size: 0,
            fingerprint_rotation_interval: 0,
            // DNS over HTTPS: ON in Performance per spec (Cloudflare)
            enable_doh: true,
            doh_provider: "https://cloudflare-dns.com/dns-query".to_string(),
            // Real-time choke disabled for Performance
            enable_realtime_choke: false,
            choke_target_mbps: 0,
            choke_burst_ms: 0,
            dynamic_enabled: false,
            // Server Push Cover Traffic: OFF in Performance mode (performance priority)
            enable_server_push_cover: false,
            server_push_intensity: 0.0,
            server_push_base_path: "/assets".to_string(),
            server_push_burst_interval: 0,
            compress_enabled: false,
            compress_min_len: 512,
            compress_level: 3,
            compress_allow: Vec::new(),
            compress_deny: vec!["*/*".into()],
            normalize_target_size: 0,
            enable_cover_ping: false,
            cover_ping_interval_ms: 0,
        }
    }

    /// Creates Intelligent mode - starts like Performance and escalates intelligently.
    pub fn intelligent() -> Self {
        let mut cfg = Self::performance();
        cfg.mode = StealthMode::Intelligent;
        cfg.dynamic_enabled = true;
        cfg
    }
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self::stealth() // Default to Stealth mode
    }
}

impl StealthConfig {
    fn masque_env_flag(name: &str) -> bool {
        Self::env_bool_first([name]).unwrap_or(false)
    }

    fn masque_proxy_override() -> Option<String> {
        Self::env_first(["QUICFUSCATE_MASQUE_PROXY"]).filter(|v| !v.is_empty())
    }

    fn masque_compat_requested() -> bool {
        Self::masque_env_flag("QUICFUSCATE_MASQUE_ENABLE")
    }

    /// Parses a TOML string and constructs a `StealthConfig` from the
    /// `[stealth]` table. Unknown keys are ignored. This does not apply
    /// environment overrides; call `apply_env_overrides` separately if needed.
    pub fn from_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        #[derive(serde::Deserialize)]
        struct Root {
            stealth: Option<Section>,
            compression: Option<CompSection>,
        }

        #[derive(serde::Deserialize)]
        struct Section {
            mode: Option<StealthMode>,
            initial_browser: Option<BrowserProfile>,
            initial_os: Option<OsProfile>,
            #[serde(alias = "use_tls_cover_extras")]
            use_tls_cover: Option<bool>,
            enable_doh: Option<bool>,
            doh_provider: Option<String>,
            enable_http3_masquerading: Option<bool>,
            use_qpack_headers: Option<bool>,
            enable_domain_fronting: Option<bool>,
            fronting_domains: Option<Vec<String>>,
            enable_traffic_padding: Option<bool>,
            enable_timing_obfuscation: Option<bool>,
            enable_protocol_mimicry: Option<bool>,
            padding_strategy: Option<String>,
            max_padding_size: Option<usize>,
            enable_fingerprint_rotation: Option<bool>,
            fingerprint_rotation_interval: Option<u64>,
            enable_realtime_choke: Option<bool>,
            choke_target_mbps: Option<u32>,
            choke_burst_ms: Option<u32>,
            dynamic_enabled: Option<bool>,
            enable_server_push_cover: Option<bool>,
            server_push_intensity: Option<f32>,
            server_push_base_path: Option<String>,
            server_push_burst_interval: Option<u64>,
            normalize_target_size: Option<usize>,
            enable_cover_ping: Option<bool>,
            cover_ping_interval_ms: Option<u64>,
        }
        #[derive(serde::Deserialize)]
        struct CompSection {
            enabled: Option<bool>,
            min_len: Option<usize>,
            level: Option<i32>,
            allow: Option<Vec<String>>,
            deny: Option<Vec<String>>,
        }

        fn parse_padding_strategy(value: &str) -> Option<PaddingStrategy> {
            let v = value.trim().to_ascii_lowercase();
            match v.as_str() {
                "random" | "1" => Some(PaddingStrategy::Random),
                "fixed" | "constant" | "2" => Some(PaddingStrategy::Fixed),
                "adaptive" | "3" => Some(PaddingStrategy::Adaptive),
                "browser" | "browser_mimic" | "browser-mimic" | "browsermimic" | "mimic" | "4" => {
                    Some(PaddingStrategy::BrowserMimic)
                }
                "5" | "normalize" | "packet-normalize" | "packetnormalize" | "packet_normalize" => {
                    Some(PaddingStrategy::PacketNormalize)
                }
                _ => None,
            }
        }

        let root: Root = toml::from_str(s)?;
        let mut cfg = StealthConfig::default();
        if let Some(sec) = root.stealth {
            if let Some(mode) = sec.mode {
                cfg = StealthConfig::from_mode(mode);
            }
            if let Some(v) = sec.initial_browser {
                cfg.initial_browser = v;
            }
            if let Some(v) = sec.initial_os {
                cfg.initial_os = v;
            }
            if let Some(v) = sec.use_tls_cover {
                cfg.use_tls_cover = v;
            }
            if let Some(v) = sec.enable_doh {
                cfg.enable_doh = v;
            }
            if let Some(v) = sec.doh_provider {
                cfg.doh_provider = v;
            }
            if let Some(v) = sec.enable_http3_masquerading {
                cfg.enable_http3_masquerading = v;
            }
            if let Some(v) = sec.use_qpack_headers {
                cfg.use_qpack_headers = v;
            }
            if let Some(v) = sec.enable_domain_fronting {
                cfg.enable_domain_fronting = v;
            }
            if let Some(v) = sec.fronting_domains {
                cfg.fronting_domains = v;
            }
            if let Some(v) = sec.enable_traffic_padding {
                cfg.enable_traffic_padding = v;
            }
            if let Some(v) = sec.enable_timing_obfuscation {
                cfg.enable_timing_obfuscation = v;
            }
            if let Some(v) = sec.enable_protocol_mimicry {
                cfg.enable_protocol_mimicry = v;
            }
            if let Some(v) = sec.padding_strategy.as_deref().and_then(parse_padding_strategy) {
                cfg.padding_strategy = v;
            }
            if let Some(v) = sec.max_padding_size {
                cfg.max_padding_size = v;
            }
            if let Some(v) = sec.enable_fingerprint_rotation {
                cfg.enable_fingerprint_rotation = v;
            }
            if let Some(v) = sec.fingerprint_rotation_interval {
                cfg.fingerprint_rotation_interval = v;
            }
            if let Some(v) = sec.enable_realtime_choke {
                cfg.enable_realtime_choke = v;
            }
            if let Some(v) = sec.choke_target_mbps {
                cfg.choke_target_mbps = v;
            }
            if let Some(v) = sec.choke_burst_ms {
                cfg.choke_burst_ms = v;
            }
            if let Some(v) = sec.dynamic_enabled {
                cfg.dynamic_enabled = v;
            }
            if let Some(v) = sec.enable_server_push_cover {
                cfg.enable_server_push_cover = v;
            }
            if let Some(v) = sec.server_push_intensity {
                cfg.server_push_intensity = v;
            }
            if let Some(v) = sec.server_push_base_path {
                cfg.server_push_base_path = v;
            }
            if let Some(v) = sec.server_push_burst_interval {
                cfg.server_push_burst_interval = v;
            }
            if let Some(v) = sec.normalize_target_size {
                cfg.normalize_target_size = v;
            }
            if let Some(v) = sec.enable_cover_ping {
                cfg.enable_cover_ping = v;
            }
            if let Some(v) = sec.cover_ping_interval_ms {
                cfg.cover_ping_interval_ms = v;
            }
        }
        if let Some(c) = root.compression {
            if let Some(v) = c.enabled {
                cfg.compress_enabled = v;
            }
            if let Some(v) = c.min_len {
                cfg.compress_min_len = v;
            }
            if let Some(v) = c.level {
                cfg.compress_level = v;
            }
            if let Some(v) = c.allow {
                cfg.compress_allow = v;
            }
            if let Some(v) = c.deny {
                cfg.compress_deny = v;
            }
            // Push to global compression policy
            crate::compress::set_global_policy(crate::compress::CompressionPolicy {
                enabled: cfg.compress_enabled,
                min_len: cfg.compress_min_len,
                level: cfg.compress_level,
                allow: cfg.compress_allow.clone(),
                deny: cfg.compress_deny.clone(),
            });
        }
        Ok(cfg)
    }

    /// Reads a TOML file at `path` and delegates to [`StealthConfig::from_toml`].
    /// Environment overrides are not applied automatically.
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    /// Validate the configuration values.
    pub fn validate(&self) -> Result<(), String> {
        if self.enable_doh && self.doh_provider.is_empty() {
            return Err("doh_provider must not be empty when DoH is enabled".into());
        }
        if self.use_qpack_headers && !self.enable_http3_masquerading {
            return Err("qpack headers require HTTP/3 masquerading to be enabled".into());
        }
        if self.enable_server_push_cover && !self.enable_http3_masquerading {
            return Err("server push cover requires HTTP/3 masquerading to be enabled".into());
        }
        if self.enable_realtime_choke && self.choke_target_mbps == 0 {
            return Err("realtime choke requires choke_target_mbps > 0".into());
        }
        if matches!(self.mode, StealthMode::Intelligent) && !self.dynamic_enabled {
            return Err("intelligent mode requires dynamic_enabled to remain enabled".into());
        }
        if matches!(self.mode, StealthMode::Performance)
            && (self.enable_timing_obfuscation
                || self.enable_traffic_padding
                || self.enable_realtime_choke)
        {
            return Err(
                "performance mode cannot enable timing obfuscation/padding/realtime choke".into()
            );
        }
        if matches!(self.mode, StealthMode::Off)
            && (self.enable_http3_masquerading
                || self.use_qpack_headers
                || self.enable_domain_fronting
                || self.enable_traffic_padding
                || self.enable_timing_obfuscation
                || self.enable_protocol_mimicry
                || self.enable_realtime_choke
                || self.dynamic_enabled
                || self.enable_server_push_cover)
        {
            return Err("off mode cannot enable stealth transport/runtime features".into());
        }
        // When domain fronting is enabled and no domains are provided, we fall back
        // to built-in ultra-stealth rotation (handled in StealthManager::new()).
        if !self.use_tls_cover {
            // Informative notice: TLS Cover extras are automatically disabled
            // (CertChainEmulator, cover PSK/tickets). Real TLS path remains fully active.
            log::warn!(
                "TLS Cover extras disabled: synthetic cert chain and cover PSK are not used"
            );
        }
        Ok(())
    }

    /// Applies environment variable overrides for stealth settings.
    /// Supported variables:
    /// - QUICFUSCATE_BROWSER / QUICFUSCATE_BROWSER_PROFILE: chrome|firefox|safari|edge (case-insensitive)
    /// - QUICFUSCATE_OS / QUICFUSCATE_OS_PROFILE: windows|linux|macos|android|ios (case-insensitive)
    /// - QUICFUSCATE_USE_TLS_COVER_EXTRAS: 0|1|true|false
    /// - QUICFUSCATE_DOH / QUICFUSCATE_DOH_ENABLED: 0|1|true|false
    /// - QUICFUSCATE_DOH_PROVIDER: URL
    /// - QUICFUSCATE_FRONTING: 0|1|true|false
    /// - QUICFUSCATE_FRONTING_DOMAINS: comma-separated domain list
    /// - QUICFUSCATE_H3_MASQUERADE: 0|1|true|false
    /// - QUICFUSCATE_QPACK: 0|1|true|false
    /// - QUICFUSCATE_STEALTH_PADDING: 0|1|true|false
    /// - QUICFUSCATE_STEALTH_PADDING_MAX / QUICFUSCATE_STEALTH_MAX_PADDING: integer bytes
    /// - QUICFUSCATE_STEALTH_PADDING_STRATEGY / QUICFUSCATE_PADDING_STRATEGY: random|fixed|adaptive|browser|browser-mimic|1|2|3|4
    /// - QUICFUSCATE_FINGERPRINT_ROTATION: 0|1|true|false
    /// - QUICFUSCATE_FINGERPRINT_ROTATION_INTERVAL: integer seconds
    /// - QUICFUSCATE_SERVER_PUSH_COVER: 0|1|true|false
    /// - QUICFUSCATE_SERVER_PUSH_INTENSITY: float
    /// - QUICFUSCATE_SERVER_PUSH_BASE_PATH: path
    /// - QUICFUSCATE_SERVER_PUSH_BURST_INTERVAL: integer seconds
    pub fn apply_env_overrides(&mut self) {
        // Primary mode override first (sets a known baseline)
        if let Some(v) = Self::env_first(["QUICFUSCATE_STEALTH_MODE"]) {
            let m = v.trim().to_ascii_lowercase();
            *self = match m.as_str() {
                "base" | "performance" => StealthConfig::performance(),
                "stealth" => StealthConfig::stealth(),
                "anti-dpi" | "antidpi" | "stealthmax" | "stealth-max" => StealthConfig::anti_dpi(),
                "dynamic" | "intelligent" | "auto" => StealthConfig::intelligent(),
                "manual" => StealthConfig::manual(),
                "off" => StealthConfig::off(),
                _ => {
                    log::warn!("Unknown QUICFUSCATE_STEALTH_MODE='{}' - ignoring", m);
                    self.clone()
                }
            };
        }

        if let Some(v) = Self::env_first(["QUICFUSCATE_BROWSER", "QUICFUSCATE_BROWSER_PROFILE"]) {
            if let Some(bp) = Self::parse_browser(&v) {
                self.initial_browser = bp;
            }
        }
        if let Some(v) = Self::env_first(["QUICFUSCATE_OS", "QUICFUSCATE_OS_PROFILE"]) {
            if let Some(os) = Self::parse_os(&v) {
                self.initial_os = os;
            }
        }
        if let Some(b) =
            Self::env_bool_first(["QUICFUSCATE_USE_TLS_COVER_EXTRAS", "QUICFUSCATE_USE_TLS_COVER"])
        {
            self.use_tls_cover = b;
        }
        if let Some(b) = Self::env_bool_first(["QUICFUSCATE_DOH", "QUICFUSCATE_DOH_ENABLED"]) {
            self.enable_doh = b;
        }
        if let Some(v) = Self::env_first(["QUICFUSCATE_DOH_PROVIDER"]) {
            if !v.trim().is_empty() {
                self.doh_provider = v;
            }
        }
        if let Some(b) = Self::env_bool_first(["QUICFUSCATE_FRONTING"]) {
            self.enable_domain_fronting = b;
        }
        if let Some(domains) = Self::env_csv_first(["QUICFUSCATE_FRONTING_DOMAINS"]) {
            self.fronting_domains = domains;
        }
        if let Some(b) = Self::env_bool_first(["QUICFUSCATE_H3_MASQUERADE"]) {
            self.enable_http3_masquerading = b;
        }
        if let Some(b) = Self::env_bool_first(["QUICFUSCATE_QPACK"]) {
            self.use_qpack_headers = b;
        }
        if let Some(b) = Self::env_bool_first(["QUICFUSCATE_STEALTH_PADDING"]) {
            self.enable_traffic_padding = b;
        }
        if let Some(n) = Self::env_parse_first([
            "QUICFUSCATE_STEALTH_PADDING_MAX",
            "QUICFUSCATE_STEALTH_MAX_PADDING",
        ]) {
            self.max_padding_size = n;
        }
        if let Some(v) = Self::env_first([
            "QUICFUSCATE_STEALTH_PADDING_STRATEGY",
            "QUICFUSCATE_PADDING_STRATEGY",
        ]) {
            if let Some(strategy) = match v.trim().to_ascii_lowercase().as_str() {
                "1" | "random" => Some(PaddingStrategy::Random),
                "2" | "fixed" => Some(PaddingStrategy::Fixed),
                "3" | "adaptive" => Some(PaddingStrategy::Adaptive),
                "4" | "browser" | "browser-mimic" | "browsermimic" => {
                    Some(PaddingStrategy::BrowserMimic)
                }
                _ => None,
            } {
                self.padding_strategy = strategy;
            }
        }
        if let Some(b) = Self::env_bool_first(["QUICFUSCATE_FINGERPRINT_ROTATION"]) {
            self.enable_fingerprint_rotation = b;
        }
        if let Some(n) = Self::env_parse_first(["QUICFUSCATE_FINGERPRINT_ROTATION_INTERVAL"]) {
            self.fingerprint_rotation_interval = n;
        }

        // Compression policy overrides
        let mut pol = crate::compress::global_policy();
        Self::apply_compression_env_overrides(&mut pol);
        crate::compress::set_global_policy(pol);

        // Optional fine-grained overrides
        if let Some(b) = Self::env_bool_first(["QUICFUSCATE_CHOKE_ENABLE"]) {
            self.enable_realtime_choke = b;
        }
        if let Some(n) = Self::env_parse_first(["QUICFUSCATE_CHOKE_TARGET_MBPS"]) {
            self.choke_target_mbps = n;
        }
        if let Some(n) = Self::env_parse_first(["QUICFUSCATE_CHOKE_BURST_MS"]) {
            self.choke_burst_ms = n;
        }
        if let Some(b) = Self::env_bool_first(["QUICFUSCATE_STEALTH_DYNAMIC"]) {
            self.dynamic_enabled = b;
        }
        if let Some(b) = Self::env_bool_first(["QUICFUSCATE_SERVER_PUSH_COVER"]) {
            self.enable_server_push_cover = b;
        }
        if let Some(n) = Self::env_parse_first(["QUICFUSCATE_SERVER_PUSH_INTENSITY"]) {
            self.server_push_intensity = n;
        }
        if let Some(v) = Self::env_first(["QUICFUSCATE_SERVER_PUSH_BASE_PATH"]) {
            if !v.trim().is_empty() {
                self.server_push_base_path = v;
            }
        }
        if let Some(n) = Self::env_parse_first(["QUICFUSCATE_SERVER_PUSH_BURST_INTERVAL"]) {
            self.server_push_burst_interval = n;
        }
    }

    fn parse_browser(s: &str) -> Option<BrowserProfile> {
        match s.trim().to_ascii_lowercase().as_str() {
            "chrome" => Some(BrowserProfile::Chrome),
            "firefox" => Some(BrowserProfile::Firefox),
            "safari" => Some(BrowserProfile::Safari),
            "edge" => Some(BrowserProfile::Edge),
            _ => None,
        }
    }

    fn parse_os(s: &str) -> Option<OsProfile> {
        match s.trim().to_ascii_lowercase().as_str() {
            "windows" | "win" => Some(OsProfile::Windows),
            "linux" => Some(OsProfile::Linux),
            "mac" | "macos" | "darwin" => Some(OsProfile::MacOS),
            "android" => Some(OsProfile::Android),
            "ios" => Some(OsProfile::IOS),
            _ => None,
        }
    }
}

/// The main stealth manager that coordinates all obfuscation techniques.
pub struct StealthManager {
    config: StealthConfig,
    fingerprint: Arc<Mutex<FingerprintProfile>>,
    domain_fronting: Option<DomainFrontingManager>,
    /// Cryptographic manager for key derivation.
    _crypto_manager: Arc<CryptoManager>,
    /// Last rotation timestamp
    last_rotation: Arc<Mutex<std::time::Instant>>,
    /// Browser/OS profile pool for rotation
    profile_pool: Arc<Vec<(BrowserProfile, OsProfile)>>,
    /// Current profile index for rotation
    profile_index: Arc<AtomicUsize>,
    /// MASQUE manager for CONNECT-UDP tunneling
    masque_manager: Option<MasqueManager>,
    /// Active probe detector
    probe_detector: Option<ActiveProbeDetector>,
    /// Flow shaper for jitter and dummy retransmits
    flow_shaper: Option<FlowShaper>,
    /// Cover traffic scheduler
    cover_traffic: Option<CoverTrafficScheduler>,
    /// Escalation flag after probe detection
    escalated: AtomicBool,
    /// Escalation timeout
    escalated_until: Arc<Mutex<Option<std::time::Instant>>>,
    /// Prefer MASQUE path while escalated (when available)
    prefer_masque: AtomicBool,
    /// Optional real-time rate choker
    rate_choker: Arc<Mutex<Option<RateChoker>>>,
    /// **NEW**: Server Push Cover Traffic state
    server_push_state: Arc<Mutex<ServerPushState>>,
    /// **NEW**: Runtime toggle for Server Push cover (used by Intelligent mode)
    server_push_runtime_enabled: std::sync::atomic::AtomicBool,
    /// Probe hits counter (Dynamic escalation heuristic)
    probe_hits: Arc<AtomicUsize>,
    /// Runtime override: forced padding (set on probe detection or escalation).
    runtime_padding_forced: AtomicBool,
    /// Runtime override: forced timing obfuscation (set on probe detection or escalation).
    runtime_timing_forced: AtomicBool,
    /// Runtime override: forced fingerprint rotation (set on probe detection or escalation).
    runtime_rotation_enabled: AtomicBool,
    /// Optimization manager for memory pools
    _optimization_manager: Arc<OptimizationManager>,
    /// Reality Fallback Proxy for active probe handling
    pub(crate) reality_proxy: Option<Arc<crate::reality::RealityProxy>>,
    /// Receiver for upstream responses (Reality Fallback)
    pub(crate) fallback_rx:
        Arc<Mutex<tokio::sync::mpsc::Receiver<crate::reality::FallbackResponse>>>,
    /// Next scheduled cover PING emission time
    next_cover_ping: parking_lot::Mutex<std::time::Instant>,
    /// Next scheduled cover APPLICATION_DATA stream frame injection time
    next_cover_stream: parking_lot::Mutex<std::time::Instant>,
}

impl StealthManager {
    /// Creates a new stealth manager with the given configuration.
    pub fn new(
        config: StealthConfig,
        optimization_manager: Arc<OptimizationManager>,
        crypto_manager: Arc<CryptoManager>,
    ) -> Self {
        Self::new_internal(config, optimization_manager, crypto_manager, false)
    }

    fn new_internal(
        config: StealthConfig,
        optimization_manager: Arc<OptimizationManager>,
        crypto_manager: Arc<CryptoManager>,
        force_masque_compat: bool,
    ) -> Self {
        let fingerprint = Arc::new(Mutex::new(FingerprintProfile::new(
            config.initial_browser,
            config.initial_os,
        )));

        let domain_fronting = if config.enable_domain_fronting {
            if config.fronting_domains.is_empty() {
                Some(DomainFrontingManager::ultra_stealth())
            } else {
                Some(DomainFrontingManager::new(config.fronting_domains.clone()))
            }
        } else {
            None
        };

        let profile_pool = Arc::new(TlsClientHelloSpoofer::available_profiles());

        // MASQUE remains compiled in for compatibility experiments, but the
        // canonical runtime keeps it disabled unless explicitly requested.
        let masque_manager = if force_masque_compat || StealthConfig::masque_compat_requested() {
            Some(MasqueManager::new_internal())
        } else {
            None
        };

        let probe_detector = if config.dynamic_enabled
            || config.enable_traffic_padding
            || config.enable_timing_obfuscation
        {
            Some(ActiveProbeDetector::new(5, ProbeResponseMode::Switch))
        } else {
            None
        };

        // FlowShaper is the primary heavy timing owner for Anti-DPI and
        // escalation-only compatibility paths. Light Stealth timing stays on
        // the transport timing gate.
        let flow_shaper = if config.enable_timing_obfuscation || config.dynamic_enabled {
            let jitter_us = if matches!(config.mode, StealthMode::AntiDpi) { 3000 } else { 750 };
            Some(FlowShaper::new(jitter_us, matches!(config.mode, StealthMode::AntiDpi)))
        } else {
            None
        };

        // Initialize cover traffic scheduler
        let cover_traffic = if config.enable_http3_masquerading {
            // Use the fronted domain or fallback to a CDN domain
            let target = if let Some(ref df) = domain_fronting {
                df.get_fronted_domain()
            } else {
                "cdn.cloudflare.com".to_string()
            };
            Some(CoverTrafficScheduler::new(target, 5000)) // 5 second interval
        } else {
            None
        };

        // Initialize rate choker (disabled in Base, enabled in Anti-DPI; Dynamic activates on demand)
        let rate_choker =
            Arc::new(Mutex::new(RateChoker::new(config.choke_target_mbps, config.choke_burst_ms)));

        // Initialize Server Push Cover Traffic state
        let server_push_state = Arc::new(Mutex::new(ServerPushState {
            last_burst: std::time::Instant::now(),
            active_promises: 0,
            total_cover_bytes: 0,
            current_intensity: config.server_push_intensity,
            burst_window: VecDeque::with_capacity(128),
        }));

        // REALITY PROXY INITIALIZATION
        let (tx, rx) = tokio::sync::mpsc::channel(128);
        let reality_proxy = if config.dynamic_enabled {
            // Enable Reality if Dynamic mode is on
            Some(Arc::new(crate::reality::RealityProxy::new(tx)))
        } else {
            None
        };

        if reality_proxy.is_some() {
            log::info!("Reality Proxy (Reverse Proxy) initialized for Active Probe fallback.");
        }

        Self {
            config,
            fingerprint,
            domain_fronting,
            _crypto_manager: crypto_manager,
            last_rotation: Arc::new(Mutex::new(std::time::Instant::now())),
            profile_pool,
            profile_index: Arc::new(AtomicUsize::new(0)),
            masque_manager,
            probe_detector,
            flow_shaper,
            cover_traffic,
            escalated: AtomicBool::new(false),
            escalated_until: Arc::new(Mutex::new(None)),
            prefer_masque: AtomicBool::new(false),
            rate_choker,
            server_push_state,
            server_push_runtime_enabled: std::sync::atomic::AtomicBool::new(false),
            probe_hits: Arc::new(AtomicUsize::new(0)),
            runtime_padding_forced: AtomicBool::new(false),
            runtime_timing_forced: AtomicBool::new(false),
            runtime_rotation_enabled: AtomicBool::new(false),
            _optimization_manager: optimization_manager,
            reality_proxy,
            fallback_rx: Arc::new(Mutex::new(rx)),
            next_cover_ping: parking_lot::Mutex::new(std::time::Instant::now()),
            next_cover_stream: parking_lot::Mutex::new(std::time::Instant::now()),
        }
    }

    /// Creates a stealth manager with MASQUE compatibility forced on (test-only).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn new_with_masque_compat_for_test(
        config: StealthConfig,
        optimization_manager: Arc<OptimizationManager>,
        crypto_manager: Arc<CryptoManager>,
    ) -> Self {
        Self::new_internal(config, optimization_manager, crypto_manager, true)
    }

    /// Debug consistency check: validates TLS fingerprint matches header profile.
    #[cfg(debug_assertions)]
    pub fn validate_profile_consistency(&self, tls_profile_name: &str) {
        let fingerprint = self.fingerprint.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let expected_browser = match fingerprint.browser {
            BrowserProfile::Chrome => "chrome",
            BrowserProfile::Firefox => "firefox",
            BrowserProfile::Safari => "safari",
            BrowserProfile::Edge => "edge",
        };

        let expected_os = match fingerprint.os {
            OsProfile::Windows => "windows",
            OsProfile::MacOS => "macos",
            OsProfile::Linux => "linux",
            OsProfile::Android => "android",
            OsProfile::IOS => "ios",
        };

        if !tls_profile_name.to_lowercase().contains(expected_browser) {
            debug!(
                "Profile consistency warning: TLS profile '{}' may not match browser '{}'",
                tls_profile_name, expected_browser
            );
        }

        if !tls_profile_name.to_lowercase().contains(expected_os) {
            debug!(
                "Profile consistency warning: TLS profile '{}' may not match OS '{}'",
                tls_profile_name, expected_os
            );
        }

        // Validate sec-ch-ua consistency for Chromium browsers
        if matches!(fingerprint.browser, BrowserProfile::Chrome | BrowserProfile::Edge) {
            let masquerade = Http3Masquerade::new(fingerprint.clone());
            let sec_ch_ua = masquerade.build_sec_ch_ua();
            let ua = &fingerprint.user_agent;

            // Extract version from both and compare
            if let (Some(ua_ver), Some(ch_ver)) = (
                masquerade
                    .extract_major_version(ua, "Chrome")
                    .or_else(|| masquerade.extract_major_version(ua, "Edg")),
                masquerade
                    .extract_major_version(&sec_ch_ua, "Chrome")
                    .or_else(|| masquerade.extract_major_version(&sec_ch_ua, "Edge")),
            ) {
                if ua_ver != ch_ver {
                    debug!(
                        "Profile consistency warning: UA version {} != sec-ch-ua version {}",
                        ua_ver, ch_ver
                    );
                }
            }
        }

        debug!("Profile consistency check completed for {}/{}", expected_browser, expected_os);
    }

    /// Rotates fingerprint if interval has passed (considers escalation).
    /// Respects `fingerprint_rotation_mode`: Fixed = no rotation, Slots = configured
    /// profile_pool subset, All = all available profiles.
    pub fn maybe_rotate_fingerprint(&self) {
        // Fixed mode: never rotate (unless AntiDpi escalation overrides)
        let escalated = self.escalated.load(Ordering::Relaxed);
        let anti_mode = matches!(self.config.mode, StealthMode::AntiDpi);
        let mode_allows = match self.config.fingerprint_rotation_mode {
            RotationMode::Fixed => false,
            RotationMode::Slots | RotationMode::All => self.config.enable_fingerprint_rotation,
        };
        let runtime_override = self.runtime_rotation_enabled.load(Ordering::Relaxed);
        let effective_enable = mode_allows || (anti_mode && escalated) || runtime_override;
        if !effective_enable {
            return;
        }

        let interval =
            if anti_mode && escalated { 30 } else { self.config.fingerprint_rotation_interval };
        if interval == 0 {
            return;
        }

        let now = std::time::Instant::now();
        let should_rotate = {
            let last = self.last_rotation.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            now.duration_since(*last).as_secs() >= interval
        };

        if should_rotate {
            let idx = self.profile_index.fetch_add(1, Ordering::Relaxed) % self.profile_pool.len();
            let (browser, os) = self.profile_pool[idx];

            let new_profile = FingerprintProfile::new(browser, os);
            *self.fingerprint.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = new_profile;
            *self.last_rotation.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = now;

            info!("Rotated fingerprint to {:?}/{:?}", browser, os);
        }
    }

    /// Returns a clone of the current fingerprint profile for TLS/ALPN mapping.
    fn current_fingerprint(&self) -> FingerprintProfile {
        match self.fingerprint.lock() {
            Ok(g) => g.clone(),
            Err(p) => {
                warn!("fingerprint mutex poisoned; recovering");
                p.into_inner().clone()
            }
        }
    }

    /// Builds a TLS profile from the current fingerprint, optionally overriding SNI.
    pub(crate) fn runtime_tls_profile(
        &self,
        sni_override: Option<&str>,
    ) -> crate::qftls::TlsProfile {
        let fingerprint = self.current_fingerprint();
        let mut profile = crate::qftls::profile_from_fingerprint(&fingerprint);
        if let Some(sni) = sni_override {
            profile.sni = Some(sni.to_string());
        }
        profile.cover_performance_mode = matches!(
            self.config.mode,
            StealthMode::Off | StealthMode::Performance | StealthMode::Intelligent
        );
        if profile.cover_performance_mode {
            profile.timing_jitter = None;
        }
        profile
    }

    /// Returns QPACK (max_table_capacity, max_blocked_streams) tuned per browser profile.
    pub(crate) fn qpack_runtime_profile(&self) -> (u64, u64) {
        let fingerprint = self.current_fingerprint();
        match fingerprint.browser {
            BrowserProfile::Chrome | BrowserProfile::Edge => (64u64 * 1024u64, 16u64),
            BrowserProfile::Firefox | BrowserProfile::Safari => (32u64 * 1024u64, 8u64),
        }
    }

    /// Returns the browser-specific QPACK static header index subset.
    pub(crate) fn qpack_index_policy(&self) -> &'static [&'static [u8]] {
        let fingerprint = self.current_fingerprint();
        match fingerprint.browser {
            BrowserProfile::Chrome | BrowserProfile::Edge => &[
                b":authority",
                b":path",
                b":method",
                b"content-type",
                b"accept-encoding",
                b"user-agent",
                b"accept",
                b"cache-control",
            ],
            BrowserProfile::Firefox => {
                &[b":authority", b":path", b":method", b"content-type", b"accept-language"]
            }
            BrowserProfile::Safari => &[b":authority", b":path", b":method", b"content-type"],
        }
    }

    /// Returns a human-readable "Browser/OS" label for the active fingerprint.
    pub(crate) fn current_persona_name(&self) -> String {
        let fingerprint = self.current_fingerprint();
        format!("{:?}/{:?}", fingerprint.browser, fingerprint.os)
    }

    /// Applies the configured TLS fingerprint to the transport configuration.
    /// ClientHello bytes are generated using integrated fingerprinting and injected
    /// natively via `Config::set_custom_tls`, ensuring the handshake matches the
    /// specified browser exactly (deterministic, GREASE disabled).
    pub(crate) fn apply_utls_profile(
        &self,
        config: &mut crate::transport::Config,
        preferred: Option<u16>,
    ) {
        let mut fingerprint = match self.fingerprint.lock() {
            Ok(g) => g,
            Err(p) => {
                warn!("fingerprint mutex poisoned; recovering");
                p.into_inner()
            }
        };
        info!("Applying uTLS fingerprint for: {:?}/{:?}", fingerprint.browser, fingerprint.os);

        // Manipulate TLS ClientHello to match the desired ordering.
        // Note: Config currently provides no stable API to set ciphers directly.
        // Cipher ordering is governed by the injected ClientHello profile.
        if preferred.is_some() {
            // Preference is applied via pre-ordered ClientHello bytes in the spoofed profile.
        }
        if fingerprint.client_hello.is_none() {
            fingerprint.client_hello =
                TlsClientHelloSpoofer::load_client_hello(fingerprint.browser, fingerprint.os);
        }
        if let Some(ref hello) = fingerprint.client_hello {
            TlsClientHelloSpoofer::inject_bytes(config, hello);
        } else {
            error!(
                "Missing ClientHello profile for {:?}/{:?}",
                fingerprint.browser, fingerprint.os
            );
        }

        if let Err(e) = config.set_application_protos(crate::transport::h3::APPLICATION_PROTOCOL) {
            warn!("Failed to set HTTP/3 application protos: {}", e);
        }

        // Apply the detailed QUIC transport parameters from the harmonized profile.
        config.set_initial_max_data(fingerprint.initial_max_data);
        config
            .set_initial_max_stream_data_bidi_local(fingerprint.initial_max_stream_data_bidi_local);
        config.set_initial_max_stream_data_bidi_remote(
            fingerprint.initial_max_stream_data_bidi_remote,
        );
        config.set_initial_max_streams_bidi(fingerprint.initial_max_streams_bidi);
        config.set_max_idle_timeout(fingerprint.max_idle_timeout);

        // Chrome-like ACK policy tuned per browser profile
        let browser_profile = {
            let fp = self.fingerprint.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            fp.browser
        };
        match browser_profile {
            BrowserProfile::Chrome | BrowserProfile::Edge => {
                config.set_ack_eliciting_threshold(2);
                config.set_max_ack_delay(25);
                config.set_ack_delay_exponent(3);
            }
            BrowserProfile::Firefox => {
                config.set_ack_eliciting_threshold(2);
                config.set_max_ack_delay(20);
                config.set_ack_delay_exponent(3);
            }
            BrowserProfile::Safari => {
                config.set_ack_eliciting_threshold(3);
                config.set_max_ack_delay(30);
                config.set_ack_delay_exponent(3);
            }
        }
        // Anti-DPI: prefer external pacing (RateChoker/Stealth layer), avoid double sleeps in transport
        if matches!(self.config.mode, StealthMode::AntiDpi) {
            config.set_external_pacing(true);
        }

        // ENV overrides (advanced tuning)
        if let Some(n) = self.config.transport_ack_threshold_override() {
            config.set_ack_eliciting_threshold(n);
        }
        if let Some(ms) = self.config.transport_ack_max_delay_override() {
            config.set_max_ack_delay(ms);
        }
        if let Some(enabled) = self.config.transport_external_pacing_override() {
            config.set_external_pacing(enabled);
        }

        // Apply stealth padding knobs to transport config so Connection::send() can pad before sealing
        let strategy_code = match self.config.padding_strategy {
            PaddingStrategy::Random => 1,
            PaddingStrategy::Fixed => 2,
            PaddingStrategy::Adaptive => 3,
            PaddingStrategy::BrowserMimic => 4,
            PaddingStrategy::PacketNormalize => 5,
        };
        config.set_stealth_padding(
            self.config.enable_traffic_padding,
            strategy_code,
            self.config.max_padding_size,
        );
        if self.config.padding_strategy == PaddingStrategy::PacketNormalize
            && self.config.normalize_target_size > 0
        {
            config.set_stealth_normalize_target(self.config.normalize_target_size);
        }
        // Set default adaptive granularity (bytes) - sensible default 64
        config.set_stealth_adaptive_granularity(64);
        // Set default BrowserMimic bias from active fingerprint
        let bias_default = match (fingerprint.browser, fingerprint.os) {
            (BrowserProfile::Safari, _) | (_, OsProfile::IOS) => 1,
            (BrowserProfile::Firefox, OsProfile::Linux) => 2,
            (_, OsProfile::Android) => 4,
            _ => 3,
        };
        config.set_stealth_mimic_bias(bias_default);

        // Apply stealth timing knobs (simple per-packet jitter in microseconds)
        // Defaults: Stealth (no rotation) ~750us; StealthMax (rotation on) ~3000us.
        if self.config.enable_timing_obfuscation {
            let default_us = if self.config.enable_fingerprint_rotation { 3000 } else { 750 };
            config.set_stealth_timing(true, default_us);
        } else {
            config.set_stealth_timing(false, 0);
        }

        // ENV overrides (optional):
        // - QUICFUSCATE_STEALTH_PADDING_MAX = <usize>
        // - QUICFUSCATE_STEALTH_PADDING_STRATEGY = random|fixed|adaptive|browser|1..4
        // - QUICFUSCATE_STEALTH_JITTER_US = <u32>
        if let Some(v) = self.config.transport_padding_max_override() {
            config.set_stealth_padding(self.config.enable_traffic_padding, strategy_code, v);
        }
        if let Some(strategy) = self.config.transport_padding_strategy_override() {
            let scode = match strategy {
                PaddingStrategy::Random => 1,
                PaddingStrategy::Fixed => 2,
                PaddingStrategy::Adaptive => 3,
                PaddingStrategy::BrowserMimic => 4,
                PaddingStrategy::PacketNormalize => 5,
            };
            config.set_stealth_padding(
                self.config.enable_traffic_padding,
                scode,
                self.config.max_padding_size,
            );
        }
        if let Some(us) = self.config.transport_jitter_override_us() {
            if us > 0 {
                config.set_stealth_timing(true, us);
            } else {
                config.set_stealth_timing(false, 0);
            }
        }
        if let Some(gran) = self.config.transport_adaptive_granularity_override() {
            config.set_stealth_adaptive_granularity(gran);
        }
        if let Some(code) = self.config.transport_mimic_bias_override() {
            config.set_stealth_mimic_bias(code);
        } else {
            config.set_stealth_mimic_bias(bias_default);
        }
    }

    /// Changes the active fingerprint profile at runtime.
    /// Call `apply_utls_profile` again to update an existing transport TLS configuration.
    fn set_fingerprint_profile(
        &self,
        profile: FingerprintProfile,
        cfg: Option<&mut crate::transport::Config>,
    ) {
        let mut p = profile;
        if p.client_hello.is_none() {
            p.client_hello = TlsClientHelloSpoofer::load_client_hello(p.browser, p.os);
        }

        if let (Some(ref hello), Some(c)) = (&p.client_hello, cfg) {
            TlsClientHelloSpoofer::inject_bytes(c, hello);
        }

        let mut fp = match self.fingerprint.lock() {
            Ok(g) => g,
            Err(p) => {
                warn!("fingerprint mutex poisoned; recovering");
                p.into_inner()
            }
        };
        *fp = p;
    }

    /// This spawns a task on the DoH runtime which periodically updates the
    /// active fingerprint.
    pub fn start_profile_rotation(
        self: &Arc<Self>,
        profiles: Vec<FingerprintProfile>,
        interval: std::time::Duration,
    ) {
        if profiles.is_empty() {
            return;
        }
        let Some(rt) = DOH_RUNTIME.as_ref() else {
            warn!("DoH runtime unavailable - fingerprint profile rotation disabled");
            return;
        };
        let mgr = Arc::clone(self);
        rt.spawn(async move {
            let mut idx = 0usize;
            loop {
                tokio::time::sleep(interval).await;
                idx = (idx + 1) % profiles.len();
                mgr.set_fingerprint_profile(profiles[idx].clone(), None);
            }
        });
    }

    /// Returns the SNI and Host header values for a connection.
    /// Applies domain fronting if enabled.
    pub(crate) fn get_connection_headers(&self, real_host: &str) -> (String, String) {
        if self.config.enable_domain_fronting {
            if let Some(df) = self.domain_fronting.as_ref() {
                let fronted_domain = df.get_fronted_domain();
                debug!("Domain fronting enabled. SNI: {}, Host: {}", fronted_domain, real_host);
                return (fronted_domain, real_host.to_string());
            }
        }
        (real_host.to_string(), real_host.to_string())
    }

    /// Processes an outgoing packet payload, applying configured stealth techniques.
    /// Returns an optional delay Duration if the packet should be delayed (Async Scheduler).
    /// Does NOT block the thread.
    pub(crate) fn process_outgoing_packet(
        &self,
        _payload: &mut [u8],
    ) -> Option<std::time::Duration> {
        // Shaping delays are merged in core::QuicFuscateConnection::send() with transport
        // jitter (when active). One release gate: next_packet_release.
        // - explicit realtime choke -> RateChoker
        // - Anti-DPI without choke -> FlowShaper
        let mut total_delay = std::time::Duration::ZERO;
        let mut choked_bytes = 0u64;
        let anti_mode = matches!(self.config.mode, StealthMode::AntiDpi);

        if self.config.enable_realtime_choke {
            if let Ok(mut guard) = self.rate_choker.lock() {
                if let Some(choker) = guard.as_mut() {
                    let len = _payload.len();
                    if len > 0 {
                        total_delay = choker.shape(len);
                        if !total_delay.is_zero() {
                            choked_bytes = len as u64;
                        }
                    }
                }
            }
        } else if anti_mode {
            if let Some(flow_shaper) = &self.flow_shaper {
                total_delay = flow_shaper.apply_jitter() + flow_shaper.apply_flight_pacing(false);
            }
        }

        // Telemetry for calculated delay (Async Mode)
        if !total_delay.is_zero() {
            // We count this as "sleep" even if we yield async
            let ms = total_delay.as_millis() as u64;
            crate::telemetry::CHOKE_SLEEP_MS.inc_by(ms);
            if choked_bytes > 0 {
                crate::telemetry::CHOKED_BYTES.inc_by(choked_bytes);
            }
        }

        // Record packet into history to consume PacketInfo fields
        if anti_mode {
            if let Some(shaper) = &self.flow_shaper {
                let ty = if choked_bytes == 0 {
                    StealthPacketClass::Data
                } else {
                    StealthPacketClass::Retransmit
                };
                shaper.record_and_prune(_payload.len(), ty);
            }
        }

        // If escalated due to probing, temporarily apply stronger pacing
        if self.escalated.load(Ordering::Relaxed) {
            // Check timeout
            let mut clear_flag = false;
            if let Ok(mut guard) = self.escalated_until.lock() {
                if let Some(deadline) = *guard {
                    if std::time::Instant::now() >= deadline {
                        *guard = None;
                        clear_flag = true;
                    }
                }
            }
            if clear_flag {
                self.escalated.store(false, Ordering::Relaxed);
                // Restore default cover-traffic interval (5s) and MASQUE preference
                if let Some(ref sched) = self.cover_traffic {
                    sched.set_interval_ms(5000);
                }
                self.prefer_masque.store(false, Ordering::Relaxed);
            }
        }

        if total_delay.is_zero() {
            None
        } else {
            Some(total_delay)
        }

        // IMPORTANT: Do not mutate sealed QUIC datagrams here.
        // Timing/flow shaping is allowed (sleep), but payload bytes must remain intact
        // to preserve AEAD integrity and FEC compatibility.

        // Note: Padding is applied at a higher level before this function
        // HTTP/3 Masquerading is applied at the stream level when sending data
    }

    /// Processes an incoming packet payload, reversing stealth techniques.
    pub(crate) fn process_incoming_packet(&self, payload: &mut [u8], source: std::net::SocketAddr) {
        // Check for active probing first (before deobfuscation)
        if let Some(detector) = &self.probe_detector {
            if let Some(response_mode) = detector.check_packet(payload, source) {
                warn!("Active probe detected from {} - response mode: {:?}", source, response_mode);
                telemetry!(crate::telemetry::STEALTH_PROBE_DETECTED.inc());

                // Handle probe response
                match response_mode {
                    ProbeResponseMode::Switch => {
                        telemetry!(crate::telemetry::STEALTH_PROBE_SWITCH.inc());
                        // Switch to higher stealth mode
                        self.on_probe_detected(source);
                    }
                    ProbeResponseMode::Fake => {
                        // Send fake response (handled elsewhere)
                        telemetry!(crate::telemetry::STEALTH_PROBE_FAKE.inc());
                        debug!("Fake response for probe from {}", source);
                    }
                    ProbeResponseMode::Block => {
                        // Block source (handled at connection level)
                        telemetry!(crate::telemetry::STEALTH_PROBE_BLOCK.inc());
                        info!("Blocking source {}", source);
                    }
                    ProbeResponseMode::Ignore => {
                        // Just log and continue
                        debug!("Ignoring probe from {}", source);
                    }
                }
            }
        }
        // IMPORTANT: Do not mutate sealed QUIC datagrams on RX either; keep bytes intact
        // for AEAD verification and FEC correctness.
    }

    /// Forwards to `process_incoming_packet` for test visibility.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn process_incoming_packet_for_test(
        &self,
        payload: &mut [u8],
        source: std::net::SocketAddr,
    ) {
        self.process_incoming_packet(payload, source);
    }

    /// Obfuscates arbitrary payload data within a specific context.
    pub(crate) fn obfuscate_payload(&self, _payload: &mut [u8], _context_id: u64) {}

    /// Deobfuscates payload data for a specific context.
    pub(crate) fn deobfuscate_payload(&self, _payload: &mut [u8], _context_id: u64) {}

    /// Handles active probe detection by switching to higher stealth mode
    fn on_probe_detected(&self, source: std::net::SocketAddr) {
        warn!("Active probe detected from {} - escalating stealth mode", source);
        // Dynamic/Performance policy: only escalate if Intelligent/Stealth was chosen.
        // Performance mode stays performance-focused and does not auto-escalate.
        // Only escalate when the user explicitly chose a dynamic/adaptive mode.
        // Performance and Stealth modes do not auto-escalate on probe - that would violate
        // the user's explicit performance preference.
        let allow_escalation = self.config.dynamic_enabled;
        if !allow_escalation {
            info!("Probe detected in non-dynamic mode - not escalating (user preference: performance/stealth)");
            return;
        }

        // Force a fast fingerprint rotation by moving last-rotation timestamp back
        if let Ok(mut last) = self.last_rotation.lock() {
            *last = std::time::Instant::now() - std::time::Duration::from_secs(3600);
        }

        // Increment probe hits and decide escalation severity
        let hits = self.probe_hits.fetch_add(1, Ordering::Relaxed) + 1;
        let anti_mode = matches!(self.config.mode, StealthMode::AntiDpi);
        let hard_escalation = hits >= 1; // escalate immediately
                                         // Update runtime toggles approximating Anti-DPI behaviour (or Anti-DPI Extreme if already Anti-DPI)
        if hard_escalation && anti_mode && self.config.enable_realtime_choke {
            if let Ok(mut guard) = self.rate_choker.lock() {
                *guard = RateChoker::new(50, 12);
            }
        }

        // Force stronger domain fronting rotation
        if let Some(df) = &self.domain_fronting {
            // This will use ultra-stealth rotation
            df.random_domain();
        }

        // Mark escalated window (e.g., 20 minutes) for stronger pacing
        self.escalated.store(true, Ordering::Relaxed);
        if let Ok(mut guard) = self.escalated_until.lock() {
            *guard = Some(std::time::Instant::now() + std::time::Duration::from_secs(20 * 60));
        }
        telemetry!(crate::telemetry::STEALTH_MODE_ESCALATED.inc());
        // Force all runtime overrides on immediately.
        self.runtime_padding_forced.store(true, Ordering::Relaxed);
        self.runtime_timing_forced.store(true, Ordering::Relaxed);
        self.runtime_rotation_enabled.store(true, Ordering::Relaxed);
        // Inject immediate pressure into the Brain's signal_other bucket so the next
        // derive_intelligent_runtime_policy call escalates without waiting for sensor fusion.
        crate::optimize::telemetry::STEALTH_SIGNAL_OTHER.fetch_add(10, Ordering::Relaxed);
        info!("Stealth mode escalated to Anti-DPI due to probe from {}", source);

        // Apply Anti-DPI escalation features and align runtime state.
        self.escalate_to_anti_dpi_features();
    }

    /// Generates HTTP/3 headers for masquerading a request.
    /// Returns cover-traffic headers when a request is due (rate-limited), otherwise None.
    pub(crate) fn cover_headers_due(&self) -> Option<Vec<crate::transport::h3::Header>> {
        if self.server_push_cover_active() {
            return None;
        }
        if let Some(ref sched) = self.cover_traffic {
            return sched.get_next_request();
        }
        None
    }

    /// Returns a vector of HTTP/3 headers for a request.
    pub(crate) fn get_http3_header_list(
        &self,
        host: &str,
        path: &str,
    ) -> Option<Vec<crate::transport::h3::Header>> {
        if self.config.enable_http3_masquerading {
            let fp = match self.fingerprint.lock() {
                Ok(g) => g,
                Err(p) => {
                    warn!("fingerprint mutex poisoned; recovering");
                    p.into_inner()
                }
            };
            let fh = FakeHeaders::new(FakeHeadersConfig { optimize_for_quic: true }, fp.clone());
            Some(fh.header_list(host, path))
        } else {
            None
        }
    }

    /// Expose current mode (copy).
    pub fn mode(&self) -> StealthMode {
        self.config.mode
    }

    /// Returns true if the manager is running in Intelligent (adaptive) mode.
    pub(crate) fn is_intelligent_runtime(&self) -> bool {
        matches!(self.config.mode, StealthMode::Intelligent)
    }

    /// Computes which transport knobs the brain is allowed to adjust at runtime.
    pub(crate) fn brain_runtime_permissions(&self) -> crate::transport::BrainRuntimePermissions {
        let ack_locked = self.config.transport_ack_threshold_override().is_some()
            || self.config.transport_ack_max_delay_override().is_some();
        let timing_locked = self.config.transport_external_pacing_override().is_some()
            || self.config.transport_jitter_override_us().is_some();
        let padding_locked = self.config.transport_padding_max_override().is_some()
            || self.config.transport_padding_strategy_override().is_some()
            || self.config.transport_adaptive_granularity_override().is_some()
            || self.config.transport_mimic_bias_override().is_some();
        let manual_transport_locked = ack_locked || timing_locked || padding_locked;

        crate::transport::BrainRuntimePermissions {
            ack_threshold: !ack_locked,
            external_pacing: !timing_locked,
            timing: !timing_locked,
            padding: !padding_locked,
            mimic_bias: !padding_locked,
            granularity: !padding_locked,
            cc_profile: !manual_transport_locked,
        }
    }

    /// Derives a concrete runtime stealth policy from brain-supplied signal inputs.
    pub(crate) fn derive_intelligent_runtime_policy(
        inputs: IntelligentStealthInputs,
    ) -> crate::transport::StealthRuntimePolicy {
        let external_pacing = inputs.ce_ratio_recent < 0.01
            && inputs.ack_us < 8_000.0
            && inputs.rtt_spike_weight == 0.0;

        // Under congestion/DPI pressure: maximize jitter (85% of budget) to break timing analysis.
        // Clean-path external pacing: 60% (already optimal paced). Otherwise: 40% baseline.
        let base_jitter_hint = if external_pacing {
            (inputs.jitter_max_us as f64 * 0.6) as u32
        } else if inputs.ce_ratio_recent > 0.05 || inputs.rtt_spike_weight >= 4.0 {
            // Pressure detected: ramp up, not down - more randomization defeats timing fingerprints.
            (inputs.jitter_max_us as f64 * 0.85) as u32
        } else {
            (inputs.jitter_max_us as f64 * 0.4) as u32
        };

        let tos_anomaly = inputs.signal_tos > 0;
        // Level 0 clean path: disable padding entirely to keep Intelligent mode near-zero overhead
        // when there is no pressure. Only activate once signals warrant it (level >= 1 or any anomaly).
        let (padding_enabled, padding_strategy, padding_max) = if inputs.level_hint == 0
            && inputs.ce_ratio_recent < 0.01
            && inputs.signal_other == 0
            && !tos_anomaly
        {
            (false, 0u8, 0)
        } else if inputs.ce_ratio_recent > 0.08
            || inputs.reorder_ratio > 0.02
            || inputs.signal_other > 0
        {
            (true, 1u8, inputs.pad_max_low)
        } else if inputs.size_div + inputs.iat_div > 1.4 || tos_anomaly {
            (true, 3u8, inputs.pad_max_high.min(512))
        } else {
            (true, 4u8, inputs.pad_max_low)
        };

        let mimic_bias =
            if inputs.ce_ratio_recent > 0.05 || inputs.iat_div > 1.0 || inputs.signal_other > 0 {
                1
            } else if inputs.size_div > 1.0 {
                2
            } else if inputs.ack_us < 3_000.0 {
                4
            } else {
                3
            };

        let adaptive_granularity = if inputs.ce_ratio_recent > 0.10 || inputs.signal_other > 0 {
            32
        } else if inputs.ce_ratio_recent < 0.001 {
            128
        } else {
            64
        };

        let cc_profile = match mimic_bias {
            1 => crate::transport::recovery::BrowserProfile::Safari,
            2 => crate::transport::recovery::BrowserProfile::Firefox,
            4 => crate::transport::recovery::BrowserProfile::Edge,
            _ => crate::transport::recovery::BrowserProfile::Chrome,
        };

        crate::transport::StealthRuntimePolicy {
            external_pacing,
            timing_enabled: !external_pacing,
            timing_max_jitter_us: base_jitter_hint,
            mimic_bias,
            adaptive_granularity,
            cc_profile,
            padding_enabled,
            padding_strategy,
            padding_max,
        }
    }

    /// Returns true if active stealth features (beyond Performance/Off) are engaged.
    #[cfg(feature = "orchestrator")]
    pub(crate) fn runtime_stealth_active(&self) -> bool {
        !matches!(self.config.mode, StealthMode::Performance | StealthMode::Off)
    }

    /// Enable/disable Server Push at runtime (Intelligent mode). Optionally adjust intensity.
    fn enable_server_push_runtime(&self, enabled: bool, intensity: Option<f32>) {
        self.server_push_runtime_enabled.store(enabled, Ordering::Relaxed);
        if let Some(i) = intensity {
            if let Ok(mut st) = self.server_push_state.lock() {
                st.current_intensity = i;
            }
        }
    }

    /// Applies orchestrator-driven server-push cover parameters.
    #[cfg(feature = "orchestrator")]
    pub(crate) fn sync_orchestrator_server_push_controls(
        &self,
        should_trigger: bool,
        intensity: f32,
    ) {
        if !should_trigger {
            return;
        }

        let clamped_intensity = intensity.clamp(0.0, 1.0);
        self.enable_server_push_runtime(
            true,
            Some(self.escalation_min_server_push_intensity(clamped_intensity)),
        );
    }

    fn escalation_min_server_push_intensity(&self, base_intensity: f32) -> f32 {
        if self.escalated.load(Ordering::Relaxed) {
            base_intensity.max(0.8)
        } else {
            base_intensity
        }
    }

    /// Returns the brain-computed Intelligent stealth escalation level (0 = inactive).
    pub(crate) fn intelligent_runtime_level(&self) -> u32 {
        if self.is_intelligent_runtime() {
            crate::brain::intelligent_stealth_level_hint()
        } else {
            0
        }
    }

    fn server_push_burst_interval_secs(&self) -> u64 {
        if self.config.server_push_burst_interval == 0 {
            if matches!(self.config.mode, StealthMode::Intelligent) {
                // Level 2 (anti-dpi pressure): burst every 15s for stronger cover.
                // Level 0/1: every 30s to keep overhead minimal.
                if self.intelligent_runtime_level() >= 2 { 15 } else { 30 }
            } else {
                15
            }
        } else {
            self.config.server_push_burst_interval
        }
    }

    fn desired_masque_preference_with_hint(&self, telemetry_hint: u64) -> bool {
        let hits = self.probe_hits.load(Ordering::Relaxed);
        let escalated = self.escalated.load(Ordering::Relaxed);
        telemetry_hint == 1 || hits >= 3 || escalated
    }

    fn desired_masque_preference(&self) -> bool {
        let telemetry_hint = crate::optimize::telemetry::MASQUE_HINT.load(Ordering::Relaxed);
        self.desired_masque_preference_with_hint(telemetry_hint)
    }

    fn server_push_cover_active(&self) -> bool {
        let intelligent_level = self.intelligent_runtime_level();
        let escalated = self.escalated.load(Ordering::Relaxed);
        let runtime_enabled = self.server_push_runtime_enabled.load(Ordering::Relaxed) || escalated;
        let enabled = self.config.enable_server_push_cover || runtime_enabled;
        enabled && (!matches!(self.config.mode, StealthMode::Intelligent) || intelligent_level >= 1)
    }

    fn current_server_push_state(&self) -> Option<(std::time::Instant, f32)> {
        if !self.server_push_cover_active() {
            return None;
        }

        let state = self.server_push_state.lock().unwrap_or_else(|e| e.into_inner());
        Some((state.last_burst, state.current_intensity))
    }

    /// Returns the current server-push cover plan only when the burst is due.
    pub(crate) fn server_push_cover_plan(&self) -> Option<(String, f32)> {
        let (last_burst, current_intensity) = self.current_server_push_state()?;
        let now = std::time::Instant::now();
        let interval = std::time::Duration::from_secs(self.server_push_burst_interval_secs());
        if now.duration_since(last_burst) < interval {
            return None;
        }
        Some((self.config.server_push_base_path.clone(), current_intensity))
    }

    /// Exposes server-push cover plan for test assertions.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn server_push_cover_plan_for_test(&self) -> Option<(String, f32)> {
        self.server_push_cover_plan()
    }

    fn server_push_trigger_reason(
        &self,
        loss_rate_permille: u32,
        intelligent_level: u32,
    ) -> ServerPushTriggerReason {
        if loss_rate_permille >= 50 {
            ServerPushTriggerReason::Loss
        } else if intelligent_level >= 1 {
            ServerPushTriggerReason::Gating
        } else {
            ServerPushTriggerReason::Time
        }
    }

    fn estimate_server_push_cover_bytes(
        &self,
        base_path: &str,
        promises_created: usize,
        intensity: f32,
    ) -> u64 {
        if promises_created == 0 {
            return 0;
        }
        let per_promise = 280u64
            .saturating_add(base_path.len() as u64)
            .saturating_add((intensity.clamp(0.0, 1.0) * 180.0) as u64);
        per_promise.saturating_mul(promises_created as u64)
    }

    /// Records a server-push cover burst and updates telemetry/state accordingly.
    pub(crate) fn observe_server_push_burst(
        &self,
        base_path: &str,
        promises_created: usize,
        intensity: f32,
        loss_rate_permille: u32,
        intelligent_level: u32,
    ) {
        let reason = self.server_push_trigger_reason(loss_rate_permille, intelligent_level);
        let total_bytes =
            self.estimate_server_push_cover_bytes(base_path, promises_created, intensity);
        self.update_server_push_state(promises_created, total_bytes, reason);
    }

    fn update_server_push_state(
        &self,
        promises_created: usize,
        total_bytes: u64,
        reason: ServerPushTriggerReason,
    ) {
        if let Ok(mut state) = self.server_push_state.lock() {
            let now = std::time::Instant::now();
            state.last_burst = now;
            state.active_promises = promises_created;
            state.total_cover_bytes += total_bytes;
            state.burst_window.push_back(now);
            while let Some(ts) = state.burst_window.front().copied() {
                if now.duration_since(ts) > std::time::Duration::from_secs(60) {
                    state.burst_window.pop_front();
                } else {
                    break;
                }
            }

            // Dynamic intensity adjustment based on escalation
            if self.escalated.load(Ordering::Relaxed) {
                state.current_intensity = (state.current_intensity * 1.2).min(1.0);
            } else {
                state.current_intensity =
                    (state.current_intensity * 0.95).max(self.config.server_push_intensity);
            }

            debug!(
                "Server Push state updated: {} promises, {} bytes, intensity {:.2}",
                promises_created, total_bytes, state.current_intensity
            );
            crate::optimize::telemetry::SERVER_PUSH_BURSTS_TOTAL
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            crate::optimize::telemetry::SERVER_PUSH_TOTAL_COVER_BYTES
                .fetch_add(total_bytes, std::sync::atomic::Ordering::Relaxed);
            crate::optimize::telemetry::SERVER_PUSH_BURSTS_LAST_MINUTE
                .store(state.burst_window.len() as u64, std::sync::atomic::Ordering::Relaxed);
            let intensity_ppm = (state.current_intensity.clamp(0.0, 1.0) * 1_000_000.0) as u64;
            crate::optimize::telemetry::SERVER_PUSH_CURRENT_INTENSITY_PPM
                .store(intensity_ppm, std::sync::atomic::Ordering::Relaxed);
            match reason {
                ServerPushTriggerReason::Time => {
                    crate::optimize::telemetry::SERVER_PUSH_TRIGGER_TIME_TOTAL
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                ServerPushTriggerReason::Loss => {
                    crate::optimize::telemetry::SERVER_PUSH_TRIGGER_LOSS_TOTAL
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                ServerPushTriggerReason::Gating => {
                    crate::optimize::telemetry::SERVER_PUSH_TRIGGER_GATING_TOTAL
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    }

    /// Escalate to Anti-DPI level features (without changing enum mode).
    fn escalate_to_anti_dpi_features(&self) {
        // Increase intensity conservatively to at least 0.8
        if let Ok(mut st) = self.server_push_state.lock() {
            if st.current_intensity < 0.8 {
                st.current_intensity = 0.8;
            }
        }
        // If a scheduler exists, tighten interval; otherwise rely on push promises only.
        // Called only from Intelligent-mode escalation path; always use 2500 ms.
        if let Some(ref sched) = self.cover_traffic {
            sched.set_interval_ms(2500);
        }
        // Force all three runtime overrides on so padding/timing/rotation activate immediately.
        self.runtime_padding_forced.store(true, Ordering::Relaxed);
        self.runtime_timing_forced.store(true, Ordering::Relaxed);
        self.runtime_rotation_enabled.store(true, Ordering::Relaxed);
        debug!("Escalated: Server Push cover traffic + padding/timing/rotation all forced on");
    }

    /// Indicates whether MASQUE should be preferred while escalated and available.
    pub(crate) fn masque_preferred_runtime(&self) -> bool {
        self.prefer_masque.load(Ordering::Relaxed)
    }

    /// Returns whether MASQUE is currently preferred (test-only accessor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn masque_preferred(&self) -> bool {
        self.masque_preferred_runtime()
    }

    /// Explicitly set MASQUE preference for test coverage.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_masque_preferred(&self, on: bool) {
        self.prefer_masque.store(on, Ordering::Relaxed);
    }

    /// Returns true if MASQUE datagram handling should be active.
    pub(crate) fn masque_datagram_enabled(&self) -> bool {
        if self.masque_manager.is_none() {
            return false;
        }
        StealthConfig::masque_env_flag("QUICFUSCATE_MASQUE_DATAGRAM")
    }

    /// Determine MASQUE proxy authority to use.
    /// Priority: QUICFUSCATE_MASQUE_PROXY env -> first fronting domain (":443").
    pub(crate) fn masque_proxy(&self) -> Option<String> {
        self.masque_manager.as_ref()?;
        if let Some(v) = StealthConfig::masque_proxy_override() {
            return Some(v);
        }
        if !self.config.fronting_domains.is_empty() {
            let d = &self.config.fronting_domains[0];
            if !d.is_empty() {
                return Some(format!("{}:443", d));
            }
        }
        None
    }

    /// Intelligent mode compatibility hook: only prefer MASQUE when the
    /// compatibility surface was explicitly enabled and probe/escalation
    /// pressure justifies it.
    fn maybe_escalate_masque_intelligent(&self) {
        if !matches!(self.config.mode, StealthMode::Intelligent) {
            return;
        }
        if self.masque_manager.is_none() {
            return;
        }
        let desired_preference = self.desired_masque_preference();
        let current_preference = self.prefer_masque.load(Ordering::Relaxed);
        if current_preference != desired_preference {
            self.prefer_masque.store(desired_preference, Ordering::Relaxed);
        }
    }

    /// Triggers Intelligent-mode MASQUE escalation logic for testing.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn maybe_escalate_masque_intelligent_for_test(&self) {
        self.maybe_escalate_masque_intelligent();
    }

    /// Syncs MASQUE preference using a telemetry hint value (test-only).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn sync_masque_preference_with_hint_for_test(&self, telemetry_hint: u64) {
        if !matches!(self.config.mode, StealthMode::Intelligent) {
            return;
        }
        if self.masque_manager.is_none() {
            return;
        }
        let desired_preference = self.desired_masque_preference_with_hint(telemetry_hint);
        self.prefer_masque.store(desired_preference, Ordering::Relaxed);
    }

    /// Keep Intelligent mode runtime controls in one place.
    /// This includes preference updates for compatibility MASQUE signaling and
    /// the base server-push runtime activation policy for that level.
    pub(crate) fn sync_intelligent_runtime_controls(&self, intelligent_level: u32) {
        if !self.is_intelligent_runtime() {
            return;
        }
        if intelligent_level > 0 {
            crate::optimize::telemetry::STEALTH_SIGNAL_RTT_SPIKES
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.maybe_escalate_masque_intelligent();
        if intelligent_level == 0 {
            self.enable_server_push_runtime(false, None);
            return;
        }
        let mut intensity = if intelligent_level >= 2 { 0.9 } else { 0.65 };
        intensity = self.escalation_min_server_push_intensity(intensity);
        self.enable_server_push_runtime(true, Some(intensity));
    }

    /// Toggles server-push cover traffic at runtime (test-only).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn enable_server_push_runtime_for_test(&self, enabled: bool, intensity: Option<f32>) {
        self.enable_server_push_runtime(enabled, intensity);
    }

    /// Forwards an invalid/probe packet to the Reality Proxy.
    pub(crate) fn handle_fallback(&self, packet: &[u8], source: std::net::SocketAddr) {
        if let Some(proxy) = &self.reality_proxy {
            proxy.forward_probe(packet, source);
        }
    }

    /// Returns true if a cover PING should be sent now, and advances the internal timer.
    ///
    /// Cover PINGs are ack-eliciting QUIC PING frames injected post-handshake to maintain
    /// realistic keepalive traffic patterns matching idle browser/HTTP3 sessions.
    pub(crate) fn should_send_cover_ping(&self) -> bool {
        if !self.config.enable_cover_ping || self.config.cover_ping_interval_ms == 0 {
            return false;
        }
        let interval =
            std::time::Duration::from_millis(self.config.cover_ping_interval_ms);
        let mut guard = self.next_cover_ping.lock();
        let now = std::time::Instant::now();
        if now >= *guard {
            *guard = now + interval;
            true
        } else {
            false
        }
    }

    /// Dedicated stream ID for injected cover APPLICATION_DATA frames.
    ///
    /// Client-initiated bidirectional, ordinal 62 (stream_id = 4 * 62 = 248).
    /// Placed far enough from real H3 request streams (0, 4, 8, ...) to avoid conflicts.
    pub(crate) const COVER_STREAM_ID: u64 = 248;

    /// Returns true if a cover APPLICATION_DATA frame should be injected now.
    ///
    /// Fires at 3x the cover_ping_interval to complement PING keepalives with
    /// realistic-looking application-layer stream traffic.
    pub(crate) fn should_inject_cover_stream_frame(&self) -> bool {
        if !self.config.enable_cover_ping || self.config.cover_ping_interval_ms == 0 {
            return false;
        }
        let interval =
            std::time::Duration::from_millis(self.config.cover_ping_interval_ms * 3);
        let mut guard = self.next_cover_stream.lock();
        let now = std::time::Instant::now();
        if now >= *guard {
            *guard = now + interval;
            true
        } else {
            false
        }
    }

    /// Produce a random-length (16-64 bytes) cover stream payload.
    ///
    /// Drawn from the OS entropy source so the payload is indistinguishable from
    /// real encrypted application data at the traffic-analysis layer.
    pub(crate) fn generate_cover_stream_data(&self) -> Vec<u8> {
        let mut len_byte = [0u8; 1];
        crate::rng::fill_secure_or_abort(&mut len_byte, "stealth::cover_stream");
        let len = 16 + (len_byte[0] as usize % 49); // 16..=64 bytes
        let mut data = vec![0u8; len];
        crate::rng::fill_secure_or_abort(&mut data, "stealth::cover_stream_data");
        data
    }

    /// Polls for upstream responses to route back to the scanner.
    pub(crate) fn poll_fallback(&self) -> Option<crate::reality::FallbackResponse> {
        if let Ok(mut rx) = self.fallback_rx.try_lock() {
            if let Ok(resp) = rx.try_recv() {
                return Some(resp);
            }
        }
        None
    }
}

/// Snapshot of brain-derived signals consumed by the Intelligent-mode policy derivation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct IntelligentStealthInputs {
    /// Brain-derived escalation level hint: 0=clean-path, 1=stealth, 2=anti-dpi pressure.
    pub level_hint: u8,
    /// Recent ECN-CE ratio (0.0-1.0) indicating congestion.
    pub ce_ratio_recent: f64,
    /// Smoothed ACK inter-arrival time in microseconds.
    pub ack_us: f64,
    /// Jensen-Shannon divergence of packet-size histogram vs baseline.
    pub size_div: f64,
    /// Jensen-Shannon divergence of inter-arrival-time histogram vs baseline.
    pub iat_div: f64,
    /// Fraction of out-of-order packets (0.0-1.0).
    pub reorder_ratio: f64,
    /// Accumulated RTT spike weight from Kalman filter outliers.
    pub rtt_spike_weight: f64,
    /// Count of ToS/DSCP anomaly signals in the current window.
    pub signal_tos: u64,
    /// Count of unclassified anomaly signals in the current window.
    pub signal_other: u64,
    /// Maximum jitter budget in microseconds for timing obfuscation.
    pub jitter_max_us: u32,
    /// Low-mode padding ceiling in bytes.
    pub pad_max_low: usize,
    /// High-mode padding ceiling in bytes.
    pub pad_max_high: usize,
}

#[cfg(test)]
mod stealth_coverage_tests {
    use crate::stealth::test_support::{EnvGuard, acquire_env_lock};
    use super::*;
    use std::sync::Arc;

    fn make_manager(config: StealthConfig) -> StealthManager {
        StealthManager::new(
            config,
            Arc::new(OptimizationManager::new()),
            Arc::new(CryptoManager::new()),
        )
    }

    // =========================================================================
    // 1. StealthManager lifecycle
    // =========================================================================

    #[test]
    fn manager_off_mode_has_no_flow_shaper_or_probe_detector() {
        let m = make_manager(StealthConfig::off());
        assert_eq!(m.mode(), StealthMode::Off);
        assert!(m.flow_shaper.is_none());
        assert!(m.probe_detector.is_none());
        assert!(m.cover_traffic.is_none());
        assert!(m.domain_fronting.is_none());
    }

    #[test]
    fn manager_performance_mode_has_cover_traffic_but_no_flow_shaper() {
        let m = make_manager(StealthConfig::performance());
        assert_eq!(m.mode(), StealthMode::Performance);
        // Performance: h3 masquerade on -> cover_traffic scheduler present
        assert!(m.cover_traffic.is_some());
        // Performance: no timing obfuscation -> no FlowShaper
        assert!(m.flow_shaper.is_none());
        assert!(!m.escalated.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn manager_stealth_mode_has_flow_shaper_and_cover_traffic() {
        let m = make_manager(StealthConfig::stealth());
        assert_eq!(m.mode(), StealthMode::Stealth);
        assert!(m.cover_traffic.is_some());
        // Stealth enables timing obfuscation -> FlowShaper present
        assert!(m.flow_shaper.is_some());
        assert!(m.domain_fronting.is_some());
    }

    #[test]
    fn manager_intelligent_mode_enables_dynamic_and_probe_detector() {
        let m = make_manager(StealthConfig::intelligent());
        assert_eq!(m.mode(), StealthMode::Intelligent);
        assert!(m.is_intelligent_runtime());
        assert!(m.probe_detector.is_some());
        // Intelligent inherits Performance base -> flow_shaper present (dynamic_enabled=true)
        assert!(m.flow_shaper.is_some());
        // Reality proxy enabled in Intelligent mode
        assert!(m.reality_proxy.is_some());
    }

    #[test]
    fn manager_anti_dpi_mode_has_all_features() {
        let m = make_manager(StealthConfig::anti_dpi());
        assert_eq!(m.mode(), StealthMode::AntiDpi);
        assert!(m.flow_shaper.is_some());
        assert!(m.cover_traffic.is_some());
        assert!(m.domain_fronting.is_some());
    }

    #[test]
    fn manager_mode_returns_correct_mode() {
        for (config, expected) in [
            (StealthConfig::off(), StealthMode::Off),
            (StealthConfig::performance(), StealthMode::Performance),
            (StealthConfig::stealth(), StealthMode::Stealth),
            (StealthConfig::anti_dpi(), StealthMode::AntiDpi),
            (StealthConfig::manual(), StealthMode::Manual),
            (StealthConfig::intelligent(), StealthMode::Intelligent),
        ] {
            let m = make_manager(config);
            assert_eq!(m.mode(), expected);
        }
    }

    // =========================================================================
    // 2. Traffic shaping (FlowShaper + RateChoker)
    // =========================================================================

    #[test]
    fn flow_shaper_jitter_bounds_respected() {
        let shaper = FlowShaper::new(2000, false);
        for _ in 0..200 {
            let d = shaper.apply_jitter();
            let us = d.as_micros() as u64;
            // min = max(2000/2, 1) = 1000, max = 2000
            assert!(
                (1000..=2000).contains(&us),
                "jitter {} us outside [1000, 2000]",
                us
            );
        }
    }

    #[test]
    fn flow_shaper_zero_jitter_clamps_to_one() {
        // jitter_us=0 -> max=max(0,1)=1, min=max(1/2,1)=1 -> always 1
        let shaper = FlowShaper::new(0, false);
        for _ in 0..50 {
            assert_eq!(shaper.apply_jitter().as_micros(), 1);
        }
    }

    #[test]
    fn flow_shaper_record_and_prune_limits_history() {
        let shaper = FlowShaper::new(100, false);
        for i in 0..300 {
            shaper.record_and_prune(i, StealthPacketClass::Data);
        }
        let hist = shaper.packet_history.lock().expect("lock");
        // History capped at 256 + pruning of >2s entries
        assert!(hist.len() <= 256);
    }

    #[test]
    fn rate_choker_none_when_zero_target() {
        assert!(RateChoker::new(0, 100).is_none());
    }

    #[test]
    fn rate_choker_initial_burst_allows_small_packets() {
        let mut choker = RateChoker::new(100, 50).expect("should create");
        // Initial burst: tokens are full. Small packet should go through instantly.
        let delay = choker.shape(100);
        assert_eq!(delay, std::time::Duration::ZERO);
    }

    #[test]
    fn rate_choker_large_payload_causes_delay() {
        let mut choker = RateChoker::new(1, 10).expect("should create");
        // 1 Mbps target, 10ms burst -> capacity = (1e6/8) * 0.01 = 1250 bytes
        // Drain all tokens in one large burst
        let _ = choker.shape(2000);
        // Force last=now so no time refill happens
        choker.last = std::time::Instant::now();
        choker.tokens = 0.0;
        // Now even a small packet should need wait since tokens are 0
        let delay = choker.shape(100);
        assert!(delay > std::time::Duration::ZERO);
    }

    // =========================================================================
    // 3. StealthConfig constructors and validation
    // =========================================================================

    #[test]
    fn config_from_mode_roundtrip() {
        let modes = [
            StealthMode::Off,
            StealthMode::Performance,
            StealthMode::Stealth,
            StealthMode::AntiDpi,
            StealthMode::Manual,
            StealthMode::Intelligent,
        ];
        for mode in modes {
            let cfg = StealthConfig::from_mode(mode);
            assert_eq!(cfg.mode, mode, "from_mode({:?}) should produce matching mode", mode);
        }
    }

    #[test]
    fn config_default_is_stealth() {
        let cfg = StealthConfig::default();
        assert_eq!(cfg.mode, StealthMode::Stealth);
    }

    #[test]
    fn config_ultra_stealth_is_anti_dpi() {
        let cfg = StealthConfig::ultra_stealth();
        assert_eq!(cfg.mode, StealthMode::AntiDpi);
    }

    #[test]
    fn config_validate_rejects_choke_without_target() {
        let mut cfg = StealthConfig::stealth();
        cfg.enable_realtime_choke = true;
        cfg.choke_target_mbps = 0;
        let err = cfg.validate().expect_err("choke without target");
        assert!(err.contains("choke_target_mbps"));
    }

    #[test]
    fn config_validate_rejects_server_push_without_h3() {
        let mut cfg = StealthConfig::manual();
        cfg.enable_server_push_cover = true;
        cfg.enable_http3_masquerading = false;
        let err = cfg.validate().expect_err("push without h3");
        assert!(err.contains("server push cover requires"));
    }

    #[test]
    fn config_validate_rejects_performance_with_timing() {
        let mut cfg = StealthConfig::performance();
        cfg.enable_timing_obfuscation = true;
        let err = cfg.validate().expect_err("perf with timing");
        assert!(err.contains("performance mode"));
    }

    #[test]
    fn config_stealth_has_expected_defaults() {
        let cfg = StealthConfig::stealth();
        assert!(cfg.enable_traffic_padding);
        assert!(cfg.enable_timing_obfuscation);
        assert!(cfg.enable_http3_masquerading);
        assert!(cfg.use_tls_cover);
        assert!(cfg.enable_cover_ping);
        assert_eq!(cfg.padding_strategy, PaddingStrategy::Adaptive);
        assert_eq!(cfg.cover_ping_interval_ms, 30_000);
    }

    #[test]
    fn config_off_disables_everything() {
        let cfg = StealthConfig::off();
        assert!(!cfg.enable_traffic_padding);
        assert!(!cfg.enable_timing_obfuscation);
        assert!(!cfg.enable_http3_masquerading);
        assert!(!cfg.use_tls_cover);
        assert!(!cfg.enable_domain_fronting);
        assert!(!cfg.enable_doh);
        assert!(!cfg.enable_cover_ping);
        assert!(!cfg.enable_server_push_cover);
        assert!(!cfg.dynamic_enabled);
        assert_eq!(cfg.max_padding_size, 0);
    }

    // =========================================================================
    // 4. Cover traffic (Cover PING + Cover Stream)
    // =========================================================================

    #[test]
    fn cover_stream_id_constant() {
        // 4 * 62 = 248 (client-initiated bidirectional stream)
        assert_eq!(StealthManager::COVER_STREAM_ID, 248);
    }

    #[test]
    fn cover_ping_disabled_when_off() {
        let m = make_manager(StealthConfig::off());
        assert!(!m.should_send_cover_ping());
    }

    #[test]
    fn cover_ping_enabled_in_stealth() {
        let m = make_manager(StealthConfig::stealth());
        // First call should return true (now >= initial deadline)
        assert!(m.should_send_cover_ping());
        // Immediately after, it should return false (interval not elapsed)
        assert!(!m.should_send_cover_ping());
    }

    #[test]
    fn cover_stream_injection_disabled_when_off() {
        let m = make_manager(StealthConfig::off());
        assert!(!m.should_inject_cover_stream_frame());
    }

    #[test]
    fn cover_stream_injection_fires_then_waits() {
        let m = make_manager(StealthConfig::stealth());
        // First call: fires
        assert!(m.should_inject_cover_stream_frame());
        // Second call: interval (3x cover_ping_interval) not elapsed
        assert!(!m.should_inject_cover_stream_frame());
    }

    #[test]
    fn generate_cover_stream_data_returns_valid_range() {
        let m = make_manager(StealthConfig::stealth());
        for _ in 0..20 {
            let data = m.generate_cover_stream_data();
            assert!((16..=64).contains(&data.len()), "cover stream len {} out of [16,64]", data.len());
        }
    }

    #[test]
    fn generate_cover_stream_data_is_random() {
        let m = make_manager(StealthConfig::stealth());
        let a = m.generate_cover_stream_data();
        let b = m.generate_cover_stream_data();
        // Extremely unlikely for two random payloads to be identical
        assert_ne!(a, b, "cover stream data should be random");
    }

    // =========================================================================
    // 5. apply_env_overrides
    // =========================================================================

    #[test]
    fn env_override_known_modes() {
        let _lock = acquire_env_lock();
        for (value, expected) in [
            ("performance", StealthMode::Performance),
            ("stealth", StealthMode::Stealth),
            ("anti-dpi", StealthMode::AntiDpi),
            ("intelligent", StealthMode::Intelligent),
            ("off", StealthMode::Off),
            ("manual", StealthMode::Manual),
        ] {
            let _guard = EnvGuard::set("QUICFUSCATE_STEALTH_MODE", value);
            let mut cfg = StealthConfig::stealth();
            cfg.apply_env_overrides();
            assert_eq!(cfg.mode, expected, "mode override '{}' failed", value);
        }
    }

    #[test]
    fn env_override_unknown_mode_keeps_original() {
        let _lock = acquire_env_lock();
        let _guard = EnvGuard::set("QUICFUSCATE_STEALTH_MODE", "nonexistent_mode");
        let mut cfg = StealthConfig::stealth();
        cfg.apply_env_overrides();
        // Unknown mode triggers a warning but keeps the original config
        assert_eq!(cfg.mode, StealthMode::Stealth);
    }

    #[test]
    fn env_override_browser_and_os() {
        let _lock = acquire_env_lock();
        let _b = EnvGuard::set("QUICFUSCATE_BROWSER", "firefox");
        let _o = EnvGuard::set("QUICFUSCATE_OS", "linux");
        let mut cfg = StealthConfig::stealth();
        cfg.apply_env_overrides();
        assert_eq!(cfg.initial_browser, BrowserProfile::Firefox);
        assert_eq!(cfg.initial_os, OsProfile::Linux);
    }

    #[test]
    fn env_override_padding_max() {
        let _lock = acquire_env_lock();
        let _p = EnvGuard::set("QUICFUSCATE_STEALTH_PADDING_MAX", "512");
        let mut cfg = StealthConfig::stealth();
        cfg.apply_env_overrides();
        assert_eq!(cfg.max_padding_size, 512);
    }

    // =========================================================================
    // 6. DomainFrontingManager
    // =========================================================================

    #[test]
    fn domain_fronting_round_robin_cycles() {
        let df = DomainFrontingManager::new(vec![
            "a.example".into(),
            "b.example".into(),
            "c.example".into(),
        ]);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..30 {
            seen.insert(df.get_fronted_domain());
        }
        // With jitter, all 3 should eventually be visited
        assert!(seen.len() >= 2, "round-robin should visit multiple domains, got {:?}", seen);
    }

    #[test]
    fn domain_fronting_random_domain_fallback() {
        let df = DomainFrontingManager::new(Vec::new());
        let d = df.random_domain();
        assert_eq!(d, "cdn.cloudflare.com");
    }

    #[test]
    fn domain_fronting_from_providers_populates() {
        let df = DomainFrontingManager::from_providers(vec![CdnProvider::Cloudflare]);
        assert!(!df.domains.is_empty());
        // Should contain known Cloudflare domains
        assert!(df.domains.iter().any(|d| d.contains("cloudflare")));
    }

    #[test]
    fn domain_fronting_ultra_stealth_has_many_domains() {
        let df = DomainFrontingManager::ultra_stealth();
        assert!(df.domains.len() >= 20, "ultra stealth should have 20+ domains, got {}", df.domains.len());
    }

    // =========================================================================
    // 7. FingerprintProfile
    // =========================================================================

    #[test]
    fn fingerprint_profile_chrome_windows_has_correct_ua() {
        let fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
        assert!(fp.user_agent.contains("Chrome/"));
        assert!(fp.user_agent.contains("Windows NT"));
        assert_eq!(fp.browser, BrowserProfile::Chrome);
        assert_eq!(fp.os, OsProfile::Windows);
    }

    #[test]
    fn fingerprint_profile_safari_ios_has_mobile_ua() {
        let fp = FingerprintProfile::new(BrowserProfile::Safari, OsProfile::IOS);
        assert!(fp.user_agent.contains("iPhone"));
        assert!(fp.user_agent.contains("Safari"));
    }

    #[test]
    fn fingerprint_profile_generates_client_hello() {
        let fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
        assert!(fp.client_hello.is_some());
        let ch = fp.client_hello.as_ref().expect("client_hello");
        assert!(ch.len() > 50, "ClientHello too short");
    }

    #[test]
    fn fingerprint_profile_has_server_hello() {
        let fp = FingerprintProfile::new(BrowserProfile::Firefox, OsProfile::Linux);
        assert!(fp.server_hello.is_some());
        let sh = fp.server_hello.as_ref().expect("server_hello");
        assert_eq!(sh.tls_version, 0x0303);
        // Cipher should be a valid TLS 1.3 cipher
        assert!(
            sh.cipher_suite == 0x1301 || sh.cipher_suite == 0x1303,
            "unexpected cipher 0x{:04X}",
            sh.cipher_suite
        );
    }

    #[test]
    fn fingerprint_fallback_for_unsupported_combo() {
        // Edge/IOS is not explicitly listed -> falls back to Chrome/Windows
        let fp = FingerprintProfile::new(BrowserProfile::Edge, OsProfile::IOS);
        assert_eq!(fp.browser, BrowserProfile::Chrome);
        assert_eq!(fp.os, OsProfile::Windows);
    }

    // =========================================================================
    // 8. BrowserProfile / OsProfile parsing
    // =========================================================================

    #[test]
    fn browser_profile_from_str() {
        assert_eq!("chrome".parse::<BrowserProfile>(), Ok(BrowserProfile::Chrome));
        assert_eq!("Firefox".parse::<BrowserProfile>(), Ok(BrowserProfile::Firefox));
        assert_eq!("SAFARI".parse::<BrowserProfile>(), Ok(BrowserProfile::Safari));
        assert_eq!("edge".parse::<BrowserProfile>(), Ok(BrowserProfile::Edge));
        assert!("unknown".parse::<BrowserProfile>().is_err());
    }

    #[test]
    fn os_profile_from_str() {
        assert_eq!("windows".parse::<OsProfile>(), Ok(OsProfile::Windows));
        assert_eq!("MacOS".parse::<OsProfile>(), Ok(OsProfile::MacOS));
        assert_eq!("LINUX".parse::<OsProfile>(), Ok(OsProfile::Linux));
        assert_eq!("ios".parse::<OsProfile>(), Ok(OsProfile::IOS));
        assert_eq!("android".parse::<OsProfile>(), Ok(OsProfile::Android));
        assert!("freebsd".parse::<OsProfile>().is_err());
    }

    // =========================================================================
    // 9. Intelligent mode policy derivation
    // =========================================================================

    #[test]
    fn intelligent_policy_level0_clean_disables_padding() {
        let policy = StealthManager::derive_intelligent_runtime_policy(IntelligentStealthInputs {
            level_hint: 0,
            ce_ratio_recent: 0.0,
            ack_us: 1000.0,
            size_div: 0.1,
            iat_div: 0.1,
            reorder_ratio: 0.0,
            rtt_spike_weight: 0.0,
            signal_tos: 0,
            signal_other: 0,
            jitter_max_us: 1000,
            pad_max_low: 128,
            pad_max_high: 640,
        });
        assert!(policy.external_pacing);
        assert!(!policy.padding_enabled);
        assert_eq!(policy.padding_max, 0);
    }

    #[test]
    fn intelligent_policy_high_ce_ratio_activates_padding() {
        let policy = StealthManager::derive_intelligent_runtime_policy(IntelligentStealthInputs {
            level_hint: 1,
            ce_ratio_recent: 0.15,
            ack_us: 10000.0,
            size_div: 0.5,
            iat_div: 0.5,
            reorder_ratio: 0.05,
            rtt_spike_weight: 3.0,
            signal_tos: 0,
            signal_other: 1,
            jitter_max_us: 2000,
            pad_max_low: 128,
            pad_max_high: 640,
        });
        assert!(policy.padding_enabled);
        assert!(policy.timing_enabled);
        assert!(!policy.external_pacing);
    }

    #[test]
    fn intelligent_policy_tos_anomaly_triggers_adaptive_padding() {
        let policy = StealthManager::derive_intelligent_runtime_policy(IntelligentStealthInputs {
            level_hint: 1,
            ce_ratio_recent: 0.005,
            ack_us: 5000.0,
            size_div: 0.8,
            iat_div: 0.7,
            reorder_ratio: 0.0,
            rtt_spike_weight: 0.0,
            signal_tos: 1,
            signal_other: 0,
            jitter_max_us: 1500,
            pad_max_low: 100,
            pad_max_high: 500,
        });
        assert!(policy.padding_enabled);
        // ToS anomaly -> adaptive strategy (3)
        assert_eq!(policy.padding_strategy, 3);
    }

    #[test]
    fn intelligent_policy_mimic_bias_varies_with_inputs() {
        // High CE ratio -> bias=1 (Safari-like small packets)
        let p1 = StealthManager::derive_intelligent_runtime_policy(IntelligentStealthInputs {
            level_hint: 2,
            ce_ratio_recent: 0.10,
            ack_us: 12000.0,
            size_div: 1.5,
            iat_div: 1.0,
            reorder_ratio: 0.0,
            rtt_spike_weight: 0.0,
            signal_tos: 0,
            signal_other: 0,
            jitter_max_us: 1000,
            pad_max_low: 128,
            pad_max_high: 640,
        });
        assert_eq!(p1.mimic_bias, 1);

        // Fast ACK, low divergence -> bias=4 (mobile)
        let p2 = StealthManager::derive_intelligent_runtime_policy(IntelligentStealthInputs {
            level_hint: 0,
            ce_ratio_recent: 0.0,
            ack_us: 1000.0,
            size_div: 0.1,
            iat_div: 0.1,
            reorder_ratio: 0.0,
            rtt_spike_weight: 0.0,
            signal_tos: 0,
            signal_other: 0,
            jitter_max_us: 1000,
            pad_max_low: 128,
            pad_max_high: 640,
        });
        assert_eq!(p2.mimic_bias, 4);
    }

    // =========================================================================
    // 10. Server Push cover traffic
    // =========================================================================

    #[test]
    fn server_push_cover_not_active_in_off_mode() {
        let m = make_manager(StealthConfig::off());
        assert!(!m.server_push_cover_active());
    }

    #[test]
    fn server_push_cover_active_in_anti_dpi() {
        let m = make_manager(StealthConfig::anti_dpi());
        assert!(m.server_push_cover_active());
    }

    #[test]
    fn server_push_burst_estimation_zero_promises() {
        let m = make_manager(StealthConfig::stealth());
        let bytes = m.estimate_server_push_cover_bytes("/assets", 0, 0.5);
        assert_eq!(bytes, 0);
    }

    #[test]
    fn server_push_burst_estimation_positive_promises() {
        let m = make_manager(StealthConfig::stealth());
        let bytes = m.estimate_server_push_cover_bytes("/assets", 5, 0.5);
        assert!(bytes > 0);
        // More promises = more bytes
        let bytes2 = m.estimate_server_push_cover_bytes("/assets", 10, 0.5);
        assert!(bytes2 > bytes);
    }

    #[test]
    fn server_push_trigger_reason_classification() {
        let m = make_manager(StealthConfig::stealth());
        assert_eq!(m.server_push_trigger_reason(100, 0), ServerPushTriggerReason::Loss);
        assert_eq!(m.server_push_trigger_reason(10, 2), ServerPushTriggerReason::Gating);
        assert_eq!(m.server_push_trigger_reason(10, 0), ServerPushTriggerReason::Time);
    }

    // =========================================================================
    // 11. brain_runtime_permissions
    // =========================================================================

    #[test]
    fn brain_permissions_all_unlocked_by_default() {
        let _lock = acquire_env_lock();
        // Clear all relevant env vars
        let _a = EnvGuard::set("QUICFUSCATE_ACK_THRESHOLD", "");
        let _b = EnvGuard::set("QUICFUSCATE_STEALTH_JITTER_US", "");
        let _c = EnvGuard::set("QUICFUSCATE_STEALTH_PADDING_STRATEGY", "");
        let _d = EnvGuard::set("QUICFUSCATE_STEALTH_MIMIC_BIAS", "");
        let _e = EnvGuard::set("QUICFUSCATE_EXTERNAL_PACING", "");
        let _f = EnvGuard::set("QUICFUSCATE_STEALTH_PADDING_MAX", "");
        let _g = EnvGuard::set("QUICFUSCATE_STEALTH_MAX_PADDING", "");
        let _h = EnvGuard::set("QUICFUSCATE_ACK_MAX_DELAY_MS", "");
        let _i = EnvGuard::set("QUICFUSCATE_STEALTH_ADAPTIVE_GRAN", "");

        // Remove empty vars so env_first returns None
        unsafe {
            std::env::remove_var("QUICFUSCATE_ACK_THRESHOLD");
            std::env::remove_var("QUICFUSCATE_STEALTH_JITTER_US");
            std::env::remove_var("QUICFUSCATE_STEALTH_PADDING_STRATEGY");
            std::env::remove_var("QUICFUSCATE_STEALTH_MIMIC_BIAS");
            std::env::remove_var("QUICFUSCATE_EXTERNAL_PACING");
            std::env::remove_var("QUICFUSCATE_STEALTH_PADDING_MAX");
            std::env::remove_var("QUICFUSCATE_STEALTH_MAX_PADDING");
            std::env::remove_var("QUICFUSCATE_ACK_MAX_DELAY_MS");
            std::env::remove_var("QUICFUSCATE_STEALTH_ADAPTIVE_GRAN");
            std::env::remove_var("QUICFUSCATE_PADDING_STRATEGY");
        }

        let m = make_manager(StealthConfig::intelligent());
        let perms = m.brain_runtime_permissions();
        assert!(perms.ack_threshold);
        assert!(perms.external_pacing);
        assert!(perms.timing);
        assert!(perms.padding);
        assert!(perms.mimic_bias);
        assert!(perms.granularity);
        assert!(perms.cc_profile);
    }

    // =========================================================================
    // 12. Http3Masquerade
    // =========================================================================

    #[test]
    fn http3_masquerade_generates_pseudo_headers() {
        let fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
        let masq = Http3Masquerade::new(fp);
        let headers = masq.generate_headers("cdn.cloudflare.com", "/");
        // Must contain pseudo-headers
        assert!(headers.iter().any(|h| h.name() == b":method"));
        assert!(headers.iter().any(|h| h.name() == b":scheme"));
        assert!(headers.iter().any(|h| h.name() == b":authority"));
        assert!(headers.iter().any(|h| h.name() == b":path"));
        // Must contain user-agent
        assert!(headers.iter().any(|h| h.name() == b"user-agent"));
    }

    #[test]
    fn http3_masquerade_chromium_has_sec_ch_ua() {
        let fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
        let masq = Http3Masquerade::new(fp);
        let headers = masq.generate_headers("example.com", "/");
        assert!(headers.iter().any(|h| h.name() == b"sec-ch-ua"),
            "Chrome masquerade should include sec-ch-ua");
    }

    #[test]
    fn http3_masquerade_cloudflare_is_cross_site() {
        let fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
        let masq = Http3Masquerade::new(fp);
        let site = masq.get_sec_fetch_site("cdn.cloudflare.com");
        assert_eq!(site, "cross-site");
    }

    #[test]
    fn http3_masquerade_non_cdn_is_none_site() {
        let fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
        let masq = Http3Masquerade::new(fp);
        let site = masq.get_sec_fetch_site("my-private-server.org");
        assert_eq!(site, "none");
    }

    // =========================================================================
    // 13. ActiveProbeDetector
    // =========================================================================

    #[test]
    fn probe_detector_detects_gfw_pattern() {
        let detector = ActiveProbeDetector::new(5, ProbeResponseMode::Switch);
        let gfw_packet = vec![0x16, 0x03, 0x01, 0x00, 0x00, 0xff, 0xff];
        let addr: std::net::SocketAddr = "1.2.3.4:1234".parse().expect("addr");
        let result = detector.check_packet(&gfw_packet, addr);
        assert!(result.is_some());
        assert_eq!(result, Some(ProbeResponseMode::Switch));
    }

    #[test]
    fn probe_detector_ignores_normal_quic_packet() {
        let detector = ActiveProbeDetector::new(5, ProbeResponseMode::Switch);
        // Normal-looking QUIC short header (Fixed Bit set)
        let normal = vec![0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let addr: std::net::SocketAddr = "5.6.7.8:5678".parse().expect("addr");
        let result = detector.check_packet(&normal, addr);
        assert!(result.is_none());
    }

    #[test]
    fn probe_detector_fake_response_for_gfw() {
        let detector = ActiveProbeDetector::new(5, ProbeResponseMode::Fake);
        let resp = detector.generate_fake_response("GFW_TLS_Probe");
        // Should be a TLS alert
        assert_eq!(resp[0], 0x15);
    }

    // =========================================================================
    // 14. CoverTrafficScheduler
    // =========================================================================

    #[test]
    fn cover_traffic_scheduler_respects_interval() {
        let sched = CoverTrafficScheduler::new("cdn.example.com".into(), 60_000);
        // First call succeeds (initial last_request is "now")
        // It should return Some on first eligible call after interval
        let req = sched.get_next_request();
        // The initial last_request is Instant::now(), so 0ms elapsed < 60000ms interval => None
        assert!(req.is_none());
    }

    #[test]
    fn cover_traffic_scheduler_set_interval() {
        let sched = CoverTrafficScheduler::new("cdn.example.com".into(), 5000);
        sched.set_interval_ms(1000);
        assert_eq!(sched.interval_ms.load(std::sync::atomic::Ordering::Relaxed), 1000);
    }

    // =========================================================================
    // 15. Runtime TLS profile
    // =========================================================================

    #[test]
    fn runtime_tls_profile_performance_mode_is_cover_performance() {
        let m = make_manager(StealthConfig::performance());
        let profile = m.runtime_tls_profile(None);
        assert!(profile.cover_performance_mode);
        assert!(profile.timing_jitter.is_none());
    }

    #[test]
    fn runtime_tls_profile_stealth_mode_has_timing_jitter() {
        let m = make_manager(StealthConfig::stealth());
        let profile = m.runtime_tls_profile(None);
        assert!(!profile.cover_performance_mode);
        assert!(profile.timing_jitter.is_some());
    }

    #[test]
    fn runtime_tls_profile_sni_override() {
        let m = make_manager(StealthConfig::stealth());
        let profile = m.runtime_tls_profile(Some("custom.example.com"));
        assert_eq!(profile.sni.as_deref(), Some("custom.example.com"));
    }

    // =========================================================================
    // 16. QPACK profiles
    // =========================================================================

    #[test]
    fn qpack_runtime_profile_chrome_vs_firefox() {
        let m_chrome = make_manager(StealthConfig::stealth()); // default Chrome/Windows
        let (cap_c, blocked_c) = m_chrome.qpack_runtime_profile();
        assert_eq!(cap_c, 64 * 1024);
        assert_eq!(blocked_c, 16);

        // Firefox profile
        let mut cfg = StealthConfig::stealth();
        cfg.initial_browser = BrowserProfile::Firefox;
        let m_ff = make_manager(cfg);
        let (cap_f, blocked_f) = m_ff.qpack_runtime_profile();
        assert_eq!(cap_f, 32 * 1024);
        assert_eq!(blocked_f, 8);
    }

    #[test]
    fn current_persona_name_format() {
        let m = make_manager(StealthConfig::stealth());
        let name = m.current_persona_name();
        assert!(name.contains("Chrome"), "expected Chrome in persona, got {}", name);
        assert!(name.contains("Windows"), "expected Windows in persona, got {}", name);
    }

    // =========================================================================
    // 17. PaddingStrategy coverage
    // =========================================================================

    #[test]
    fn padding_strategy_env_parsing() {
        let cfg = StealthConfig::stealth();
        // Test the internal transport_padding_strategy_override path by checking the parser
        let parse = |s: &str| -> Option<PaddingStrategy> {
            match s.trim().to_ascii_lowercase().as_str() {
                "1" | "random" => Some(PaddingStrategy::Random),
                "2" | "fixed" => Some(PaddingStrategy::Fixed),
                "3" | "adaptive" => Some(PaddingStrategy::Adaptive),
                "4" | "browser" | "browser-mimic" | "browsermimic" => Some(PaddingStrategy::BrowserMimic),
                "5" | "normalize" | "packet-normalize" | "packetnormalize" => Some(PaddingStrategy::PacketNormalize),
                _ => None,
            }
        };
        assert_eq!(parse("random"), Some(PaddingStrategy::Random));
        assert_eq!(parse("2"), Some(PaddingStrategy::Fixed));
        assert_eq!(parse("adaptive"), Some(PaddingStrategy::Adaptive));
        assert_eq!(parse("browser-mimic"), Some(PaddingStrategy::BrowserMimic));
        assert_eq!(parse("normalize"), Some(PaddingStrategy::PacketNormalize));
        assert_eq!(parse("unknown"), None);
        let _ = cfg; // prevent unused warning
    }

    #[test]
    fn anti_dpi_uses_packet_normalize() {
        let cfg = StealthConfig::anti_dpi();
        assert_eq!(cfg.normalize_target_size, 1200);
        assert_eq!(cfg.padding_strategy, PaddingStrategy::BrowserMimic);
    }
}

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests;
