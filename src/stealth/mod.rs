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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
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

include!("parts/tls_cover_provider.rs");

/// TLS Cover record generation for DPI evasion (synthetic ClientHello/ServerHello).
pub mod tls_cover;

/// TCP/ICMP fingerprint obfuscation (TODO-462).
pub mod fingerprint;

pub use fingerprint::{
    IcmpUnreachablePolicy, NormalizeOutcome, NormalizeResult, OsFingerprintProfile,
    PacketNormalizer,
};

// Legacy external TLS FFI removed: native TLS fingerprint injection is used exclusively.

include!("parts/doh.rs");
include!("parts/browser_profiles.rs");
include!("parts/http3_masquerade.rs");
include!("parts/domain_fronting.rs");
include!("parts/masque_manager.rs");
include!("parts/cover_traffic.rs");
include!("parts/probe_detector.rs");
include!("parts/flow_shaping.rs");
include!("parts/chaff.rs");
include!("parts/tls_client_hello.rs");
include!("parts/config.rs");
include!("parts/escalation.rs");
include!("parts/runtime.rs");
include!("parts/manager.rs");
include!("parts/stealth_coverage_tests.rs");

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests;
