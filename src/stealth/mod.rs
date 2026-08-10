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
- Deterministic ClientHello metadata must never be presented as a wire override;
  the real handshake remains owned by rustls.
- After edits: run `cargo check` and `cargo doc` to validate.
===============================================================================
*/

// clap dependency removed - using manual enum implementation
use crate::crypto::hkdf::{hkdf_expand, hkdf_extract};
use log::{debug, info, warn};
// use of sha2 replaced with centralized SIMD dispatch
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::crypto::CryptoManager; // Assumed for integration
use crate::optimize::OptimizationManager; // Assumed for integration
use crate::telemetry;
pub(crate) use qf_stealth::TlsCoverCipherPreference;
pub use qf_stealth::{RateChoker, ServerPushState, ServerPushTriggerReason};

// Integrated test module (keeps src layout monolithic; tests live alongside)
// Test module removed - tests are inline

include!("parts/tls_cover_provider.rs");

/// TLS Cover record generation for DPI evasion (synthetic ClientHello/ServerHello).
pub mod tls_cover;

/// TCP/ICMP fingerprint obfuscation (TODO-462).
pub mod fingerprint;

pub use fingerprint::{
    IcmpUnreachablePolicy, NormalizeOutcome, NormalizeResult, OsFingerprintProfile,
    PacketNormalizer,
};

// Legacy external TLS FFI removed: rustls owns the real handshake and the
// deterministic profile catalog is retained only for compatibility/audit work.

include!("parts/browser_profiles.rs");
pub use qf_stealth::{
    FecMode, PaddingStrategy, RotationMode, StealthConfig, StealthMode, TlsCoverCipherSuite,
};
include!("parts/http3_masquerade.rs");
include!("parts/domain_fronting.rs");
include!("parts/cover_traffic.rs");
include!("parts/probe_detector.rs");
include!("parts/flow_shaping.rs");
include!("parts/chaff.rs");
include!("parts/tls_client_hello.rs");
include!("parts/escalation.rs");
include!("parts/runtime.rs");
include!("parts/manager.rs");
include!("parts/stealth_coverage_tests.rs");

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests;
