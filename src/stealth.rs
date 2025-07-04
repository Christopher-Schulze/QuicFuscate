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
//? inspection (DPI) systems. It integrates multiple strategies to create a
//! layered defense against network surveillance.

use crate::telemetry::{DNS_QUERIES, OBFUSCATED_PACKETS};
use lazy_static::lazy_static;
use log::{debug, error, info};
use reqwest::Client;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use url::Url;

use crate::crypto::CryptoManager; // Assumed for integration
use crate::optimize::{self, OptimizationManager}; // Assumed for integration
use std::os::raw::c_void;

// --- Global Tokio Runtime for async DoH requests ---
lazy_static! {
    static ref DOH_RUNTIME: Runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime for DoH");
}

// --- 1. DNS over HTTPS (DoH) ---

/// Asynchronously resolves a domain name to an IP address using DNS-over-HTTPS.
///
/// # Arguments
/// * `domain` - The domain to resolve.
/// * `doh_provider` - The URL of the DoH resolver (e.g., "https://cloudflare-dns.com/dns-query").
///
/// # Returns
/// A `Result` containing the resolved `IpAddr` or a `reqwest::Error`.
pub async fn resolve_doh(
    client: &Client,
    domain: &str,
    doh_provider: &str,
) -> Result<IpAddr, reqwest::Error> {
    DNS_QUERIES.inc();
    let mut url = Url::parse(doh_provider).unwrap();
    url.query_pairs_mut()
        .append_pair("name", domain)
        .append_pair("type", "A");

    let resp = client
        .get(url)
        .header("Accept", "application/dns-json")
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    if let Some(answers) = resp.get("Answer") {
        for answer in answers.as_array().unwrap() {
            if answer["type"] == 1 {
                // A record
                if let Some(ip_str) = answer["data"].as_str() {
                    if let Ok(ip) = ip_str.parse() {
                        return Ok(ip);
                    }
                }
            }
        }
    }
    // Fallback or error
    Ok(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
}

// --- 2. Browser/OS Fingerprinting ---

/// Defines the target browser for fingerprint spoofing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrowserProfile {
    Chrome,
    Firefox,
    Safari,
    Opera,
    Brave,
    Edge,
    Vivaldi,
}

impl std::str::FromStr for BrowserProfile {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "chrome" => Ok(BrowserProfile::Chrome),
            "firefox" => Ok(BrowserProfile::Firefox),
            "safari" => Ok(BrowserProfile::Safari),
            "opera" => Ok(BrowserProfile::Opera),
            "brave" => Ok(BrowserProfile::Brave),
            "edge" => Ok(BrowserProfile::Edge),
            "vivaldi" => Ok(BrowserProfile::Vivaldi),
            _ => Err(()),
        }
    }
}

/// Defines the target operating system for fingerprint spoofing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsProfile {
    Windows,
    MacOS,
    Linux,
    IOS,
    Android,
}

/// Represents a complete client fingerprint profile.
#[derive(Debug, Clone)]
pub struct FingerprintProfile {
    pub browser: BrowserProfile,
    pub os: OsProfile,
    pub user_agent: String,
    pub tls_cipher_suites: Vec<u16>,
    pub accept_language: String,
    // Detailed QUIC transport parameters for deeper fingerprinting
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_streams_bidi: u64,
    pub max_idle_timeout: u64,
}

impl FingerprintProfile {
    /// Creates a new profile for a given browser and OS combination, with harmonized values.
    pub fn new(browser: BrowserProfile, os: OsProfile) -> Self {
        match (browser, os) {
            // --- Windows Profiles ---
            (BrowserProfile::Chrome, OsProfile::Windows) => Self {
                browser, os,
                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
            },
           (BrowserProfile::Firefox, OsProfile::Windows) => Self {
                browser, os,
                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xcca9, 0xcca8, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.5".to_string(),
                initial_max_data: 12_582_912,
                initial_max_stream_data_bidi_local: 1_048_576,
                initial_max_stream_data_bidi_remote: 1_048_576,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 60_000,
            },
           (BrowserProfile::Opera, OsProfile::Windows) => Self {
               browser, os,
               user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0".to_string(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
               accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
           },
           (BrowserProfile::Brave, OsProfile::Windows) => Self {
               browser, os,
               user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Brave/1.67.0".to_string(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
               accept_language: "en-US,en;q=0.9".to_string(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
           },
           (BrowserProfile::Edge, OsProfile::Windows) => Self {
               browser, os,
               user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0".to_string(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
               accept_language: "en-US,en;q=0.9".to_string(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
           },
           (BrowserProfile::Vivaldi, OsProfile::Windows) => Self {
               browser, os,
               user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Vivaldi/6.7.999.31".to_string(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
               accept_language: "en-US,en;q=0.9".to_string(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
           },
            // --- macOS Profiles ---
            (BrowserProfile::Safari, OsProfile::MacOS) => Self {
                browser, os,
                user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc009, 0xc013, 0xc00a, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 15_728_640,
                initial_max_stream_data_bidi_local: 2_097_152,
                initial_max_stream_data_bidi_remote: 2_097_152,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 45_000,
            },
            // --- Fallback Profile ---
            _ => Self::new(BrowserProfile::Chrome, OsProfile::Windows),
        }
    }

    /// Generates a set of realistic HTTP headers based on the profile.
    pub fn generate_http_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), self.user_agent.clone());
        headers.insert(
            "Accept".to_string(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
                .to_string(),
        );
        headers.insert("Accept-Language".to_string(), self.accept_language.clone());
        headers.insert(
            "Accept-Encoding".to_string(),
            "gzip, deflate, br".to_string(),
        );
        headers.insert("Connection".to_string(), "keep-alive".to_string());
        headers
    }
}

// --- 3. HTTP/3 Masquerading ---

/// Manages the generation of fake HTTP/3 headers to masquerade QUIC traffic.
pub struct Http3Masquerade {
    profile: FingerprintProfile,
}

impl Http3Masquerade {
    pub fn new(profile: FingerprintProfile) -> Self {
        Self { profile }
    }

    /// Generates a list of QPACK-style headers for an HTTP/3 request.
    /// This is a simplified representation. A real implementation uses QPACK.
    pub fn generate_headers(&self, host: &str, path: &str) -> Vec<quiche::h3::Header> {
        vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", host.as_bytes()),
            quiche::h3::Header::new(b":path", path.as_bytes()),
            quiche::h3::Header::new(b"user-agent", self.profile.user_agent.as_bytes()),
        ]
    }

    /// Encodes the generated headers using QPACK compression. The resulting
    /// bytes can be fed directly into a HTTP/3 stream.
    pub fn generate_qpack_headers(&self, host: &str, path: &str) -> Vec<u8> {
        let headers = self.generate_headers(host, path);
        let mut encoder = quiche::h3::qpack::Encoder::new();
        let mut out = Vec::new();
        let _ = encoder.encode(&mut out, 0, &headers);
        out
    }
}

// --- 4. Domain Fronting ---

/// Represents a CDN provider that can be used for domain fronting.
#[derive(Debug, Clone, Copy)]
pub enum CdnProvider {
    Cloudflare,
    Google,
    MicrosoftAzure,
    Akamai,
    Fastly,
}

impl CdnProvider {
    fn get_domain(&self) -> &'static str {
        match self {
            CdnProvider::Cloudflare => "www.cloudflare.com",
            CdnProvider::Google => "www.google.com",
            CdnProvider::MicrosoftAzure => "azure.microsoft.com",
            CdnProvider::Akamai => "www.akamai.com",
            CdnProvider::Fastly => "www.fastly.com",
        }
    }
}

/// Manages domain fronting by rotating through CDN providers.
pub struct DomainFrontingManager {
    providers: Vec<CdnProvider>,
    index: AtomicUsize,
}

impl DomainFrontingManager {
    pub fn new(providers: Vec<CdnProvider>) -> Self {
        Self {
            providers,
            index: AtomicUsize::new(0),
        }
    }

    /// Selects the next CDN provider to use for domain fronting.
    pub fn get_fronted_domain(&self) -> &'static str {
        let current = self.index.fetch_add(1, Ordering::SeqCst);
        let idx = current % self.providers.len();
        self.providers[idx].get_domain()
    }
}

// --- 5. XOR-based Traffic Obfuscation ---

/// A simple XOR obfuscator for packet payloads.
pub struct XorObfuscator {
    key: Vec<u8>,
    position: AtomicUsize,
}

impl XorObfuscator {
    /// Creates a new obfuscator, ideally using a key from the CryptoManager.
    pub fn new(crypto_manager: &CryptoManager) -> Self {
        // Generate a session specific key so that each connection uses a
        // different obfuscation key.
        let key = crypto_manager.generate_session_key(32);
        Self {
            key,
            position: AtomicUsize::new(0),
        }
    }

    /// Applies XOR obfuscation to a mutable payload using the best available SIMD implementation.
    pub fn obfuscate(&self, payload: &mut [u8]) {
        if self.key.is_empty() {
            return;
        }

        OBFUSCATED_PACKETS.inc();
        let key = &self.key;
        let key_len = key.len();
        let start = self.position.load(Ordering::Relaxed);

        optimize::dispatch(|policy| {
            let len = payload.len();
            let mut processed = 0;

            // This unsafe block is required for SIMD intrinsics and pointer operations.
            // The logic within is carefully designed to be safe by respecting memory boundaries.
            #[allow(unsafe_code)]
            unsafe {
                match policy {
                    // AVX2/AVX512 path for x86_64
                    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                    optimize::SimdPolicy::Avx2 | optimize::SimdPolicy::Avx512 => {
                        use std::arch::x86_64::*;
                        const CHUNK_SIZE: usize = 32;

                        if len >= CHUNK_SIZE {
                            let payload_ptr = payload.as_mut_ptr();
                            while processed + CHUNK_SIZE <= len {
                                let mut key_pattern = [0u8; CHUNK_SIZE];
                                for i in 0..CHUNK_SIZE {
                                    key_pattern[i] = key[(start + processed + i) % key_len];
                                }
                                let key_vec =
                                    _mm256_loadu_si256(key_pattern.as_ptr() as *const __m256i);

                                let data_ptr = payload_ptr.add(processed);
                                let data_vec = _mm256_loadu_si256(data_ptr as *const __m256i);
                                let xor_result = _mm256_xor_si256(data_vec, key_vec);
                                _mm256_storeu_si256(data_ptr as *mut __m256i, xor_result);
                                processed += CHUNK_SIZE;
                            }
                        }
                    }

                    // NEON path for aarch64
                    #[cfg(target_arch = "aarch64")]
                    optimize::SimdPolicy::Neon => {
                        use std::arch::aarch64::*;
                        const CHUNK_SIZE: usize = 16;

                        if len >= CHUNK_SIZE {
                            // Create a repeating key pattern for a 128-bit register.
                            let payload_ptr = payload.as_mut_ptr();
                            while processed + CHUNK_SIZE <= len {
                                let mut key_pattern = [0u8; CHUNK_SIZE];
                                for i in 0..CHUNK_SIZE {
                                    key_pattern[i] = key[(start + processed + i) % key_len];
                                }
                                let key_vec = vld1q_u8(key_pattern.as_ptr());

                                let data_ptr = payload_ptr.add(processed);
                                let data_vec = vld1q_u8(data_ptr);
                                let xor_result = veorq_u8(data_vec, key_vec);
                                vst1q_u8(data_ptr, xor_result);
                                processed += CHUNK_SIZE;
                            }
                        }
                    }

                    // Scalar fallback for other architectures or when SIMD is disabled.
                    _ => {
                        for (i, byte) in payload.iter_mut().enumerate() {
                            *byte ^= key[(start + i) % key_len];
                        }
                        // The scalar path processes the entire payload, so we can return.
                        return;
                    }
                }
            }

            // Process any remaining bytes that did not fit into a full SIMD chunk.
            if processed < len {
                for i in processed..len {
                    payload[i] ^= key[(start + i) % key_len];
                }
            }
        });
        let new_pos = (start + payload.len()) % key_len;
        self.position.store(new_pos, Ordering::Relaxed);
    }

    /// Reverses XOR obfuscation. The operation is symmetrical.
    pub fn deobfuscate(&self, payload: &mut [u8]) {
        self.obfuscate(payload);
    }
}

// --- 6. TLS Client Hello Spoofing ---

/// Allows manipulation of the TLS ClientHello to mimic real browser behaviour.
pub struct TlsClientHelloSpoofer;

impl TlsClientHelloSpoofer {
    /// Apply the spoofing parameters. In this simplified implementation we only
    /// log the action. A real implementation would interface with quiche's
    /// underlying TLS stack via FFI.
    #[allow(unused_variables)]
    pub fn apply(config: &mut quiche::Config, suites: &[u16]) {
        debug!(
            "uTLS: manipulating ClientHello with {} suites",
            suites.len()
        );
    }
}

// --- 7. Stealth Manager and Configuration ---

/// Configuration for the main StealthManager.
#[derive(Clone)]
pub struct StealthConfig {
    pub browser_profile: BrowserProfile,
    pub os_profile: OsProfile,
    pub enable_doh: bool,
    pub doh_provider: String,
    pub enable_http3_masquerading: bool,
    pub use_qpack_headers: bool,
    pub enable_domain_fronting: bool,
    pub cdn_providers: Vec<CdnProvider>,
    pub enable_xor_obfuscation: bool,
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            browser_profile: BrowserProfile::Chrome,
            os_profile: OsProfile::Windows,
            enable_doh: true,
            doh_provider: "https://cloudflare-dns.com/dns-query".to_string(),
            enable_http3_masquerading: true,
            use_qpack_headers: true,
            enable_domain_fronting: true,
            cdn_providers: vec![
                CdnProvider::Cloudflare,
                CdnProvider::Google,
                CdnProvider::MicrosoftAzure,
                CdnProvider::Akamai,
                CdnProvider::Fastly,
            ],
            enable_xor_obfuscation: true,
        }
    }
}

/// The central orchestrator for all stealth techniques.
pub struct StealthManager {
    config: StealthConfig,
    fingerprint: Mutex<FingerprintProfile>,
    doh_client: Client,
    domain_fronter: Option<DomainFrontingManager>,
    xor_obfuscator: Option<XorObfuscator>,
    // Integration with other modules
    crypto_manager: Arc<CryptoManager>,
    optimization_manager: Arc<OptimizationManager>,
}

impl StealthManager {
    /// Creates a new `StealthManager` with the given configuration.
    pub fn new(
        config: StealthConfig,
        crypto_manager: Arc<CryptoManager>,
        optimization_manager: Arc<OptimizationManager>,
    ) -> Self {
        let fingerprint = FingerprintProfile::new(config.browser_profile, config.os_profile);

        let domain_fronter = if config.enable_domain_fronting {
            Some(DomainFrontingManager::new(config.cdn_providers.clone()))
        } else {
            None
        };

        let xor_obfuscator = if config.enable_xor_obfuscation {
            Some(XorObfuscator::new(&crypto_manager))
        } else {
            None
        };

        Self {
            config,
            fingerprint: Mutex::new(fingerprint),
            doh_client: Client::new(),
            domain_fronter,
            xor_obfuscator,
            crypto_manager,
            optimization_manager,
        }
    }

    /// Applies the configured uTLS profile to a quiche configuration.
    /// This function simulates a real uTLS fingerprint by configuring various
    /// QUIC transport parameters to match the typical behavior of the target browser.
    /// NOTE: For a perfect fingerprint match, patching the underlying TLS stack (e.g., BoringSSL)
    /// to control the Client Hello message format (cipher suite order, extensions, GREASE values)
    /// would be required. This is a simulation based on available quiche settings.
    pub fn apply_utls_profile(&self, config: &mut quiche::Config) {
        let fingerprint = self.fingerprint.lock().unwrap();
        info!(
            "Applying uTLS fingerprint for: {:?}/{:?}",
            fingerprint.browser, fingerprint.os
        );

        // Set cipher suites according to the profile's specified order.
        let quiche_ciphers: Vec<quiche::Cipher> = fingerprint
            .tls_cipher_suites
            .iter()
            .filter_map(|&iana_id| map_iana_to_quiche_cipher(iana_id))
            .collect();

        if !quiche_ciphers.is_empty() {
            if let Err(e) = config.set_ciphers(&quiche_ciphers) {
                error!("Failed to set custom cipher suites: {}", e);
            }
            // Manipulate TLS ClientHello to match the desired ordering.
            let suite_ids: Vec<u16> = fingerprint.tls_cipher_suites.clone();
            TlsClientHelloSpoofer::apply(config, &suite_ids);
        }

        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .unwrap();

        // Apply the detailed QUIC transport parameters from the harmonized profile.
        config.set_initial_max_data(fingerprint.initial_max_data);
        config
            .set_initial_max_stream_data_bidi_local(fingerprint.initial_max_stream_data_bidi_local);
        config.set_initial_max_stream_data_bidi_remote(
            fingerprint.initial_max_stream_data_bidi_remote,
        );
        config.set_initial_max_streams_bidi(fingerprint.initial_max_streams_bidi);
        config.set_max_idle_timeout(fingerprint.max_idle_timeout);
    }

    /// Changes the active fingerprint profile at runtime.
    /// Call `apply_utls_profile` again to update an existing quiche configuration.
    pub fn set_fingerprint_profile(&self, profile: FingerprintProfile) {
        let mut fp = self.fingerprint.lock().unwrap();
        *fp = profile;
    }

    /// Returns the currently active fingerprint profile.
    pub fn current_profile(&self) -> FingerprintProfile {
        self.fingerprint.lock().unwrap().clone()
    }

    /// Resolves a domain, using DoH if enabled.
    pub fn resolve_domain(&self, domain: &str) -> IpAddr {
        if self.config.enable_doh {
            debug!(
                "Resolving {} via DoH provider: {}",
                domain, self.config.doh_provider
            );
            DOH_RUNTIME
                .block_on(resolve_doh(
                    &self.doh_client,
                    domain,
                    &self.config.doh_provider,
                ))
                .unwrap_or_else(|e| {
                    error!("DoH resolution failed: {}. Falling back.", e);
                    // Simple fallback, in a real scenario might try standard DNS.
                    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
                })
        } else {
            // Fallback to standard DNS resolution (conceptual)
            info!("DoH disabled, using standard DNS for {}", domain);
            // In a real app, you would use std::net::ToSocketAddrs here.
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
        }
    }

    /// Returns the SNI and Host header values for a connection.
    /// Applies domain fronting if enabled.
    pub fn get_connection_headers(&self, real_host: &str) -> (String, String) {
        if self.config.enable_domain_fronting && self.domain_fronter.is_some() {
            let fronted_domain = self.domain_fronter.as_ref().unwrap().get_fronted_domain();
            debug!(
                "Domain fronting enabled. SNI: {}, Host: {}",
                fronted_domain, real_host
            );
            (fronted_domain.to_string(), real_host.to_string()) // SNI = front, Host = real
        } else {
            (real_host.to_string(), real_host.to_string()) // SNI = real, Host = real
        }
    }

    /// Processes an outgoing packet payload, applying configured stealth techniques.
    pub fn process_outgoing_packet(&self, payload: &mut [u8]) {
        // The optimization manager could provide an efficient buffer from a pool.
        // let mut buffer = self.optimization_manager.get_buffer(payload.len());
        // buffer.copy_from_slice(payload);
        /// Maps an IANA-defined TLS cipher suite ID to the `quiche::Cipher` enum.
        ///
        /// Note: `quiche` only supports a subset of all possible cipher suites.
        /// This function will ignore any unsupported ciphers.
        fn map_iana_to_quiche_cipher(iana_id: u16) -> Option<quiche::Cipher> {
            match iana_id {
                // TLS 1.3 Cipher Suites
                0x1301 => Some(quiche::Cipher::TLS13_AES_128_GCM_SHA256),
                0x1302 => Some(quiche::Cipher::TLS13_AES_256_GCM_SHA384),
                0x1303 => Some(quiche::Cipher::TLS13_CHACHA20_POLY1305_SHA256),

                // TLS 1.2 Cipher Suites (ECDHE)
                0xc02b => Some(quiche::Cipher::ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
                0xc02f => Some(quiche::Cipher::ECDHE_RSA_WITH_AES_128_GCM_SHA256),
                0xc02c => Some(quiche::Cipher::ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
                0xc030 => Some(quiche::Cipher::ECDHE_RSA_WITH_AES_256_GCM_SHA384),
                0xcca9 => Some(quiche::Cipher::ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
                0xcca8 => Some(quiche::Cipher::ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),

                // Other common but potentially unsupported ciphers - mapped to None
                // 0xc013 => ECDHE_RSA_WITH_AES_128_CBC_SHA
                // 0xc014 => ECDHE_RSA_WITH_AES_256_CBC_SHA
                // 0xc009 => ECDHE_ECDSA_WITH_AES_128_CBC_SHA
                // 0xc00a => ECDHE_ECDSA_WITH_AES_256_CBC_SHA
                _ => None,
            }
        }

        if self.config.enable_xor_obfuscation && self.xor_obfuscator.is_some() {
            debug!("Applying XOR obfuscation to outgoing packet.");
            self.xor_obfuscator.as_ref().unwrap().obfuscate(payload);
        }

        // HTTP/3 Masquerading is applied at the stream level when sending data,
        // not on raw packets here.
    }

    /// Processes an incoming packet payload, reversing stealth techniques.
    pub fn process_incoming_packet(&self, payload: &mut [u8]) {
        if self.config.enable_xor_obfuscation && self.xor_obfuscator.is_some() {
            debug!("Reversing XOR obfuscation on incoming packet.");
            self.xor_obfuscator.as_ref().unwrap().deobfuscate(payload);
        }
    }

    /// Generates HTTP/3 headers for masquerading a request.
    pub fn get_http3_masquerade_headers(&self, host: &str, path: &str) -> Option<Vec<u8>> {
        if self.config.enable_http3_masquerading {
            let masquerade = {
                let fp = self.fingerprint.lock().unwrap();
                Http3Masquerade::new(fp.clone())
            };
            debug!("Generating HTTP/3 masquerade headers for host: {}", host);
            if self.config.use_qpack_headers {
                Some(masquerade.generate_qpack_headers(host, path))
            } else {
                let headers = masquerade.generate_headers(host, path);
                let mut encoder = quiche::h3::qpack::Encoder::new();
                let mut out = Vec::new();
                let _ = encoder.encode(&mut out, 0, &headers);
                Some(out)
            }
        } else {
            None
        }
    }
}
