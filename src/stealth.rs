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

use base64;
use clap::ValueEnum;
use lazy_static::lazy_static;
use log::{debug, error, info};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use url::Url;

use crate::crypto::CryptoManager; // Assumed for integration
use crate::fake_tls::{self, ServerHelloParamsOwned};
use crate::optimize::{self, OptimizationManager}; // Assumed for integration
use crate::telemetry;
use crate::tls_ffi;

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
/// A `Result` containing the resolved `IpAddr` or an error.
pub async fn resolve_doh(
    client: &Client,
    domain: &str,
    doh_provider: &str,
) -> Result<IpAddr, Box<dyn std::error::Error>> {
    let mut url = Url::parse(doh_provider).map_err(|e| {
        error!("Invalid DoH provider URL: {}", e);
        e
    })?;
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

// --- 2. Browser/OS Fingerprinting ---

/// Defines the target browser for fingerprint spoofing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum)]
pub enum OsProfile {
    Windows,
    MacOS,
    Linux,
    IOS,
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
    pub client_hello: Option<Vec<u8>>,
    pub server_hello: Option<ServerHelloParamsOwned>,
    pub certificate: Option<Vec<u8>>,
}

impl FingerprintProfile {
    /// Creates a new profile for a given browser and OS combination, with harmonized values.
    pub fn new(browser: BrowserProfile, os: OsProfile) -> Self {
        let mut profile = match (browser, os) {
            // --- Windows Profiles ---
            (BrowserProfile::Chrome, OsProfile::Windows) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
            },
           (BrowserProfile::Firefox, OsProfile::Windows) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xcca9, 0xcca8, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.5".to_string(),
                initial_max_data: 12_582_912,
                initial_max_stream_data_bidi_local: 1_048_576,
                initial_max_stream_data_bidi_remote: 1_048_576,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 60_000,
                client_hello: None,
            },
           (BrowserProfile::Opera, OsProfile::Windows) => Self {
               browser, os,               user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0".to_string(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
               accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
           },
           (BrowserProfile::Brave, OsProfile::Windows) => Self {
               browser, os,               user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Brave/1.67.0".to_string(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
               accept_language: "en-US,en;q=0.9".to_string(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
           },
           (BrowserProfile::Edge, OsProfile::Windows) => Self {
               browser, os,               user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0".to_string(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
               accept_language: "en-US,en;q=0.9".to_string(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
           },
           (BrowserProfile::Edge, OsProfile::MacOS) => Self {
               browser, os,               user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0".to_string(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
               accept_language: "en-US,en;q=0.9".to_string(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
           },
           (BrowserProfile::Edge, OsProfile::Linux) => Self {
               browser, os,               user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0".to_string(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
               accept_language: "en-US,en;q=0.9".to_string(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
           },
           (BrowserProfile::Vivaldi, OsProfile::Windows) => Self {
               browser, os,               user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Vivaldi/6.7.999.31".to_string(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
               accept_language: "en-US,en;q=0.9".to_string(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
           },
           (BrowserProfile::Vivaldi, OsProfile::MacOS) => Self {
               browser, os,               user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Vivaldi/6.7.999.31".to_string(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
               accept_language: "en-US,en;q=0.9".to_string(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
           },
           (BrowserProfile::Vivaldi, OsProfile::Linux) => Self {
               browser, os,               user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Vivaldi/6.7.999.31".to_string(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
               accept_language: "en-US,en;q=0.9".to_string(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
           },
            // --- macOS Profiles ---
           (BrowserProfile::Safari, OsProfile::MacOS) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc009, 0xc013, 0xc00a, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 15_728_640,
                initial_max_stream_data_bidi_local: 2_097_152,
                initial_max_stream_data_bidi_remote: 2_097_152,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 45_000,
                client_hello: None,
            },
            (BrowserProfile::Chrome, OsProfile::MacOS) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
            },
            (BrowserProfile::Opera, OsProfile::MacOS) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
            },
            (BrowserProfile::Brave, OsProfile::MacOS) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Brave/1.67.0".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
            },
            (BrowserProfile::Firefox, OsProfile::MacOS) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6; rv:127.0) Gecko/20100101 Firefox/127.0".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xcca9, 0xcca8, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.5".to_string(),
                initial_max_data: 12_582_912,
                initial_max_stream_data_bidi_local: 1_048_576,
                initial_max_stream_data_bidi_remote: 1_048_576,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 60_000,
                client_hello: None,
            },
            (BrowserProfile::Chrome, OsProfile::Linux) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
            },
            (BrowserProfile::Opera, OsProfile::Linux) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
            },
            (BrowserProfile::Brave, OsProfile::Linux) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Brave/1.67.0".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
            },
            (BrowserProfile::Firefox, OsProfile::Linux) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xcca9, 0xcca8, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.5".to_string(),
                initial_max_data: 12_582_912,
                initial_max_stream_data_bidi_local: 1_048_576,
                initial_max_stream_data_bidi_remote: 1_048_576,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 60_000,
                client_hello: None,
            },
            (BrowserProfile::Chrome, OsProfile::Android) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
            },
            (BrowserProfile::Firefox, OsProfile::Android) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (Android 14; Mobile; rv:127.0) Gecko/127.0 Firefox/127.0".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xcca9, 0xcca8, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
            },
            (BrowserProfile::Opera, OsProfile::Android) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36 OPR/112.0.0.0".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
            },
            (BrowserProfile::Brave, OsProfile::Android) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36 Brave/1.67.0".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
            },
            (BrowserProfile::Edge, OsProfile::Android) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36 EdgA/126.0.0.0".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
            },
            (BrowserProfile::Vivaldi, OsProfile::Android) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36 Vivaldi/6.7.999.31".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
            },
            (BrowserProfile::Safari, OsProfile::IOS) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc009, 0xc013, 0xc00a, 0xc014],
                accept_language: "en-US,en;q=0.9".to_string(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
            },
            // --- Fallback Profile ---
            _ => Self::new(BrowserProfile::Chrome, OsProfile::Windows),
        };

        profile.client_hello = TlsClientHelloSpoofer::load_client_hello(browser, os);
        profile.server_hello = None;
        profile.certificate = None;
        profile
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
        let mut headers = vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", host.as_bytes()),
            quiche::h3::Header::new(b":path", path.as_bytes()),
            quiche::h3::Header::new(b"user-agent", self.profile.user_agent.as_bytes()),
        ];

        let http_headers = self.profile.generate_http_headers();
        if let Some(al) = http_headers.get("Accept-Language") {
            headers.push(quiche::h3::Header::new(b"accept-language", al.as_bytes()));
        }
        if let Some(acc) = http_headers.get("Accept") {
            headers.push(quiche::h3::Header::new(b"accept", acc.as_bytes()));
        }
        if let Some(enc) = http_headers.get("Accept-Encoding") {
            headers.push(quiche::h3::Header::new(b"accept-encoding", enc.as_bytes()));
        }
        headers
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

/// Configuration for [`FakeHeaders`].
pub struct FakeHeadersConfig {
    pub optimize_for_quic: bool,
    pub use_qpack_headers: bool,
}

/// Generates HTTP/3 headers optionally optimized for QUIC.
pub struct FakeHeaders {
    cfg: FakeHeadersConfig,
    profile: FingerprintProfile,
}

impl FakeHeaders {
    pub fn new(cfg: FakeHeadersConfig, profile: FingerprintProfile) -> Self {
        Self { cfg, profile }
    }

    pub fn header_list(&self, host: &str, path: &str) -> Vec<quiche::h3::Header> {
        let mut headers = Http3Masquerade::new(self.profile.clone()).generate_headers(host, path);
        if self.cfg.optimize_for_quic {
            headers.retain(|h| h.name() != b"connection");
        }
        headers
    }

    pub fn qpack_block(&self, host: &str, path: &str) -> Vec<u8> {
        let list = self.header_list(host, path);
        let mut enc = quiche::h3::qpack::Encoder::new();
        let mut out = Vec::new();
        let _ = enc.encode(&mut out, 0, &list);
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

/// Manages domain fronting by rotating through configured domains.
pub struct DomainFrontingManager {
    domains: Vec<String>,
    index: AtomicUsize,
}

impl DomainFrontingManager {
    /// Creates a new manager from a list of domains.
    pub fn new(domains: Vec<String>) -> Self {
        Self {
            domains,
            index: AtomicUsize::new(0),
        }
    }

    /// Creates a manager from built-in CDN providers.
    pub fn from_providers(providers: Vec<CdnProvider>) -> Self {
        let domains = providers
            .into_iter()
            .map(|p| p.get_domain().to_string())
            .collect();
        Self::new(domains)
    }

    /// Selects the next domain to use for domain fronting in a round-robin fashion.
    pub fn get_fronted_domain(&self) -> String {
        let current = self.index.fetch_add(1, Ordering::SeqCst);
        let idx = current % self.domains.len();
        self.domains[idx].clone()
    }

    /// Randomly chooses a domain. Useful when deterministic rotation is undesired.
    pub fn random_domain(&self) -> String {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        self.domains
            .choose(&mut rng)
            .cloned()
            .unwrap_or_else(|| "cdn.example.com".to_string())
    }

    /// Replaces the current domain list.
    pub fn set_domains(&mut self, domains: Vec<String>) {
        self.domains = domains;
        self.index.store(0, Ordering::SeqCst);
    }
}

// --- 5. XOR-based Traffic Obfuscation ---

/// A simple XOR obfuscator for packet payloads.
pub struct XorObfuscator {
    key: Mutex<Vec<u8>>,
    position: AtomicUsize,
}

impl XorObfuscator {
    /// Creates a new obfuscator, ideally using a key from the CryptoManager.
    pub fn new(crypto_manager: &CryptoManager) -> Self {
        // Generate a session specific key so that each connection uses a
        // different obfuscation key.
        let key = crypto_manager.generate_session_key(32);
        Self {
            key: Mutex::new(key),
            position: AtomicUsize::new(0),
        }
    }

    /// Applies XOR obfuscation to a mutable payload using the best available SIMD implementation.
    pub fn obfuscate(&self, payload: &mut [u8]) {
        let mut key = self.key.lock().unwrap();
        if key.is_empty() {
            return;
        }

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
        // Rolling key update using SHA-256 after each packet
        let digest = Sha256::digest(&key[..]);
        key.clear();
        key.extend_from_slice(&digest);
        self.position.store(0, Ordering::Relaxed);
    }

    /// Reverses XOR obfuscation. The operation is symmetrical.
    pub fn deobfuscate(&self, payload: &mut [u8]) {
        self.obfuscate(payload);
    }

    /// Generates a fresh obfuscation key using the provided CryptoManager.
    pub fn rekey(&self, crypto_manager: &CryptoManager) {
        let mut key = self.key.lock().unwrap();
        *key = crypto_manager.generate_session_key(32);
        self.position.store(0, Ordering::Relaxed);
    }
}

// --- 6. TLS Client Hello Spoofing ---

/// Allows manipulation of the TLS ClientHello to mimic real browser behaviour.
pub struct TlsClientHelloSpoofer;

impl TlsClientHelloSpoofer {
    fn profile_path(browser: BrowserProfile, os: OsProfile) -> std::path::PathBuf {
        let browser = match browser {
            BrowserProfile::Chrome => "chrome",
            BrowserProfile::Firefox => "firefox",
            BrowserProfile::Safari => "safari",
            BrowserProfile::Opera => "opera",
            BrowserProfile::Brave => "brave",
            BrowserProfile::Edge => "edge",
            BrowserProfile::Vivaldi => "vivaldi",
        };
        let os = match os {
            OsProfile::Windows => "windows",
            OsProfile::MacOS => "macos",
            OsProfile::Linux => "linux",
            OsProfile::IOS => "ios",
            OsProfile::Android => "android",
        };
        Path::new("browser_profiles").join(format!("{}_{}.chlo", browser, os))
    }

    fn load_client_hello(browser: BrowserProfile, os: OsProfile) -> Option<Vec<u8>> {
        let path = Self::profile_path(browser, os);
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|d| base64::decode(d.trim()).ok())
    }

    /// Injects the given ClientHello bytes into the quiche configuration via FFI.
    fn inject_bytes(cfg: &mut quiche::Config, hello: &[u8]) {
        unsafe {
            let b = tls_ffi::quiche_chlo_builder_new_wrapper();
            if !b.is_null() {
                tls_ffi::quiche_chlo_builder_add_wrapper(b, hello.as_ptr(), hello.len());
                tls_ffi::quiche_config_set_chlo_builder_wrapper(
                    cfg as *mut _ as *mut std::ffi::c_void,
                    b,
                );
                tls_ffi::quiche_chlo_builder_free_wrapper(b);
                // Disable GREASE and randomization when injecting a real ClientHello
                tls_ffi::quiche_ssl_disable_tls_grease(std::ptr::null_mut(), 1);
                tls_ffi::quiche_ssl_set_deterministic_hello(std::ptr::null_mut(), 1);
            }
        }
    }

    /// Loads the specified profile and injects it into the quiche config.
    pub fn inject_profile(cfg: &mut quiche::Config, browser: BrowserProfile, os: OsProfile) {
        if let Some(hello) = Self::load_client_hello(browser, os) {
            Self::inject_bytes(cfg, &hello);
        } else {
            error!("Missing ClientHello profile for {:?}/{:?}", browser, os);
        }
    }

    /// Returns a list of all available browser/OS combinations for which a
    /// ClientHello dump exists in `browser_profiles`.
    pub fn available_profiles() -> Vec<(BrowserProfile, OsProfile)> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir("browser_profiles") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let s = name.to_string_lossy();
                if !s.ends_with(".chlo") {
                    continue;
                }
                let n = s.trim_end_matches(".chlo");
                let parts: Vec<&str> = n.split('_').collect();
                if parts.len() != 2 {
                    continue;
                }
                if let (Ok(b), Ok(o)) = (parts[0].parse(), parts[1].parse()) {
                    out.push((b, o));
                }
            }
        }
        out
    }
}

// --- 7. Stealth Manager and Configuration ---

/// Configuration for the main StealthManager.
#[derive(Clone)]
pub struct StealthConfig {
    pub browser_profile: BrowserProfile,
    pub os_profile: OsProfile,
    pub use_fake_tls: bool,
    pub enable_doh: bool,
    pub doh_provider: String,
    pub enable_http3_masquerading: bool,
    pub use_qpack_headers: bool,
    pub enable_domain_fronting: bool,
    pub fronting_domains: Vec<String>,
    pub cdn_providers: Vec<CdnProvider>,
    pub enable_xor_obfuscation: bool,
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            browser_profile: BrowserProfile::Chrome,
            os_profile: OsProfile::Windows,
            use_fake_tls: false,
            enable_doh: true,
            doh_provider: "https://cloudflare-dns.com/dns-query".to_string(),
            enable_http3_masquerading: true,
            use_qpack_headers: true,
            enable_domain_fronting: true,
            fronting_domains: Vec::new(),
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

impl StealthConfig {
    pub fn from_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        #[derive(serde::Deserialize)]
        struct Root {
            stealth: Option<Section>,
        }

        #[derive(serde::Deserialize)]
        struct Section {
            browser_profile: Option<BrowserProfile>,
            os_profile: Option<OsProfile>,
            use_fake_tls: Option<bool>,
            enable_doh: Option<bool>,
            doh_provider: Option<String>,
            enable_http3_masquerading: Option<bool>,
            use_qpack_headers: Option<bool>,
            enable_domain_fronting: Option<bool>,
            fronting_domains: Option<Vec<String>>,
            enable_xor_obfuscation: Option<bool>,
        }

        let root: Root = toml::from_str(s)?;
        let mut cfg = StealthConfig::default();
        if let Some(sec) = root.stealth {
            if let Some(v) = sec.browser_profile {
                cfg.browser_profile = v;
            }
            if let Some(v) = sec.os_profile {
                cfg.os_profile = v;
            }
            if let Some(v) = sec.use_fake_tls {
                cfg.use_fake_tls = v;
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
            if let Some(v) = sec.enable_xor_obfuscation {
                cfg.enable_xor_obfuscation = v;
            }
        }
        Ok(cfg)
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    /// Validate the configuration values.
    pub fn validate(&self) -> Result<(), String> {
        if self.enable_doh && self.doh_provider.is_empty() {
            return Err("doh_provider must not be empty when DoH is enabled".into());
        }
        if self.enable_domain_fronting
            && self.fronting_domains.is_empty()
            && self.cdn_providers.is_empty()
        {
            return Err("fronting_domains required when domain fronting is enabled".into());
        }
        Ok(())
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
        mut config: StealthConfig,
        crypto_manager: Arc<CryptoManager>,
        optimization_manager: Arc<OptimizationManager>,
    ) -> Self {
        let mut fingerprint = FingerprintProfile::new(config.browser_profile, config.os_profile);
        if fingerprint.client_hello.is_none() {
            fingerprint.client_hello =
                TlsClientHelloSpoofer::load_client_hello(fingerprint.browser, fingerprint.os);
        }

        let domain_fronter = if config.enable_domain_fronting {
            if !config.fronting_domains.is_empty() {
                Some(DomainFrontingManager::new(config.fronting_domains.clone()))
            } else {
                Some(DomainFrontingManager::from_providers(
                    config.cdn_providers.clone(),
                ))
            }
        } else {
            None
        };

        let xor_obfuscator = if config.enable_xor_obfuscation {
            Some(XorObfuscator::new(&crypto_manager))
        } else {
            None
        };

        telemetry!(telemetry::STEALTH_DOH.set(if config.enable_doh { 1 } else { 0 }));
        telemetry!(
            telemetry::STEALTH_FRONTING.set(if config.enable_domain_fronting { 1 } else { 0 })
        );
        telemetry!(telemetry::STEALTH_XOR.set(if config.enable_xor_obfuscation { 1 } else { 0 }));

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

    /// Returns all fingerprint profiles for which a ClientHello dump exists.
    pub fn available_fingerprints() -> Vec<FingerprintProfile> {
        TlsClientHelloSpoofer::available_profiles()
            .into_iter()
            .map(|(b, o)| FingerprintProfile::new(b, o))
            .collect()
    }

    /// Applies the configured TLS fingerprint to a quiche configuration.
    /// ClientHello bytes are loaded from `browser_profiles/*.chlo` and passed
    /// to quiche using the `quiche_config_set_custom_tls` hook. This ensures
    /// the handshake matches the captured browser exactly.
    pub fn apply_utls_profile(&self, config: &mut quiche::Config, preferred: Option<u16>) {
        let mut fingerprint = self.fingerprint.lock().unwrap();
        info!(
            "Applying uTLS fingerprint for: {:?}/{:?}",
            fingerprint.browser, fingerprint.os
        );

        // Build the final cipher list, optionally preferring a runtime selected suite.
        let mut suite_ids = fingerprint.tls_cipher_suites.clone();
        if let Some(id) = preferred {
            if !suite_ids.contains(&id) {
                suite_ids.insert(0, id);
            }
        }

        let quiche_ciphers: Vec<quiche::Cipher> = suite_ids
            .iter()
            .filter_map(|&iana_id| map_iana_to_quiche_cipher(iana_id))
            .collect();

        if !quiche_ciphers.is_empty() {
            if let Err(e) = config.set_ciphers(&quiche_ciphers) {
                error!("Failed to set custom cipher suites: {}", e);
            }
            // Manipulate TLS ClientHello to match the desired ordering.
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
    pub fn set_fingerprint_profile(
        &self,
        profile: FingerprintProfile,
        mut cfg: Option<&mut quiche::Config>,
    ) {
        let mut p = profile;
        if p.client_hello.is_none() {
            p.client_hello = TlsClientHelloSpoofer::load_client_hello(p.browser, p.os);
        }

        if let (Some(ref hello), Some(c)) = (&p.client_hello, cfg.as_deref_mut()) {
            TlsClientHelloSpoofer::inject_bytes(c, hello);
        }

        let mut fp = self.fingerprint.lock().unwrap();
        *fp = p;
    }

    /// Returns the currently active fingerprint profile.
    pub fn current_profile(&self) -> FingerprintProfile {
        self.fingerprint.lock().unwrap().clone()
    }

    /// Generates the FakeTLS handshake bytes for the current profile.
    pub fn fake_tls_handshake(&self) -> Vec<u8> {
        let fp = self.fingerprint.lock().unwrap();
        fake_tls::FakeTls::handshake(&fp)
    }

    /// Configures the provided quiche `Config` for the active fingerprint.
    /// Depending on the configuration this either applies an uTLS profile or
    /// generates FakeTLS handshake bytes. The returned vector is only populated
    /// when FakeTLS is in use.
    pub fn configure_tls(
        &self,
        cfg: &mut quiche::Config,
        enable_utls: bool,
        preferred: Option<u16>,
    ) -> Option<Vec<u8>> {
        if self.config.use_fake_tls {
            let hello = self.fake_tls_handshake();
            if !hello.is_empty() {
                return Some(hello);
            }
        }

        if enable_utls {
            self.apply_utls_profile(cfg, preferred);
            // ensure deterministic handshake when using real TLS fingerprints
            unsafe {
                tls_ffi::quiche_ssl_disable_tls_grease(std::ptr::null_mut(), 1);
                tls_ffi::quiche_ssl_set_deterministic_hello(std::ptr::null_mut(), 1);
            }
        }

        None
    }

    /// Starts automatic rotation through the given browser profiles.
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
        let mgr = Arc::clone(self);
        DOH_RUNTIME.spawn(async move {
            let mut idx = 0usize;
            loop {
                tokio::time::sleep(interval).await;
                idx = (idx + 1) % profiles.len();
                mgr.set_fingerprint_profile(profiles[idx].clone(), None);
            }
        });
    }

    /// Resolves a domain, using DoH if enabled.
    pub fn resolve_domain(&self, domain: &str) -> IpAddr {
        if self.config.enable_doh {
            debug!(
                "Resolving {} via DoH provider: {}",
                domain, self.config.doh_provider
            );
            match DOH_RUNTIME.block_on(resolve_doh(
                &self.doh_client,
                domain,
                &self.config.doh_provider,
            )) {
                Ok(ip) => ip,
                Err(e) => {
                    telemetry!(telemetry::DNS_ERRORS.inc());
                    error!("DoH resolution failed: {}. Falling back.", e);
                    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
                }
            }
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
            (fronted_domain, real_host.to_string()) // SNI = front, Host = real
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

    /// Processes a TLS ClientHello message before it is sent.
    pub fn process_client_hello(&self, payload: &mut [u8]) {
        if self.config.enable_xor_obfuscation && self.xor_obfuscator.is_some() {
            debug!("Obfuscating ClientHello payload.");
            self.xor_obfuscator.as_ref().unwrap().obfuscate(payload);
        }
    }

    /// Obfuscates arbitrary payload data within a specific context.
    pub fn obfuscate_payload(&self, payload: &mut [u8], _context_id: u64) {
        if self.config.enable_xor_obfuscation && self.xor_obfuscator.is_some() {
            debug!("Obfuscating payload for context {}", _context_id);
            self.xor_obfuscator.as_ref().unwrap().obfuscate(payload);
        }
    }

    /// Generates HTTP/3 headers for masquerading a request.
    pub fn get_http3_masquerade_headers(&self, host: &str, path: &str) -> Option<Vec<u8>> {
        if self.config.enable_http3_masquerading {
            let fp = self.fingerprint.lock().unwrap();
            let fh = FakeHeaders::new(
                FakeHeadersConfig {
                    optimize_for_quic: true,
                    use_qpack_headers: self.config.use_qpack_headers,
                },
                fp.clone(),
            );
            debug!("Generating HTTP/3 masquerade headers for host: {}", host);
            if self.config.use_qpack_headers {
                Some(fh.qpack_block(host, path))
            } else {
                let headers = fh.header_list(host, path);
                let mut enc = quiche::h3::qpack::Encoder::new();
                let mut out = Vec::new();
                let _ = enc.encode(&mut out, 0, &headers);
                Some(out)
            }
        } else {
            None
        }
    }

    /// Returns a vector of HTTP/3 headers for a request.
    pub fn get_http3_header_list(&self, host: &str, path: &str) -> Option<Vec<quiche::h3::Header>> {
        if self.config.enable_http3_masquerading {
            let fp = self.fingerprint.lock().unwrap();
            let fh = FakeHeaders::new(
                FakeHeadersConfig {
                    optimize_for_quic: true,
                    use_qpack_headers: self.config.use_qpack_headers,
                },
                fp.clone(),
            );
            Some(fh.header_list(host, path))
        } else {
            None
        }
    }

    /// Returns whether FakeTLS should be used for handshakes.
    pub fn use_fake_tls(&self) -> bool {
        self.config.use_fake_tls
    }
}
