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

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use clap::ValueEnum;
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use quiche::h3::NameValue;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use url::Url;

use self::fake_tls::ServerHelloParamsOwned;
use crate::crypto::CryptoManager; // Assumed for integration
use crate::optimize::OptimizationManager; // Assumed for integration
use crate::telemetry;

// --- Inlined: fake_tls.rs ---
// Minimal FakeTLS record layer for fingerprinting
// Generates a forged ClientHello and synthetic server response without
// establishing a real TLS session.
pub mod fake_tls {
    use super::FingerprintProfile;

    /// Owned variant of [`ServerHelloParams`] for storing in fingerprint profiles.
    #[derive(Debug, Clone)]
    pub struct ServerHelloParamsOwned {
        pub tls_version: u16,
        pub cipher_suite: u16,
        pub extensions: Vec<u8>,
    }

    /// Parameters used to craft a minimal ClientHello message.
    #[derive(Clone, Copy)]
    pub struct ClientHelloParams<'a> {
        /// TLS protocol version (e.g. `0x0303` for TLS 1.2).
        pub tls_version: u16,
        /// List of cipher suites encoded as IANA identifiers.
        pub cipher_suites: &'a [u16],
        /// Raw extension block to append after the compression method.
        pub extensions: &'a [u8],
    }

    /// Parameters used to craft a minimal ServerHello message.
    #[derive(Clone, Copy)]
    pub struct ServerHelloParams<'a> {
        /// TLS protocol version returned by the server.
        pub tls_version: u16,
        /// Selected cipher suite encoded as IANA identifier.
        pub cipher_suite: u16,
        /// Raw extension block of the server response.
        pub extensions: &'a [u8],
    }

    /// Hard coded ClientHello payload used when a profile does not provide one.
    /// This is not a valid TLS handshake, it merely resembles one for DPI evasion.
    pub const DEFAULT_CLIENT_HELLO: &[u8] = &[
        0x16, 0x03, 0x01, 0x00, 0x0f, // record header
        0x01, 0x00, 0x00, 0x0b, // handshake header
        b'f', b'a', b'k', b'e', b'-', b'c', b'l', b'i', b'e', b'n', b't',
    ];

    /// Hard coded ServerHello payload returned by the fake server.
    pub const DEFAULT_SERVER_HELLO: &[u8] = &[
        0x16, 0x03, 0x03, 0x00, 0x0f, 0x02, 0x00, 0x00, 0x0b, b'f', b'a', b'k', b'e', b'-', b's',
        b'e', b'r', b'v', b'e', b'r',
    ];

    /// Hard coded certificate payload used by the fake server.
    pub const DEFAULT_CERTIFICATE: &[u8] = &[
        0x16, 0x03, 0x03, 0x00, 0x08, 0x0b, 0x00, 0x00, 0x04, b'c', b'e', b'r', b't',
    ];

    pub struct FakeTls;

    impl FakeTls {
        /// Returns the ClientHello message for the given fingerprint profile.
        pub fn client_hello(profile: &FingerprintProfile) -> Vec<u8> {
            if let Some(ref ch) = profile.client_hello {
                ch.clone()
            } else {
                DEFAULT_CLIENT_HELLO.to_vec()
            }
        }

        /// Helper to build a TLS handshake record for the given handshake type and
        /// payload.
        fn record(htype: u8, payload: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(payload.len() + 9);
            out.extend_from_slice(&[0x16, 0x03, 0x03]); // Handshake record, TLS 1.2
            let len = payload.len() + 4;
            out.extend_from_slice(&(len as u16).to_be_bytes());
            out.push(htype);
            let l = (payload.len() as u32).to_be_bytes();
            out.extend_from_slice(&l[1..]);
            out.extend_from_slice(payload);
            out
        }

        /// Builds a minimal ClientHello record using the provided parameters.
        pub fn client_hello_custom(params: ClientHelloParams) -> Vec<u8> {
            let mut payload = Vec::new();
            payload.extend_from_slice(&params.tls_version.to_be_bytes());
            payload.extend_from_slice(&[0u8; 32]); // random
            payload.push(0); // session id len
            payload.extend_from_slice(&((params.cipher_suites.len() * 2) as u16).to_be_bytes());
            for cs in params.cipher_suites {
                payload.extend_from_slice(&cs.to_be_bytes());
            }
            payload.push(1); // compression methods len
            payload.push(0); // null compression
            payload.extend_from_slice(&(params.extensions.len() as u16).to_be_bytes());
            payload.extend_from_slice(params.extensions);
            Self::record(0x01, &payload)
        }

        /// Builds a minimal ServerHello record using the provided parameters.
        pub fn server_hello_custom(params: ServerHelloParams) -> Vec<u8> {
            let mut payload = Vec::new();
            payload.extend_from_slice(&params.tls_version.to_be_bytes());
            payload.extend_from_slice(&[0u8; 32]); // random
            payload.push(0); // session id len
            payload.extend_from_slice(&params.cipher_suite.to_be_bytes());
            payload.push(0); // null compression
            payload.extend_from_slice(&(params.extensions.len() as u16).to_be_bytes());
            payload.extend_from_slice(params.extensions);
            Self::record(0x02, &payload)
        }

        /// Builds a TLS Certificate record from raw certificate bytes.
        pub fn certificate_record(cert: &[u8]) -> Vec<u8> {
            Self::record(0x0b, cert)
        }

        /// Builds the server response consisting of a custom ServerHello and certificate.
        pub fn server_response_custom(sh: ServerHelloParams, cert: &[u8]) -> Vec<u8> {
            let mut out = Self::server_hello_custom(sh);
            out.extend_from_slice(&Self::certificate_record(cert));
            out
        }

        /// Builds a full FakeTLS handshake from explicit parameters.
        pub fn handshake_custom(ch: ClientHelloParams, sh: ServerHelloParams) -> Vec<u8> {
            let mut out = Self::client_hello_custom(ch);
            out.extend_from_slice(&Self::server_hello_custom(sh));
            out
        }

        /// Builds a FakeTLS handshake including a custom certificate record.
        pub fn handshake_custom_with_cert(
            ch: ClientHelloParams,
            sh: ServerHelloParams,
            cert: &[u8],
        ) -> Vec<u8> {
            let mut out = Self::client_hello_custom(ch);
            out.extend_from_slice(&Self::server_response_custom(sh, cert));
            out
        }

        /// Returns the fake server response consisting of ServerHello and a dummy
        /// certificate record.
        pub fn server_response() -> Vec<u8> {
            let mut out = DEFAULT_SERVER_HELLO.to_vec();
            out.extend_from_slice(DEFAULT_CERTIFICATE);
            out
        }

        /// Generates the complete FakeTLS handshake sequence.
        pub fn handshake(profile: &FingerprintProfile) -> Vec<u8> {
            let cert = profile
                .certificate
                .as_deref()
                .unwrap_or(DEFAULT_CERTIFICATE);

            if profile.client_hello.is_none() && profile.server_hello.is_none() {
                let cipher_suite = *profile.tls_cipher_suites.first().unwrap_or(&0x1301);
                let suites = [cipher_suite];
                let ch_params = ClientHelloParams {
                    tls_version: 0x0303,
                    cipher_suites: &suites,
                    extensions: &[],
                };
                let sh_params = ServerHelloParams {
                    tls_version: 0x0303,
                    cipher_suite,
                    extensions: &[],
                };
                Self::handshake_custom_with_cert(ch_params, sh_params, cert)
            } else {
                let mut out = Self::client_hello(profile);

                let sh_params = if let Some(ref owned) = profile.server_hello {
                    ServerHelloParams {
                        tls_version: owned.tls_version,
                        cipher_suite: owned.cipher_suite,
                        extensions: &owned.extensions,
                    }
                } else {
                    ServerHelloParams {
                        tls_version: 0x0303,
                        cipher_suite: *profile.tls_cipher_suites.first().unwrap_or(&0x1301),
                        extensions: &[],
                    }
                };

                out.extend_from_slice(&Self::server_response_custom(sh_params, cert));
                out
            }
        }
    }
}

// --- Inlined: tls_ffi.rs ---
pub mod tls_ffi {
    use std::os::raw::c_void;
    use std::sync::OnceLock;

    use base64::engine::general_purpose::STANDARD as BASE64_STD;
    use base64::Engine;
    use libloading::{Library, Symbol};

    type CustomTlsFn = unsafe extern "C" fn(*mut c_void, *const u8, usize);
    type EnableSimdFn = unsafe extern "C" fn(*mut c_void);
    type BuilderNewFn = unsafe extern "C" fn() -> *mut c_void;
    type BuilderAddFn = unsafe extern "C" fn(*mut c_void, *const u8, usize);
    type BuilderUseFn = unsafe extern "C" fn(*mut c_void, *mut c_void);
    type BuilderFreeFn = unsafe extern "C" fn(*mut c_void);
    type DisableGreaseFn = unsafe extern "C" fn(*mut c_void, i32);
    type DeterministicFn = unsafe extern "C" fn(*mut c_void, i32);

    static LIB: OnceLock<Option<Library>> = OnceLock::new();
    static SET_TLS: OnceLock<Option<CustomTlsFn>> = OnceLock::new();
    static ENABLE_SIMD: OnceLock<Option<EnableSimdFn>> = OnceLock::new();
    static BUILDER_NEW: OnceLock<Option<BuilderNewFn>> = OnceLock::new();
    static BUILDER_ADD: OnceLock<Option<BuilderAddFn>> = OnceLock::new();
    static BUILDER_USE: OnceLock<Option<BuilderUseFn>> = OnceLock::new();
    static BUILDER_FREE: OnceLock<Option<BuilderFreeFn>> = OnceLock::new();
    static DISABLE_GREASE: OnceLock<Option<DisableGreaseFn>> = OnceLock::new();
    static SET_DETERMINISTIC: OnceLock<Option<DeterministicFn>> = OnceLock::new();

    #[cfg(test)]
    pub static LAST_HELLO: once_cell::sync::Lazy<std::sync::Mutex<Vec<u8>>> =
        once_cell::sync::Lazy::new(|| std::sync::Mutex::new(Vec::new()));

    fn load_real_symbols() {
        if let Ok(path) = std::env::var("QUICHE_PATH") {
            let lib_path = format!("{}/target/latest/libquiche.so", path);
            if let Ok(lib) = unsafe { Library::new(&lib_path) } {
                unsafe {
                    let set: Result<Symbol<CustomTlsFn>, _> =
                        lib.get(b"quiche_config_set_custom_tls");
                    if let Ok(f) = set {
                        SET_TLS.set(Some(*f)).ok();
                    }

                    let simd: Result<Symbol<EnableSimdFn>, _> =
                        lib.get(b"quiche_config_enable_simd");
                    if let Ok(f) = simd {
                        ENABLE_SIMD.set(Some(*f)).ok();
                    }

                    let bnew: Result<Symbol<BuilderNewFn>, _> = lib.get(b"quiche_chlo_builder_new");
                    if let Ok(f) = bnew {
                        BUILDER_NEW.set(Some(*f)).ok();
                    }
                    let badd: Result<Symbol<BuilderAddFn>, _> = lib.get(b"quiche_chlo_builder_add");
                    if let Ok(f) = badd {
                        BUILDER_ADD.set(Some(*f)).ok();
                    }
                    let buse: Result<Symbol<BuilderUseFn>, _> =
                        lib.get(b"quiche_config_set_chlo_builder");
                    if let Ok(f) = buse {
                        BUILDER_USE.set(Some(*f)).ok();
                    }
                    let bfree: Result<Symbol<BuilderFreeFn>, _> =
                        lib.get(b"quiche_chlo_builder_free");
                    if let Ok(f) = bfree {
                        BUILDER_FREE.set(Some(*f)).ok();
                    }

                    let dgrease: Result<Symbol<DisableGreaseFn>, _> =
                        lib.get(b"SSL_disable_tls_grease");
                    if let Ok(f) = dgrease {
                        DISABLE_GREASE.set(Some(*f)).ok();
                    }

                    let dhello: Result<Symbol<DeterministicFn>, _> =
                        lib.get(b"SSL_set_deterministic_hello");
                    if let Ok(f) = dhello {
                        SET_DETERMINISTIC.set(Some(*f)).ok();
                    }
                }
                LIB.set(Some(lib)).ok();
            } else {
                log::debug!("failed to load {}", lib_path);
            }
        }
    }

    /// FFI shim for injecting a custom TLS ClientHello into quiche.
    ///
    /// Builds without the patched quiche library provide a no-op
    /// implementation so that tests can run. When linked against a
    /// modified quiche with support for custom ClientHello messages the
    /// symbol will be overridden by the real implementation.
    /// Set custom TLS configuration for the given quiche config.
    ///
    /// # Safety
    /// This function is unsafe because:
    /// - It dereferences raw pointers (`cfg`, `hello`) without validation
    /// - It calls external C library functions through function pointers
    /// - The caller must ensure `cfg` is a valid pointer to a quiche config
    /// - The caller must ensure `hello` points to valid memory of at least `len` bytes
    #[no_mangle]
    pub unsafe extern "C" fn quiche_config_set_custom_tls(
        cfg: *mut c_void,
        hello: *const u8,
        len: usize,
    ) {
        let f = SET_TLS.get_or_init(|| {
            load_real_symbols();
            SET_TLS.get().cloned().flatten()
        });

        if let Some(real) = f.as_ref() {
            real(cfg, hello, len);
        } else {
            // no-op to avoid stub logging in non-test builds
        }

        #[cfg(test)]
        {
            let mut buf = match LAST_HELLO.lock() {
                Ok(g) => g,
                Err(poisoned) => {
                    log::warn!("tls_ffi: LAST_HELLO mutex poisoned; recovering inner vector");
                    poisoned.into_inner()
                }
            };
            buf.clear();
            buf.extend_from_slice(unsafe { std::slice::from_raw_parts(hello, len) });
        }
    }

    /// Create a new ClientHello builder wrapper.
    ///
    /// # Safety
    /// This function is unsafe because:
    /// - It calls external C library functions through function pointers
    /// - Returns a raw pointer that must be properly managed by the caller
    #[no_mangle]
    pub unsafe extern "C" fn quiche_chlo_builder_new_wrapper() -> *mut c_void {
        let f = BUILDER_NEW.get_or_init(|| {
            load_real_symbols();
            BUILDER_NEW.get().cloned().flatten()
        });
        if let Some(real) = f.as_ref() {
            real()
        } else {
            std::ptr::null_mut()
        }
    }

    /// Add data to a ClientHello builder wrapper.
    ///
    /// # Safety
    /// This function is unsafe because:
    /// - It dereferences raw pointers (`builder`, `data`) without validation
    /// - It calls external C library functions through function pointers
    /// - The caller must ensure `builder` is a valid pointer to a builder
    /// - The caller must ensure `data` points to valid memory of at least `len` bytes
    #[no_mangle]
    pub unsafe extern "C" fn quiche_chlo_builder_add_wrapper(
        builder: *mut c_void,
        data: *const u8,
        len: usize,
    ) {
        let f = BUILDER_ADD.get_or_init(|| {
            load_real_symbols();
            BUILDER_ADD.get().cloned().flatten()
        });
        if let Some(real) = f.as_ref() {
            real(builder, data, len);
        }
    }

    /// Set ClientHello builder for the given quiche config.
    ///
    /// # Safety
    /// This function is unsafe because:
    /// - It dereferences raw pointers (`cfg`, `builder`) without validation
    /// - It calls external C library functions through function pointers
    /// - The caller must ensure both pointers are valid
    #[no_mangle]
    pub unsafe extern "C" fn quiche_config_set_chlo_builder_wrapper(
        cfg: *mut c_void,
        builder: *mut c_void,
    ) {
        let f = BUILDER_USE.get_or_init(|| {
            load_real_symbols();
            BUILDER_USE.get().cloned().flatten()
        });
        if let Some(real) = f.as_ref() {
            real(cfg, builder);
        }
    }

    /// Free a ClientHello builder wrapper.
    ///
    /// # Safety
    /// This function is unsafe because:
    /// - It dereferences a raw pointer (`builder`) without validation
    /// - It calls external C library functions through function pointers
    /// - The caller must ensure `builder` is a valid pointer
    #[no_mangle]
    pub unsafe extern "C" fn quiche_chlo_builder_free_wrapper(builder: *mut c_void) {
        let f = BUILDER_FREE.get_or_init(|| {
            load_real_symbols();
            BUILDER_FREE.get().cloned().flatten()
        });
        if let Some(real) = f.as_ref() {
            real(builder);
        }
    }

    /// Disable TLS GREASE for the given SSL context.
    ///
    /// # Safety
    /// This function is unsafe because:
    /// - It dereferences a raw pointer (`ssl`) without validation
    /// - It calls external C library functions through function pointers
    /// - The caller must ensure `ssl` is a valid pointer to an SSL context
    #[no_mangle]
    pub unsafe extern "C" fn quiche_ssl_disable_tls_grease(ssl: *mut c_void, val: i32) {
        let f = DISABLE_GREASE.get_or_init(|| {
            load_real_symbols();
            DISABLE_GREASE.get().cloned().flatten()
        });
        if let Some(real) = f.as_ref() {
            real(ssl, val);
        }
    }

    /// Set deterministic hello for the given SSL context.
    ///
    /// # Safety
    /// This function is unsafe because:
    /// - It dereferences a raw pointer (`ssl`) without validation
    /// - It calls external C library functions through function pointers
    /// - The caller must ensure `ssl` is a valid pointer to an SSL context
    #[no_mangle]
    pub unsafe extern "C" fn quiche_ssl_set_deterministic_hello(ssl: *mut c_void, val: i32) {
        let f = SET_DETERMINISTIC.get_or_init(|| {
            load_real_symbols();
            SET_DETERMINISTIC.get().cloned().flatten()
        });
        if let Some(real) = f.as_ref() {
            real(ssl, val);
        }
    }

    /// Enable SIMD optimizations for the given quiche configuration.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it:
    /// - Dereferences a raw pointer (`_cfg`) that must be a valid quiche configuration pointer
    /// - Calls into external C library functions that may have their own safety requirements
    /// - The caller must ensure `_cfg` is a valid, non-null pointer to a quiche configuration
    #[no_mangle]
    pub unsafe extern "C" fn quiche_config_enable_simd(_cfg: *mut c_void) {
        let f = ENABLE_SIMD.get_or_init(|| {
            load_real_symbols();
            ENABLE_SIMD.get().cloned().flatten()
        });

        if let Some(real) = f.as_ref() {
            real(_cfg);
        } else {
            // no-op to avoid stub logging in non-test builds
        }
    }

    /// Convenience helper to read a base64 encoded ClientHello from `path`
    /// and inject it into the given quiche configuration.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it calls `quiche_config_set_custom_tls` with a raw pointer.
    /// The caller must ensure `cfg` is a valid, non-null pointer to a quiche configuration.
    pub unsafe fn load_client_hello_from_file(cfg: *mut c_void, path: &str) -> std::io::Result<()> {
        let data = std::fs::read_to_string(path)?;
        let bytes = BASE64_STD
            .decode(data.trim())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        quiche_config_set_custom_tls(cfg, bytes.as_ptr(), bytes.len());
        Ok(())
    }
}

// --- Global Tokio Runtime for async DoH requests ---
lazy_static! {
    static ref DOH_RUNTIME: Runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            // Infallible fallback: single-threaded runtime
            log::error!("Failed to create multi-threaded Tokio runtime for DoH: {}. Falling back to current_thread runtime.", e);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|e2| {
                    log::error!(
                        "Failed to create fallback current_thread Tokio runtime as well: {}. Aborting.",
                        e2
                    );
                    std::process::abort();
                })
        });
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
    let mut url = Url::parse(doh_provider).inspect_err(|&e| {
        error!("Invalid DoH provider URL: {}", e);
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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum, serde::Serialize, serde::Deserialize,
)]
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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum, serde::Serialize, serde::Deserialize,
)]
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
                server_hello: None,
                certificate: None,
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
        let mut out = vec![0u8; 4096];
        let written = match encoder.encode(&headers, out.as_mut_slice()) {
            Ok(n) => n,
            Err(e) => {
                warn!("QPACK encode failed: {}", e);
                0
            }
        };
        out.truncate(written);
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
        let mut out = vec![0u8; 4096];
        let written = match enc.encode(&list, out.as_mut_slice()) {
            Ok(n) => n,
            Err(e) => {
                warn!("QPACK encode failed: {}", e);
                0
            }
        };
        out.truncate(written);
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
        let mut key = match self.key.lock() {
            Ok(g) => g,
            Err(p) => {
                warn!("XorObfuscator key mutex poisoned; recovering");
                p.into_inner()
            }
        };
        if key.is_empty() {
            return;
        }

        let key_len = key.len();
        let start = self.position.load(Ordering::Relaxed);
        for i in 0..payload.len() {
            payload[i] ^= key[(start + i) % key_len];
        }
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
        let mut key = match self.key.lock() {
            Ok(g) => g,
            Err(p) => {
                warn!("XorObfuscator key mutex poisoned; recovering");
                p.into_inner()
            }
        };
        *key = crypto_manager.generate_session_key(32);
        self.position.store(0, Ordering::Relaxed);
    }
}

// --- 6. TLS Client Hello Spoofing ---

/// Allows manipulation of the TLS ClientHello to mimic real browser behaviour.
pub struct TlsClientHelloSpoofer;

impl TlsClientHelloSpoofer {
    fn load_client_hello(browser: BrowserProfile, os: OsProfile) -> Option<Vec<u8>> {
        let rel = format!(
            "{}_{}.chlo",
            match browser {
                BrowserProfile::Chrome => "chrome",
                BrowserProfile::Firefox => "firefox",
                BrowserProfile::Safari => "safari",
                BrowserProfile::Opera => "opera",
                BrowserProfile::Brave => "brave",
                BrowserProfile::Edge => "edge",
                BrowserProfile::Vivaldi => "vivaldi",
            },
            match os {
                OsProfile::Windows => "windows",
                OsProfile::MacOS => "macos",
                OsProfile::Linux => "linux",
                OsProfile::IOS => "ios",
                OsProfile::Android => "android",
            }
        );

        let candidates = [
            Path::new("browser_profiles").join(&rel),
            Path::new("src/browser_profiles").join(&rel),
        ];

        for p in candidates.iter() {
            if let Ok(s) = std::fs::read_to_string(p) {
                if let Ok(bytes) = BASE64_STD.decode(s.trim()) {
                    return Some(bytes);
                }
            }
        }
        None
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
        let base = if Path::new("browser_profiles").is_dir() {
            "browser_profiles"
        } else if Path::new("src/browser_profiles").is_dir() {
            "src/browser_profiles"
        } else {
            "browser_profiles"
        };
        if let Ok(entries) = std::fs::read_dir(base) {
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

    /// Applies environment variable overrides for stealth settings.
    /// Supported variables:
    /// - QUICFUSCATE_BROWSER: chrome|firefox|safari|edge (case-insensitive)
    /// - QUICFUSCATE_OS: windows|linux|macos|android|ios (case-insensitive)
    /// - QUICFUSCATE_USE_FAKE_TLS: 0|1|true|false
    /// - QUICFUSCATE_DOH: 0|1|true|false
    /// - QUICFUSCATE_DOH_PROVIDER: URL
    /// - QUICFUSCATE_FRONTING: 0|1|true|false
    /// - QUICFUSCATE_QPACK: 0|1|true|false
    /// - QUICFUSCATE_XOR: 0|1|true|false
    pub fn apply_env_overrides(&mut self) {
        fn parse_bool(v: &str) -> Option<bool> {
            match v.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => Some(true),
                "0" | "false" | "no" | "off" => Some(false),
                _ => None,
            }
        }

        if let Ok(v) = std::env::var("QUICFUSCATE_BROWSER") {
            if let Some(bp) = Self::parse_browser(&v) {
                self.browser_profile = bp;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_OS") {
            if let Some(os) = Self::parse_os(&v) {
                self.os_profile = os;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_USE_FAKE_TLS") {
            if let Some(b) = parse_bool(&v) {
                self.use_fake_tls = b;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_DOH") {
            if let Some(b) = parse_bool(&v) {
                self.enable_doh = b;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_DOH_PROVIDER") {
            if !v.trim().is_empty() {
                self.doh_provider = v;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_FRONTING") {
            if let Some(b) = parse_bool(&v) {
                self.enable_domain_fronting = b;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_QPACK") {
            if let Some(b) = parse_bool(&v) {
                self.use_qpack_headers = b;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_XOR") {
            if let Some(b) = parse_bool(&v) {
                self.enable_xor_obfuscation = b;
            }
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

/// The central orchestrator for all stealth techniques.
pub struct StealthManager {
    config: StealthConfig,
    fingerprint: Mutex<FingerprintProfile>,
    doh_client: Client,
    domain_fronter: Option<DomainFrontingManager>,
    xor_obfuscator: Option<XorObfuscator>,
    // Integration with other modules
    #[allow(dead_code)]
    crypto_manager: Arc<CryptoManager>,
    #[allow(dead_code)]
    optimization_manager: Arc<OptimizationManager>,
}

impl StealthManager {
    /// Creates a new `StealthManager` with the given configuration.
    pub fn new(
        config: StealthConfig,
        crypto_manager: Arc<CryptoManager>,
        optimization_manager: Arc<OptimizationManager>,
    ) -> Self {
        let mut cfg = config;
        // Apply environment overrides lazily at construction to maximize flexibility
        cfg.apply_env_overrides();

        let mut fingerprint = FingerprintProfile::new(cfg.browser_profile, cfg.os_profile);
        if fingerprint.client_hello.is_none() {
            fingerprint.client_hello =
                TlsClientHelloSpoofer::load_client_hello(fingerprint.browser, fingerprint.os);
        }

        let domain_fronter = if cfg.enable_domain_fronting {
            if !cfg.fronting_domains.is_empty() {
                Some(DomainFrontingManager::new(cfg.fronting_domains.clone()))
            } else {
                Some(DomainFrontingManager::from_providers(
                    cfg.cdn_providers.clone(),
                ))
            }
        } else {
            None
        };

        let xor_obfuscator = if cfg.enable_xor_obfuscation {
            Some(XorObfuscator::new(&crypto_manager))
        } else {
            None
        };

        telemetry!(telemetry::STEALTH_DOH.set(if cfg.enable_doh { 1 } else { 0 }));
        telemetry!(telemetry::STEALTH_FRONTING.set(if cfg.enable_domain_fronting { 1 } else { 0 }));
        telemetry!(telemetry::STEALTH_XOR.set(if cfg.enable_xor_obfuscation { 1 } else { 0 }));

        Self {
            config: cfg,
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
        let mut fingerprint = match self.fingerprint.lock() {
            Ok(g) => g,
            Err(p) => {
                warn!("fingerprint mutex poisoned; recovering");
                p.into_inner()
            }
        };
        info!(
            "Applying uTLS fingerprint for: {:?}/{:?}",
            fingerprint.browser, fingerprint.os
        );

        // Manipulate TLS ClientHello to match the desired ordering.
        // Note: quiche::Config currently provides no stable API to set ciphers directly.
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

        if let Err(e) = config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL) {
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
    }

    /// Changes the active fingerprint profile at runtime.
    /// Call `apply_utls_profile` again to update an existing quiche configuration.
    pub fn set_fingerprint_profile(
        &self,
        profile: FingerprintProfile,
        cfg: Option<&mut quiche::Config>,
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

    /// Returns the currently active fingerprint profile.
    pub fn current_profile(&self) -> FingerprintProfile {
        match self.fingerprint.lock() {
            Ok(g) => g.clone(),
            Err(p) => {
                warn!("fingerprint mutex poisoned; recovering");
                p.into_inner().clone()
            }
        }
    }

    /// Generates the FakeTLS handshake bytes for the current profile.
    pub fn fake_tls_handshake(&self) -> Vec<u8> {
        let fp = match self.fingerprint.lock() {
            Ok(g) => g,
            Err(p) => {
                warn!("fingerprint mutex poisoned; recovering");
                p.into_inner()
            }
        };
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
        if self.config.enable_domain_fronting {
            if let Some(df) = self.domain_fronter.as_ref() {
                let fronted_domain = df.get_fronted_domain();
                debug!(
                    "Domain fronting enabled. SNI: {}, Host: {}",
                    fronted_domain, real_host
                );
                return (fronted_domain, real_host.to_string());
            }
        }
        (real_host.to_string(), real_host.to_string())
    }

    /// Processes an outgoing packet payload, applying configured stealth techniques.
    pub fn process_outgoing_packet(&self, payload: &mut [u8]) {
        // The optimization manager could provide an efficient buffer from a pool.
        // let mut buffer = self.optimization_manager.get_buffer(payload.len());
        // buffer.copy_from_slice(payload);
        if self.config.enable_xor_obfuscation {
            if let Some(xo) = self.xor_obfuscator.as_ref() {
                debug!("Applying XOR obfuscation to outgoing packet.");
                xo.obfuscate(payload);
            }
        }

        // HTTP/3 Masquerading is applied at the stream level when sending data,
        // not on raw packets here.
    }

    /// Processes an incoming packet payload, reversing stealth techniques.
    pub fn process_incoming_packet(&self, payload: &mut [u8]) {
        if self.config.enable_xor_obfuscation {
            if let Some(xo) = self.xor_obfuscator.as_ref() {
                debug!("Reversing XOR obfuscation on incoming packet.");
                xo.deobfuscate(payload);
            }
        }
    }

    /// Processes a TLS ClientHello message before it is sent.
    pub fn process_client_hello(&self, payload: &mut [u8]) {
        if self.config.enable_xor_obfuscation {
            if let Some(xo) = self.xor_obfuscator.as_ref() {
                debug!("Obfuscating ClientHello payload.");
                xo.obfuscate(payload);
            }
        }
    }

    /// Obfuscates arbitrary payload data within a specific context.
    pub fn obfuscate_payload(&self, payload: &mut [u8], _context_id: u64) {
        if self.config.enable_xor_obfuscation {
            if let Some(xo) = self.xor_obfuscator.as_ref() {
                debug!("Obfuscating payload for context {}", _context_id);
                xo.obfuscate(payload);
            }
        }
    }

    /// Generates HTTP/3 headers for masquerading a request.
    pub fn get_http3_masquerade_headers(&self, host: &str, path: &str) -> Option<Vec<u8>> {
        if self.config.enable_http3_masquerading {
            let fp = match self.fingerprint.lock() {
                Ok(g) => g,
                Err(p) => {
                    warn!("fingerprint mutex poisoned; recovering");
                    p.into_inner()
                }
            };
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
                let mut out = vec![0u8; 4096];
                let written = match enc.encode(&headers, out.as_mut_slice()) {
                    Ok(n) => n,
                    Err(e) => {
                        warn!("QPACK encode failed: {}", e);
                        0
                    }
                };
                out.truncate(written);
                Some(out)
            }
        } else {
            None
        }
    }

    /// Returns a vector of HTTP/3 headers for a request.
    pub fn get_http3_header_list(&self, host: &str, path: &str) -> Option<Vec<quiche::h3::Header>> {
        if self.config.enable_http3_masquerading {
            let fp = match self.fingerprint.lock() {
                Ok(g) => g,
                Err(p) => {
                    warn!("fingerprint mutex poisoned; recovering");
                    p.into_inner()
                }
            };
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
