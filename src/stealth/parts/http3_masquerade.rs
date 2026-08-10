// --- 3. HTTP/3 Masquerading ---

pub use qf_stealth::Http3Masquerade;

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
    pub fn header_list(&self, host: &str, path: &str) -> Vec<qf_transport_types::h3::Header> {
        let mut headers = Http3Masquerade::new(self.profile.clone()).generate_headers(host, path);
        if self.cfg.optimize_for_quic {
            headers.retain(|header| header.name() != b"connection");
        }
        headers
    }
}
