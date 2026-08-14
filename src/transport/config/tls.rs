use super::Config;
use rustls::pki_types::pem::PemObject;
use zeroize::Zeroizing;

impl Config {
    /// Enables or disables TLS peer certificate verification.
    pub fn verify_peer(&mut self, verify: bool) {
        self.verify_peer = verify;
    }

    /// Loads certificate chain from file.
    pub fn load_cert_chain_from_pem_file(
        &mut self,
        path: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        let cert_data = std::fs::read(path).map_err(|e| {
            crate::error::ConnectionError::TlsError(format!(
                "Certificate chain read failed ({}): {}",
                path, e
            ))
        })?;
        let certs = rustls::pki_types::CertificateDer::pem_slice_iter(&cert_data)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                crate::error::ConnectionError::TlsError(format!(
                    "Certificate chain parse failed ({}): {}",
                    path, e
                ))
            })?;
        if certs.is_empty() {
            return Err(crate::error::ConnectionError::TlsError(format!(
                "Certificate chain parse failed ({}): no certificates found",
                path
            )));
        }
        self.cert_chain_path = Some(path.to_string());
        Ok(())
    }

    /// Loads private key from file.
    pub fn load_priv_key_from_pem_file(
        &mut self,
        path: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        let key_data = Zeroizing::new(std::fs::read(path).map_err(|e| {
            crate::error::ConnectionError::TlsError(format!(
                "Private key read failed ({}): {}",
                path, e
            ))
        })?);
        rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_data).map_err(|e| {
            crate::error::ConnectionError::TlsError(format!(
                "Private key parse failed ({}): {}",
                path, e
            ))
        })?;
        self.priv_key_path = Some(path.to_string());
        Ok(())
    }

    /// Loads CA certificates from a PEM file for peer verification.
    pub fn load_verify_locations_from_file(
        &mut self,
        file: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        let ca_data = std::fs::read(file).map_err(|e| {
            crate::error::ConnectionError::TlsError(format!(
                "CA file read failed ({}): {}",
                file, e
            ))
        })?;
        let certs = rustls::pki_types::CertificateDer::pem_slice_iter(&ca_data)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                crate::error::ConnectionError::TlsError(format!(
                    "CA file parse failed ({}): {}",
                    file, e
                ))
            })?;
        if certs.is_empty() {
            return Err(crate::error::ConnectionError::TlsError(format!(
                "CA file parse failed ({}): no certificates found",
                file
            )));
        }
        let mut roots = rustls::RootCertStore::empty();
        for cert in certs {
            roots.add(cert).map_err(|error| {
                crate::error::ConnectionError::TlsError(format!(
                    "CA certificate validation failed ({}): {}",
                    file, error
                ))
            })?;
        }
        self.verify_locations_file = Some(file.to_string());
        Ok(())
    }

    /// Sets a CA certificate directory for peer verification.
    pub fn load_verify_locations_from_directory(
        &mut self,
        dir: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        let meta = std::fs::metadata(dir).map_err(|e| {
            crate::error::ConnectionError::TlsError(format!(
                "CA directory stat failed ({}): {}",
                dir, e
            ))
        })?;
        if !meta.is_dir() {
            return Err(crate::error::ConnectionError::TlsError(format!(
                "CA directory is not a directory ({})",
                dir
            )));
        }
        std::fs::read_dir(dir).map_err(|e| {
            crate::error::ConnectionError::TlsError(format!(
                "CA directory read failed ({}): {}",
                dir, e
            ))
        })?;
        self.verify_locations_directory = Some(dir.to_string());
        Ok(())
    }

    /// Installs a TLS session ticket encryption key (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_ticket_key(&mut self, _key: &[u8]) -> Result<(), crate::error::ConnectionError> {
        if _key.is_empty() {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        self.ticket_key =
            Some(crate::secret::SecretBytes::new(_key.to_vec(), "tls_ticket_encryption_key"));
        Ok(())
    }

    /// Configures qlog output at default verbosity (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_qlog(
        &mut self,
        path: &str,
        title: &str,
        desc: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        self.set_qlog_with_level(path, title, desc, 0)
    }

    /// Configures qlog output with a specific verbosity level (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_qlog_with_level(
        &mut self,
        path: &str,
        title: &str,
        desc: &str,
        level: u32,
    ) -> Result<(), crate::error::ConnectionError> {
        self.qlog_config = Some((path.to_string(), title.to_string(), desc.to_string(), level));
        Ok(())
    }

    /// Returns `Some(())` if qlog is configured, `None` otherwise.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn qlog_streamer(&self) -> Option<()> {
        self.qlog_config.as_ref().map(|_| ())
    }

    /// Stores a TLS session ticket for 0-RTT resumption (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_session(&mut self, ticket: &[u8]) {
        self.tls_session =
            Some(crate::secret::SecretBytes::new(ticket.to_vec(), "tls_config_session_ticket"));
    }

    /// Sets initial congestion window for the handshake phase (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_initial_congestion_window_packets_in_handshake(&mut self, v: usize) {
        self.set_initial_congestion_window_packets(v);
    }

    /// Enables or disables HyStart++ during the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_hystart_in_handshake(&mut self, v: bool) {
        self.enable_hystart(v);
    }

    /// Enables or disables send pacing during the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_pacing_in_handshake(&mut self, v: bool) {
        self.enable_pacing(v);
    }

    /// Sets the max pacing rate (bytes/s) for the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_max_pacing_rate_in_handshake(&mut self, v: u64) {
        self.set_max_pacing_rate(v);
    }

    /// Sets max UDP payload size during the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_max_send_udp_payload_size_in_handshake(&mut self, v: usize) {
        self.set_max_send_udp_payload_size(v);
    }

    /// Sets send capacity factor during the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_send_capacity_factor_in_handshake(&mut self, v: u64) {
        self.set_send_capacity_factor(v as f64);
    }

    /// Enables or disables PMTU discovery during the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_discover_pmtu_in_handshake(&mut self, v: bool) {
        self.discover_pmtu(v);
    }

    /// Sets the max idle timeout during the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_max_idle_timeout_in_handshake(&mut self, v: u64) {
        self.set_max_idle_timeout(v);
    }

    /// Sets initial max bidirectional streams during the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_initial_max_streams_bidi_in_handshake(&mut self, v: u64) {
        self.initial_max_streams_bidi = v;
    }

    /// Sets initial max unidirectional streams during the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_initial_max_streams_uni_in_handshake(&mut self, v: u64) {
        self.initial_max_streams_uni = v;
    }

    /// Sets congestion control algorithm for the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_cc_algorithm_in_handshake(&mut self, algo: super::CongestionControlAlgorithm) {
        self.set_cc_algorithm(algo);
    }

    /// Sets congestion control algorithm by name for the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_cc_algorithm_name_in_handshake(
        &mut self,
        name: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        self.set_cc_algorithm_name(name)
    }

    /// Injects custom BBR tuning bytes for the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_custom_bbr_settings_in_handshake(&mut self, s: &[u8]) {
        self.custom_bbr_settings = if s.is_empty() { None } else { Some(s.to_vec()) };
    }
}
