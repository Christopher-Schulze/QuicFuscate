use super::*;

impl CryptoContext {
    /// Return the exact effective packet-key owners installed on this connection.
    pub fn packet_protection_snapshot(&self) -> crate::qftls::PacketProtectionSnapshot {
        self.packet_protection
    }

    /// Install a fully authenticated private 1-RTT payload owner.
    ///
    /// The caller must already have completed the private negotiation state machine. This
    /// method accepts only exact family material and never changes QUIC header protection.
    #[allow(
        clippy::too_many_arguments,
        reason = "the authenticated installer keeps both directional key/IV material and boundaries explicit"
    )]
    #[allow(dead_code, reason = "compatibility installer retained for direct transport tests")]
    pub(crate) fn install_authenticated_private_1rtt(
        &mut self,
        family: qf_crypto::PrivateAeadFamily,
        write_key: &[u8],
        write_iv: &[u8],
        read_key: &[u8],
        read_iv: &[u8],
        write_boundary: u64,
        read_boundary: u64,
    ) -> Result<(), ConnectionError> {
        self.install_authenticated_private_1rtt_with_schedule(
            family,
            write_key,
            write_iv,
            read_key,
            read_iv,
            write_boundary,
            read_boundary,
            None,
            None,
            None,
            false,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the authenticated installer keeps directional material, boundaries, and schedule ownership explicit"
    )]
    pub(crate) fn install_authenticated_private_1rtt_with_schedule(
        &mut self,
        family: qf_crypto::PrivateAeadFamily,
        write_key: &[u8],
        write_iv: &[u8],
        read_key: &[u8],
        read_iv: &[u8],
        write_boundary: u64,
        read_boundary: u64,
        schedule: Option<crate::qftls::PrivateEpochSchedule>,
        write_direction: Option<crate::qftls::PrivateDirection>,
        read_direction: Option<crate::qftls::PrivateDirection>,
        initial_read_key_phase: bool,
    ) -> Result<(), ConnectionError> {
        if write_boundary == 0
            || read_boundary == 0
            || write_boundary > MAX_QUIC_VARINT
            || read_boundary > MAX_QUIC_VARINT
        {
            return Err(ConnectionError::InvalidState);
        }
        if self.seal_1rtt.is_none()
            || self.open_1rtt.is_none()
            || self.hp_1rtt.is_none()
            || self.hp_1rtt_open.is_none()
        {
            return Err(ConnectionError::InvalidState);
        }
        if self.private_seal_1rtt.is_some()
            || self.private_open_1rtt.is_some()
            || self.private_write_boundary_1rtt.is_some()
            || self.private_read_boundary_1rtt.is_some()
        {
            return Err(ConnectionError::InvalidState);
        }
        if !matches!(
            self.packet_protection.one_rtt.packet_aead_owner,
            crate::qftls::PacketProtectionOwner::RustlsStandard
                | crate::qftls::PacketProtectionOwner::TransportStandard
        ) || !matches!(
            self.packet_protection.one_rtt.header_protection_owner,
            crate::qftls::PacketProtectionOwner::RustlsStandard
                | crate::qftls::PacketProtectionOwner::TransportStandard
        ) {
            return Err(ConnectionError::InvalidState);
        }
        let (private_seal, _) =
            qf_crypto::select_private_packet_data_aead(family, write_key, write_iv)?;
        let (_, private_open) =
            qf_crypto::select_private_packet_data_aead(family, read_key, read_iv)?;
        self.private_seal_1rtt = Some(Arc::new(private_seal));
        self.private_open_1rtt = Some(Arc::new(private_open));
        self.private_next_open_1rtt = None;
        self.private_write_boundary_1rtt = Some(write_boundary);
        self.private_read_boundary_1rtt = Some(read_boundary);
        self.private_read_start_1rtt = Some(read_boundary);
        self.private_read_key_phase_1rtt = initial_read_key_phase;
        self.private_read_update_pending_1rtt = false;
        self.private_previous_read_1rtt.clear();
        self.private_epoch_schedule = schedule;
        self.private_write_direction = write_direction;
        self.private_read_direction = read_direction;
        self.private_write_epoch = 1;
        self.private_read_epoch = 1;
        self.private_read_update_pending_1rtt = false;
        self.packet_protection.one_rtt.packet_aead_owner =
            crate::qftls::PacketProtectionOwner::PrivateAdvanced;
        Ok(())
    }

    fn clear_private_1rtt(&mut self) {
        self.private_seal_1rtt = None;
        self.private_open_1rtt = None;
        self.private_next_open_1rtt = None;
        self.private_write_boundary_1rtt = None;
        self.private_read_boundary_1rtt = None;
        self.private_read_start_1rtt = None;
        self.private_read_key_phase_1rtt = false;
        self.private_read_update_pending_1rtt = false;
        self.private_previous_read_1rtt.clear();
        self.private_epoch_schedule = None;
        self.private_write_direction = None;
        self.private_read_direction = None;
        self.private_write_epoch = 0;
        self.private_read_epoch = 0;
    }

    /// Returns true while an Initial or Handshake flight still needs transmission.
    pub fn has_pending_handshake_send(&self) -> bool {
        self.crypto_initial.has_pending_send() || self.crypto_handshake.has_pending_send()
    }

    /// Installs 0-RTT read and write keys from the given TLS secrets.
    pub fn install_0rtt_keys(
        &mut self,
        read_secret: &[u8],
        write_secret: &[u8],
    ) -> Result<(), ConnectionError> {
        let (read_key, read_iv) = derive_key_iv(read_secret)?;
        let (write_key, write_iv) = derive_key_iv(write_secret)?;
        let write_hp = derive_hp_key(write_secret)?;
        let read_hp = derive_hp_key(read_secret)?;
        let (_, open) = select_packet_data_aead(&read_key, &read_iv);
        let (seal, _) = select_packet_data_aead(&write_key, &write_iv);
        self.zero_rtt_enabled = true;
        self.open_0rtt = Some(open);
        self.seal_0rtt = Some(seal);
        self.hp_0rtt = Some(Box::new(crate::crypto::aead::AesHp::from_key(&write_hp)));
        self.hp_0rtt_open = Some(Box::new(crate::crypto::aead::AesHp::from_key(&read_hp)));
        self.refresh_compatibility_zero_rtt_snapshot();
        Ok(())
    }
}

impl CryptoContext {
    /// Enables or disables 0-RTT key installation for this crypto context.
    pub fn set_zero_rtt_enabled(&mut self, enabled: bool) {
        self.zero_rtt_enabled = enabled;
        if enabled {
            self.refresh_compatibility_zero_rtt_snapshot();
        } else {
            self.open_0rtt = None;
            self.seal_0rtt = None;
            self.hp_0rtt = None;
            self.hp_0rtt_open = None;
            self.packet_protection.zero_rtt =
                crate::qftls::PacketProtectionLevelSnapshot::disabled();
        }
    }

    /// Install or rotate the TLS Cover cipher without permitting counter reuse.
    pub fn install_tls_cover_cipher(
        &mut self,
        material: TlsCoverKeyMaterial<'_>,
    ) -> Result<TlsCoverInstallOutcome, ConnectionError> {
        self.tls_cover_cipher.install(
            material,
            &mut self.tls_cover_write_seq,
            &mut self.tls_cover_read_seq,
        )
    }

    #[inline]
    /// Returns the TLS Cover cipher algorithm in use, if configured.
    pub fn tls_cover_cipher_kind(&self) -> Option<TlsCoverCipherKind> {
        self.tls_cover_cipher.cipher_kind()
    }

    /// Encrypt a TLS Cover record using the configured TLS Cover cipher.
    pub fn encrypt_tls_cover_record(
        &mut self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ConnectionError> {
        self.tls_cover_cipher.encrypt_record(&mut self.tls_cover_write_seq, aad, plaintext)
    }

    /// Decrypt a TLS Cover record using the configured TLS Cover cipher.
    pub fn decrypt_tls_cover_record(
        &mut self,
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, ConnectionError> {
        self.tls_cover_cipher.decrypt_record(&mut self.tls_cover_read_seq, aad, ciphertext)
    }

    /// Install AES-GCM for Initial packets (compatibility path).
    /// QUIC initial keys are direction-specific, so we accept read/write secrets separately.
    pub fn install_aes_gcm_initial(
        &mut self,
        read_secret: &[u8],
        write_secret: &[u8],
        version: u32,
    ) -> Result<(), ConnectionError> {
        let rkey = crate::crypto::kdf::derive_pkt_key_for_version(read_secret, 16, version)?;
        let wkey = crate::crypto::kdf::derive_pkt_key_for_version(write_secret, 16, version)?;
        let riv = crate::crypto::kdf::derive_pkt_iv_for_version(read_secret, 12, version)?;
        let wiv = crate::crypto::kdf::derive_pkt_iv_for_version(write_secret, 12, version)?;
        let mut k16 = [0u8; 16];
        let mut iv12 = [0u8; 12];
        k16.copy_from_slice(&wkey);
        iv12.copy_from_slice(&wiv);
        self.seal_initial = Some(Box::new(AesGcm128::from_arrays(&k16, &iv12)));
        k16.copy_from_slice(&rkey);
        iv12.copy_from_slice(&riv);
        self.open_initial = Some(Box::new(AesGcm128::from_arrays(&k16, &iv12)));
        self.packet_protection.initial.packet_aead_owner =
            crate::qftls::PacketProtectionOwner::QuicInitialStandard;
        self.packet_protection.initial.standard_cipher_suite =
            Some(crate::qftls::StandardCipherSuite::Aes128GcmSha256);
        // HP can be installed later when header protection keys are derived
        Ok(())
    }

    /// Install AES-GCM for Handshake packets (compatibility path)
    pub fn install_aes_gcm_handshake(&mut self, secret: &[u8]) -> Result<(), ConnectionError> {
        let (key, iv) = derive_key_iv(secret)?;
        let mut k16 = [0u8; 16];
        k16.copy_from_slice(&key[..16]);
        let seal = AesGcm128::from_arrays(&k16, &iv);
        let open = AesGcm128::from_arrays(&k16, &iv);
        self.seal_handshake = Some(Box::new(seal));
        self.open_handshake = Some(Box::new(open));
        self.refresh_transport_handshake_snapshot();
        // HP can be installed later when header protection keys are derived
        Ok(())
    }

    /// Install AES-based Header Protection for Initial packets.
    /// QUIC header protection is direction-specific, so we accept read/write secrets separately.
    pub fn install_hp_initial(
        &mut self,
        read_secret: &[u8],
        write_secret: &[u8],
        version: u32,
    ) -> Result<(), ConnectionError> {
        let hp_key_w = derive_hp_key_for_version(write_secret, version)?;
        let hp_key_r = derive_hp_key_for_version(read_secret, version)?;
        self.hp_initial = Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key_w)));
        self.hp_initial_open = Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key_r)));
        self.packet_protection.initial.header_protection_owner =
            crate::qftls::PacketProtectionOwner::QuicInitialStandard;
        self.packet_protection.initial.standard_cipher_suite =
            Some(crate::qftls::StandardCipherSuite::Aes128GcmSha256);
        Ok(())
    }

    /// Install AES-based Header Protection for Handshake packets
    pub fn install_hp_handshake(&mut self, secret: &[u8]) -> Result<(), ConnectionError> {
        let hp_key = derive_hp_key(secret)?;
        self.hp_handshake = Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
        self.hp_handshake_open = Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
        self.refresh_transport_handshake_snapshot();
        Ok(())
    }

    fn install_read_1rtt_secret(&mut self, secret: &[u8]) -> Result<(), ConnectionError> {
        let (key, iv) = derive_key_iv(secret)?;
        let (_, open) = select_packet_data_aead(&key, &iv);
        let hp_key = derive_hp_key(secret)?;
        self.open_1rtt = Some(Arc::new(open));
        self.hp_1rtt_open = Some(Arc::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
        self.refresh_compatibility_one_rtt_snapshot();
        Ok(())
    }

    fn install_write_1rtt_secret(&mut self, secret: &[u8]) -> Result<(), ConnectionError> {
        let (key, iv) = derive_key_iv(secret)?;
        let (seal, _) = select_packet_data_aead(&key, &iv);
        let hp_key = derive_hp_key(secret)?;
        self.seal_1rtt = Some(Arc::new(seal));
        self.hp_1rtt = Some(Arc::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
        self.refresh_compatibility_one_rtt_snapshot();
        Ok(())
    }

    fn refresh_compatibility_zero_rtt_snapshot(&mut self) {
        let owner = if self.open_0rtt.is_some()
            && self.seal_0rtt.is_some()
            && self.hp_0rtt.is_some()
            && self.hp_0rtt_open.is_some()
        {
            crate::qftls::PacketProtectionOwner::TransportStandard
        } else {
            crate::qftls::PacketProtectionOwner::Transitioning
        };
        self.packet_protection.zero_rtt = crate::qftls::PacketProtectionLevelSnapshot {
            packet_aead_owner: owner,
            header_protection_owner: owner,
            standard_cipher_suite: Some(crate::qftls::StandardCipherSuite::Aes128GcmSha256),
        };
    }

    fn refresh_compatibility_one_rtt_snapshot(&mut self) {
        if self.private_seal_1rtt.is_some()
            && self.private_open_1rtt.is_some()
            && self.private_write_boundary_1rtt.is_some()
            && self.private_read_boundary_1rtt.is_some()
        {
            self.packet_protection.one_rtt.packet_aead_owner =
                crate::qftls::PacketProtectionOwner::PrivateAdvanced;
            return;
        }
        let owner = if self.open_1rtt.is_some()
            && self.seal_1rtt.is_some()
            && self.hp_1rtt.is_some()
            && self.hp_1rtt_open.is_some()
        {
            crate::qftls::PacketProtectionOwner::TransportStandard
        } else {
            crate::qftls::PacketProtectionOwner::Transitioning
        };
        self.packet_protection.one_rtt = crate::qftls::PacketProtectionLevelSnapshot {
            packet_aead_owner: owner,
            header_protection_owner: owner,
            standard_cipher_suite: Some(crate::qftls::StandardCipherSuite::Aes128GcmSha256),
        };
    }

    fn refresh_transport_handshake_snapshot(&mut self) {
        let owner = if self.open_handshake.is_some()
            && self.seal_handshake.is_some()
            && self.hp_handshake.is_some()
            && self.hp_handshake_open.is_some()
        {
            crate::qftls::PacketProtectionOwner::TransportStandard
        } else {
            crate::qftls::PacketProtectionOwner::Transitioning
        };
        self.packet_protection.handshake = crate::qftls::PacketProtectionLevelSnapshot {
            packet_aead_owner: owner,
            header_protection_owner: owner,
            standard_cipher_suite: Some(crate::qftls::StandardCipherSuite::Aes128GcmSha256),
        };
    }

    fn push_previous_read_key(&mut self, open: Arc<crate::crypto::PacketAeadOpen>) {
        self.previous_read_1rtt.push_back(PreviousRead1RttKey { open });
        while self.previous_read_1rtt.len() > ONE_RTT_READ_KEY_WINDOW {
            let _ = self.previous_read_1rtt.pop_front();
        }
    }

    fn push_previous_private_read_epoch(&mut self, epoch: PreviousPrivateReadEpoch) {
        self.private_previous_read_1rtt.push_back(epoch);
        while self.private_previous_read_1rtt.len() > PRIVATE_READ_EPOCH_WINDOW {
            let _ = self.private_previous_read_1rtt.pop_front();
        }
    }

    fn derive_private_read_epoch(
        &self,
        epoch: u32,
    ) -> Result<Arc<crate::crypto::PacketAeadOpen>, ConnectionError> {
        let schedule =
            self.private_epoch_schedule.as_ref().ok_or(ConnectionError::KeyUpdateError)?;
        let direction = self.private_read_direction.ok_or(ConnectionError::KeyUpdateError)?;
        let material = schedule
            .derive(direction, epoch)
            .map_err(|error| ConnectionError::CryptoError(error.to_string()))?;
        let (_, open) = qf_crypto::select_private_packet_data_aead(
            schedule.family(),
            material.key.as_slice(),
            material.iv.as_slice(),
        )?;
        Ok(Arc::new(open))
    }

    fn derive_private_write_epoch(
        &self,
        epoch: u32,
    ) -> Result<Arc<crate::crypto::PacketAeadSeal>, ConnectionError> {
        let schedule =
            self.private_epoch_schedule.as_ref().ok_or(ConnectionError::KeyUpdateError)?;
        let direction = self.private_write_direction.ok_or(ConnectionError::KeyUpdateError)?;
        let material = schedule
            .derive(direction, epoch)
            .map_err(|error| ConnectionError::CryptoError(error.to_string()))?;
        let (seal, _) = qf_crypto::select_private_packet_data_aead(
            schedule.family(),
            material.key.as_slice(),
            material.iv.as_slice(),
        )?;
        Ok(Arc::new(seal))
    }

    pub(super) fn stage_private_read_update(&mut self) -> Result<(), ConnectionError> {
        if self.private_open_1rtt.is_none() {
            return Ok(());
        }
        if self.private_read_update_pending_1rtt {
            return Err(ConnectionError::KeyUpdateError);
        }
        let next_epoch =
            self.private_read_epoch.checked_add(1).ok_or(ConnectionError::KeyUpdateError)?;
        let next = self.derive_private_read_epoch(next_epoch)?;
        self.private_next_open_1rtt = Some(next);
        self.private_read_update_pending_1rtt = true;
        Ok(())
    }

    /// Commit a private read epoch only after a packet authenticated with the new key phase.
    pub(crate) fn commit_private_read_epoch(
        &mut self,
        packet_number: u64,
        key_phase: bool,
    ) -> Result<bool, ConnectionError> {
        let Some(current_start) = self.private_read_start_1rtt else {
            return Ok(false);
        };
        let Some(current) = self.private_open_1rtt.as_ref() else {
            return Ok(false);
        };
        if packet_number < current_start || key_phase == self.private_read_key_phase_1rtt {
            return Ok(false);
        }
        if !self.private_read_update_pending_1rtt {
            return Err(ConnectionError::KeyUpdateError);
        }
        let next = self.private_next_open_1rtt.clone().ok_or(ConnectionError::KeyUpdateError)?;
        let next_epoch =
            self.private_read_epoch.checked_add(1).ok_or(ConnectionError::KeyUpdateError)?;
        let next_next = self.derive_private_read_epoch(
            next_epoch.checked_add(1).ok_or(ConnectionError::KeyUpdateError)?,
        )?;
        let previous = PreviousPrivateReadEpoch {
            open: current.clone(),
            start_packet_number: current_start,
            key_phase: self.private_read_key_phase_1rtt,
        };
        self.push_previous_private_read_epoch(previous);
        self.private_open_1rtt = Some(next);
        self.private_next_open_1rtt = Some(next_next);
        self.private_read_epoch = next_epoch;
        self.private_read_start_1rtt = Some(packet_number);
        self.private_read_key_phase_1rtt = key_phase;
        self.private_read_update_pending_1rtt = false;
        Ok(true)
    }

    /// Rotates the 1-RTT read key, pushing the old key into the read window.
    pub fn rotate_1rtt_read_keypair(
        &mut self,
        open: Box<dyn crate::crypto::aead::AeadOpen + Send + Sync>,
    ) -> Result<(), ConnectionError> {
        self.stage_private_read_update()?;
        if let Some(prev_open) = self.open_1rtt.take() {
            self.push_previous_read_key(prev_open);
        }
        self.open_1rtt = Some(Arc::new(crate::crypto::PacketAeadOpen::dynamic(open)));
        self.read_generation_1rtt = self.read_generation_1rtt.saturating_add(1);
        self.read_secret_1rtt = None;
        Ok(())
    }

    /// Rotates the 1-RTT write key, replacing the current sealer.
    pub fn rotate_1rtt_write_keypair(
        &mut self,
        seal: Box<dyn crate::crypto::aead::AeadSeal + Send + Sync>,
    ) -> Result<(), ConnectionError> {
        let private_next = if self.private_seal_1rtt.is_some() {
            let next_epoch =
                self.private_write_epoch.checked_add(1).ok_or(ConnectionError::KeyUpdateError)?;
            Some((next_epoch, self.derive_private_write_epoch(next_epoch)?))
        } else {
            None
        };
        self.seal_1rtt = Some(Arc::new(crate::crypto::PacketAeadSeal::dynamic(seal)));
        if let Some((next_epoch, private_seal)) = private_next {
            self.private_seal_1rtt = Some(private_seal);
            self.private_write_epoch = next_epoch;
        }
        self.write_generation_1rtt = self.write_generation_1rtt.saturating_add(1);
        self.write_secret_1rtt = None;
        Ok(())
    }

    /// Derives the next 1-RTT read secret and rotates the opener.
    pub fn key_update_1rtt_read(&mut self) -> Result<bool, ConnectionError> {
        let Some(cur) = self.read_secret_1rtt.clone() else {
            return Ok(false);
        };
        self.stage_private_read_update()?;
        let next = crate::crypto::kdf::derive_next_secret(cur.as_slice())?;
        let (key, iv) = derive_key_iv(&next)?;
        let (_, open) = select_packet_data_aead(&key, &iv);
        if let Some(prev_open) = self.open_1rtt.take() {
            self.push_previous_read_key(prev_open);
        }
        self.open_1rtt = Some(Arc::new(open));
        self.read_secret_1rtt = Some(crate::secret::SecretBytes::new(next, "tls_1rtt_read_secret"));
        self.read_generation_1rtt = self.read_generation_1rtt.saturating_add(1);
        Ok(true)
    }

    /// Derives the next 1-RTT write secret and rotates the sealer.
    pub fn key_update_1rtt_write(&mut self) -> Result<bool, ConnectionError> {
        let Some(cur) = self.write_secret_1rtt.as_deref() else {
            return Ok(false);
        };
        let next = crate::crypto::kdf::derive_next_secret(cur)?;
        let (key, iv) = derive_key_iv(&next)?;
        let (seal, _) = select_packet_data_aead(&key, &iv);
        let private_next = if self.private_seal_1rtt.is_some() {
            let next_epoch =
                self.private_write_epoch.checked_add(1).ok_or(ConnectionError::KeyUpdateError)?;
            Some((next_epoch, self.derive_private_write_epoch(next_epoch)?))
        } else {
            None
        };
        self.seal_1rtt = Some(Arc::new(seal));
        if let Some((next_epoch, private_seal)) = private_next {
            self.private_seal_1rtt = Some(private_seal);
            self.private_write_epoch = next_epoch;
        }
        self.write_secret_1rtt =
            Some(crate::secret::SecretBytes::new(next, "tls_1rtt_write_secret"));
        self.write_generation_1rtt = self.write_generation_1rtt.saturating_add(1);
        Ok(true)
    }

    /// Backwards-compatible helper for call sites that still update both directions together.
    pub fn key_update_1rtt(&mut self) -> Result<bool, ConnectionError> {
        let write = self.key_update_1rtt_write()?;
        let read = self.key_update_1rtt_read()?;
        Ok(write || read)
    }
}

impl crate::qftls::QuicTlsKeyInstaller for parking_lot::RwLock<CryptoContext> {
    fn clear_handshake_and_one_rtt_keys(&self) {
        let mut crypto = self.write();
        crypto.seal_handshake = None;
        crypto.open_handshake = None;
        crypto.hp_handshake = None;
        crypto.hp_handshake_open = None;
        crypto.seal_1rtt = None;
        crypto.open_1rtt = None;
        crypto.hp_1rtt = None;
        crypto.hp_1rtt_open = None;
        crypto.clear_private_1rtt();
        crypto.read_secret_1rtt = None;
        crypto.write_secret_1rtt = None;
        crypto.read_generation_1rtt = 0;
        crypto.write_generation_1rtt = 0;
        crypto.previous_read_1rtt.clear();
        crypto.packet_protection.handshake =
            crate::qftls::PacketProtectionLevelSnapshot::uninstalled();
        crypto.packet_protection.one_rtt =
            crate::qftls::PacketProtectionLevelSnapshot::uninstalled();
        crypto.packet_protection.negotiated_tls_cipher_suite = None;
    }

    fn install_handshake_keys(&self, keys: crate::qftls::QuicTlsHandshakeKeys) {
        let mut crypto = self.write();
        match keys.standard_cipher_suite {
            crate::qftls::StandardCipherSuite::Aes128GcmSha256 => {
                qf_telemetry::QUIC_HANDSHAKE_AES128_KEY_INSTALLS.inc();
            }
            crate::qftls::StandardCipherSuite::Aes256GcmSha384 => {
                qf_telemetry::QUIC_HANDSHAKE_AES256_KEY_INSTALLS.inc();
            }
        }
        crypto.seal_handshake = Some(keys.seal);
        crypto.open_handshake = Some(keys.open);
        crypto.hp_handshake = Some(keys.hp_seal);
        crypto.hp_handshake_open = Some(keys.hp_open);
        crypto.packet_protection.handshake = crate::qftls::PacketProtectionLevelSnapshot {
            packet_aead_owner: crate::qftls::PacketProtectionOwner::RustlsStandard,
            header_protection_owner: crate::qftls::PacketProtectionOwner::RustlsStandard,
            standard_cipher_suite: Some(keys.standard_cipher_suite),
        };
        crypto.packet_protection.negotiated_tls_cipher_suite = Some(keys.standard_cipher_suite);
    }

    fn install_one_rtt_keys(&self, keys: crate::qftls::QuicTlsOneRttKeys) {
        let mut crypto = self.write();
        match keys.standard_cipher_suite {
            crate::qftls::StandardCipherSuite::Aes128GcmSha256 => {
                qf_telemetry::QUIC_ONE_RTT_AES128_KEY_INSTALLS.inc();
            }
            crate::qftls::StandardCipherSuite::Aes256GcmSha384 => {
                qf_telemetry::QUIC_ONE_RTT_AES256_KEY_INSTALLS.inc();
            }
        }
        crypto.seal_1rtt = Some(keys.seal);
        crypto.open_1rtt = Some(keys.open);
        crypto.hp_1rtt = Some(keys.hp_seal);
        crypto.hp_1rtt_open = Some(keys.hp_open);
        crypto.clear_private_1rtt();
        crypto.read_secret_1rtt = None;
        crypto.write_secret_1rtt = None;
        crypto.read_generation_1rtt = 0;
        crypto.write_generation_1rtt = 0;
        crypto.previous_read_1rtt.clear();
        crypto.packet_protection.one_rtt = crate::qftls::PacketProtectionLevelSnapshot {
            packet_aead_owner: crate::qftls::PacketProtectionOwner::RustlsStandard,
            header_protection_owner: crate::qftls::PacketProtectionOwner::RustlsStandard,
            standard_cipher_suite: Some(keys.standard_cipher_suite),
        };
        crypto.packet_protection.negotiated_tls_cipher_suite = Some(keys.standard_cipher_suite);
    }

    fn has_one_rtt_keys(&self) -> bool {
        let crypto = self.read();
        crypto.seal_1rtt.is_some()
            && crypto.open_1rtt.is_some()
            && crypto.hp_1rtt.is_some()
            && crypto.hp_1rtt_open.is_some()
    }

    fn key_update_1rtt_read(&self) -> Result<bool, ConnectionError> {
        self.write().key_update_1rtt_read()
    }

    fn key_update_1rtt_write(&self) -> Result<bool, ConnectionError> {
        self.write().key_update_1rtt_write()
    }

    fn rotate_1rtt_read_keypair(
        &self,
        open: Box<dyn qf_crypto::aead::AeadOpen + Send + Sync>,
    ) -> Result<(), ConnectionError> {
        self.write().rotate_1rtt_read_keypair(open)
    }

    fn rotate_1rtt_write_keypair(
        &self,
        seal: Box<dyn qf_crypto::aead::AeadSeal + Send + Sync>,
    ) -> Result<(), ConnectionError> {
        self.write().rotate_1rtt_write_keypair(seal)
    }
}

// Install AEAD/HP from TLS key schedule.
impl crate::crypto::aead::KeyScheduleHooks for CryptoContext {
    fn set_read_secret(
        &mut self,
        level: crate::crypto::aead::Level,
        alg: crate::crypto::aead::Algorithm,
        secret: &[u8],
    ) -> Result<(), ConnectionError> {
        let (key, iv) = derive_key_iv(secret)?;
        match level {
            crate::crypto::aead::Level::Initial => {
                match alg {
                    crate::crypto::aead::Algorithm::AES128_GCM => {
                        let mut k16 = [0u8; 16];
                        k16.copy_from_slice(&key[..16]);
                        self.open_initial = Some(Box::new(AesGcm128::from_arrays(&k16, &iv)));
                    }
                }
                let hp_key = derive_hp_key(secret)?;
                self.hp_initial_open =
                    Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
            }
            crate::crypto::aead::Level::Handshake => {
                match alg {
                    crate::crypto::aead::Algorithm::AES128_GCM => {
                        let mut k16 = [0u8; 16];
                        k16.copy_from_slice(&key[..16]);
                        self.open_handshake = Some(Box::new(AesGcm128::from_arrays(&k16, &iv)));
                    }
                }
                let hp_key = derive_hp_key(secret)?;
                self.hp_handshake_open =
                    Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
                self.refresh_transport_handshake_snapshot();
            }
            crate::crypto::aead::Level::ZeroRTT => {
                if self.zero_rtt_enabled {
                    let (_, open) = select_packet_data_aead(&key, &iv);
                    self.open_0rtt = Some(open);
                    let hp_key = derive_hp_key(secret)?;
                    self.hp_0rtt_open =
                        Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
                    self.refresh_compatibility_zero_rtt_snapshot();
                }
            }
            crate::crypto::aead::Level::OneRTT => {
                self.install_read_1rtt_secret(secret)?;
                self.read_secret_1rtt =
                    Some(crate::secret::SecretBytes::new(secret.to_vec(), "tls_1rtt_read_secret"));
                self.read_generation_1rtt = 0;
                self.previous_read_1rtt.clear();
            }
        }
        Ok(())
    }
    fn set_write_secret(
        &mut self,
        level: crate::crypto::aead::Level,
        alg: crate::crypto::aead::Algorithm,
        secret: &[u8],
    ) -> Result<(), ConnectionError> {
        let (key, iv) = derive_key_iv(secret)?;
        match level {
            crate::crypto::aead::Level::Initial => {
                match alg {
                    crate::crypto::aead::Algorithm::AES128_GCM => {
                        let mut k16 = [0u8; 16];
                        k16.copy_from_slice(&key[..16]);
                        self.seal_initial = Some(Box::new(AesGcm128::from_arrays(&k16, &iv)));
                    }
                }
                let hp_key = derive_hp_key(secret)?;
                self.hp_initial = Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
            }
            crate::crypto::aead::Level::Handshake => {
                match alg {
                    crate::crypto::aead::Algorithm::AES128_GCM => {
                        let mut k16 = [0u8; 16];
                        k16.copy_from_slice(&key[..16]);
                        self.seal_handshake = Some(Box::new(AesGcm128::from_arrays(&k16, &iv)));
                    }
                }
                let hp_key = derive_hp_key(secret)?;
                self.hp_handshake = Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
                self.refresh_transport_handshake_snapshot();
            }
            crate::crypto::aead::Level::ZeroRTT => {
                if self.zero_rtt_enabled {
                    let (seal, _) = select_packet_data_aead(&key, &iv);
                    self.seal_0rtt = Some(seal);
                    let hp_key = derive_hp_key(secret)?;
                    self.hp_0rtt = Some(Box::new(crate::crypto::aead::AesHp::from_key(&hp_key)));
                    self.refresh_compatibility_zero_rtt_snapshot();
                }
            }
            crate::crypto::aead::Level::OneRTT => {
                self.install_write_1rtt_secret(secret)?;
                self.write_secret_1rtt =
                    Some(crate::secret::SecretBytes::new(secret.to_vec(), "tls_1rtt_write_secret"));
                self.write_generation_1rtt = 0;
            }
        }
        Ok(())
    }
}
