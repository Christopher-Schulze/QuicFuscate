//! Core owner for the authenticated private packet-protection control exchange.
//!
//! The transport owns packet keys. This module owns only bounded control state and the
//! authenticated message queue that bridges H3/MASQUE events to that transport owner.

use super::*;
use crate::qftls::{
    PrivateNegotiationKind, PrivateNegotiationMachine, PrivateNegotiationMessage,
    PrivateNegotiationRole, PrivateNegotiationState, PrivateProtocolError,
};
use qf_crypto::PacketProtectionMode;
use std::collections::VecDeque;
use std::sync::Arc;

impl QuicFuscateConnection {
    fn private_packet_protection_role(&self) -> crate::qftls::PrivateNegotiationRole {
        if self.conn.is_server() {
            crate::qftls::PrivateNegotiationRole::Server
        } else {
            crate::qftls::PrivateNegotiationRole::Client
        }
    }

    pub(super) fn ensure_private_packet_protection_runtime(
        &mut self,
    ) -> Result<bool, crate::error::ConnectionError> {
        if self.private_packet_protection_runtime.is_some()
            || self.private_packet_protection_mode == PacketProtectionMode::Standard
        {
            return Ok(self.private_packet_protection_runtime.is_some());
        }
        let control_available = if self.conn.is_server() {
            self.peer_private_packet_protection_control_available()
        } else {
            self.local_private_packet_protection_control_available()
        };
        if !self.conn.tls_handshake_complete()
            || self.authenticated_qkey_transcript_hash.is_none()
            || !control_available
        {
            return Ok(false);
        }
        let Some(family) = self.private_packet_protection_family else {
            return Ok(false);
        };
        let Some((original_dcid, current_dcid)) =
            self.conn.private_protocol_canonical_connection_ids()
        else {
            return Ok(false);
        };
        let generation_value = if self.conn.is_server() {
            self.masque_peer_generation().or(self.client_connection_generation)
        } else {
            self.client_connection_generation
        };
        let generation = u32::try_from(generation_value.unwrap_or(0))
            .map_err(|_| crate::error::ConnectionError::InvalidState)?;
        if generation == 0 {
            return Ok(false);
        }
        let qkey_hash = self
            .authenticated_qkey_transcript_hash
            .ok_or(crate::error::ConnectionError::InvalidState)?;
        let role = self.private_packet_protection_role();
        let mut context = Vec::with_capacity(128);
        context.extend_from_slice(crate::qftls::PRIVATE_EXPORTER_CONTEXT_DOMAIN);
        context.extend_from_slice(&generation.to_be_bytes());
        context.extend_from_slice(&self.conn.config_version().to_be_bytes());
        context.extend_from_slice(&qkey_hash);
        context.push(2);
        context.extend_from_slice(b"h3");
        context.push(u8::try_from(original_dcid.len()).unwrap_or(0));
        context.extend_from_slice(&original_dcid);
        context.push(u8::try_from(current_dcid.len()).unwrap_or(0));
        context.extend_from_slice(&current_dcid);
        let exporter_root = self.conn.export_keying_material(
            crate::qftls::PRIVATE_EXPORTER_LABEL,
            &context,
            crate::qftls::PRIVATE_HASH_LEN,
        )?;
        let mut nonce = [0u8; crate::qftls::PRIVATE_NONCE_LEN];
        crate::rng::fill_secure(&mut nonce).map_err(|_| {
            crate::error::ConnectionError::CryptoError(
                "private packet-protection nonce entropy unavailable".to_string(),
            )
        })?;
        let machine = crate::qftls::PrivateNegotiationMachine::new(
            self.private_packet_protection_mode,
            role,
            Some(family),
            generation,
            self.conn.config_version(),
            b"h3".to_vec(),
            original_dcid,
            current_dcid,
            qkey_hash,
            nonce,
        )
        .map_err(|error| crate::error::ConnectionError::CryptoError(error.to_string()))?;
        let mut runtime =
            PrivatePacketProtectionRuntime::new(self.private_packet_protection_mode, role, machine);
        runtime
            .machine_mut()
            .install_exporter_root(exporter_root.as_slice())
            .map_err(|error| crate::error::ConnectionError::CryptoError(error.to_string()))?;
        runtime
            .machine_mut()
            .mark_authenticated()
            .map_err(|error| crate::error::ConnectionError::CryptoError(error.to_string()))?;
        if role == crate::qftls::PrivateNegotiationRole::Client {
            runtime.start_client_proposal();
        }
        self.private_packet_protection_runtime = Some(Arc::new(std::sync::Mutex::new(runtime)));
        let callback_runtime = self
            .private_packet_protection_runtime
            .as_ref()
            .cloned()
            .ok_or(crate::error::ConnectionError::InvalidState)?;
        self.set_private_packet_protection_cb(Arc::new(std::sync::Mutex::new(Box::new(
            move |payload: &[u8]| {
                let mut runtime =
                    callback_runtime.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                runtime.receive(payload);
            },
        ))));
        Ok(true)
    }

    pub(crate) fn private_packet_protection_control_tick(
        &mut self,
    ) -> Result<(), crate::error::ConnectionError> {
        let _ = self.ensure_private_packet_protection_runtime()?;
        let Some(runtime) = self.private_packet_protection_runtime.as_ref().cloned() else {
            return Ok(());
        };
        let boundary = self.conn.next_application_send_packet_number()?.saturating_add(1);
        let mut activation_pending = false;
        let mut messages = Vec::new();
        {
            let mut runtime = runtime.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(error) = runtime.take_error() {
                if !private_protocol_error_is_fallback(&error)
                    || runtime.mode() == PacketProtectionMode::AdvancedRequired
                {
                    return Err(crate::error::ConnectionError::CryptoError(error.to_string()));
                }
            }
            runtime.ensure_local_confirmation(boundary);
            while let Some(payload) = runtime.take_outbound() {
                messages.push(payload);
            }
            if runtime.machine().state() == PrivateNegotiationState::SwitchScheduled
                && !runtime.owner_activation_attempted()
            {
                activation_pending = true;
            }
        }
        for (index, payload) in messages.iter().enumerate() {
            let result = if self.conn.is_server() {
                self.send_peer_private_packet_protection_capsule(payload)
            } else {
                self.send_private_packet_protection_capsule(payload)
            };
            if let Err(error) = result {
                let mut runtime = runtime.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                for pending in messages[index..].iter().rev() {
                    runtime.requeue_front(pending.clone());
                }
                return Err(error);
            }
        }
        if activation_pending {
            let mut runtime = runtime.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            runtime
                .machine_mut()
                .activate()
                .map_err(|error| crate::error::ConnectionError::CryptoError(error.to_string()))?;
            if let Err(error) = self.conn.activate_private_packet_protection(runtime.machine(), 1) {
                runtime.machine_mut().terminate();
                return Err(error);
            }
            runtime.mark_owner_activation_attempted();
        }
        Ok(())
    }
}

const MAX_OUTBOUND_MESSAGES: usize = 4;

pub(crate) struct PrivatePacketProtectionRuntime {
    mode: PacketProtectionMode,
    role: PrivateNegotiationRole,
    machine: PrivateNegotiationMachine,
    outbound: VecDeque<Vec<u8>>,
    last_error: Option<PrivateProtocolError>,
    owner_activation_attempted: bool,
    local_confirmation_queued: bool,
}

impl PrivatePacketProtectionRuntime {
    pub(crate) fn new(
        mode: PacketProtectionMode,
        role: PrivateNegotiationRole,
        machine: PrivateNegotiationMachine,
    ) -> Self {
        Self {
            mode,
            role,
            machine,
            outbound: VecDeque::with_capacity(MAX_OUTBOUND_MESSAGES),
            last_error: None,
            owner_activation_attempted: false,
            local_confirmation_queued: false,
        }
    }

    pub(crate) fn machine(&self) -> &PrivateNegotiationMachine {
        &self.machine
    }

    pub(crate) fn machine_mut(&mut self) -> &mut PrivateNegotiationMachine {
        &mut self.machine
    }

    pub(crate) fn mode(&self) -> PacketProtectionMode {
        self.mode
    }

    pub(crate) fn owner_activation_attempted(&self) -> bool {
        self.owner_activation_attempted
    }

    pub(crate) fn mark_owner_activation_attempted(&mut self) {
        self.owner_activation_attempted = true;
    }

    pub(crate) fn take_error(&mut self) -> Option<PrivateProtocolError> {
        self.last_error.take()
    }

    pub(crate) fn take_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    pub(crate) fn requeue_front(&mut self, payload: Vec<u8>) {
        if self.outbound.len() < MAX_OUTBOUND_MESSAGES {
            self.outbound.push_front(payload);
        } else {
            self.last_error = Some(PrivateProtocolError::PayloadTooLarge);
        }
    }

    pub(crate) fn start_client_proposal(&mut self) {
        if self.role != PrivateNegotiationRole::Client
            || self.machine.state() != PrivateNegotiationState::StandardAuthenticated
        {
            return;
        }
        match self.machine.build_proposal() {
            Ok(proposal) => {
                if let Err(error) = self.queue_message(&proposal) {
                    self.last_error = Some(error);
                }
            }
            Err(error) if !private_protocol_error_is_fallback(&error) => {
                self.last_error = Some(error);
            }
            Err(_) => {}
        }
    }

    pub(crate) fn ensure_local_confirmation(&mut self, boundary: u64) {
        if self.local_confirmation_queued
            || self.machine.state() != PrivateNegotiationState::SelectionConfirmed
        {
            return;
        }
        match self.machine.build_confirmation(boundary) {
            Ok(confirmation) => match self.queue_message(&confirmation) {
                Ok(()) => self.local_confirmation_queued = true,
                Err(error) => self.last_error = Some(error),
            },
            Err(error) => self.last_error = Some(error),
        }
    }

    pub(crate) fn queue_message(
        &mut self,
        message: &PrivateNegotiationMessage,
    ) -> Result<(), PrivateProtocolError> {
        if self.outbound.len() >= MAX_OUTBOUND_MESSAGES {
            return Err(PrivateProtocolError::PayloadTooLarge);
        }
        let encoded = self.machine.encode_message(message)?;
        self.outbound.push_back(encoded);
        Ok(())
    }

    /// Process one authenticated control payload. Boundary-bearing confirmations are completed by
    /// the Core owner after the callback returns, because only Core can read the transport PN.
    pub(crate) fn receive(&mut self, payload: &[u8]) {
        let result = (|| {
            let message = PrivateNegotiationMessage::decode(payload)?;
            match (self.role, message.kind) {
                (PrivateNegotiationRole::Server, PrivateNegotiationKind::Proposal) => {
                    self.machine.receive_proposal(&message)?;
                    let selection = self.machine.build_selection()?;
                    self.queue_message(&selection)?;
                }
                (PrivateNegotiationRole::Client, PrivateNegotiationKind::Selection) => {
                    self.machine.receive_selection(&message)?;
                }
                (_, PrivateNegotiationKind::Confirmation) => {
                    self.machine.receive_confirmation(&message)?;
                }
                _ => return Err(PrivateProtocolError::InvalidState),
            }
            Ok::<(), PrivateProtocolError>(())
        })();
        if let Err(error) = result {
            self.last_error = Some(error);
        }
    }
}

pub(crate) fn private_protocol_error_is_fallback(error: &PrivateProtocolError) -> bool {
    matches!(error, PrivateProtocolError::StandardFallback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qftls::{PRIVATE_HASH_LEN, PRIVATE_NONCE_LEN};
    use qf_crypto::PrivateAeadFamily;

    fn machine(role: PrivateNegotiationRole) -> PrivateNegotiationMachine {
        PrivateNegotiationMachine::new(
            PacketProtectionMode::Auto,
            role,
            Some(PrivateAeadFamily::Aegis128L),
            7,
            1,
            b"h3".to_vec(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            [0x44; PRIVATE_HASH_LEN],
            if role == PrivateNegotiationRole::Client {
                [0x11; PRIVATE_NONCE_LEN]
            } else {
                [0x22; PRIVATE_NONCE_LEN]
            },
        )
        .expect("machine")
    }

    fn runtime(role: PrivateNegotiationRole) -> PrivatePacketProtectionRuntime {
        let mut machine = machine(role);
        machine.install_exporter_root(&[0x77; PRIVATE_HASH_LEN]).expect("exporter root");
        machine.mark_authenticated().expect("authenticated state");
        PrivatePacketProtectionRuntime::new(PacketProtectionMode::Auto, role, machine)
    }

    #[test]
    fn runtime_routes_proposal_selection_and_confirmations() {
        let mut client = runtime(PrivateNegotiationRole::Client);
        let mut server = runtime(PrivateNegotiationRole::Server);

        client.start_client_proposal();
        let proposal = client.take_outbound().expect("client proposal");
        server.receive(&proposal);
        assert!(server.take_error().is_none());
        let selection = server.take_outbound().expect("server selection");

        client.receive(&selection);
        assert!(client.take_error().is_none());
        client.ensure_local_confirmation(100);
        server.ensure_local_confirmation(200);
        let client_confirmation = client.take_outbound().expect("client confirmation");
        let server_confirmation = server.take_outbound().expect("server confirmation");

        server.receive(&client_confirmation);
        client.receive(&server_confirmation);
        assert!(server.take_error().is_none());
        assert!(client.take_error().is_none());
        assert_eq!(client.machine().state(), PrivateNegotiationState::SwitchScheduled);
        assert_eq!(server.machine().state(), PrivateNegotiationState::SwitchScheduled);
    }
}
