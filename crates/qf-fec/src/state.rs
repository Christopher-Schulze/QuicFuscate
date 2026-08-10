//! Root-independent FEC state contracts exposed by the adaptive controller.

use crate::{FecControlPolicy, FecMode};

/// Connection-local FEC evidence returned to the transport and control planes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct FecTelemetrySnapshot {
    /// Whether packet-level collection is enabled for this connection.
    pub enabled: bool,
    /// Operator-owned control policy.
    pub control_policy: FecControlPolicy,
    /// Currently committed codec mode.
    pub active_mode: FecMode,
    /// Effective source-packet window for the committed mode.
    pub effective_window: usize,
    /// Cumulative packets covered by loss-controller observations.
    pub observed_packets: u64,
    /// Cumulative lost packets covered by loss-controller observations.
    pub observed_lost_packets: u64,
    /// Committed codec transitions.
    pub mode_transitions: u64,
    /// Accepted operator-policy transitions.
    pub policy_transitions: u64,
    /// Source datagrams serialized into the network-facing output buffer.
    pub source_packets_sent: u64,
    /// Repair datagrams serialized into the network-facing output buffer.
    pub repair_packets_sent: u64,
    /// Original QUIC payload bytes represented by sent source datagrams.
    pub source_payload_bytes_sent: u64,
    /// Source wire bytes serialized for transmission.
    pub source_wire_bytes_sent: u64,
    /// Repair wire bytes serialized for transmission.
    pub repair_wire_bytes_sent: u64,
    /// Accepted source datagrams received.
    pub source_packets_received: u64,
    /// Accepted repair datagrams received.
    pub repair_packets_received: u64,
    /// Original QUIC payload bytes represented by received source datagrams.
    pub source_payload_bytes_received: u64,
    /// Accepted source wire bytes received.
    pub source_wire_bytes_received: u64,
    /// Accepted repair wire bytes received.
    pub repair_wire_bytes_received: u64,
    /// Source packets delivered to QUIC, originals plus recoveries.
    pub decoded_packets: u64,
    /// Source packets reconstructed from repair data.
    pub recovered_packets: u64,
    /// Original QUIC payload bytes reconstructed from repair data.
    pub recovered_payload_bytes: u64,
}

impl FecTelemetrySnapshot {
    /// Create an empty connection-local telemetry snapshot.
    #[doc(hidden)]
    pub fn new(
        enabled: bool,
        control_policy: FecControlPolicy,
        active_mode: FecMode,
        effective_window: usize,
    ) -> Self {
        Self {
            enabled,
            control_policy,
            active_mode,
            effective_window,
            observed_packets: 0,
            observed_lost_packets: 0,
            mode_transitions: 0,
            policy_transitions: 0,
            source_packets_sent: 0,
            repair_packets_sent: 0,
            source_payload_bytes_sent: 0,
            source_wire_bytes_sent: 0,
            repair_wire_bytes_sent: 0,
            source_packets_received: 0,
            repair_packets_received: 0,
            source_payload_bytes_received: 0,
            source_wire_bytes_received: 0,
            repair_wire_bytes_received: 0,
            decoded_packets: 0,
            recovered_packets: 0,
            recovered_payload_bytes: 0,
        }
    }
}

/// Atomic result of changing one live connection's operator-owned FEC policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct FecPolicyChange {
    /// Policy effective before the command.
    pub previous_policy: FecControlPolicy,
    /// Codec mode effective before the command.
    pub previous_mode: FecMode,
    /// Policy effective when the command returned.
    pub effective_policy: FecControlPolicy,
    /// Codec mode effective when the command returned.
    pub effective_mode: FecMode,
}

/// Atomic result of changing one live connection's operator-owned FEC policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct ActiveFecPolicyChange {
    /// Controller-level policy and mode transition.
    pub controller: FecPolicyChange,
    /// Source datagrams preserved across the command boundary.
    pub queued_sources_preserved: usize,
    /// Repair-only datagrams discarded before acknowledgement.
    pub queued_repairs_discarded: usize,
}
