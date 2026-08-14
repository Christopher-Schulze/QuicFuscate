use super::*;
use crate::fec::wire::WirePacketMeta;

pub(crate) const H3_TUNNEL_FRAME_MAGIC: &[u8; 4] = b"QFT1";
pub(crate) const H3_TUNNEL_FRAME_HEADER_LEN: usize = 6;
pub(crate) const MAX_INNER_IP_PACKET_LEN: usize = u16::MAX as usize;
pub(crate) const MAX_H3_TUNNEL_PENDING_LEN: usize =
    2 * (H3_TUNNEL_FRAME_HEADER_LEN + MAX_INNER_IP_PACKET_LEN);
pub(crate) const IPV6_MINIMUM_LINK_MTU: usize = 1280;
pub(crate) const MAX_BOUND_MASQUE_FLOWS: usize = qf_engine_types::MAX_CIRCUIT_HOPS as usize + 2;

#[derive(Default)]
pub(crate) struct H3TunnelFrameDecoder {
    pub(crate) pending: Vec<u8>,
}

impl H3TunnelFrameDecoder {
    pub(crate) fn push<F>(&mut self, data: &[u8], mut on_packet: F) -> Result<(), &'static str>
    where
        F: FnMut(&mut [u8]),
    {
        if self.pending.len().saturating_add(data.len()) > MAX_H3_TUNNEL_PENDING_LEN {
            self.pending.clear();
            return Err("H3 tunnel frame buffer exceeded its bounded capacity");
        }
        self.pending.extend_from_slice(data);

        let mut consumed = 0usize;
        while self.pending.len().saturating_sub(consumed) >= H3_TUNNEL_FRAME_HEADER_LEN {
            let header = &self.pending[consumed..consumed + H3_TUNNEL_FRAME_HEADER_LEN];
            if &header[..H3_TUNNEL_FRAME_MAGIC.len()] != H3_TUNNEL_FRAME_MAGIC {
                self.pending.clear();
                return Err("invalid H3 tunnel frame magic");
            }
            let packet_len = usize::from(u16::from_be_bytes([header[4], header[5]]));
            if packet_len == 0 {
                self.pending.clear();
                return Err("empty H3 tunnel packet");
            }
            let frame_len = H3_TUNNEL_FRAME_HEADER_LEN + packet_len;
            if self.pending.len() - consumed < frame_len {
                break;
            }
            let packet_start = consumed + H3_TUNNEL_FRAME_HEADER_LEN;
            let packet_end = consumed + frame_len;
            let packet = &mut self.pending[packet_start..packet_end];
            if !matches!(packet.first().map(|byte| byte >> 4), Some(4 | 6)) {
                self.pending.clear();
                return Err("H3 tunnel frame does not contain an IP packet");
            }
            on_packet(packet);
            consumed = packet_end;
        }

        if consumed > 0 {
            self.pending.drain(..consumed);
        }
        Ok(())
    }
}

pub(crate) struct Http3PollBindings {
    pub(crate) masque_datagram_cb: Option<DatagramHandler>,
    pub(crate) masque_control_cb: Option<CapsuleHandler>,
    pub(crate) masque_cb: Option<CapsuleHandler>,
    pub(crate) masque_relay_cb: Option<MasqueRelayHandler>,
    pub(crate) private_packet_protection_cb: Option<PrivatePacketProtectionHandler>,
    pub(crate) memory_pool: Arc<crate::optimize::MemoryPool>,
}

pub(crate) struct MasqueDispatchContext<'a> {
    pub(crate) bindings: &'a Http3PollBindings,
    pub(crate) normalizer: &'a PacketNormalizer,
    pub(crate) local_flows: &'a HashMap<u64, MasqueFlowBinding>,
    pub(crate) peer_flows: &'a HashMap<u64, MasqueFlowBinding>,
}

pub type PendingMasqueFlow =
    (u64, Option<MasqueUdpTarget>, MasqueFlowPurpose, Option<[u8; 16]>, Option<u8>);

/// Sink for an opaque UDP payload received on a purpose-bound MASQUE relay flow.
pub type MasqueRelayHandler =
    Arc<std::sync::Mutex<Box<dyn FnMut(u64, &MasqueUdpTarget, &[u8]) + Send>>>;

#[derive(Clone, Debug)]
pub(crate) struct MasqueFlowBinding {
    pub(crate) stream_id: u64,
    pub(crate) target: Option<MasqueUdpTarget>,
    pub(crate) purpose: MasqueFlowPurpose,
    pub(crate) generation: Option<u64>,
    pub(crate) circuit_id: Option<[u8; 16]>,
    pub(crate) hop_budget: Option<u8>,
    pub(crate) accepted: bool,
    pub(crate) control_sent: bool,
}

pub(crate) struct OutgoingFecPacket {
    pub(crate) packet: FecPacket,
    pub(crate) wire_meta: Option<WirePacketMeta>,
    pub(crate) send_info: crate::transport::SendInfo,
    pub(crate) congestion_controlled: bool,
}

impl OutgoingFecPacket {
    pub(crate) fn write_to(&self, buf: &mut [u8]) -> Result<usize, String> {
        let Some(meta) = self.wire_meta else {
            return self.packet.to_raw(buf);
        };
        let symbol = self.packet.payload_slice().ok_or_else(|| "No data available".to_string())?;
        let payload = if meta.systematic {
            wire::source_symbol_payload(symbol).map_err(|error| error.to_string())?
        } else {
            symbol
        };
        wire::write_packet(meta, payload, buf).map_err(|error| error.to_string())
    }

    pub(crate) fn telemetry_shape(&self) -> (bool, usize) {
        match self.wire_meta {
            None => (true, self.packet.data_len),
            Some(meta) if meta.systematic => {
                (true, self.packet.data_len.saturating_sub(2 * wire::SOURCE_LENGTH_LEN))
            }
            Some(_) => (false, 0),
        }
    }
}

#[derive(Default)]
pub(crate) struct OutboundPacer {
    pub(crate) next_release: Option<Instant>,
    pub(crate) burst_bytes: usize,
    pub(crate) burst_last_at: Option<Instant>,
}

impl OutboundPacer {
    pub(crate) fn next_release(&self) -> Option<Instant> {
        self.next_release
    }

    pub(crate) fn is_blocked(&mut self, now: Instant) -> bool {
        let Some(release) = self.next_release else {
            return false;
        };
        if now < release {
            return true;
        }
        self.next_release = None;
        false
    }

    pub(crate) fn record_send(
        &mut self,
        now: Instant,
        bytes: usize,
        send_quantum: usize,
        rate_bytes_per_second: u64,
    ) {
        if bytes == 0 {
            return;
        }
        if rate_bytes_per_second == 0 {
            self.burst_bytes = 0;
            self.burst_last_at = None;
            return;
        }
        if let Some(last_at) = self.burst_last_at {
            let elapsed_nanos = now.saturating_duration_since(last_at).as_nanos();
            let decayed = (u128::from(rate_bytes_per_second).saturating_mul(elapsed_nanos)
                / 1_000_000_000)
                .min(usize::MAX as u128) as usize;
            self.burst_bytes = self.burst_bytes.saturating_sub(decayed);
        }
        self.burst_last_at = Some(now);
        self.burst_bytes = self.burst_bytes.saturating_add(bytes);
        if self.burst_bytes < send_quantum.max(1) {
            return;
        }

        let paced_bytes = std::mem::take(&mut self.burst_bytes);
        self.burst_last_at = None;
        let numerator = (paced_bytes as u128).saturating_mul(1_000_000_000);
        let denominator = rate_bytes_per_second as u128;
        let delay_nanos = numerator.div_ceil(denominator).max(1).min(u64::MAX as u128) as u64;
        self.next_release = Some(now + Duration::from_nanos(delay_nanos));
    }

    pub(crate) fn reset(&mut self) {
        self.next_release = None;
        self.burst_bytes = 0;
        self.burst_last_at = None;
    }
}

/// Parameters for creating a new QuicFuscateConnection.
pub struct ConnectionParams {
    /// Monotonic clock shared by transport, H3, stealth, and TLS.
    pub clock: crate::time_source::ProtocolClock,
    /// Underlying QUIC transport connection.
    pub conn: Box<crate::transport::Connection>,
    /// Local socket address.
    pub local_addr: SocketAddr,
    /// Remote socket address.
    pub peer_addr: SocketAddr,
    /// HTTP Host header value (may differ from SNI when domain fronting).
    pub host_header: String,
    /// TLS SNI hostname override (None uses host_header).
    pub sni_host: Option<String>,
    /// QKey authentication token in hex (client mode only).
    pub qkey_auth_token_hex: Option<qf_engine_types::QKeyToken>,
    /// Shared stealth manager for obfuscation and fingerprint control.
    pub stealth_manager: Arc<StealthManager>,
    /// Shared optimization manager for memory pool and CPU feature detection.
    pub optimization_manager: Arc<OptimizationManager>,
    /// Forward error correction configuration.
    pub fec_config: FecConfig,
    /// Frozen raw-IP normalizer for decoded client-to-server tunnel ingress.
    ///
    /// It is never applied to sealed QUIC packets or ordinary server-to-client
    /// raw-IP downlink payloads.
    pub tunnel_ingress_normalizer: PacketNormalizer,
    /// Authenticated private packet-protection policy for this connection.
    pub private_packet_protection_mode: qf_crypto::PacketProtectionMode,
    /// Frozen product family selected by the engine policy, if private mode is enabled.
    pub private_packet_protection_family: Option<qf_crypto::PrivateAeadFamily>,
}
