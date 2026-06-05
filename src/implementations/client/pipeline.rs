//! Packet processing pipeline for the client.
//!
//! This module implements the bidirectional packet flow:
//! - Outbound: TUN -> Stealth -> FEC -> QUIC
//! - Inbound: QUIC -> FEC -> Stealth -> TUN

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::{ClientSubsystems, FecCodec};

/// Pipeline statistics.
#[derive(Debug, Default)]
pub struct PipelineStats {
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub fec_recoveries: AtomicU64,
}

impl PipelineStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_outbound(&self, bytes: usize) {
        self.packets_out.fetch_add(1, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_inbound(&self, bytes: usize) {
        self.packets_in.fetch_add(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_drop(&self) {
        self.packets_dropped.fetch_add(1, Ordering::Relaxed);
        crate::instrumentation::global().transport.record_packet_loss();
    }

    pub fn record_fec_recovery(&self) {
        self.fec_recoveries.fetch_add(1, Ordering::Relaxed);
        crate::instrumentation::global().fec.record_recovery();
    }
}

/// Outbound packet processor (TUN -> Network).
pub struct OutboundPipeline {
    fec: Arc<std::sync::Mutex<FecCodec>>,
    stealth: Arc<crate::stealth::StealthManager>,
    stats: Arc<PipelineStats>,
}

impl OutboundPipeline {
    pub fn new(subsystems: &ClientSubsystems, stats: Arc<PipelineStats>) -> Self {
        Self { fec: subsystems.fec.clone(), stealth: subsystems.stealth.clone(), stats }
    }

    /// Process an outbound packet.
    ///
    /// Returns the processed packet ready for QUIC transmission.
    pub fn process(&self, packet: &[u8]) -> Result<Vec<u8>, PipelineError> {
        self.process_batch(packet).map(|mut packets| packets.pop().unwrap_or_default())
    }

    /// Process an outbound packet and return all encoded packets.
    pub fn process_batch(&self, packet: &[u8]) -> Result<Vec<Vec<u8>>, PipelineError> {
        if packet.is_empty() {
            return Err(PipelineError::EmptyPacket);
        }

        // Step 1: Apply stealth obfuscation
        let mut obfuscated = packet.to_vec();
        self.stealth.obfuscate_payload(&mut obfuscated, 0);

        // Step 2: Apply FEC encoding
        let encoded = self.apply_fec_packets(&obfuscated)?;

        // Update stats
        for pkt in &encoded {
            self.stats.record_outbound(pkt.len());
        }

        Ok(encoded)
    }

    fn apply_fec_packets(&self, packet: &[u8]) -> Result<Vec<Vec<u8>>, PipelineError> {
        let mut fec = self.fec.lock().map_err(|_| PipelineError::LockError)?;
        Ok(fec.encode_packets(packet))
    }
}

/// Inbound packet processor (Network -> TUN).
pub struct InboundPipeline {
    fec: Arc<std::sync::Mutex<FecCodec>>,
    stealth: Arc<crate::stealth::StealthManager>,
    stats: Arc<PipelineStats>,
}

impl InboundPipeline {
    pub fn new(subsystems: &ClientSubsystems, stats: Arc<PipelineStats>) -> Self {
        Self { fec: subsystems.fec.clone(), stealth: subsystems.stealth.clone(), stats }
    }

    /// Process an inbound packet.
    ///
    /// Returns the original IP packet for TUN injection.
    pub fn process(&self, packet: &[u8]) -> Result<Vec<u8>, PipelineError> {
        self.process_batch(packet).map(|mut packets| packets.pop().unwrap_or_default())
    }

    /// Process an inbound packet and return all decoded packets.
    pub fn process_batch(&self, packet: &[u8]) -> Result<Vec<Vec<u8>>, PipelineError> {
        if packet.is_empty() {
            return Err(PipelineError::EmptyPacket);
        }

        // Step 1: Apply FEC decoding
        let decoded_packets = self.apply_fec_packets(packet)?;

        // Step 2: Remove stealth obfuscation
        let mut out = Vec::new();
        for mut pkt in decoded_packets {
            self.stealth.deobfuscate_payload(&mut pkt, 0);
            self.stats.record_inbound(pkt.len());
            out.push(pkt);
        }

        Ok(out)
    }

    fn apply_fec_packets(&self, packet: &[u8]) -> Result<Vec<Vec<u8>>, PipelineError> {
        let mut fec = self.fec.lock().map_err(|_| PipelineError::LockError)?;
        Ok(fec.decode_packets(packet))
    }
}

/// Pipeline errors.
#[derive(Debug, Clone)]
pub enum PipelineError {
    EmptyPacket,
    LockError,
    StealthError(String),
    FecError(String),
    BufferTooSmall,
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineError::EmptyPacket => write!(f, "Empty packet"),
            PipelineError::LockError => write!(f, "Lock acquisition failed"),
            PipelineError::StealthError(e) => write!(f, "Stealth error: {}", e),
            PipelineError::FecError(e) => write!(f, "FEC error: {}", e),
            PipelineError::BufferTooSmall => write!(f, "Buffer too small"),
        }
    }
}

impl std::error::Error for PipelineError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_stats() {
        let stats = PipelineStats::new();
        stats.record_outbound(100);
        stats.record_inbound(200);
        stats.record_drop();

        assert_eq!(stats.packets_out.load(Ordering::Relaxed), 1);
        assert_eq!(stats.bytes_out.load(Ordering::Relaxed), 100);
        assert_eq!(stats.packets_in.load(Ordering::Relaxed), 1);
        assert_eq!(stats.bytes_in.load(Ordering::Relaxed), 200);
        assert_eq!(stats.packets_dropped.load(Ordering::Relaxed), 1);
    }
}
