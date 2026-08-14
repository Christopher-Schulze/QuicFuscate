use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

#[derive(Debug)]
pub(in crate::implementations::server) struct ClientFanoutPacket {
    pub(in crate::implementations::server) source: SocketAddr,
    pub(in crate::implementations::server) destination: IpAddr,
    pub(in crate::implementations::server) packet: Vec<u8>,
}

const MAX_CLIENT_FANOUT_ENTRIES: usize = 256;
const MAX_CLIENT_FANOUT_BYTES: usize = 384 * 1024;
pub(in crate::implementations::server) const MAX_CLIENT_FANOUT_ENTRIES_PER_SOURCE: usize = 32;
const MAX_CLIENT_FANOUT_BYTES_PER_SOURCE: usize = 64 * 1024;
pub(in crate::implementations::server) const MAX_CLIENT_FANOUT_DRAIN_BATCH: usize = 64;

#[derive(Clone, Copy, Debug, Default)]
struct ClientFanoutSourceUsage {
    entries: usize,
    bytes: usize,
}

#[derive(Debug)]
pub(in crate::implementations::server) struct ClientFanoutQueueState {
    packets: std::collections::VecDeque<ClientFanoutPacket>,
    bytes: usize,
    source_usage: std::collections::HashMap<SocketAddr, ClientFanoutSourceUsage>,
    max_entries: usize,
    max_bytes: usize,
    max_source_entries: usize,
    max_source_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::implementations::server) enum ClientFanoutReject {
    Queue,
    Bytes,
    PerSource,
    PerSourceBytes,
}

impl ClientFanoutQueueState {
    pub(in crate::implementations::server) fn new() -> Self {
        Self::with_limits(
            MAX_CLIENT_FANOUT_ENTRIES,
            MAX_CLIENT_FANOUT_BYTES,
            MAX_CLIENT_FANOUT_ENTRIES_PER_SOURCE,
            MAX_CLIENT_FANOUT_BYTES_PER_SOURCE,
        )
    }

    pub(in crate::implementations::server) fn with_limits(
        max_entries: usize,
        max_bytes: usize,
        max_source_entries: usize,
        max_source_bytes: usize,
    ) -> Self {
        Self {
            packets: std::collections::VecDeque::new(),
            bytes: 0,
            source_usage: std::collections::HashMap::new(),
            max_entries,
            max_bytes,
            max_source_entries,
            max_source_bytes,
        }
    }

    pub(in crate::implementations::server) fn enqueue(
        &mut self,
        source: SocketAddr,
        destination: IpAddr,
        packet: &[u8],
    ) -> Result<(), ClientFanoutReject> {
        let packet_bytes = packet.len();
        if self.packets.len() >= self.max_entries {
            return Err(ClientFanoutReject::Queue);
        }
        if packet_bytes > self.max_bytes.saturating_sub(self.bytes) {
            return Err(ClientFanoutReject::Bytes);
        }
        let source_usage = self.source_usage.get(&source).copied().unwrap_or_default();
        if source_usage.entries >= self.max_source_entries {
            return Err(ClientFanoutReject::PerSource);
        }
        if packet_bytes > self.max_source_bytes.saturating_sub(source_usage.bytes) {
            return Err(ClientFanoutReject::PerSourceBytes);
        }

        self.packets.push_back(ClientFanoutPacket { source, destination, packet: packet.to_vec() });
        self.bytes += packet_bytes;
        let source_usage = self.source_usage.entry(source).or_default();
        source_usage.entries += 1;
        source_usage.bytes += packet_bytes;
        Ok(())
    }

    pub(in crate::implementations::server) fn pop_front(&mut self) -> Option<ClientFanoutPacket> {
        let fanout = self.packets.pop_front()?;
        let packet_bytes = fanout.packet.len();
        self.bytes = self.bytes.saturating_sub(packet_bytes);
        let remove_source = if let Some(source_usage) = self.source_usage.get_mut(&fanout.source) {
            source_usage.entries = source_usage.entries.saturating_sub(1);
            source_usage.bytes = source_usage.bytes.saturating_sub(packet_bytes);
            source_usage.entries == 0
        } else {
            false
        };
        if remove_source {
            self.source_usage.remove(&fanout.source);
        }
        Some(fanout)
    }

    pub(in crate::implementations::server) fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    #[cfg(test)]
    pub(in crate::implementations::server) fn len(&self) -> usize {
        self.packets.len()
    }

    #[cfg(test)]
    pub(in crate::implementations::server) fn bytes(&self) -> usize {
        self.bytes
    }
}

pub(in crate::implementations::server) type ClientFanoutQueue =
    Arc<std::sync::Mutex<ClientFanoutQueueState>>;

pub(in crate::implementations::server) fn new_client_fanout_queue() -> ClientFanoutQueue {
    Arc::new(std::sync::Mutex::new(ClientFanoutQueueState::new()))
}
