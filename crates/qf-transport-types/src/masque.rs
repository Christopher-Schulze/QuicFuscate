//! Root-independent bounded MASQUE downlink queue contract.

use std::collections::VecDeque;

/// Bounded FIFO for server-generated MASQUE response packets.
///
/// The queue is shared with DNS resolution workers, while one dequeued packet
/// can remain owned by the connection for a retry after QUIC DATAGRAM pressure.
#[derive(Debug)]
pub struct MasqueDownlinkQueue {
    packets: VecDeque<Vec<u8>>,
    bytes: usize,
    max_packets: usize,
    max_bytes: usize,
}

/// Admission failure for a bounded MASQUE downlink queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MasqueDownlinkQueueReject {
    /// The queue already contains its maximum number of packets.
    PacketCapacity,
    /// The packet would exceed the queue byte budget.
    ByteCapacity,
}

/// One opaque UDP response bound to its authenticated MASQUE flow.
#[derive(Debug, PartialEq, Eq)]
pub struct MasqueRelayResponse {
    pub flow_id: u64,
    pub payload: Vec<u8>,
}

/// Bounded cross-task response queue for intermediate-hop UDP associations.
#[derive(Debug)]
pub struct MasqueRelayResponseQueue {
    responses: VecDeque<MasqueRelayResponse>,
    bytes: usize,
    max_packets: usize,
    max_bytes: usize,
}

impl MasqueRelayResponseQueue {
    pub fn new(max_packets: usize, max_bytes: usize) -> Self {
        Self { responses: VecDeque::new(), bytes: 0, max_packets, max_bytes }
    }

    pub fn enqueue(
        &mut self,
        flow_id: u64,
        payload: Vec<u8>,
    ) -> Result<(), MasqueDownlinkQueueReject> {
        if self.responses.len() >= self.max_packets {
            return Err(MasqueDownlinkQueueReject::PacketCapacity);
        }
        if self.bytes.saturating_add(payload.len()) > self.max_bytes {
            return Err(MasqueDownlinkQueueReject::ByteCapacity);
        }
        self.bytes = self.bytes.saturating_add(payload.len());
        self.responses.push_back(MasqueRelayResponse { flow_id, payload });
        Ok(())
    }

    pub fn pop_front(&mut self) -> Option<MasqueRelayResponse> {
        let response = self.responses.pop_front()?;
        self.bytes = self.bytes.saturating_sub(response.payload.len());
        Some(response)
    }

    pub fn discard_all(&mut self) -> (usize, usize) {
        let packets = self.responses.len();
        let bytes = self.bytes;
        self.responses.clear();
        self.bytes = 0;
        (packets, bytes)
    }
}

impl MasqueDownlinkQueue {
    /// Creates an empty queue with packet-count and byte-size limits.
    pub fn new(max_packets: usize, max_bytes: usize) -> Self {
        Self { packets: VecDeque::new(), bytes: 0, max_packets, max_bytes }
    }

    /// Enqueues one packet if both configured bounds remain satisfied.
    pub fn enqueue(&mut self, packet: Vec<u8>) -> Result<(), MasqueDownlinkQueueReject> {
        if self.packets.len() >= self.max_packets {
            return Err(MasqueDownlinkQueueReject::PacketCapacity);
        }
        if self.bytes.saturating_add(packet.len()) > self.max_bytes {
            return Err(MasqueDownlinkQueueReject::ByteCapacity);
        }
        self.bytes = self.bytes.saturating_add(packet.len());
        self.packets.push_back(packet);
        Ok(())
    }

    /// Removes and returns the oldest packet, if any.
    pub fn pop_front(&mut self) -> Option<Vec<u8>> {
        let packet = self.packets.pop_front()?;
        self.bytes = self.bytes.saturating_sub(packet.len());
        Some(packet)
    }

    /// Drops all queued packets and returns the packet and byte counts.
    pub fn discard_all(&mut self) -> (usize, usize) {
        let packets = self.packets.len();
        let bytes = self.bytes;
        self.packets.clear();
        self.bytes = 0;
        (packets, bytes)
    }

    /// Returns the number of queued packets.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Returns true when no packet is queued.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Returns the total number of bytes queued.
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::{MasqueDownlinkQueue, MasqueDownlinkQueueReject, MasqueRelayResponseQueue};

    #[test]
    fn bounded_fifo_preserves_order_and_byte_accounting() {
        let mut queue = MasqueDownlinkQueue::new(2, 4);
        assert!(queue.is_empty());
        queue.enqueue(vec![1, 2]).expect("first packet must fit");
        queue.enqueue(vec![3]).expect("second packet must fit");
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.bytes(), 3);
        assert_eq!(queue.pop_front(), Some(vec![1, 2]));
        assert_eq!(queue.pop_front(), Some(vec![3]));
        assert_eq!(queue.pop_front(), None);
        assert!(queue.is_empty());
        assert_eq!(queue.bytes(), 0);
    }

    #[test]
    fn admission_reports_packet_and_byte_capacity_separately() {
        let mut queue = MasqueDownlinkQueue::new(1, 4);
        queue.enqueue(vec![1]).expect("first packet must fit");
        assert_eq!(queue.enqueue(vec![2]), Err(MasqueDownlinkQueueReject::PacketCapacity));

        let mut byte_limited = MasqueDownlinkQueue::new(2, 1);
        byte_limited.enqueue(vec![1]).expect("first byte must fit");
        byte_limited.pop_front();
        assert_eq!(byte_limited.enqueue(vec![1, 2]), Err(MasqueDownlinkQueueReject::ByteCapacity));
    }

    #[test]
    fn discard_all_returns_and_resets_ownership_accounting() {
        let mut queue = MasqueDownlinkQueue::new(4, 64);
        queue.enqueue(vec![1, 2]).expect("first packet must fit");
        queue.enqueue(vec![3]).expect("second packet must fit");
        assert_eq!(queue.discard_all(), (2, 3));
        assert!(queue.is_empty());
        assert_eq!(queue.bytes(), 0);
        assert_eq!(queue.discard_all(), (0, 0));
    }

    #[test]
    fn relay_queue_preserves_flow_identity_and_bounds() {
        let mut queue = MasqueRelayResponseQueue::new(2, 4);
        queue.enqueue(7, vec![1, 2]).expect("first response");
        queue.enqueue(9, vec![3]).expect("second response");
        assert_eq!(queue.enqueue(11, vec![4]), Err(MasqueDownlinkQueueReject::PacketCapacity));
        let response = queue.pop_front().expect("queued response");
        assert_eq!(response.flow_id, 7);
        assert_eq!(response.payload, vec![1, 2]);
        assert_eq!(queue.discard_all(), (1, 1));
    }
}
