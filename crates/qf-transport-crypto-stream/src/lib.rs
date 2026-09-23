//! Reliable CRYPTO-frame buffering shared by each QUIC encryption level.

use qf_error::ConnectionError;
use std::collections::{BTreeMap, BTreeSet};

/// CryptoStream manages CRYPTO frame data for each encryption level.
#[derive(Default)]
pub struct CryptoStream {
    /// Send buffer for outgoing CRYPTO frames.
    send_buf: Vec<u8>,
    /// Current send offset.
    send_off: u64,
    /// Sent-but-unacked ranges retained for retransmission.
    unacked: BTreeMap<u64, Vec<u8>>,
    /// Total bytes held in `unacked`.
    unacked_bytes: usize,
    /// Offsets queued for retransmission after loss/PTO, sorted by offset.
    retx: BTreeSet<u64>,
    /// Receive buffer for incoming CRYPTO frames, which may arrive out of order.
    recv_buf: BTreeMap<u64, Vec<u8>>,
    /// Next expected receive offset.
    recv_off: u64,
}

/// Maximum unsent or sent-but-unacknowledged CRYPTO bytes per encryption level.
pub const MAX_CRYPTO_BUFFERED_BYTES: usize = 4 * 1024 * 1024;
const MAX_CRYPTO_RECV_WINDOW_BYTES: u64 = 65_536;
const MAX_CRYPTO_RECV_INTERVALS: usize = 1_024;

#[inline]
fn checked_u64_add_offset(offset: u64, length: usize) -> Result<u64, ConnectionError> {
    let length = u64::try_from(length).map_err(|_| ConnectionError::InvalidPacket)?;
    offset.checked_add(length).ok_or(ConnectionError::InvalidPacket)
}

impl CryptoStream {
    /// Creates a new empty CryptoStream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues data to be sent in CRYPTO frames.
    pub fn send(&mut self, data: &[u8]) -> Result<(), ConnectionError> {
        let queued = self
            .send_buf
            .len()
            .checked_add(data.len())
            .ok_or(ConnectionError::CryptoBufferExceeded)?;
        if queued > MAX_CRYPTO_BUFFERED_BYTES {
            return Err(ConnectionError::CryptoBufferExceeded);
        }
        self.send_buf.extend_from_slice(data);
        Ok(())
    }

    /// Gets the next CRYPTO frame to send, up to `max_len` bytes.
    pub fn next_crypto_frame(
        &mut self,
        max_len: usize,
    ) -> Result<Option<(u64, Vec<u8>)>, ConnectionError> {
        if max_len == 0 {
            return Ok(None);
        }
        while let Some(&offset) = self.retx.first() {
            let Some(data) = self.unacked.get(&offset) else {
                self.retx.pop_first();
                continue;
            };
            if data.len() <= max_len {
                let data = data.clone();
                self.retx.pop_first();
                return Ok(Some((offset, data)));
            }
            if max_len == 0 {
                return Ok(None);
            }
            let suffix_offset = checked_u64_add_offset(offset, max_len)?;
            let (prefix, suffix) = data.split_at(max_len);
            let prefix = prefix.to_vec();
            let suffix = suffix.to_vec();
            self.unacked.remove(&offset);
            self.unacked.insert(offset, prefix.clone());
            self.unacked.insert(suffix_offset, suffix);
            self.retx.pop_first();
            self.retx.insert(suffix_offset);
            return Ok(Some((offset, prefix)));
        }
        if self.send_buf.is_empty() {
            return Ok(None);
        }

        let available = MAX_CRYPTO_BUFFERED_BYTES
            .checked_sub(self.unacked_bytes)
            .ok_or(ConnectionError::InvalidState)?;
        let len = max_len.min(self.send_buf.len()).min(available);
        if len == 0 {
            return Ok(None);
        }
        let offset = self.send_off;
        let next_offset = checked_u64_add_offset(offset, len)?;
        let retained_bytes =
            self.unacked_bytes.checked_add(len).ok_or(ConnectionError::CryptoBufferExceeded)?;
        let data: Vec<u8> = self.send_buf.drain(..len).collect();
        self.send_off = next_offset;
        self.unacked_bytes = retained_bytes;
        self.unacked.insert(offset, data.clone());
        Ok(Some((offset, data)))
    }

    /// Drops the acknowledged range `[offset, offset+len)` from retention.
    pub fn ack_crypto(&mut self, offset: u64, len: u64) -> Result<(), ConnectionError> {
        if len == 0 {
            return Ok(());
        }
        let ack_end = offset.checked_add(len).ok_or(ConnectionError::InvalidPacket)?;
        let overlapping: Vec<u64> =
            self.unacked.range(..ack_end).map(|(start, _)| *start).collect();
        let mut plans = Vec::with_capacity(overlapping.len());
        let mut removed_bytes = 0usize;
        let mut added_bytes = 0usize;
        for start in overlapping {
            let Some(data) = self.unacked.get(&start).cloned() else {
                continue;
            };
            let end = checked_u64_add_offset(start, data.len())?;
            if end <= offset {
                continue;
            }
            let head_len = if start < offset {
                Some(usize::try_from(offset - start).map_err(|_| ConnectionError::InvalidPacket)?)
            } else {
                None
            };
            let tail_start = if end > ack_end {
                Some(
                    usize::try_from(
                        ack_end.checked_sub(start).ok_or(ConnectionError::InvalidPacket)?,
                    )
                    .map_err(|_| ConnectionError::InvalidPacket)?,
                )
            } else {
                None
            };
            removed_bytes = removed_bytes
                .checked_add(data.len())
                .ok_or(ConnectionError::CryptoBufferExceeded)?;
            if let Some(head_len) = head_len {
                added_bytes = added_bytes
                    .checked_add(head_len)
                    .ok_or(ConnectionError::CryptoBufferExceeded)?;
            }
            if let Some(tail_start) = tail_start {
                added_bytes = added_bytes
                    .checked_add(data.len() - tail_start)
                    .ok_or(ConnectionError::CryptoBufferExceeded)?;
            }
            plans.push((start, data, head_len, tail_start));
        }
        if self.unacked_bytes < removed_bytes {
            return Err(ConnectionError::InvalidState);
        }
        let retained_bytes = self.unacked_bytes - removed_bytes;
        let retained_bytes =
            retained_bytes.checked_add(added_bytes).ok_or(ConnectionError::CryptoBufferExceeded)?;

        for (start, data, head_len, tail_start) in plans {
            let queued_for_retransmission = self.retx.remove(&start);
            self.unacked.remove(&start);
            if let Some(head_len) = head_len {
                self.unacked.insert(start, data[..head_len].to_vec());
                if queued_for_retransmission {
                    self.retx.insert(start);
                }
            }
            if let Some(tail_start) = tail_start {
                self.unacked.insert(ack_end, data[tail_start..].to_vec());
                if queued_for_retransmission {
                    self.retx.insert(ack_end);
                }
            }
        }
        self.unacked_bytes = retained_bytes;
        Ok(())
    }

    /// Requeues the lost range `[offset, offset+len)` for retransmission.
    pub fn requeue_crypto(&mut self, offset: u64, len: u64) -> Result<(), ConnectionError> {
        if len == 0 {
            return Ok(());
        }
        let end = offset.checked_add(len).ok_or(ConnectionError::InvalidPacket)?;
        let mut offsets = Vec::new();
        if let Some((&start, data)) = self.unacked.range(..offset).next_back() {
            if checked_u64_add_offset(start, data.len())? > offset {
                offsets.push(start);
            }
        }
        for (&start, data) in self.unacked.range(offset..end) {
            if checked_u64_add_offset(start, data.len())? > offset {
                offsets.push(start);
            }
        }
        for offset in offsets {
            self.retx.insert(offset);
        }
        Ok(())
    }

    /// Requeues every retained unacked range for retransmission.
    pub fn requeue_all_unacked(&mut self) {
        self.retx.extend(self.unacked.keys().copied());
    }

    /// Returns the total bytes currently retained as sent-but-unacked.
    pub fn unacked_bytes(&self) -> usize {
        self.unacked_bytes
    }

    /// Returns true while unsent CRYPTO bytes remain at this encryption level.
    pub fn has_pending_send(&self) -> bool {
        !self.send_buf.is_empty()
    }

    /// Receives a CRYPTO frame, which may be out of order.
    pub fn recv(&mut self, offset: u64, data: Vec<u8>) -> Result<(), ConnectionError> {
        let data_end = checked_u64_add_offset(offset, data.len())?;
        if data_end <= self.recv_off {
            return Ok(());
        }
        let receive_window_end = self.recv_off.saturating_add(MAX_CRYPTO_RECV_WINDOW_BYTES);
        if data_end > receive_window_end {
            return Err(ConnectionError::CryptoBufferExceeded);
        }
        let start = offset.max(self.recv_off);
        let trim = usize::try_from(start - offset).map_err(|_| ConnectionError::InvalidPacket)?;
        let incoming = &data[trim..];
        if incoming.is_empty() {
            return Ok(());
        }

        let mut merged_start = start;
        let mut merged_end = data_end;
        let mut merged_keys = Vec::new();
        let mut removed_bytes = 0usize;
        let mut covered = false;
        for (&existing_start, existing) in &self.recv_buf {
            let existing_end = checked_u64_add_offset(existing_start, existing.len())?;
            if existing_end < merged_start {
                continue;
            }
            if existing_start > merged_end {
                break;
            }
            let overlap_start = start.max(existing_start);
            let overlap_end = data_end.min(existing_end);
            if overlap_start < overlap_end {
                let input_offset = usize::try_from(overlap_start - start)
                    .map_err(|_| ConnectionError::InvalidPacket)?;
                let existing_offset = usize::try_from(overlap_start - existing_start)
                    .map_err(|_| ConnectionError::InvalidPacket)?;
                let overlap_len = usize::try_from(overlap_end - overlap_start)
                    .map_err(|_| ConnectionError::InvalidPacket)?;
                if incoming[input_offset..input_offset + overlap_len]
                    != existing[existing_offset..existing_offset + overlap_len]
                {
                    return Err(ConnectionError::InvalidFrame);
                }
            }
            covered |= existing_start <= start && existing_end >= data_end;
            merged_start = merged_start.min(existing_start);
            merged_end = merged_end.max(existing_end);
            removed_bytes = removed_bytes
                .checked_add(existing.len())
                .ok_or(ConnectionError::CryptoBufferExceeded)?;
            merged_keys.push(existing_start);
        }
        if covered {
            return Ok(());
        }
        let merged_len = usize::try_from(merged_end - merged_start)
            .map_err(|_| ConnectionError::CryptoBufferExceeded)?;
        let retained_bytes = self
            .recv_buf
            .values()
            .try_fold(0usize, |total, interval| total.checked_add(interval.len()))
            .ok_or(ConnectionError::CryptoBufferExceeded)?;
        let next_retained = retained_bytes
            .checked_sub(removed_bytes)
            .and_then(|remaining| remaining.checked_add(merged_len))
            .ok_or(ConnectionError::InvalidState)?;
        if next_retained > MAX_CRYPTO_RECV_WINDOW_BYTES as usize
            || self.recv_buf.len() - merged_keys.len() + 1 > MAX_CRYPTO_RECV_INTERVALS
        {
            return Err(ConnectionError::CryptoBufferExceeded);
        }

        let mut merged = vec![0u8; merged_len];
        let incoming_offset =
            usize::try_from(start - merged_start).map_err(|_| ConnectionError::InvalidPacket)?;
        merged[incoming_offset..incoming_offset + incoming.len()].copy_from_slice(incoming);
        for &existing_start in &merged_keys {
            let existing =
                self.recv_buf.get(&existing_start).ok_or(ConnectionError::InvalidState)?;
            let merged_offset = usize::try_from(existing_start - merged_start)
                .map_err(|_| ConnectionError::InvalidPacket)?;
            merged[merged_offset..merged_offset + existing.len()].copy_from_slice(existing);
        }
        for key in merged_keys {
            self.recv_buf.remove(&key);
        }
        self.recv_buf.insert(merged_start, merged);
        Ok(())
    }

    /// Reads available contiguous data from the receive buffer.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut written = 0;
        while written < buf.len() {
            if let Some(data) = self.recv_buf.remove(&self.recv_off) {
                let to_copy = (buf.len() - written).min(data.len());
                buf[written..written + to_copy].copy_from_slice(&data[..to_copy]);
                written += to_copy;
                self.recv_off += to_copy as u64;
                if to_copy < data.len() {
                    self.recv_buf.insert(self.recv_off, data[to_copy..].to_vec());
                    break;
                }
            } else {
                break;
            }
        }
        written
    }

    /// Returns true when data is ready to read at the next contiguous offset.
    pub fn has_data(&self) -> bool {
        self.recv_buf.contains_key(&self.recv_off)
    }

    /// Resets all buffers and offsets to their initial state.
    pub fn reset(&mut self) {
        self.send_buf.clear();
        self.send_off = 0;
        self.unacked.clear();
        self.unacked_bytes = 0;
        self.retx.clear();
        self.recv_buf.clear();
        self.recv_off = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::{CryptoStream, MAX_CRYPTO_BUFFERED_BYTES};
    use qf_error::ConnectionError;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    struct CountingAllocator;

    static ALLOCATION_CALLS: AtomicUsize = AtomicUsize::new(0);
    static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);

    // SAFETY: all allocation and deallocation requests are forwarded unchanged to System.
    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() {
                ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
                ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            }
            pointer
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            unsafe { System.dealloc(pointer, layout) };
        }
    }

    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator;

    #[test]
    fn crypto_stream_range_overflow_is_typed_and_atomic() {
        let mut stream = CryptoStream::new();
        stream.send(b"pending").expect("queue data");
        stream.send_off = u64::MAX;
        assert_eq!(stream.next_crypto_frame(7), Err(ConnectionError::InvalidPacket));
        assert_eq!(stream.send_off, u64::MAX);
        assert_eq!(stream.send_buf, b"pending");
        assert!(stream.unacked.is_empty());
        assert_eq!(stream.recv(u64::MAX, vec![0x01]), Err(ConnectionError::InvalidPacket));
        assert_eq!(stream.ack_crypto(u64::MAX, 1), Err(ConnectionError::InvalidPacket));
        assert_eq!(stream.requeue_crypto(u64::MAX, 1), Err(ConnectionError::InvalidPacket));
    }

    #[test]
    fn reset_discards_unsent_unacked_retransmission_and_receive_state() {
        let mut stream = CryptoStream::new();
        stream.send(b"sent").expect("queue sent data");
        let (sent_offset, sent) =
            stream.next_crypto_frame(usize::MAX).expect("take sent data").expect("sent frame");
        stream.requeue_crypto(sent_offset, sent.len() as u64).expect("queue retransmission");
        stream.send(b"unsent").expect("queue unsent data");
        stream.recv(0, b"received".to_vec()).expect("queue receive data");

        stream.reset();

        assert_eq!(stream.unacked_bytes(), 0);
        assert!(!stream.has_pending_send());
        assert!(!stream.has_data());
        assert_eq!(stream.next_crypto_frame(usize::MAX), Ok(None));
        assert_eq!(stream.send_off, 0);
        assert_eq!(stream.recv_off, 0);
    }

    #[test]
    fn unsent_capacity_rejects_overflow_without_changing_existing_bytes() {
        let mut stream = CryptoStream::new();
        assert_eq!(
            stream.send(&vec![0xA5; MAX_CRYPTO_BUFFERED_BYTES + 1]),
            Err(ConnectionError::CryptoBufferExceeded)
        );
        assert!(stream.send_buf.is_empty());
        let full = vec![0x5A; MAX_CRYPTO_BUFFERED_BYTES];
        stream.send(&full).expect("admit exact-cap flight");
        assert_eq!(stream.send(b"extra"), Err(ConnectionError::CryptoBufferExceeded));
        assert_eq!(stream.send_buf, full);
        assert_eq!(stream.send_off, 0);
    }

    #[test]
    fn retained_capacity_blocks_fresh_bytes_until_ack_without_eviction() {
        let mut stream = CryptoStream::new();
        let full = vec![0xA5; MAX_CRYPTO_BUFFERED_BYTES];
        stream.send(&full).expect("queue full flight");
        let (offset, sent) = stream
            .next_crypto_frame(MAX_CRYPTO_BUFFERED_BYTES)
            .expect("take full flight")
            .expect("full flight available");
        assert_eq!((offset, sent.len()), (0, MAX_CRYPTO_BUFFERED_BYTES));
        stream.send(b"tail").expect("queue following flight");
        assert_eq!(stream.next_crypto_frame(4), Ok(None));
        assert_eq!(stream.unacked_bytes(), MAX_CRYPTO_BUFFERED_BYTES);
        assert_eq!(stream.send_buf, b"tail");
        for _ in 0..32 {
            assert_eq!(stream.next_crypto_frame(4), Ok(None));
        }
        assert_eq!(stream.unacked_bytes(), MAX_CRYPTO_BUFFERED_BYTES);
        assert_eq!(stream.send_buf, b"tail");
        stream.requeue_all_unacked();
        let (retry_offset, retry) = stream
            .next_crypto_frame(MAX_CRYPTO_BUFFERED_BYTES)
            .expect("take retransmission")
            .expect("oldest flight retained");
        assert_eq!((retry_offset, retry), (0, full));
        stream.ack_crypto(0, MAX_CRYPTO_BUFFERED_BYTES as u64).expect("ACK full flight");
        assert_eq!(
            stream.next_crypto_frame(4),
            Ok(Some((MAX_CRYPTO_BUFFERED_BYTES as u64, b"tail".to_vec())))
        );
    }

    #[test]
    fn zero_frame_budget_does_not_create_an_empty_retained_range() {
        let mut stream = CryptoStream::new();
        stream.send(b"pending").expect("queue bytes");
        assert_eq!(stream.next_crypto_frame(0), Ok(None));
        assert_eq!(stream.send_buf, b"pending");
        assert_eq!(stream.send_off, 0);
        assert_eq!(stream.unacked_bytes(), 0);
    }

    #[test]
    fn partial_ack_releases_only_its_bytes_and_retransmission_precedes_fresh_data() {
        let mut stream = CryptoStream::new();
        stream.send(b"abcd").expect("queue first range");
        stream.next_crypto_frame(4).expect("send first range").expect("first range available");
        let remaining = vec![0xA5; MAX_CRYPTO_BUFFERED_BYTES - 4];
        stream.send(&remaining).expect("queue remaining flight");
        stream
            .next_crypto_frame(MAX_CRYPTO_BUFFERED_BYTES)
            .expect("send remaining flight")
            .expect("remaining flight available");
        stream.send(b"next").expect("queue next flight");
        stream.ack_crypto(0, 2).expect("ACK two bytes");
        assert_eq!(stream.unacked_bytes(), MAX_CRYPTO_BUFFERED_BYTES - 2);
        stream.requeue_crypto(2, 2).expect("queue loss before fresh data");
        assert_eq!(stream.next_crypto_frame(2), Ok(Some((2, b"cd".to_vec()))));
        assert_eq!(
            stream.next_crypto_frame(4),
            Ok(Some((MAX_CRYPTO_BUFFERED_BYTES as u64, b"ne".to_vec())))
        );
        assert_eq!(stream.unacked_bytes(), MAX_CRYPTO_BUFFERED_BYTES);
        assert_eq!(stream.next_crypto_frame(2), Ok(None));
        assert_eq!(stream.send_buf, b"xt");
        stream.ack_crypto(2, 2).expect("ACK another retained pair");
        assert_eq!(
            stream.next_crypto_frame(2),
            Ok(Some(((MAX_CRYPTO_BUFFERED_BYTES + 2) as u64, b"xt".to_vec())))
        );
        assert_eq!(stream.unacked_bytes(), MAX_CRYPTO_BUFFERED_BYTES);
    }

    #[test]
    fn partial_ack_preserves_queued_retransmission_of_unacked_suffix() {
        let mut stream = CryptoStream::new();
        stream.send(b"abcdef").expect("queue flight");
        assert_eq!(stream.next_crypto_frame(6), Ok(Some((0, b"abcdef".to_vec()))));
        stream.requeue_crypto(0, 6).expect("mark flight lost");
        stream.ack_crypto(0, 2).expect("ACK prefix after loss");
        assert_eq!(stream.next_crypto_frame(6), Ok(Some((2, b"cdef".to_vec()))));
        assert_eq!(stream.next_crypto_frame(6), Ok(None));
    }

    #[test]
    fn middle_ack_preserves_both_queued_retransmission_fragments() {
        let mut stream = CryptoStream::new();
        stream.send(b"abcdef").expect("queue flight");
        assert_eq!(stream.next_crypto_frame(6), Ok(Some((0, b"abcdef".to_vec()))));
        stream.requeue_all_unacked();
        stream.ack_crypto(2, 2).expect("ACK middle after PTO");
        assert_eq!(stream.next_crypto_frame(6), Ok(Some((0, b"ab".to_vec()))));
        assert_eq!(stream.next_crypto_frame(6), Ok(Some((4, b"ef".to_vec()))));
        assert_eq!(stream.next_crypto_frame(6), Ok(None));
    }

    #[test]
    fn duplicate_pto_and_partial_retry_keep_one_unacked_suffix() {
        let mut stream = CryptoStream::new();
        stream.send(b"abcdef").expect("queue flight");
        assert_eq!(stream.next_crypto_frame(6), Ok(Some((0, b"abcdef".to_vec()))));
        stream.requeue_all_unacked();
        stream.requeue_all_unacked();
        stream.requeue_crypto(0, 6).expect("duplicate loss report");
        assert_eq!(stream.retx.len(), 1);
        assert_eq!(stream.next_crypto_frame(2), Ok(Some((0, b"ab".to_vec()))));
        assert_eq!(stream.retx.iter().copied().collect::<Vec<_>>(), vec![2]);
        stream.ack_crypto(0, 2).expect("ACK retransmitted prefix");
        assert_eq!(stream.next_crypto_frame(6), Ok(Some((2, b"cdef".to_vec()))));
        assert_eq!(stream.next_crypto_frame(6), Ok(None));
        stream.requeue_all_unacked();
        stream.ack_crypto(2, 4).expect("ACK remaining bytes");
        assert!(stream.retx.is_empty());
        assert_eq!(stream.next_crypto_frame(6), Ok(None));
    }

    #[test]
    #[ignore = "manual native PTO requeue measurement"]
    fn benchmark_retransmission_index_at_range_counts() {
        for (range_count, iterations) in [(1, 10_000), (128, 1_000), (4_096, 20), (16_384, 3)] {
            let mut stream = CryptoStream::new();
            for offset in 0..range_count {
                stream.unacked.insert(offset as u64, vec![0xA5]);
            }
            let mut queue = VecDeque::new();
            let queue_alloc_start = ALLOCATION_CALLS.load(Ordering::Relaxed);
            let queue_bytes_start = ALLOCATED_BYTES.load(Ordering::Relaxed);
            let start = Instant::now();
            for _ in 0..iterations {
                queue.clear();
                for &offset in stream.unacked.keys() {
                    if !queue.contains(&offset) {
                        queue.push_back(offset);
                    }
                }
                assert_eq!(queue.len(), range_count);
            }
            let queue_nanos = start.elapsed().as_nanos() / iterations as u128;
            let queue_allocs = ALLOCATION_CALLS.load(Ordering::Relaxed) - queue_alloc_start;
            let queue_bytes = ALLOCATED_BYTES.load(Ordering::Relaxed) - queue_bytes_start;
            let set_alloc_start = ALLOCATION_CALLS.load(Ordering::Relaxed);
            let set_bytes_start = ALLOCATED_BYTES.load(Ordering::Relaxed);
            let start = Instant::now();
            for _ in 0..iterations {
                stream.retx.clear();
                stream.requeue_all_unacked();
                assert_eq!(stream.retx.len(), range_count);
            }
            let set_nanos = start.elapsed().as_nanos() / iterations as u128;
            let set_allocs = ALLOCATION_CALLS.load(Ordering::Relaxed) - set_alloc_start;
            let set_bytes = ALLOCATED_BYTES.load(Ordering::Relaxed) - set_bytes_start;
            println!(
                "ranges={range_count} queue_ns={queue_nanos} set_ns={set_nanos} \
                 queue_allocs={queue_allocs} queue_bytes={queue_bytes} \
                 set_allocs={set_allocs} set_bytes={set_bytes} iterations={iterations}"
            );
        }
    }

    #[test]
    fn receive_window_stays_anchored_to_next_unread_byte() {
        let mut stream = CryptoStream::new();
        stream.recv(65_535, vec![0xA5]).expect("edge byte within window");
        assert_eq!(stream.recv(65_536, vec![0x5A]), Err(ConnectionError::CryptoBufferExceeded));
        assert_eq!(stream.recv_buf.len(), 1);
        assert_eq!(stream.recv_off, 0);
        stream.recv(0, b"ok".to_vec()).expect("receive missing prefix");
        let mut consumed = [0u8; 2];
        assert_eq!(stream.read(&mut consumed), 2);
        assert_eq!(&consumed, b"ok");
        stream.recv(65_536, vec![0x5A]).expect("window advances only after delivery");
        assert_eq!(stream.recv_buf.len(), 1);
    }

    #[test]
    fn receive_merges_reordered_identical_overlaps_and_trims_delivered_prefix() {
        let mut stream = CryptoStream::new();
        stream.recv(2, b"cdef".to_vec()).expect("receive later range");
        stream.recv(0, b"abcd".to_vec()).expect("receive missing prefix");
        let mut prefix = [0u8; 3];
        assert_eq!(stream.read(&mut prefix), 3);
        assert_eq!(&prefix, b"abc");
        stream.recv(1, b"bcde".to_vec()).expect("identical partial duplicate");
        stream.recv(0, b"abcdef".to_vec()).expect("delivered-prefix retransmission");
        let mut suffix = [0u8; 4];
        assert_eq!(stream.read(&mut suffix), 3);
        assert_eq!(&suffix[..3], b"def");
        assert!(stream.recv_buf.is_empty());
    }

    #[test]
    fn conflicting_crypto_overlap_is_rejected_without_mutation() {
        let mut stream = CryptoStream::new();
        stream.recv(0, b"abcd".to_vec()).expect("receive first range");
        let retained_allocation = stream.recv_buf.get(&0).expect("retained range").as_ptr();
        stream.recv(1, b"bc".to_vec()).expect("admit exact duplicate");
        assert_eq!(
            stream.recv_buf.get(&0).expect("same retained range").as_ptr(),
            retained_allocation
        );
        assert_eq!(stream.recv(2, b"XY".to_vec()), Err(ConnectionError::InvalidFrame));
        assert_eq!(stream.recv_buf.get(&0).map(Vec::as_slice), Some(b"abcd".as_slice()));
        assert_eq!(stream.recv_off, 0);
    }

    #[test]
    fn receive_interval_count_is_bounded_independently_of_bytes() {
        let mut stream = CryptoStream::new();
        for offset in (1..=2_047).step_by(2) {
            stream.recv(offset, vec![0xA5]).expect("admit bounded sparse interval");
        }
        assert_eq!(stream.recv_buf.len(), 1_024);
        assert_eq!(stream.recv(2_049, vec![0x5A]), Err(ConnectionError::CryptoBufferExceeded));
        assert_eq!(stream.recv_buf.len(), 1_024);
        stream.recv(0, vec![0xA5]).expect("merge first sparse interval");
        assert_eq!(stream.recv_buf.len(), 1_024);
        let mut first = [0u8; 2];
        assert_eq!(stream.read(&mut first), 2);
        assert_eq!(stream.recv_buf.len(), 1_023);
        stream.recv(2_049, vec![0x5A]).expect("released interval slot permits new range");
        assert_eq!(stream.recv_buf.len(), 1_024);
    }
}
