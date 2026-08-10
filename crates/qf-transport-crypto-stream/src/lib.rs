//! Reliable CRYPTO-frame buffering shared by each QUIC encryption level.

use qf_error::ConnectionError;
use std::collections::{BTreeMap, VecDeque};

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
    retx: VecDeque<u64>,
    /// Receive buffer for incoming CRYPTO frames, which may arrive out of order.
    recv_buf: BTreeMap<u64, Vec<u8>>,
    /// Next expected receive offset.
    recv_off: u64,
    /// Maximum receive offset seen.
    recv_max: u64,
}

const MAX_CRYPTO_UNACKED_BYTES: usize = 4 * 1024 * 1024;

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
        self.send_buf.len().checked_add(data.len()).ok_or(ConnectionError::CryptoBufferExceeded)?;
        self.send_buf.extend_from_slice(data);
        Ok(())
    }

    /// Gets the next CRYPTO frame to send, up to `max_len` bytes.
    pub fn next_crypto_frame(
        &mut self,
        max_len: usize,
    ) -> Result<Option<(u64, Vec<u8>)>, ConnectionError> {
        while let Some(&offset) = self.retx.front() {
            let Some(data) = self.unacked.get(&offset) else {
                self.retx.pop_front();
                continue;
            };
            if data.len() <= max_len {
                let data = data.clone();
                self.retx.pop_front();
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
            self.retx.pop_front();
            self.retx.push_front(suffix_offset);
            return Ok(Some((offset, prefix)));
        }
        if self.send_buf.is_empty() {
            return Ok(None);
        }

        let len = max_len.min(self.send_buf.len());
        let offset = self.send_off;
        let next_offset = checked_u64_add_offset(offset, len)?;
        let retained_bytes =
            self.unacked_bytes.checked_add(len).ok_or(ConnectionError::CryptoBufferExceeded)?;
        let data: Vec<u8> = self.send_buf.drain(..len).collect();
        self.send_off = next_offset;
        self.unacked_bytes = retained_bytes;
        self.unacked.insert(offset, data.clone());
        self.evict_unacked_overflow();
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
            self.unacked.remove(&start);
            if let Some(head_len) = head_len {
                self.unacked.insert(start, data[..head_len].to_vec());
            }
            if let Some(tail_start) = tail_start {
                self.unacked.insert(ack_end, data[tail_start..].to_vec());
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
        let offsets: Vec<u64> = self
            .unacked
            .range(..end)
            .map(|(start, data)| {
                let data_end = checked_u64_add_offset(*start, data.len())?;
                Ok((*start, data_end))
            })
            .collect::<Result<Vec<_>, ConnectionError>>()?
            .into_iter()
            .filter(|(_, data_end)| *data_end > offset)
            .map(|(start, _)| start)
            .collect();
        for offset in offsets {
            if !self.retx.contains(&offset) {
                self.retx.push_back(offset);
            }
        }
        let mut sorted: Vec<u64> = self.retx.iter().copied().collect();
        sorted.sort_unstable();
        self.retx = sorted.into_iter().collect();
        Ok(())
    }

    /// Requeues every retained unacked range for retransmission.
    pub fn requeue_all_unacked(&mut self) {
        let mut offsets: Vec<u64> = self.unacked.keys().copied().collect();
        offsets.sort_unstable();
        for offset in offsets {
            if !self.retx.contains(&offset) {
                self.retx.push_back(offset);
            }
        }
    }

    /// Returns the total bytes currently retained as sent-but-unacked.
    pub fn unacked_bytes(&self) -> usize {
        self.unacked_bytes
    }

    fn evict_unacked_overflow(&mut self) {
        while self.unacked_bytes > MAX_CRYPTO_UNACKED_BYTES {
            let Some((&oldest, _)) = self.unacked.iter().next() else {
                break;
            };
            if let Some(data) = self.unacked.remove(&oldest) {
                self.unacked_bytes -= data.len();
                log::warn!("CRYPTO unacked overflow: evicted range at offset {oldest}");
            }
        }
    }

    /// Returns true while unsent CRYPTO bytes remain at this encryption level.
    pub fn has_pending_send(&self) -> bool {
        !self.send_buf.is_empty()
    }

    /// Receives a CRYPTO frame, which may be out of order.
    pub fn recv(&mut self, offset: u64, data: Vec<u8>) -> Result<(), ConnectionError> {
        let data_end = checked_u64_add_offset(offset, data.len())?;
        let receive_window_end =
            self.recv_max.checked_add(65536).ok_or(ConnectionError::FlowControl)?;
        if data_end > receive_window_end {
            return Err(ConnectionError::FlowControl);
        }
        self.recv_max = self.recv_max.max(data_end);
        self.recv_buf.insert(offset, data);
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
        self.recv_buf.clear();
        self.recv_off = 0;
        self.recv_max = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::CryptoStream;
    use qf_error::ConnectionError;

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
}
