//! Zero-overhead FEC pass-through backends.
//!
//! These backends keep the clean-link path allocation-free while retaining enough bounded state to
//! upgrade safely when a sequence gap is observed.

use crate::FecPacket;
use qf_memory_pool::MemoryPool;
use std::collections::VecDeque;
use std::sync::Arc;

/// Zero-overhead encoder for clean-link scenarios.
#[doc(hidden)]
pub struct ZeroEncoder {
    #[doc(hidden)]
    pub packets_passed: u64,
}

impl ZeroEncoder {
    #[doc(hidden)]
    pub fn new(_k: usize, _n: usize) -> Self {
        Self { packets_passed: 0 }
    }

    #[inline(always)]
    #[doc(hidden)]
    pub fn take_packet(&mut self, _packet: FecPacket) {
        self.packets_passed = self.packets_passed.saturating_add(1);
    }

    #[inline(always)]
    #[doc(hidden)]
    pub fn generate_repair_packet(
        &mut self,
        _index: usize,
        _pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        None
    }

    #[inline(always)]
    #[doc(hidden)]
    pub fn clear_window(&mut self) {
        self.packets_passed = 0;
    }

    #[inline(always)]
    #[doc(hidden)]
    pub fn packets_in_window(&self) -> usize {
        0
    }
}

/// Zero-overhead decoder with bounded gap-detection replay state.
#[doc(hidden)]
pub struct ZeroDecoder {
    last_seq: u64,
    recent: VecDeque<FecPacket>,
    max_buffer: usize,
    loss_detected: bool,
}

impl ZeroDecoder {
    #[doc(hidden)]
    pub fn new(_k: usize, _pool: Arc<MemoryPool>) -> Self {
        Self {
            last_seq: 0,
            recent: VecDeque::with_capacity(32),
            max_buffer: 64,
            loss_detected: false,
        }
    }

    #[inline(always)]
    #[doc(hidden)]
    pub fn take_packet(&mut self, packet: FecPacket) {
        if packet.is_systematic {
            if self.last_seq > 0 && packet.seq > self.last_seq.saturating_add(1) {
                self.loss_detected = true;
            }
            self.last_seq = packet.seq;
        }
        self.recent.push_back(packet);
        if self.recent.len() > self.max_buffer {
            self.recent.pop_front();
        }
    }

    #[doc(hidden)]
    pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        if self.loss_detected {
            None
        } else {
            Some(std::mem::take(&mut self.recent))
        }
    }

    #[doc(hidden)]
    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        std::mem::take(&mut self.recent)
    }
}
