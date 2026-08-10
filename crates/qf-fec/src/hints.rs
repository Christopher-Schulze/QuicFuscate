//! Connection-local hints shared by Brain and the FEC observer.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Connection-local FEC hints owned by one Brain/FEC observer pair.
#[doc(hidden)]
pub struct BrainFecHints {
    interval_pkts: AtomicU64,
    redundancy_ppm: AtomicU32,
}

impl BrainFecHints {
    /// Create the validated default hint state for a new connection.
    #[doc(hidden)]
    pub fn new() -> Self {
        Self { interval_pkts: AtomicU64::new(8), redundancy_ppm: AtomicU32::new(100_000) }
    }

    /// Return the Brain's preferred streaming interval in packets.
    #[inline(always)]
    #[doc(hidden)]
    pub fn interval_pkts(&self) -> u64 {
        self.interval_pkts.load(Ordering::Relaxed)
    }

    /// Return the Brain's preferred redundancy in parts per million.
    #[inline(always)]
    #[doc(hidden)]
    pub fn redundancy_ppm(&self) -> u32 {
        self.redundancy_ppm.load(Ordering::Relaxed)
    }

    /// Publish a new streaming interval in packets.
    #[inline(always)]
    #[doc(hidden)]
    pub fn set_interval_pkts(&self, value: u64) {
        self.interval_pkts.store(value, Ordering::Relaxed);
    }

    /// Publish a new redundancy value in parts per million.
    #[inline(always)]
    #[doc(hidden)]
    pub fn set_redundancy_ppm(&self, value: u32) {
        self.redundancy_ppm.store(value, Ordering::Relaxed);
    }
}
