use super::{AlignedBox, Arc, AtomicBool, AtomicUsize, MemoryPoolError, Ordering};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PoolBlockOrigin {
    Accounted,
    Ephemeral,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PoolBlockLocation {
    Queue,
    Tls,
    CheckedOut,
}

#[derive(Debug, Clone, Copy)]
struct PoolBlockRecord {
    origin: PoolBlockOrigin,
    location: PoolBlockLocation,
}

#[derive(Debug, Default)]
struct PoolOwnershipState {
    records: HashMap<usize, PoolBlockRecord>,
}

/// Shared lifetime and ownership state for a `MemoryPool` and its thread-local caches.
/// The `Arc` held by each TLS cache keeps this ledger alive until its blocks are dropped,
/// even when the owning `MemoryPool` has already been dropped on another thread.
#[derive(Debug)]
pub(super) struct PoolOwnershipLedger {
    state: std::sync::Mutex<PoolOwnershipState>,
    pub(super) closed: AtomicBool,
    capacity: Arc<AtomicUsize>,
    in_use: Arc<AtomicUsize>,
    available: Arc<AtomicUsize>,
}

impl PoolOwnershipLedger {
    pub(super) fn try_new(
        capacity: Arc<AtomicUsize>,
        in_use: Arc<AtomicUsize>,
        available: Arc<AtomicUsize>,
        expected_capacity: usize,
    ) -> Result<Self, MemoryPoolError> {
        let mut state = PoolOwnershipState::default();
        state
            .records
            .try_reserve(expected_capacity)
            .map_err(|_| MemoryPoolError::AllocationFailed)?;
        Ok(Self {
            state: std::sync::Mutex::new(state),
            closed: AtomicBool::new(false),
            capacity,
            in_use,
            available,
        })
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, PoolOwnershipState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[inline]
    fn decrement(counter: &AtomicUsize) {
        let _ = counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| Some(value.saturating_sub(1)));
    }

    pub(super) fn register(
        &self,
        ptr: *const u8,
        origin: PoolBlockOrigin,
        location: PoolBlockLocation,
    ) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }

        let address = ptr as usize;
        let mut state = self.lock_state();
        if self.closed.load(Ordering::Acquire) {
            return false;
        }

        if let Some(previous) = state.records.remove(&address) {
            log::debug!(
                target: "memory_pool",
                "replacing stale ownership record for duplicate block address {:p} (old={previous:?}, new origin={origin:?}, location={location:?})",
                ptr,
            );
            if previous.origin == PoolBlockOrigin::Accounted {
                Self::decrement(&self.capacity);
                match previous.location {
                    PoolBlockLocation::Queue | PoolBlockLocation::Tls => {
                        Self::decrement(&self.available);
                    }
                    PoolBlockLocation::CheckedOut => {
                        Self::decrement(&self.in_use);
                    }
                }
            }
        }
        state.records.insert(address, PoolBlockRecord { origin, location });
        if origin == PoolBlockOrigin::Accounted {
            self.capacity.fetch_add(1, Ordering::AcqRel);
            match location {
                PoolBlockLocation::Queue | PoolBlockLocation::Tls => {
                    self.available.fetch_add(1, Ordering::AcqRel);
                }
                PoolBlockLocation::CheckedOut => {
                    self.in_use.fetch_add(1, Ordering::AcqRel);
                }
            }
        }
        true
    }

    pub(super) fn checkout(&self, ptr: *const u8, from: PoolBlockLocation) -> bool {
        let mut state = self.lock_state();
        let Some(record) = state.records.get_mut(&(ptr as usize)) else {
            return false;
        };
        if record.origin != PoolBlockOrigin::Accounted || record.location != from {
            return false;
        }
        record.location = PoolBlockLocation::CheckedOut;
        Self::decrement(&self.available);
        self.in_use.fetch_add(1, Ordering::AcqRel);
        true
    }

    pub(super) fn begin_free(&self, ptr: *const u8) -> Option<PoolBlockOrigin> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }

        let mut state = self.lock_state();
        let address = ptr as usize;
        let record = state.records.get(&address).copied()?;
        if record.location != PoolBlockLocation::CheckedOut {
            return None;
        }
        if record.origin == PoolBlockOrigin::Ephemeral {
            state.records.remove(&address);
        }
        Some(record.origin)
    }

    pub(super) fn return_accounted(&self, ptr: *const u8, location: PoolBlockLocation) -> bool {
        let mut state = self.lock_state();
        let Some(record) = state.records.get_mut(&(ptr as usize)) else {
            return false;
        };
        if record.origin != PoolBlockOrigin::Accounted
            || record.location != PoolBlockLocation::CheckedOut
        {
            return false;
        }
        record.location = location;
        Self::decrement(&self.in_use);
        self.available.fetch_add(1, Ordering::AcqRel);
        true
    }

    pub(super) fn move_available(
        &self,
        ptr: *const u8,
        from: PoolBlockLocation,
        to: PoolBlockLocation,
    ) -> bool {
        let mut state = self.lock_state();
        let Some(record) = state.records.get_mut(&(ptr as usize)) else {
            return false;
        };
        if record.origin != PoolBlockOrigin::Accounted || record.location != from {
            return false;
        }
        record.location = to;
        true
    }

    pub(super) fn discard_available(&self, ptr: *const u8, location: PoolBlockLocation) -> bool {
        let mut state = self.lock_state();
        let address = ptr as usize;
        let Some(record) = state.records.get(&address).copied() else {
            return false;
        };
        if record.origin != PoolBlockOrigin::Accounted || record.location != location {
            return false;
        }
        state.records.remove(&address);
        Self::decrement(&self.available);
        Self::decrement(&self.capacity);
        true
    }

    /// Removes the ledger record for a block that is about to be physically released.
    ///
    /// This is the fail-closed cleanup path for malformed queue/TLS transitions. The caller
    /// has already removed the block from its physical owner, so retaining any ledger record
    /// would make a future allocator address look like a duplicate live block.
    pub(super) fn discard_released(&self, ptr: *const u8) -> bool {
        let mut state = self.lock_state();
        let Some(record) = state.records.remove(&(ptr as usize)) else {
            return false;
        };
        if record.origin == PoolBlockOrigin::Accounted {
            Self::decrement(&self.capacity);
            match record.location {
                PoolBlockLocation::Queue | PoolBlockLocation::Tls => {
                    Self::decrement(&self.available);
                }
                PoolBlockLocation::CheckedOut => {
                    Self::decrement(&self.in_use);
                }
            }
        }
        true
    }

    pub(super) fn release_block(
        &self,
        block: AlignedBox<[u8]>,
        lock_ledger: &super::BlockLockLedger,
    ) {
        self.discard_released(block.as_ptr());
        super::release_locked_block(block, lock_ledger);
    }

    #[cfg(test)]
    pub(super) fn assert_consistent(&self) {
        let state = self.lock_state();
        let mut accounted = 0usize;
        let mut available = 0usize;
        let mut in_use = 0usize;
        for record in state.records.values() {
            if record.origin != PoolBlockOrigin::Accounted {
                continue;
            }
            accounted += 1;
            match record.location {
                PoolBlockLocation::Queue | PoolBlockLocation::Tls => available += 1,
                PoolBlockLocation::CheckedOut => in_use += 1,
            }
        }
        assert_eq!(self.capacity.load(Ordering::Acquire), accounted);
        assert_eq!(self.available.load(Ordering::Acquire), available);
        assert_eq!(self.in_use.load(Ordering::Acquire), in_use);
        assert_eq!(available + in_use, accounted);
    }

    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.lock_state().records.clear();
    }
}
