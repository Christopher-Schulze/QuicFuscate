use std::sync::atomic::Ordering;

use super::{
    default_hard_max_capacity, MemoryPool, MemoryPoolError, MemoryPoolRuntimeConfig,
    PoolBlockLocation, PoolBlockOrigin, PoolOwnershipLedger, PooledBlock, DEFAULT_POOL_MAX_BYTES,
    LOCK_BLOCKS_TEST_MUTEX,
};

#[cfg(unix)]
use super::{ZeroCopyBuffer, ZeroCopyRecvBuffer};
#[cfg(any(unix, windows))]
use super::{ZeroCopyError, ZeroCopyTransfer};

#[cfg(any(unix, windows))]
#[test]
fn zero_copy_transfer_classifies_zero_complete_and_partial_progress() {
    let zero = ZeroCopyTransfer::from_syscall_count(0, 8).expect("zero result is valid");
    assert!(zero.is_zero());
    assert!(!zero.is_complete());
    assert!(!zero.is_partial());

    let partial = ZeroCopyTransfer::from_syscall_count(4, 8).expect("partial result is valid");
    assert_eq!(partial.transferred(), 4);
    assert_eq!(partial.requested(), 8);
    assert!(partial.is_partial());
    assert!(!partial.is_complete());

    let complete = ZeroCopyTransfer::from_syscall_count(8, 8).expect("complete result is valid");
    assert!(complete.is_complete());
    assert!(!complete.is_partial());
    assert!(matches!(
        ZeroCopyTransfer::from_syscall_count(9, 8),
        Err(ZeroCopyError::InvalidTransferCount { transferred: 9, requested: 8 })
    ));
}

#[cfg(unix)]
#[test]
fn unix_zero_copy_checks_iovec_count_and_normalizes_syscall_errors() {
    let maximum = super::unix_iovec_max();
    let data = [0u8; 1];
    let buffers = vec![&data[..]; maximum + 1];
    assert!(matches!(ZeroCopyBuffer::new(&buffers), Err(ZeroCopyError::InvalidBufferCount { .. })));

    let payload = [1u8, 2, 3];
    let send = ZeroCopyBuffer::new(&[&payload[..]]).expect("valid send buffer");
    assert!(matches!(send.send(-1), Err(ZeroCopyError::Io(_))));

    let mut receive_storage = [0u8; 8];
    let mut receive_buffers = [&mut receive_storage[..]];
    let mut receive =
        ZeroCopyRecvBuffer::new_mut(&mut receive_buffers).expect("valid receive buffer");
    assert!(matches!(receive.recv(-1), Err(ZeroCopyError::Io(_))));
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn windows_zero_copy_checks_u32_abi_bounds() {
    assert!(matches!(
        super::checked_windows_buffer_length(0, u32::MAX as usize + 1),
        Err(ZeroCopyError::BufferLengthTooLarge { .. })
    ));
    assert!(matches!(
        super::checked_windows_buffer_count(u32::MAX as usize + 1),
        Err(ZeroCopyError::InvalidBufferCount { .. })
    ));
}

#[test]
fn fallible_constructor_rejects_zero_and_unrepresentable_configuration() {
    assert!(matches!(MemoryPool::try_new(0, 4_096), Err(MemoryPoolError::InvalidCapacity)));
    assert!(matches!(MemoryPool::try_new(1, 0), Err(MemoryPoolError::InvalidBlockSize)));
    assert!(matches!(MemoryPool::try_new_adaptive(1, 0), Err(MemoryPoolError::InvalidBlockSize)));
    assert!(matches!(
        MemoryPool::try_new(usize::MAX, 2_048),
        Err(MemoryPoolError::CapacityOverflow)
    ));
    assert!(matches!(
        MemoryPool::try_new(1, usize::MAX - 100),
        Err(MemoryPoolError::CapacityOverflow)
    ));
    assert!(matches!(super::checked_pool_layout(0), Err(MemoryPoolError::InvalidBlockSize)));
}

#[test]
fn fallible_allocation_and_resize_preserve_the_existing_contract() {
    let pool = MemoryPool::try_new(1, 2_048).expect("valid fallible pool");
    let block = pool.try_alloc().expect("fallible allocation must succeed");
    assert_eq!(block.len(), 2_048);
    pool.free(block);
    pool.try_set_capacity(2).expect("fallible growth must succeed");
    assert_eq!(pool.capacity.load(Ordering::Acquire), 2);
    pool.try_set_capacity(0).expect("fallible shrink must succeed");
    assert_eq!(pool.capacity.load(Ordering::Acquire), 0);
}

#[test]
fn pooled_block_drop_returns_the_checked_out_block() {
    use std::sync::Arc;

    let pool = Arc::new(MemoryPool::new(1, 2_048));
    let before = pool.accounting_snapshot();
    {
        let mut block = PooledBlock::new(Arc::clone(&pool));
        block[0] = 0xA5;
        assert_eq!(pool.in_use.load(Ordering::Acquire), before.1 + 1);
    }
    assert_eq!(pool.accounting_snapshot(), before);
    pool.ownership.assert_consistent();
}

#[test]
fn pooled_block_transfer_disarms_only_the_guard() {
    use std::sync::Arc;

    let pool = Arc::new(MemoryPool::new(1, 2_048));
    let before = pool.accounting_snapshot();
    let mut guard = PooledBlock::new(Arc::clone(&pool));
    let originating_pool = guard.pool();
    let block = guard.take_block().expect("a new guard owns one block");
    drop(guard);
    assert_eq!(pool.in_use.load(Ordering::Acquire), before.1 + 1);
    originating_pool.free(block);
    assert_eq!(pool.accounting_snapshot(), before);
    pool.ownership.assert_consistent();
}

#[test]
fn fallible_slice_allocation_rejects_oversized_data_and_copies_exact_data() {
    let pool = MemoryPool::try_new(1, 2_048).expect("valid fallible pool");
    let data = vec![0xA5; 2_200];
    assert!(matches!(
        pool.try_alloc_from_slice(&data),
        Err(MemoryPoolError::SliceTooLarge { requested: 2_200, block_size: 2_048 })
    ));
    let data = vec![0xA5; 2_048];
    let block = pool
        .try_alloc_from_slice(&data)
        .expect("fallible slice allocation must succeed for an exact block");
    assert_eq!(block.len(), 2_048);
    assert!(block.iter().all(|byte| *byte == 0xA5));
    pool.free(block);
}

#[test]
fn default_growth_limit_is_byte_bounded_and_never_below_initial_capacity() {
    assert_eq!(default_hard_max_capacity(512, 65_536), 1_024);
    assert_eq!(default_hard_max_capacity(32_768, 2_048), 32_768);
    assert_eq!(
        default_hard_max_capacity(65_536, 2_048),
        65_536,
        "an explicitly larger initial pool remains valid"
    );
    assert_eq!(DEFAULT_POOL_MAX_BYTES, 64 * 1024 * 1024);
}

#[test]
fn explicit_constructor_preserves_requested_block_size() {
    let pool = MemoryPool::new(1, 128 * 1024);
    assert_eq!(pool.block_size(), 128 * 1024);
    assert_eq!(pool.alloc().len(), 128 * 1024);
}

#[test]
fn explicit_constructor_applies_only_the_minimum_block_size() {
    let pool = MemoryPool::new(1, 1);
    assert_eq!(pool.block_size(), 2048);
    assert_eq!(pool.alloc().len(), 2048);
}

#[test]
fn adaptive_block_profiles_remain_explicitly_selectable() {
    assert_eq!(MemoryPool::adaptive_block_size_for_mtu(1500), 4096);
    assert_eq!(MemoryPool::adaptive_block_size_for_mtu(9000), 16_384);
    assert_eq!(MemoryPool::adaptive_block_size_for_mtu(9001), 65_536);
}

#[test]
fn runtime_policy_is_validated_once_from_one_snapshot() {
    let environment = qf_common::env_utils::EnvSnapshot::from_pairs([
        ("QUICFUSCATE_POOL_AUTO_TUNE", "off"),
        ("QUICFUSCATE_POOL_MIN_CAP", "0"),
        ("QUICFUSCATE_POOL_MAX_CAP", "invalid"),
        ("QUICFUSCATE_POOL_TICK_MS", " 250 "),
        ("QUICFUSCATE_POOL_UTIL_LOW", "0"),
        ("QUICFUSCATE_POOL_UTIL_HIGH", "110"),
        ("QUICFUSCATE_TLS_CACHE", "8"),
        ("QUICFUSCATE_TLS_LOW", "0"),
        ("QUICFUSCATE_TLS_HIGH", "64"),
    ]);
    let runtime = MemoryPoolRuntimeConfig::from_snapshot(&environment);

    assert!(!runtime.auto_tune);
    assert_eq!(runtime.min_capacity, 64);
    assert_eq!(runtime.max_capacity, super::DEFAULT_AUTO_TUNE_MAX_CAPACITY);
    assert_eq!(runtime.tick_ms, 250);
    assert_eq!(runtime.utilization_low, 1);
    assert_eq!(runtime.utilization_high, 95);
    assert_eq!(runtime.tls_cache_limit.load(std::sync::atomic::Ordering::Relaxed), 8);
    assert_eq!(runtime.tls_low, 24);
    assert_eq!(runtime.tls_high, 64);
}

#[test]
fn thread_local_blocks_remain_owned_by_their_origin_pool() {
    let first_pool = super::MemoryPool::new(1, 2_048);
    let second_pool = super::MemoryPool::new(1, 2_048);
    let first_block = first_pool.alloc();
    let first_pointer = first_block.as_ptr();
    assert!(first_pool.try_cache_block(first_block, 1).is_ok());
    first_pool.ownership.assert_consistent();

    let second_block = second_pool.alloc();
    assert_ne!(second_block.as_ptr(), first_pointer);

    let first_block_again = first_pool.alloc();
    assert_eq!(first_block_again.as_ptr(), first_pointer);
    first_pool.free(first_block_again);
    first_pool.ownership.assert_consistent();
}

#[test]
fn ephemeral_blocks_never_change_accounted_counters() {
    let environment =
        qf_common::env_utils::EnvSnapshot::from_pairs([("QUICFUSCATE_POOL_HARD_MAX_CAP", "1")]);
    let pool = MemoryPool::new_with_snapshot(1, 2_048, &environment);
    pool.runtime.tls_cache_limit.store(0, Ordering::Relaxed);

    let accounted = pool.alloc();
    let ephemeral = pool.alloc();
    assert_eq!(pool.capacity.load(Ordering::Acquire), 1);
    assert_eq!(pool.in_use.load(Ordering::Acquire), 1);
    assert_eq!(pool.available.load(Ordering::Acquire), 0);

    pool.free(ephemeral);
    assert_eq!(pool.capacity.load(Ordering::Acquire), 1);
    assert_eq!(pool.in_use.load(Ordering::Acquire), 1);
    assert_eq!(pool.available.load(Ordering::Acquire), 0);

    let pointer = accounted.as_ptr();
    pool.free(accounted);
    assert_eq!(pool.ownership.begin_free(pointer), None);
    assert_eq!(pool.capacity.load(Ordering::Acquire), 1);
    assert_eq!(pool.in_use.load(Ordering::Acquire), 0);
    assert_eq!(pool.available.load(Ordering::Acquire), 1);
    pool.ownership.assert_consistent();
}

#[test]
fn duplicate_address_registration_replaces_stale_state_without_counter_drift() {
    use std::sync::Arc;

    let capacity = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let in_use = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let available = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ledger = PoolOwnershipLedger::try_new(
        Arc::clone(&capacity),
        Arc::clone(&in_use),
        Arc::clone(&available),
        1,
    )
    .expect("one-record ledger reservation must succeed");
    let pointer = 0x1000usize as *const u8;

    assert!(ledger.register(pointer, PoolBlockOrigin::Accounted, PoolBlockLocation::CheckedOut));
    assert!(ledger.register(pointer, PoolBlockOrigin::Accounted, PoolBlockLocation::Queue));
    assert_eq!(capacity.load(Ordering::Acquire), 1);
    assert_eq!(in_use.load(Ordering::Acquire), 0);
    assert_eq!(available.load(Ordering::Acquire), 1);
    ledger.assert_consistent();
}

#[test]
fn foreign_and_mismatched_blocks_do_not_enter_pool_state() {
    use std::alloc::{alloc, Layout};

    let pool = MemoryPool::new(1, 2_048);
    pool.runtime.tls_cache_limit.store(0, Ordering::Relaxed);
    let foreign_pool = MemoryPool::new(1, 2_048);
    foreign_pool.runtime.tls_cache_limit.store(0, Ordering::Relaxed);

    let foreign = foreign_pool.alloc();
    pool.free(foreign);
    assert_eq!(pool.capacity.load(Ordering::Acquire), 1);
    assert_eq!(pool.available.load(Ordering::Acquire), 1);
    assert_eq!(pool.in_use.load(Ordering::Acquire), 0);
    assert_eq!(foreign_pool.in_use.load(Ordering::Acquire), 1);

    let layout = Layout::from_size_align(1, 64).expect("one-byte layout");
    let raw = unsafe { alloc(layout) };
    assert!(!raw.is_null());
    let slice = unsafe { std::slice::from_raw_parts_mut(raw, 1) };
    let mismatched = unsafe { aligned_box::AlignedBox::<[u8]>::from_raw_parts(slice, layout) };
    pool.free(mismatched);
    assert_eq!(pool.capacity.load(Ordering::Acquire), 1);
    assert_eq!(pool.available.load(Ordering::Acquire), 1);
    assert_eq!(pool.in_use.load(Ordering::Acquire), 0);
    pool.ownership.assert_consistent();
}

#[test]
fn shrink_flushes_tls_and_releases_accounted_capacity() {
    let pool = MemoryPool::new(2, 2_048);
    pool.runtime.tls_cache_limit.store(2, Ordering::Relaxed);
    let first = pool.alloc();
    let second = pool.alloc();
    pool.free(first);
    pool.free(second);
    assert_eq!(pool.available.load(Ordering::Acquire), 2);

    pool.set_capacity(0);
    assert_eq!(pool.capacity.load(Ordering::Acquire), 0);
    assert_eq!(pool.available.load(Ordering::Acquire), 0);
    assert_eq!(pool.in_use.load(Ordering::Acquire), 0);
    pool.ownership.assert_consistent();
}

#[test]
fn concurrent_queue_transitions_preserve_exact_accounting() {
    use std::sync::Arc;

    let pool = Arc::new(MemoryPool::new(4, 2_048));
    pool.runtime.tls_cache_limit.store(0, Ordering::Relaxed);
    let mut workers = Vec::new();
    for _ in 0..8 {
        let pool = Arc::clone(&pool);
        workers.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let block = pool.alloc();
                pool.free(block);
            }
        }));
    }
    for worker in workers {
        worker.join().expect("memory pool worker must finish");
    }
    let capacity = pool.capacity.load(Ordering::Acquire);
    assert!(capacity >= 4);
    assert_eq!(pool.available.load(Ordering::Acquire), capacity);
    assert_eq!(pool.in_use.load(Ordering::Acquire), 0);
    pool.ownership.assert_consistent();
}

#[test]
fn tls_ledger_survives_pool_drop_until_thread_cleanup() {
    use std::sync::{mpsc, Arc};

    let pool = Arc::new(MemoryPool::new(1, 2_048));
    pool.runtime.tls_cache_limit.store(1, Ordering::Relaxed);
    let ledger = Arc::clone(&pool.ownership);
    let lock_ledger = Arc::clone(&pool.lock_ledger);
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker_pool = Arc::clone(&pool);
    let worker = std::thread::spawn(move || {
        let block = worker_pool.alloc();
        worker_pool.free(block);
        drop(worker_pool);
        ready_tx.send(()).expect("worker must signal TLS ownership");
        release_rx.recv().expect("worker must receive cleanup signal");
    });

    ready_rx.recv().expect("worker must cache a block");
    drop(pool);
    release_tx.send(()).expect("worker cleanup signal must send");
    worker.join().expect("worker must clean up its TLS cache");
    assert!(ledger.closed.load(Ordering::Acquire));
    assert_eq!(lock_ledger.len(), 0);
}

#[test]
fn capacity_shrink_releases_locked_queue_blocks() {
    let _guard = LOCK_BLOCKS_TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let original = MemoryPool::lock_blocks_enabled();
    MemoryPool::set_lock_blocks(true);
    {
        let pool = MemoryPool::new(1, 2_048);
        pool.runtime.tls_cache_limit.store(1, Ordering::Relaxed);
        let block = pool.alloc();
        pool.free(block);
        pool.set_capacity(0);
        assert_eq!(pool.capacity.load(Ordering::Acquire), 0);
        assert_eq!(pool.lock_ledger.len(), 0);
        pool.ownership.assert_consistent();
    }
    MemoryPool::set_lock_blocks(original);
}
