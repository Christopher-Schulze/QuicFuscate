use super::*;

#[test]
fn test_unsafe_memory_pool() {
    let pool = Arc::new(UnsafeMemoryPool::new(10, 4096, 0));

    // SAFETY: alloc_uninit returns a valid NonNull<u8> from the pool with 4096-byte
    // blocks. copy_from_slice writes at most block_size bytes. slice::from_raw_parts
    // uses the same pointer and the returned len (clamped to block_size). free returns
    // the pointer to the pool. All operations use pointers from this pool only.
    unsafe {
        // Test allocation
        let ptr1 = pool.alloc_uninit();
        // Verify alignment instead of nullness (NonNull guarantees non-null)
        assert_eq!((ptr1.as_ptr() as usize) & 63, 0, "Memory pool alignment not 64B");

        // Test write
        let data = b"Hello, World!";
        let len = pool.copy_from_slice(ptr1, data).expect("live pool copy must succeed");
        assert_eq!(len, data.len());

        // Test read
        let slice = slice::from_raw_parts(ptr1.as_ptr(), len);
        assert_eq!(slice, data);

        // Test free
        pool.free(ptr1).expect("preallocated block must return");

        // Test synchronized available-cache hit
        let ptr2 = pool.alloc_uninit();
        assert_eq!(ptr1, ptr2); // Should get same pointer from the available cache
        pool.free(ptr2).expect("reused block must return");
    }
}

#[test]
fn test_unsafe_packet() {
    let pool = Arc::new(UnsafeMemoryPool::new(5, 1024, 0));

    // SAFETY: ptr is from pool.alloc_uninit (valid, 1024-byte block). from_raw_parts
    // is called with len=0, capacity=1024, matching the pool block. extend_from_slice
    // writes 9 bytes which is < 1024 capacity. Packet is dropped normally, returning
    // the pointer to the pool.
    unsafe {
        let ptr = pool.alloc_uninit();
        let mut packet = UnsafePacket::from_raw_parts(ptr, 0, 1024, Arc::clone(&pool))
            .expect("valid pool packet parts");

        // Test extend
        let data = b"Test data";
        packet.extend_from_slice(data).unwrap();
        assert_eq!(packet.as_slice(), data);

        // Test IoSlice creation
        let io_slice = packet.as_io_slice();
        assert_eq!(io_slice.len(), data.len());
    }
}

#[test]
fn test_unsafe_compression() {
    let pool = Arc::new(UnsafeMemoryPool::new(10, 8192, 0));
    let compressor = unsafe_compress::UnsafeCompressor::new(Arc::clone(&pool), None, 3)
        .expect("valid compressor context");

    // SAFETY: compress_direct takes a valid &[u8] slice (stack-allocated byte string
    // literal). The pool has 8192-byte blocks, sufficient for header + compressed
    // output of 59 bytes of input. The returned UnsafePacket is used read-only via
    // as_slice() and dropped normally.
    unsafe {
        let data = b"This is test data for compression. It should compress well.";
        let packet = compressor.compress_direct(data).unwrap();

        // Verify magic byte
        assert_eq!(*packet.as_slice().first().unwrap(), 0x5A);

        // Verify length encoding
        let len_bytes = &packet.as_slice()[1..5];
        let original_len =
            u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);
        assert_eq!(original_len as usize, data.len());
    }
}

#[test]
fn test_unsafe_compressor_rejects_invalid_level_and_source_length() {
    let pool = Arc::new(UnsafeMemoryPool::new(2, 8192, 0));
    let invalid = unsafe_compress::UnsafeCompressor::new(Arc::clone(&pool), None, 0);
    assert!(matches!(invalid, Err(UnsafeError::InvalidCompressionLevel)));
    assert_eq!(
        unsafe_compress::validate_source_len(u32::MAX as usize + 1),
        Err(UnsafeError::InputTooLarge)
    );
}

#[test]
fn test_unsafe_compressor_dictionary_roundtrip_and_level_contract() {
    let pool = Arc::new(UnsafeMemoryPool::new(4, 8192, 0));
    let dictionary = b"shared dictionary phrase for the compression contract";
    let data = b"shared dictionary phrase for the compression contract repeated twice";
    let compressor = unsafe_compress::UnsafeCompressor::new(Arc::clone(&pool), Some(dictionary), 7)
        .expect("valid dictionary compressor context");

    // SAFETY: data is a valid slice and the returned packet is dropped after inspection.
    unsafe {
        let packet = compressor.compress_direct(data).expect("dictionary compression");
        let encoded = packet.as_slice();
        assert_eq!(encoded[0], 0x5D);
        let hash = u16::from_be_bytes([encoded[1], encoded[2]]);
        let version = u16::from_be_bytes([encoded[3], encoded[4]]);
        assert_eq!(version, 1);
        assert_ne!(hash, 0);
        let original_len = u32::from_be_bytes([encoded[5], encoded[6], encoded[7], encoded[8]]);
        assert_eq!(original_len as usize, data.len());

        let mut decompressor =
            zstd::bulk::Decompressor::with_dictionary(dictionary).expect("dictionary decoder");
        let decoded =
            decompressor.decompress(&encoded[9..], data.len()).expect("dictionary decompression");
        assert_eq!(decoded, data);
    }
}

#[test]
fn test_unsafe_compressor_serializes_concurrent_calls() {
    let pool = Arc::new(UnsafeMemoryPool::new(4, 8192, 0));
    let compressor = Arc::new(
        unsafe_compress::UnsafeCompressor::new(Arc::clone(&pool), None, 3)
            .expect("valid concurrent compressor context"),
    );
    let mut workers = Vec::new();

    for worker_id in 0..8u8 {
        let compressor = Arc::clone(&compressor);
        workers.push(std::thread::spawn(move || {
            let data = vec![worker_id; 256];
            for _ in 0..16 {
                // SAFETY: data is a valid slice and the packet remains owned by this
                // worker until it is dropped at the end of the iteration.
                let packet =
                    unsafe { compressor.compress_direct(&data).expect("serialized compression") };
                let encoded = packet.as_slice();
                assert_eq!(encoded[0], 0x5A);
                let original_len =
                    u32::from_be_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]);
                assert_eq!(original_len as usize, data.len());
            }
        }));
    }

    for worker in workers {
        worker.join().expect("compression worker must complete");
    }
    assert_eq!(pool.in_use_count(), 0);
}

#[test]
fn test_unsafe_compressor_capacity_failure_returns_output_block() {
    let pool = Arc::new(UnsafeMemoryPool::new(1, 64, 0));
    let compressor = unsafe_compress::UnsafeCompressor::new(Arc::clone(&pool), None, 3)
        .expect("valid small compressor context");
    let result = unsafe { compressor.compress_direct(&[0xA5; 128]) };
    assert!(matches!(result, Err(UnsafeError::CapacityOverflow)));
    assert_eq!(pool.in_use_count(), 0);
    assert_eq!(pool.available_count(), 1);
}

#[test]
fn test_unsafe_compressor_parameter_validation_is_fail_closed() {
    let plan = unsafe_compress::CompressionPlan {
        level: 3,
        workers: 0,
        target_block: 0,
        strategy: unsafe_compress::CompressionStrategy::DFast,
        window_log: 17,
        checksum: false,
        content_size: false,
    };
    assert_eq!(
        unsafe_compress::validate_compression_plan(plan),
        Err(UnsafeError::ParameterRejected)
    );
}

#[cfg(feature = "compression_zstd_ffi")]
#[test]
fn test_native_zstd_parameter_failure_is_typed() {
    let ctx = NonNull::new(unsafe { zstd_sys::ZSTD_createCCtx() }).expect("native zstd context");
    let result =
        unsafe_compress::native_set_parameter(ctx, zstd_sys::ZSTD_cParameter::ZSTD_c_windowLog, 1);
    assert_eq!(result, Err(UnsafeError::ParameterRejected));
    // SAFETY: ctx is the live pointer returned above and has not been freed elsewhere.
    unsafe {
        let _ = zstd_sys::ZSTD_freeCCtx(ctx.as_ptr());
    }
}

/// Test with Miri for memory safety
#[cfg(miri)]
#[test]
fn test_miri_safety() {
    let pool = Arc::new(UnsafeMemoryPool::new(3, 256, 0));

    // SAFETY: ptr1 and ptr2 are distinct NonNull pointers from pool.alloc_uninit,
    // each backed by a 256-byte allocation. write_bytes writes exactly 256 bytes
    // to each (matching the block size). ptr dereferences (*ptr1.as_ptr()) read
    // the first byte of each valid allocation. free returns pointers to the pool.
    // No double-free because each pointer is freed exactly once.
    unsafe {
        let ptr1 = pool.alloc_uninit();
        let ptr2 = pool.alloc_uninit();

        // Write to ensure no overlap
        ptr::write_bytes(ptr1.as_ptr(), 0xAA, 256);
        ptr::write_bytes(ptr2.as_ptr(), 0xBB, 256);

        // Read back
        assert_eq!(*ptr1.as_ptr(), 0xAA);
        assert_eq!(*ptr2.as_ptr(), 0xBB);

        pool.free(ptr1).expect("first Miri block must return");
        pool.free(ptr2).expect("second Miri block must return");
    }
}

#[test]
fn test_pool_alloc_free_cycle() {
    let pool = Arc::new(UnsafeMemoryPool::new(8, 512, 0));

    // SAFETY: alloc_uninit returns valid NonNull pointers from the pool with
    // 512-byte blocks. Each pointer is freed exactly once via pool.free, which
    // returns the block to the pool. No double-free, no use-after-free.
    unsafe {
        let mut ptrs = Vec::new();
        // Allocate 8 blocks
        for _ in 0..8 {
            ptrs.push(pool.alloc_uninit());
        }
        assert_eq!(ptrs.len(), 8);

        // Free all blocks - must not panic
        for ptr in ptrs {
            pool.free(ptr).expect("cycle block must return");
        }

        // Re-allocate to verify pool reuse works after free cycle
        let reused = pool.alloc_uninit();
        pool.free(reused).expect("reused cycle block must return");
    }
}

#[test]
fn test_pool_alignment_64() {
    let pool = Arc::new(UnsafeMemoryPool::new(16, 4096, 0));

    // SAFETY: alloc_uninit returns valid NonNull pointers. We only inspect
    // the pointer address for alignment, then free each one exactly once.
    unsafe {
        for _ in 0..16 {
            let ptr = pool.alloc_uninit();
            assert_eq!(
                ptr.as_ptr() as usize % 64,
                0,
                "pointer {:p} is not 64-byte aligned",
                ptr.as_ptr()
            );
            pool.free(ptr).expect("aligned block must return");
        }
    }
}

#[test]
fn test_packet_extend_sequential() {
    let pool = Arc::new(UnsafeMemoryPool::new(4, 1024, 0));

    // SAFETY: ptr from alloc_uninit is valid for 1024 bytes. from_raw_parts
    // with len=0, capacity=1024 is correct. Each extend_from_slice adds data
    // within the 1024-byte capacity. Packet dropped normally at end.
    unsafe {
        let ptr = pool.alloc_uninit();
        let mut pkt = UnsafePacket::from_raw_parts(ptr, 0, 1024, Arc::clone(&pool))
            .expect("valid sequential packet parts");

        let chunks: [&[u8]; 5] = [b"AAAA", b"BBBB", b"CCCC", b"DDDD", b"EEEE"];
        for chunk in &chunks {
            pkt.extend_from_slice(chunk).unwrap();
        }

        let data = pkt.as_slice();
        assert_eq!(data.len(), 20);
        assert_eq!(&data[0..4], b"AAAA");
        assert_eq!(&data[4..8], b"BBBB");
        assert_eq!(&data[8..12], b"CCCC");
        assert_eq!(&data[12..16], b"DDDD");
        assert_eq!(&data[16..20], b"EEEE");
    }
}

#[test]
fn test_packet_extend_overflow() {
    let pool = Arc::new(UnsafeMemoryPool::new(2, 128, 0));

    // SAFETY: ptr from alloc_uninit is valid for 128 bytes (pool block_size
    // rounds 128 up to 128 which is already 64-aligned). from_raw_parts with
    // len=0, capacity=128. First extend of 100 bytes succeeds. Second extend
    // of 100 bytes exceeds capacity and must return Err. Packet dropped normally.
    unsafe {
        let ptr = pool.alloc_uninit();
        let mut pkt = UnsafePacket::from_raw_parts(ptr, 0, 128, Arc::clone(&pool))
            .expect("valid overflow packet parts");

        let buf = [0xCCu8; 100];
        let first = pkt.extend_from_slice(&buf);
        assert!(first.is_ok(), "first extend within capacity must succeed");

        let second = pkt.extend_from_slice(&buf);
        assert!(
            matches!(second, Err(UnsafeError::CapacityOverflow)),
            "extend beyond capacity must return CapacityOverflow"
        );
        // Length must remain at 100 (the overflow write must not have taken effect)
        assert_eq!(pkt.as_slice().len(), 100);
    }
}

#[test]
fn test_xor_blocks_involution() {
    // XOR is its own inverse: (data ^ key) ^ key == data
    let original = (0..128u8).collect::<Vec<u8>>();
    let key: Vec<u8> = (0..128u8).map(|i| i.wrapping_mul(37)).collect();

    let mut buf = original.clone();

    // First XOR pass
    for i in 0..buf.len() {
        buf[i] ^= key[i];
    }
    // buf is now ciphertext - must differ from original (unless key is all zeros)
    assert_ne!(buf, original, "XOR with non-zero key must change data");

    // Second XOR pass (involution)
    for i in 0..buf.len() {
        buf[i] ^= key[i];
    }
    assert_eq!(buf, original, "double XOR must restore original data");
}

#[test]
fn test_pool_copy_from_slice_clamps_to_block_size() {
    let pool = Arc::new(UnsafeMemoryPool::new(2, 64, 0));

    // SAFETY: alloc_uninit returns valid pointer for 64 bytes (block_size).
    // copy_from_slice with oversized data should clamp to block_size.
    // slice::from_raw_parts reads back the clamped length. free returns to pool.
    unsafe {
        let ptr = pool.alloc_uninit();
        let big_data = [0xABu8; 256]; // larger than block_size (64)
        let written =
            pool.copy_from_slice(ptr, &big_data).expect("live oversized copy must succeed");
        assert_eq!(written, 64, "copy_from_slice must clamp to block_size");

        // Verify the data was actually written
        let slice = std::slice::from_raw_parts(ptr.as_ptr(), written);
        assert!(slice.iter().all(|&b| b == 0xAB));
        pool.free(ptr).expect("clamped-copy block must return");
    }
}

#[test]
fn test_pool_copy_from_slice_zero_length() {
    let pool = Arc::new(UnsafeMemoryPool::new(2, 128, 0));

    // SAFETY: alloc_uninit returns valid pointer. copy_from_slice with empty
    // slice writes zero bytes. free returns to pool.
    unsafe {
        let ptr = pool.alloc_uninit();
        let written = pool.copy_from_slice(ptr, &[]).expect("live empty copy must succeed");
        assert_eq!(written, 0);
        pool.free(ptr).expect("empty-copy block must return");
    }
}

#[test]
fn test_packet_empty_slice() {
    let pool = Arc::new(UnsafeMemoryPool::new(2, 256, 0));

    // SAFETY: ptr from alloc_uninit is valid for 256 bytes.
    // from_raw_parts with len=0 creates empty packet.
    unsafe {
        let ptr = pool.alloc_uninit();
        let pkt = UnsafePacket::from_raw_parts(ptr, 0, 256, Arc::clone(&pool))
            .expect("valid empty packet parts");
        assert!(pkt.as_slice().is_empty());
        assert_eq!(pkt.as_io_slice().len(), 0);
    }
}

#[test]
fn test_packet_extend_zero_length_data() {
    let pool = Arc::new(UnsafeMemoryPool::new(2, 128, 0));

    // SAFETY: ptr from alloc_uninit is valid. Extending with empty slice is a no-op.
    unsafe {
        let ptr = pool.alloc_uninit();
        let mut pkt = UnsafePacket::from_raw_parts(ptr, 0, 128, Arc::clone(&pool))
            .expect("valid zero-length packet parts");
        let result = pkt.extend_from_slice(&[]);
        assert!(result.is_ok());
        assert_eq!(pkt.as_slice().len(), 0);
    }
}

#[test]
fn test_packet_extend_exact_capacity() {
    let pool = Arc::new(UnsafeMemoryPool::new(2, 128, 0));

    // SAFETY: ptr from alloc_uninit is valid for 128 bytes.
    // Extending with exactly 128 bytes should succeed.
    unsafe {
        let ptr = pool.alloc_uninit();
        let mut pkt = UnsafePacket::from_raw_parts(ptr, 0, 128, Arc::clone(&pool))
            .expect("valid exact-capacity packet parts");
        let data = [0xFFu8; 128];
        let result = pkt.extend_from_slice(&data);
        assert!(result.is_ok());
        assert_eq!(pkt.as_slice().len(), 128);
        assert!(pkt.as_slice().iter().all(|&b| b == 0xFF));
    }
}

#[test]
fn test_pool_block_size_rounds_up_to_cache_line() {
    // block_size=1 should round up to 64 (cache line)
    let pool = Arc::new(UnsafeMemoryPool::new(1, 1, 0));

    // SAFETY: alloc_uninit returns pointer for a block that is at least 64 bytes
    // (rounded up). copy_from_slice with 64 bytes should succeed.
    unsafe {
        let ptr = pool.alloc_uninit();
        let data = [0xCCu8; 64];
        let written = pool.copy_from_slice(ptr, &data).expect("rounded block copy must succeed");
        assert_eq!(written, 64, "block_size=1 should round to 64");
        pool.free(ptr).expect("rounded block must return");
    }
}

#[test]
fn test_pool_fallible_constructor_rejects_invalid_layout_and_capacity() {
    assert!(matches!(
        UnsafeMemoryPool::try_new(0, 64, 0),
        Err(UnsafeError::InvalidPoolConfiguration)
    ));
    assert!(matches!(
        UnsafeMemoryPool::try_new(1, 0, 0),
        Err(UnsafeError::InvalidPoolConfiguration)
    ));
    assert!(matches!(
        UnsafeMemoryPool::try_new(usize::MAX, 64, 0),
        Err(UnsafeError::CapacityOverflow)
    ));
    assert!(matches!(
        UnsafeMemoryPool::try_new(1, usize::MAX - 100, 0),
        Err(UnsafeError::CapacityOverflow)
    ));
}

#[test]
fn test_pool_fallible_allocation_reuses_and_returns_blocks() {
    let pool = UnsafeMemoryPool::try_new(1, 256, 0).expect("valid fallible pool");

    // SAFETY: the fallible allocator returns an owned live pool block, and the exact
    // pointer is returned once after the assertion.
    unsafe {
        let ptr = pool.try_alloc_uninit().expect("fallible allocation must succeed");
        assert_eq!(pool.in_use_count(), 1);
        pool.free(ptr).expect("fallible block must return");
    }
    assert_eq!(pool.available_count(), 1);
}

#[test]
fn test_multiple_pools_independent() {
    let pool_a = Arc::new(UnsafeMemoryPool::new(4, 256, 0));
    let pool_b = Arc::new(UnsafeMemoryPool::new(4, 512, 0));

    // SAFETY: Each pool's alloc_uninit returns independent pointers.
    // We write distinct patterns and verify no cross-contamination.
    unsafe {
        let ptr_a = pool_a.alloc_uninit();
        let ptr_b = pool_b.alloc_uninit();

        std::ptr::write_bytes(ptr_a.as_ptr(), 0xAA, 256);
        std::ptr::write_bytes(ptr_b.as_ptr(), 0xBB, 512);

        assert_eq!(*ptr_a.as_ptr(), 0xAA);
        assert_eq!(*ptr_b.as_ptr(), 0xBB);

        pool_a.free(ptr_a).expect("pool A block must return");
        pool_b.free(ptr_b).expect("pool B block must return");
    }
}

#[test]
fn test_pool_send_sync_contract() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<UnsafeMemoryPool>();
}

#[test]
fn test_pool_rejects_foreign_subslice_and_double_free() {
    let pool = Arc::new(UnsafeMemoryPool::new(2, 256, 0));
    let foreign_pool = Arc::new(UnsafeMemoryPool::new(2, 256, 0));

    // SAFETY: both pointers are live blocks from their respective pools. The shifted
    // pointer remains within its allocation but is intentionally not a valid pool base.
    unsafe {
        let foreign_ptr = foreign_pool.alloc_uninit();
        assert_eq!(
            pool.free(foreign_ptr),
            Err(UnsafeError::ForeignPointer),
            "a block from another pool must not enter this registry"
        );
        assert_eq!(pool.in_use_count(), 0);
        assert_eq!(foreign_pool.in_use_count(), 1);
        foreign_pool.free(foreign_ptr).expect("foreign pool must reclaim its own block");

        let ptr = pool.alloc_uninit();
        let shifted = NonNull::new_unchecked(ptr.as_ptr().add(1));
        let shifted_result = pool.free(shifted);
        assert!(
            matches!(
                shifted_result,
                Err(UnsafeError::InvalidPointer) | Err(UnsafeError::ForeignPointer)
            ),
            "a sub-slice base must be rejected"
        );
        assert_eq!(pool.in_use_count(), 1);

        pool.free(ptr).expect("live base block must return");
        assert_eq!(
            pool.free(ptr),
            Err(UnsafeError::DoubleFree),
            "a returned block must not be accepted twice"
        );
        assert_eq!(pool.in_use_count(), 0);
        assert_eq!(pool.available_count(), 2);
    }
}

#[test]
fn test_pool_separates_fallback_ownership_and_capacity() {
    let pool = Arc::new(UnsafeMemoryPool::new(1, 256, 0));

    // SAFETY: the first block is preallocated and the second necessarily uses the
    // distinct fallback path because the configured preallocated capacity is one.
    unsafe {
        let preallocated = pool.alloc_uninit();
        let fallback = pool.alloc_uninit();
        assert_eq!(pool.available_count(), 0);
        assert_eq!(pool.in_use_count(), 2);
        assert_eq!(pool.allocation_count(), 2);

        pool.free(fallback).expect("fallback block must deallocate directly");
        assert_eq!(pool.available_count(), 0);
        assert_eq!(pool.allocation_count(), 1);
        assert_eq!(pool.in_use_count(), 1);

        pool.free(preallocated).expect("preallocated block must return to available cache");
        assert_eq!(pool.available_count(), 1);
        assert_eq!(pool.allocation_count(), 1);
        assert_eq!(pool.in_use_count(), 0);
    }
}

#[test]
fn test_pool_prefetch_bounds_undersized_block() {
    let pool = Arc::new(UnsafeMemoryPool::new(1, 1, 0));

    // SAFETY: new() rounds this block to one 64-byte cache line. The prefetch helper
    // must issue only the offset zero hint and the block is returned once afterward.
    unsafe {
        let ptr = pool.alloc_uninit();
        pool.prefetch_block(ptr.as_ptr());
        pool.free(ptr).expect("undersized-prefetch block must return");
    }
}

#[test]
fn test_packet_constructor_rejects_invalid_runtime_parts() {
    let pool = Arc::new(UnsafeMemoryPool::new(1, 128, 0));

    // SAFETY: ptr is live and valid for the final constructor call. The first two calls
    // intentionally fail before taking ownership, so ptr remains available for cleanup.
    unsafe {
        let ptr = pool.alloc_uninit();
        assert!(matches!(
            UnsafePacket::from_raw_parts(ptr, 129, 128, Arc::clone(&pool)),
            Err(UnsafeError::InvalidPacket)
        ));
        assert!(matches!(
            UnsafePacket::from_raw_parts(ptr, 0, 129, Arc::clone(&pool)),
            Err(UnsafeError::InvalidPacket)
        ));
        assert_eq!(pool.in_use_count(), 1);

        let packet = UnsafePacket::from_raw_parts(ptr, 0, 128, Arc::clone(&pool))
            .expect("valid packet parts must be admitted");
        drop(packet);
        assert_eq!(pool.in_use_count(), 0);
    }
}

#[test]
fn test_packet_extend_supports_overlapping_source() {
    let pool = Arc::new(UnsafeMemoryPool::new(1, 128, 0));

    // SAFETY: the seed is copied into the live block, and the source slice is an alias
    // within that same block. extend_from_slice uses ptr::copy, which supports overlap.
    unsafe {
        let ptr = pool.alloc_uninit();
        let seed = *b"ABCDEFGH";
        ptr::copy(seed.as_ptr(), ptr.as_ptr(), seed.len());
        let mut packet = UnsafePacket::from_raw_parts(ptr, 4, 128, Arc::clone(&pool))
            .expect("valid overlapping packet parts");
        let source = slice::from_raw_parts(ptr.as_ptr().add(2), 4);
        packet.extend_from_slice(source).expect("overlapping extension must succeed");
        assert_eq!(packet.as_slice(), b"ABCDCDEF");
    }
}

#[test]
fn test_packet_extend_checked_addition_overflow() {
    let pool = Arc::new(UnsafeMemoryPool::new(1, 128, 0));

    // SAFETY: this test-only state reaches checked_add before any packet memory is read
    // or written. The live pointer remains valid and is returned by Drop afterward.
    unsafe {
        let ptr = pool.alloc_uninit();
        let mut packet = UnsafePacket {
            data: ptr,
            len: usize::MAX,
            capacity: usize::MAX,
            pool: Arc::clone(&pool),
        };
        assert_eq!(packet.extend_from_slice(&[1]), Err(UnsafeError::CapacityOverflow));
    }
    assert_eq!(pool.in_use_count(), 0);
}

#[test]
fn test_pool_concurrent_alloc_free() {
    let pool = Arc::new(UnsafeMemoryPool::new(4, 256, 0));
    let mut workers = Vec::new();

    for worker_id in 0..8u8 {
        let pool = Arc::clone(&pool);
        workers.push(std::thread::spawn(move || {
            for iteration in 0..200u16 {
                // SAFETY: each worker owns its block until free, and all pointers are
                // obtained from and returned to the same synchronized pool.
                unsafe {
                    let ptr = pool.alloc_uninit();
                    let marker = [worker_id, iteration as u8, 0xA5, 0x5A];
                    let written = pool
                        .copy_from_slice(ptr, &marker)
                        .expect("concurrent live copy must succeed");
                    assert_eq!(written, marker.len());
                    pool.free(ptr).expect("concurrent block must return");
                }
            }
        }));
    }

    for worker in workers {
        worker.join().expect("pool worker must complete");
    }
    assert_eq!(pool.in_use_count(), 0);
    assert_eq!(pool.available_count(), 4);
    assert_eq!(pool.allocation_count(), 4);
}

#[test]
fn test_unsafe_error_variants() {
    // Verify UnsafeError enum is Copy/Eq
    let e1 = UnsafeError::CapacityOverflow;
    let e2 = UnsafeError::CompressionFailed;
    assert_ne!(e1, e2);
    let e3 = e1; // Copy
    assert_eq!(e1, e3);
}
