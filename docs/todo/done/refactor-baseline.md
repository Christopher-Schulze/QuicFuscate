# Optimize Refactor Baseline

Date: 2026-01-24

This baseline is a forensic snapshot of the public surface and module layout before refactoring.

## Source Files Covered
- `src/accelerate.rs` (lines: 9976)
- `src/simd.rs` (lines: 7445)
- `src/optimize.rs` (use dependency graph only)

## Module Block Line Ranges (accelerate.rs)
```
L14-L559 module transport_io
L560-L1189 module random
L1190-L1815 module iter
L1816-L2482 module sort
L2483-L3971 module string
L3972-L4172 module compress
L4173-L6719 module brain
L6720-L8046 module stealth
L8047-L9361 module transport
L9362-L9976 module memory
```

## Public API Inventory (accelerate.rs)
```
L37 struct UdpGsoConfig
L85 fn enable
L117 fn send_batch
L222 fn send_batch
L354 struct ZeroCopySocket
L360 fn new
L380 fn send_zerocopy
L505 struct BusyPollSocket
L510 fn new
L533 struct NicParallelism
L537 fn configure_rps
L582 fn random_u64
L612 fn random_bytes_secure
L654 struct AesCtrDrbg
L661 fn new
L666 fn next_u64
L700 fn fill_bytes
L754 struct AesCtrDrbg
L761 fn new
L768 fn next_u64
L775 fn fill_bytes
L888 struct AesCtrDrbg
L892 fn new
L897 fn next_u64
L902 fn fill_bytes
L909 fn random_array_u32
L1025 fn shuffle
L1195 fn sum_f32
L1269 fn sum_u32
L1341 fn sum_u64
L1830 fn sort_u32
L2227 fn sort_f32
L2291 fn argsort
L2493 fn string_equals
L2648 fn string_contains
L2819 fn validate_utf8
L3043 fn parse_u64
L3111 fn base64_encode
L3510 fn base64_decode
L3978 struct PayloadCounters
L3990 fn merge
L4002 fn classify
L4184 fn compute_statistics
L4448 fn decay_histogram
L4524 fn jensen_shannon_divergence
L4898 fn __test_decay_histogram_avx512
L4905 fn __test_decay_histogram_avx2
L4912 fn __test_decay_histogram_sse41
L4919 fn __test_jensen_shannon_avx512
L4924 fn __test_jensen_shannon_avx2
L4929 fn __test_jensen_shannon_sse41
L5099 fn compute_correlation
L5407 fn moving_average
L5688 fn matrix_multiply
L6082 fn compute_percentile
L6190 fn relu_batch
L6348 fn softmax_batch
L6734 struct AsciiSimdBackend
L6740 fn detect
L6745 fn append_bytes
L6750 fn append_decimal
L6757 fn append_lower_hex
L6765 fn append_ascii_simd
L6770 fn append_decimal_simd
L6775 fn append_lower_hex_simd
L6970 fn inject_pattern
L7180 fn mix_entropy
L7350 fn generate_http_headers
L7456 fn add_tls_padding
L7570 fn gfni_padding_bytes
L7666 fn generate_fake_hmac
L7699 fn shape_traffic_pattern
L7819 fn titlecase_header_name
L7950 fn count_ascii_printable
L8069 struct CongestionSample
L8078 fn from_transport_stats
L8090 struct CongestionSummary
L8100 fn aggregate_congestion
L8401 fn ack_range_search
L8512 fn bitmap_set_range
L8734 fn count_ecn_marks
L8879 fn decode_packet_number
L9021 fn parse_stream_frames
L9376 fn memcpy_non_temporal
L9455 fn transpose_matrix
L9719 fn prefetch_sequential
L9760 fn prefetch_random
L9799 fn alloc_cache_aligned
L9818 fn clear_cache_lines
L9871 struct LockFreeRingBuffer
L9880 fn new
L9892 fn push
L9927 fn pop
L9966 fn alloc_numa_local
L9973 fn alloc_numa_local
```

## Public API Inventory (simd.rs)
```
L132 struct AccelerationPlans
L145 struct AccelerationPlanner
L148 fn global
L183 fn crypto_default_aead
L187 fn crypto_aead_for_len
L193 struct CryptoPlan
L275 struct FecPlan
L300 struct TransportPlan
L335 struct StealthPlan
L356 struct BrainPlan
L383 struct MemoryPlan
L402 struct UtilityPlan
L434 fn as_str
L449 fn sha256_digest
L482 fn sha256_digest
L495 fn select
L510 fn select_for_len
L1950 struct SimdOps
L1954 fn instance
L1963 fn dispatch
L2011 fn xor_blocks
L2043 fn memcpy_fast
L2075 fn crc32
L2093 fn popcnt
L2124 fn gf_mul
L2167 fn gf4_mul
L2324 fn gf16_mul
L2501 fn aes_encrypt_block
L2526 fn ghash
L2683 fn sha256
L2698 fn hmac_sha256
L2721 fn histogram
L2758 fn encode_huff_into
L2787 fn find_pattern
L2826 fn dot_product_f32
L2855 fn matmul_amx
L4729 fn berlekamp_massey_gf256
L4766 fn parse_header_bmi2
L4793 fn decode_varint
L4813 fn validate_header
L4856 fn pack_bits
L4881 fn unpack_bits
L4916 fn encode_varint
L4978 fn decode_varint
L4984 fn decode_varint
L4990 fn decode_varint
L5022 fn compare
L5052 fn qpack_encode
L5080 fn qpack_decode
L5584 fn xor_multi_key
L6612 fn gf_pow
L6623 fn xor_blocks
L6629 fn memcpy
L6633 fn crc32
L6667 fn popcnt
L6671 fn gf_mul
L6677 fn gf_mul_byte
L6695 fn aes_encrypt_block
L6701 fn ghash
L6706 fn sha256
L6710 fn histogram
L6718 fn find_pattern
L6722 fn dot_product_f32
L6726 fn matmul
L6738 fn berlekamp_massey
L6787 fn matmul_gf256
L6806 fn reed_solomon_encode
L6855 fn reed_solomon_decode
L6879 fn qpack_encode
L6885 fn qpack_decode
L6891 fn validate_header
L6899 fn pack_bits
L6926 fn unpack_bits
L6952 fn encode_varint
L6965 fn decode_varint
L6987 fn gf_inv
L7299 fn sha256
L7417 fn hmac_sha256
```

## Dependency Graph (use statements)

### accelerate.rs
```
L8 use crate::optimize::{CpuProfile, FeatureDetector};
L18 use libc::{c_void, iovec, msghdr, sockaddr_storage, socklen_t};
L19 use std::net::{SocketAddr, UdpSocket};
L20 use std::os::unix::io::{AsRawFd, RawFd};
L44 use std::arch::aarch64::*;
L81 use std::arch::x86_64::*;
L118 use std::mem::MaybeUninit;
L227 use std::sync::atomic::Ordering;
L562 use crate::optimize::CpuFeature;
L564 use crate::optimize::CpuProfile;
L566 use crate::optimize::FeatureDetector;
L568 use crate::optimize::{CpuFeature, FeatureDetector};
L570 use rand::rngs::OsRng;
L572 use rand::Rng;
L573 use rand::RngCore;
L576 use std::arch::x86_64::*;
L578 use std::cell::RefCell;
L785 use std::arch::aarch64::*;
L1068 use rand::seq::SliceRandom;
L1098 use rand::seq::SliceRandom;
L1106 use std::arch::aarch64::*;
L1191 use crate::optimize::telemetry;
L1192 use crate::optimize::{CpuProfile, FeatureDetector};
L1430 use std::arch::x86_64::*;
L1450 use std::arch::x86_64::*;
L1472 use std::arch::aarch64::*;
L1494 use std::arch::x86_64::*;
L1516 use std::arch::aarch64::*;
L1551 use std::arch::x86_64::*;
L1577 use std::arch::x86_64::*;
L1604 use std::arch::aarch64::*;
L1627 use std::arch::x86_64::*;
L1655 use std::arch::aarch64::*;
L1690 use std::arch::x86_64::*;
L1712 use std::arch::x86_64::*;
L1734 use std::arch::aarch64::*;
L1756 use std::arch::x86_64::*;
L1778 use std::arch::aarch64::*;
L1817 use crate::optimize::telemetry;
L1818 use crate::optimize::FeatureDetector;
L1820 use crate::simd::CpuProfile;
L1822 use std::any::TypeId;
L1823 use std::slice;
L1826 use std::arch::x86_64::*;
L2041 use std::arch::aarch64::*;
L2133 use std::arch::aarch64::*;
L2369 use core::cmp::Ordering;
L2429 use core::cmp::Ordering;
L2430 use std::arch::aarch64::*;
L2488 use crate::optimize::CpuProfile;
L2489 use crate::optimize::FeatureDetector;
L2540 use std::arch::x86_64::*;
L2574 use std::arch::aarch64::*;
L2621 use std::arch::aarch64::*;
L2705 use std::arch::x86_64::*;
L2755 use std::arch::aarch64::*;
L2860 use std::arch::x86_64::*;
L2968 use std::arch::aarch64::*;
L3016 use std::arch::aarch64::*;
L3067 use std::arch::x86_64::*;
L3179 use std::arch::x86_64::*;
L3243 use std::arch::aarch64::*;
L3317 use std::arch::aarch64::*;
L3430 use std::arch::aarch64::*;
L3471 use std::arch::aarch64::*;
L3557 use base64::engine::general_purpose::STANDARD;
L3558 use base64::Engine;
L3566 use base64::engine::general_purpose::STANDARD;
L3567 use base64::Engine;
L3568 use std::arch::x86_64::*;
L3658 use base64::engine::general_purpose::STANDARD;
L3659 use base64::Engine;
L3660 use std::arch::x86_64::*;
L3749 use base64::engine::general_purpose::STANDARD;
L3750 use base64::Engine;
L3751 use std::arch::aarch64::*;
L3838 use base64::engine::general_purpose::STANDARD;
L3839 use base64::Engine;
L3840 use std::arch::aarch64::*;
L3946 use std::arch::aarch64::*;
L3975 use crate::optimize::{CpuProfile, FeatureDetector};
L4075 use std::arch::x86_64::*;
L4123 use std::arch::aarch64::*;
L4177 use crate::optimize::telemetry;
L4178 use crate::optimize::{CpuFeature, FeatureDetector};
L4180 use crate::simd::CpuProfile;
L4232 use std::arch::x86_64::*;
L4292 use std::arch::x86_64::*;
L4340 use std::arch::aarch64::*;
L4410 use std::arch::aarch64::*;
L4591 use std::arch::x86_64::*;
L4603 use std::arch::x86_64::*;
L4619 use std::arch::x86_64::*;
L4633 use std::arch::x86_64::*;
L4647 use std::arch::x86_64::*;
L4662 use std::arch::x86_64::*;
L4676 use std::arch::x86_64::*;
L4690 use std::arch::x86_64::*;
L4717 use std::arch::x86_64::*;
L4744 use std::arch::x86_64::*;
L4771 use std::arch::x86_64::*;
L4814 use std::arch::x86_64::*;
L4857 use std::arch::x86_64::*;
L4936 use std::arch::aarch64::*;
L4959 use std::arch::aarch64::*;
L4997 use std::arch::aarch64::*;
L5045 use std::arch::aarch64::*;
L5162 use std::arch::x86_64::*;
L5201 use std::arch::x86_64::*;
L5252 use std::arch::aarch64::*;
L5310 use std::arch::aarch64::*;
L5353 use std::arch::x86_64::*;
L5364 use std::arch::x86_64::*;
L5388 use std::arch::x86_64::*;
L5398 use std::arch::x86_64::*;
L5473 use std::arch::x86_64::*;
L5527 use std::arch::x86_64::*;
L5581 use std::arch::x86_64::*;
L5635 use std::arch::aarch64::*;
L5871 use std::arch::x86_64::*;
L5918 use std::arch::x86_64::*;
L5979 use std::arch::aarch64::*;
L6046 use std::arch::aarch64::*;
L6245 use std::arch::x86_64::*;
L6267 use std::arch::x86_64::*;
L6288 use std::arch::aarch64::*;
L6322 use std::arch::aarch64::*;
L6400 use std::arch::x86_64::*;
L6465 use std::arch::x86_64::*;
L6564 use std::arch::aarch64::*;
L6650 use std::arch::aarch64::*;
L6685 use std::arch::x86_64::*;
L6696 use std::arch::x86_64::*;
L6725 use crate::optimize::CpuProfile;
L6726 use crate::optimize::FeatureDetector;
L6728 use std::arch::x86_64::*;
L6885 use std::arch::x86_64::*;
L6919 use std::arch::x86_64::*;
L6945 use std::arch::aarch64::*;
L7066 use std::arch::x86_64::*;
L7124 use std::arch::aarch64::*;
L7268 use std::arch::x86_64::*;
L7339 use std::arch::aarch64::*;
L7536 use std::arch::x86_64::*;
L7610 use std::arch::x86_64::*;
L7639 use std::arch::aarch64::*;
L7672 use crate::optimize::CpuFeature;
L7681 use crate::optimize::CpuFeature;
L7731 use std::arch::x86_64::*;
L7792 use std::arch::aarch64::*;
L7898 use std::arch::x86_64::*;
L7924 use std::arch::aarch64::*;
L7999 use std::arch::x86_64::*;
L8024 use std::arch::aarch64::*;
L8052 use crate::optimize::telemetry::CONGESTION_NEON_BATCHES;
L8054 use crate::optimize::telemetry::{CONGESTION_AVX2_BATCHES, CONGESTION_VNNI_BATCHES};
L8056 use crate::optimize::CpuProfile;
L8058 use crate::optimize::CpuProfile;
L8059 use crate::optimize::FeatureDetector;
L8060 use crate::transport::Stats;
L8062 use std::arch::x86_64::*;
L8192 use std::arch::x86_64::*;
L8263 use std::arch::x86_64::*;
L8274 use std::arch::x86_64::*;
L8284 use std::arch::aarch64::*;
L8354 use std::arch::aarch64::*;
L8363 use std::arch::aarch64::*;
L8422 use crate::optimize::CpuProfile;
L8481 use std::arch::aarch64::*;
L8584 use std::arch::aarch64::*;
L8655 use std::arch::aarch64::*;
L8802 use std::arch::aarch64::*;
L8834 use std::arch::aarch64::*;
L8966 use std::arch::aarch64::*;
L9000 use std::arch::aarch64::*;
L9099 use std::arch::aarch64::*;
L9202 use std::arch::x86_64::*;
L9336 use super::*;
L9367 use crate::optimize::CpuProfile;
L9369 use crate::optimize::CpuProfile;
L9370 use crate::optimize::FeatureDetector;
L9372 use std::arch::x86_64::*;
L9565 use std::arch::aarch64::*;
L9616 use std::arch::aarch64::*;
```

### optimize.rs
```
L7 use cpufeatures;
L9 use crossbeam_queue::{ArrayQueue, SegQueue};
L18 use libc::{iovec, msghdr, recvmsg, sendmsg};
L19 use log::{error, info, warn};
L20 use serde::Deserialize;
L22 use smallvec::SmallVec;
L23 use std::any::Any;
L24 use std::cell::RefCell;
L25 use std::collections::HashSet;
L26 use std::io;
L27 use std::net::SocketAddr;
L29 use std::os::unix::io::RawFd;
L30 use std::sync::atomic::{AtomicUsize, Ordering};
L31 use std::sync::{Arc, OnceLock};
L39 use x86_sse2::xor_repeating_key32_sse2;
L74 use windows_sys::Win32::Networking::WinSock::{WSARecvMsg, WSASendMsg, WSABUF, WSAMSG};
L78 use libc::{c_int, c_void, size_t};
L122 use std::sync::atomic::{AtomicUsize, Ordering};
L123 use windows_sys::Win32::System::SystemInformation::{
L807 use std::process::Command;
L832 use std::fs;
L923 use std::arch::is_riscv_feature_detected;
L1303 use std::arch::x86_64::*;
L1336 use std::arch::x86_64::*;
L1370 use std::arch::x86_64::*;
L1388 use std::arch::x86_64::*;
L1405 use std::arch::aarch64::*;
L1428 use std::arch::aarch64::*;
L1779 use super::{bitslice_policy_tag, dispatch_bitslice, with_override};
L1780 use crate::simd::{CpuFeature, FeatureDetector};
L1982 use std::thread;
L2035 use std::sync::atomic::Ordering;
L2503 use std::sync::OnceLock as LocalOnce;
L2544 use socket2::SockAddr;
L2574 use socket2::SockAddr;
L2626 use libc::{mmsghdr, sockaddr, socklen_t};
L2734 use socket2::SockAddr;
L2767 use socket2::SockAddr;
L2768 use windows_sys::Win32::Networking::WinSock::SOCKADDR_STORAGE;
L2900 use super::ZeroCopyBuffer;
L2902 use std::io::{self, Error};
L2904 use std::net::SocketAddr;
L2906 use std::os::unix::io::{AsRawFd, RawFd};
L2909 use thiserror::Error;
L2912 use {
L3118 use std::time::Instant;
L3165 use std::time::Instant;
L3330 use std::io::ErrorKind;
L3335 use std::io::ErrorKind;
L3340 use std::io::ErrorKind;
L3345 use std::io::ErrorKind;
L3366 use libc;
L3367 use std::net::{SocketAddr, UdpSocket};
L3368 use std::sync::Arc;
L3538 use super::{FeatureDetector, SimdDispatch};
L3544 use super::super::telemetry;
L3545 use super::super::{FeatureDetector, SimdDispatch};
L3675 use std::arch::x86_64::*;
L3694 use std::arch::x86_64::*;
L3744 use std::arch::x86_64::*;
L3782 use std::arch::x86_64::*;
L3820 use std::arch::aarch64::*;
L3872 use std::arch::aarch64::*;
L3926 use std::arch::x86_64::*;
L3969 use std::arch::aarch64::*;
L4069 use super::FeatureDetector;
L4104 use std::arch::x86_64::*;
L4131 use std::arch::x86_64::*;
L4191 use std::arch::aarch64::*;
L4248 use std::arch::aarch64::*;
L4313 use std::sync::{Mutex, OnceLock};
L4316 use super::FeatureDetector;
L4349 use crate::crypto::chacha::chacha20_block;
L4389 use crate::crypto::chacha::chacha20_block;
L4489 use crate::crypto::chacha::chacha20_block;
L4517 use std::arch::x86_64::*;
L4667 use std::arch::x86_64::*;
L4721 use std::arch::x86_64::*;
L4728 use std::arch::x86_64::*;
L4842 use std::arch::aarch64::*;
L4989 use std::arch::x86_64::*;
L4998 use std::arch::x86_64::*;
L5012 use std::arch::aarch64::*;
L5033 use std::arch::x86_64::*;
L5063 use super::FeatureDetector;
L5115 use super::FeatureDetector;
L5143 use std::arch::x86_64::*;
L5163 use std::arch::x86_64::*;
L5191 use super::FeatureDetector;
L5261 use std::arch::x86_64::*;
L5295 use std::arch::x86_64::*;
L5329 use std::arch::x86_64::*;
L5363 use std::arch::aarch64::*;
L5397 use std::arch::aarch64::*;
L5430 use std::arch::x86_64::*;
L5483 use std::arch::x86_64::*;
L5533 use std::arch::aarch64::*;
L5612 use std::arch::aarch64::*;
L5755 use std::mem::MaybeUninit;
L5793 use core::arch::x86_64::{_mm_prefetch, _MM_HINT_NTA, _MM_HINT_T0, _MM_HINT_T1};
L6191 use lazy_static::lazy_static;
L6192 use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
L6239 use std::fmt::Write as _;
L6978 use sysinfo::ProcessesToUpdate;
L6998 use std::sync::atomic::AtomicBool;
```

## Invariants
- Public API names and signatures listed above must not change.
- Telemetry counters must retain names and semantics.
- Module block line ranges serve as an anchor for refactor mapping.

## 32-bit Constraints
- 32-bit targets to keep in scope:
  - `i686-unknown-linux-gnu`
  - `armv7-unknown-linux-gnueabihf`
  - `i686-pc-windows-msvc` (optional if toolchain is available)
- No unchecked arithmetic that can overflow `u32` or truncate `usize`.
- Use `checked_*` on frame length math and varint-derived sizes in refactor slices.

## Telemetry Counters (optimize/telemetry.rs)
```
L6196 ZC_COMPLETIONS_TOTAL
L6198 ZC_COMPLETED_BYTES_TOTAL
L6200 ZEROCOPY_SEND_CALLS
L6202 ZEROCOPY_SEND_FALLBACKS
L6208 H3_FRAMES
L6209 H3_HEADERS
L6210 H3_DATA_BYTES
L6211 H3_ERRORS
L6214 MASQUE_ACTIVE
L6218 AEGIS_PLAN
L6221 MASQUE_HINT
L6224 IP_V4_PACKETS
L6225 IP_V6_PACKETS
L6226 IP_TOS_SUM
L6227 IP_TOS_SAMPLES
L6230 STEALTH_SIGNAL_RTT_SPIKES
L6231 STEALTH_SIGNAL_ECN_CE
L6232 STEALTH_SIGNAL_RST
L6233 STEALTH_SIGNAL_TOS_ANOM
L6234 STEALTH_SIGNAL_OTHER
L6505 UNSAFE_POOL_CREATED
L6506 UNSAFE_POOL_CAPACITY
L6507 UNSAFE_ALLOC_CALLS
L6508 UNSAFE_FREE_CALLS
L6509 UNSAFE_TLS_HITS
L6510 UNSAFE_GLOBAL_HITS
L6511 UNSAFE_FALLBACK_ALLOCS
L6512 UNSAFE_DEALLOCS
L6515 SIMD_GF_OPS
L6516 SIMD_XOR_OPS
L6517 SIMD_PREFETCH_OPS
L6520 UNSAFE_COMPRESS_CALLS
L6521 UNSAFE_COMPRESS_FAILURES
L6522 UNSAFE_COMPRESS_BYTES_IN
L6523 UNSAFE_COMPRESS_BYTES_OUT
L6526 ENTROPY_CALCULATIONS
L6527 ENTROPY_SIMD_USED
L6530 ZERO_COPY_SENDS
L6531 ZERO_COPY_RECVS
L6532 IOSLICE_OPERATIONS
L6535 FEC_SIMD_ENCODE
L6536 FEC_SIMD_DECODE
L6537 FEC_AVX2_OPS
L6538 BRAIN_HISTOGRAM_AVX512_OPS
L6539 BRAIN_HISTOGRAM_AVX2_OPS
L6540 BRAIN_HISTOGRAM_SSE_OPS
L6541 BRAIN_HISTOGRAM_NEON_OPS
L6542 BRAIN_HISTOGRAM_SVE2_OPS
L6543 BRAIN_HISTOGRAM_SCALAR_OPS
L6546 PLAN_DECISIONS_TOTAL
L6547 PLAN_DECISIONS_DEFAULT
L6548 PLAN_DECISIONS_LEN
L6549 PLAN_DECISIONS_X8
L6550 PLAN_DECISIONS_X4
L6551 PLAN_DECISIONS_L
L6552 PLAN_DECISIONS_NEON_X4
L6553 PLAN_DECISIONS_NEON_L
L6554 PLAN_DECISIONS_MORUS
L6557 COMPRESS_DECISIONS_TOTAL
L6558 COMPRESS_DECISIONS_ALLOW
L6559 COMPRESS_DECISIONS_SKIP_LEN
L6560 COMPRESS_DECISIONS_SKIP_LOSS
L6561 COMPRESS_DECISIONS_SKIP_PROFILE
L6564 GHASH_SCALAR_CALLS
L6565 GHASH_SCALAR_BYTES
L6566 FEC_AVX512_OPS
L6567 FEC_GF16_VBMI2_OPS
L6568 FEC_NEON_OPS
L6569 FEC_SVE2_OPS
L6570 FEC_BERLEKAMP_SVE2_OPS
L6573 AVX512_OPS
L6574 AVX2_OPS
L6576 NEON_OPS
L6577 SVE2_OPS
L6578 SCALAR_OPS
L6581 AES_BLOCK_AESNI_OPS
L6582 AES_BLOCK_VAES_OPS
L6583 AES_BLOCK_AESE_OPS
L6584 AES_BLOCK_SSSE3_OPS
L6585 AES_BLOCK_SVE_OPS
L6586 AES_BLOCK_NEON_TABLE_OPS
L6587 AES_BLOCK_SCALAR_OPS
L6588 SHA256_AVX2_OPS
L6589 SHA256_VNNI_OPS
L6590 SHA256_SHA_OPS
L6591 SHA256_NEON_OPS
L6592 SHA256_SVE2_OPS
L6593 SHA256_SCALAR_OPS
L6594 HMAC_SHA256_AVX2_OPS
L6595 HMAC_SHA256_VNNI_OPS
L6596 HMAC_SHA256_SHA_OPS
L6597 HMAC_SHA256_NEON_OPS
L6598 HMAC_SHA256_SVE2_OPS
L6599 HMAC_SHA256_SCALAR_OPS
L6602 GHASH_PCLMUL_OPS
L6603 GHASH_VPCLMUL_OPS
L6604 GHASH_PMULL_OPS
L6605 GHASH_NEON_OPS
L6606 GHASH_SSE_OPS
L6607 GHASH_SCALAR_OPS
L6610 CHACHA20_X4_AVX2_OPS
L6611 CHACHA20_X4_AVX_OPS
L6612 CHACHA20_X4_SSE41_OPS
L6613 CHACHA20_X4_NEON_OPS
L6614 CHACHA20_X4_SCALAR_OPS
L6617 CRC32_SSE42_OPS
L6618 CRC32_ARM_OPS
L6619 CRC32_SCALAR_OPS
L6622 FEC_AVX2_GF_OPS
L6623 FEC_SSSE3_OPS
L6624 FEC_GFNI_OPS
L6627 GF16_VPCLMUL_OPS
L6628 GF16_PCLMUL_OPS
L6629 GF16_PMULL_OPS
L6631 PATTERN_AVX512_VBMI2_OPS
L6632 PATTERN_AVX512_OPS
L6633 PATTERN_AVX2_OPS
L6634 PATTERN_NEON_OPS
L6635 PATTERN_SVE2_OPS
L6636 PATTERN_SCALAR_OPS
L6639 UNSAFE_SPEEDUP_FACTOR
L6640 UNSAFE_LATENCY_REDUCTION_US
L6641 UNSAFE_THROUGHPUT_GBPS
L6642 CRYPTO_PROFILE
L6645 AEGIS_BATCH_OPS
L6648 XDP_ACTIVE
L6649 XDP_FALLBACKS
L6650 XDP_BYTES_SENT
L6651 XDP_BYTES_RECEIVED
L6652 XDP_SEND_LATENCY
L6653 XDP_RECV_LATENCY
L6654 XDP_THROUGHPUT
L6657 MEM_POOL_CAPACITY
L6658 MEM_POOL_BLOCK_SIZE
L6659 MEM_POOL_IN_USE
L6660 MEM_POOL_USAGE_BYTES
L6661 MEM_POOL_FRAGMENTATION
L6662 MEM_POOL_UTILIZATION
L6664 MEM_POOL_NUMA_POLICY
L6667 SIMD_ACTIVE
L6668 SIMD_USAGE_AVX2
L6669 SIMD_USAGE_AVX512
L6670 SIMD_USAGE_AVX10_256
L6671 SIMD_USAGE_AVX10_512
L6673 SIMD_USAGE_SSE2
L6674 SIMD_USAGE_NEON
L6675 SIMD_USAGE_SCALAR
L6676 SIMD_USAGE_RVV
L6677 ARGSORT_AVX2_OPS
L6678 ARGSORT_NEON_OPS
L6679 ARGSORT_FALLBACK_OPS
L6680 MOVING_AVG_AVX512_OPS
L6681 MOVING_AVG_AVX2_OPS
L6682 MOVING_AVG_NEON_OPS
L6683 MOVING_AVG_SSE_OPS
L6684 MOVING_AVG_SCALAR_OPS
L6685 FAKETLS_CHACHA_OPS
L6686 FAKETLS_AES_GCM_OPS
L6687 FAKETLS_CIPHER_FAILURES
L6688 AES_CTR_AESNI_OPS
L6689 AES_CTR_AESE_OPS
L6690 AES_CTR_SVE_OPS
L6691 AES_CTR_SSSE3_OPS
L6692 AES_CTR_SCALAR_OPS
L6693 RNG_AES_CTR_OPS
L6694 POLY1305_AVX512_OPS
L6695 POLY1305_AVX2_OPS
L6696 POLY1305_SSE2_OPS
L6697 POLY1305_SVE_OPS
L6698 POLY1305_NEON_OPS
L6699 POLY1305_SCALAR_OPS
L6700 ITER_SUM_F32_AVX512_OPS
L6701 ITER_SUM_F32_AVX2_OPS
L6702 ITER_SUM_F32_SSE_OPS
L6703 ITER_SUM_F32_NEON_OPS
L6704 ITER_SUM_F32_SVE_OPS
L6705 ITER_SUM_F32_RVV_OPS
L6706 ITER_SUM_F32_SCALAR_OPS
L6707 ITER_SUM_U32_AVX512_OPS
L6708 ITER_SUM_U32_AVX2_OPS
L6709 ITER_SUM_U32_SSE_OPS
L6710 ITER_SUM_U32_NEON_OPS
L6711 ITER_SUM_U32_SVE_OPS
L6712 ITER_SUM_U32_RVV_OPS
L6713 ITER_SUM_U32_SCALAR_OPS
L6714 ITER_SUM_U64_AVX512_OPS
L6715 ITER_SUM_U64_AVX2_OPS
L6716 ITER_SUM_U64_SSE_OPS
L6717 ITER_SUM_U64_NEON_OPS
L6718 ITER_SUM_U64_SVE_OPS
L6719 ITER_SUM_U64_RVV_OPS
L6720 ITER_SUM_U64_SCALAR_OPS
L6723 CPU_FEATURE_MASK
L6726 MEMORY_USAGE_BYTES
L6727 BYTES_SENT
L6728 BYTES_RECEIVED
L6731 DECODING_TIME_MS
L6732 WIEDEMANN_USAGE
L6733 WIEDEMANN_AMX_OPS
L6734 WIEDEMANN_SCALAR_OPS
L6735 FEC_MODE
L6736 LOSS_RATE
L6737 FEC_MODE_SWITCHES
L6738 FEC_WINDOW
L6739 FEC_OVERFLOWS
L6740 DNS_ERRORS
L6742 FEC_EMITTED_QUEUE
L6743 FOUNTAIN_PROGRESS
L6744 FOUNTAIN_SYMBOL_SIZE
L6745 FEC_EMITTED_UNIQUE
L6746 FEC_EMITTED_ORDER_DEPTH
L6749 FEC_LAZY_SKIPPED
L6751 FEC_INTERLEAVE_REPAIRS
L6753 ZERO_MODE_UPGRADES
L6756 STEALTH_DOH
L6757 STEALTH_FRONTING
L6758 STEALTH_XOR
L6759 STEALTH_PADDING_GFNI_OPS
L6761 STEALTH_PUSH_PROMISES
L6762 STEALTH_PUSH_BYTES
L6764 CONGESTION_VNNI_BATCHES
L6765 CONGESTION_AVX2_BATCHES
L6766 CONGESTION_NEON_BATCHES
L6769 MASQUE_BYTES_SENT
L6770 MASQUE_BYTES_RECEIVED
L6771 MASQUE_CAPSULE_00
L6772 MASQUE_CAPSULE_21
L6773 MASQUE_CAPSULE_22
L6774 MASQUE_CAPSULE_00_BYTES
L6775 MASQUE_CAPSULE_21_BYTES
L6776 MASQUE_CAPSULE_22_BYTES
L6779 STEALTH_BROWSER_PROFILE
L6780 STEALTH_OS_PROFILE
L6783 URING_ACTIVE
L6784 URING_SEND_ATTEMPTS
L6785 URING_FALLBACKS
L6786 URING_BYTES_SENT
L6787 URING_BYTES_RECEIVED
L6788 URING_SUBMISSIONS
L6789 URING_COMPLETIONS
L6790 URING_ERRORS
L6791 URING_QUEUE_DEPTH
L6794 ACK_DELAY_LAST_US
L6795 ACK_DELAY_BUCKET_LE_1MS
L6796 ACK_DELAY_BUCKET_LE_4MS
L6797 ACK_DELAY_BUCKET_LE_16MS
L6798 ACK_DELAY_BUCKET_LE_64MS
L6799 ACK_DELAY_BUCKET_LE_256MS
L6800 ACK_DELAY_BUCKET_GT_256MS
L6803 CHOKE_SLEEP_MS
L6804 CHOKED_BYTES
L6807 COMPRESS_ATTEMPTS
L6808 COMPRESS_SUCCESS
L6809 COMPRESS_TRUNCATIONS
L6810 COMPRESS_DICT_USED
L6811 COMPRESS_BYTES_OUT
L6812 COMPRESS_BYTES_IN
L6813 ENTROPY_TEXTUAL_SEEN
L6814 ENTROPY_SKIP
L6815 COMPRESS_PREPROC_CALLS
L6816 COMPRESS_PREPROC_TEXTUAL
L6817 COMPRESS_PREPROC_BINARY
L6818 COMPRESS_PREPROC_ASCII_BYTES
L6819 COMPRESS_PREPROC_HIGH_BYTES
L6820 COMPRESS_PREPROC_NEWLINES
L6821 COMPRESS_PREPROC_NULLS
L6822 COMPRESS_PREPROC_CHUNKS
L6823 COMPRESS_PREPROC_CHUNK_REPEATS
L6826 BODY_POOL_BLOCK_SIZE
L6827 BODY_POOL_CAPACITY
L6828 BODY_POOL_ALLOCS
L6834 RS_ENC_TIME_NS
L6835 RS_DEC_TIME_NS
L6836 RS_REPAIR_EMITTED
L6837 RS_RECOVERED
L6838 RS_OVERHEAD_PPM
L6839 RS_WINDOW_K
L6840 RS_WINDOW_N
L6841 RS_GF_SIZE
L6844 MEM_POOL_HITS_TLS
L6845 MEM_POOL_HITS_QUEUE
L6846 MEM_POOL_ALLOC_GROW
L6847 MEM_POOL_ALLOC_EPHEMERAL
L6999 TELEMETRY_ENABLED
```

## Telemetry Counter Names (frozen)
```
ACK_DELAY_BUCKET_GT_256MS
ACK_DELAY_BUCKET_LE_16MS
ACK_DELAY_BUCKET_LE_1MS
ACK_DELAY_BUCKET_LE_256MS
ACK_DELAY_BUCKET_LE_4MS
ACK_DELAY_BUCKET_LE_64MS
ACK_DELAY_LAST_US
AEGIS_BATCH_OPS
AEGIS_PLAN
AES_BLOCK_AESE_OPS
AES_BLOCK_AESNI_OPS
AES_BLOCK_NEON_TABLE_OPS
AES_BLOCK_SCALAR_OPS
AES_BLOCK_SSSE3_OPS
AES_BLOCK_SVE_OPS
AES_BLOCK_VAES_OPS
AES_CTR_AESE_OPS
AES_CTR_AESNI_OPS
AES_CTR_SCALAR_OPS
AES_CTR_SSSE3_OPS
AES_CTR_SVE_OPS
ARGSORT_AVX2_OPS
ARGSORT_FALLBACK_OPS
ARGSORT_NEON_OPS
AVX2_OPS
AVX512_OPS
BODY_POOL_ALLOCS
BODY_POOL_BLOCK_SIZE
BODY_POOL_CAPACITY
BRAIN_HISTOGRAM_AVX2_OPS
BRAIN_HISTOGRAM_AVX512_OPS
BRAIN_HISTOGRAM_NEON_OPS
BRAIN_HISTOGRAM_SCALAR_OPS
BRAIN_HISTOGRAM_SSE_OPS
BRAIN_HISTOGRAM_SVE2_OPS
BYTES_RECEIVED
BYTES_SENT
CHACHA20_X4_AVX2_OPS
CHACHA20_X4_AVX_OPS
CHACHA20_X4_NEON_OPS
CHACHA20_X4_SCALAR_OPS
CHACHA20_X4_SSE41_OPS
CHOKED_BYTES
CHOKE_SLEEP_MS
COMPRESS_ATTEMPTS
COMPRESS_BYTES_IN
COMPRESS_BYTES_OUT
COMPRESS_DECISIONS_ALLOW
COMPRESS_DECISIONS_SKIP_LEN
COMPRESS_DECISIONS_SKIP_LOSS
COMPRESS_DECISIONS_SKIP_PROFILE
COMPRESS_DECISIONS_TOTAL
COMPRESS_DICT_USED
COMPRESS_PREPROC_ASCII_BYTES
COMPRESS_PREPROC_BINARY
COMPRESS_PREPROC_CALLS
COMPRESS_PREPROC_CHUNKS
COMPRESS_PREPROC_CHUNK_REPEATS
COMPRESS_PREPROC_HIGH_BYTES
COMPRESS_PREPROC_NEWLINES
COMPRESS_PREPROC_NULLS
COMPRESS_PREPROC_TEXTUAL
COMPRESS_SUCCESS
COMPRESS_TRUNCATIONS
CONGESTION_AVX2_BATCHES
CONGESTION_NEON_BATCHES
CONGESTION_VNNI_BATCHES
CPU_FEATURE_MASK
CRC32_ARM_OPS
CRC32_SCALAR_OPS
CRC32_SSE42_OPS
CRYPTO_PROFILE
DECODED_PACKETS
DECODED_PARTIAL_PACKETS
DECODING_TIME_MS
DNS_ERRORS
ENCODED_PACKETS
ENTROPY_CALCULATIONS
ENTROPY_SIMD_USED
ENTROPY_SKIP
ENTROPY_TEXTUAL_SEEN
FAKETLS_AES_GCM_OPS
FAKETLS_CHACHA_OPS
FAKETLS_CIPHER_FAILURES
FEC_AVX2_GF_OPS
FEC_AVX2_OPS
FEC_AVX512_OPS
FEC_BERLEKAMP_SVE2_OPS
FEC_EMITTED_ORDER_DEPTH
FEC_EMITTED_QUEUE
FEC_EMITTED_UNIQUE
FEC_GF16_VBMI2_OPS
FEC_GFNI_OPS
FEC_INTERLEAVE_REPAIRS
FEC_LAZY_SKIPPED
FEC_MODE
FEC_MODE_SWITCHES
FEC_NEON_OPS
FEC_OVERFLOWS
FEC_PACKETS_DECODED
FEC_PACKETS_ENCODED
FEC_PACKETS_RECOVERED
FEC_SIMD_DECODE
FEC_SIMD_ENCODE
FEC_SSSE3_OPS
FEC_SVE2_OPS
FEC_WINDOW
FOUNTAIN_PROGRESS
FOUNTAIN_SYMBOL_SIZE
GF16_PCLMUL_OPS
GF16_PMULL_OPS
GF16_VPCLMUL_OPS
GHASH_NEON_OPS
GHASH_PCLMUL_OPS
GHASH_PMULL_OPS
GHASH_SCALAR_BYTES
GHASH_SCALAR_CALLS
GHASH_SCALAR_OPS
GHASH_SSE_OPS
GHASH_VPCLMUL_OPS
H3_DATA_BYTES
H3_ERRORS
H3_FRAMES
H3_HEADERS
HMAC_SHA256_AVX2_OPS
HMAC_SHA256_NEON_OPS
HMAC_SHA256_SCALAR_OPS
HMAC_SHA256_SHA_OPS
HMAC_SHA256_SVE2_OPS
HMAC_SHA256_VNNI_OPS
IOSLICE_OPERATIONS
IP_TOS_SAMPLES
IP_TOS_SUM
IP_V4_PACKETS
IP_V6_PACKETS
ITER_SUM_F32_AVX2_OPS
ITER_SUM_F32_AVX512_OPS
ITER_SUM_F32_NEON_OPS
ITER_SUM_F32_RVV_OPS
ITER_SUM_F32_SCALAR_OPS
ITER_SUM_F32_SSE_OPS
ITER_SUM_F32_SVE_OPS
ITER_SUM_U32_AVX2_OPS
ITER_SUM_U32_AVX512_OPS
ITER_SUM_U32_NEON_OPS
ITER_SUM_U32_RVV_OPS
ITER_SUM_U32_SCALAR_OPS
ITER_SUM_U32_SSE_OPS
ITER_SUM_U32_SVE_OPS
ITER_SUM_U64_AVX2_OPS
ITER_SUM_U64_AVX512_OPS
ITER_SUM_U64_NEON_OPS
ITER_SUM_U64_RVV_OPS
ITER_SUM_U64_SCALAR_OPS
ITER_SUM_U64_SSE_OPS
ITER_SUM_U64_SVE_OPS
LOSS_RATE
MASQUE_ACTIVE
MASQUE_BYTES_RECEIVED
MASQUE_BYTES_SENT
MASQUE_CAPSULE_00
MASQUE_CAPSULE_00_BYTES
MASQUE_CAPSULE_21
MASQUE_CAPSULE_21_BYTES
MASQUE_CAPSULE_22
MASQUE_CAPSULE_22_BYTES
MASQUE_HINT
MEMORY_USAGE_BYTES
MEM_POOL_ALLOC_EPHEMERAL
MEM_POOL_ALLOC_GROW
MEM_POOL_BLOCK_SIZE
MEM_POOL_CAPACITY
MEM_POOL_FRAGMENTATION
MEM_POOL_HITS_QUEUE
MEM_POOL_HITS_TLS
MEM_POOL_IN_USE
MEM_POOL_NUMA_POLICY
MEM_POOL_USAGE_BYTES
MEM_POOL_UTILIZATION
MOVING_AVG_AVX2_OPS
MOVING_AVG_AVX512_OPS
MOVING_AVG_NEON_OPS
MOVING_AVG_SCALAR_OPS
MOVING_AVG_SSE_OPS
NEON_OPS
PACKETS_LOST
PACKETS_RECEIVED
PACKETS_SENT
PATH_MIGRATIONS
PATTERN_AVX2_OPS
PATTERN_AVX512_OPS
PATTERN_AVX512_VBMI2_OPS
PATTERN_NEON_OPS
PATTERN_SCALAR_OPS
PATTERN_SVE2_OPS
PLAN_DECISIONS_DEFAULT
PLAN_DECISIONS_L
PLAN_DECISIONS_LEN
PLAN_DECISIONS_MORUS
PLAN_DECISIONS_NEON_L
PLAN_DECISIONS_NEON_X4
PLAN_DECISIONS_TOTAL
PLAN_DECISIONS_X4
PLAN_DECISIONS_X8
POLY1305_AVX2_OPS
POLY1305_AVX512_OPS
POLY1305_NEON_OPS
POLY1305_SCALAR_OPS
POLY1305_SSE2_OPS
POLY1305_SVE_OPS
RNG_AES_CTR_OPS
RS_DEC_TIME_NS
RS_ENC_TIME_NS
RS_GF_SIZE
RS_OVERHEAD_PPM
RS_RECOVERED
RS_REPAIR_EMITTED
RS_WINDOW_K
RS_WINDOW_N
SCALAR_OPS
SHA256_AVX2_OPS
SHA256_NEON_OPS
SHA256_SCALAR_OPS
SHA256_SHA_OPS
SHA256_SVE2_OPS
SHA256_VNNI_OPS
SIMD_ACTIVE
SIMD_GF_OPS
SIMD_PREFETCH_OPS
SIMD_USAGE_AVX10_256
SIMD_USAGE_AVX10_512
SIMD_USAGE_AVX2
SIMD_USAGE_AVX512
SIMD_USAGE_NEON
SIMD_USAGE_RVV
SIMD_USAGE_SCALAR
SIMD_USAGE_SSE2
SIMD_XOR_OPS
STEALTH_BROWSER_PROFILE
STEALTH_DOH
STEALTH_FRONTING
STEALTH_HEADERS_GENERATED
STEALTH_OS_PROFILE
STEALTH_PADDING_GFNI_OPS
STEALTH_PUSH_BYTES
STEALTH_PUSH_PROMISES
STEALTH_QPACK_POOL_FALLBACKS
STEALTH_SIGNAL_ECN_CE
STEALTH_SIGNAL_OTHER
STEALTH_SIGNAL_RST
STEALTH_SIGNAL_RTT_SPIKES
STEALTH_SIGNAL_TOS_ANOM
STEALTH_XOR
SVE2_OPS
TELEMETRY_ENABLED
TLS_PROVIDER_KIND
UNSAFE_ALLOC_CALLS
UNSAFE_COMPRESS_BYTES_IN
UNSAFE_COMPRESS_BYTES_OUT
UNSAFE_COMPRESS_CALLS
UNSAFE_COMPRESS_FAILURES
UNSAFE_DEALLOCS
UNSAFE_FALLBACK_ALLOCS
UNSAFE_FREE_CALLS
UNSAFE_GLOBAL_HITS
UNSAFE_LATENCY_REDUCTION_US
UNSAFE_POOL_CAPACITY
UNSAFE_POOL_CREATED
UNSAFE_SPEEDUP_FACTOR
UNSAFE_THROUGHPUT_GBPS
UNSAFE_TLS_HITS
URING_ACTIVE
URING_BYTES_RECEIVED
URING_BYTES_SENT
URING_COMPLETIONS
URING_ERRORS
URING_FALLBACKS
URING_QUEUE_DEPTH
URING_SEND_ATTEMPTS
URING_SUBMISSIONS
WIEDEMANN_AMX_OPS
WIEDEMANN_SCALAR_OPS
WIEDEMANN_USAGE
XDP_ACTIVE
XDP_BYTES_RECEIVED
XDP_BYTES_SENT
XDP_FALLBACKS
XDP_RECV_LATENCY
XDP_SEND_LATENCY
XDP_THROUGHPUT
ZC_COMPLETED_BYTES_TOTAL
ZC_COMPLETIONS_TOTAL
ZERO_COPY_RECVS
ZERO_COPY_SENDS
ZERO_MODE_UPGRADES
ZEROCOPY_SEND_CALLS
ZEROCOPY_SEND_FALLBACKS
```

## Phase 1 Freeze Lists
- API Freeze: the Public API Inventory sections in this file are the canonical freeze list.
- Telemetry Freeze: the Telemetry Counter Names section above is the canonical list.
