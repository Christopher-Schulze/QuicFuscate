#![allow(private_interfaces)]

use crate::gf16_mul_scalar_slice_padded;
use crate::gf_tables;
use crate::wire;
use aligned_box::AlignedBox;
use qf_memory_pool::{MemoryPool, PooledBlock};
use rayon::prelude::*;
use std::collections::VecDeque;
use std::sync::Arc;

const PAR_THRESHOLD: usize = 8192;

#[derive(Clone)]
pub struct SharedFecBuffer {
    inner: Arc<SharedFecBufferInner>,
}

struct SharedFecBufferInner {
    buf: Option<AlignedBox<[u8]>>,
    pool: Arc<MemoryPool>,
}

impl Drop for SharedFecBufferInner {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            self.pool.free(buf);
        }
    }
}

impl SharedFecBuffer {
    fn new(buf: AlignedBox<[u8]>, pool: Arc<MemoryPool>) -> Self {
        Self { inner: Arc::new(SharedFecBufferInner { buf: Some(buf), pool }) }
    }

    #[doc(hidden)]
    pub fn bytes(&self, len: usize) -> &[u8] {
        self.inner.buf.as_deref().map_or(&[], |buf| &buf[..len.min(buf.len())])
    }

    #[cfg(any(test, feature = "rust-tests"))]
    #[doc(hidden)]
    pub fn strong_count(&self) -> usize {
        std::sync::Arc::strong_count(&self.inner)
    }
}

/// Unified FEC packet carrying source or repair data with pool-managed buffers.
pub struct FecPacket {
    /// Unique packet identifier (source ID or repair window anchor).
    pub id: u64,
    /// Aligned payload buffer, recycled to the memory pool when the last handle drops.
    pub data: Option<SharedFecBuffer>,
    /// Actual byte count of valid payload within `data`.
    pub data_len: usize,
    /// True for original source packets, false for repair/coded packets.
    pub is_systematic: bool,
    /// GF coefficient vector for repair packets (None for source packets).
    pub coefficients: Option<AlignedBox<[u8]>>,
    /// Number of valid bytes in the coefficients buffer.
    pub coeff_len: usize,
    /// Shared memory pool for buffer allocation and recycling.
    pub mem_pool: Arc<MemoryPool>,
    /// Transport-level sequence number for ordering and gap detection.
    pub seq: u64,
    /// Creation timestamp for latency tracking.
    pub timestamp: std::time::Instant,
}

impl Drop for FecPacket {
    fn drop(&mut self) {
        // Payload buffers recycle when the last SharedFecBuffer handle drops.
        if let Some(coeffs) = self.coefficients.take() {
            self.mem_pool.free(coeffs);
        }
    }
}

impl FecPacket {
    /// Crate-internal compatibility constructor from raw aligned buffers.
    ///
    /// Production paths should use [`Self::from_pooled_blocks`]; checked public input validation is
    /// available through [`Self::try_new`]. This constructor bounds declared lengths to their
    /// backing buffers, normalizes systematic packets by discarding any coefficient metadata, and
    /// panics if the bounded `data_len` or `coeff_len` exceeds the memory-pool block size. It is
    /// This compatibility constructor is hidden from the public documentation because callers
    /// that accept untrusted input must use the checked constructors.
    #[doc(hidden)]
    pub fn new(
        id: u64,
        data: Option<AlignedBox<[u8]>>,
        data_len: usize,
        is_systematic: bool,
        coefficients: Option<AlignedBox<[u8]>>,
        coeff_len: usize,
        mem_pool: Arc<MemoryPool>,
    ) -> Self {
        let (data, data_len) = match data {
            Some(data) => {
                let bounded_len = data_len.min(data.len());
                (Some(data), bounded_len)
            }
            None => (None, 0),
        };
        let (coefficients, coeff_len) = if is_systematic {
            if let Some(coefficients) = coefficients {
                mem_pool.free(coefficients);
            }
            (None, 0)
        } else {
            match coefficients {
                Some(coefficients) => {
                    let bounded_len = coeff_len.min(coefficients.len());
                    (Some(coefficients), bounded_len)
                }
                None => (None, 0),
            }
        };

        assert!(
            data_len <= mem_pool.block_size(),
            "FecPacket::new: data_len ({data_len}) exceeds memory-pool block size ({block_size}); use try_new for checked construction",
            block_size = mem_pool.block_size()
        );
        assert!(
            coeff_len <= mem_pool.block_size(),
            "FecPacket::new: coeff_len ({coeff_len}) exceeds memory-pool block size ({block_size}); use try_new for checked construction",
            block_size = mem_pool.block_size()
        );

        let data = data.map(|buf| SharedFecBuffer::new(buf, Arc::clone(&mem_pool)));

        Self {
            id,
            data,
            data_len,
            is_systematic,
            coefficients,
            coeff_len,
            mem_pool,
            seq: id, // Default: seq = id
            timestamp: std::time::Instant::now(),
        }
    }

    /// Unchecked constructor for test fixtures that need to deliberately create invalid
    /// oversized packets (e.g. to verify that encoders reject them or that `Clone` bounds
    /// coefficient length). It does not bound `data_len`/`coeff_len`, nor does it enforce the
    /// systematic/repair coefficient contract.
    #[cfg(any(test, feature = "rust-tests"))]
    #[doc(hidden)]
    pub fn new_unchecked(
        id: u64,
        data: Option<AlignedBox<[u8]>>,
        data_len: usize,
        is_systematic: bool,
        coefficients: Option<AlignedBox<[u8]>>,
        coeff_len: usize,
        mem_pool: Arc<MemoryPool>,
    ) -> Self {
        let data = data.map(|buf| SharedFecBuffer::new(buf, Arc::clone(&mem_pool)));
        Self {
            id,
            data,
            data_len,
            is_systematic,
            coefficients,
            coeff_len,
            mem_pool,
            seq: id,
            timestamp: std::time::Instant::now(),
        }
    }

    /// Construct a compatibility packet while rejecting inconsistent metadata.
    pub fn try_new(
        id: u64,
        data: Option<AlignedBox<[u8]>>,
        data_len: usize,
        is_systematic: bool,
        coefficients: Option<AlignedBox<[u8]>>,
        coeff_len: usize,
        mem_pool: Arc<MemoryPool>,
    ) -> Result<Self, String> {
        if data_len > mem_pool.block_size() {
            return Err("data length exceeds memory-pool block size".into());
        }
        if coeff_len > mem_pool.block_size() {
            return Err("coefficient length exceeds memory-pool block size".into());
        }
        if data_len > data.as_ref().map_or(0, |buffer| buffer.len()) {
            return Err("data length exceeds backing buffer".into());
        }
        if coeff_len > coefficients.as_ref().map_or(0, |buffer| buffer.len()) {
            return Err("coefficient length exceeds backing buffer".into());
        }
        if is_systematic && (coeff_len != 0 || coefficients.is_some()) {
            return Err("systematic packet cannot carry coefficients".into());
        }
        Ok(Self::new(id, data, data_len, is_systematic, coefficients, coeff_len, mem_pool))
    }

    /// Construct a packet by transferring live pool guards after all lengths are validated.
    ///
    /// The guards must originate from `mem_pool`. Any rejected guard remains owned by its
    /// original pool and is returned automatically, so data and coefficients cannot leak when
    /// packet construction is rejected.
    #[doc(hidden)]
    pub fn from_pooled_blocks(
        id: u64,
        data: Option<PooledBlock>,
        data_len: usize,
        is_systematic: bool,
        coefficients: Option<PooledBlock>,
        coeff_len: usize,
        mem_pool: Arc<MemoryPool>,
    ) -> Result<Self, String> {
        if let Some(block) = data.as_ref() {
            if !Arc::ptr_eq(&block.pool(), &mem_pool) {
                return Err("FEC data block belongs to a different memory pool".into());
            }
            if !block.is_live() || data_len > block.len() {
                return Err("FEC data block cannot contain its declared length".into());
            }
        } else if data_len != 0 {
            return Err("FEC data length is nonzero without a data block".into());
        }
        if let Some(block) = coefficients.as_ref() {
            if !Arc::ptr_eq(&block.pool(), &mem_pool) {
                return Err("FEC coefficient block belongs to a different memory pool".into());
            }
            if !block.is_live() || coeff_len > block.len() {
                return Err("FEC coefficient block cannot contain its declared length".into());
            }
        } else if coeff_len != 0 {
            return Err("FEC coefficient length is nonzero without a coefficient block".into());
        }
        if is_systematic && (coeff_len != 0 || coefficients.is_some()) {
            return Err("systematic packet cannot carry coefficients".into());
        }

        let mut data_raw = match data {
            Some(mut block) => match block.take_block() {
                Some(raw) => Some(raw),
                None => return Err("FEC data guard was already transferred".into()),
            },
            None => None,
        };
        let coefficients_raw = match coefficients {
            Some(mut block) => match block.take_block() {
                Some(raw) => Some(raw),
                None => {
                    if let Some(raw) = data_raw.take() {
                        mem_pool.free(raw);
                    }
                    return Err("FEC coefficient guard was already transferred".into());
                }
            },
            None => None,
        };

        Ok(Self::new(id, data_raw, data_len, is_systematic, coefficients_raw, coeff_len, mem_pool))
    }

    /// Payload bytes for this packet (up to `data_len`).
    #[inline]
    pub fn payload_slice(&self) -> Option<&[u8]> {
        self.data.as_ref().map(|shared| shared.bytes(self.data_len))
    }

    /// Mutable payload view when this packet is the sole owner of the shared buffer.
    #[inline]
    #[doc(hidden)]
    pub fn payload_mut_unique(&mut self) -> Option<&mut [u8]> {
        let shared = self.data.as_mut()?;
        let inner = Arc::get_mut(&mut shared.inner)?;
        let buf = inner.buf.as_mut()?;
        let end = self.data_len.min(buf.len());
        Some(&mut buf[..end])
    }

    /// Create a systematic FEC packet from a raw byte block, copying into a pool buffer.
    ///
    /// This is a convenience wrapper around [`Self::try_from_block`] for callers that already
    /// know the input fits a pool block. If the block is oversized, construction fails.
    pub fn from_block(id: u64, block: &[u8], mem_pool: Arc<MemoryPool>) -> Result<Self, String> {
        Self::try_from_block(id, block, Arc::clone(&mem_pool))
            .map_err(|error| format!("from_block failed: {error}"))
    }

    /// Create a systematic packet or reject a symbol that cannot fit one pool block.
    pub fn try_from_block(
        id: u64,
        block: &[u8],
        mem_pool: Arc<MemoryPool>,
    ) -> Result<Self, String> {
        if block.len() > mem_pool.block_size() {
            return Err("data block exceeds memory-pool block size".into());
        }
        let mut dst = PooledBlock::new(Arc::clone(&mem_pool));
        let n = block.len();
        dst[..n].copy_from_slice(block);
        Self::from_pooled_blocks(id, Some(dst), n, true, None, 0, mem_pool)
            .map_err(|error| format!("data block rejected: {error}"))
    }

    /// Copy only the payload into `buf` (no headers). This is NOT the
    /// Legacy streaming format retained for compatibility tests. Production
    /// transport framing uses [`wire::write_packet`].
    pub fn to_raw(&self, buf: &mut [u8]) -> Result<usize, String> {
        let Some(data) = self.payload_slice() else {
            return Err("No data available".to_string());
        };
        // Fail closed on an undersized buffer. Clamping to `buf.len()` copied a prefix and
        // reported success, so the caller emitted a truncated FEC packet as if it were whole.
        if buf.len() < data.len() {
            return Err(format!(
                "raw FEC payload needs {} bytes but the output buffer holds {}",
                data.len(),
                buf.len()
            ));
        }
        buf[..data.len()].copy_from_slice(data);
        Ok(data.len())
    }

    /// Serialize a streaming-friendly raw format for transport DATAGRAM:
    /// [magic:2=0xF1EC][is_systematic:1][base_id:8][seq:8][coeff_len:2][coeffs (coeff_len bytes)][payload]
    pub fn to_stream_raw(&self, buf: &mut [u8]) -> Result<usize, String> {
        if self.is_systematic {
            if self.coeff_len != 0 || self.coefficients.is_some() {
                return Err("CoefficientMetadataInvalid".into());
            }
        } else if self.coeff_len == 0 || self.coefficients.is_none() {
            return Err("CoefficientMetadataInvalid".into());
        }
        let mut off = 0usize;
        if buf.len() < 2 + 1 + 8 + 8 + 2 {
            return Err("BufferTooShort".into());
        }
        // Magic for safe demultiplexing of FEC datagrams
        buf[0] = 0xF1;
        buf[1] = 0xEC;
        off += 2;
        buf[off] = if self.is_systematic { 1 } else { 0 };
        off += 1;
        // base_id conveys the equation window anchor (id of the last source in window at sender)
        buf[off..off + 8].copy_from_slice(&self.id.to_be_bytes());
        off += 8;
        // seq conveys the transport sequence (used by InterleavedDecoder for block routing)
        buf[off..off + 8].copy_from_slice(&self.seq.to_be_bytes());
        off += 8;
        let coeff_len = u16::try_from(self.coeff_len).map_err(|_| "CoeffLengthOverflow")?;
        if buf.len() < off + 2 {
            return Err("BufferTooShort".into());
        }
        buf[off..off + 2].copy_from_slice(&coeff_len.to_be_bytes());
        off += 2;
        if let Some(ref coeffs) = self.coefficients {
            if buf.len() < off + self.coeff_len {
                return Err("BufferTooShort".into());
            }
            let coeffs = coeffs
                .get(..self.coeff_len)
                .ok_or_else(|| "CoefficientLengthInvalid".to_string())?;
            buf[off..off + self.coeff_len].copy_from_slice(coeffs);
            off += self.coeff_len;
        } else if self.coeff_len > 0 {
            return Err("coeff_len>0 but no coefficients present".into());
        }
        if let Some(data) = self.payload_slice() {
            let n = data.len().min(buf.len().saturating_sub(off));
            if n < self.data_len {
                return Err("BufferTooShort".into());
            }
            buf[off..off + n].copy_from_slice(&data[..n]);
            off += n;
            Ok(off)
        } else {
            Err("No data available".into())
        }
    }

    /// Parse streaming-friendly raw format from transport DATAGRAM.
    /// Returns a FecPacket owning aligned buffers allocated from the pool.
    pub fn from_stream_raw(input: &[u8], pool: Arc<MemoryPool>) -> Result<Self, String> {
        if input.len() < 2 + 1 + 8 + 8 + 2 {
            return Err("BufferTooShort".into());
        }
        if input[0] != 0xF1 || input[1] != 0xEC {
            return Err("BadMagic".into());
        }
        let mut off = 2usize;
        let flags = input[off];
        if flags & !1 != 0 {
            return Err("UnsupportedFlags".into());
        }
        let is_systematic = flags & 1 != 0;
        off += 1;
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&input[off..off + 8]);
        let base_id = u64::from_be_bytes(id_bytes);
        off += 8;
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&input[off..off + 8]);
        let seq = u64::from_be_bytes(seq_bytes);
        off += 8;
        let mut cl_bytes = [0u8; 2];
        cl_bytes.copy_from_slice(&input[off..off + 2]);
        off += 2;
        let coeff_len = u16::from_be_bytes(cl_bytes) as usize;
        if (is_systematic && coeff_len != 0) || (!is_systematic && coeff_len == 0) {
            return Err("CoefficientMetadataInvalid".into());
        }
        if input.len() < off + coeff_len {
            return Err("BufferTooShort".into());
        }
        let coeffs = if coeff_len > 0 {
            if coeff_len > pool.block_size() {
                return Err("CoeffBufferTooSmall".into());
            }
            let mut cbuf = PooledBlock::new(Arc::clone(&pool));
            cbuf[..coeff_len].copy_from_slice(&input[off..off + coeff_len]);
            off += coeff_len;
            Some(cbuf)
        } else {
            None
        };
        let payload_len = input.len().saturating_sub(off);
        if payload_len > pool.block_size() {
            return Err("DataBufferTooSmall".into());
        }
        let mut dbuf = PooledBlock::new(Arc::clone(&pool));
        dbuf[..payload_len].copy_from_slice(&input[off..]);
        let mut pkt = Self::from_pooled_blocks(
            base_id,
            Some(dbuf),
            payload_len,
            is_systematic,
            coeffs,
            coeff_len,
            pool,
        )?;
        pkt.seq = seq;
        Ok(pkt)
    }

    /// Returns the payload length in bytes.
    pub fn len(&self) -> usize {
        self.data_len
    }
    /// Returns true if the packet carries no payload data.
    pub fn is_empty(&self) -> bool {
        self.data_len == 0
    }
}

impl Clone for FecPacket {
    fn clone(&self) -> Self {
        let data_len =
            self.data.as_ref().map(|shared| shared.bytes(self.data_len).len()).unwrap_or(0);
        let data_clone = self.data.clone();

        let (coeffs_clone, coeff_len) = if let Some(ref coeffs) = self.coefficients {
            let mut buf = self.mem_pool.alloc();
            let copy_len = self.coeff_len.min(buf.len()).min(coeffs.len());
            buf[..copy_len].copy_from_slice(&coeffs[..copy_len]);
            (Some(buf), copy_len)
        } else {
            (None, 0)
        };

        Self {
            id: self.id,
            data: data_clone,
            data_len,
            is_systematic: self.is_systematic,
            coefficients: coeffs_clone,
            coeff_len,
            mem_pool: Arc::clone(&self.mem_pool),
            seq: self.seq,
            timestamp: self.timestamp,
        }
    }
}

/// Forward error correction operating mode controlling redundancy level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, clap::ValueEnum)]
#[repr(u8)]
pub enum FecMode {
    /// No FEC - zero overhead passthrough for loss-free links.
    Zero,
    /// Minimal redundancy for excellent conditions (<2% loss).
    Light,
    /// Standard block-code protection for moderate loss (2-10%).
    Normal,
    /// Increased redundancy for fair conditions.
    Medium,
    /// High redundancy for poor conditions (10-25% loss).
    Strong,
    /// Very high redundancy for severe loss (25-50%).
    Extreme,
    /// Maximum redundancy for extreme conditions.
    Ultra,
    /// Rateless LT fountain codes for >50% loss.
    Fountain,
    /// Continuous streaming repair emission for low-latency recovery.
    Streaming,
}

impl FecMode {
    /// Stable public codec-mode order used by telemetry and runtime evidence.
    pub const ALL: [Self; 9] = [
        Self::Zero,
        Self::Light,
        Self::Normal,
        Self::Medium,
        Self::Strong,
        Self::Extreme,
        Self::Ultra,
        Self::Fountain,
        Self::Streaming,
    ];

    /// Stable public numeric telemetry ID.
    pub const fn telemetry_id(self) -> u8 {
        self as u8
    }

    /// Stable public telemetry label.
    pub const fn telemetry_name(self) -> &'static str {
        match self {
            Self::Zero => "zero",
            Self::Light => "light",
            Self::Normal => "normal",
            Self::Medium => "medium",
            Self::Strong => "strong",
            Self::Extreme => "extreme",
            Self::Ultra => "ultra",
            Self::Fountain => "fountain",
            Self::Streaming => "streaming",
        }
    }
}

/// Operator-owned FEC control policy, independent from the active codec mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FecControlPolicy {
    /// Keep the connection in raw Zero mode for its full lifetime.
    Off,
    /// Allow the adaptive controller to select the cheapest sufficient codec.
    #[default]
    Auto,
}

// Galois field marker types
/// GF(2^4) - For low loss (<5%), 4x less computation than GF(2^8)
#[doc(hidden)]
pub struct GF4;
/// GF(2^8) - Standard field for moderate loss
#[doc(hidden)]
pub struct GF8;
/// GF(2^16) - For high loss scenarios, larger symbol space
#[doc(hidden)]
pub struct GF16;

// Core FEC encoder/decoder types
#[doc(hidden)]
pub struct Encoder<F> {
    k: usize,
    window: VecDeque<FecPacket>,
    _field: std::marker::PhantomData<F>,
}

impl<F> Encoder<F> {
    /// Create a new encoder with source block size `k` and sliding window capacity.
    pub fn new(k: usize, _n: usize) -> Self {
        Self { k, window: VecDeque::with_capacity(k), _field: std::marker::PhantomData }
    }

    #[doc(hidden)]
    pub fn take_packet(&mut self, p: FecPacket) {
        if self.window.len() < self.k {
            self.window.push_back(p);
        } else {
            // Sliding window: drop oldest, push newest (used by Streaming mode)
            let _ = self.window.pop_front();
            self.window.push_back(p);
        }
    }

    #[doc(hidden)]
    pub fn clear_window(&mut self) {
        self.window.clear();
    }

    #[doc(hidden)]
    pub fn packets_in_window(&self) -> usize {
        self.window.len()
    }
}

#[doc(hidden)]
pub struct Encoder16 {
    inner: Encoder<GF16>,
    coeff_rows: Vec<u8>,
    coeff_stride: usize,
}

/// Public wrapper for GF(2^8) encoder used by transport integration.
#[cfg(any(test, feature = "rust-tests"))]
pub struct Encoder8(Encoder<GF8>);

#[cfg(any(test, feature = "rust-tests"))]
impl Encoder8 {
    /// Create a new GF(2^8) encoder with source block size `k` and total codeword size `n`.
    pub fn new(k: usize, n: usize) -> Self {
        Self(Encoder::<GF8>::new(k, n))
    }
    /// Feed a source packet into the encoding window.
    pub fn take_packet(&mut self, p: FecPacket) {
        self.0.take_packet(p)
    }
    /// Generate the `idx`-th repair packet from the current encoding window.
    pub fn generate_repair_packet(
        &mut self,
        idx: usize,
        pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        Encoder::<GF8>::generate_repair_packet(&mut self.0, idx, pool)
    }
}

impl Encoder<GF8> {
    #[doc(hidden)]
    pub fn generate_repair_packet(
        &mut self,
        idx: usize,
        pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        if self.window.is_empty() || self.k == 0 {
            return None;
        }
        // Determine max payload length among window packets
        let max_len = self.window.iter().map(|p| p.data_len).max().unwrap_or(0);
        if max_len == 0 {
            return None;
        }
        if max_len > pool.block_size() {
            return None;
        }
        let block_source_count = u16::try_from(self.k).ok()?;
        let repair_index = u16::try_from(idx).ok()?;
        if self.k > pool.block_size() {
            return None;
        }
        let mut out = PooledBlock::new(Arc::clone(pool));
        // Zero initialize target region
        for b in &mut out[..max_len] {
            *b = 0;
        }

        // Coefficients (GF(2^8)), length = k
        let mut coeff_box = PooledBlock::new(Arc::clone(pool));
        wire::WireCodec::Gf8
            .write_repair_coefficients(block_source_count, repair_index, &mut coeff_box)
            .ok()?;
        let wlen = self.window.len().min(self.k);

        // Apply coefficients to data using optimized matrix helper
        // row is 1xK (one repair packet depends on K source packets)
        // We can just iterate and accumulate.
        // matrix_multiply_scalar expects matrix arguments, but here we generate one row.

        // Manual row accumulation
        for (j, pkt) in self.window.iter().enumerate().take(wlen) {
            if let Some(data) = pkt.payload_slice() {
                let len = data.len().min(max_len);
                let c = coeff_box[j];
                // Accumulate: out[i] ^= c * data[i]
                gf_tables::gf_mul_scalar_slice(c, &data[..len], &mut out[..len]);
            }
        }

        // Repair ID must be the window anchor (max source ID in window) for decoder coefficient mapping
        let window_anchor_id = self.window.iter().map(|p| p.id).max().unwrap_or(0);

        FecPacket::from_pooled_blocks(
            window_anchor_id,
            Some(out),
            max_len,
            false,
            Some(coeff_box),
            self.k,
            Arc::clone(pool),
        )
        .ok()
    }
}

/// Internal GF(2^4) encoder for low-loss adaptive runtime paths.
#[doc(hidden)]
pub struct Encoder4(Encoder<GF4>);

impl Encoder4 {
    pub fn new(k: usize, n: usize) -> Self {
        Self(Encoder::<GF4>::new(k, n))
    }
    pub fn take_packet(&mut self, p: FecPacket) {
        self.0.take_packet(p)
    }
    pub fn clear_window(&mut self) {
        self.0.clear_window()
    }
    pub fn packets_in_window(&self) -> usize {
        self.0.packets_in_window()
    }
    pub fn generate_repair_packet(
        &mut self,
        idx: usize,
        pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        Encoder::<GF4>::generate_repair_packet(&mut self.0, idx, pool)
    }
}

impl Encoder<GF4> {
    #[doc(hidden)]
    pub fn generate_repair_packet(
        &mut self,
        idx: usize,
        pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        if self.window.is_empty() || self.k == 0 {
            return None;
        }
        let max_len = self.window.iter().map(|p| p.data_len).max().unwrap_or(0);
        if max_len == 0 {
            return None;
        }
        if max_len > pool.block_size() {
            return None;
        }
        let block_source_count = u16::try_from(self.k).ok()?;
        let repair_index = u16::try_from(idx).ok()?;
        if self.k > pool.block_size() {
            return None;
        }
        let mut out = PooledBlock::new(Arc::clone(pool));
        // Zero initialize target region
        out[..max_len].fill(0);

        // Coefficients (GF(2^4))
        // We store them as u8 (1..15)
        let mut coeff_box = PooledBlock::new(Arc::clone(pool));
        wire::WireCodec::Gf4
            .write_repair_coefficients(block_source_count, repair_index, &mut coeff_box)
            .ok()?;
        let wlen = self.window.len().min(self.k);

        for (j, pkt) in self.window.iter().enumerate().take(wlen) {
            if let Some(data) = pkt.payload_slice() {
                let len = data.len().min(max_len);
                let c = coeff_box[j];
                qf_simd::galois::gf4_mul_xor(&data[..len], c, &mut out[..len]);
            }
        }

        // Repair ID must be the window anchor (max source ID in window) for decoder coefficient mapping
        let window_anchor_id = self.window.iter().map(|p| p.id).max().unwrap_or(0);

        FecPacket::from_pooled_blocks(
            window_anchor_id,
            Some(out),
            max_len,
            false,
            Some(coeff_box),
            self.k,
            Arc::clone(pool),
        )
        .ok()
    }
}

impl Encoder16 {
    #[doc(hidden)]
    pub fn new(k: usize, n: usize) -> Self {
        let mut encoder =
            Self { inner: Encoder::<GF16>::new(k, n), coeff_rows: Vec::new(), coeff_stride: 0 };
        encoder.prepare_coeff_rows(n.saturating_sub(k));
        encoder
    }

    #[inline]
    #[doc(hidden)]
    pub fn take_packet(&mut self, p: FecPacket) {
        self.inner.take_packet(p);
    }

    #[inline]
    #[doc(hidden)]
    pub fn clear_window(&mut self) {
        self.inner.clear_window();
    }

    #[inline]
    #[doc(hidden)]
    pub fn packets_in_window(&self) -> usize {
        self.inner.packets_in_window()
    }

    fn prepare_coeff_rows(&mut self, repair_rows: usize) {
        let Some(stride) = self.inner.k.checked_mul(2) else {
            self.coeff_stride = 0;
            self.coeff_rows.clear();
            return;
        };
        if stride == 0 || repair_rows == 0 || repair_rows > u16::MAX as usize {
            self.coeff_stride = 0;
            self.coeff_rows.clear();
            return;
        }
        let Ok(block_source_count) = u16::try_from(self.inner.k) else {
            self.coeff_stride = 0;
            self.coeff_rows.clear();
            return;
        };
        self.coeff_stride = stride;
        let Some(total_len) = repair_rows.checked_mul(stride) else {
            self.coeff_stride = 0;
            self.coeff_rows.clear();
            return;
        };
        self.coeff_rows.resize(total_len, 0);
        for idx in 0..repair_rows {
            let Some(start) = idx.checked_mul(stride) else {
                self.coeff_rows.clear();
                return;
            };
            let Some(end) = start.checked_add(stride) else {
                self.coeff_rows.clear();
                return;
            };
            let row = &mut self.coeff_rows[start..end];
            let result = wire::WireCodec::Gf16.write_repair_coefficients(
                block_source_count,
                idx as u16,
                row,
            );
            debug_assert_eq!(result, Ok(stride));
        }
    }

    fn ensure_coeff_row(&mut self, idx: usize) -> bool {
        if idx > u16::MAX as usize {
            return false;
        }
        let Some(expected_stride) = self.inner.k.checked_mul(2) else {
            return false;
        };
        if expected_stride == 0 {
            return false;
        }
        if self.coeff_stride != expected_stride {
            let Some(row_count) = idx.checked_add(1) else {
                return false;
            };
            self.prepare_coeff_rows(row_count);
            let Some(required_len) = row_count.checked_mul(self.coeff_stride) else {
                return false;
            };
            return self.coeff_rows.len() >= required_len;
        }
        let rows = self.coeff_rows.len().checked_div(self.coeff_stride).unwrap_or(0);
        if rows <= idx {
            let old_len = self.coeff_rows.len();
            let Some(required_len) =
                idx.checked_add(1).and_then(|row_count| row_count.checked_mul(self.coeff_stride))
            else {
                return false;
            };
            self.coeff_rows.resize(required_len, 0);
            let Ok(block_source_count) = u16::try_from(self.inner.k) else {
                self.coeff_rows.clear();
                return false;
            };
            for row_idx in rows..=idx {
                let Ok(repair_index) = u16::try_from(row_idx) else {
                    self.coeff_rows.clear();
                    return false;
                };
                let Some(start) = row_idx.checked_mul(self.coeff_stride) else {
                    self.coeff_rows.clear();
                    return false;
                };
                let Some(end) = start.checked_add(self.coeff_stride) else {
                    self.coeff_rows.clear();
                    return false;
                };
                let row = &mut self.coeff_rows[start..end];
                let result = wire::WireCodec::Gf16.write_repair_coefficients(
                    block_source_count,
                    repair_index,
                    row,
                );
                debug_assert_eq!(result, Ok(self.coeff_stride));
            }
            debug_assert_eq!(old_len % self.coeff_stride, 0);
        }
        true
    }

    #[doc(hidden)]
    pub fn generate_repair_packet(
        &mut self,
        idx: usize,
        pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        if self.inner.window.len() < self.inner.k || self.inner.k == 0 {
            return None;
        }
        let max_len = self.inner.window.iter().map(|p| p.data_len).max().unwrap_or(0);
        if max_len == 0 {
            return None;
        }
        // Pad the final GF16 word instead of truncating an odd source byte.
        // The protected source-length prefix removes this zero padding after recovery.
        let max_len_even = max_len.checked_add(max_len % 2)?;
        if max_len_even == 0 {
            return None;
        }
        let coeff_bytes = self.inner.k.checked_mul(2)?;
        if max_len_even > pool.block_size() || coeff_bytes > pool.block_size() {
            return None;
        }
        if !self.ensure_coeff_row(idx) {
            return None;
        }
        let row_start = idx.checked_mul(self.coeff_stride)?;
        let row_end = row_start.checked_add(coeff_bytes)?;
        let mut out = PooledBlock::new(Arc::clone(pool));
        for b in &mut out[..max_len_even] {
            *b = 0;
        }

        // Coefficients (GF(2^16)) stored as big-endian bytes, length = 2*k
        let mut coeff_box = PooledBlock::new(Arc::clone(pool));
        coeff_box[..coeff_bytes].copy_from_slice(&self.coeff_rows[row_start..row_end]);

        // Accumulate
        let wlen = self.inner.window.len().min(self.inner.k);
        if max_len_even >= (PAR_THRESHOLD * 4) && wlen >= 8 {
            let chunk = 16384usize; // bytes, will align down to even length
            let parts: Vec<(usize, Vec<u8>)> = (0..max_len_even.div_ceil(chunk))
                .into_par_iter()
                .map(|ci| {
                    let mut start = ci * chunk;
                    let mut end = (start + chunk).min(max_len_even);
                    // enforce even boundaries
                    if !start.is_multiple_of(2) {
                        start += 1;
                    }
                    if !end.is_multiple_of(2) {
                        end -= 1;
                    }
                    if end <= start {
                        return (start, Vec::new());
                    }
                    let mut acc = vec![0u8; end - start];
                    for (j, pkt) in self.inner.window.iter().enumerate().take(wlen) {
                        if let Some(data) = pkt.payload_slice() {
                            let s_len = data.len().min(max_len_even);
                            if start < s_len {
                                let len = (s_len - start).min(acc.len());
                                if len >= 2 {
                                    let c = u16::from_be_bytes([
                                        coeff_box[2 * j],
                                        coeff_box[2 * j + 1],
                                    ]);
                                    gf16_mul_scalar_slice_padded(
                                        c,
                                        &data[start..start + len],
                                        &mut acc[..],
                                    );
                                }
                            }
                        }
                    }
                    (start, acc)
                })
                .collect();
            for (start, acc) in parts.into_iter() {
                let len = acc.len();
                if len > 0 {
                    // Vectorized XOR combine
                    qf_simd::core::xor_blocks(&mut out[start..start + len], &acc[..]);
                    qf_telemetry::FEC_SIMD_ENCODE.inc();
                }
            }
        } else {
            for (j, pkt) in self.inner.window.iter().enumerate().take(self.inner.k) {
                if let Some(data) = pkt.payload_slice() {
                    let s_len = data.len().min(max_len_even);
                    if s_len < 2 {
                        continue;
                    }
                    let c = u16::from_be_bytes([coeff_box[2 * j], coeff_box[2 * j + 1]]);
                    gf16_mul_scalar_slice_padded(c, &data[..s_len], &mut out[..max_len_even]);
                }
            }
        }

        let id = self.inner.window.back().map(|p| p.id).unwrap_or(0);
        FecPacket::from_pooled_blocks(
            id,
            Some(out),
            max_len_even,
            false,
            Some(coeff_box),
            coeff_bytes,
            Arc::clone(pool),
        )
        .ok()
    }
}
