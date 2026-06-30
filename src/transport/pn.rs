use crate::transport::ConnectionId;
/// QUIC packet number space tracking and ACK generation.
pub mod pnspace {
    use super::ranges::RangeSet;
    use std::time::{Duration, Instant};

    /// Per-epoch packet number space tracking ACK state and receive history.
    #[derive(Default, Clone)]
    pub struct PktNumSpace {
        /// Largest packet number received in this space.
        pub largest_recv: Option<u64>,
        /// Set of received packet number ranges for ACK generation.
        pub ack_ranges: RangeSet,
        /// Whether an ACK frame should be emitted.
        pub ack_elicited: bool,
        /// Timestamp of the last ACK emission.
        pub last_ack_time: Option<Instant>,
        /// Timestamp of the last packet received.
        pub last_recv_time: Option<Instant>,
        /// Count of packets received since the last ACK was sent.
        pub recvd_since_ack: u64,
    }

    impl PktNumSpace {
        /// Creates a new empty packet number space.
        #[inline(always)]
        pub fn new() -> Self {
            Self {
                largest_recv: None,
                ack_ranges: RangeSet::default(),
                ack_elicited: false,
                last_ack_time: None,
                last_recv_time: None,
                recvd_since_ack: 0,
            }
        }

        /// Maximum packet number per RFC 9000 Section 17.1 (2^62 - 1)
        const MAX_PACKET_NUMBER: u64 = (1u64 << 62) - 1;

        /// Track a newly received packet number and decide if ACK should be elicited.
        /// Returns false if the packet should be rejected (duplicate or overflow).
        #[inline(always)]
        pub fn on_packet_recv(
            &mut self,
            pn: u64,
            max_ack_delay_ms: u64,
            ack_threshold: u64,
        ) -> bool {
            // RFC 9000 Section 17.1: packet numbers are limited to 2^62 - 1
            if pn > Self::MAX_PACKET_NUMBER {
                return false;
            }

            // Duplicate detection: check if PN already exists in our ack ranges
            if self.contains(pn) {
                return false;
            }

            // Insert PN into ACK ranges (coalescing ranges internally)
            self.ack_ranges.insert(pn..pn + 1);

            // Track largest received PN
            self.largest_recv = Some(self.largest_recv.map(|l| l.max(pn)).unwrap_or(pn));

            let now = Instant::now();
            self.last_recv_time = Some(now);
            self.recvd_since_ack = self.recvd_since_ack.saturating_add(1);

            // Overdue if exceeded max_ack_delay since last ACK emission
            let overdue = self
                .last_ack_time
                .map(|t| {
                    now.saturating_duration_since(t) >= Duration::from_millis(max_ack_delay_ms)
                })
                .unwrap_or(true);

            if self.recvd_since_ack >= ack_threshold.max(1) || overdue {
                self.ack_elicited = true;
            }
            true
        }

        /// Returns a flattened Vec of ACK ranges for encoding
        #[inline(always)]
        pub fn ack_ranges_vec(&self) -> Vec<(u64, u64)> {
            self.ack_ranges.iter().map(|r| (r.start, r.end)).collect()
        }

        /// Returns true if an ACK frame is pending emission (without consuming it).
        /// Used to bypass the congestion gate for ACK-only packets, which are
        /// critical for protocol liveness and must not be blocked by congestion
        /// control (RFC 9002 §7.2: ACK-only packets are not congestion-controlled).
        #[inline(always)]
        pub fn has_pending_ack(&self) -> bool {
            self.ack_elicited
        }

        /// Takes an ACK decision and returns (ack_delay, ranges)
        #[inline(always)]
        pub fn take_ack(&mut self, ack_delay_exponent: u64) -> Option<(u64, Vec<(u64, u64)>)> {
            if !self.ack_elicited {
                return None;
            }
            self.ack_elicited = false;
            self.recvd_since_ack = 0;

            let now = Instant::now();
            let delay = if let Some(last) = self.last_recv_time {
                now.saturating_duration_since(last)
            } else {
                Duration::from_micros(0)
            };
            self.last_ack_time = Some(now);

            // QUIC ACK delay encoding uses 2^ack_delay_exponent microseconds units
            let micros = delay.as_micros() as u64;
            let ack_delay = micros >> ack_delay_exponent.min(20);

            Some((ack_delay, self.ack_ranges.iter().map(|r| (r.start, r.end)).collect()))
        }

        /// True if PN is currently within our ack ranges
        #[inline(always)]
        pub fn contains(&self, pn: u64) -> bool {
            for r in self.ack_ranges.iter() {
                if pn >= r.start && pn < r.end {
                    return true;
                }
            }
            false
        }

        /// Force ACK-elicitation (e.g., on receiving ack-eliciting frames)
        #[inline(always)]
        pub fn note_ack_eliciting(&mut self) {
            self.ack_elicited = true;
        }
    }
}

/// Connection ID set for tracking active CIDs.
pub mod cid {
    use super::ConnectionId;
    use std::collections::HashSet;

    /// Set of active QUIC connection IDs backed by a HashSet.
    #[derive(Debug, Clone)]
    pub struct ConnectionIdSet {
        inner: HashSet<Vec<u8>>,
    }

    impl ConnectionIdSet {
        /// Creates a new empty connection ID set.
        pub fn new() -> Self {
            Self { inner: HashSet::new() }
        }

        /// Inserts a connection ID into the set.
        pub fn insert(&mut self, id: &ConnectionId) {
            self.inner.insert(id.as_ref().to_vec());
        }

        /// Returns true if the set contains the given connection ID.
        pub fn contains(&self, id: &ConnectionId) -> bool {
            self.inner.contains(id.as_ref())
        }
    }

    impl Default for ConnectionIdSet {
        fn default() -> Self {
            Self::new()
        }
    }
}

/// Random number generation for transport operations.
///
/// The `rand_*` APIs are cryptographically secure and remain mandatory for
/// security-sensitive transport values. The `fast_rand_*` APIs are explicitly
/// non-cryptographic and only valid for hot-path heuristics such as padding and
/// jitter decisions.
pub mod rand {
    use std::cell::Cell;

    thread_local! {
        static FAST_RNG_STATE: Cell<u64> = Cell::new(seed_fast_rng());
    }

    /// Generate random bytes
    pub fn rand_bytes(buf: &mut [u8]) {
        crate::rng::fill_secure_or_abort(buf, "transport::rand::rand_bytes");
    }

    /// Generate random u8
    pub fn rand_u8() -> u8 {
        let mut buf = [0; 1];
        rand_bytes(&mut buf);
        buf[0]
    }

    /// Generate random u64
    pub fn rand_u64() -> u64 {
        let mut buf = [0; 8];
        rand_bytes(&mut buf);
        u64::from_ne_bytes(buf)
    }

    /// Generate random u64 uniformly distributed in [0, max)
    pub fn rand_u64_uniform(max: u64) -> u64 {
        if max == 0 {
            return 0;
        }
        let chunk_size = u64::MAX / max;
        let end_of_last_chunk = chunk_size * max;

        let mut r = rand_u64();
        while r >= end_of_last_chunk {
            r = rand_u64();
        }
        r / chunk_size
    }

    #[inline(always)]
    fn seed_fast_rng() -> u64 {
        let seed = rand_u64();
        if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        }
    }

    #[inline(always)]
    fn splitmix64_step(state: u64) -> u64 {
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Generate fast non-cryptographic random `u64`.
    ///
    /// Use only for per-packet heuristics such as timing jitter, cover traffic,
    /// and padding decisions. Security-sensitive transport values such as
    /// connection IDs, path challenges, keys, and nonces must keep using
    /// `rand_bytes`, `rand_u8`, `rand_u64`, or `rand_u64_uniform`.
    #[inline(always)]
    pub fn fast_rand_u64() -> u64 {
        FAST_RNG_STATE.with(|state| {
            let next = state.get().wrapping_add(0x9e37_79b9_7f4a_7c15);
            state.set(next);
            splitmix64_step(next)
        })
    }

    /// Generate fast non-cryptographic random `u64` uniformly in `[0, max)`.
    ///
    /// This avoids repeated OS RNG calls in hot-path stealth heuristics while
    /// preserving rejection-sampling uniformity. Not for security-sensitive
    /// randomness.
    #[inline(always)]
    pub fn fast_rand_u64_uniform(max: u64) -> u64 {
        if max == 0 {
            return 0;
        }
        let chunk_size = u64::MAX / max;
        let end_of_last_chunk = chunk_size * max;

        let mut r = fast_rand_u64();
        while r >= end_of_last_chunk {
            r = fast_rand_u64();
        }
        r / chunk_size
    }
}

/// Compact range set for QUIC ACK ranges (inline for small sets, BTree for large).
pub mod ranges {
    use std::collections::{BTreeMap, Bound};

    const MAX_INLINE_CAPACITY: usize = 4;
    const MIN_TO_INLINE: usize = 2;

    /// Adaptive range set that starts inline and promotes to BTree at threshold.
    #[derive(Clone, PartialEq, Eq, PartialOrd)]
    pub enum RangeSet {
        /// Small inline storage (up to 4 ranges).
        Inline(InlineRangeSet),
        /// BTree-backed storage for larger range sets.
        BTree(BTreeRangeSet),
    }

    /// Inline (Vec-backed) range set for small ACK range counts.
    #[derive(Clone, PartialEq, Eq, PartialOrd)]
    pub struct InlineRangeSet {
        pub(crate) inner: Vec<(u64, u64)>,
        pub(crate) capacity: usize,
    }

    /// BTree-backed range set for large ACK range counts.
    #[derive(Clone, PartialEq, Eq, PartialOrd)]
    pub struct BTreeRangeSet {
        pub(crate) inner: BTreeMap<u64, u64>,
        pub(crate) capacity: usize,
    }

    impl RangeSet {
        /// Creates a new inline range set with the given maximum capacity.
        pub fn new(capacity: usize) -> Self {
            RangeSet::Inline(InlineRangeSet { inner: Vec::new(), capacity })
        }

        /// Returns the number of disjoint ranges stored.
        pub fn len(&self) -> usize {
            match self {
                RangeSet::Inline(set) => set.inner.len(),
                RangeSet::BTree(set) => set.inner.len(),
            }
        }

        /// Returns true if no ranges are stored.
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        #[inline(always)]
        fn fixup(&mut self) {
            match self {
                RangeSet::Inline(set) if set.inner.len() == MAX_INLINE_CAPACITY => {
                    let mut map: BTreeMap<u64, u64> = BTreeMap::new();
                    for (s, e) in set.inner.iter().copied() {
                        map.insert(s, e);
                    }
                    *self = RangeSet::BTree(BTreeRangeSet { inner: map, capacity: set.capacity });
                }
                RangeSet::BTree(set) if set.inner.len() <= MIN_TO_INLINE => {
                    let mut inner = Vec::with_capacity(MAX_INLINE_CAPACITY);
                    for (s, e) in set.inner.iter() {
                        if inner.len() < MAX_INLINE_CAPACITY {
                            inner.push((*s, *e));
                        }
                    }
                    *self = RangeSet::Inline(InlineRangeSet { inner, capacity: set.capacity });
                }
                _ => {}
            }
        }

        #[inline]
        /// Inserts a range, coalescing with adjacent/overlapping ranges.
        pub fn insert(&mut self, item: std::ops::Range<u64>) {
            match self {
                RangeSet::Inline(set) => set.insert(item),
                RangeSet::BTree(set) => set.insert(item),
            }
            self.fixup();
        }

        /// Iterates over all stored ranges in ascending order.
        pub fn iter(
            &self,
        ) -> impl DoubleEndedIterator<Item = std::ops::Range<u64>> + ExactSizeIterator + '_
        {
            enum Either<A, B> {
                Left(A),
                Right(B),
            }
            struct InlineIter<'a> {
                data: std::slice::Iter<'a, (u64, u64)>,
            }
            impl Iterator for InlineIter<'_> {
                type Item = std::ops::Range<u64>;
                fn next(&mut self) -> Option<Self::Item> {
                    self.data.next().map(|(s, e)| (*s)..(*e))
                }
            }
            struct Iter<'a>(
                Either<std::collections::btree_map::Iter<'a, u64, u64>, InlineIter<'a>>,
            );
            impl Iterator for Iter<'_> {
                type Item = std::ops::Range<u64>;
                fn next(&mut self) -> Option<Self::Item> {
                    match &mut self.0 {
                        Either::Left(i) => i.next().map(|(s, e)| (*s)..(*e)),
                        Either::Right(i) => i.next(),
                    }
                }
            }
            impl DoubleEndedIterator for Iter<'_> {
                fn next_back(&mut self) -> Option<std::ops::Range<u64>> {
                    match &mut self.0 {
                        Either::Left(i) => i.next_back().map(|(s, e)| (*s)..(*e)),
                        Either::Right(_) => None,
                    }
                }
            }
            impl ExactSizeIterator for Iter<'_> {
                fn len(&self) -> usize {
                    match &self.0 {
                        Either::Left(i) => i.len(),
                        Either::Right(_ii) => 0,
                    }
                }
            }
            match self {
                RangeSet::BTree(set) => Iter(Either::Left(set.inner.iter())),
                RangeSet::Inline(set) => Iter(Either::Right(InlineIter { data: set.inner.iter() })),
            }
        }

        /// Iterates over all individual values across all stored ranges.
        pub fn flatten(&self) -> impl DoubleEndedIterator<Item = u64> + '_ {
            struct Flat<I: Iterator<Item = std::ops::Range<u64>>>(I, Option<std::ops::Range<u64>>);
            impl<I: Iterator<Item = std::ops::Range<u64>>> Iterator for Flat<I> {
                type Item = u64;
                fn next(&mut self) -> Option<Self::Item> {
                    loop {
                        if let Some(r) = &mut self.1 {
                            if r.start < r.end {
                                let v = r.start;
                                r.start += 1;
                                return Some(v);
                            }
                        }
                        self.1 = self.0.next();
                        self.1.as_ref()?;
                    }
                }
            }
            impl<I: DoubleEndedIterator<Item = std::ops::Range<u64>>> DoubleEndedIterator for Flat<I> {
                fn next_back(&mut self) -> Option<u64> {
                    None
                }
            }
            Flat(self.iter(), None)
        }

        /// Returns the smallest value in the set, if any.
        pub fn first(&self) -> Option<u64> {
            match self {
                RangeSet::Inline(set) => set.inner.first().map(|(s, _)| *s),
                RangeSet::BTree(set) => set.inner.first_key_value().map(|(k, _)| *k),
            }
        }

        /// Returns the largest value in the set, if any.
        pub fn last(&self) -> Option<u64> {
            match self {
                RangeSet::Inline(set) => set.inner.last().map(|(_, e)| *e - 1),
                RangeSet::BTree(set) => set.inner.last_key_value().map(|(_, v)| *v - 1),
            }
        }

        /// Removes all values up to and including `largest`.
        pub fn remove_until(&mut self, largest: u64) {
            match self {
                RangeSet::Inline(set) => set.remove_until(largest),
                RangeSet::BTree(set) => set.remove_until(largest),
            }
            self.fixup();
        }

        /// Inserts a single value as a one-element range.
        pub fn push_item(&mut self, item: u64) {
            self.insert(item..item + 1)
        }
    }

    impl Default for RangeSet {
        fn default() -> Self {
            RangeSet::Inline(InlineRangeSet { inner: Vec::new(), capacity: usize::MAX })
        }
    }

    impl InlineRangeSet {
        fn insert(&mut self, item: std::ops::Range<u64>) {
            let start = item.start;
            let mut end = item.end;
            let mut pos = 0;
            loop {
                match self.inner.get_mut(pos) {
                    Some((s, e)) => {
                        if start > *e {
                            pos += 1;
                            continue;
                        }
                        if end < *s {
                            if self.inner.len() == self.capacity {
                                self.inner.remove(0);
                                pos = pos.saturating_sub(1);
                            }
                            self.inner.insert(pos, (start, end));
                            return;
                        }
                        if start < *s {
                            *s = start;
                        }
                        if end > *e {
                            *e = end;
                            break;
                        } else {
                            return;
                        }
                    }
                    None => {
                        if self.inner.len() == self.capacity {
                            self.inner.remove(0);
                        }
                        self.inner.push((start, end));
                        return;
                    }
                }
            }
            while let Some((s, e)) = self.inner.get(pos + 1).copied() {
                if end < s {
                    break;
                }
                let new_e = e.max(end);
                self.inner[pos].1 = new_e;
                end = new_e;
                self.inner.remove(pos + 1);
            }
        }

        fn remove_until(&mut self, largest: u64) {
            while let Some((s, e)) = self.inner.first_mut() {
                if largest >= *e {
                    self.inner.remove(0);
                    continue;
                }
                *s = (largest + 1).max(*s);
                if *s == *e {
                    self.inner.remove(0);
                }
                break;
            }
        }
    }

    impl BTreeRangeSet {
        fn insert(&mut self, item: std::ops::Range<u64>) {
            let mut start = item.start;
            let mut end = item.end;
            if let Some(r) = self.prev_to(start) {
                if ranges_overlap(&r, &item) {
                    self.inner.remove(&r.start);
                    start = start.min(r.start);
                    end = end.max(r.end);
                }
            }
            while let Some(r) = self.next_to(start) {
                if item.contains(&r.start) && item.contains(&r.end) {
                    self.inner.remove(&r.start);
                    continue;
                }
                if !ranges_overlap(&r, &item) {
                    break;
                }
                self.inner.remove(&r.start);
                start = start.min(r.start);
                end = end.max(r.end);
            }
            if self.inner.len() >= self.capacity {
                self.inner.pop_first();
            }
            self.inner.insert(start, end);
        }

        fn remove_until(&mut self, largest: u64) {
            let ranges: Vec<std::ops::Range<u64>> = self
                .inner
                .range((Bound::Unbounded, Bound::Included(&largest)))
                .map(|(&s, &e)| s..e)
                .collect();
            for r in ranges {
                self.inner.remove(&r.start);
                if r.end > largest + 1 {
                    let start = largest + 1;
                    self.insert(start..r.end);
                }
            }
        }

        fn prev_to(&self, item: u64) -> Option<std::ops::Range<u64>> {
            self.inner
                .range((Bound::Unbounded, Bound::Included(&item)))
                .map(|(&s, &e)| s..e)
                .next_back()
        }

        fn next_to(&self, item: u64) -> Option<std::ops::Range<u64>> {
            self.inner.range((Bound::Included(&item), Bound::Unbounded)).map(|(&s, &e)| s..e).next()
        }
    }

    fn ranges_overlap(a: &std::ops::Range<u64>, b: &std::ops::Range<u64>) -> bool {
        a.start < b.end && b.start < a.end
    }
}

/// Offset-keyed byte buffer for QUIC stream reassembly.
pub mod range_buf {
    use std::cmp;
    use std::fmt::Debug;
    use std::marker::PhantomData;
    use std::ops::Deref;
    use std::sync::Arc;
    /// A byte buffer with a stream offset, used for QUIC stream data reassembly.
    #[derive(Clone, Debug, Default)]
    pub struct RangeBuf<F = DefaultBufFactory>
    where
        F: BufFactory,
    {
        pub(crate) data: F::Buf,
        pub(crate) start: usize,
        pub(crate) pos: usize,
        pub(crate) len: usize,
        pub(crate) off: u64,
        pub(crate) fin: bool,
        _bf: PhantomData<F>,
    }
    /// Factory trait for creating backing buffers (enables zero-copy variants).
    pub trait BufFactory: Clone + Default + Debug {
        type Buf: Clone + Debug + AsRef<[u8]>;
        fn buf_from_slice(buf: &[u8]) -> Self::Buf;
    }
    /// Trait for splitting a buffer at a byte offset.
    pub trait BufSplit {
        fn split_at(&mut self, at: usize) -> Self;
        fn try_add_prefix(&mut self, _prefix: &[u8]) -> bool {
            false
        }
    }
    /// Default buffer factory using Arc-wrapped boxed slices.
    #[derive(Debug, Clone, Default)]
    pub struct DefaultBufFactory;
    /// Default buffer type: an Arc-wrapped boxed byte slice.
    #[derive(Debug, Clone, Default)]
    pub struct DefaultBuf(Arc<Box<[u8]>>);
    impl BufFactory for DefaultBufFactory {
        type Buf = DefaultBuf;
        fn buf_from_slice(buf: &[u8]) -> Self::Buf {
            DefaultBuf(Arc::new(buf.into()))
        }
    }
    impl AsRef<[u8]> for DefaultBuf {
        fn as_ref(&self) -> &[u8] {
            &self.0[..]
        }
    }
    impl<F: BufFactory> RangeBuf<F>
    where
        F::Buf: Clone,
    {
        /// Creates a RangeBuf from a byte slice, stream offset, and FIN flag.
        pub fn from(buf: &[u8], off: u64, fin: bool) -> RangeBuf<F> {
            Self::from_raw(F::buf_from_slice(buf), off, fin)
        }
        /// Creates a RangeBuf from a pre-allocated buffer, offset, and FIN flag.
        pub fn from_raw(data: F::Buf, off: u64, fin: bool) -> RangeBuf<F> {
            RangeBuf {
                len: data.as_ref().len(),
                data,
                start: 0,
                pos: 0,
                off,
                fin,
                _bf: Default::default(),
            }
        }
        /// Returns true if this buffer carries the FIN (stream end) flag.
        pub fn fin(&self) -> bool {
            self.fin
        }
        /// Returns the current stream byte offset of the unconsumed portion.
        pub fn off(&self) -> u64 {
            (self.off - self.start as u64) + self.pos as u64
        }
        /// Returns the maximum stream byte offset covered by this buffer.
        pub fn max_off(&self) -> u64 {
            self.off() + self.len() as u64
        }
        /// Returns the number of unconsumed bytes remaining.
        pub fn len(&self) -> usize {
            self.len - (self.pos - self.start)
        }
        /// Returns true if all bytes have been consumed.
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }
        /// Advances the read cursor by `count` bytes.
        pub fn consume(&mut self, count: usize) {
            self.pos += count;
        }
        /// Splits off bytes starting at `at`, returning the tail as a new RangeBuf.
        pub fn split_off(&mut self, at: usize) -> RangeBuf<F>
        where
            F::Buf: Clone + AsRef<[u8]>,
        {
            assert!(at <= self.len, "split index {} > len {}", at, self.len);
            let buf = RangeBuf {
                data: self.data.clone(),
                start: self.start + at,
                pos: cmp::max(self.pos, self.start + at),
                len: self.len - at,
                off: self.off + at as u64,
                _bf: Default::default(),
                fin: self.fin,
            };
            self.pos = cmp::min(self.pos, self.start + at);
            self.len = at;
            self.fin = false;
            buf
        }
    }
    impl<F: BufFactory> Deref for RangeBuf<F> {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            &self.data.as_ref()[self.pos..self.start + self.len]
        }
    }
    impl<F: BufFactory> Ord for RangeBuf<F> {
        fn cmp(&self, other: &RangeBuf<F>) -> cmp::Ordering {
            self.off.cmp(&other.off).reverse()
        }
    }
    impl<F: BufFactory> PartialOrd for RangeBuf<F> {
        fn partial_cmp(&self, other: &RangeBuf<F>) -> Option<cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl<F: BufFactory> Eq for RangeBuf<F> {}
    impl<F: BufFactory> PartialEq for RangeBuf<F> {
        fn eq(&self, other: &RangeBuf<F>) -> bool {
            self.off == other.off
        }
    }
}

/// QUIC variable-length integer encoding/decoding (RFC 9000 Section 16).
pub mod varint {
    use crate::error::ConnectionError;

    #[inline(always)]
    /// Returns the wire length in bytes needed to encode `v` as a QUIC varint.
    pub const fn varint_len(v: u64) -> usize {
        if v <= 0x3f {
            1
        } else if v <= 0x3fff {
            2
        } else if v <= 0x3fff_ffff {
            4
        } else {
            8
        }
    }

    #[inline(always)]
    /// Encodes `v` as a QUIC varint into `out`, returning bytes written.
    pub fn write_varint(v: u64, out: &mut [u8]) -> Result<usize, ConnectionError> {
        use crate::transport::udpfast::unlikely;
        let n = varint_len(v);
        if unlikely(out.len() < n) {
            return Err(ConnectionError::BufferTooShort);
        }
        let written = crate::simd::transport::encode_varint(v, &mut out[..n]);
        debug_assert!(written == n || written == 0);
        if unlikely(written == 0) {
            return Err(ConnectionError::InvalidPacket);
        }
        Ok(written)
    }

    #[inline(always)]
    /// Encodes `v` as a QUIC varint with exactly `n` bytes of wire encoding.
    pub fn write_varint_with_len(
        v: u64,
        n: usize,
        out: &mut [u8],
    ) -> Result<usize, ConnectionError> {
        if out.len() < n {
            return Err(ConnectionError::BufferTooShort);
        }
        match n {
            1 => write_varint(v, out),
            2 => {
                if v > 0x3fff {
                    return Err(ConnectionError::InvalidPacket);
                }
                out[0] = 0x40 | (((v >> 8) & 0x3f) as u8);
                out[1] = (v & 0xff) as u8;
                Ok(2)
            }
            4 => {
                if v > 0x3fff_ffff {
                    return Err(ConnectionError::InvalidPacket);
                }
                out[0] = 0x80 | (((v >> 24) & 0x3f) as u8);
                out[1] = ((v >> 16) & 0xff) as u8;
                out[2] = ((v >> 8) & 0xff) as u8;
                out[3] = (v & 0xff) as u8;
                Ok(4)
            }
            8 => {
                if v > 0x3fff_ffff_ffff_ffff {
                    return Err(ConnectionError::InvalidPacket);
                }
                out[0] = 0xc0 | (((v >> 56) & 0x3f) as u8);
                out[1] = ((v >> 48) & 0xff) as u8;
                out[2] = ((v >> 40) & 0xff) as u8;
                out[3] = ((v >> 32) & 0xff) as u8;
                out[4] = ((v >> 24) & 0xff) as u8;
                out[5] = ((v >> 16) & 0xff) as u8;
                out[6] = ((v >> 8) & 0xff) as u8;
                out[7] = (v & 0xff) as u8;
                Ok(8)
            }
            _ => Err(ConnectionError::InvalidPacket),
        }
    }

    #[inline(always)]
    /// Decodes a QUIC varint from `input`, returning (value, bytes_consumed).
    pub fn read_varint(input: &[u8]) -> Result<(u64, usize), ConnectionError> {
        use crate::transport::udpfast::unlikely;
        if unlikely(input.is_empty()) {
            return Err(ConnectionError::BufferTooShort);
        }
        if let Some((value, used)) = crate::simd::transport::decode_varint(input) {
            if unlikely(used == 0) {
                return Err(ConnectionError::InvalidPacket);
            }
            return Ok((value, used));
        }

        // SIMD path failed to decode; fall back to scalar classification for error semantics.
        let first = input[0];
        let tag = first >> 6;
        let need = match tag {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => return Err(ConnectionError::InvalidPacket),
        };
        if input.len() < need {
            return Err(ConnectionError::BufferTooShort);
        }

        // Compute scalar result for the variable-length integer decode.
        let res = match tag {
            0 => ((first & 0x3f) as u64, 1),
            1 => {
                let v = (((first & 0x3f) as u64) << 8) | (input[1] as u64);
                (v, 2)
            }
            2 => {
                let v = (((first & 0x3f) as u64) << 24)
                    | ((input[1] as u64) << 16)
                    | ((input[2] as u64) << 8)
                    | (input[3] as u64);
                (v, 4)
            }
            3 => {
                let v = (((first & 0x3f) as u64) << 56)
                    | ((input[1] as u64) << 48)
                    | ((input[2] as u64) << 40)
                    | ((input[3] as u64) << 32)
                    | ((input[4] as u64) << 24)
                    | ((input[5] as u64) << 16)
                    | ((input[6] as u64) << 8)
                    | (input[7] as u64);
                (v, 8)
            }
            _ => {
                debug_assert!(false, "invalid varint tag");
                return Err(ConnectionError::InvalidPacket);
            }
        };
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::pnspace::PktNumSpace;
    use super::rand;
    use super::ranges::RangeSet;
    use super::varint;

    // --- RangeSet tests ---

    #[test]
    fn rangeset_insert_single() {
        let mut rs = RangeSet::new(64);
        rs.insert(5..10);
        let ranges: Vec<_> = rs.iter().collect();
        assert_eq!(ranges, vec![5..10]);
    }

    #[test]
    fn rangeset_insert_coalesces_adjacent() {
        let mut rs = RangeSet::new(64);
        rs.insert(5..10);
        rs.insert(10..15);
        let ranges: Vec<_> = rs.iter().collect();
        assert_eq!(ranges, vec![5..15]);
    }

    #[test]
    fn rangeset_insert_coalesces_overlapping() {
        let mut rs = RangeSet::new(64);
        rs.insert(5..12);
        rs.insert(10..20);
        let ranges: Vec<_> = rs.iter().collect();
        assert_eq!(ranges, vec![5..20]);
    }

    #[test]
    fn rangeset_insert_disjoint_preserved() {
        let mut rs = RangeSet::new(64);
        rs.insert(1..3);
        rs.insert(10..15);
        rs.insert(20..25);
        let ranges: Vec<_> = rs.iter().collect();
        assert_eq!(ranges, vec![1..3, 10..15, 20..25]);
    }

    #[test]
    fn rangeset_flatten_produces_individual_values() {
        let mut rs = RangeSet::new(64);
        rs.insert(3..6);
        rs.insert(10..12);
        let values: Vec<u64> = rs.flatten().collect();
        assert_eq!(values, vec![3, 4, 5, 10, 11]);
    }

    #[test]
    fn rangeset_remove_until_prunes_correctly() {
        let mut rs = RangeSet::new(64);
        rs.insert(5..10);
        rs.insert(15..20);
        rs.remove_until(12);
        let ranges: Vec<_> = rs.iter().collect();
        assert_eq!(ranges, vec![15..20]);
    }

    #[test]
    fn rangeset_push_item_single_value() {
        let mut rs = RangeSet::new(64);
        rs.push_item(42);
        let ranges: Vec<_> = rs.iter().collect();
        assert_eq!(ranges, vec![42..43]);
    }

    #[test]
    fn rangeset_push_item_coalesces_consecutive() {
        let mut rs = RangeSet::new(64);
        rs.push_item(5);
        rs.push_item(6);
        rs.push_item(7);
        let ranges: Vec<_> = rs.iter().collect();
        assert_eq!(ranges, vec![5..8]);
    }

    #[test]
    fn fast_rand_uniform_zero_max_returns_zero() {
        assert_eq!(rand::fast_rand_u64_uniform(0), 0);
    }

    #[test]
    fn fast_rand_uniform_stays_below_max() {
        for max in [1, 2, 3, 7, 64, 100, 1024, 4096] {
            for _ in 0..256 {
                assert!(rand::fast_rand_u64_uniform(max) < max);
            }
        }
    }

    #[test]
    fn fast_rand_u64_produces_variation() {
        let first = rand::fast_rand_u64();
        let mut changed = false;
        for _ in 0..16 {
            if rand::fast_rand_u64() != first {
                changed = true;
                break;
            }
        }
        assert!(changed, "fast transport RNG must not be a constant stream");
    }

    #[test]
    fn rangeset_empty_iter() {
        let rs = RangeSet::new(64);
        assert_eq!(rs.iter().count(), 0);
        assert_eq!(rs.flatten().count(), 0);
    }

    // --- PktNumSpace tests ---

    #[test]
    fn pkt_num_space_accepts_valid_pn() {
        let mut pns = PktNumSpace::new();
        assert!(pns.on_packet_recv(0, 25, 2));
        assert!(pns.on_packet_recv(1, 25, 2));
        assert!(pns.on_packet_recv(5, 25, 2));
    }

    #[test]
    fn pkt_num_space_rejects_duplicate() {
        let mut pns = PktNumSpace::new();
        assert!(pns.on_packet_recv(42, 25, 2));
        assert!(!pns.on_packet_recv(42, 25, 2));
    }

    #[test]
    fn pkt_num_space_tracks_largest() {
        let mut pns = PktNumSpace::new();
        pns.on_packet_recv(3, 25, 2);
        pns.on_packet_recv(7, 25, 2);
        pns.on_packet_recv(1, 25, 2);
        assert_eq!(pns.largest_recv, Some(7));
    }

    // --- varint tests ---

    #[test]
    fn varint_len_boundaries() {
        assert_eq!(varint::varint_len(0), 1);
        assert_eq!(varint::varint_len(0x3f), 1);
        assert_eq!(varint::varint_len(0x40), 2);
        assert_eq!(varint::varint_len(0x3fff), 2);
        assert_eq!(varint::varint_len(0x4000), 4);
        assert_eq!(varint::varint_len(0x3fff_ffff), 4);
        assert_eq!(varint::varint_len(0x4000_0000), 8);
    }

    #[test]
    fn varint_write_read_roundtrip() {
        let test_values = [
            0u64,
            1,
            63,
            64,
            16383,
            16384,
            1_073_741_823,
            1_073_741_824,
            4_611_686_018_427_387_903,
        ];
        for &v in &test_values {
            let mut buf = [0u8; 8];
            let written = varint::write_varint(v, &mut buf).unwrap();
            let (decoded, consumed) = varint::read_varint(&buf[..written]).unwrap();
            assert_eq!(decoded, v, "roundtrip failed for {v}");
            assert_eq!(consumed, written, "consumed mismatch for {v}");
        }
    }

    #[test]
    fn varint_read_empty_buffer_errors() {
        assert!(varint::read_varint(&[]).is_err());
    }

    #[test]
    fn varint_write_buffer_too_short_errors() {
        let mut buf = [0u8; 1];
        assert!(varint::write_varint(0x4000, &mut buf).is_err());
    }

    #[test]
    fn varint_write_with_len_2byte() {
        let mut buf = [0u8; 2];
        let n = varint::write_varint_with_len(100, 2, &mut buf).unwrap();
        assert_eq!(n, 2);
        let (val, consumed) = varint::read_varint(&buf).unwrap();
        assert_eq!(val, 100);
        assert_eq!(consumed, 2);
    }
}
