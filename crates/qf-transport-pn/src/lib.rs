use qf_transport_types::ConnectionId;
/// QUIC packet number space tracking and ACK generation.
pub mod pnspace {
    use super::ranges::RangeSet;
    use qf_common::time_source::ProtocolClock;
    use std::time::{Duration, Instant};

    /// Per-epoch packet number space tracking ACK state and receive history.
    #[derive(Clone)]
    pub struct PktNumSpace {
        /// Clock owned by the enclosing protocol connection.
        clock: ProtocolClock,
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
        /// Deadline for acknowledging the first unacknowledged ack-eliciting
        /// packet when the packet-count threshold is not reached.
        ack_deadline: Option<Instant>,
    }

    impl Default for PktNumSpace {
        fn default() -> Self {
            Self::new()
        }
    }

    impl PktNumSpace {
        /// Creates a new empty packet number space.
        pub fn new() -> Self {
            Self::new_with_clock(ProtocolClock::default())
        }

        /// Creates a packet number space owned by an explicit protocol clock.
        #[inline(always)]
        pub fn new_with_clock(clock: ProtocolClock) -> Self {
            Self {
                clock,
                largest_recv: None,
                ack_ranges: RangeSet::default(),
                ack_elicited: false,
                last_ack_time: None,
                last_recv_time: None,
                recvd_since_ack: 0,
                ack_deadline: None,
            }
        }

        /// Maximum packet number per RFC 9000 Section 17.1 (2^62 - 1)
        /// Maximum packet number permitted by RFC 9000 Section 17.1.
        pub const MAX_PACKET_NUMBER: u64 = (1u64 << 62) - 1;

        /// Track a newly received packet number without making ACK scheduling
        /// depend on frames that may be non-ack-eliciting.
        /// Returns false if the packet should be rejected (duplicate or overflow).
        #[inline(always)]
        pub fn on_packet_recv(&mut self, pn: u64) -> bool {
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
            self.has_pending_ack_at(self.clock.now())
        }

        /// Returns true if an ACK is pending at an explicit protocol timestamp.
        #[inline(always)]
        pub fn has_pending_ack_at(&self, now: Instant) -> bool {
            self.ack_elicited || self.ack_deadline.is_some_and(|deadline| now >= deadline)
        }

        /// Takes an ACK decision and returns (ack_delay, ranges)
        #[inline(always)]
        pub fn take_ack(&mut self, ack_delay_exponent: u64) -> Option<(u64, Vec<(u64, u64)>)> {
            self.take_ack_at(ack_delay_exponent, self.clock.now())
        }

        /// Inspect the pending ACK without consuming the pending decision.
        ///
        /// Returns the same `(ack_delay, ranges)` a commit would emit, but leaves `ack_elicited`,
        /// `recvd_since_ack`, and `ack_deadline` untouched. Callers that may fail to serialize the
        /// frame use this and only call [`Self::commit_ack_at`] once the bytes are written, so an
        /// undersized output buffer or a serialization error cannot silently drop an ACK that no
        /// further inbound packet is guaranteed to re-trigger.
        #[inline(always)]
        pub fn peek_ack_at(
            &self,
            ack_delay_exponent: u64,
            now: Instant,
        ) -> Option<(u64, Vec<(u64, u64)>)> {
            if !self.has_pending_ack_at(now) {
                return None;
            }

            let delay = if let Some(last) = self.last_recv_time {
                now.saturating_duration_since(last)
            } else {
                Duration::from_micros(0)
            };

            // QUIC ACK delay encoding uses 2^ack_delay_exponent microseconds units
            let micros = delay.as_micros() as u64;
            let ack_delay = micros >> ack_delay_exponent.min(20);

            Some((ack_delay, self.ack_ranges.iter().map(|r| (r.start, r.end)).collect()))
        }

        /// Commit a previously inspected ACK: clear the pending decision and record the send time.
        ///
        /// Idempotent in effect but must be called exactly once per emitted ACK frame, after the
        /// frame has been successfully written.
        #[inline(always)]
        pub fn commit_ack_at(&mut self, now: Instant) {
            self.ack_elicited = false;
            self.recvd_since_ack = 0;
            self.ack_deadline = None;
            self.last_ack_time = Some(now);
        }

        /// Takes an ACK decision at an explicit protocol timestamp.
        ///
        /// Convenience for callers that cannot fail between inspection and emission. Paths whose
        /// serialization can fail must use [`Self::peek_ack_at`] plus [`Self::commit_ack_at`].
        #[inline(always)]
        pub fn take_ack_at(
            &mut self,
            ack_delay_exponent: u64,
            now: Instant,
        ) -> Option<(u64, Vec<(u64, u64)>)> {
            let taken = self.peek_ack_at(ack_delay_exponent, now)?;
            self.commit_ack_at(now);
            Some(taken)
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

        /// Record an ack-eliciting packet and schedule an ACK at the configured
        /// threshold or delay boundary. ACK-only packets must never call this.
        #[inline(always)]
        pub fn note_ack_eliciting(&mut self, max_ack_delay_ms: u64, ack_threshold: u64) {
            self.note_ack_eliciting_at(max_ack_delay_ms, ack_threshold, self.clock.now());
        }

        /// Records an ACK-eliciting packet at an explicit protocol timestamp.
        #[inline(always)]
        pub fn note_ack_eliciting_at(
            &mut self,
            max_ack_delay_ms: u64,
            ack_threshold: u64,
            now: Instant,
        ) {
            if self.recvd_since_ack == 0 {
                self.ack_deadline =
                    Some(now.checked_add(Duration::from_millis(max_ack_delay_ms)).unwrap_or(now));
            }
            self.last_recv_time = Some(now);
            self.recvd_since_ack = self.recvd_since_ack.saturating_add(1);
            let overdue = self
                .last_ack_time
                .map(|last_ack| {
                    now.saturating_duration_since(last_ack)
                        >= Duration::from_millis(max_ack_delay_ms)
                })
                .unwrap_or(true);
            if self.recvd_since_ack >= ack_threshold.max(1) || overdue {
                self.ack_elicited = true;
            }
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
        inner: HashSet<ConnectionId>,
    }

    impl ConnectionIdSet {
        /// Creates a new empty connection ID set.
        pub fn new() -> Self {
            Self { inner: HashSet::new() }
        }

        /// Inserts a connection ID into the set.
        pub fn insert(&mut self, id: &ConnectionId) {
            self.inner.insert(*id);
        }

        /// Returns true if the set contains the given connection ID.
        pub fn contains(&self, id: &ConnectionId) -> bool {
            self.inner.contains(id)
        }
    }

    impl Default for ConnectionIdSet {
        fn default() -> Self {
            Self::new()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn tracks_inline_connection_ids_by_value() {
            let first = ConnectionId::from_ref(b"first-dcid");
            let second = ConnectionId::from_ref(b"second-dcid");
            let mut set = ConnectionIdSet::new();

            assert!(!set.contains(&first));
            set.insert(&first);
            set.insert(&second);
            set.insert(&first);

            assert!(set.contains(&first));
            assert!(set.contains(&second));
            assert!(!set.contains(&ConnectionId::from_ref(b"other-dcid")));
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
        qf_common::rng::fill_secure_or_abort(buf, "transport::rand::rand_bytes");
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

#[cfg(test)]
mod tests {
    use super::pnspace::PktNumSpace;
    use super::rand;
    use super::ranges::RangeSet;
    use qf_common::time_source::{ProtocolClock, TimeSource};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime};

    struct MutableAckClock {
        now: Mutex<Instant>,
    }

    impl TimeSource for MutableAckClock {
        fn now_instant(&self) -> Instant {
            *self.now.lock().expect("ack clock mutex must not be poisoned")
        }

        fn now_system(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH
        }
    }

    impl MutableAckClock {
        fn set(&self, now: Instant) {
            *self.now.lock().expect("ack clock mutex must not be poisoned") = now;
        }
    }

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

    /// Inspecting a pending ACK must not consume it.
    ///
    /// Before the split, `take_ack` cleared the pending flag, the receive counter, and the
    /// deadline before the caller knew whether the frame would fit or serialize. A failure there
    /// dropped the ACK, and nothing guarantees another inbound packet arrives to re-trigger one.
    #[test]
    fn peek_ack_leaves_the_pending_decision_intact() {
        let now = std::time::Instant::now();
        let mut pns = PktNumSpace::new();
        assert!(pns.on_packet_recv(0));
        pns.note_ack_eliciting(0, 1);
        assert!(pns.has_pending_ack(), "an ack-eliciting packet must schedule an ACK");

        let first = pns.peek_ack_at(3, now).expect("a pending ACK must be inspectable");
        assert!(pns.has_pending_ack(), "inspection must not consume the pending decision");

        // Repeated inspection is stable and still non-consuming.
        let second = pns.peek_ack_at(3, now).expect("still pending");
        assert_eq!(first.1, second.1, "the reported ranges must not change under inspection");
        assert!(pns.has_pending_ack());
    }

    /// Committing clears the pending decision exactly once.
    #[test]
    fn commit_ack_clears_the_pending_decision_and_ranges_survive() {
        let now = std::time::Instant::now();
        let mut pns = PktNumSpace::new();
        assert!(pns.on_packet_recv(7));
        pns.note_ack_eliciting(0, 1);

        let (_, ranges) = pns.peek_ack_at(3, now).expect("pending");
        assert!(!ranges.is_empty(), "the fixture must carry ranges");

        pns.commit_ack_at(now);
        assert!(!pns.has_pending_ack(), "commit must clear the pending decision");
        assert!(pns.peek_ack_at(3, now).is_none(), "nothing is pending after a commit");

        // The stored ranges are retained; only the pending decision was consumed.
        assert!(pns.contains(7), "committing an ACK must not forget what was received");

        // A later ack-eliciting packet schedules a fresh ACK carrying the retained range.
        assert!(pns.on_packet_recv(8));
        pns.note_ack_eliciting(0, 1);
        let (_, later) = pns.peek_ack_at(3, now).expect("a new ACK is pending");
        assert!(!later.is_empty());
    }

    /// A failed emission must leave the ACK pending so the next send can carry it.
    #[test]
    fn an_inspected_but_uncommitted_ack_survives_for_a_later_attempt() {
        let now = std::time::Instant::now();
        let mut pns = PktNumSpace::new();
        assert!(pns.on_packet_recv(1));
        pns.note_ack_eliciting(0, 1);

        // Model a send that inspects, then fails on capacity and never commits.
        let _ = pns.peek_ack_at(3, now).expect("pending");
        assert!(pns.has_pending_ack(), "a failed emission must not consume the ACK");

        // The retry succeeds and commits.
        let (_, ranges) = pns.peek_ack_at(3, now).expect("still pending on retry");
        assert!(!ranges.is_empty());
        pns.commit_ack_at(now);
        assert!(!pns.has_pending_ack());
    }

    #[test]
    fn pkt_num_space_accepts_valid_pn() {
        let mut pns = PktNumSpace::new();
        assert!(pns.on_packet_recv(0));
        assert!(pns.on_packet_recv(1));
        assert!(pns.on_packet_recv(5));
    }

    #[test]
    fn pkt_num_space_rejects_duplicate() {
        let mut pns = PktNumSpace::new();
        assert!(pns.on_packet_recv(42));
        assert!(!pns.on_packet_recv(42));
    }

    #[test]
    fn pkt_num_space_tracks_largest() {
        let mut pns = PktNumSpace::new();
        pns.on_packet_recv(3);
        pns.on_packet_recv(7);
        pns.on_packet_recv(1);
        assert_eq!(pns.largest_recv, Some(7));
    }

    #[test]
    fn ack_only_packet_number_does_not_schedule_an_ack() {
        let mut pns = PktNumSpace::new();
        assert!(pns.on_packet_recv(1));
        assert!(!pns.has_pending_ack());
    }

    #[test]
    fn ack_eliciting_packets_respect_threshold_after_initial_ack() {
        let mut pns = PktNumSpace::new();
        assert!(pns.on_packet_recv(1));
        pns.note_ack_eliciting(25, 2);
        assert!(pns.take_ack(3).is_some(), "the first ack-eliciting packet is acknowledged");

        assert!(pns.on_packet_recv(2));
        pns.note_ack_eliciting(25, 2);
        assert!(!pns.has_pending_ack());
        assert!(pns.on_packet_recv(3));
        pns.note_ack_eliciting(25, 2);
        assert!(pns.has_pending_ack());
    }

    #[test]
    fn delayed_ack_deadline_releases_single_tail_packet() {
        let mut pns = PktNumSpace::new();
        assert!(pns.on_packet_recv(1));
        pns.note_ack_eliciting(25, 2);
        assert!(pns.take_ack(3).is_some());

        assert!(pns.on_packet_recv(2));
        pns.note_ack_eliciting(1, 2);
        assert!(!pns.has_pending_ack());
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(pns.has_pending_ack());
        assert!(pns.take_ack(3).is_some());
    }

    #[test]
    fn packet_number_space_uses_owned_clock_for_ack_deadline() {
        let base = Instant::now();
        let source = Arc::new(MutableAckClock { now: Mutex::new(base) });
        let mut pns = PktNumSpace::new_with_clock(ProtocolClock::from_source(source.clone()));

        assert!(pns.on_packet_recv(1));
        pns.note_ack_eliciting(10, 1);
        assert!(pns.has_pending_ack());
        assert!(pns.take_ack(3).is_some());

        source.set(base + Duration::from_millis(1));
        assert!(pns.on_packet_recv(2));
        pns.note_ack_eliciting(10, 2);
        assert!(!pns.has_pending_ack());

        source.set(base + Duration::from_millis(11));
        assert!(pns.has_pending_ack());
        assert!(pns.take_ack(3).is_some());

        source.set(base.checked_sub(Duration::from_millis(1)).expect("base must be recent"));
        assert!(pns.on_packet_recv(3));
        pns.note_ack_eliciting(10, 2);
        assert!(!pns.has_pending_ack());
    }
}
