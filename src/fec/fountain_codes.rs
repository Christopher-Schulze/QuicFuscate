use super::{MemoryPool, DEFAULT_FOUNTAIN_SEED};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

const SPLITMIX64_GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;
const MAX_FOUNTAIN_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const MAX_FOUNTAIN_SOURCE_SYMBOLS: usize = super::wire::MAX_TOTAL_COUNT as usize;

#[inline]
fn splitmix64_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(SPLITMIX64_GAMMA);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn deterministic_source_indices(
    symbol_count: usize,
    degree_dist: &[f64],
    rng_seed: u64,
    symbol_id: u64,
) -> Vec<usize> {
    if symbol_count == 0 {
        return Vec::new();
    }
    let mut rng_state = rng_seed.wrapping_add(symbol_id.wrapping_mul(SPLITMIX64_GAMMA));
    let random = (splitmix64_next(&mut rng_state) as f64) / (u64::MAX as f64);
    let degree = degree_dist
        .iter()
        .enumerate()
        .find_map(|(degree, &cumulative)| (random <= cumulative).then_some(degree.max(1)))
        .unwrap_or(symbol_count);
    let mut selected = HashSet::with_capacity(degree);
    let mut indices = Vec::with_capacity(degree);
    for _ in 0..degree {
        let index = (splitmix64_next(&mut rng_state) % symbol_count as u64) as usize;
        if selected.insert(index) {
            indices.push(index);
        }
    }
    indices
}

/// **LT (Luby Transform) Fountain Code** - Rateless erasure coding
pub struct LTEncoder {
    k: usize,              // Number of source symbols
    symbols: Vec<Vec<u8>>, // Source symbols
    degree_dist: Vec<f64>, // Degree distribution (Robust Soliton)
    rng_seed: u64,
    symbol_size: usize,
}

impl LTEncoder {
    /// Create a new LT encoder with `k` source symbols and fixed symbol size.
    pub fn new(k: usize, symbol_size: usize) -> Self {
        Self::new_with_seed(k, symbol_size, DEFAULT_FOUNTAIN_SEED)
    }

    /// Create an LT encoder with an explicit connection-local PRNG seed.
    pub fn new_with_seed(k: usize, symbol_size: usize, rng_seed: u64) -> Self {
        let k = k.clamp(1, MAX_FOUNTAIN_SOURCE_SYMBOLS);
        let symbol_size = symbol_size.clamp(1, MAX_FOUNTAIN_PAYLOAD_BYTES);
        let degree_dist = Self::robust_soliton_distribution(k);
        Self { k, symbols: Vec::with_capacity(k), degree_dist, rng_seed, symbol_size }
    }

    /// **Robust Soliton Distribution** - Optimal degree distribution for LT codes
    fn robust_soliton_distribution(k: usize) -> Vec<f64> {
        if k == 0 {
            return vec![1.0];
        }
        let mut dist = vec![0.0; k + 1];
        let c = 0.03; // Failure probability parameter
        let delta = 0.5; // Overhead parameter
        let s = c * (k as f64).ln() * (k as f64 / delta).sqrt();

        // Ideal Soliton distribution
        dist[1] = 1.0 / k as f64;
        #[allow(clippy::needless_range_loop)]
        for i in 2..=k {
            dist[i] = 1.0 / (i * (i - 1)) as f64;
        }

        // Robust component
        let robust_limit = if s.is_finite() && s > f64::EPSILON {
            ((k as f64 / s).floor() as usize).clamp(1, k)
        } else {
            k
        };
        #[allow(clippy::needless_range_loop)]
        for i in 1..=robust_limit {
            dist[i] += s / (i * k) as f64;
        }

        // Normalize
        let sum: f64 = dist.iter().sum();
        for d in &mut dist {
            *d /= sum;
        }

        // Convert to cumulative distribution
        for i in 1..dist.len() {
            dist[i] += dist[i - 1];
        }

        dist
    }

    /// **Generate encoded symbol** and return indices for BP decoding
    pub fn generate_symbol_with_indices(&mut self, symbol_id: u64) -> (Vec<u8>, Vec<usize>) {
        if self.symbols.is_empty() {
            return (vec![0; self.symbol_size], Vec::new());
        }

        let used_indices = self.source_indices(symbol_id);
        let encoded_len =
            self.symbols.iter().map(Vec::len).max().unwrap_or(0).min(self.symbol_size);
        let mut encoded = vec![0u8; encoded_len];
        for &index in &used_indices {
            let source = &self.symbols[index];
            let len = source.len().min(encoded.len());
            super::fast_xor_inplace(&source[..len], &mut encoded[..len]);
        }
        (encoded, used_indices)
    }

    fn source_indices(&self, symbol_id: u64) -> Vec<usize> {
        deterministic_source_indices(
            self.symbols.len(),
            &self.degree_dist,
            self.rng_seed,
            symbol_id,
        )
    }

    /// Add a source symbol to the encoder's symbol buffer.
    /// Rejects symbols longer than the configured `symbol_size` or beyond the
    /// configured source count. Shorter symbols are accepted and zero-padded.
    pub fn add_source_symbol(&mut self, symbol: Vec<u8>) -> bool {
        if self.symbols.len() >= self.k() {
            return false;
        }
        if symbol.len() > self.symbol_size {
            return false;
        }
        self.symbols.push(symbol);
        true
    }

    /// Return the fixed symbol size in bytes.
    #[cfg(test)]
    pub fn symbol_size(&self) -> usize {
        self.symbol_size
    }
    /// Clear all buffered source symbols.
    pub fn clear_window(&mut self) {
        self.symbols.clear();
    }
    /// Return the number of source symbols currently buffered.
    pub fn packets_in_window(&self) -> usize {
        self.symbols.len()
    }
    /// Return the configured number of source symbols (k).
    pub fn k(&self) -> usize {
        self.k
    }

    pub(crate) fn set_seed(&mut self, rng_seed: u64) {
        self.rng_seed = rng_seed;
    }
}

/// **Belief Propagation Decoder** for LT codes
pub struct LTDecoder {
    k: usize,
    symbol_size: usize,
    received_symbols: HashMap<u64, Vec<u8>>,
    decoded_symbols: Vec<Option<Vec<u8>>>,
    symbol_degrees: HashMap<u64, HashSet<usize>>,
    degree_one_queue: VecDeque<u64>,
    queued_symbol_ids: HashSet<u64>,
    symbol_order: VecDeque<u64>,
    max_symbols: usize,
    max_payload_bytes: usize,
    max_queue_len: usize,
    max_propagation_work: usize,
    retained_payload_bytes: usize,
    propagation_work: usize,
    propagation_budget_exhausted: bool,
    degree_dist: Vec<f64>,
    rng_seed: u64,
    pub(crate) mem_pool: Arc<MemoryPool>,
}

impl LTDecoder {
    /// Return the fixed symbol size in bytes.
    #[inline]
    #[cfg(test)]
    pub fn symbol_size(&self) -> usize {
        self.symbol_size
    }
    /// Create a new LT decoder expecting `k` source symbols.
    pub fn new(k: usize, symbol_size: usize, mem_pool: Arc<MemoryPool>) -> Self {
        Self::new_with_seed(k, symbol_size, mem_pool, DEFAULT_FOUNTAIN_SEED)
    }

    /// Create an LT decoder with an explicit connection-local PRNG seed.
    pub fn new_with_seed(
        k: usize,
        symbol_size: usize,
        mem_pool: Arc<MemoryPool>,
        rng_seed: u64,
    ) -> Self {
        let max_symbols = k.saturating_mul(5).saturating_add(4);
        Self::new_with_repair_limit(k, symbol_size, mem_pool, rng_seed, max_symbols)
    }

    /// Create a decoder with a per-window repair admission limit.
    pub(crate) fn new_with_repair_limit(
        k: usize,
        symbol_size: usize,
        mem_pool: Arc<MemoryPool>,
        rng_seed: u64,
        requested_max_symbols: usize,
    ) -> Self {
        let k = k.clamp(1, MAX_FOUNTAIN_SOURCE_SYMBOLS);
        let symbol_size =
            symbol_size.clamp(1, mem_pool.block_size().min(MAX_FOUNTAIN_PAYLOAD_BYTES));
        let max_symbols = requested_max_symbols.clamp(1, super::wire::MAX_TOTAL_COUNT as usize);
        let max_payload_bytes =
            max_symbols.saturating_mul(symbol_size).clamp(1, MAX_FOUNTAIN_PAYLOAD_BYTES);
        let max_propagation_work = max_symbols.saturating_mul(k);
        Self {
            k,
            symbol_size,
            received_symbols: HashMap::new(),
            decoded_symbols: vec![None; k],
            symbol_degrees: HashMap::new(),
            degree_one_queue: VecDeque::new(),
            queued_symbol_ids: HashSet::new(),
            symbol_order: VecDeque::new(),
            max_symbols,
            max_payload_bytes,
            max_queue_len: max_symbols,
            max_propagation_work,
            retained_payload_bytes: 0,
            propagation_work: 0,
            propagation_budget_exhausted: false,
            degree_dist: LTEncoder::robust_soliton_distribution(k),
            rng_seed,
            mem_pool,
        }
    }

    fn reject_symbol(&self, reason: &str) -> bool {
        crate::telemetry::FEC_FOUNTAIN_DECODER_ADMISSION_REJECTIONS.inc();
        log::debug!("Fountain decoder rejected symbol: {reason}");
        false
    }

    fn remove_queued_symbol(&mut self, symbol_id: u64) {
        if self.queued_symbol_ids.remove(&symbol_id) {
            self.degree_one_queue.retain(|queued_id| *queued_id != symbol_id);
        }
    }

    fn remove_symbol_state(&mut self, symbol_id: u64) {
        if let Some(data) = self.received_symbols.remove(&symbol_id) {
            self.retained_payload_bytes = self.retained_payload_bytes.saturating_sub(data.len());
        }
        self.symbol_degrees.remove(&symbol_id);
        self.symbol_order.retain(|queued_id| *queued_id != symbol_id);
        self.remove_queued_symbol(symbol_id);
    }

    fn evict_oldest_symbol(&mut self) -> bool {
        while let Some(symbol_id) = self.symbol_order.pop_front() {
            if self.received_symbols.contains_key(&symbol_id) {
                self.remove_symbol_state(symbol_id);
                crate::telemetry::FEC_FOUNTAIN_DECODER_EVICTIONS.inc();
                log::debug!(
                    "Fountain decoder evicted symbol id={symbol_id} retained_symbols={} retained_payload_bytes={}",
                    self.received_symbols.len(),
                    self.retained_payload_bytes
                );
                return true;
            }
        }
        false
    }

    fn make_room_for_symbol(&mut self, data_len: usize) -> bool {
        if data_len > self.symbol_size || data_len > self.max_payload_bytes {
            return self.reject_symbol("payload exceeds configured symbol or byte limit");
        }
        while self.received_symbols.len() >= self.max_symbols
            || self.retained_payload_bytes.saturating_add(data_len) > self.max_payload_bytes
        {
            if !self.evict_oldest_symbol() {
                return self.reject_symbol("decoder state limit cannot be satisfied");
            }
        }
        true
    }

    fn insert_symbol(&mut self, symbol_id: u64, data: Vec<u8>) -> bool {
        if self.received_symbols.contains_key(&symbol_id) {
            return self.reject_symbol("duplicate symbol id");
        }
        if !self.make_room_for_symbol(data.len()) {
            return false;
        }
        self.retained_payload_bytes = self.retained_payload_bytes.saturating_add(data.len());
        self.symbol_order.push_back(symbol_id);
        self.received_symbols.insert(symbol_id, data);
        true
    }

    fn enqueue_degree_one(&mut self, symbol_id: u64) -> bool {
        if !self.queued_symbol_ids.insert(symbol_id) {
            return true;
        }
        if self.degree_one_queue.len() >= self.max_queue_len {
            self.queued_symbol_ids.remove(&symbol_id);
            crate::telemetry::FEC_FOUNTAIN_DECODER_ADMISSION_REJECTIONS.inc();
            log::debug!("Fountain decoder dropped degree-one queue entry id={symbol_id}");
            return false;
        }
        self.degree_one_queue.push_back(symbol_id);
        true
    }

    pub fn add_source_symbol(&mut self, source_index: usize, data: Vec<u8>) -> bool {
        if source_index >= self.k || data.len() > self.symbol_size {
            return self.reject_symbol("invalid source index or oversized source data");
        }
        if self.decoded_symbols[source_index].is_some() {
            return self.reject_symbol("duplicate source index");
        }
        self.decoded_symbols[source_index] = Some(data.clone());
        let _ = self.propagate_decoded_symbol(source_index, &data);
        true
    }

    pub fn source_indices(&self, symbol_id: u64) -> HashSet<usize> {
        deterministic_source_indices(self.k, &self.degree_dist, self.rng_seed, symbol_id)
            .into_iter()
            .collect()
    }

    pub(crate) fn set_seed(&mut self, rng_seed: u64) {
        self.rng_seed = rng_seed;
    }

    /// Add received symbol for decoding (no degree info available)
    #[cfg(test)]
    pub fn add_received_symbol(&mut self, symbol_id: u64, data: Vec<u8>) {
        let _ = self.insert_symbol(symbol_id, data);
        // Without source index set we cannot peel immediately. We rely on
        // additional encoded symbols with indices to trigger peeling.
    }

    /// **Belief Propagation Decoding** - Iterative peeling decoder
    pub fn add_encoded_symbol(
        &mut self,
        symbol_id: u64,
        data: Vec<u8>,
        source_indices: HashSet<usize>,
    ) -> bool {
        if data.len() > self.symbol_size {
            return self.reject_symbol("encoded data exceeds configured symbol size");
        }
        if source_indices.is_empty()
            || source_indices.len() > self.k
            || source_indices.iter().any(|&index| index >= self.k)
        {
            return self.reject_symbol("invalid source-index set");
        }
        if !self.insert_symbol(symbol_id, data) {
            return false;
        }
        self.symbol_degrees.insert(symbol_id, source_indices.clone());

        if source_indices.len() == 1 {
            let _ = self.enqueue_degree_one(symbol_id);
        }

        self.belief_propagation_step()
    }

    /// Execute one round of belief propagation peeling, returning true if progress was made.
    pub fn belief_propagation_step(&mut self) -> bool {
        let mut progressed = false;
        while let Some(symbol_id) = self.degree_one_queue.pop_back() {
            self.queued_symbol_ids.remove(&symbol_id);
            if let Some(indices) = self.symbol_degrees.get(&symbol_id).cloned() {
                if indices.len() == 1 {
                    let Some(&source_idx) = indices.iter().next() else {
                        continue;
                    };
                    if self.decoded_symbols[source_idx].is_none() {
                        if let Some(encoded_data) = self.received_symbols.get(&symbol_id) {
                            let decoded = encoded_data.clone();
                            self.decoded_symbols[source_idx] = Some(decoded.clone());
                            // Update all other encoded symbols
                            let propagation_complete =
                                self.propagate_decoded_symbol(source_idx, &decoded);
                            progressed = true;
                            if !propagation_complete {
                                break;
                            }
                        }
                    }
                }
            }
        }
        progressed
    }

    /// Run belief propagation to completion, returning true if all symbols decoded.
    pub fn belief_propagation_decode(&mut self) -> bool {
        // Iterate peeling until no further progress is possible
        while self.belief_propagation_step() {}
        // Return whether all source symbols have been decoded
        self.decoded_symbols.iter().all(|s| s.is_some())
    }

    /// Return all successfully decoded source symbols (partial results).
    #[cfg(test)]
    pub fn get_partial(&mut self) -> Vec<Vec<u8>> {
        // Touch symbol_size to ensure compiler understands it is used
        let _sz = self.symbol_size();
        self.decoded_symbols.iter().filter_map(|s| s.clone()).collect()
    }

    pub fn get_partial_indexed(&self) -> Vec<(usize, Vec<u8>)> {
        self.decoded_symbols
            .iter()
            .enumerate()
            .filter_map(|(index, symbol)| symbol.clone().map(|data| (index, data)))
            .collect()
    }

    // Removed is_complete; use decoding_progress() or get_decoded_symbols()

    /// XOR a decoded symbol out of all dependent encoded symbols and enqueue new degree-1 entries.
    ///
    /// The returned flag is false only when the per-window propagation budget was exhausted.
    pub fn propagate_decoded_symbol(&mut self, decoded_idx: usize, decoded_data: &[u8]) -> bool {
        if decoded_idx >= self.k || decoded_data.len() > self.symbol_size {
            return self.reject_symbol("invalid decoded symbol index or length");
        }
        let mut to_update = Vec::new();

        for (&symbol_id, indices) in &self.symbol_degrees {
            if self.propagation_work >= self.max_propagation_work {
                self.propagation_budget_exhausted = true;
                break;
            }
            self.propagation_work = self.propagation_work.saturating_add(1);
            crate::telemetry::FEC_FOUNTAIN_DECODER_PROPAGATION_WORK.inc();
            if indices.contains(&decoded_idx) {
                to_update.push(symbol_id);
            }
        }

        for symbol_id in to_update {
            // Remove decoded symbol from this encoded symbol (SIMD-accelerated XOR)
            if let Some(encoded_data) = self.received_symbols.get_mut(&symbol_id) {
                let sl = core::cmp::min(encoded_data.len(), decoded_data.len());
                super::fast_xor_inplace(&decoded_data[..sl], &mut encoded_data[..sl]);
            }

            let (became_empty, became_degree_one) =
                if let Some(indices) = self.symbol_degrees.get_mut(&symbol_id) {
                    indices.remove(&decoded_idx);
                    (indices.is_empty(), indices.len() == 1)
                } else {
                    (false, false)
                };

            if became_empty {
                self.remove_symbol_state(symbol_id);
            } else if became_degree_one {
                let _ = self.enqueue_degree_one(symbol_id);
            }
        }
        !self.propagation_budget_exhausted
    }

    /// Return all decoded source symbols if decoding is complete, None otherwise.
    pub fn get_decoded_symbols(&self) -> Option<Vec<Vec<u8>>> {
        let mut out = Vec::with_capacity(self.decoded_symbols.len());
        for symbol in &self.decoded_symbols {
            let data = symbol.as_ref()?;
            out.push(data.clone());
        }
        Some(out)
    }

    pub fn get_decoded_indexed(&self) -> Option<Vec<(usize, Vec<u8>)>> {
        let symbols = self.get_decoded_symbols()?;
        Some(symbols.into_iter().enumerate().collect())
    }

    /// Return fraction of source symbols decoded (0.0 to 1.0).
    pub fn decoding_progress(&self) -> f32 {
        if self.k == 0 {
            return 1.0;
        }
        let decoded_count = self.decoded_symbols.iter().filter(|s| s.is_some()).count();
        decoded_count as f32 / self.k as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pool() -> Arc<MemoryPool> {
        crate::optimize::global_pool()
    }

    // ---------------------------------------------------------------
    // LTEncoder - basic construction and properties
    // ---------------------------------------------------------------

    #[test]
    fn encoder_new_sets_params() {
        let enc = LTEncoder::new(10, 64);
        assert_eq!(enc.k(), 10);
        assert_eq!(enc.symbol_size(), 64);
        assert_eq!(enc.packets_in_window(), 0);
    }

    #[test]
    fn encoder_add_source_symbols() {
        let mut enc = LTEncoder::new(4, 8);
        for i in 0..4 {
            enc.add_source_symbol(vec![i; 8]);
        }
        assert_eq!(enc.packets_in_window(), 4);
    }

    #[test]
    fn encoder_rejects_overflow() {
        let mut enc = LTEncoder::new(2, 4);
        enc.add_source_symbol(vec![0xAA; 4]);
        enc.add_source_symbol(vec![0xBB; 4]);
        enc.add_source_symbol(vec![0xCC; 4]); // beyond k - should be ignored
        assert_eq!(enc.packets_in_window(), 2);
    }

    #[test]
    fn encoder_clear_window() {
        let mut enc = LTEncoder::new(4, 8);
        for i in 0..4 {
            enc.add_source_symbol(vec![i; 8]);
        }
        enc.clear_window();
        assert_eq!(enc.packets_in_window(), 0);
    }

    #[test]
    fn encoder_empty_produces_zero_symbol() {
        let mut enc = LTEncoder::new(4, 16);
        // No source symbols added
        let (data, indices) = enc.generate_symbol_with_indices(1);
        assert_eq!(data, vec![0; 16], "empty encoder must produce zero-filled symbol");
        assert!(indices.is_empty(), "empty encoder must have no source indices");
    }

    #[test]
    fn encoder_deterministic_output() {
        let mut enc = LTEncoder::new(4, 8);
        for i in 0u8..4 {
            enc.add_source_symbol(vec![i * 10; 8]);
        }
        let (d1, i1) = enc.generate_symbol_with_indices(42);
        // Rebuild encoder identically
        let mut enc2 = LTEncoder::new(4, 8);
        for i in 0u8..4 {
            enc2.add_source_symbol(vec![i * 10; 8]);
        }
        let (d2, i2) = enc2.generate_symbol_with_indices(42);
        assert_eq!(d1, d2, "same seed+id must produce identical encoded symbol");
        assert_eq!(i1, i2, "same seed+id must produce identical indices");
    }

    #[test]
    fn seeded_encoder_and_decoder_share_symbol_sets() {
        let seed = 0x6f31_2a8d_95c4_e107;
        let mut encoder = LTEncoder::new_with_seed(12, 32, seed);
        let decoder = LTDecoder::new_with_seed(12, 32, make_pool(), seed);
        for value in 0u8..12 {
            encoder.add_source_symbol(vec![value; 32]);
        }

        let (_, encoder_indices) = encoder.generate_symbol_with_indices(77);
        let encoder_indices = encoder_indices.into_iter().collect::<HashSet<_>>();
        assert_eq!(encoder_indices, decoder.source_indices(77));
    }

    #[test]
    fn different_connection_seeds_change_symbol_sets() {
        let mut first = LTEncoder::new_with_seed(12, 32, 1);
        let mut second = LTEncoder::new_with_seed(12, 32, 2);
        for value in 0u8..12 {
            let symbol = vec![value; 32];
            first.add_source_symbol(symbol.clone());
            second.add_source_symbol(symbol);
        }

        let (_, first_indices) = first.generate_symbol_with_indices(77);
        let (_, second_indices) = second.generate_symbol_with_indices(77);
        assert_ne!(first_indices, second_indices);
    }

    #[test]
    fn encoder_different_ids_produce_different_symbols() {
        let mut enc = LTEncoder::new(4, 16);
        for i in 0u8..4 {
            enc.add_source_symbol(vec![i.wrapping_mul(17); 16]);
        }
        let (d1, _) = enc.generate_symbol_with_indices(1);
        let (d2, _) = enc.generate_symbol_with_indices(2);
        // Extremely unlikely (but not impossible) for two different ids to collide
        // on the same encoded output - we check they differ
        assert_ne!(d1, d2, "different symbol_ids should generally produce different output");
    }

    #[test]
    fn encoded_symbol_has_correct_size() {
        let mut enc = LTEncoder::new(3, 32);
        for i in 0u8..3 {
            enc.add_source_symbol(vec![i; 32]);
        }
        let (data, _) = enc.generate_symbol_with_indices(100);
        assert_eq!(data.len(), 32, "encoded symbol must match configured symbol_size");
    }

    // ---------------------------------------------------------------
    // LTDecoder - basic construction
    // ---------------------------------------------------------------

    #[test]
    fn decoder_new_starts_empty() {
        let pool = make_pool();
        let dec = LTDecoder::new(4, 8, pool);
        assert_eq!(dec.symbol_size(), 8);
        assert_eq!(dec.decoding_progress(), 0.0);
        assert!(dec.get_decoded_symbols().is_none());
    }

    // ---------------------------------------------------------------
    // Full roundtrip: encode then decode via belief propagation
    // ---------------------------------------------------------------

    #[test]
    fn roundtrip_single_symbol() {
        let symbol_size = 16;
        let k = 1;
        let original = vec![0xABu8; symbol_size];

        let mut enc = LTEncoder::new(k, symbol_size);
        enc.add_source_symbol(original.clone());

        let pool = make_pool();
        let mut dec = LTDecoder::new(k, symbol_size, pool);

        // For k=1 every encoded symbol has degree 1 pointing at index 0
        let (data, indices) = enc.generate_symbol_with_indices(1);
        let index_set: HashSet<usize> = indices.into_iter().collect();
        dec.add_encoded_symbol(1, data, index_set);

        let decoded = dec.get_decoded_symbols();
        assert!(decoded.is_some(), "single symbol must decode immediately");
        assert_eq!(decoded.as_ref().map(|v| v.len()), Some(1));
        assert_eq!(decoded.as_ref().map(|v| &v[0]), Some(&original));
    }

    #[test]
    fn roundtrip_encoder_generates_valid_xor_combinations() {
        // Verify that the encoder's XOR combination of source symbols is
        // mathematically correct: for each generated symbol, manually XOR
        // the same source indices and compare.
        let k = 5;
        let symbol_size = 32;

        let originals: Vec<Vec<u8>> = (0..k)
            .map(|i| (0..symbol_size).map(|j| ((i * 37 + j) & 0xFF) as u8).collect())
            .collect();

        let mut enc = LTEncoder::new(k, symbol_size);
        for sym in &originals {
            enc.add_source_symbol(sym.clone());
        }

        for sym_id in 1..=20u64 {
            let (encoded, indices) = enc.generate_symbol_with_indices(sym_id);
            // Manually compute XOR of the selected source symbols
            let mut expected = vec![0u8; symbol_size];
            for &idx in &indices {
                for j in 0..symbol_size {
                    expected[j] ^= originals[idx][j];
                }
            }
            assert_eq!(
                encoded, expected,
                "encoded symbol {sym_id} must equal XOR of source symbols at indices {:?}",
                indices
            );
        }
    }

    #[test]
    fn roundtrip_with_manual_degree_one_seeding() {
        // Full encode/decode roundtrip. First provide encoder-generated symbols
        // (which may be high-degree), then seed with degree-1 symbols from the
        // encoder's actual source data to kickstart peeling.
        let k = 5;
        let symbol_size = 32;

        let originals: Vec<Vec<u8>> = (0..k)
            .map(|i| (0..symbol_size).map(|j| ((i * 37 + j) & 0xFF) as u8).collect())
            .collect();

        let mut enc = LTEncoder::new(k, symbol_size);
        for sym in &originals {
            enc.add_source_symbol(sym.clone());
        }

        let pool = make_pool();
        let mut dec = LTDecoder::new(k, symbol_size, pool);

        // Add many encoder-generated symbols (high degree helps once peeling starts)
        for sym_id in 1..=30u64 {
            let (data, indices) = enc.generate_symbol_with_indices(sym_id);
            let idx_set: HashSet<usize> = indices.into_iter().collect();
            dec.add_encoded_symbol(sym_id, data, idx_set);
        }

        // Seed with degree-1 symbols for indices that are not yet decoded
        // (simulates receiving systematic/uncoded packets in a real fountain stream)
        for (next_id, (i, orig)) in (1000u64..).zip(originals.iter().enumerate().take(k)) {
            let mut idx = HashSet::new();
            idx.insert(i);
            dec.add_encoded_symbol(next_id, orig.clone(), idx);
        }

        assert!(
            dec.belief_propagation_decode(),
            "must decode with degree-1 seeds + high-degree encoded symbols"
        );
        let result = dec.get_decoded_symbols().expect("complete");
        for (i, sym) in result.iter().enumerate() {
            assert_eq!(sym, &originals[i], "symbol {i} mismatch after roundtrip");
        }
    }

    #[test]
    fn roundtrip_degree_one_symbols_decode_directly() {
        // If we manually inject k degree-1 symbols, each covering exactly one source,
        // the decoder must recover all immediately.
        let k = 4;
        let symbol_size = 8;
        let originals: Vec<Vec<u8>> =
            (0..k).map(|i| vec![(i as u8 + 1) * 11; symbol_size]).collect();

        let pool = make_pool();
        let mut dec = LTDecoder::new(k, symbol_size, pool);

        for (i, orig) in originals.iter().enumerate().take(k) {
            let mut indices = HashSet::new();
            indices.insert(i);
            // Degree-1 symbol: data is just the source symbol itself
            dec.add_encoded_symbol(i as u64, orig.clone(), indices);
        }

        assert!(dec.belief_propagation_decode(), "k degree-1 symbols must fully decode");
        let result = dec.get_decoded_symbols().expect("complete decode");
        for (i, sym) in result.iter().enumerate() {
            assert_eq!(sym, &originals[i]);
        }
    }

    // ---------------------------------------------------------------
    // Belief propagation peeling
    // ---------------------------------------------------------------

    #[test]
    fn peeling_xor_recovers_missing_symbol() {
        // 2 source symbols: A, B.
        // Provide A XOR B (degree-2) first, then A (degree-1).
        // When A is decoded, propagation XORs A out of A^B, reducing it to
        // degree-1 pointing at B, which the peeling loop then resolves.
        let k = 2;
        let sz = 8;
        let a = vec![0x11u8; sz];
        let b = vec![0x22u8; sz];

        let mut a_xor_b = vec![0u8; sz];
        for i in 0..sz {
            a_xor_b[i] = a[i] ^ b[i];
        }

        let pool = make_pool();
        let mut dec = LTDecoder::new(k, sz, pool);

        // First: provide A XOR B as degree-2 (cannot decode yet)
        let mut idx_ab = HashSet::new();
        idx_ab.insert(0);
        idx_ab.insert(1);
        dec.add_encoded_symbol(101, a_xor_b, idx_ab);

        // Second: provide A as degree-1 (triggers peeling cascade)
        let mut idx_a = HashSet::new();
        idx_a.insert(0);
        dec.add_encoded_symbol(100, a.clone(), idx_a);

        assert!(dec.belief_propagation_decode(), "peeling must recover B from A and A^B");
        let result = dec.get_decoded_symbols().expect("full decode");
        assert_eq!(&result[0], &a);
        assert_eq!(&result[1], &b);
    }

    // ---------------------------------------------------------------
    // Partial recovery and progress tracking
    // ---------------------------------------------------------------

    #[test]
    fn partial_decode_progress() {
        let k = 4;
        let sz = 8;
        let pool = make_pool();
        let mut dec = LTDecoder::new(k, sz, pool);

        assert_eq!(dec.decoding_progress(), 0.0);

        // Provide only one degree-1 symbol
        let mut idx = HashSet::new();
        idx.insert(2);
        dec.add_encoded_symbol(1, vec![0xBB; sz], idx);

        assert!((dec.decoding_progress() - 0.25).abs() < f32::EPSILON, "1 of 4 decoded = 25%");
        assert!(dec.get_decoded_symbols().is_none(), "incomplete decode must return None");

        let partial = dec.get_partial();
        assert_eq!(partial.len(), 1, "partial should contain 1 decoded symbol");
        assert_eq!(partial[0], vec![0xBB; sz]);
    }

    #[test]
    fn add_received_symbol_without_indices() {
        let k = 2;
        let sz = 4;
        let pool = make_pool();
        let mut dec = LTDecoder::new(k, sz, pool);

        // add_received_symbol does not provide index info - no peeling possible
        dec.add_received_symbol(1, vec![0xFF; sz]);
        assert_eq!(
            dec.decoding_progress(),
            0.0,
            "received symbol without indices cannot trigger decode"
        );
    }

    #[test]
    fn decoder_bounds_unique_repair_symbol_flood() {
        let pool = make_pool();
        let mut dec = LTDecoder::new(4, 8, pool);
        let indices = HashSet::from([0usize, 1usize]);

        for symbol_id in 0..100_000u64 {
            let _ = dec.add_encoded_symbol(symbol_id, vec![symbol_id as u8; 8], indices.clone());
        }

        assert!(dec.received_symbols.len() <= dec.max_symbols);
        assert!(dec.symbol_degrees.len() <= dec.max_symbols);
        assert!(dec.symbol_order.len() <= dec.max_symbols);
        assert!(dec.degree_one_queue.len() <= dec.max_queue_len);
        assert!(dec.retained_payload_bytes <= dec.max_payload_bytes);
        assert!(dec.propagation_work <= dec.max_propagation_work);
        assert!(!dec.received_symbols.contains_key(&0));
        assert!(dec.received_symbols.contains_key(&99_999));
    }

    #[test]
    fn decoder_rejects_invalid_indices_and_oversized_payloads() {
        let pool = make_pool();
        let mut dec = LTDecoder::new(2, 8, pool);

        assert!(!dec.add_encoded_symbol(1, vec![0; 8], HashSet::new()));
        assert!(!dec.add_encoded_symbol(2, vec![0; 8], HashSet::from([2usize])));
        assert!(!dec.add_encoded_symbol(3, vec![0; 9], HashSet::from([0usize])));
        assert!(dec.received_symbols.is_empty());
        assert!(dec.symbol_degrees.is_empty());
        assert_eq!(dec.retained_payload_bytes, 0);
    }

    #[test]
    fn encoder_rejects_long_source_symbols() {
        let mut enc = LTEncoder::new(4, 8);
        assert!(!enc.add_source_symbol(vec![0; 9]));
        assert_eq!(enc.packets_in_window(), 0);
    }

    #[test]
    fn encoder_accepts_short_source_symbols_and_bounds_output_to_max_source_len() {
        let mut enc = LTEncoder::new(4, 8);
        assert!(enc.add_source_symbol(vec![0xAB; 4]));
        let (data, _) = enc.generate_symbol_with_indices(1);
        // Output length tracks the longest buffered source, bounded by symbol_size.
        assert_eq!(data.len(), 4);
        assert_eq!(&data[..4], &[0xAB; 4]);
    }

    #[test]
    fn decoder_rejects_oversized_source_symbol() {
        let pool = make_pool();
        let mut dec = LTDecoder::new(2, 4, pool);
        assert!(!dec.add_source_symbol(0, vec![0; 5]));
        assert!(dec.decoded_symbols[0].is_none());
    }

    #[test]
    fn decoder_rejects_duplicate_source_index() {
        let pool = make_pool();
        let mut dec = LTDecoder::new(2, 4, pool);
        assert!(dec.add_source_symbol(0, vec![0x11; 4]));
        assert!(!dec.add_source_symbol(0, vec![0x22; 4]));
        assert_eq!(dec.decoded_symbols[0].as_ref().unwrap(), &vec![0x11; 4]);
    }

    #[test]
    fn encoder_constructor_clamps_zero_dimensions() {
        let enc = LTEncoder::new(0, 0);
        assert_eq!(enc.k(), 1);
        assert_eq!(enc.symbol_size(), 1);
    }

    #[test]
    fn decoder_constructor_clamps_zero_dimensions() {
        let pool = make_pool();
        let dec = LTDecoder::new(0, 0, pool);
        assert_eq!(dec.k, 1);
        assert_eq!(dec.symbol_size, 1);
        assert_eq!(dec.decoding_progress(), 0.0);
    }

    #[test]
    fn decoder_clamps_zero_repair_limit() {
        let pool = make_pool();
        let dec = LTDecoder::new_with_repair_limit(4, 8, pool, 0, 0);
        assert_eq!(dec.max_symbols, 1);
        assert_eq!(dec.max_queue_len, 1);
    }

    // ---------------------------------------------------------------
    // Robust Soliton Distribution sanity
    // ---------------------------------------------------------------

    #[test]
    fn soliton_distribution_is_valid_cdf() {
        for k in [1, 2, 5, 10, 50, 100] {
            let dist = LTEncoder::robust_soliton_distribution(k);
            // Must be non-decreasing (CDF property)
            for i in 1..dist.len() {
                assert!(dist[i] >= dist[i - 1], "CDF must be non-decreasing at k={k}, i={i}");
            }
            // Last element must be ~1.0 (within floating point tolerance)
            let last = dist[dist.len() - 1];
            assert!((last - 1.0).abs() < 1e-10, "CDF must reach 1.0 at k={k}, got {last}");
        }
    }

    #[test]
    fn soliton_distribution_k_zero() {
        let dist = LTEncoder::robust_soliton_distribution(0);
        assert_eq!(dist, vec![1.0], "k=0 must return [1.0]");
    }

    // ---------------------------------------------------------------
    // Edge: k=1 encoder/decoder
    // ---------------------------------------------------------------

    #[test]
    fn k_one_roundtrip() {
        let sz = 64;
        let data = (0..sz).map(|i| (i * 3) as u8).collect::<Vec<_>>();

        let mut enc = LTEncoder::new(1, sz);
        enc.add_source_symbol(data.clone());

        let pool = make_pool();
        let mut dec = LTDecoder::new(1, sz, pool);

        let (encoded, indices) = enc.generate_symbol_with_indices(1);
        let idx_set: HashSet<usize> = indices.into_iter().collect();
        dec.add_encoded_symbol(1, encoded, idx_set);

        let result = dec.get_decoded_symbols().expect("k=1 must decode with 1 symbol");
        assert_eq!(result[0], data);
        assert_eq!(dec.decoding_progress(), 1.0);
    }

    // ---------------------------------------------------------------
    // Encoder generates non-trivial indices
    // ---------------------------------------------------------------

    #[test]
    fn generated_indices_reference_valid_source_symbols() {
        let k = 8;
        let sz = 16;
        let mut enc = LTEncoder::new(k, sz);
        for i in 0..k as u8 {
            enc.add_source_symbol(vec![i; sz]);
        }

        for sym_id in 1..=20u64 {
            let (_, indices) = enc.generate_symbol_with_indices(sym_id);
            for &idx in &indices {
                assert!(idx < k, "index {idx} out of bounds for k={k} at sym_id={sym_id}");
            }
            // Indices should be unique (HashSet was used during generation)
            let unique: HashSet<usize> = indices.iter().copied().collect();
            assert_eq!(unique.len(), indices.len(), "indices must be unique for sym_id={sym_id}");
        }
    }

    // ---------------------------------------------------------------
    // Larger roundtrip stress test
    // ---------------------------------------------------------------

    #[test]
    fn roundtrip_k10_peeling_cascade() {
        // k=10 roundtrip: provide encoded symbols from the encoder, then
        // seed degree-1 entries for a subset of indices. The peeling cascade
        // should recover remaining symbols from the high-degree encoded pool.
        let k = 10;
        let sz = 64;
        let originals: Vec<Vec<u8>> =
            (0..k).map(|i| (0..sz).map(|j| ((i * 13 + j * 7) & 0xFF) as u8).collect()).collect();

        let mut enc = LTEncoder::new(k, sz);
        for sym in &originals {
            enc.add_source_symbol(sym.clone());
        }

        let pool = make_pool();
        let mut dec = LTDecoder::new(k, sz, pool);

        // Add many encoded symbols to build a rich dependency graph
        for sym_id in 1..=50u64 {
            let (data, indices) = enc.generate_symbol_with_indices(sym_id);
            let idx_set: HashSet<usize> = indices.into_iter().collect();
            dec.add_encoded_symbol(sym_id, data, idx_set);
        }

        // Seed degree-1 for all source symbols to trigger full cascade
        for (i, orig) in originals.iter().enumerate().take(k) {
            let mut idx = HashSet::new();
            idx.insert(i);
            dec.add_encoded_symbol(1000 + i as u64, orig.clone(), idx);
        }

        assert!(dec.belief_propagation_decode(), "k=10 must decode with degree-1 seeds");
        let result = dec.get_decoded_symbols().expect("complete");
        for (i, sym) in result.iter().enumerate() {
            assert_eq!(sym, &originals[i], "symbol {i} mismatch");
        }
    }
}
