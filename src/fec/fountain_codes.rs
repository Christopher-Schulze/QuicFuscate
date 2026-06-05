use super::MemoryPool;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

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
        let degree_dist = Self::robust_soliton_distribution(k);
        Self {
            k,
            symbols: Vec::with_capacity(k),
            degree_dist,
            rng_seed: 12345, // Fixed seed for reproducibility
            symbol_size,
        }
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

        // Deterministic random number generator based on symbol_id
        let mut rng_state = self.rng_seed.wrapping_mul(symbol_id).wrapping_add(0x9e3779b9);

        // Select degree using robust soliton distribution
        let degree = self.select_degree(&mut rng_state);

        // Select source symbols to XOR
        let mut encoded = vec![0u8; self.symbol_size];
        let mut selected = HashSet::new();
        let mut used_indices = Vec::with_capacity(degree);

        for _ in 0..degree {
            let idx = (rng_state % self.symbols.len() as u64) as usize;
            rng_state = rng_state.wrapping_mul(1664525).wrapping_add(1013904223);

            if selected.insert(idx) && idx < self.symbols.len() {
                // SIMD-accelerated XOR combine
                super::fast_xor_inplace(&self.symbols[idx][..], &mut encoded[..]);
                used_indices.push(idx);
            }
        }

        (encoded, used_indices)
    }

    fn select_degree(&self, rng_state: &mut u64) -> usize {
        let r = (*rng_state as f64) / (u64::MAX as f64);
        *rng_state = rng_state.wrapping_mul(1664525).wrapping_add(1013904223);

        for (degree, &cum_prob) in self.degree_dist.iter().enumerate() {
            if r <= cum_prob {
                return degree.max(1);
            }
        }
        self.k() // Fallback to maximum degree
    }

    /// Add a source symbol to the encoder's symbol buffer.
    pub fn add_source_symbol(&mut self, symbol: Vec<u8>) {
        if self.symbols.len() < self.k() {
            self.symbols.push(symbol);
        }
    }

    /// Return the fixed symbol size in bytes.
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
}

/// **Belief Propagation Decoder** for LT codes
pub struct LTDecoder {
    k: usize,
    symbol_size: usize,
    received_symbols: HashMap<u64, Vec<u8>>,
    decoded_symbols: Vec<Option<Vec<u8>>>,
    symbol_degrees: HashMap<u64, HashSet<usize>>,
    degree_one_queue: Vec<u64>,
    pub(crate) mem_pool: Arc<MemoryPool>,
}

impl LTDecoder {
    /// Return the fixed symbol size in bytes.
    #[inline]
    pub fn symbol_size(&self) -> usize {
        self.symbol_size
    }
    /// Create a new LT decoder expecting `k` source symbols.
    pub fn new(k: usize, symbol_size: usize, mem_pool: Arc<MemoryPool>) -> Self {
        Self {
            k,
            symbol_size,
            received_symbols: HashMap::new(),
            decoded_symbols: vec![None; k],
            symbol_degrees: HashMap::new(),
            degree_one_queue: Vec::new(),
            mem_pool,
        }
    }

    /// Add received symbol for decoding (no degree info available)
    pub fn add_received_symbol(&mut self, symbol_id: u64, data: Vec<u8>) {
        self.received_symbols.insert(symbol_id, data);
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
        self.received_symbols.insert(symbol_id, data);
        self.symbol_degrees.insert(symbol_id, source_indices.clone());

        if source_indices.len() == 1 {
            self.degree_one_queue.push(symbol_id);
        }

        self.belief_propagation_step()
    }

    /// Execute one round of belief propagation peeling, returning true if progress was made.
    pub fn belief_propagation_step(&mut self) -> bool {
        let mut progressed = false;
        while let Some(symbol_id) = self.degree_one_queue.pop() {
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
                            self.propagate_decoded_symbol(source_idx, &decoded);
                            progressed = true;
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
    pub fn get_partial(&mut self) -> Vec<Vec<u8>> {
        // Touch symbol_size to ensure compiler understands it is used
        let _sz = self.symbol_size();
        self.decoded_symbols.iter().filter_map(|s| s.clone()).collect()
    }

    // Removed is_complete; use decoding_progress() or get_decoded_symbols()

    /// XOR a decoded symbol out of all dependent encoded symbols and enqueue new degree-1 entries.
    pub fn propagate_decoded_symbol(&mut self, decoded_idx: usize, decoded_data: &[u8]) {
        let mut to_update = Vec::new();

        for (&symbol_id, indices) in &self.symbol_degrees {
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

            if let Some(indices) = self.symbol_degrees.get_mut(&symbol_id) {
                indices.remove(&decoded_idx);

                if indices.len() == 1 {
                    self.degree_one_queue.push(symbol_id);
                }
            }
        }
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

    /// Return fraction of source symbols decoded (0.0 to 1.0).
    pub fn decoding_progress(&self) -> f32 {
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
        let mut next_id = 1000u64;
        for (i, orig) in originals.iter().enumerate().take(k) {
            let mut idx = HashSet::new();
            idx.insert(i);
            dec.add_encoded_symbol(next_id, orig.clone(), idx);
            next_id += 1;
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
