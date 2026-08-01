use super::*;

/// **Adaptive Reed-Solomon Encoder** with dynamic parameter selection
pub struct AdaptiveRSEncoder {
    base_k: usize,
    base_n: usize,
    current_k: usize,
    current_n: usize,
    loss_history: VecDeque<f32>,
    gf_size: usize, // Galois field size (256 for GF(2^8), 65536 for GF(2^16))
    primitive_poly: u32,
}

impl AdaptiveRSEncoder {
    /// Create an adaptive RS encoder with initial block parameters (k, n).
    pub fn new(base_k: usize, base_n: usize) -> Self {
        Self {
            base_k,
            base_n,
            current_k: base_k,
            current_n: base_n,
            loss_history: VecDeque::with_capacity(100),
            gf_size: 256,          // Start with GF(2^8)
            primitive_poly: 0x11D, // x^8 + x^4 + x^3 + x^2 + 1
        }
    }

    /// **Dynamic Parameter Adaptation** based on network conditions
    pub fn adapt_parameters(&mut self, current_loss: f32, latency_ms: f32, bandwidth_mbps: f32) {
        self.loss_history.push_back(current_loss);
        if self.loss_history.len() > 100 {
            self.loss_history.pop_front();
        }

        let len = self.loss_history.len();
        let (left, right) = self.loss_history.as_slices();
        let sum_loss = accelerate::iter::sum_f32(left) + accelerate::iter::sum_f32(right);
        let avg_loss: f32 = if len > 0 { sum_loss / len as f32 } else { 0.0 };
        let loss_variance = self.calculate_loss_variance(avg_loss);

        // **Adaptive Strategy Selection**
        if avg_loss > 0.3 || loss_variance > 0.1 {
            // High/variable loss: Increase redundancy, consider larger GF
            self.current_n = (self.base_n as f32 * (1.0 + avg_loss * 2.0)) as usize;
            if avg_loss > 0.5 {
                self.gf_size = 65536; // Switch to GF(2^16) for better error correction
                self.primitive_poly = 0x1100B; // x^16 + x^12 + x^3 + x + 1
            }
        } else if avg_loss < 0.05 && latency_ms < 10.0 {
            // Low loss, low latency: Optimize for speed
            self.current_n = self.base_n;
            self.current_k = (self.base_k as f32 * 1.2) as usize; // Larger blocks for efficiency
            self.gf_size = 256; // Stay with GF(2^8) for speed
        } else {
            // Balanced approach
            self.current_k = self.base_k;
            self.current_n = (self.base_n as f32 * (1.0 + avg_loss)) as usize;
        }

        // Bandwidth-aware adaptation
        if bandwidth_mbps < 10.0 {
            // Low bandwidth: Minimize overhead
            let max_overhead = 0.2; // 20% max overhead
            let max_n = (self.current_k as f32 / (1.0 - max_overhead)) as usize;
            self.current_n = self.current_n.min(max_n);
        }

        // Ensure valid parameters
        self.current_k = self.current_k.min(self.gf_size - 1);
        self.current_n = self.current_n.min(self.gf_size - 1).max(self.current_k + 1);
    }

    fn calculate_loss_variance(&self, avg_loss: f32) -> f32 {
        if self.loss_history.len() < 2 {
            return 0.0;
        }

        let len = self.loss_history.len();
        let (left, right) = self.loss_history.as_slices();
        let mut diffs = Vec::with_capacity(len);
        diffs.extend(left.iter().map(|&loss| (loss - avg_loss).powi(2)));
        diffs.extend(right.iter().map(|&loss| (loss - avg_loss).powi(2)));

        let sum_sq = accelerate::iter::sum_f32(&diffs);
        sum_sq / (len - 1) as f32
    }

    // Removed encode/parity helper (not used in the production path).

    /// Return the current (k, n, gf_size) parameters after adaptation.
    pub fn current_parameters(&self) -> (usize, usize, usize) {
        (self.current_k, self.current_n, self.gf_size)
    }
}

#[cfg(test)]
mod tests {
    use super::AdaptiveRSEncoder;

    // Convenience: single adapt call, returns (k, n, gf_size).
    fn adapt_once(loss: f32, latency_ms: f32, bandwidth_mbps: f32) -> (usize, usize, usize) {
        let mut enc = AdaptiveRSEncoder::new(10, 14);
        enc.adapt_parameters(loss, latency_ms, bandwidth_mbps);
        enc.current_parameters()
    }

    // ---- Loss threshold switching ----

    #[test]
    fn low_loss_low_latency_selects_larger_k() {
        // avg < 0.05 AND latency < 10 -> LOW branch: k = base_k * 1.2, n = base_n
        let (k, n, gf) = adapt_once(0.01, 5.0, 100.0);
        // base_k=10 -> k = (10 * 1.2) as usize = 12
        assert_eq!(k, 12, "low-loss low-latency path must enlarge k");
        assert_eq!(n, 14, "low-loss low-latency path must keep base n");
        assert_eq!(gf, 256);
    }

    #[test]
    fn moderate_loss_uses_balanced_redundancy() {
        // 0.05 <= avg <= 0.3, any latency -> BALANCED: k = base_k, n = base_n * (1 + avg_loss)
        let (k, n, _gf) = adapt_once(0.15, 50.0, 100.0);
        // n = (14 * 1.15) as usize = 16
        assert_eq!(k, 10, "balanced path must keep base k");
        assert_eq!(n, 16, "balanced path must scale n by (1 + avg_loss)");
    }

    #[test]
    fn high_loss_switches_to_gf16() {
        // avg > 0.5 -> GF(2^16) switch
        let (_, _, gf) = adapt_once(0.6, 50.0, 100.0);
        assert_eq!(gf, 65536, "loss > 0.5 must trigger GF(2^16) switch");
    }

    #[test]
    fn extreme_loss_caps_without_panic() {
        // loss = 1.0 must not panic and must produce valid params (k < n, both < gf_size)
        let (k, n, gf) = adapt_once(1.0, 50.0, 100.0);
        assert!(k < n, "k must be strictly less than n");
        assert!(n < gf, "n must be less than gf_size");
        assert!(k < gf, "k must be less than gf_size");
        assert!(k > 0 && n > 0, "k and n must be positive");
    }

    // ---- Bandwidth-aware clamping ----

    #[test]
    fn low_bandwidth_caps_n() {
        // bandwidth < 10.0 -> n capped to floor(current_k / 0.8) = current_k * 1.25
        // With moderate loss (0.15): current_k = 10, uncapped n = 16
        // max_n = (10 / 0.8) as usize = 12; capped n = min(16, 12) = 12
        let (k, n, _) = adapt_once(0.15, 50.0, 5.0);
        let expected_max_n = (k as f32 / 0.8) as usize;
        assert!(n <= expected_max_n, "low-bandwidth must cap n to {expected_max_n}, got {n}");
    }

    #[test]
    fn high_bandwidth_allows_full_redundancy() {
        // bandwidth >= 10.0 -> no bandwidth cap applied
        let (_, n_low_bw, _) = adapt_once(0.15, 50.0, 5.0);
        let (_, n_high_bw, _) = adapt_once(0.15, 50.0, 100.0);
        assert!(n_high_bw > n_low_bw, "high bandwidth must allow more redundancy than low");
    }

    // ---- Latency-driven adaptation ----

    #[test]
    fn high_latency_prevents_low_loss_path() {
        // Low loss but high latency -> must NOT enter LOW branch (k stays base_k, not base_k*1.2)
        let (k_hi_lat, _, _) = adapt_once(0.01, 200.0, 100.0);
        let (k_lo_lat, _, _) = adapt_once(0.01, 5.0, 100.0);
        assert_ne!(
            k_hi_lat, k_lo_lat,
            "high latency must not trigger the low-latency k enlargement"
        );
        assert_eq!(k_hi_lat, 10, "high latency + low loss falls into balanced branch, k = base_k");
    }

    #[test]
    fn low_latency_with_low_loss_enlarges_k() {
        // latency < 10 AND loss < 0.05 -> LOW branch: k = (base_k * 1.2) as usize
        let (k, _, _) = adapt_once(0.02, 5.0, 100.0);
        assert_eq!(k, 12); // (10 * 1.2) as usize
    }

    // ---- Parameter stability and reflection ----

    #[test]
    fn repeated_calls_same_input_stable_output() {
        let mut enc = AdaptiveRSEncoder::new(10, 14);
        // Push enough identical samples so the moving average stabilises.
        for _ in 0..20 {
            enc.adapt_parameters(0.01, 5.0, 100.0);
        }
        let (k1, n1, gf1) = enc.current_parameters();
        enc.adapt_parameters(0.01, 5.0, 100.0);
        let (k2, n2, gf2) = enc.current_parameters();
        assert_eq!((k1, n1, gf1), (k2, n2, gf2), "stable inputs must produce stable output");
    }

    #[test]
    fn parameter_update_reflected_in_current_parameters() {
        let mut enc = AdaptiveRSEncoder::new(10, 14);
        // Initial state before any adaptation.
        let (k0, n0, gf0) = enc.current_parameters();
        assert_eq!((k0, n0, gf0), (10, 14, 256));

        // After adapting to high loss, current_parameters() must reflect the change.
        enc.adapt_parameters(0.6, 50.0, 100.0);
        let (_, _, gf_after) = enc.current_parameters();
        assert_eq!(gf_after, 65536, "current_parameters must reflect gf_size change after adapt");
    }
}
