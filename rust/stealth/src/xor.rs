use rand::{rngs::SmallRng, Rng, SeedableRng};

/// Available obfuscation patterns.
#[derive(Clone, Copy)]
pub enum XORPattern {
    /// XOR with a static key.
    Simple,
    /// Apply multiple XOR passes with different keys.
    Layered,
    /// XOR each byte with its offset to defeat repetition.
    PositionBased,
}

/// Runtime configuration for the [`XORObfuscator`].
#[derive(Clone, Copy)]
pub struct XORConfig {
    /// Whether keys should change over time.
    pub dynamic_keys: bool,
    /// Use multiple XOR passes when obfuscating.
    pub multi_layer: bool,
    /// Interval in packets before rotating the key.
    pub rotation_interval: u64,
    /// Initial key value.
    pub base_key: u8,
}

impl Default for XORConfig {
    fn default() -> Self {
        Self {
            dynamic_keys: true,
            multi_layer: false,
            rotation_interval: 128,
            base_key: 0xAA,
        }
    }
}

/// Simple XOR based obfuscator used for stealth features.
pub struct XORObfuscator {
    cfg: XORConfig,
    key: u8,
    counter: u64,
    rng: SmallRng,
}

impl Default for XORObfuscator {
    fn default() -> Self {
        Self::new()
    }
}

impl XORObfuscator {
    /// Create a new obfuscator with default configuration.
    pub fn new() -> Self {
        Self::with_config(XORConfig::default())
    }

    /// Create a new obfuscator from a custom configuration.
    pub fn with_config(cfg: XORConfig) -> Self {
        Self {
            key: cfg.base_key,
            cfg,
            counter: 0,
            rng: SmallRng::from_entropy(),
        }
    }

    fn maybe_rotate(&mut self) {
        if self.cfg.dynamic_keys && self.counter >= self.cfg.rotation_interval {
            self.key = self.rng.gen();
            self.counter = 0;
        }
    }

    /// Obfuscate the given data using the specified pattern.
    pub fn obfuscate(&mut self, data: &[u8], pattern: XORPattern) -> Vec<u8> {
        self.counter = self.counter.wrapping_add(1);
        self.maybe_rotate();

        match pattern {
            XORPattern::Simple => data.iter().map(|b| b ^ self.key).collect(),
            XORPattern::Layered => {
                let mut out: Vec<u8> = data.iter().map(|b| b ^ self.key).collect();
                if self.cfg.multi_layer {
                    for layer in 1..=2u8 {
                        for byte in out.iter_mut() {
                            *byte ^= self.key.wrapping_add(layer);
                        }
                    }
                }
                out
            }
            XORPattern::PositionBased => data
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ self.key ^ (i as u8))
                .collect(),
        }
    }

    /// Reverse the obfuscation using the same pattern.
    pub fn deobfuscate(&mut self, data: &[u8], pattern: XORPattern) -> Vec<u8> {
        // XOR is symmetric
        self.obfuscate(data, pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let mut obf = XORObfuscator::new();
        let data = vec![1u8, 2, 3, 4, 5];
        let enc = obf.obfuscate(&data, XORPattern::Simple);
        let dec = obf.deobfuscate(&enc, XORPattern::Simple);
        assert_eq!(dec, data);
    }

    #[test]
    fn xor_obfuscation_changes_data() {
        let mut obf = XORObfuscator::new();
        let data = [0xFFu8];
        let enc = obf.obfuscate(&data, XORPattern::Simple);
        assert_eq!(enc, vec![0x55]);
    }
}
