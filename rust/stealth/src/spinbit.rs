use rand::Rng;

pub struct SpinBitRandomizer {
    probability: f64,
    enabled: bool,
}

impl SpinBitRandomizer {
    pub fn new() -> Self {
        Self { probability: 0.5, enabled: true }
    }

    pub fn set_probability(&mut self, p: f64) { self.probability = p; }

    pub fn randomize(&self, bit: bool) -> bool {
        if !self.enabled { return bit; }
        let flip = rand::thread_rng().gen_bool(self.probability);
        if flip { !bit } else { bit }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn randomizer_flips() {
        let r = SpinBitRandomizer::new();
        let _ = r.randomize(true);
    }

    #[test]
    fn always_flip_when_probability_one() {
        let mut r = SpinBitRandomizer::new();
        r.set_probability(1.0);
        assert!(!r.randomize(true));
        assert!(r.randomize(false));
    }
}
