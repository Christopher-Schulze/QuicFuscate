

#[derive(Clone, Copy)]
pub enum XORPattern {
    Simple,
}

pub struct XORObfuscator {
    key: u8,
}

impl XORObfuscator {
    pub fn new() -> Self {
        Self { key: 0xAA }
    }

    pub fn obfuscate(&mut self, data: &[u8], pattern: XORPattern) -> Vec<u8> {
        match pattern {
            XORPattern::Simple => {
                data.iter().map(|b| b ^ self.key).collect()
            }
        }
    }

    pub fn deobfuscate(&mut self, data: &[u8], pattern: XORPattern) -> Vec<u8> {
        // symmetric
        self.obfuscate(data, pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let mut obf = XORObfuscator::new();
        let data = vec![1u8,2,3,4,5];
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
