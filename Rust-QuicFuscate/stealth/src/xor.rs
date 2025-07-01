

#[derive(Clone, Copy)]
pub enum XorPattern {
    Simple,
}

pub struct XorObfuscator {
    key: u8,
}

impl XorObfuscator {
    pub fn new() -> Self {
        Self { key: 0xAA }
    }

    pub fn obfuscate(&mut self, data: &[u8], pattern: XorPattern) -> Vec<u8> {
        match pattern {
            XorPattern::Simple => {
                data.iter().map(|b| b ^ self.key).collect()
            }
        }
    }

    pub fn deobfuscate(&mut self, data: &[u8], pattern: XorPattern) -> Vec<u8> {
        // symmetric
        self.obfuscate(data, pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let mut obf = XorObfuscator::new();
        let data = vec![1u8,2,3,4,5];
        let enc = obf.obfuscate(&data, XorPattern::Simple);
        let dec = obf.deobfuscate(&enc, XorPattern::Simple);
        assert_eq!(dec, data);
    }
}
