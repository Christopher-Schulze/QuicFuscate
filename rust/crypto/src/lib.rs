pub struct AEGIS128X;
impl AEGIS128X {
    pub fn new() -> Self { Self }
}

pub struct AEGIS128L;
impl AEGIS128L {
    pub fn new() -> Self { Self }
}

pub struct MORUS1280;
impl MORUS1280 {
    pub fn new() -> Self { Self }
}

#[derive(Clone, Copy)]
pub enum CipherSuite {
    Aegis128xVaes512,
    Aegis128xAesni,
    Aegis128lNeon,
    Aegis128lAesni,
    Morus1280_128,
}

pub struct CipherSuiteSelector {
    suite: CipherSuite,
}

impl CipherSuiteSelector {
    pub fn new() -> Self {
        Self { suite: CipherSuite::Aegis128xVaes512 }
    }

    pub fn select_best_cipher_suite(&self) -> CipherSuite {
        self.suite
    }

    pub fn set_cipher_suite(&mut self, suite: CipherSuite) {
        self.suite = suite;
    }

    pub fn encrypt(
        &self,
        _plaintext: &[u8],
        _key: &[u8],
        _nonce: &[u8],
        _ad: &[u8],
        _ciphertext: &mut Vec<u8>,
        _tag: &mut [u8],
    ) {
    }

    pub fn decrypt(
        &self,
        _ciphertext: &[u8],
        _key: &[u8],
        _nonce: &[u8],
        _ad: &[u8],
        _tag: &[u8],
        _plaintext: &mut Vec<u8>,
    ) -> bool {
        true
    }

    pub fn get_current_cipher_suite(&self) -> CipherSuite {
        self.suite
    }

    pub fn get_cipher_suite_name(&self) -> &'static str {
        "stub"
    }

    pub fn is_hardware_accelerated(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {}
}
