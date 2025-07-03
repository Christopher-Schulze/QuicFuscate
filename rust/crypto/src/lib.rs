#![cfg_attr(target_arch = "x86_64", feature(stdarch_x86_avx512))]
mod aegis128l;
#[cfg(feature = "aegis128x")]
mod aegis128x;
mod error;
mod features;
mod morus;
mod morus1280;

pub use aegis128l::Aegis128L;
#[cfg(feature = "aegis128x")]
pub use aegis128x::Aegis128X;
pub use morus::Morus;
pub use morus1280::Morus1280;

pub use error::CryptoError;

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
        let suite = Self::select_best_cipher_suite_internal();
        Self { suite }
    }

    fn select_best_cipher_suite_internal() -> CipherSuite {
        if features::vaes_available() {
            CipherSuite::Aegis128xVaes512
        } else if features::neon_available() {
            CipherSuite::Aegis128lNeon
        } else if features::aesni_available() {
            CipherSuite::Aegis128lAesni
        } else {
            CipherSuite::Morus1280_128
        }
    }

    pub fn select_best_cipher_suite(&self) -> CipherSuite {
        Self::select_best_cipher_suite_internal()
    }

    pub fn set_cipher_suite(&mut self, suite: CipherSuite) {
        self.suite = suite;
    }

    pub fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8; 16],
        nonce: &[u8; 16],
        ad: &[u8],
        ciphertext: &mut Vec<u8>,
        tag: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        match self.suite {
            CipherSuite::Aegis128xVaes512 | CipherSuite::Aegis128xAesni => {
                #[cfg(feature = "aegis128x")]
                {
                    Aegis128X::new().encrypt(plaintext, key, nonce, ad, ciphertext, tag)
                }
                #[cfg(not(feature = "aegis128x"))]
                {
                    Aegis128L::new().encrypt(plaintext, key, nonce, ad, ciphertext, tag)
                }
            }
            CipherSuite::Aegis128lNeon | CipherSuite::Aegis128lAesni => {
                Aegis128L::new().encrypt(plaintext, key, nonce, ad, ciphertext, tag)
            }
            CipherSuite::Morus1280_128 => {
                Morus1280::new().encrypt(plaintext, key, nonce, ad, ciphertext, tag)
            }
        }
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8; 16],
        nonce: &[u8; 16],
        ad: &[u8],
        tag: &[u8; 16],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        match self.suite {
            CipherSuite::Aegis128xVaes512 | CipherSuite::Aegis128xAesni => {
                #[cfg(feature = "aegis128x")]
                {
                    Aegis128X::new().decrypt(ciphertext, key, nonce, ad, tag, plaintext)
                }
                #[cfg(not(feature = "aegis128x"))]
                {
                    Aegis128L::new().decrypt(ciphertext, key, nonce, ad, tag, plaintext)
                }
            }
            CipherSuite::Aegis128lNeon | CipherSuite::Aegis128lAesni => {
                Aegis128L::new().decrypt(ciphertext, key, nonce, ad, tag, plaintext)
            }
            CipherSuite::Morus1280_128 => {
                Morus1280::new().decrypt(ciphertext, key, nonce, ad, tag, plaintext)
            }
        }
    }

    pub fn get_current_cipher_suite(&self) -> CipherSuite {
        self.suite
    }

    pub fn get_cipher_suite_name(&self) -> &'static str {
        match self.suite {
            CipherSuite::Aegis128xVaes512 => "AEGIS-128X-VAES512",
            CipherSuite::Aegis128xAesni => "AEGIS-128X-AESNI",
            CipherSuite::Aegis128lNeon => "AEGIS-128L-NEON",
            CipherSuite::Aegis128lAesni => "AEGIS-128L-AESNI",
            CipherSuite::Morus1280_128 => "MORUS-1280-128",
        }
    }

    pub fn is_hardware_accelerated(&self) -> bool {
        match self.suite {
            CipherSuite::Aegis128xVaes512 => features::vaes_available(),
            CipherSuite::Aegis128xAesni => features::aesni_available(),
            CipherSuite::Aegis128lNeon => features::neon_available(),
            CipherSuite::Aegis128lAesni => features::aesni_available(),
            CipherSuite::Morus1280_128 => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_returns_some_suite() {
        let selector = CipherSuiteSelector::new();
        let _ = selector.get_cipher_suite_name();
        assert!(matches!(
            selector.get_current_cipher_suite(),
            CipherSuite::Aegis128xVaes512
                | CipherSuite::Aegis128xAesni
                | CipherSuite::Aegis128lNeon
                | CipherSuite::Aegis128lAesni
                | CipherSuite::Morus1280_128
        ));
    }
}
