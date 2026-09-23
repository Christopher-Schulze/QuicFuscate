//! Pure-Rust HPKE provider implementing the `rustls::crypto::hpke` traits.
//!
//! rustls ships an HPKE implementation only inside its aws-lc-rs provider. ECH
//! (Encrypted ClientHello) needs an [`Hpke`] suite table; this crate supplies
//! one backed by `hpke-rs` with the `rustcrypto` backend (RustCrypto
//! primitives), so ECH works without the aws-lc-sys C toolchain.
//!
//! Only glue is implemented here: suite selection, type conversion, and error
//! mapping. All HPKE primitives stay inside the audited upstream crate.
//! Suites not listed in [`ALL_SUPPORTED_SUITES`] are never instantiated, so
//! unsupported KEM/KDF/AEAD combinations fail closed at `EchConfig::new`.

use hpke_rs::hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs::{Hpke as RsHpke, Mode};
use hpke_rs_crypto::HpkeCrypto;
use hpke_rs_rust_crypto::HpkeRustCrypto;
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;
use rustls::{Error, OtherError};

type Backend = HpkeRustCrypto;

fn map_err(e: hpke_rs::HpkeError) -> Error {
    Error::Other(OtherError(std::sync::Arc::new(e)))
}

/// An HPKE instance backed by `hpke-rs` (RustCrypto primitives), bound to one
/// fixed KEM/KDF/AEAD combination.
#[derive(Debug)]
pub struct RustCryptoHpke {
    kem: KemAlgorithm,
    kdf: KdfAlgorithm,
    aead: AeadAlgorithm,
    suite: HpkeSuite,
}

impl RustCryptoHpke {
    const fn new(
        kem: KemAlgorithm,
        kdf: KdfAlgorithm,
        aead: AeadAlgorithm,
        suite: HpkeSuite,
    ) -> Self {
        Self { kem, kdf, aead, suite }
    }

    fn config(&self) -> RsHpke<Backend> {
        RsHpke::new(Mode::Base, self.kem, self.kdf, self.aead)
    }
}

impl Hpke for RustCryptoHpke {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let mut hpke = self.config();
        let (enc, ct) = hpke
            .seal(
                &hpke_rs::HpkePublicKey::from(pub_key.0.clone()),
                info,
                aad,
                plaintext,
                None,
                None,
                None,
            )
            .map_err(map_err)?;
        Ok((EncapsulatedSecret(enc), ct))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let mut hpke = self.config();
        let (enc, ctx) = hpke
            .setup_sender(&hpke_rs::HpkePublicKey::from(pub_key.0.clone()), info, None, None, None)
            .map_err(map_err)?;
        Ok((EncapsulatedSecret(enc), Box::new(Sealer(ctx))))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        let hpke = self.config();
        hpke.open(
            &enc.0,
            &hpke_rs::HpkePrivateKey::from(secret_key.secret_bytes().to_vec()),
            info,
            aad,
            ciphertext,
            None,
            None,
            None,
        )
        .map_err(map_err)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        let hpke = self.config();
        let ctx = hpke
            .setup_receiver(
                &enc.0,
                &hpke_rs::HpkePrivateKey::from(secret_key.secret_bytes().to_vec()),
                info,
                None,
                None,
                None,
            )
            .map_err(map_err)?;
        Ok(Box::new(Opener(ctx)))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let mut prng = Backend::prng();
        let (public_key, private_key) =
            Backend::kem_key_gen(self.kem, &mut prng).map_err(|error| map_err(error.into()))?;
        Ok((HpkePublicKey(public_key), HpkePrivateKey::from(private_key)))
    }

    fn suite(&self) -> HpkeSuite {
        self.suite
    }
}

struct Sealer(hpke_rs::Context<Backend>);

impl core::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sealer").finish_non_exhaustive()
    }
}

impl HpkeSealer for Sealer {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.seal(aad, plaintext).map_err(map_err)
    }
}

struct Opener(hpke_rs::Context<Backend>);

impl core::fmt::Debug for Opener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Opener").finish_non_exhaustive()
    }
}

impl HpkeOpener for Opener {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.open(aad, ciphertext).map_err(map_err)
    }
}

macro_rules! suite {
    ($name:ident, $kem:ident, $rs_kem:ident, $kdf:ident, $rs_kdf:ident, $aead:ident, $rs_aead:ident) => {
        #[doc = "HPKE suite backed by hpke-rs rustcrypto; `suite()` reports the matching `HpkeSuite` wire IDs."]
        pub static $name: &RustCryptoHpke = &RustCryptoHpke::new(
            KemAlgorithm::$rs_kem,
            KdfAlgorithm::$rs_kdf,
            AeadAlgorithm::$rs_aead,
            HpkeSuite {
                kem: HpkeKem::$kem,
                sym: HpkeSymmetricCipherSuite { kdf_id: HpkeKdf::$kdf, aead_id: HpkeAead::$aead },
            },
        );
    };
}

suite!(
    DH_KEM_P256_HKDF_SHA256_AES_128,
    DHKEM_P256_HKDF_SHA256,
    DhKemP256,
    HKDF_SHA256,
    HkdfSha256,
    AES_128_GCM,
    Aes128Gcm
);
suite!(
    DH_KEM_P256_HKDF_SHA256_AES_256,
    DHKEM_P256_HKDF_SHA256,
    DhKemP256,
    HKDF_SHA256,
    HkdfSha256,
    AES_256_GCM,
    Aes256Gcm
);
suite!(
    DH_KEM_P256_HKDF_SHA256_CHACHA20_POLY_1305,
    DHKEM_P256_HKDF_SHA256,
    DhKemP256,
    HKDF_SHA256,
    HkdfSha256,
    CHACHA20_POLY_1305,
    ChaCha20Poly1305
);
suite!(
    DH_KEM_P384_HKDF_SHA384_AES_128,
    DHKEM_P384_HKDF_SHA384,
    DhKemP384,
    HKDF_SHA384,
    HkdfSha384,
    AES_128_GCM,
    Aes128Gcm
);
suite!(
    DH_KEM_P384_HKDF_SHA384_AES_256,
    DHKEM_P384_HKDF_SHA384,
    DhKemP384,
    HKDF_SHA384,
    HkdfSha384,
    AES_256_GCM,
    Aes256Gcm
);
suite!(
    DH_KEM_P384_HKDF_SHA384_CHACHA20_POLY_1305,
    DHKEM_P384_HKDF_SHA384,
    DhKemP384,
    HKDF_SHA384,
    HkdfSha384,
    CHACHA20_POLY_1305,
    ChaCha20Poly1305
);
suite!(
    DH_KEM_X25519_HKDF_SHA256_AES_128,
    DHKEM_X25519_HKDF_SHA256,
    DhKem25519,
    HKDF_SHA256,
    HkdfSha256,
    AES_128_GCM,
    Aes128Gcm
);
suite!(
    DH_KEM_X25519_HKDF_SHA256_AES_256,
    DHKEM_X25519_HKDF_SHA256,
    DhKem25519,
    HKDF_SHA256,
    HkdfSha256,
    AES_256_GCM,
    Aes256Gcm
);
suite!(
    DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY_1305,
    DHKEM_X25519_HKDF_SHA256,
    DhKem25519,
    HKDF_SHA256,
    HkdfSha256,
    CHACHA20_POLY_1305,
    ChaCha20Poly1305
);

/// Default RFC 9180 HPKE suites supported by this provider, mirroring the
/// coverage of `rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES`, minus
/// the P-521 KEMs the hpke-rs rustcrypto backend does not implement. An
/// ECHConfigList that offers only P-521 suites fails closed at `EchConfig::new`
/// the same way an unsupported list does.
pub static ALL_SUPPORTED_SUITES: &[&dyn Hpke] = &[
    DH_KEM_P256_HKDF_SHA256_AES_128,
    DH_KEM_P256_HKDF_SHA256_AES_256,
    DH_KEM_P256_HKDF_SHA256_CHACHA20_POLY_1305,
    DH_KEM_P384_HKDF_SHA384_AES_128,
    DH_KEM_P384_HKDF_SHA384_AES_256,
    DH_KEM_P384_HKDF_SHA384_CHACHA20_POLY_1305,
    DH_KEM_X25519_HKDF_SHA256_AES_128,
    DH_KEM_X25519_HKDF_SHA256_AES_256,
    DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY_1305,
];

#[cfg(test)]
mod tests;
