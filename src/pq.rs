#[cfg(feature = "pq")]
use pqcrypto_kyber::kyber768::{self, Ciphertext, PublicKey, SecretKey, SharedSecret};
#[cfg(feature = "pq")]
use pqcrypto_dilithium::dilithium3::{self, DetachedSignature};

/// Utilities for Post-Quantum key exchange and signatures using Kyber and Dilithium.
#[cfg(feature = "pq")]
pub struct PqCrypto;

#[cfg(feature = "pq")]
impl PqCrypto {
    /// Generates a Kyber768 keypair.
    pub fn kyber_keypair() -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = kyber768::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }

    /// Encapsulates a shared secret to the given Kyber768 public key.
    pub fn kyber_encapsulate(pk_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let pk = PublicKey::from_bytes(pk_bytes).expect("invalid kyber public key");
        let (ss, ct) = kyber768::encapsulate(&pk);
        (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
    }

    /// Decapsulates the Kyber768 ciphertext to recover the shared secret.
    pub fn kyber_decapsulate(ct_bytes: &[u8], sk_bytes: &[u8]) -> Vec<u8> {
        let ct = Ciphertext::from_bytes(ct_bytes).expect("invalid kyber ciphertext");
        let sk = SecretKey::from_bytes(sk_bytes).expect("invalid kyber secret key");
        let ss = kyber768::decapsulate(&ct, &sk);
        ss.as_bytes().to_vec()
    }

    /// Generates a Dilithium3 keypair.
    pub fn dilithium_keypair() -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = dilithium3::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }

    /// Creates a Dilithium3 detached signature for the given message.
    pub fn dilithium_sign(msg: &[u8], sk_bytes: &[u8]) -> Vec<u8> {
        let sk = dilithium3::SecretKey::from_bytes(sk_bytes).expect("invalid dilithium secret key");
        let sig = dilithium3::sign_detached(msg, &sk);
        sig.as_bytes().to_vec()
    }

    /// Verifies a Dilithium3 signature against the message.
    pub fn dilithium_verify(msg: &[u8], sig_bytes: &[u8], pk_bytes: &[u8]) -> bool {
        let pk = dilithium3::PublicKey::from_bytes(pk_bytes).expect("invalid dilithium public key");
        let sig = DetachedSignature::from_bytes(sig_bytes).expect("invalid dilithium signature");
        dilithium3::verify_detached(&sig, msg, &pk).is_ok()
    }
}
