//! libaegis AEGIS-128 packet owners.
//!
//! `L`, `X2`, and `X4` share the QUIC packet API: 16-byte key, 12-byte IV,
//! 16-byte nonce, 16-byte tag. They are different algorithms. The private
//! payload pin stays `L` until a same-API matrix on every target host picks
//! one variant for both peers. There is no trial-decrypt fallback.

use crate::aead::{AeadOpen, AeadSeal};
use crate::error::ConnectionError;
use zeroize::Zeroize;

const TAG_LEN: usize = 16;

macro_rules! libaegis_owner {
    ($name:ident, $module:ident, $prim:ident) => {
        pub(crate) struct $name {
            key: [u8; 16],
            iv: [u8; 12],
        }

        impl $name {
            pub(crate) fn from_arrays(key: &[u8; 16], iv: &[u8; 12]) -> Self {
                Self { key: *key, iv: *iv }
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.key.zeroize();
                self.iv.zeroize();
            }
        }

        impl AeadSeal for $name {
            fn seal_with_u64_counter(
                &self,
                counter: u64,
                ad: &[u8],
                buf: &mut [u8],
                len: usize,
                _extra_in: Option<&[u8]>,
            ) -> Result<usize, ConnectionError> {
                let sealed = crate::checked_seal_capacity(buf.len(), len)?;
                let nonce = crate::make_nonce16(&self.iv, counter)?;
                let tag = aegis::$module::$prim::<TAG_LEN>::new(&self.key, &nonce)
                    .encrypt_in_place(&mut buf[..len], ad);
                buf[len..sealed].copy_from_slice(&tag);
                Ok(sealed)
            }
        }

        impl AeadOpen for $name {
            fn open_with_u64_counter(
                &self,
                counter: u64,
                ad: &[u8],
                buf: &mut [u8],
            ) -> Result<usize, ConnectionError> {
                if buf.len() < TAG_LEN {
                    return Err(ConnectionError::BufferTooShort);
                }
                let pt_len = buf.len() - TAG_LEN;
                let nonce = crate::make_nonce16(&self.iv, counter)?;
                let mut tag = [0u8; TAG_LEN];
                tag.copy_from_slice(&buf[pt_len..]);
                aegis::$module::$prim::<TAG_LEN>::new(&self.key, &nonce)
                    .decrypt_in_place(&mut buf[..pt_len], &tag, ad)
                    .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
                Ok(pt_len)
            }
        }
    };
}

libaegis_owner!(LibAegis128L, aegis128l, Aegis128L);
libaegis_owner!(LibAegis128X2, aegis128x2, Aegis128X2);
libaegis_owner!(LibAegis128X4, aegis128x4, Aegis128X4);

/// Which libaegis AEGIS-128 algorithm a packet owner uses.
///
/// The three values do not decrypt each other. Both peers must use the same one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LibAegis128Variant {
    /// AEGIS-128L. This is the private-payload pin until the matrix says otherwise.
    L,
    /// AEGIS-128X2.
    X2,
    /// AEGIS-128X4.
    X4,
}

#[cfg(test)]
mod tests {
    use super::LibAegis128L;
    use crate::aead::{AeadOpen, AeadSeal};

    #[test]
    fn libaegis_matches_pinned_cfrg_aegis128l_vector_1() {
        let key = hex::decode("10010000000000000000000000000000").unwrap();
        let nonce = hex::decode("10000200000000000000000000000000").unwrap();
        let mut buf = hex::decode("00000000000000000000000000000000").unwrap();
        let expected_ct = hex::decode("c1c0e58bd913006feba00f4b3cc3594e").unwrap();
        let expected_tag = hex::decode("abe0ece80c24868a226a35d16bdae37a").unwrap();
        let key: [u8; 16] = key.try_into().unwrap();
        let nonce: [u8; 16] = nonce.try_into().unwrap();
        let tag =
            aegis::aegis128l::Aegis128L::<16>::new(&key, &nonce).encrypt_in_place(&mut buf, b"");
        assert_eq!(buf, expected_ct);
        assert_eq!(tag.as_slice(), expected_tag.as_slice());
    }

    #[test]
    fn libaegis_quic_nonce_roundtrip() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 12];
        let ad = b"opt-in";
        let mut left = vec![0u8; 64];
        let mut right = left.clone();
        for (i, byte) in left.iter_mut().take(48).enumerate() {
            *byte = i as u8;
        }
        right[..48].copy_from_slice(&left[..48]);
        let lib = LibAegis128L::from_arrays(&key, &iv);
        let sealed = lib.seal_with_u64_counter(9, ad, &mut left, 48, None).expect("libaegis seal");
        let opened = lib.open_with_u64_counter(9, ad, &mut left[..sealed]).expect("libaegis open");
        assert_eq!(opened, 48);
        assert_eq!(&left[..48], &right[..48]);
    }

    fn pinned_empty_tag(prim: impl Fn(&[u8; 16], &[u8; 16]) -> [u8; 16], expected_tag: &str) {
        let key: [u8; 16] =
            hex::decode("000102030405060708090a0b0c0d0e0f").unwrap().try_into().unwrap();
        let nonce: [u8; 16] =
            hex::decode("101112131415161718191a1b1c1d1e1f").unwrap().try_into().unwrap();
        let tag = prim(&key, &nonce);
        assert_eq!(tag.as_slice(), hex::decode(expected_tag).unwrap().as_slice());
    }

    #[test]
    fn libaegis_x2_and_x4_match_pinned_empty_message_tags() {
        pinned_empty_tag(
            |key, nonce| {
                aegis::aegis128x2::Aegis128X2::<16>::new(key, nonce).encrypt_in_place(&mut [], b"")
            },
            "63117dc57756e402819a82e13eca8379",
        );
        pinned_empty_tag(
            |key, nonce| {
                aegis::aegis128x4::Aegis128X4::<16>::new(key, nonce).encrypt_in_place(&mut [], b"")
            },
            "5bef762d0947c00455b97bb3af30dfa3",
        );
    }

    #[test]
    fn libaegis_128_variants_do_not_share_ciphertext() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 12];
        let owners: [Box<dyn AeadSeal>; 3] = [
            Box::new(super::LibAegis128L::from_arrays(&key, &iv)),
            Box::new(super::LibAegis128X2::from_arrays(&key, &iv)),
            Box::new(super::LibAegis128X4::from_arrays(&key, &iv)),
        ];
        let mut outs = Vec::new();
        for owner in &owners {
            let mut buf = vec![0x5Au8; 64];
            owner.seal_with_u64_counter(3, b"ad", &mut buf, 48, None).expect("seal");
            outs.push(buf);
        }
        assert_ne!(outs[0], outs[1]);
        assert_ne!(outs[0], outs[2]);
        assert_ne!(outs[1], outs[2]);
    }
}
