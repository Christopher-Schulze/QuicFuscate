//! AEGIS batch adapters for the common AEAD traits.

use crate::crypto::aead::{AeadOpen, AeadOpenItem, AeadSeal, AeadSealItem};
use crate::error::ConnectionError;
use std::sync::atomic::Ordering;

use super::{Aegis128L, Aegis128LAead, Aegis128X4, Aegis128X4Aead, Aegis128X8, Aegis128X8Aead};

#[inline]
fn aegis_batch_homogeneous_seal(items: &[AeadSealItem<'_>]) -> bool {
    if items.len() <= 1 {
        return false;
    }
    let first = &items[0];
    items[1..]
        .iter()
        .all(|it| it.plaintext_len == first.plaintext_len && it.ad.len() == first.ad.len())
}

#[inline]
fn aegis_batch_homogeneous_open(items: &[AeadOpenItem<'_>]) -> bool {
    if items.len() <= 1 {
        return false;
    }
    let first = &items[0];
    items[1..].iter().all(|it| it.buf.len() == first.buf.len() && it.ad.len() == first.ad.len())
}

#[inline]
fn record_aegis_batch_ops(count: usize, homogeneous: bool) {
    if count > 1 && homogeneous {
        qf_telemetry::AEGIS_BATCH_OPS.fetch_add(count as u64, Ordering::Relaxed);
    }
}

impl AeadSeal for Aegis128LAead {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, ConnectionError> {
        let sealed = crate::crypto::checked_seal_capacity(buf.len(), len)?;
        let nonce16 = crate::crypto::make_nonce16(&self.iv, counter)?;
        let mut cipher = Aegis128L::new(&self.key, &nonce16)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        let (pt, rest) = buf.split_at_mut(len);
        let tag = cipher.encrypt_in_place(pt, ad);
        rest[..16].copy_from_slice(&tag);
        Ok(sealed)
    }

    fn supports_batch_seal(&self) -> bool {
        true
    }

    fn seal_batch(&self, items: &mut [AeadSealItem<'_>]) -> Result<(), ConnectionError> {
        if items.is_empty() {
            return Ok(());
        }
        let homogeneous = aegis_batch_homogeneous_seal(items);
        let first = &items[0];
        if first.buf.len() < crate::crypto::sealed_len(first.plaintext_len)? {
            return Err(ConnectionError::BufferTooShort);
        }
        let first_nonce = crate::crypto::make_nonce16(&self.iv, first.counter)?;
        let mut cipher = Aegis128L::new(&self.key, &first_nonce)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        for (index, item) in items.iter_mut().enumerate() {
            if index > 0 {
                if item.buf.len() < crate::crypto::sealed_len(item.plaintext_len)? {
                    return Err(ConnectionError::BufferTooShort);
                }
                let nonce16 = crate::crypto::make_nonce16(&self.iv, item.counter)?;
                cipher
                    .reinit(&self.key, &nonce16)
                    .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
            }
            let (pt, rest) = item.buf.split_at_mut(item.plaintext_len);
            let tag = cipher.encrypt_in_place(pt, item.ad);
            rest[..16].copy_from_slice(&tag);
        }
        record_aegis_batch_ops(items.len(), homogeneous);
        Ok(())
    }
}

impl AeadOpen for Aegis128LAead {
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, ConnectionError> {
        if buf.len() < 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let ct_len = buf.len() - 16;
        let (ct, tag_in) = buf.split_at_mut(ct_len);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_in[..16]);
        let nonce16 = crate::crypto::make_nonce16(&self.iv, counter)?;
        let mut cipher = Aegis128L::new(&self.key, &nonce16)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        cipher
            .decrypt_in_place(ct, ad, &tag)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        Ok(ct_len)
    }

    fn supports_batch_open(&self) -> bool {
        true
    }

    fn open_batch(&self, items: &mut [AeadOpenItem<'_>]) -> Result<(), ConnectionError> {
        if items.is_empty() {
            return Ok(());
        }
        let homogeneous = aegis_batch_homogeneous_open(items);
        let first = &items[0];
        if first.buf.len() < 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let first_nonce = crate::crypto::make_nonce16(&self.iv, first.counter)?;
        let mut cipher = Aegis128L::new(&self.key, &first_nonce)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        for (index, item) in items.iter_mut().enumerate() {
            if index > 0 {
                if item.buf.len() < 16 {
                    return Err(ConnectionError::BufferTooShort);
                }
                let nonce16 = crate::crypto::make_nonce16(&self.iv, item.counter)?;
                cipher
                    .reinit(&self.key, &nonce16)
                    .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
            }
            let ct_len = item.buf.len() - 16;
            let (ct, tag_in) = item.buf.split_at_mut(ct_len);
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&tag_in[..16]);
            cipher
                .decrypt_in_place(ct, item.ad, &tag)
                .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        }
        record_aegis_batch_ops(items.len(), homogeneous);
        Ok(())
    }
}

impl AeadSeal for Aegis128X4Aead {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, ConnectionError> {
        let sealed = crate::crypto::sealed_len(len)?;
        let mut item = AeadSealItem { counter, ad, buf, plaintext_len: len };
        self.seal_batch(std::slice::from_mut(&mut item))?;
        Ok(sealed)
    }

    fn supports_batch_seal(&self) -> bool {
        true
    }

    fn seal_batch(&self, items: &mut [AeadSealItem<'_>]) -> Result<(), ConnectionError> {
        aegis_x4_seal_batch(&self.key, &self.iv, items)
    }
}

impl AeadOpen for Aegis128X4Aead {
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, ConnectionError> {
        if buf.len() < 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let ct_len = buf.len() - 16;
        let mut item = AeadOpenItem { counter, ad, buf };
        self.open_batch(std::slice::from_mut(&mut item))?;
        Ok(ct_len)
    }

    fn supports_batch_open(&self) -> bool {
        true
    }

    fn open_batch(&self, items: &mut [AeadOpenItem<'_>]) -> Result<(), ConnectionError> {
        aegis_x4_open_batch(&self.key, &self.iv, items)
    }
}

impl AeadSeal for Aegis128X8Aead {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, ConnectionError> {
        let sealed = crate::crypto::sealed_len(len)?;
        let mut item = AeadSealItem { counter, ad, buf, plaintext_len: len };
        self.seal_batch(std::slice::from_mut(&mut item))?;
        Ok(sealed)
    }

    fn supports_batch_seal(&self) -> bool {
        true
    }

    fn seal_batch(&self, items: &mut [AeadSealItem<'_>]) -> Result<(), ConnectionError> {
        aegis_x8_seal_batch(&self.key, &self.iv, items)
    }
}

impl AeadOpen for Aegis128X8Aead {
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, ConnectionError> {
        if buf.len() < 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let ct_len = buf.len() - 16;
        let mut item = AeadOpenItem { counter, ad, buf };
        self.open_batch(std::slice::from_mut(&mut item))?;
        Ok(ct_len)
    }

    fn supports_batch_open(&self) -> bool {
        true
    }

    fn open_batch(&self, items: &mut [AeadOpenItem<'_>]) -> Result<(), ConnectionError> {
        aegis_x8_open_batch(&self.key, &self.iv, items)
    }
}

fn aegis_x4_seal_batch(
    key: &[u8; 16],
    iv: &[u8; 12],
    items: &mut [AeadSealItem<'_>],
) -> Result<(), ConnectionError> {
    if items.is_empty() {
        return Ok(());
    }
    let homogeneous = aegis_batch_homogeneous_seal(items);
    let first = &items[0];
    if first.buf.len() < crate::crypto::sealed_len(first.plaintext_len)? {
        return Err(ConnectionError::BufferTooShort);
    }
    let first_nonce = crate::crypto::make_nonce16(iv, first.counter)?;
    let mut cipher = Aegis128X4::new(key, &first_nonce)
        .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
    for (index, item) in items.iter_mut().enumerate() {
        if index > 0 {
            if item.buf.len() < crate::crypto::sealed_len(item.plaintext_len)? {
                return Err(ConnectionError::BufferTooShort);
            }
            let nonce16 = crate::crypto::make_nonce16(iv, item.counter)?;
            cipher
                .reinit(key, &nonce16)
                .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        }
        let (pt, rest) = item.buf.split_at_mut(item.plaintext_len);
        let tag = cipher.encrypt_in_place(pt, item.ad);
        rest[..16].copy_from_slice(&tag);
    }
    record_aegis_batch_ops(items.len(), homogeneous);
    Ok(())
}

fn aegis_x4_open_batch(
    key: &[u8; 16],
    iv: &[u8; 12],
    items: &mut [AeadOpenItem<'_>],
) -> Result<(), ConnectionError> {
    if items.is_empty() {
        return Ok(());
    }
    let homogeneous = aegis_batch_homogeneous_open(items);
    let first = &items[0];
    if first.buf.len() < 16 {
        return Err(ConnectionError::BufferTooShort);
    }
    let first_nonce = crate::crypto::make_nonce16(iv, first.counter)?;
    let mut cipher = Aegis128X4::new(key, &first_nonce)
        .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
    for (index, item) in items.iter_mut().enumerate() {
        if index > 0 {
            if item.buf.len() < 16 {
                return Err(ConnectionError::BufferTooShort);
            }
            let nonce16 = crate::crypto::make_nonce16(iv, item.counter)?;
            cipher
                .reinit(key, &nonce16)
                .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        }
        let ct_len = item.buf.len() - 16;
        let (ct, tag_in) = item.buf.split_at_mut(ct_len);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_in[..16]);
        cipher
            .decrypt_in_place(ct, item.ad, &tag)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
    }
    record_aegis_batch_ops(items.len(), homogeneous);
    Ok(())
}

fn aegis_x8_seal_batch(
    key: &[u8; 16],
    iv: &[u8; 12],
    items: &mut [AeadSealItem<'_>],
) -> Result<(), ConnectionError> {
    if items.is_empty() {
        return Ok(());
    }
    let homogeneous = aegis_batch_homogeneous_seal(items);
    let first = &items[0];
    if first.buf.len() < crate::crypto::sealed_len(first.plaintext_len)? {
        return Err(ConnectionError::BufferTooShort);
    }
    let first_nonce = crate::crypto::make_nonce16(iv, first.counter)?;
    let mut cipher = Aegis128X8::new(key, &first_nonce)
        .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
    for (index, item) in items.iter_mut().enumerate() {
        if index > 0 {
            if item.buf.len() < crate::crypto::sealed_len(item.plaintext_len)? {
                return Err(ConnectionError::BufferTooShort);
            }
            let nonce16 = crate::crypto::make_nonce16(iv, item.counter)?;
            cipher
                .reinit(key, &nonce16)
                .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        }
        let (pt, rest) = item.buf.split_at_mut(item.plaintext_len);
        let tag = cipher.encrypt_in_place(pt, item.ad);
        rest[..16].copy_from_slice(&tag);
    }
    record_aegis_batch_ops(items.len(), homogeneous);
    Ok(())
}

fn aegis_x8_open_batch(
    key: &[u8; 16],
    iv: &[u8; 12],
    items: &mut [AeadOpenItem<'_>],
) -> Result<(), ConnectionError> {
    if items.is_empty() {
        return Ok(());
    }
    let homogeneous = aegis_batch_homogeneous_open(items);
    let first = &items[0];
    if first.buf.len() < 16 {
        return Err(ConnectionError::BufferTooShort);
    }
    let first_nonce = crate::crypto::make_nonce16(iv, first.counter)?;
    let mut cipher = Aegis128X8::new(key, &first_nonce)
        .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
    for (index, item) in items.iter_mut().enumerate() {
        if index > 0 {
            if item.buf.len() < 16 {
                return Err(ConnectionError::BufferTooShort);
            }
            let nonce16 = crate::crypto::make_nonce16(iv, item.counter)?;
            cipher
                .reinit(key, &nonce16)
                .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
        }
        let ct_len = item.buf.len() - 16;
        let (ct, tag_in) = item.buf.split_at_mut(ct_len);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_in[..16]);
        cipher
            .decrypt_in_place(ct, item.ad, &tag)
            .map_err(|_| ConnectionError::CryptoError("crypto failure".into()))?;
    }
    record_aegis_batch_ops(items.len(), homogeneous);
    Ok(())
}
