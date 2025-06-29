use std::os::raw::{c_uint,c_uchar,c_void};

extern "C" {
    fn morus_new() -> *mut c_void;
    fn morus_free(ptr: *mut c_void);
    fn morus_encrypt(
        ctx: *mut c_void,
        plaintext: *const c_uchar,
        plaintext_len: usize,
        key: *const c_uchar,
        nonce: *const c_uchar,
        ad: *const c_uchar,
        ad_len: usize,
        ciphertext: *mut c_uchar,
        tag: *mut c_uchar,
    );
}

pub struct Morus {
    inner: *mut c_void,
}

impl Morus {
    pub fn new() -> Self {
        unsafe { Self { inner: morus_new() } }
    }

    pub fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8],
    ) {
        unsafe {
            morus_encrypt(
                self.inner,
                plaintext.as_ptr(),
                plaintext.len(),
                key.as_ptr(),
                nonce.as_ptr(),
                ad.as_ptr(),
                ad.len(),
                ciphertext.as_mut_ptr(),
                tag.as_mut_ptr(),
            );
        }
    }
}

impl Drop for Morus {
    fn drop(&mut self) {
        unsafe { morus_free(self.inner) }
    }
}
