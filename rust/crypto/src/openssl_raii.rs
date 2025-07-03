use crate::error::{CryptoError, Result};
use openssl_sys as ffi;

pub struct SslCtx {
    ctx: *mut ffi::SSL_CTX,
}

impl SslCtx {
    pub fn new() -> Result<Self> {
        unsafe {
            let ctx = ffi::SSL_CTX_new(ffi::TLS_method());
            if ctx.is_null() {
                Err(CryptoError::OpenSsl)
            } else {
                Ok(Self { ctx })
            }
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::SSL_CTX {
        self.ctx
    }
}

impl Drop for SslCtx {
    fn drop(&mut self) {
        unsafe { ffi::SSL_CTX_free(self.ctx) }
    }
}

pub struct Ssl {
    ssl: *mut ffi::SSL,
}

impl Ssl {
    pub fn new(ctx: &SslCtx) -> Result<Self> {
        unsafe {
            let ssl = ffi::SSL_new(ctx.as_ptr());
            if ssl.is_null() {
                Err(CryptoError::OpenSsl)
            } else {
                Ok(Self { ssl })
            }
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::SSL {
        self.ssl
    }
}

impl Drop for Ssl {
    fn drop(&mut self) {
        unsafe { ffi::SSL_free(self.ssl) }
    }
}
