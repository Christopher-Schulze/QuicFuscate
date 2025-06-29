use std::os::raw::{c_int, c_uchar, c_void};
use libc;

extern "C" {
    fn xor_obfuscator_new() -> *mut c_void;
    fn xor_obfuscator_free(ptr: *mut c_void);
    fn xor_obfuscator_obfuscate(
        ptr: *mut c_void,
        data: *const c_uchar,
        len: usize,
        out: *mut *mut c_uchar,
        out_len: *mut usize,
    ) -> c_int;
}

pub struct XorObfuscator {
    inner: *mut c_void,
}

impl XorObfuscator {
    pub fn new() -> Self {
        unsafe { Self { inner: xor_obfuscator_new() } }
    }

    pub fn obfuscate(&self, data: &[u8]) -> Option<Vec<u8>> {
        unsafe {
            let mut out_ptr: *mut u8 = std::ptr::null_mut();
            let mut out_len: usize = 0;
            let res = xor_obfuscator_obfuscate(
                self.inner,
                data.as_ptr(),
                data.len(),
                &mut out_ptr,
                &mut out_len,
            );
            if res != 0 { return None; }
            let slice = std::slice::from_raw_parts(out_ptr, out_len);
            let vec = slice.to_vec();
            libc::free(out_ptr as *mut c_void);
            Some(vec)
        }
    }
}

impl Drop for XorObfuscator {
    fn drop(&mut self) { unsafe { xor_obfuscator_free(self.inner) } }
}
