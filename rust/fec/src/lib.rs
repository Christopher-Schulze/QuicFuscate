use std::os::raw::{c_int, c_uchar, c_void};
use libc;

extern "C" {
    fn fec_module_init() -> c_int;
    fn fec_module_cleanup();
    fn fec_module_encode(data: *const c_uchar, data_size: usize, out: *mut *mut c_uchar, out_size: *mut usize) -> c_int;
}

pub fn init() -> i32 { unsafe { fec_module_init() as i32 } }
pub fn cleanup() { unsafe { fec_module_cleanup() } }

pub fn encode(data: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let res = fec_module_encode(data.as_ptr(), data.len(), &mut out_ptr, &mut out_len);
        if res != 0 { return None; }
        let slice = std::slice::from_raw_parts(out_ptr, out_len);
        let vec = slice.to_vec();
        libc::free(out_ptr as *mut c_void);
        Some(vec)
    }
}
