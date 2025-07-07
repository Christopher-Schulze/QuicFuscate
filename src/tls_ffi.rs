use std::os::raw::c_void;
use std::sync::OnceLock;

use libloading::{Library, Symbol};

type CustomTlsFn = unsafe extern "C" fn(*mut c_void, *const u8, usize);
type EnableSimdFn = unsafe extern "C" fn(*mut c_void);

static LIB: OnceLock<Option<Library>> = OnceLock::new();
static SET_TLS: OnceLock<Option<CustomTlsFn>> = OnceLock::new();
static ENABLE_SIMD: OnceLock<Option<EnableSimdFn>> = OnceLock::new();

fn load_real_symbols() {
    if let Ok(path) = std::env::var("QUICHE_PATH") {
        let lib_path = format!("{}/target/latest/libquiche.so", path);
        if let Ok(lib) = unsafe { Library::new(&lib_path) } {
            unsafe {
                let set: Result<Symbol<CustomTlsFn>, _> =
                    lib.get(b"quiche_config_set_custom_tls");
                if let Ok(f) = set {
                    SET_TLS.set(Some(*f)).ok();
                }

                let simd: Result<Symbol<EnableSimdFn>, _> =
                    lib.get(b"quiche_config_enable_simd");
                if let Ok(f) = simd {
                    ENABLE_SIMD.set(Some(*f)).ok();
                }
            }
            LIB.set(Some(lib)).ok();
        } else {
            log::debug!("failed to load {}", lib_path);
        }
    }
}

/// FFI shim for injecting a custom TLS ClientHello into quiche.
///
/// Builds without the patched quiche library provide a no-op
/// implementation so that tests can run. When linked against a
/// modified quiche with support for custom ClientHello messages the
/// symbol will be overridden by the real implementation.
#[no_mangle]
pub unsafe extern "C" fn quiche_config_set_custom_tls(
    cfg: *mut c_void,
    hello: *const u8,
    len: usize,
) {
    let f = SET_TLS.get_or_init(|| {
        load_real_symbols();
        SET_TLS.get().cloned().flatten()
    });

    if let Some(real) = f.as_ref() {
        real(cfg, hello, len);
    } else {
        log::debug!("quiche_config_set_custom_tls stub invoked");
    }
}

#[no_mangle]
pub unsafe extern "C" fn quiche_config_enable_simd(_cfg: *mut c_void) {
    let f = ENABLE_SIMD.get_or_init(|| {
        load_real_symbols();
        ENABLE_SIMD.get().cloned().flatten()
    });

    if let Some(real) = f.as_ref() {
        real(_cfg);
    } else {
        log::debug!("quiche_config_enable_simd stub invoked");
    }
}
