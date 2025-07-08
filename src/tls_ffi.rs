use std::os::raw::c_void;
use std::sync::OnceLock;

use libloading::{Library, Symbol};

type CustomTlsFn = unsafe extern "C" fn(*mut c_void, *const u8, usize);
type EnableSimdFn = unsafe extern "C" fn(*mut c_void);
type BuilderNewFn = unsafe extern "C" fn() -> *mut c_void;
type BuilderAddFn = unsafe extern "C" fn(*mut c_void, *const u8, usize);
type BuilderUseFn = unsafe extern "C" fn(*mut c_void, *mut c_void);
type BuilderFreeFn = unsafe extern "C" fn(*mut c_void);
type DisableGreaseFn = unsafe extern "C" fn(*mut c_void, i32);
type DeterministicFn = unsafe extern "C" fn(*mut c_void, i32);

static LIB: OnceLock<Option<Library>> = OnceLock::new();
static SET_TLS: OnceLock<Option<CustomTlsFn>> = OnceLock::new();
static ENABLE_SIMD: OnceLock<Option<EnableSimdFn>> = OnceLock::new();
static BUILDER_NEW: OnceLock<Option<BuilderNewFn>> = OnceLock::new();
static BUILDER_ADD: OnceLock<Option<BuilderAddFn>> = OnceLock::new();
static BUILDER_USE: OnceLock<Option<BuilderUseFn>> = OnceLock::new();
static BUILDER_FREE: OnceLock<Option<BuilderFreeFn>> = OnceLock::new();
static DISABLE_GREASE: OnceLock<Option<DisableGreaseFn>> = OnceLock::new();
static SET_DETERMINISTIC: OnceLock<Option<DeterministicFn>> = OnceLock::new();

#[cfg(test)]
pub static LAST_HELLO: once_cell::sync::Lazy<std::sync::Mutex<Vec<u8>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(Vec::new()));

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

                let bnew: Result<Symbol<BuilderNewFn>, _> = lib.get(b"quiche_chlo_builder_new");
                if let Ok(f) = bnew {
                    BUILDER_NEW.set(Some(*f)).ok();
                }
                let badd: Result<Symbol<BuilderAddFn>, _> = lib.get(b"quiche_chlo_builder_add");
                if let Ok(f) = badd {
                    BUILDER_ADD.set(Some(*f)).ok();
                }
                let buse: Result<Symbol<BuilderUseFn>, _> = lib.get(b"quiche_config_set_chlo_builder");
                if let Ok(f) = buse {
                    BUILDER_USE.set(Some(*f)).ok();
                }
                let bfree: Result<Symbol<BuilderFreeFn>, _> = lib.get(b"quiche_chlo_builder_free");
                if let Ok(f) = bfree {
                    BUILDER_FREE.set(Some(*f)).ok();
                }

                let dgrease: Result<Symbol<DisableGreaseFn>, _> =
                    lib.get(b"SSL_disable_tls_grease");
                if let Ok(f) = dgrease {
                    DISABLE_GREASE.set(Some(*f)).ok();
                }

                let dhello: Result<Symbol<DeterministicFn>, _> =
                    lib.get(b"SSL_set_deterministic_hello");
                if let Ok(f) = dhello {
                    SET_DETERMINISTIC.set(Some(*f)).ok();
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

    #[cfg(test)]
    {
        let mut buf = LAST_HELLO.lock().unwrap();
        buf.clear();
        buf.extend_from_slice(unsafe { std::slice::from_raw_parts(hello, len) });
    }
}

#[no_mangle]
pub unsafe extern "C" fn quiche_chlo_builder_new_wrapper() -> *mut c_void {
    let f = BUILDER_NEW.get_or_init(|| {
        load_real_symbols();
        BUILDER_NEW.get().cloned().flatten()
    });
    if let Some(real) = f.as_ref() {
        real()
    } else {
        std::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn quiche_chlo_builder_add_wrapper(
    builder: *mut c_void,
    data: *const u8,
    len: usize,
) {
    let f = BUILDER_ADD.get_or_init(|| {
        load_real_symbols();
        BUILDER_ADD.get().cloned().flatten()
    });
    if let Some(real) = f.as_ref() {
        real(builder, data, len);
    }
}

#[no_mangle]
pub unsafe extern "C" fn quiche_config_set_chlo_builder_wrapper(
    cfg: *mut c_void,
    builder: *mut c_void,
) {
    let f = BUILDER_USE.get_or_init(|| {
        load_real_symbols();
        BUILDER_USE.get().cloned().flatten()
    });
    if let Some(real) = f.as_ref() {
        real(cfg, builder);
    }
}

#[no_mangle]
pub unsafe extern "C" fn quiche_chlo_builder_free_wrapper(builder: *mut c_void) {
    let f = BUILDER_FREE.get_or_init(|| {
        load_real_symbols();
        BUILDER_FREE.get().cloned().flatten()
    });
    if let Some(real) = f.as_ref() {
        real(builder);
    }
}

#[no_mangle]
pub unsafe extern "C" fn quiche_ssl_disable_tls_grease(ssl: *mut c_void, val: i32) {
    let f = DISABLE_GREASE.get_or_init(|| {
        load_real_symbols();
        DISABLE_GREASE.get().cloned().flatten()
    });
    if let Some(real) = f.as_ref() {
        real(ssl, val);
    }
}

#[no_mangle]
pub unsafe extern "C" fn quiche_ssl_set_deterministic_hello(ssl: *mut c_void, val: i32) {
    let f = SET_DETERMINISTIC.get_or_init(|| {
        load_real_symbols();
        SET_DETERMINISTIC.get().cloned().flatten()
    });
    if let Some(real) = f.as_ref() {
        real(ssl, val);
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
