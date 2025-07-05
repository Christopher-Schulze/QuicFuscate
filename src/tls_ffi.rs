use std::os::raw::c_void;

/// FFI shim for injecting a custom TLS ClientHello into quiche.
///
/// Builds without the patched quiche library provide a no-op
/// implementation so that tests can run. When linked against a
/// modified quiche with support for custom ClientHello messages the
/// symbol will be overridden by the real implementation.
#[no_mangle]
pub unsafe extern "C" fn quiche_config_set_custom_tls(
    _cfg: *mut c_void,
    _hello: *const u8,
    _len: usize,
) {
    log::debug!("quiche_config_set_custom_tls stub invoked");
}
