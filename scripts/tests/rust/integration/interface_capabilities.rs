use quicfuscate::interface::{tun_capabilities, validate_tun_runtime_requirements};

#[test]
fn test_tun_capabilities_report_matches_target() {
    let caps = tun_capabilities();
    assert_eq!(
        caps.built_in,
        cfg!(target_os = "linux") || cfg!(target_os = "android") || cfg!(target_os = "macos")
    );
    assert_eq!(caps.supports_raw_fd, cfg!(unix));
    assert_eq!(
        caps.supports_zero_copy,
        cfg!(target_os = "linux") || cfg!(target_os = "android") || cfg!(target_os = "macos")
    );
}

#[test]
fn test_tun_runtime_requirement_helper_matches_capabilities() {
    let caps = tun_capabilities();
    let result = validate_tun_runtime_requirements();
    let should_be_ok = caps.built_in || caps.external_factory_registered;
    assert_eq!(
        result.is_ok(),
        should_be_ok,
        "runtime requirement validation must match reported capabilities"
    );
}

#[test]
fn test_tun_open_rejects_invalid_mtu_before_platform_handling() {
    let pool = quicfuscate::optimize::global_pool();
    let cfg = quicfuscate::interface::TunConfig {
        name: None,
        ip: None,
        netmask: None,
        mtu: 500,
        zero_copy: true,
        ip6: None,
        prefix6: None,
    };
    let err =
        quicfuscate::interface::TunInterface::open(cfg, pool).expect_err("invalid mtu must fail");
    assert!(matches!(err, quicfuscate::interface::TunError::Config(_)));
}

#[cfg(any(target_os = "windows", target_os = "ios"))]
#[test]
fn test_tun_open_requires_external_factory_on_factory_platforms() {
    if tun_capabilities().external_factory_registered {
        return;
    }
    let pool = quicfuscate::optimize::global_pool();
    let cfg = quicfuscate::interface::TunConfig::default();
    let err = quicfuscate::interface::TunInterface::open(cfg, pool)
        .expect_err("TunInterface::open must fail without external factory on windows/ios targets");
    assert!(matches!(err, quicfuscate::interface::TunError::Config(_)));
}

#[cfg(any(target_os = "windows", target_os = "ios"))]
#[test]
fn test_factory_registration_selection_and_failure_path() {
    use quicfuscate::interface::{
        register_tun_factory, TunConfig, TunDevice, TunError, TunInterface,
    };
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    if tun_capabilities().external_factory_registered {
        return;
    }

    struct DummyTun;
    impl TunDevice for DummyTun {
        fn name(&self) -> &str {
            "dummy-tun"
        }
        fn mtu(&self) -> u16 {
            1500
        }
        fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
        fn write(&self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
    }

    let call_count = Arc::new(AtomicUsize::new(0));
    let call_count_cb = Arc::clone(&call_count);
    let registered = register_tun_factory(Box::new(move |_cfg: &TunConfig| {
        let idx = call_count_cb.fetch_add(1, Ordering::Relaxed);
        if idx == 0 {
            Err(io::Error::new(io::ErrorKind::Other, "factory failure on first call"))
        } else {
            Ok(Box::new(DummyTun) as Box<dyn TunDevice>)
        }
    }));
    assert!(registered, "expected first factory registration to succeed");

    let pool = quicfuscate::optimize::global_pool();
    let cfg = TunConfig::default();
    let first = TunInterface::open(cfg.clone(), Arc::clone(&pool));
    assert!(matches!(first, Err(TunError::Io(_))), "first call should surface factory failure");

    let second = TunInterface::open(cfg, pool);
    assert!(second.is_ok(), "second call should use registered factory successfully");
}
