#![cfg(feature = "rust-tests")]

use quicfuscate::fec::FecMode;
use quicfuscate::interface::app_config::AppConfig;
use quicfuscate::interface::{register_tun_factory, TunConfig, TunDevice, TunInterface};
use quicfuscate::optimize::MemoryPool;
use quicfuscate::stealth::StealthMode;
use std::io;
use std::sync::{Arc, Mutex};

struct DummyTun {
    name: String,
    mtu: u16,
    read_buf: Arc<Mutex<Vec<u8>>>,
    writes: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl TunDevice for DummyTun {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut data = self.read_buf.lock().unwrap_or_else(|e| e.into_inner());
        if data.is_empty() {
            return Ok(0);
        }
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        data.drain(..n);
        Ok(n)
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut writes = self.writes.lock().unwrap_or_else(|e| e.into_inner());
        writes.push(buf.to_vec());
        Ok(buf.len())
    }
}

#[test]
fn app_config_parses_and_validates_defaults() {
    let cfg = AppConfig::from_toml("").expect("from_toml");
    cfg.validate().expect("validate");
}

#[test]
fn app_config_rejects_invalid_toml() {
    assert!(AppConfig::from_toml("invalid = [").is_err());
}

#[test]
fn app_config_parses_canonical_quicfuscate_toml() {
    let cfg_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config/quicfuscate.toml");
    let contents = std::fs::read_to_string(&cfg_path).expect("read config/quicfuscate.toml");
    let cfg = AppConfig::from_toml(&contents).expect("parse canonical config");
    cfg.validate().expect("validate canonical config");

    assert_eq!(cfg.fec.initial_mode, FecMode::Zero);
    assert_eq!(cfg.stealth.mode, StealthMode::Intelligent);
    assert!(cfg.stealth.use_tls_cover);
    assert!(cfg.optimize.pool_capacity > 0);
    assert!(cfg.optimize.block_size > 0);
}

#[test]
fn tun_factory_roundtrip_reads_and_writes() {
    let read_buf = Arc::new(Mutex::new(vec![1u8, 2, 3, 4]));
    let writes = Arc::new(Mutex::new(Vec::new()));
    let read_buf_factory = read_buf.clone();
    let writes_factory = writes.clone();

    let registered = register_tun_factory(Box::new(move |cfg: &TunConfig| {
        Ok(Box::new(DummyTun {
            name: cfg.name.clone().unwrap_or_else(|| "dummy0".into()),
            mtu: cfg.mtu,
            read_buf: read_buf_factory.clone(),
            writes: writes_factory.clone(),
        }))
    }));
    if !registered {
        // Another test or caller already registered a factory; skip safely.
        return;
    }

    let pool = Arc::new(MemoryPool::new(8, 2048));
    let cfg = TunConfig {
        name: Some("dummy0".into()),
        ip: None,
        netmask: None,
        mtu: 1400,
        zero_copy: true,
        ip6: None,
        prefix6: None,
    };
    let tun = TunInterface::open(cfg, pool).expect("open tun");
    assert_eq!(tun.name(), "dummy0");

    let (block, len) = tun.read_block().expect("read_block");
    assert_eq!(len, 4);
    assert_eq!(&block[..len], &[1u8, 2, 3, 4]);

    let written = tun.write(b"ping").expect("write");
    assert_eq!(written, 4);
    let recorded = writes.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0], b"ping");
}
