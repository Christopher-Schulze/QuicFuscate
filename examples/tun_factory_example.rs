#![cfg(feature = "tun-tests")]

// Example: Register a custom TUN factory for external platform integration.
// This uses a minimal in-process device that requires no OS privileges.

use quicfuscate::interface::{register_tun_factory, TunConfig, TunDevice, TunInterface};
use quicfuscate::optimize::MemoryPool;
use std::io;
use std::sync::Arc;

struct ExampleTun {
    name: String,
    mtu: u16,
}

impl TunDevice for ExampleTun {
    fn name(&self) -> &str {
        &self.name
    }
    fn mtu(&self) -> u16 {
        self.mtu
    }
    fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
        // No inbound traffic in this example
        Ok(0)
    }
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        println!("[ExampleTun:{}] write {} bytes", self.name, buf.len());
        Ok(buf.len())
    }
}

fn example_usage() {
    // Register the factory once. Subsequent calls will be ignored (OnceLock).
    let ok = register_tun_factory(Box::new(|cfg: &TunConfig| {
        Ok(Box::new(ExampleTun {
            name: cfg.name.clone().unwrap_or_else(|| "example0".into()),
            mtu: cfg.mtu,
        }))
    }));
    println!("Factory registered: {}", ok);

    // Open via TunInterface using the registered factory
    let pool = Arc::new(MemoryPool::new(16, 2048));
    let cfg = TunConfig {
        name: Some("example0".into()),
        mtu: 1500,
        zero_copy: true,
        ip: None,
        netmask: None,
        ip6: None,
        prefix6: None,
    };
    let tun = TunInterface::open(cfg, pool).expect("open tun");

    // Demonstrate write path
    let pkt = b"hello-tun";
    let n = tun.write(pkt).expect("write");
    println!("wrote {} bytes", n);
}

fn main() {
    println!("TUN Factory Example - tun-tests");
    example_usage();
}
