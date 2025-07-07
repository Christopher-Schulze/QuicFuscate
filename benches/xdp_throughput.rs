#[cfg(all(target_os = "linux", feature = "xdp"))]
mod benches {
    use criterion::{criterion_group, criterion_main, Criterion};
    use quicfuscate::xdp_socket::XdpSocket;
    use std::env;
    use std::net::UdpSocket;
    use std::process::Command;

    struct VethGuard;
    impl VethGuard {
        fn setup() -> Self {
            Command::new("ip")
                .args(["link", "add", "veth-bench0", "type", "veth", "peer", "name", "veth-bench1"])
                .status()
                .unwrap();
            Command::new("ip").args(["addr", "add", "10.6.0.1/24", "dev", "veth-bench0"]).status().unwrap();
            Command::new("ip").args(["addr", "add", "10.6.0.2/24", "dev", "veth-bench1"]).status().unwrap();
            Command::new("ip").args(["link", "set", "veth-bench0", "up"]).status().unwrap();
            Command::new("ip").args(["link", "set", "veth-bench1", "up"]).status().unwrap();
            Self
        }
    }
    impl Drop for VethGuard {
        fn drop(&mut self) {
            let _ = Command::new("ip").args(["link", "del", "veth-bench0"]).status();
        }
    }

    fn bench_throughput(c: &mut Criterion) {
        let _guard = VethGuard::setup();
        env::set_var("XDP_IFACE", "veth-bench0");
        let xdp_addr: std::net::SocketAddr = "10.6.0.1:0".parse().unwrap();
        let udp = UdpSocket::bind("10.6.0.2:0").unwrap();
        udp.connect(xdp_addr).unwrap();
        udp.set_nonblocking(true).unwrap();
        let udp_addr = udp.local_addr().unwrap();

        let mut xdp = XdpSocket::new(xdp_addr, udp_addr).unwrap();
        let msg = [0u8; 512];
        let mut buf = [0u8; 512];
        c.bench_function("xdp_send_recv", |b| {
            b.iter(|| {
                xdp.send(&[&msg]).unwrap();
                let _ = udp.recv(&mut buf).unwrap();
            });
        });
        env::remove_var("XDP_IFACE");
    }

    criterion_group!(benches, bench_throughput);
    criterion_main!(benches);
}
