#[cfg(all(target_os = "linux", feature = "xdp"))]
mod xdp_tests {
    use quicfuscate::telemetry;
    use quicfuscate::xdp_socket::XdpSocket;
    use std::env;
    use std::net::UdpSocket;
    use std::process::Command;
    use std::time::{Duration, Instant};

    fn wait_recv(sock: &UdpSocket, buf: &mut [u8]) -> usize {
        let start = Instant::now();
        loop {
            match sock.recv(buf) {
                Ok(n) => return n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() > Duration::from_secs(1) {
                        panic!("timeout waiting for recv");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("recv failed: {e}"),
            }
        }
    }

    struct VethGuard;
    impl VethGuard {
        fn setup() -> Self {
            Command::new("ip")
                .args([
                    "link",
                    "add",
                    "veth-test0",
                    "type",
                    "veth",
                    "peer",
                    "name",
                    "veth-test1",
                ])
                .status()
                .unwrap();
            Command::new("ip")
                .args(["addr", "add", "10.5.0.1/24", "dev", "veth-test0"])
                .status()
                .unwrap();
            Command::new("ip")
                .args(["addr", "add", "10.5.0.2/24", "dev", "veth-test1"])
                .status()
                .unwrap();
            Command::new("ip")
                .args(["link", "set", "veth-test0", "up"])
                .status()
                .unwrap();
            Command::new("ip")
                .args(["link", "set", "veth-test1", "up"])
                .status()
                .unwrap();
            Self
        }
    }

    impl Drop for VethGuard {
        fn drop(&mut self) {
            let _ = Command::new("ip")
                .args(["link", "del", "veth-test0"])
                .status();
        }
    }

    fn wait_recv_xdp(sock: &XdpSocket, buf: &mut [u8]) -> usize {
        let start = Instant::now();
        loop {
            match sock.recv(buf) {
                Ok(n) => return n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() > Duration::from_secs(1) {
                        panic!("timeout waiting for recv");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("recv failed: {e}"),
            }
        }
    }

    #[test]
    fn xdp_socket_send_and_recv() {
        let _guard = VethGuard::setup();
        env::set_var("XDP_IFACE", "veth-test0");
        let xdp_addr: std::net::SocketAddr = "10.5.0.1:0".parse().unwrap();
        let udp = UdpSocket::bind("10.5.0.2:0").unwrap();
        udp.connect(xdp_addr).unwrap();
        udp.set_nonblocking(true).unwrap();
        let udp_addr = udp.local_addr().unwrap();

        let xdp = XdpSocket::new(xdp_addr, udp_addr).unwrap();
        let msg = b"hello";
        assert_eq!(xdp.send(&[msg.as_ref()]).unwrap(), msg.len());

        let mut buf = [0u8; 32];
        let n = wait_recv(&udp, &mut buf);
        assert_eq!(&buf[..n], msg);

        let reply = b"world";
        udp.send(reply).unwrap();
        let mut buf2 = [0u8; 32];
        let n2 = wait_recv_xdp(&xdp, &mut buf2);
        assert_eq!(&buf2[..n2], reply);
        env::remove_var("XDP_IFACE");
    }

    #[test]
    fn xdp_socket_migrate() {
        let _guard = VethGuard::setup();
        env::set_var("XDP_IFACE", "veth-test0");
        let xdp_addr: std::net::SocketAddr = "10.5.0.1:0".parse().unwrap();

        let udp1 = UdpSocket::bind("10.5.0.2:0").unwrap();
        udp1.connect(xdp_addr).unwrap();
        udp1.set_nonblocking(true).unwrap();
        let udp1_addr = udp1.local_addr().unwrap();

        let mut xdp = XdpSocket::new(xdp_addr, udp1_addr).unwrap();
        let start = telemetry::XDP_BYTES_SENT.get();

        let msg = b"first";
        assert_eq!(xdp.send(&[msg.as_ref()]).unwrap(), msg.len());
        let mut buf = [0u8; 32];
        let n = wait_recv(&udp1, &mut buf);
        assert_eq!(&buf[..n], msg);

        let udp2 = UdpSocket::bind("10.5.0.2:0").unwrap();
        udp2.connect(xdp_addr).unwrap();
        udp2.set_nonblocking(true).unwrap();
        let udp2_addr = udp2.local_addr().unwrap();
        xdp.reconfigure(xdp_addr, udp2_addr).unwrap();

        let msg2 = b"second";
        assert_eq!(xdp.send(&[msg2.as_ref()]).unwrap(), msg2.len());
        let mut buf2 = [0u8; 32];
        let n2 = wait_recv(&udp2, &mut buf2);
        assert_eq!(&buf2[..n2], msg2);

        assert!(telemetry::XDP_BYTES_SENT.get() >= start + (msg.len() + msg2.len()) as u64);
        env::remove_var("XDP_IFACE");
    }
}

#[cfg(all(target_os = "linux", not(feature = "xdp")))]
mod fallback_tests {
    use quicfuscate::xdp_socket::XdpSocket;
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    fn wait_recv(sock: &UdpSocket, buf: &mut [u8]) -> usize {
        let start = Instant::now();
        loop {
            match sock.recv(buf) {
                Ok(n) => return n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() > Duration::from_secs(1) {
                        panic!("timeout waiting for recv");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("recv failed: {e}"),
            }
        }
    }

    #[test]
    fn udp_fallback_send_recv() {
        let xdp_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.connect(xdp_addr).unwrap();
        udp.set_nonblocking(true).unwrap();
        let udp_addr = udp.local_addr().unwrap();

        let mut xdp = XdpSocket::new(xdp_addr, udp_addr).unwrap();
        let msg = b"hello";
        assert_eq!(xdp.send(&[msg.as_ref()]).unwrap(), msg.len());
        let mut buf = [0u8; 32];
        let n = wait_recv(&udp, &mut buf);
        assert_eq!(&buf[..n], msg);

        let reply = b"world";
        udp.send(reply).unwrap();
        let mut buf2 = [0u8; 32];
        let n2 = xdp.recv(&mut buf2).unwrap();
        assert_eq!(&buf2[..n2], reply);
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn xdp_socket_not_supported() {
    eprintln!("skipping XDP socket tests on non-linux");
}
