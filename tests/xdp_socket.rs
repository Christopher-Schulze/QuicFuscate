#[cfg(target_os = "linux")]
mod tests {
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
}

#[cfg(not(target_os = "linux"))]
#[test]
fn xdp_socket_not_supported() {
    eprintln!("skipping XDP socket tests on non-linux");
}
