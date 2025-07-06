#[cfg(target_os = "linux")]
use quicfuscate::xdp_socket::XdpSocket;
#[cfg(target_os = "linux")]
use std::net::UdpSocket;

#[cfg(target_os = "linux")]
#[test]
fn xdp_socket_send_recv() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind server");
    let server_addr = server.local_addr().unwrap();
    let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let xdp = XdpSocket::new(bind_addr, server_addr).expect("create xdp socket");

    let msg = b"ping";
    let sent = xdp.send(&[&msg[..]]).expect("send");
    assert_eq!(sent, msg.len());

    let mut buf = [0u8; 16];
    let (len, client_addr) = server.recv_from(&mut buf).expect("recv_from");
    assert_eq!(len, msg.len());
    assert_eq!(&buf[..len], msg);

    server.send_to(b"pong", client_addr).expect("send_to");
    let mut buf2 = [0u8; 16];
    let len2 = xdp.recv(&mut buf2).expect("recv");
    assert_eq!(len2, 4);
    assert_eq!(&buf2[..len2], b"pong");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn xdp_socket_send_recv() {
    assert!(!quicfuscate::xdp_socket::XdpSocket::is_supported());
}
