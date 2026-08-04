#![cfg(feature = "rust-tests")]

#[cfg(not(target_os = "linux"))]
compile_error!(
    "rt-io-hotpath-kernel-integration requires Linux; use test-transport.sh for an explicit SKIP"
);

#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::net::UdpSocket;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use quicfuscate::optimize::zc_batch;

#[test]
#[cfg(target_os = "linux")]
fn zc_batch_sendmmsg_kernel_path_sends_all_datagrams() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_secs(1))).expect("set read timeout");
    let recv_addr = receiver.local_addr().expect("receiver addr");

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    sender.connect(recv_addr).expect("connect sender");

    let payloads: Vec<&[u8]> = vec![b"kernel-alpha", b"kernel-beta", b"kernel-gamma"];
    let sent = zc_batch::sendmmsg(sender.as_raw_fd(), &payloads).expect("sendmmsg");
    assert_eq!(sent, payloads.len(), "sendmmsg should send full batch");

    let mut received = Vec::with_capacity(sent);
    for _ in 0..sent {
        let mut buf = [0u8; 256];
        let (len, _from) = receiver.recv_from(&mut buf).expect("recv datagram");
        received.push(buf[..len].to_vec());
    }

    let expected: HashSet<Vec<u8>> = payloads.iter().map(|p| p.to_vec()).collect();
    let actual: HashSet<Vec<u8>> = received.into_iter().collect();
    assert_eq!(actual, expected, "received datagrams mismatch");
}
