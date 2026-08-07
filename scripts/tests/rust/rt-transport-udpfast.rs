#![cfg(feature = "rust-tests")]

use quicfuscate::transport::udpfast::{aligned_buffer_len_for_rust_tests, UdpFastPath};
use std::net::SocketAddr;

#[test]
fn aligned_buffer_is_cacheline_aligned() {
    let len = aligned_buffer_len_for_rust_tests(1).expect("aligned buffer allocation");
    assert_eq!(len % 64, 0);
    assert!(len >= 64);
}

#[test]
fn udp_fastpath_initializes_and_counters_zero() {
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let fp = UdpFastPath::new(addr).expect("fastpath new");
    assert_eq!(fp.counters_for_rust_tests(), (0, 0, 0, 0));
}
