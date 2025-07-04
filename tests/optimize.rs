use quicfuscate::optimize::{MemoryPool, OptimizationManager};
use quicfuscate::xdp_socket::XdpSocket;
use std::net::SocketAddr;

#[test]
fn memory_pool_alloc_free() {
    let pool = MemoryPool::new(4, 128);
    let block = pool.alloc();
    assert_eq!(block.len(), 128);
    assert_eq!((block.as_ptr() as usize) % 64, 0);
    pool.free(block);
}

#[test]
fn xdp_socket_creation() {
    let mgr = OptimizationManager::new();
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let remote: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let supported = XdpSocket::is_supported();
    assert_eq!(supported, mgr.is_xdp_available());
    let sock = mgr.create_xdp_socket(bind, remote);
    if supported {
        assert!(sock.is_some());
    } else {
        assert!(sock.is_none());
    }
}
