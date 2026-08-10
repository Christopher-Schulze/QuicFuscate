//! Compatibility projection for the transport UDP workspace leaf.
//!
//! The low-level GSO/GRO, sendmmsg/recvmmsg, address-validation, and NIC-RPS implementation is
//! owned by `qf-transport-udp`. This adapter preserves the historical `optimize::udp` paths used
//! by the root transport and test-only batch surfaces.

pub use qf_transport_udp::{send_batch, UdpGsoConfig};

#[cfg(all(target_os = "linux", any(test, feature = "rust-tests")))]
pub use qf_transport_udp::NicParallelism;

#[cfg(unix)]
#[allow(dead_code)]
pub(crate) fn validate_datagram_len(len: usize) -> std::io::Result<()> {
    qf_transport_udp::validate_datagram_len(len)
}

#[cfg(unix)]
#[allow(dead_code)]
pub(crate) fn checked_syscall_count(
    result: libc::c_int,
    prepared: usize,
) -> std::io::Result<usize> {
    qf_transport_udp::checked_syscall_count(result, prepared)
}

#[cfg(unix)]
#[allow(dead_code)]
pub(crate) fn checked_received_len(
    result: u32,
    capacity: usize,
    index: usize,
) -> std::io::Result<usize> {
    qf_transport_udp::checked_received_len(result, capacity, index)
}

#[cfg(unix)]
#[allow(dead_code)]
pub(crate) fn sockaddr_storage_for(
    addr: std::net::SocketAddr,
) -> (libc::sockaddr_storage, libc::socklen_t) {
    qf_transport_udp::sockaddr_storage_for(addr)
}

#[cfg(unix)]
#[allow(dead_code)]
pub(crate) fn socket_addr_from_storage(
    storage: &libc::sockaddr_storage,
    length: usize,
) -> std::io::Result<std::net::SocketAddr> {
    qf_transport_udp::socket_addr_from_storage(storage, length)
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub(crate) fn send_batch_fd(
    fd: std::os::fd::RawFd,
    packets: &[(&[u8], std::net::SocketAddr)],
) -> std::io::Result<usize> {
    qf_transport_udp::send_batch_fd(fd, packets)
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub(crate) fn send_batch_connected(
    fd: std::os::fd::RawFd,
    payloads: &[&[u8]],
) -> std::io::Result<usize> {
    qf_transport_udp::send_batch_connected(fd, payloads)
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub(crate) fn recv_batch_connected(
    fd: std::os::fd::RawFd,
    bufs: &mut [&mut [u8]],
) -> std::io::Result<usize> {
    qf_transport_udp::recv_batch_connected(fd, bufs)
}
