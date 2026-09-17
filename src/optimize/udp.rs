//! Compatibility projection for the transport UDP workspace leaf.
//!
//! The low-level GSO/GRO, sendmmsg/recvmmsg, address-validation, and NIC-RPS implementation is
//! owned by `qf-transport-udp`. This adapter preserves the historical `optimize::udp` paths used
//! by the root transport and test-only batch surfaces.

pub use qf_transport_udp::{send_batch, UdpGsoConfig};

#[cfg(all(target_os = "linux", any(test, feature = "rust-tests")))]
pub use qf_transport_udp::NicParallelism;

#[cfg(target_os = "linux")]
pub(crate) fn send_batch_connected(
    fd: std::os::fd::RawFd,
    payloads: &[&[u8]],
) -> std::io::Result<usize> {
    qf_transport_udp::send_batch_connected(fd, payloads)
}

#[cfg(target_os = "linux")]
pub(crate) fn recv_batch_connected(
    fd: std::os::fd::RawFd,
    bufs: &mut [&mut [u8]],
) -> std::io::Result<usize> {
    qf_transport_udp::recv_batch_connected(fd, bufs)
}
