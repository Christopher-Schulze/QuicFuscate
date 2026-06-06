use libc::{c_void, iovec, msghdr, sockaddr_storage, socklen_t};
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;

#[cfg(target_os = "macos")]
extern "C" {
    fn sendmsg_x(
        s: libc::c_int,
        msgp: *const libc::msghdr,
        cnt: libc::c_uint,
        flags: libc::c_int,
    ) -> libc::c_int;
}

// =========================================================================
// UDP GSO/GRO - Generic Segmentation/Receive Offload (Linux >= 4.18)
// =========================================================================

/// UDP GSO capability detection and configuration
pub struct UdpGsoConfig {
    pub enabled: bool,
    pub max_segments: u16,
    pub gso_size: u16,
}

#[cfg(all(target_arch = "x86_64", not(feature = "simd-selfcheck")))]
use std::arch::x86_64::*;

impl UdpGsoConfig {
    /// Detect and enable UDP GSO on socket
    pub fn enable(sock: &UdpSocket) -> std::io::Result<Self> {
        let fd = sock.as_raw_fd();

        // Enable UDP_SEGMENT option (SOL_UDP = 17, UDP_SEGMENT = 103)
        const SOL_UDP: libc::c_int = 17;
        const UDP_SEGMENT: libc::c_int = 103;

        let enable: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_UDP,
                UDP_SEGMENT,
                &enable as *const _ as *const c_void,
                std::mem::size_of_val(&enable) as socklen_t,
            )
        };

        if ret == 0 {
            Ok(Self { enabled: true, max_segments: 64, gso_size: 1472 })
        } else {
            Ok(Self { enabled: false, max_segments: 1, gso_size: 0 })
        }
    }
}

// =========================================================================
// sendmmsg/recvmmsg - Batched syscalls for reduced overhead
// =========================================================================

/// Batched UDP send with sendmmsg (Linux/BSD)
#[cfg(target_os = "linux")]
pub fn send_batch(sock: &UdpSocket, packets: &[(&[u8], SocketAddr)]) -> std::io::Result<usize> {
    send_batch_linux(sock, packets)
}

#[cfg(target_os = "linux")]
fn send_batch_linux(sock: &UdpSocket, packets: &[(&[u8], SocketAddr)]) -> std::io::Result<usize> {
    use std::mem::MaybeUninit;

    if packets.is_empty() {
        return Ok(0);
    }

    let fd = sock.as_raw_fd();
    let mut messages: Vec<libc::mmsghdr> = Vec::with_capacity(packets.len());
    let mut iovecs: Vec<iovec> = Vec::with_capacity(packets.len());
    let mut addrs: Vec<sockaddr_storage> = Vec::with_capacity(packets.len());

    for (data, addr) in packets {
        let mut storage = MaybeUninit::<sockaddr_storage>::uninit();
        let len = match addr {
            SocketAddr::V4(v4) => {
                #[cfg(target_os = "macos")]
                let raw = libc::sockaddr_in {
                    sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.ip().octets()) },
                    sin_zero: [0; 8],
                };
                #[cfg(not(target_os = "macos"))]
                let raw = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.ip().octets()) },
                    sin_zero: [0; 8],
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &raw as *const _ as *const u8,
                        storage.as_mut_ptr() as *mut u8,
                        std::mem::size_of_val(&raw),
                    );
                }
                std::mem::size_of::<libc::sockaddr_in>() as socklen_t
            }
            SocketAddr::V6(v6) => {
                #[cfg(target_os = "macos")]
                let raw = libc::sockaddr_in6 {
                    sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo(),
                    sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                    sin6_scope_id: v6.scope_id(),
                };
                #[cfg(not(target_os = "macos"))]
                let raw = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo(),
                    sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                    sin6_scope_id: v6.scope_id(),
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &raw as *const _ as *const u8,
                        storage.as_mut_ptr() as *mut u8,
                        std::mem::size_of_val(&raw),
                    );
                }
                std::mem::size_of::<libc::sockaddr_in6>() as socklen_t
            }
        };

        let storage = unsafe { storage.assume_init() };
        addrs.push(storage);

        iovecs.push(iovec { iov_base: data.as_ptr() as *mut c_void, iov_len: data.len() });
        let addr_idx = addrs.len() - 1;
        let iov_idx = iovecs.len() - 1;

        let msg_hdr = msghdr {
            msg_name: &mut addrs[addr_idx] as *mut _ as *mut c_void,
            msg_namelen: len,
            msg_iov: &mut iovecs[iov_idx] as *mut iovec,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        messages.push(libc::mmsghdr { msg_hdr, msg_len: 0 });
    }

    let ret = unsafe {
        libc::sendmmsg(
            fd,
            messages.as_mut_ptr(),
            messages.len() as libc::c_uint,
            libc::MSG_DONTWAIT,
        )
    };

    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(ret as usize)
}

/// Batched UDP send for connected sockets via sendmmsg (Linux).
///
/// This variant does not attach per-packet destination addresses and is intended
/// for pre-connected sockets in hot paths.
#[cfg(target_os = "linux")]
pub(crate) fn send_batch_connected(fd: RawFd, payloads: &[&[u8]]) -> std::io::Result<usize> {
    if payloads.is_empty() {
        return Ok(0);
    }

    let mut iovecs: Vec<iovec> = Vec::with_capacity(payloads.len());
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(payloads.len());

    for payload in payloads {
        iovecs.push(iovec { iov_base: payload.as_ptr() as *mut c_void, iov_len: payload.len() });
    }

    for iov in &mut iovecs {
        msgs.push(libc::mmsghdr {
            msg_hdr: msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: iov as *mut iovec,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            msg_len: 0,
        });
    }

    let rc =
        unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), msgs.len() as u32, libc::MSG_DONTWAIT) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}

/// Batched UDP receive for connected sockets via recvmmsg (Linux).
#[cfg(target_os = "linux")]
pub(crate) fn recv_batch_connected(fd: RawFd, bufs: &mut [&mut [u8]]) -> std::io::Result<usize> {
    if bufs.is_empty() {
        return Ok(0);
    }

    let mut iovecs: Vec<iovec> = Vec::with_capacity(bufs.len());
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(bufs.len());

    for buf in bufs.iter_mut() {
        iovecs.push(iovec { iov_base: buf.as_mut_ptr() as *mut c_void, iov_len: buf.len() });
    }

    for iov in &mut iovecs {
        msgs.push(libc::mmsghdr {
            msg_hdr: msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: iov as *mut iovec,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            msg_len: 0,
        });
    }

    let rc = unsafe {
        libc::recvmmsg(
            fd,
            msgs.as_mut_ptr(),
            msgs.len() as u32,
            libc::MSG_DONTWAIT,
            std::ptr::null_mut(),
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}

/// Batched UDP send using sendmsg_x where available (macOS/iOS).
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn send_batch(sock: &UdpSocket, packets: &[(&[u8], SocketAddr)]) -> std::io::Result<usize> {
    if packets.is_empty() {
        return Ok(0);
    }

    let fd = sock.as_raw_fd();
    let mut messages: Vec<msghdr> = Vec::with_capacity(packets.len());
    let mut iovecs: Vec<iovec> = Vec::with_capacity(packets.len());
    let mut addrs: Vec<sockaddr_storage> = Vec::with_capacity(packets.len());
    let mut addr_lens: Vec<socklen_t> = Vec::with_capacity(packets.len());

    for (data, addr) in packets {
        let mut storage: sockaddr_storage = unsafe { std::mem::zeroed() };
        let len = match addr {
            SocketAddr::V4(v4) => {
                #[cfg(target_os = "macos")]
                let raw = libc::sockaddr_in {
                    sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.ip().octets()) },
                    sin_zero: [0; 8],
                };
                #[cfg(not(target_os = "macos"))]
                let raw = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.ip().octets()) },
                    sin_zero: [0; 8],
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &raw as *const _ as *const u8,
                        &mut storage as *mut _ as *mut u8,
                        std::mem::size_of_val(&raw),
                    );
                }
                std::mem::size_of::<libc::sockaddr_in>() as socklen_t
            }
            SocketAddr::V6(v6) => {
                #[cfg(target_os = "macos")]
                let raw = libc::sockaddr_in6 {
                    sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo(),
                    sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                    sin6_scope_id: v6.scope_id(),
                };
                #[cfg(not(target_os = "macos"))]
                let raw = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo(),
                    sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                    sin6_scope_id: v6.scope_id(),
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &raw as *const _ as *const u8,
                        &mut storage as *mut _ as *mut u8,
                        std::mem::size_of_val(&raw),
                    );
                }
                std::mem::size_of::<libc::sockaddr_in6>() as socklen_t
            }
        };

        addrs.push(storage);
        addr_lens.push(len);
        iovecs.push(iovec { iov_base: data.as_ptr() as *mut c_void, iov_len: data.len() });
    }

    for i in 0..packets.len() {
        messages.push(msghdr {
            msg_name: &mut addrs[i] as *mut _ as *mut c_void,
            msg_namelen: addr_lens[i],
            msg_iov: &mut iovecs[i] as *mut iovec,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        });
    }

    let flags = libc::MSG_DONTWAIT;

    #[cfg(target_os = "macos")]
    {
        let sent = unsafe { sendmsg_x(fd, messages.as_ptr(), messages.len() as u32, flags) };
        if sent >= 0 {
            return Ok(sent as usize);
        }

        let err = std::io::Error::last_os_error();
        if !matches!(
            err.raw_os_error(),
            Some(libc::ENOSYS)
                | Some(libc::EOPNOTSUPP)
                | Some(libc::ENOTSUP)
                | Some(libc::EINVAL)
                | Some(libc::EADDRNOTAVAIL)
        ) {
            return Err(err);
        }
    }

    let mut sent = 0usize;
    for msg in &messages {
        let rc = unsafe { libc::sendmsg(fd, msg as *const _ as *const _, flags) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        sent += 1;
    }
    Ok(sent)
}

// =========================================================================
// NIC Parallelism - RSS/RPS/RFS configuration
// =========================================================================

#[cfg(target_os = "linux")]
#[cfg(any(test, feature = "rust-tests"))]
pub struct NicParallelism;

#[cfg(target_os = "linux")]
#[cfg(any(test, feature = "rust-tests"))]
impl NicParallelism {
    pub fn configure_rps(interface: &str) -> std::io::Result<()> {
        let mut sys = sysinfo::System::new();
        sys.refresh_cpu_all();
        let cpu_count = sys.cpus().len().max(1);
        let cpu_mask = (1u128 << cpu_count) - 1;
        let mask_str = format!("{:x}", cpu_mask);

        let base = format!("/sys/class/net/{}/queues", interface);
        for entry in std::fs::read_dir(&base)? {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("rx-") {
                let rps_cpus = entry.path().join("rps_cpus");
                if rps_cpus.exists() {
                    std::fs::write(&rps_cpus, &mask_str)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, UdpSocket};

    #[test]
    fn test_gso_config_fields_default_disabled() {
        // GSO enable requires a real socket; on macOS setsockopt(SOL_UDP) fails
        // gracefully returning an Ok with enabled=false
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind failed");
        let config = UdpGsoConfig::enable(&sock).expect("enable should not fail");
        // On macOS/non-Linux, GSO is unsupported so enabled=false
        #[cfg(target_os = "macos")]
        {
            assert!(!config.enabled);
            assert_eq!(config.max_segments, 1);
            assert_eq!(config.gso_size, 0);
        }
        // On Linux it may succeed or fail depending on kernel version
        #[cfg(target_os = "linux")]
        {
            // Either way, struct fields must be internally consistent
            if config.enabled {
                assert_eq!(config.max_segments, 64);
                assert_eq!(config.gso_size, 1472);
            } else {
                assert_eq!(config.max_segments, 1);
                assert_eq!(config.gso_size, 0);
            }
        }
    }

    #[test]
    fn test_send_batch_empty_returns_zero() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind failed");
        let packets: Vec<(&[u8], SocketAddr)> = vec![];
        let sent = send_batch(&sock, &packets).expect("send_batch failed on empty");
        assert_eq!(sent, 0);
    }

    #[test]
    fn test_send_batch_single_packet() {
        let recv_sock = UdpSocket::bind("127.0.0.1:0").expect("bind recv failed");
        let dest: SocketAddr = recv_sock.local_addr().expect("local_addr failed");

        let send_sock = UdpSocket::bind("127.0.0.1:0").expect("bind send failed");
        let payload = b"hello quicfuscate";
        let packets: Vec<(&[u8], SocketAddr)> = vec![(payload.as_slice(), dest)];

        let sent = send_batch(&send_sock, &packets).expect("send_batch failed");
        assert_eq!(sent, 1);

        // Verify the packet was actually received
        recv_sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).expect("set timeout");
        let mut buf = [0u8; 128];
        let (n, _from) = recv_sock.recv_from(&mut buf).expect("recv_from failed");
        assert_eq!(&buf[..n], payload);
    }

    #[test]
    fn test_send_batch_multiple_packets_to_same_dest() {
        let recv_sock = UdpSocket::bind("127.0.0.1:0").expect("bind recv failed");
        let dest: SocketAddr = recv_sock.local_addr().expect("local_addr failed");
        recv_sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).expect("set timeout");

        let send_sock = UdpSocket::bind("127.0.0.1:0").expect("bind send failed");

        let payloads: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i; 10]).collect();
        let packets: Vec<(&[u8], SocketAddr)> =
            payloads.iter().map(|p| (p.as_slice(), dest)).collect();

        let sent = send_batch(&send_sock, &packets).expect("send_batch failed");
        // sendmsg_x on macOS may return partial count; on Linux sendmmsg sends all.
        // At minimum one packet must be sent, at most all 5.
        assert!((1..=5).contains(&sent), "sent={} out of range [1,5]", sent);

        // Verify the reported number of packets were actually received
        let mut received = Vec::new();
        for _ in 0..sent {
            let mut buf = [0u8; 128];
            let (n, _) = recv_sock.recv_from(&mut buf).expect("recv_from");
            received.push(buf[..n].to_vec());
        }
        assert_eq!(received.len(), sent);
        // Each packet should be 10 bytes
        for (i, pkt) in received.iter().enumerate() {
            assert_eq!(pkt.len(), 10, "packet {} wrong length", i);
        }
    }

    #[test]
    fn test_send_batch_ipv6_loopback() {
        // IPv6 loopback may not be available on all CI hosts
        let recv_res = UdpSocket::bind("[::1]:0");
        let recv_sock = match recv_res {
            Ok(s) => s,
            Err(_) => return, // IPv6 not available, skip gracefully
        };
        let dest: SocketAddr = recv_sock.local_addr().expect("local_addr");
        recv_sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).expect("set timeout");

        let send_sock = UdpSocket::bind("[::1]:0").expect("bind send");
        let payload = b"ipv6test";
        let packets: Vec<(&[u8], SocketAddr)> = vec![(payload.as_slice(), dest)];

        let sent = send_batch(&send_sock, &packets).expect("send_batch ipv6");
        assert_eq!(sent, 1);

        let mut buf = [0u8; 64];
        let (n, _) = recv_sock.recv_from(&mut buf).expect("recv ipv6");
        assert_eq!(&buf[..n], payload);
    }
}
