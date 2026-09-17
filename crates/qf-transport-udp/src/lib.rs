#[cfg(unix)]
use libc::{c_void, iovec, msghdr, sockaddr_storage, socklen_t};
#[cfg(target_os = "linux")]
use smallvec::SmallVec;
use std::net::{SocketAddr, UdpSocket};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;

mod fastpath;

#[cfg(any(test, feature = "rust-tests"))]
pub use fastpath::aligned_buffer_len_for_rust_tests;
pub use fastpath::{likely, unlikely, UdpFastPath, MAX_BATCH_SIZE};

#[cfg(target_os = "linux")]
const UDP_BATCH_STACK: usize = 64;

#[cfg(target_os = "macos")]
extern "C" {
    fn sendmsg_x(
        s: libc::c_int,
        msgp: *const libc::msghdr,
        cnt: libc::c_uint,
        flags: libc::c_int,
    ) -> libc::c_int;
}

#[cfg(unix)]
const UDP_BATCH_LIMIT: usize = 64;

#[cfg(unix)]
const _: () = {
    assert!(std::mem::size_of::<sockaddr_storage>() >= std::mem::size_of::<libc::sockaddr_in>());
    assert!(std::mem::size_of::<sockaddr_storage>() >= std::mem::size_of::<libc::sockaddr_in6>());
    assert!(std::mem::align_of::<sockaddr_storage>() >= std::mem::align_of::<libc::sockaddr_in>());
    assert!(std::mem::align_of::<sockaddr_storage>() >= std::mem::align_of::<libc::sockaddr_in6>());
};

#[cfg(unix)]
fn validate_batch_len(len: usize) -> std::io::Result<()> {
    if len > UDP_BATCH_LIMIT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("UDP batch contains {len} datagrams; maximum is {UDP_BATCH_LIMIT}"),
        ));
    }
    Ok(())
}

#[cfg(unix)]
#[doc(hidden)]
pub fn validate_datagram_len(len: usize) -> std::io::Result<()> {
    if len > u32::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("UDP datagram length {len} exceeds the 32-bit syscall result width"),
        ));
    }
    Ok(())
}

#[cfg(unix)]
#[doc(hidden)]
pub fn checked_syscall_count(result: libc::c_int, prepared: usize) -> std::io::Result<usize> {
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let completed = usize::try_from(result).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "UDP syscall returned an unrepresentable completion count",
        )
    })?;
    if completed > prepared {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("UDP syscall returned {completed} completions for {prepared} messages"),
        ));
    }
    Ok(completed)
}

#[cfg(unix)]
#[doc(hidden)]
pub fn checked_received_len(result: u32, capacity: usize, index: usize) -> std::io::Result<usize> {
    let length = usize::try_from(result).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("received UDP length at index {index} is not representable"),
        )
    })?;
    if length > capacity {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "received UDP length {length} at index {index} exceeds buffer capacity {capacity}"
            ),
        ));
    }
    Ok(length)
}

#[cfg(unix)]
fn checked_sent_len(actual: usize, expected: usize, index: usize) -> std::io::Result<()> {
    if actual != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            format!("UDP datagram {index} completed with {actual} bytes; expected {expected}"),
        ));
    }
    Ok(())
}

#[cfg(unix)]
#[doc(hidden)]
pub fn sockaddr_storage_for(addr: SocketAddr) -> (sockaddr_storage, socklen_t) {
    // The const assertions above prove that the storage is large and aligned
    // enough for both address families. Zeroing the C storage gives every
    // padding byte a defined value before the family-specific prefix is copied.
    // SAFETY: sockaddr_storage is a plain C storage type whose size and
    // alignment are asserted above; zero initializes every byte.
    let mut storage: sockaddr_storage = unsafe { std::mem::zeroed() };
    let length = match addr {
        SocketAddr::V4(v4) => {
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            let raw = libc::sockaddr_in {
                sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.ip().octets()) },
                sin_zero: [0; 8],
            };
            #[cfg(not(any(target_os = "macos", target_os = "ios")))]
            let raw = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.ip().octets()) },
                sin_zero: [0; 8],
            };
            // SAFETY: `raw` and `storage` are valid non-overlapping byte
            // ranges, and the copied prefix is exactly the initialized C
            // sockaddr_in representation.
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
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            let raw = libc::sockaddr_in6 {
                sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                sin6_scope_id: v6.scope_id(),
            };
            #[cfg(not(any(target_os = "macos", target_os = "ios")))]
            let raw = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: `raw` and `storage` are valid non-overlapping byte
            // ranges, and the copied prefix is exactly the initialized C
            // sockaddr_in6 representation.
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
    (storage, length)
}

#[cfg(unix)]
#[doc(hidden)]
pub fn socket_addr_from_storage(
    storage: &sockaddr_storage,
    length: usize,
) -> std::io::Result<SocketAddr> {
    let family_prefix_len = std::mem::size_of::<libc::sockaddr>();
    if length > std::mem::size_of::<sockaddr_storage>() || length < family_prefix_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid UDP peer address length {length}"),
        ));
    }

    // SAFETY: `storage` is aligned as proven above, and the family field is at
    // the ABI-defined prefix of sockaddr_storage on every supported Unix.
    let family = unsafe { (*(storage as *const _ as *const libc::sockaddr)).sa_family as i32 };
    match family {
        libc::AF_INET => {
            if length < std::mem::size_of::<libc::sockaddr_in>() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "IPv4 peer address is shorter than sockaddr_in",
                ));
            }
            // SAFETY: the family and full sockaddr_in length were validated.
            let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Ok(SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(addr.sin_port),
            )))
        }
        libc::AF_INET6 => {
            if length < std::mem::size_of::<libc::sockaddr_in6>() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "IPv6 peer address is shorter than sockaddr_in6",
                ));
            }
            // SAFETY: the family and full sockaddr_in6 length were validated.
            let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr),
                u16::from_be(addr.sin6_port),
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            )))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported UDP peer address family {family}"),
        )),
    }
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

impl UdpGsoConfig {
    /// Detect UDP GSO support on socket.
    #[cfg(target_os = "linux")]
    pub fn enable(sock: &UdpSocket) -> std::io::Result<Self> {
        Self::enable_fd(sock.as_raw_fd())
    }

    /// Detect UDP GSO support on an existing socket descriptor.
    #[cfg(target_os = "linux")]
    #[doc(hidden)]
    pub fn enable_fd(fd: RawFd) -> std::io::Result<Self> {
        // UDP_SEGMENT is a per-message segment-size knob, not a boolean enable.
        // Probe support only; send paths must attach the actual segment size.
        const SOL_UDP: libc::c_int = 17;
        const UDP_SEGMENT: libc::c_int = 103;

        let mut current_size: libc::c_int = 0;
        let mut current_size_len = std::mem::size_of::<libc::c_int>() as socklen_t;
        // SAFETY: the output pointer and length pointer reference live local
        // values, and the caller supplies the socket descriptor.
        let ret = unsafe {
            libc::getsockopt(
                fd,
                SOL_UDP,
                UDP_SEGMENT,
                &mut current_size as *mut _ as *mut c_void,
                &mut current_size_len,
            )
        };

        if ret == 0 {
            Ok(Self { enabled: true, max_segments: 64, gso_size: 1472 })
        } else {
            Ok(Self { enabled: false, max_segments: 1, gso_size: 0 })
        }
    }

    /// Detect UDP GSO support on socket.
    #[cfg(not(target_os = "linux"))]
    pub fn enable(_sock: &UdpSocket) -> std::io::Result<Self> {
        Ok(Self { enabled: false, max_segments: 1, gso_size: 0 })
    }
}

/// Kernel-level UDP GSO capability probe for an existing descriptor.
///
/// `UDP_SEGMENT` is a per-message segment-size knob, so support is probed via
/// `getsockopt`; send paths still attach the actual segment size as ancillary
/// data on every send.
#[cfg(target_os = "linux")]
pub fn probe_udp_gso(fd: RawFd) -> bool {
    UdpGsoConfig::enable_fd(fd).map(|config| config.enabled).unwrap_or(false)
}

/// Enable receive-side UDP coalescing (`UDP_GRO`) on a socket.
///
/// Returns `false` when the kernel rejects the option; callers must keep the
/// per-datagram receive path in that case. When enabled, `recvmmsg` messages
/// may carry a `UDP_GRO` control message with the original segment size and a
/// payload containing several back-to-back datagrams.
#[cfg(target_os = "linux")]
pub fn enable_udp_gro_fd(fd: RawFd) -> std::io::Result<bool> {
    let val: libc::c_int = 1;
    // SAFETY: `val` outlives the synchronous setsockopt call.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_UDP,
            libc::UDP_GRO,
            &val as *const _ as *const c_void,
            std::mem::size_of_val(&val) as socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(true)
}

/// Enable receive-side UDP coalescing (`UDP_GRO`) on a socket.
#[cfg(target_os = "linux")]
pub fn enable_udp_gro(sock: &UdpSocket) -> std::io::Result<bool> {
    enable_udp_gro_fd(sock.as_raw_fd())
}

/// Disable `UDP_GRO` on a socket (best-effort).
///
/// Needed when a receiver that understands the `UDP_GRO` control message is
/// replaced by one with MTU-sized buffers: a coalesced super-buffer would
/// otherwise arrive with MSG_TRUNC and lose its tail.
#[cfg(target_os = "linux")]
pub fn disable_udp_gro_fd(fd: RawFd) -> std::io::Result<()> {
    let val: libc::c_int = 0;
    // SAFETY: `val` outlives the synchronous setsockopt call.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_UDP,
            libc::UDP_GRO,
            &val as *const _ as *const c_void,
            std::mem::size_of_val(&val) as socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Send one super-buffer as `UDP_SEGMENT` GSO datagrams (Linux).
///
/// The kernel splits `payload` into `ceil(len / segment_size)` wire datagrams;
/// every interior segment is exactly `segment_size` bytes and the final one
/// may be shorter. Returns the number of payload bytes accepted, which is
/// always `payload.len()` on success.
#[cfg(target_os = "linux")]
pub fn send_udp_segment(
    fd: RawFd,
    addr: SocketAddr,
    payload: &[u8],
    segment_size: u16,
) -> std::io::Result<usize> {
    validate_datagram_len(payload.len())?;
    if segment_size == 0 || payload.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "UDP GSO requires a non-empty payload and a non-zero segment size",
        ));
    }

    let (storage, storage_len) = sockaddr_storage_for(addr);
    let iov = iovec { iov_base: payload.as_ptr() as *mut c_void, iov_len: payload.len() };

    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as usize;
    #[repr(align(8))]
    struct CmsgStorage([u8; 64]);
    let mut cmsg_buf = CmsgStorage([0u8; 64]);
    if cmsg_space > cmsg_buf.0.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "UDP GSO control message exceeds stack buffer",
        ));
    }

    // SAFETY: `storage`, `iov`, and `cmsg_buf` stay alive and immovable for the
    // duration of the synchronous sendmsg call.
    unsafe {
        let mut msg: msghdr = std::mem::zeroed();
        msg.msg_name = &storage as *const _ as *mut c_void;
        msg.msg_namelen = storage_len;
        msg.msg_iov = &iov as *const _ as *mut iovec;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.0.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_space;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP GSO control header unavailable",
            ));
        }
        (*cmsg).cmsg_level = libc::SOL_UDP;
        (*cmsg).cmsg_type = libc::UDP_SEGMENT;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as usize;
        *(libc::CMSG_DATA(cmsg) as *mut u16) = segment_size;

        let sent = libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT);
        if sent < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let sent_bytes = usize::try_from(sent).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "UDP GSO returned an unrepresentable byte count",
            )
        })?;
        if sent_bytes != payload.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                format!(
                    "UDP GSO datagram completed with {sent_bytes} bytes; expected {}",
                    payload.len()
                ),
            ));
        }
        Ok(sent_bytes)
    }
}

/// One datagram slot completed by [`recv_batch_gro`].
///
/// `gso_size > 0` marks a kernel-coalesced buffer: the slot holds
/// `ceil(len / gso_size)` original datagrams stored back-to-back, with the
/// final segment possibly shorter than `gso_size`. `addr` is `Some` when the
/// caller requested peer capture (unconnected sockets).
#[cfg(target_os = "linux")]
pub struct RecvSlot {
    pub len: usize,
    pub addr: Option<SocketAddr>,
    pub gso_size: u16,
}

/// `recvmmsg` into caller-provided buffers with `UDP_GRO` ancillary parsing.
///
/// Fills up to `bufs.len()` messages in one syscall and returns one
/// [`RecvSlot`] per completed message. Set `capture_addr` for unconnected
/// sockets to receive the peer address per message. A `WouldBlock` result
/// yields zero records, not an error. The stack-backed `SmallVec` keeps the
/// drain allocation-free.
#[cfg(target_os = "linux")]
pub fn recv_batch_gro(
    fd: RawFd,
    bufs: &mut [&mut [u8]],
    capture_addr: bool,
) -> std::io::Result<SmallVec<[RecvSlot; UDP_BATCH_STACK]>> {
    let mut out: SmallVec<[RecvSlot; UDP_BATCH_STACK]> = SmallVec::new();
    if bufs.is_empty() {
        return Ok(out);
    }
    validate_batch_len(bufs.len())?;

    #[repr(align(8))]
    struct CmsgRx([u8; 32]);

    let mut msgs: SmallVec<[libc::mmsghdr; UDP_BATCH_STACK]> = SmallVec::with_capacity(bufs.len());
    let mut iovecs: SmallVec<[iovec; UDP_BATCH_STACK]> = SmallVec::with_capacity(bufs.len());
    let mut addrs: SmallVec<[sockaddr_storage; UDP_BATCH_STACK]> =
        SmallVec::with_capacity(if capture_addr { bufs.len() } else { 0 });
    let mut cmsgs: SmallVec<[CmsgRx; UDP_BATCH_STACK]> = SmallVec::with_capacity(bufs.len());

    for buf in bufs.iter_mut() {
        iovecs.push(iovec { iov_base: buf.as_mut_ptr() as *mut c_void, iov_len: buf.len() });
        cmsgs.push(CmsgRx([0u8; 32]));
        if capture_addr {
            // SAFETY: sockaddr_storage is plain C storage; zeroing defines
            // every padding byte.
            addrs.push(unsafe { std::mem::zeroed() });
        }
    }

    for i in 0..bufs.len() {
        // SAFETY: each msghdr points at storage held alive in the SmallVecs
        // above for the duration of the synchronous syscall.
        let mut msg: msghdr = unsafe { std::mem::zeroed() };
        if capture_addr {
            msg.msg_name = &mut addrs[i] as *mut _ as *mut c_void;
            msg.msg_namelen = std::mem::size_of::<sockaddr_storage>() as u32;
        }
        msg.msg_iov = &mut iovecs[i];
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgs[i].0.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsgs[i].0.len();
        msgs.push(libc::mmsghdr { msg_hdr: msg, msg_len: 0 });
    }

    // SAFETY: `msgs`, `iovecs`, `addrs`, and `cmsgs` remain alive and immovable
    // for the duration of the synchronous recvmmsg call.
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
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(out);
        }
        return Err(error);
    }
    let completed = checked_syscall_count(rc, msgs.len())?;

    for i in 0..completed {
        if msgs[i].msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("UDP datagram at index {i} exceeded the receive buffer (MSG_TRUNC)"),
            ));
        }
        let len = checked_received_len(msgs[i].msg_len, bufs[i].len(), i)?;

        let mut gso_size = 0u16;
        // SAFETY: the kernel wrote a valid cmsg chain into `cmsgs[i]` up to
        // `msg_controllen`; CMSG_NXTHDR walks it within bounds.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msgs[i].msg_hdr);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_UDP && (*cmsg).cmsg_type == libc::UDP_GRO {
                    gso_size = *(libc::CMSG_DATA(cmsg) as *const u16);
                    break;
                }
                cmsg = libc::CMSG_NXTHDR(&msgs[i].msg_hdr, cmsg);
            }
        }

        let addr = if capture_addr {
            let addr_len = usize::try_from(msgs[i].msg_hdr.msg_namelen).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("peer address length at index {i} is not representable"),
                )
            })?;
            Some(socket_addr_from_storage(&addrs[i], addr_len)?)
        } else {
            None
        };
        out.push(RecvSlot { len, addr, gso_size });
    }
    Ok(out)
}

/// Single `recvmsg` with `UDP_GRO` ancillary parsing (Linux).
///
/// Returns `(len, peer, gso_size)`; `peer` is `Some` when `capture_addr` is
/// set (unconnected sockets). `gso_size > 0` means `buf[..len]` holds a
/// kernel-coalesced sequence of `gso_size`-aligned datagrams.
#[cfg(target_os = "linux")]
pub fn recv_msg_gro(
    fd: RawFd,
    buf: &mut [u8],
    capture_addr: bool,
) -> std::io::Result<(usize, Option<SocketAddr>, u16)> {
    #[repr(align(8))]
    struct CmsgRx([u8; 32]);

    let mut iov = iovec { iov_base: buf.as_mut_ptr() as *mut c_void, iov_len: buf.len() };
    // SAFETY: sockaddr_storage is plain C storage; zeroing defines padding.
    let mut storage: sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut cmsg_buf = CmsgRx([0u8; 32]);

    // SAFETY: `storage`, `iov`, and `cmsg_buf` stay alive and immovable for the
    // duration of the synchronous recvmsg call; `msg` then keeps the
    // kernel-written msg_controllen/msg_flags/msg_namelen for the walk below.
    let mut msg: msghdr = unsafe { std::mem::zeroed() };
    if capture_addr {
        msg.msg_name = &mut storage as *mut _ as *mut c_void;
        msg.msg_namelen = std::mem::size_of::<sockaddr_storage>() as u32;
    }
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.0.as_mut_ptr() as *mut c_void;
    msg.msg_controllen = cmsg_buf.0.len();

    let rc = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if msg.msg_flags & libc::MSG_TRUNC != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "UDP datagram exceeded the receive buffer (MSG_TRUNC)",
        ));
    }

    let mut gso_size = 0u16;
    // SAFETY: `msg` points at `cmsg_buf`, which holds the cmsg chain the
    // kernel wrote up to `msg_controllen`.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_UDP && (*cmsg).cmsg_type == libc::UDP_GRO {
                gso_size = *(libc::CMSG_DATA(cmsg) as *const u16);
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    let len = usize::try_from(rc).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "recvmsg returned an unrepresentable byte count",
        )
    })?;
    let len = checked_received_len(len as u32, buf.len(), 0)?;

    let addr = if capture_addr {
        let addr_len = usize::try_from(msg.msg_namelen).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "peer address length is not representable",
            )
        })?;
        Some(socket_addr_from_storage(&storage, addr_len)?)
    } else {
        None
    };
    Ok((len, addr, gso_size))
}

// =========================================================================
// sendmmsg/recvmmsg - Batched syscalls for reduced overhead
// =========================================================================

/// Batched UDP send with `sendmmsg` on Linux.
///
/// The returned count is the number of complete datagrams reported by the
/// kernel. It may be smaller than the input on non-blocking backpressure. A
/// partial byte result is returned as `WriteZero`, never as a complete send.
#[cfg(target_os = "linux")]
pub fn send_batch(sock: &UdpSocket, packets: &[(&[u8], SocketAddr)]) -> std::io::Result<usize> {
    send_batch_fd(sock.as_raw_fd(), packets)
}

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn send_batch_fd(fd: RawFd, packets: &[(&[u8], SocketAddr)]) -> std::io::Result<usize> {
    if packets.is_empty() {
        return Ok(0);
    }
    validate_batch_len(packets.len())?;

    let mut messages: SmallVec<[libc::mmsghdr; UDP_BATCH_STACK]> =
        SmallVec::with_capacity(packets.len());
    let mut iovecs: SmallVec<[iovec; UDP_BATCH_STACK]> = SmallVec::with_capacity(packets.len());
    let mut addrs: SmallVec<[sockaddr_storage; UDP_BATCH_STACK]> =
        SmallVec::with_capacity(packets.len());

    for (data, addr) in packets {
        validate_datagram_len(data.len())?;
        let (storage, len) = sockaddr_storage_for(*addr);
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

    // SAFETY: `messages` and its pointed-to address/iovec storage remain alive
    // and immovable for the duration of the synchronous syscall.
    let ret = unsafe {
        libc::sendmmsg(
            fd,
            messages.as_mut_ptr(),
            messages.len() as libc::c_uint,
            libc::MSG_DONTWAIT,
        )
    };

    let completed = checked_syscall_count(ret, messages.len())?;
    for (index, ((data, _), message)) in packets.iter().zip(messages.iter()).enumerate() {
        if index == completed {
            break;
        }
        checked_sent_len(
            usize::try_from(message.msg_len).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("sendmmsg returned an unrepresentable length at index {index}"),
                )
            })?,
            data.len(),
            index,
        )?;
    }

    Ok(completed)
}

/// Batched UDP send for connected sockets via sendmmsg (Linux).
///
/// This variant does not attach per-packet destination addresses and is intended
/// for pre-connected sockets in hot paths.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn send_batch_connected(fd: RawFd, payloads: &[&[u8]]) -> std::io::Result<usize> {
    if payloads.is_empty() {
        return Ok(0);
    }
    validate_batch_len(payloads.len())?;

    let mut iovecs: SmallVec<[iovec; UDP_BATCH_STACK]> = SmallVec::with_capacity(payloads.len());
    let mut msgs: SmallVec<[libc::mmsghdr; UDP_BATCH_STACK]> =
        SmallVec::with_capacity(payloads.len());

    for payload in payloads {
        validate_datagram_len(payload.len())?;
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

    // SAFETY: `msgs` and its iovec storage remain alive and immovable for the
    // duration of the synchronous syscall; the batch length is prevalidated.
    let rc =
        unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), msgs.len() as u32, libc::MSG_DONTWAIT) };
    let completed = checked_syscall_count(rc, msgs.len())?;
    for (index, (payload, message)) in payloads.iter().zip(msgs.iter()).enumerate() {
        if index == completed {
            break;
        }
        checked_sent_len(
            usize::try_from(message.msg_len).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("sendmmsg returned an unrepresentable length at index {index}"),
                )
            })?,
            payload.len(),
            index,
        )?;
    }
    Ok(completed)
}

/// Batched UDP receive for connected sockets via recvmmsg (Linux).
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn recv_batch_connected(fd: RawFd, bufs: &mut [&mut [u8]]) -> std::io::Result<usize> {
    if bufs.is_empty() {
        return Ok(0);
    }
    validate_batch_len(bufs.len())?;

    let mut iovecs: SmallVec<[iovec; UDP_BATCH_STACK]> = SmallVec::with_capacity(bufs.len());
    let mut msgs: SmallVec<[libc::mmsghdr; UDP_BATCH_STACK]> = SmallVec::with_capacity(bufs.len());

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

    // SAFETY: `msgs` and its iovec storage remain alive and immovable for the
    // duration of the synchronous syscall; the batch length is prevalidated.
    let rc = unsafe {
        libc::recvmmsg(
            fd,
            msgs.as_mut_ptr(),
            msgs.len() as u32,
            libc::MSG_DONTWAIT,
            std::ptr::null_mut(),
        )
    };
    let completed = checked_syscall_count(rc, msgs.len())?;
    for (index, (buf, message)) in bufs.iter().zip(msgs.iter()).enumerate() {
        if index == completed {
            break;
        }
        checked_received_len(message.msg_len, buf.len(), index)?;
    }
    Ok(completed)
}

/// Batched UDP send using `sendmsg_x` where available (macOS/iOS).
///
/// The returned count is the number of complete datagrams. A short byte
/// result from the scalar fallback is returned as `WriteZero`.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn send_batch(sock: &UdpSocket, packets: &[(&[u8], SocketAddr)]) -> std::io::Result<usize> {
    if packets.is_empty() {
        return Ok(0);
    }
    validate_batch_len(packets.len())?;

    let fd = sock.as_raw_fd();
    let mut messages: Vec<msghdr> = Vec::with_capacity(packets.len());
    let mut iovecs: Vec<iovec> = Vec::with_capacity(packets.len());
    let mut addrs: Vec<sockaddr_storage> = Vec::with_capacity(packets.len());
    let mut addr_lens: Vec<socklen_t> = Vec::with_capacity(packets.len());

    for (data, addr) in packets {
        validate_datagram_len(data.len())?;
        let (storage, len) = sockaddr_storage_for(*addr);
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
    let mut sent = 0usize;

    #[cfg(target_os = "macos")]
    {
        // SAFETY: all message, address, and iovec storage remains alive and
        // immovable for the synchronous platform syscall.
        let result = unsafe { sendmsg_x(fd, messages.as_ptr(), messages.len() as u32, flags) };
        if result >= 0 {
            sent = checked_syscall_count(result, messages.len())?;
        } else {
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
    }

    for (index, msg) in messages.iter().enumerate().skip(sent) {
        // SAFETY: `msg` points into the live message vector and its referenced
        // address/iovec storage remains alive for this synchronous call.
        let rc = unsafe { libc::sendmsg(fd, msg as *const _ as *const _, flags) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let bytes = usize::try_from(rc).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("sendmsg returned an unrepresentable length at index {index}"),
            )
        })?;
        checked_sent_len(bytes, packets[index].0.len(), index)?;
        sent += 1;
    }
    Ok(sent)
}

/// Portable batched UDP fallback for platforms without a multi-message syscall.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
pub fn send_batch(sock: &UdpSocket, packets: &[(&[u8], SocketAddr)]) -> std::io::Result<usize> {
    let mut sent = 0usize;
    for &(data, addr) in packets {
        let bytes = sock.send_to(data, addr)?;
        if bytes != data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "partial UDP datagram send",
            ));
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
const LINUX_INTERFACE_NAME_MAX: usize = 15;

#[cfg(target_os = "linux")]
#[cfg(any(test, feature = "rust-tests"))]
fn validate_rps_interface(interface: &str) -> std::io::Result<()> {
    if interface.is_empty()
        || !interface.is_ascii()
        || interface.len() > LINUX_INTERFACE_NAME_MAX
        || interface == "."
        || interface == ".."
        || interface.bytes().any(|byte| byte == b'/' || byte == b'\\' || byte.is_ascii_control())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "RPS interface name must be one bounded ASCII sysfs path component",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[cfg(any(test, feature = "rust-tests"))]
fn rps_cpu_mask(cpu_count: usize) -> std::io::Result<u128> {
    if !(1..=128).contains(&cpu_count) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("RPS CPU count {cpu_count} is outside the supported 1..=128 mask"),
        ));
    }
    Ok(if cpu_count == 128 { u128::MAX } else { (1u128 << cpu_count) - 1 })
}

#[cfg(target_os = "linux")]
#[cfg(any(test, feature = "rust-tests"))]
impl NicParallelism {
    pub fn configure_rps(interface: &str) -> std::io::Result<()> {
        validate_rps_interface(interface)?;
        let mut sys = sysinfo::System::new();
        sys.refresh_cpu_all();
        let cpu_count = sys.cpus().len().max(1);
        let cpu_mask = rps_cpu_mask(cpu_count)?;
        let mask_str = format!("{:x}", cpu_mask);

        let base = std::path::Path::new("/sys/class/net").join(interface).join("queues");
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
        // GSO probing requires a real socket; unsupported platforms fail gracefully
        // with enabled=false.
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

    #[cfg(unix)]
    #[test]
    fn test_udp_syscall_metadata_rejects_malformed_results() {
        assert_eq!(checked_syscall_count(2, 2).expect("valid count"), 2);
        assert_eq!(checked_received_len(0, 0, 0).expect("valid zero length"), 0);

        let count_error = checked_syscall_count(3, 2).expect_err("count must be bounded");
        assert_eq!(count_error.kind(), std::io::ErrorKind::InvalidData);

        let length_error = checked_received_len(9, 8, 4).expect_err("length must fit buffer");
        assert_eq!(length_error.kind(), std::io::ErrorKind::InvalidData);

        let partial_error = checked_sent_len(7, 8, 2).expect_err("partial send must fail");
        assert_eq!(partial_error.kind(), std::io::ErrorKind::WriteZero);

        let batch_error =
            validate_batch_len(UDP_BATCH_LIMIT + 1).expect_err("batch must be bounded");
        assert_eq!(batch_error.kind(), std::io::ErrorKind::InvalidInput);

        #[cfg(target_pointer_width = "64")]
        {
            let datagram_error =
                validate_datagram_len(u32::MAX as usize + 1).expect_err("datagram must fit u32");
            assert_eq!(datagram_error.kind(), std::io::ErrorKind::InvalidInput);
        }

        let address: SocketAddr = "127.0.0.1:4433".parse().expect("test address");
        let (storage, length) = sockaddr_storage_for(address);
        let parsed =
            socket_addr_from_storage(&storage, usize::try_from(length).expect("sockaddr length"))
                .expect("valid address metadata");
        assert_eq!(parsed, address);

        let mut unknown_family = storage;
        // SAFETY: the storage is correctly aligned and large enough for the ABI sockaddr
        // prefix; changing only the family keeps the malformed fixture in-bounds.
        unsafe {
            (*(std::ptr::addr_of_mut!(unknown_family) as *mut libc::sockaddr)).sa_family = 0;
        }
        let family_error =
            socket_addr_from_storage(&unknown_family, std::mem::size_of::<libc::sockaddr_in>())
                .expect_err("unknown address family must fail");
        assert_eq!(family_error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn test_sockaddr_storage_round_trip_requires_full_abi_length() {
        for text in ["127.0.0.1:4433", "[::1]:4433"] {
            let expected: SocketAddr = text.parse().expect("test address");
            let (storage, length) = sockaddr_storage_for(expected);
            let parsed = socket_addr_from_storage(
                &storage,
                usize::try_from(length).expect("sockaddr length"),
            )
            .expect("round-trip address");
            assert_eq!(parsed, expected);

            let short_length = usize::try_from(length).expect("sockaddr length") - 1;
            let short_error =
                socket_addr_from_storage(&storage, short_length).expect_err("short address");
            assert_eq!(short_error.kind(), std::io::ErrorKind::InvalidData);
        }

        let address: SocketAddr = "127.0.0.1:4433".parse().expect("test address");
        let (storage, _) = sockaddr_storage_for(address);
        let long_error =
            socket_addr_from_storage(&storage, std::mem::size_of::<sockaddr_storage>() + 1)
                .expect_err("oversized address");
        assert_eq!(long_error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
    #[test]
    fn test_send_batch_rejects_unrepresentable_batch_count() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind failed");
        let destination: SocketAddr = "127.0.0.1:9".parse().expect("destination");
        let payload = b"bounded";
        let packets = vec![(payload.as_slice(), destination); UDP_BATCH_LIMIT + 1];

        let error = send_batch(&sock, &packets).expect_err("batch limit must be enforced");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_rps_contract_rejects_path_traversal_and_unrepresentable_cpu_masks() {
        for interface in ["", ".", "..", "eth/0", "eth\\0", "eth\0"] {
            let error = validate_rps_interface(interface).expect_err("invalid interface");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
        assert!(validate_rps_interface("eth0").is_ok());
        assert_eq!(rps_cpu_mask(1).expect("one CPU"), 1);
        assert_eq!(rps_cpu_mask(128).expect("128 CPUs"), u128::MAX);
        assert!(rps_cpu_mask(129).is_err());
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

    /// UDP_SEGMENT sendmsg must emit exactly the segment boundaries the peer
    /// sees: one syscall produces N MTU-sized datagrams on the wire.
    #[cfg(target_os = "linux")]
    #[test]
    fn gso_segment_send_splits_on_wire() {
        use std::os::unix::io::AsRawFd;
        let recv_sock = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
        recv_sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).expect("timeout");
        let dest = recv_sock.local_addr().expect("local_addr");
        let send_sock = UdpSocket::bind("127.0.0.1:0").expect("bind send");

        if !probe_udp_gso(send_sock.as_raw_fd()) {
            return; // kernel lacks UDP_SEGMENT
        }

        // Three 600-byte segments + 250-byte tail.
        let mut payload = vec![0u8; 600 * 3 + 250];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i / 600).min(3) as u8;
        }
        let sent = send_udp_segment(send_sock.as_raw_fd(), dest, &payload, 600).expect("gso send");
        assert_eq!(sent, payload.len());

        // Wire check: receiver sees 600/600/600/250 datagrams in order.
        let expected = [600usize, 600, 600, 250];
        let mut buf = vec![0u8; 2048];
        for (seg_idx, &want) in expected.iter().enumerate() {
            let (n, from) = recv_sock.recv_from(&mut buf).expect("recv segment");
            assert_eq!(n, want, "segment {seg_idx} size");
            assert_eq!(from, send_sock.local_addr().expect("send addr"));
            assert!(buf[..n].iter().all(|&b| b == seg_idx.min(3) as u8));
        }
    }

    /// GRO-enabled receiver must report segment size via cmsg so coalesced
    /// buffers split back into original datagram boundaries.
    #[cfg(target_os = "linux")]
    #[test]
    fn gro_recv_batch_reports_segments() {
        use std::os::unix::io::AsRawFd;
        let recv_sock = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
        recv_sock.set_nonblocking(true).expect("nonblocking");
        let dest = recv_sock.local_addr().expect("local_addr");

        if !enable_udp_gro(&recv_sock).unwrap_or(false) {
            return; // kernel lacks UDP_GRO
        }
        let send_sock = UdpSocket::bind("127.0.0.1:0").expect("bind send");
        if !probe_udp_gso(send_sock.as_raw_fd()) {
            return;
        }

        let seg = 500usize;
        let mut payload = vec![0u8; seg * 2];
        payload[..seg].fill(0xAA);
        payload[seg..].fill(0xBB);
        send_udp_segment(send_sock.as_raw_fd(), dest, &payload, seg as u16).expect("gso send");

        // Give the kernel a moment to coalesce, then drain via recvmmsg.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut b1 = vec![0u8; 65535];
        let mut b2 = vec![0u8; 65535];
        let mut bufs: [&mut [u8]; 2] = [&mut b1, &mut b2];
        let records = recv_batch_gro(recv_sock.as_raw_fd(), &mut bufs, true).expect("recv gro");

        assert!(!records.is_empty());
        let first = &records[0];
        if first.gso_size as usize == seg && first.len == payload.len() {
            // Coalesced path: one record, two segments.
            assert_eq!(first.addr, Some(send_sock.local_addr().expect("send addr")));
            let data = &bufs[0][..first.len];
            assert!(data[..seg].iter().all(|&b| b == 0xAA));
            assert!(data[seg..].iter().all(|&b| b == 0xBB));
        } else {
            // Kernel delivered uncoalesced: two records, one segment each.
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].len, seg);
            assert_eq!(records[1].len, seg);
        }
    }
}
