#[cfg(any(unix, windows))]
use std::io;
#[cfg(any(unix, windows))]
use std::net::SocketAddr;

#[cfg(unix)]
use libc::{iovec, msghdr, recvmsg, sendmsg};
#[cfg(unix)]
use smallvec::SmallVec;
#[cfg(unix)]
use std::os::unix::io::RawFd;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    WSAGetLastError, WSARecv, WSARecvFrom, WSASend, WSASendTo, WSABUF,
};

/// Platform-neutral failure values for the synchronous zero-copy syscall boundary.
#[cfg(any(unix, windows))]
#[derive(Debug)]
pub enum ZeroCopyError {
    InvalidBufferCount { count: usize, max: usize },
    BufferLengthTooLarge { index: usize, length: usize, max: usize },
    TotalLengthOverflow,
    InvalidTransferCount { transferred: usize, requested: usize },
    InvalidSocketAddress,
    InvalidSocketAddressLength { length: usize, max: usize },
    Io(io::Error),
}

#[cfg(any(unix, windows))]
impl std::fmt::Display for ZeroCopyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBufferCount { count, max } => {
                write!(formatter, "zero-copy buffer count {count} exceeds platform maximum {max}")
            }
            Self::BufferLengthTooLarge { index, length, max } => write!(
                formatter,
                "zero-copy buffer {index} length {length} exceeds platform maximum {max}"
            ),
            Self::TotalLengthOverflow => {
                formatter.write_str("zero-copy buffer lengths overflow usize")
            }
            Self::InvalidTransferCount { transferred, requested } => write!(
                formatter,
                "zero-copy syscall returned {transferred} bytes for {requested} requested bytes"
            ),
            Self::InvalidSocketAddress => {
                formatter.write_str("zero-copy syscall returned a non-IP socket address")
            }
            Self::InvalidSocketAddressLength { length, max } => {
                write!(formatter, "socket address length {length} exceeds platform maximum {max}")
            }
            Self::Io(error) => write!(formatter, "zero-copy syscall failed: {error}"),
        }
    }
}

#[cfg(any(unix, windows))]
impl std::error::Error for ZeroCopyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(any(unix, windows))]
impl From<io::Error> for ZeroCopyError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(any(unix, windows))]
impl From<ZeroCopyError> for io::Error {
    fn from(error: ZeroCopyError) -> Self {
        match error {
            ZeroCopyError::Io(error) => error,
            other => {
                let kind = match &other {
                    ZeroCopyError::InvalidTransferCount { .. } => io::ErrorKind::InvalidData,
                    _ => io::ErrorKind::InvalidInput,
                };
                io::Error::new(kind, other)
            }
        }
    }
}

/// Result type for the platform-specific zero-copy boundary.
#[cfg(any(unix, windows))]
pub type ZeroCopyResult<T> = Result<T, ZeroCopyError>;

/// Explicit byte-count result for one synchronous zero-copy operation.
#[cfg(any(unix, windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroCopyTransfer {
    transferred: usize,
    requested: usize,
}

#[cfg(any(unix, windows))]
impl ZeroCopyTransfer {
    pub(crate) fn from_syscall_count(transferred: usize, requested: usize) -> ZeroCopyResult<Self> {
        if transferred > requested {
            return Err(ZeroCopyError::InvalidTransferCount { transferred, requested });
        }
        Ok(Self { transferred, requested })
    }

    pub const fn transferred(self) -> usize {
        self.transferred
    }

    pub const fn requested(self) -> usize {
        self.requested
    }

    pub const fn is_zero(self) -> bool {
        self.transferred == 0
    }

    pub const fn is_complete(self) -> bool {
        self.transferred == self.requested
    }

    pub const fn is_partial(self) -> bool {
        self.transferred != 0 && self.transferred < self.requested
    }
}

#[cfg(any(unix, windows))]
fn checked_total_buffer_length<I>(lengths: I) -> ZeroCopyResult<usize>
where
    I: Iterator<Item = usize>,
{
    let mut total = 0usize;
    for length in lengths {
        total = total.checked_add(length).ok_or(ZeroCopyError::TotalLengthOverflow)?;
    }
    Ok(total)
}

#[cfg(any(unix, windows))]
fn checked_buffer_count(count: usize, max: usize) -> ZeroCopyResult<usize> {
    if count > max {
        return Err(ZeroCopyError::InvalidBufferCount { count, max });
    }
    Ok(count)
}

#[cfg(windows)]
pub(crate) fn checked_windows_buffer_count(count: usize) -> ZeroCopyResult<u32> {
    checked_buffer_count(count, u32::MAX as usize)?;
    u32::try_from(count)
        .map_err(|_| ZeroCopyError::InvalidBufferCount { count, max: u32::MAX as usize })
}

#[cfg(windows)]
pub(crate) fn checked_windows_buffer_length(index: usize, length: usize) -> ZeroCopyResult<u32> {
    if length > u32::MAX as usize {
        return Err(ZeroCopyError::BufferLengthTooLarge { index, length, max: u32::MAX as usize });
    }
    u32::try_from(length).map_err(|_| ZeroCopyError::BufferLengthTooLarge {
        index,
        length,
        max: u32::MAX as usize,
    })
}

#[cfg(windows)]
fn last_winsock_error() -> io::Error {
    // SAFETY: WSAGetLastError has no pointer arguments and reads the calling thread's
    // Winsock error slot immediately after the failed synchronous operation.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

#[cfg(unix)]
pub(crate) fn unix_iovec_max() -> usize {
    let abi_max = i32::MAX as usize;
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "linux", target_os = "macos"))]
    {
        // A failed sysconf query is handled fail-closed. The common Linux/macOS
        // paths return the kernel's IOV_MAX value here.
        let configured = unsafe { libc::sysconf(libc::_SC_IOV_MAX) };
        if configured > 0 {
            return (configured as usize).min(abi_max);
        }
    }
    1
}

#[cfg(unix)]
fn checked_unix_iovec_count(count: usize) -> ZeroCopyResult<usize> {
    checked_buffer_count(count, unix_iovec_max())
}

#[cfg(unix)]
fn normalize_unix_count(raw: isize, requested: usize) -> ZeroCopyResult<ZeroCopyTransfer> {
    if raw < 0 {
        return Err(ZeroCopyError::Io(io::Error::last_os_error()));
    }
    ZeroCopyTransfer::from_syscall_count(raw as usize, requested)
}

/// A send-only buffer for synchronous zero-copy vectored I/O.
///
/// The input slices are borrowed for `'a` and must remain valid and unchanged for the
/// duration of every syscall using this value. `send` and `send_to` return a typed byte
/// count. `ZeroCopyTransfer::is_partial` identifies a positive short write; the wrapper
/// never retries because stream retry and datagram atomicity are caller-owned policies.
#[cfg(unix)]
pub struct ZeroCopyBuffer<'a> {
    iovecs: SmallVec<[iovec; 4]>,
    iov_count: usize,
    total_len: usize,
    _marker: std::marker::PhantomData<&'a [u8]>,
}

/// A receive-only buffer for synchronous zero-copy vectored I/O.
///
/// The outer slice and every inner mutable slice remain exclusively borrowed for `'a`,
/// preventing callers from accessing the receive regions while a syscall can write to them.
#[cfg(unix)]
pub struct ZeroCopyRecvBuffer<'a> {
    iovecs: SmallVec<[iovec; 4]>,
    iov_count: usize,
    total_len: usize,
    _marker: std::marker::PhantomData<&'a mut [&'a mut [u8]]>,
}

#[cfg(unix)]
impl<'a> ZeroCopyBuffer<'a> {
    /// Creates a send-only buffer from borrowed byte slices.
    pub fn new(buffers: &[&'a [u8]]) -> ZeroCopyResult<Self> {
        let iov_count = checked_unix_iovec_count(buffers.len())?;
        let total_len = checked_total_buffer_length(buffers.iter().map(|buffer| buffer.len()))?;
        let mut iovecs: SmallVec<[iovec; 4]> = SmallVec::with_capacity(buffers.len());
        for buffer in buffers {
            iovecs.push(iovec {
                iov_base: buffer.as_ptr() as *mut libc::c_void,
                iov_len: buffer.len(),
            });
        }
        Ok(Self { iovecs, iov_count, total_len, _marker: std::marker::PhantomData })
    }

    /// Sends the data using `sendmsg` for true zero-copy transmission.
    pub fn send(&self, fd: RawFd) -> ZeroCopyResult<ZeroCopyTransfer> {
        let msg = msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: self.iovecs.as_ptr() as *mut _,
            // `iov_count` is bounded by the runtime IOV_MAX and i32 ABI bound above.
            msg_iovlen: self.iov_count as _,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        normalize_unix_count(unsafe { sendmsg(fd, &msg, 0) }, self.total_len)
    }

    /// Sends the data to the specified address using `sendmsg`.
    pub fn send_to(&self, fd: RawFd, addr: SocketAddr) -> ZeroCopyResult<ZeroCopyTransfer> {
        use socket2::SockAddr;
        let sockaddr = SockAddr::from(addr);
        let msg = msghdr {
            msg_name: sockaddr.as_ptr() as *mut _,
            msg_namelen: sockaddr.len(),
            msg_iov: self.iovecs.as_ptr() as *mut _,
            msg_iovlen: self.iov_count as _,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        normalize_unix_count(unsafe { sendmsg(fd, &msg, 0) }, self.total_len)
    }

    pub fn len(&self) -> usize {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.iovecs.is_empty()
    }

    pub fn as_iovecs(&self) -> &[iovec] {
        &self.iovecs
    }
}

#[cfg(unix)]
impl<'a> ZeroCopyRecvBuffer<'a> {
    /// Creates a receive-only buffer from exclusively borrowed mutable slices.
    pub fn new_mut(buffers: &'a mut [&'a mut [u8]]) -> ZeroCopyResult<Self> {
        let iov_count = checked_unix_iovec_count(buffers.len())?;
        let total_len = checked_total_buffer_length(buffers.iter().map(|buffer| buffer.len()))?;
        let mut iovecs: SmallVec<[iovec; 4]> = SmallVec::with_capacity(buffers.len());
        for buffer in buffers.iter_mut() {
            iovecs.push(iovec {
                iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
                iov_len: buffer.len(),
            });
        }
        Ok(Self { iovecs, iov_count, total_len, _marker: std::marker::PhantomData })
    }

    /// Receives data using `recvmsg` into the exclusively borrowed buffers.
    pub fn recv(&mut self, fd: RawFd) -> ZeroCopyResult<ZeroCopyTransfer> {
        let mut msg = msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: self.iovecs.as_mut_ptr(),
            msg_iovlen: self.iov_count as _,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        normalize_unix_count(unsafe { recvmsg(fd, &mut msg, 0) }, self.total_len)
    }

    /// Receives data and returns the sender address.
    pub fn recv_from(&mut self, fd: RawFd) -> ZeroCopyResult<(ZeroCopyTransfer, SocketAddr)> {
        use socket2::SockAddr;
        let (received, addr) = unsafe {
            SockAddr::try_init(|storage, len| {
                let mut msg = msghdr {
                    msg_name: storage.cast(),
                    msg_namelen: *len,
                    msg_iov: self.iovecs.as_mut_ptr(),
                    msg_iovlen: self.iov_count as _,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                };
                let ret = recvmsg(fd, &mut msg, 0);
                if ret < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    *len = msg.msg_namelen;
                    Ok(ret as usize)
                }
            })
        }
        .map_err(ZeroCopyError::Io)?;
        let socket_addr = addr.as_socket().ok_or(ZeroCopyError::InvalidSocketAddress)?;
        let transfer = ZeroCopyTransfer::from_syscall_count(received, self.total_len)?;
        Ok((transfer, socket_addr))
    }

    pub fn len(&self) -> usize {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.iovecs.is_empty()
    }

    pub fn as_iovecs(&self) -> &[iovec] {
        &self.iovecs
    }
}

#[cfg(unix)]
impl Drop for ZeroCopyBuffer<'_> {
    fn drop(&mut self) {
        self.iovecs.clear();
    }
}

#[cfg(unix)]
impl Drop for ZeroCopyRecvBuffer<'_> {
    fn drop(&mut self) {
        self.iovecs.clear();
    }
}

/// A send-only buffer for scatter/gather I/O using Windows Winsock.
#[cfg(windows)]
pub struct ZeroCopyBuffer<'a> {
    bufs: Vec<WSABUF>,
    buffer_count: u32,
    total_len: usize,
    _marker: std::marker::PhantomData<&'a [u8]>,
}

/// A receive-only buffer for scatter/gather I/O using Windows Winsock.
#[cfg(windows)]
pub struct ZeroCopyRecvBuffer<'a> {
    bufs: Vec<WSABUF>,
    buffer_count: u32,
    total_len: usize,
    _marker: std::marker::PhantomData<&'a mut [&'a mut [u8]]>,
}

#[cfg(windows)]
impl<'a> ZeroCopyBuffer<'a> {
    /// Creates a send-only buffer from borrowed immutable byte slices.
    pub fn new(buffers: &[&'a [u8]]) -> ZeroCopyResult<Self> {
        let buffer_count = checked_windows_buffer_count(buffers.len())?;
        let total_len = checked_total_buffer_length(buffers.iter().map(|buffer| buffer.len()))?;
        let mut bufs = Vec::with_capacity(buffers.len());
        for (index, buffer) in buffers.iter().enumerate() {
            let len = checked_windows_buffer_length(index, buffer.len())?;
            bufs.push(WSABUF { len, buf: buffer.as_ptr() as *mut u8 });
        }
        Ok(Self { bufs, buffer_count, total_len, _marker: std::marker::PhantomData })
    }

    /// Sends all registered buffers through a connected socket.
    pub fn send(
        &self,
        sock: windows_sys::Win32::Networking::WinSock::SOCKET,
    ) -> ZeroCopyResult<ZeroCopyTransfer> {
        let mut sent = 0u32;
        let result = unsafe {
            WSASend(
                sock,
                self.bufs.as_ptr(),
                self.buffer_count,
                &mut sent,
                0,
                core::ptr::null_mut(),
                None,
            )
        };
        if result != 0 {
            return Err(ZeroCopyError::Io(last_winsock_error()));
        }
        ZeroCopyTransfer::from_syscall_count(sent as usize, self.total_len)
    }

    /// Sends all registered buffers to the specified address.
    pub fn send_to(
        &self,
        sock: windows_sys::Win32::Networking::WinSock::SOCKET,
        addr: SocketAddr,
    ) -> ZeroCopyResult<ZeroCopyTransfer> {
        use socket2::SockAddr;
        let sockaddr = SockAddr::from(addr);
        let address_length = sockaddr.len();
        let mut sent = 0u32;
        let result = unsafe {
            WSASendTo(
                sock,
                self.bufs.as_ptr(),
                self.buffer_count,
                &mut sent,
                0,
                sockaddr.as_ptr().cast(),
                address_length,
                core::ptr::null_mut(),
                None,
            )
        };
        if result != 0 {
            return Err(ZeroCopyError::Io(last_winsock_error()));
        }
        ZeroCopyTransfer::from_syscall_count(sent as usize, self.total_len)
    }

    pub fn len(&self) -> usize {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.bufs.is_empty()
    }
}

#[cfg(windows)]
impl<'a> ZeroCopyRecvBuffer<'a> {
    /// Creates a receive-only buffer from exclusively borrowed mutable slices.
    pub fn new_mut(buffers: &'a mut [&'a mut [u8]]) -> ZeroCopyResult<Self> {
        let buffer_count = checked_windows_buffer_count(buffers.len())?;
        let total_len = checked_total_buffer_length(buffers.iter().map(|buffer| buffer.len()))?;
        let mut bufs = Vec::with_capacity(buffers.len());
        for (index, buffer) in buffers.iter_mut().enumerate() {
            let len = checked_windows_buffer_length(index, buffer.len())?;
            bufs.push(WSABUF { len, buf: buffer.as_mut_ptr() });
        }
        Ok(Self { bufs, buffer_count, total_len, _marker: std::marker::PhantomData })
    }

    /// Receives data from a connected socket into the exclusively borrowed buffers.
    pub fn recv(
        &mut self,
        sock: windows_sys::Win32::Networking::WinSock::SOCKET,
    ) -> ZeroCopyResult<ZeroCopyTransfer> {
        let mut received = 0u32;
        let mut flags = 0u32;
        let result = unsafe {
            WSARecv(
                sock,
                self.bufs.as_ptr(),
                self.buffer_count,
                &mut received,
                &mut flags,
                core::ptr::null_mut(),
                None,
            )
        };
        if result != 0 {
            return Err(ZeroCopyError::Io(last_winsock_error()));
        }
        ZeroCopyTransfer::from_syscall_count(received as usize, self.total_len)
    }

    /// Receives data and returns the sender address.
    pub fn recv_from(
        &mut self,
        sock: windows_sys::Win32::Networking::WinSock::SOCKET,
    ) -> ZeroCopyResult<(ZeroCopyTransfer, SocketAddr)> {
        use socket2::SockAddr;
        let mut received_count = 0u32;
        let mut flags = 0u32;
        let (received, sockaddr) = unsafe {
            SockAddr::try_init(|storage, storage_len| {
                let result = WSARecvFrom(
                    sock,
                    self.bufs.as_ptr(),
                    self.buffer_count,
                    &mut received_count,
                    &mut flags,
                    storage.cast(),
                    storage_len,
                    core::ptr::null_mut(),
                    None,
                );
                if result == 0 {
                    Ok(received_count as usize)
                } else {
                    Err(last_winsock_error())
                }
            })
        }
        .map_err(ZeroCopyError::Io)?;
        let addr = sockaddr.as_socket().ok_or(ZeroCopyError::InvalidSocketAddress)?;
        let transfer = ZeroCopyTransfer::from_syscall_count(received, self.total_len)?;
        Ok((transfer, addr))
    }

    pub fn len(&self) -> usize {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.bufs.is_empty()
    }
}

#[cfg(windows)]
impl Drop for ZeroCopyBuffer<'_> {
    fn drop(&mut self) {
        self.bufs.clear();
    }
}

#[cfg(windows)]
impl Drop for ZeroCopyRecvBuffer<'_> {
    fn drop(&mut self) {
        self.bufs.clear();
    }
}
