use super::*;

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
