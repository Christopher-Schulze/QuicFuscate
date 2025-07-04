#[cfg(unix)]
use crate::optimize::ZeroCopyBuffer;
#[cfg(unix)]
use std::io::{self, Error, ErrorKind};
#[cfg(unix)]
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(unix)]
pub struct XdpSocket {
    socket: std::net::UdpSocket,
}

#[cfg(unix)]
impl XdpSocket {
    /// Attempts to create a new XDP-enabled UDP socket bound to `bind_addr` and connected to `remote_addr`.
    pub fn new(bind_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(bind_addr)?;
        socket.connect(remote_addr)?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket })
    }

    /// Returns the raw file descriptor of the underlying socket.
    fn fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// Sends the provided buffers using `sendmsg` for zero-copy transmission.
    pub fn send(&self, buffers: &[&[u8]]) -> io::Result<usize> {
        let zc = ZeroCopyBuffer::new(buffers);
        let ret = zc.send(self.fd());
        if ret < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    /// Receives data into the provided buffer.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf)
    }
}

#[cfg(not(unix))]
pub struct XdpSocket;

#[cfg(not(unix))]
impl XdpSocket {
    pub fn new(_bind: SocketAddr, _remote: SocketAddr) -> io::Result<Self> {
        Err(Error::new(ErrorKind::Other, "XDP sockets not supported"))
    }
}

impl XdpSocket {
    /// Checks if XDP sockets are supported on the current platform.
    pub fn is_supported() -> bool {
        cfg!(target_os = "linux")
    }
}
