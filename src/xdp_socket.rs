#[cfg(unix)]
use crate::optimize::ZeroCopyBuffer;
use crate::telemetry;
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
            telemetry::BYTES_SENT.inc_by(ret as u64);
            Ok(ret as usize)
        }
    }

    /// Receives data into the provided buffer using `recvmsg` for zero-copy.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut slice = [&mut buf[..]];
        let mut zc = ZeroCopyBuffer::new_mut(&mut slice);
        let ret = zc.recv(self.fd());
        if ret < 0 {
            Err(Error::last_os_error())
        } else {
            telemetry::BYTES_RECEIVED.inc_by(ret as u64);
            Ok(ret as usize)
        }
    }

    /// Re-connects the socket to a new remote address after path migration.
    pub fn update_remote(&self, remote: SocketAddr) -> io::Result<()> {
        self.socket.connect(remote)
    }
}

#[cfg(not(unix))]
pub struct XdpSocket;

#[cfg(not(unix))]
impl XdpSocket {
    pub fn new(_bind: SocketAddr, _remote: SocketAddr) -> io::Result<Self> {
        Err(Error::new(ErrorKind::Other, "XDP sockets not supported"))
    }

    pub fn update_remote(&self, _remote: SocketAddr) -> io::Result<()> {
        Err(Error::new(ErrorKind::Other, "XDP sockets not supported"))
    }
}

impl XdpSocket {
    /// Checks if XDP sockets are supported on the current platform.
    pub fn is_supported() -> bool {
        cfg!(target_os = "linux")
    }
}
