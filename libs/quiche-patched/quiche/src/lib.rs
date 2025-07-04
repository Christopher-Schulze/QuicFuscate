use std::net::{UdpSocket, SocketAddr};
use std::io::{self, ErrorKind};

/// Minimal QUIC connection stub used for tests. This implementation only
/// handles raw UDP datagrams and does not perform a real QUIC handshake.
pub struct Connection {
    sock: UdpSocket,
    peer: Option<SocketAddr>,
}

impl Connection {
    /// Create a new outgoing connection associated with the given address.
    pub fn connect(addr: &str) -> io::Result<Self> {
        let peer: SocketAddr = addr
            .parse()
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
        let bind_addr = if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let sock = UdpSocket::bind(bind_addr)?;
        sock.set_nonblocking(true)?;
        sock.connect(peer)?;
        Ok(Self { sock, peer: Some(peer) })
    }

    /// Bind a socket to the given local address for receiving datagrams.
    pub fn bind(addr: &str) -> io::Result<Self> {
        let local: SocketAddr = addr
            .parse()
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
        let sock = UdpSocket::bind(local)?;
        sock.set_nonblocking(true)?;
        Ok(Self { sock, peer: None })
    }

    /// Return the local socket address this connection is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    /// Send a packet over this connection.
    pub fn send(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(peer) = self.peer {
            self.sock.send_to(data, peer)?;
        }
        Ok(())
    }

    /// Receive a pending packet if available.
    pub fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut buf = [0u8; 65535];
        match self.sock.recv_from(&mut buf) {
            Ok((len, _)) => Ok(Some(buf[..len].to_vec())),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}
