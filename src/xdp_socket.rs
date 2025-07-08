#[cfg(unix)]
use crate::optimize::ZeroCopyBuffer;
use crate::telemetry;
#[cfg(unix)]
use std::io::{self, Error, ErrorKind};
#[cfg(unix)]
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(all(unix, feature = "xdp"))]
use thiserror::Error;

#[cfg(all(unix, feature = "xdp"))]
use {
    afxdp::{
        buf_mmap::BufMmap,
        mmap_area::{MmapArea, MmapAreaOptions},
        socket::{Socket, SocketOptions, SocketRx, SocketTx},
        umem::{Umem, UmemCompletionQueue, UmemFillQueue},
        PENDING_LEN,
    },
    arraydeque::{ArrayDeque, Wrapping},
    libbpf_sys::{XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS},
    std::sync::Arc,
};

#[cfg(all(unix, feature = "xdp"))]
struct XdpState {
    rx: SocketRx<'static, [u8; 2048]>,
    tx: SocketTx<'static, [u8; 2048]>,
    fq: UmemFillQueue<'static, [u8; 2048]>,
    cq: UmemCompletionQueue<'static, [u8; 2048]>,
    pool: Vec<BufMmap<'static, [u8; 2048]>>,
    pending: ArrayDeque<[BufMmap<'static, [u8; 2048]>; PENDING_LEN], Wrapping>,
}

#[cfg(all(unix, feature = "xdp"))]
pub struct XdpSocket {
    udp: std::net::UdpSocket,
    state: Option<XdpState>,
}

#[cfg(all(unix, not(feature = "xdp")))]
pub struct XdpSocket {
    socket: std::net::UdpSocket,
}

#[cfg(not(unix))]
pub struct XdpSocket;

#[cfg(all(unix, feature = "xdp"))]
#[derive(Debug, Error)]
pub enum XdpInitError {
    #[error("memory map failed")]
    Mmap,
    #[error("invalid ring size")]
    InvalidRing,
    #[error("umem setup failed: {0}")]
    Umem(#[source] io::Error),
    #[error("socket creation failed: {0}")]
    Socket(#[source] io::Error),
    #[error("kernel does not support AF_XDP")]
    Unsupported,
}

#[cfg(all(unix, feature = "xdp"))]
fn is_unsupported(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::ENOSYS)
            | Some(libc::EOPNOTSUPP)
            | Some(libc::EPERM)
            | Some(libc::EINVAL)
            | Some(libc::ENODEV)
            | Some(libc::EAFNOSUPPORT)
    )
}

#[cfg(all(unix, feature = "xdp"))]
impl From<afxdp::mmap_area::MmapError> for XdpInitError {
    fn from(_e: afxdp::mmap_area::MmapError) -> Self {
        XdpInitError::Mmap
    }
}

#[cfg(all(unix, feature = "xdp"))]
impl From<afxdp::umem::UmemNewError> for XdpInitError {
    fn from(e: afxdp::umem::UmemNewError) -> Self {
        match e {
            afxdp::umem::UmemNewError::RingNotPowerOfTwo => XdpInitError::InvalidRing,
            afxdp::umem::UmemNewError::Create(err) => {
                if is_unsupported(&err) {
                    XdpInitError::Unsupported
                } else {
                    XdpInitError::Umem(err)
                }
            }
        }
    }
}

#[cfg(all(unix, feature = "xdp"))]
impl From<afxdp::socket::SocketNewError> for XdpInitError {
    fn from(e: afxdp::socket::SocketNewError) -> Self {
        match e {
            afxdp::socket::SocketNewError::RingNotPowerOfTwo => XdpInitError::InvalidRing,
            afxdp::socket::SocketNewError::Create(err) => {
                if is_unsupported(&err) {
                    XdpInitError::Unsupported
                } else {
                    XdpInitError::Socket(err)
                }
            }
        }
    }
}

#[cfg(all(unix, feature = "xdp"))]
fn init_state(iface: &str) -> Result<XdpState, XdpInitError> {
    const BUF_NUM: usize = 4096;
    const BUF_LEN: usize = 2048;
    let (area, mut bufs) =
        MmapArea::new(BUF_NUM, BUF_LEN, MmapAreaOptions { huge_tlb: false })?;
    let (umem, mut cq, mut fq) = Umem::new(
        area,
        XSK_RING_CONS__DEFAULT_NUM_DESCS,
        XSK_RING_PROD__DEFAULT_NUM_DESCS,
    )?;
    let (_socket, rx, tx) = Socket::new(
        umem.clone(),
        iface,
        0,
        XSK_RING_CONS__DEFAULT_NUM_DESCS,
        XSK_RING_PROD__DEFAULT_NUM_DESCS,
        SocketOptions::default(),
    )?;
    let _ = fq.fill(&mut bufs, bufs.len());
    Ok(XdpState {
        rx,
        tx,
        fq,
        cq,
        pool: bufs,
        pending: ArrayDeque::new(),
    })
}

#[cfg(all(unix, feature = "xdp"))]
fn infer_iface(addr: &SocketAddr) -> String {
    if let Ok(iface) = std::env::var("XDP_IFACE") {
        return iface;
    }
    if addr.ip().is_loopback() {
        "lo".to_string()
    } else {
        "eth0".to_string()
    }
}

#[cfg(all(unix, feature = "xdp"))]
impl XdpSocket {
    pub fn new_udp(bind: SocketAddr, remote: SocketAddr) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(bind)?;
        socket.connect(remote)?;
        socket.set_nonblocking(true)?;
        telemetry!(telemetry::XDP_ACTIVE.set(0));
        Ok(Self {
            udp: socket,
            state: None,
        })
    }

    pub fn new(bind: SocketAddr, remote: SocketAddr) -> io::Result<Self> {
        let udp = std::net::UdpSocket::bind(bind)?;
        udp.connect(remote)?;
        udp.set_nonblocking(true)?;

        let iface = infer_iface(&bind);
        match init_state(&iface) {
            Ok(state) => {
                telemetry!(telemetry::XDP_ACTIVE.set(1));
                Ok(Self { udp, state: Some(state) })
            }
            Err(XdpInitError::Unsupported) => {
                telemetry!(telemetry::XDP_FALLBACKS.inc());
                telemetry!(telemetry::XDP_ACTIVE.set(0));
                Ok(Self { udp, state: None })
            }
            Err(e) => {
                telemetry!(telemetry::XDP_FALLBACKS.inc());
                telemetry!(telemetry::XDP_ACTIVE.set(0));
                log::warn!("XDP initialization failed: {e}");
                Ok(Self { udp, state: None })
            }
        }
    }

    pub fn reconfigure(&mut self, bind: SocketAddr, remote: SocketAddr) -> io::Result<()> {
        self.state.take();
        let udp = std::net::UdpSocket::bind(bind)?;
        udp.connect(remote)?;
        udp.set_nonblocking(true)?;

        let iface = infer_iface(&bind);
        match init_state(&iface) {
            Ok(state) => {
                self.udp = udp;
                self.state = Some(state);
                telemetry!(telemetry::XDP_ACTIVE.set(1));
                Ok(())
            }
            Err(XdpInitError::Unsupported) => {
                telemetry!(telemetry::XDP_FALLBACKS.inc());
                telemetry!(telemetry::XDP_ACTIVE.set(0));
                self.udp = udp;
                Ok(())
            }
            Err(e) => {
                telemetry!(telemetry::XDP_FALLBACKS.inc());
                telemetry!(telemetry::XDP_ACTIVE.set(0));
                log::warn!("XDP reconfigure failed: {e}");
                self.udp = udp;
                Ok(())
            }
        }
    }

    fn fd(&self) -> RawFd {
        self.udp.as_raw_fd()
    }

    pub fn send(&mut self, buffers: &[&[u8]]) -> io::Result<usize> {
        use std::time::Instant;
        if let Some(state) = self.state.as_mut() {
            let start = Instant::now();
            if let Some(mut b) = state.pool.pop() {
                let len = buffers.iter().map(|b| b.len()).sum::<usize>();
                let data = buffers[0];
                let copy_len = len.min(b.data.len());
                b.data[..copy_len].copy_from_slice(&data[..copy_len]);
                b.set_len(copy_len as u16);
                let _ = state.pending.push_back(b);
                let result = state.tx.try_send(&mut state.pending, 1);
                let sent = result.unwrap_or(0);
                let _ = state.cq.service(&mut state.pool, sent);
                if sent == 1 {
                    telemetry!(telemetry::XDP_BYTES_SENT.inc_by(copy_len as u64));
                    telemetry!(
                        telemetry::XDP_SEND_LATENCY.inc_by(start.elapsed().as_micros() as u64)
                    );
                    let tput = (copy_len as u64 * 8 * 1_000_000)
                        / start.elapsed().as_micros().max(1) as u64;
                    telemetry!(telemetry::XDP_THROUGHPUT.set((tput / 1_000_000) as i64));
                    return Ok(copy_len);
                } else if result.is_err() {
                    telemetry!(telemetry::XDP_FALLBACKS.inc());
                    telemetry!(telemetry::XDP_ACTIVE.set(0));
                    self.state = None;
                }
                state.pool.extend(state.pending.drain(..));
            }
        }
        let zc = ZeroCopyBuffer::new(buffers);
        let ret = zc.send(self.fd());
        if ret < 0 {
            Err(Error::last_os_error())
        } else {
            telemetry!(telemetry::BYTES_SENT.inc_by(ret as u64));
            Ok(ret as usize)
        }
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::time::Instant;
        if let Some(state) = self.state.as_mut() {
            let start = Instant::now();
            let mut recvq: ArrayDeque<[BufMmap<[u8; 2048]>; PENDING_LEN], Wrapping> =
                ArrayDeque::new();
            match state.rx.try_recv(&mut recvq, 1, [0u8; 2048]) {
                Ok(n) if n > 0 => {
                    if let Some(mut b) = recvq.pop_front() {
                        let len = b.get_len() as usize;
                        let copy_len = len.min(buf.len());
                        buf[..copy_len].copy_from_slice(&b.data[..copy_len]);
                        let mut temp = vec![b];
                        let _ = state.fq.fill(&mut temp, 1);
                        telemetry!(telemetry::XDP_BYTES_RECEIVED.inc_by(copy_len as u64));
                        telemetry!(
                            telemetry::XDP_RECV_LATENCY.inc_by(start.elapsed().as_micros() as u64)
                        );
                        let tput = (copy_len as u64 * 8 * 1_000_000)
                            / start.elapsed().as_micros().max(1) as u64;
                        telemetry!(telemetry::XDP_THROUGHPUT.set((tput / 1_000_000) as i64));
                        return Ok(copy_len);
                    }
                }
                Err(_) => {
                    telemetry!(telemetry::XDP_FALLBACKS.inc());
                    telemetry!(telemetry::XDP_ACTIVE.set(0));
                    self.state = None;
                }
                _ => {}
            }
        }
        let mut slice = [&mut buf[..]];
        let mut zc = ZeroCopyBuffer::new_mut(&mut slice);
        let ret = zc.recv(self.fd());
        if ret < 0 {
            Err(Error::last_os_error())
        } else {
            telemetry!(telemetry::BYTES_RECEIVED.inc_by(ret as u64));
            Ok(ret as usize)
        }
    }

    pub fn update_remote(&mut self, remote: SocketAddr) -> io::Result<()> {
        self.udp.connect(remote)
    }

    pub fn is_active(&self) -> bool {
        self.state.is_some()
    }
}

#[cfg(all(unix, not(feature = "xdp")))]
impl XdpSocket {
    pub fn new(bind_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(bind_addr)?;
        socket.connect(remote_addr)?;
        socket.set_nonblocking(true)?;
        telemetry!(telemetry::XDP_ACTIVE.set(0));
        Ok(Self { socket })
    }

    pub fn new_udp(bind_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<Self> {
        Self::new(bind_addr, remote_addr)
    }

    pub fn is_active(&self) -> bool {
        false
    }

    fn fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    pub fn send(&self, buffers: &[&[u8]]) -> io::Result<usize> {
        let zc = ZeroCopyBuffer::new(buffers);
        let ret = zc.send(self.fd());
        if ret < 0 {
            Err(Error::last_os_error())
        } else {
            telemetry!(telemetry::BYTES_SENT.inc_by(ret as u64));
            Ok(ret as usize)
        }
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut slice = [&mut buf[..]];
        let mut zc = ZeroCopyBuffer::new_mut(&mut slice);
        let ret = zc.recv(self.fd());
        if ret < 0 {
            Err(Error::last_os_error())
        } else {
            telemetry!(telemetry::BYTES_RECEIVED.inc_by(ret as u64));
            Ok(ret as usize)
        }
    }

    pub fn update_remote(&self, remote: SocketAddr) -> io::Result<()> {
        self.socket.connect(remote)
    }

    pub fn reconfigure(
        &mut self,
        bind_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> io::Result<()> {
        let socket = std::net::UdpSocket::bind(bind_addr)?;
        socket.connect(remote_addr)?;
        socket.set_nonblocking(true)?;
        self.socket = socket;
        Ok(())
    }
}

#[cfg(not(unix))]
impl XdpSocket {
    pub fn new(_bind: SocketAddr, _remote: SocketAddr) -> io::Result<Self> {
        Err(Error::new(ErrorKind::Other, "XDP sockets not supported"))
    }

    pub fn update_remote(&self, _remote: SocketAddr) -> io::Result<()> {
        Err(Error::new(ErrorKind::Other, "XDP sockets not supported"))
    }

    pub fn reconfigure(&mut self, _bind: SocketAddr, _remote: SocketAddr) -> io::Result<()> {
        Err(Error::new(ErrorKind::Other, "XDP sockets not supported"))
    }

    pub fn new_udp(_bind: SocketAddr, _remote: SocketAddr) -> io::Result<Self> {
        Err(Error::new(ErrorKind::Other, "XDP sockets not supported"))
    }

    pub fn is_active(&self) -> bool {
        false
    }
}

impl XdpSocket {
    pub fn is_supported() -> bool {
        cfg!(all(target_os = "linux", feature = "xdp"))
    }
}
