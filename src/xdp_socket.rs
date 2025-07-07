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
        const BUF_NUM: usize = 4096;
        const BUF_LEN: usize = 2048;
        let (area, mut bufs) =
            match MmapArea::new(BUF_NUM, BUF_LEN, MmapAreaOptions { huge_tlb: false }) {
                Ok(v) => v,
                Err(e) => {
                    telemetry::XDP_FALLBACKS.inc();
                    return Ok(Self { udp, state: None });
                }
            };
        let (umem, mut cq, mut fq) = match Umem::new(
            area,
            XSK_RING_CONS__DEFAULT_NUM_DESCS,
            XSK_RING_PROD__DEFAULT_NUM_DESCS,
        ) {
            Ok(v) => v,
            Err(_) => {
                telemetry::XDP_FALLBACKS.inc();
                return Ok(Self { udp, state: None });
            }
        };

        let (socket, rx, tx) = match Socket::new(
            umem.clone(),
            &iface,
            0,
            XSK_RING_CONS__DEFAULT_NUM_DESCS,
            XSK_RING_PROD__DEFAULT_NUM_DESCS,
            SocketOptions::default(),
        ) {
            Ok(v) => v,
            Err(_) => {
                telemetry::XDP_FALLBACKS.inc();
                return Ok(Self { udp, state: None });
            }
        };

        let _ = fq.fill(&mut bufs, bufs.len());

        Ok(Self {
            udp,
            state: Some(XdpState {
                rx,
                tx,
                fq,
                cq,
                pool: bufs,
                pending: ArrayDeque::new(),
            }),
        })
    }

    fn fd(&self) -> RawFd {
        self.udp.as_raw_fd()
    }

    pub fn send(&mut self, buffers: &[&[u8]]) -> io::Result<usize> {
        if let Some(state) = self.state.as_mut() {
            if let Some(mut b) = state.pool.pop() {
                let len = buffers.iter().map(|b| b.len()).sum::<usize>();
                let data = buffers[0];
                let copy_len = len.min(b.data.len());
                b.data[..copy_len].copy_from_slice(&data[..copy_len]);
                b.set_len(copy_len as u16);
                let _ = state.pending.push_back(b);
                let sent = state.tx.try_send(&mut state.pending, 1).unwrap_or(0);
                let _ = state.cq.service(&mut state.pool, sent);
                if sent == 1 {
                    telemetry::XDP_BYTES_SENT.inc_by(copy_len as u64);
                    return Ok(copy_len);
                }
                state.pool.extend(state.pending.drain(..));
            }
        }
        let zc = ZeroCopyBuffer::new(buffers);
        let ret = zc.send(self.fd());
        if ret < 0 {
            Err(Error::last_os_error())
        } else {
            telemetry::BYTES_SENT.inc_by(ret as u64);
            Ok(ret as usize)
        }
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(state) = self.state.as_mut() {
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
                        telemetry::XDP_BYTES_RECEIVED.inc_by(copy_len as u64);
                        return Ok(copy_len);
                    }
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
            telemetry::BYTES_RECEIVED.inc_by(ret as u64);
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
            telemetry::BYTES_SENT.inc_by(ret as u64);
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
            telemetry::BYTES_RECEIVED.inc_by(ret as u64);
            Ok(ret as usize)
        }
    }

    pub fn update_remote(&self, remote: SocketAddr) -> io::Result<()> {
        self.socket.connect(remote)
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
