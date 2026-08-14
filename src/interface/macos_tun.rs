//! macOS utun implementation and its platform-local regression coverage.

use super::*;

use std::mem;
use std::os::fd::RawFd;
use std::process::Command;
use std::sync::atomic::{AtomicU16, Ordering};

// PF_SYSTEM/SYSPROTO_CONTROL utun open
const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;
const AF_SYS_CONTROL: u16 = 2; // AF_SYSTEM subtype
const SYSPROTO_CONTROL: libc::c_int = 2;
const UTUN_OPT_IFNAME: libc::c_int = 2;
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}
#[repr(C)]
struct SockAddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

/// macOS utun device via PF_SYSTEM/SYSPROTO_CONTROL.
pub struct MacTun {
    fd: RawFd,
    name: Arc<str>,
    mtu: AtomicU16,
}

impl MacTun {
    fn run_ifconfig(args: &[&str]) -> io::Result<()> {
        let output = Command::new("/sbin/ifconfig")
            .args(args)
            .output()
            .map_err(|error| io::Error::other(format!("ifconfig spawn: {error}")))?;
        if output.status.success() {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "ifconfig {} returned status {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }

    fn read_mtu(name: &str) -> io::Result<u16> {
        let output = Command::new("/sbin/ifconfig")
            .arg(name)
            .output()
            .map_err(|error| io::Error::other(format!("ifconfig inspect spawn: {error}")))?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "ifconfig {name} inspect returned status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let tokens: Vec<&str> = stdout.split_whitespace().collect();
        let mtu = tokens
            .windows(2)
            .find(|pair| pair[0] == "mtu")
            .and_then(|pair| pair[1].parse::<u16>().ok())
            .ok_or_else(|| io::Error::other("ifconfig inspection omitted MTU"))?;
        Ok(mtu)
    }

    fn configure(name: &str, cfg: &TunConfig) -> io::Result<u16> {
        if let (Some(IpAddr::V4(address)), Some(IpAddr::V4(netmask))) = (cfg.ip, cfg.netmask) {
            let address = address.to_string();
            let netmask = netmask.to_string();
            Self::run_ifconfig(&[name, "inet", &address, "netmask", &netmask, "up"])?;
        }
        if let (Some(address), Some(prefix)) = (cfg.ip6, cfg.prefix6) {
            let address = address.to_string();
            let prefix = prefix.to_string();
            Self::run_ifconfig(&[name, "inet6", &address, "prefixlen", &prefix, "up"])?;
        }
        let mtu = cfg.mtu.to_string();
        Self::run_ifconfig(&[name, "mtu", &mtu, "up"])?;
        let verified = Self::read_mtu(name)?;
        if verified != cfg.mtu {
            return Err(io::Error::other(format!(
                "macOS utun reported MTU {verified} after requesting {}",
                cfg.mtu
            )));
        }
        Ok(verified)
    }

    fn set_device_mtu(name: &str, mtu: u16) -> io::Result<()> {
        let mtu_text = mtu.to_string();
        Self::run_ifconfig(&[name, "mtu", &mtu_text])?;
        let verified = Self::read_mtu(name)?;
        if verified != mtu {
            return Err(io::Error::other(format!(
                "macOS utun reported MTU {verified} after requesting {mtu}"
            )));
        }
        Ok(())
    }

    fn interface_exists(name: &str) -> io::Result<bool> {
        let output = Command::new("/sbin/ifconfig")
            .arg(name)
            .output()
            .map_err(|error| io::Error::other(format!("ifconfig inspect spawn: {error}")))?;
        if output.status.success() {
            return Ok(true);
        }
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if stderr.contains("does not exist") || stderr.contains("no such") {
            return Ok(false);
        }
        Err(io::Error::other(format!(
            "ifconfig {name} inspect returned status {}: {}",
            output.status,
            stderr.trim()
        )))
    }

    fn rollback_open_error(
        fd: &mut RawFd,
        connected: bool,
        name: Option<&str>,
        primary: io::Error,
    ) -> io::Error {
        let close_error = close_owned_fd(fd).err();
        let cleanup_error = if close_error.is_none() && connected {
            match name {
                Some(name) => match Self::interface_exists(name) {
                    Ok(false) => None,
                    Ok(true) => Some(io::Error::other(format!(
                        "utun interface {name} remains after descriptor close"
                    ))),
                    Err(error) => Some(error),
                },
                None => Some(io::Error::other(
                    "utun interface identity is unavailable; absence cannot be proven",
                )),
            }
        } else {
            None
        };
        if close_error.is_none() && cleanup_error.is_none() {
            return primary;
        }
        let mut message = format!("macOS utun setup failed: {primary}");
        if let Some(error) = close_error {
            message.push_str(&format!("; descriptor close failed: {error}"));
        }
        if let Some(error) = cleanup_error {
            message.push_str(&format!("; interface rollback failed: {error}"));
        }
        io::Error::other(message)
    }

    fn writev_iovecs(
        hdr: &mut [u8; 4],
        buf: &[u8],
        written: usize,
    ) -> io::Result<[libc::iovec; 2]> {
        let total = 4usize.checked_add(buf.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "utun packet length overflow")
        })?;
        if written >= total {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "utun writev progress is outside the packet",
            ));
        }
        if written < 4 {
            // SAFETY: written < 4 proves the header pointer offset is in bounds.
            let header_ptr = unsafe { hdr.as_mut_ptr().add(written) };
            return Ok([
                libc::iovec { iov_base: header_ptr as *mut libc::c_void, iov_len: 4 - written },
                libc::iovec { iov_base: buf.as_ptr() as *mut libc::c_void, iov_len: buf.len() },
            ]);
        }
        let payload_offset = written - 4;
        // written < total proves payload_offset < buf.len() here.
        // SAFETY: The checked offset is strictly inside the payload.
        let payload_ptr = unsafe { buf.as_ptr().add(payload_offset) };
        Ok([
            libc::iovec { iov_base: hdr.as_mut_ptr() as *mut libc::c_void, iov_len: 0 },
            libc::iovec {
                iov_base: payload_ptr as *mut libc::c_void,
                iov_len: buf.len() - payload_offset,
            },
        ])
    }

    /// Open a macOS utun device with the given configuration.
    pub fn open(cfg: &TunConfig) -> io::Result<Self> {
        let mut fd = unsafe { libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut info: CtlInfo = unsafe { mem::zeroed() };
        info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);
        let rc = unsafe { libc::ioctl(fd, CTLIOCGINFO, &mut info) };
        if rc < 0 {
            let error = io::Error::last_os_error();
            return Err(Self::rollback_open_error(&mut fd, false, None, error));
        }

        let mut addr: SockAddrCtl = unsafe { mem::zeroed() };
        addr.sc_len = mem::size_of::<SockAddrCtl>() as u8;
        addr.sc_family = libc::AF_SYSTEM as u8;
        addr.ss_sysaddr = AF_SYS_CONTROL;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = 0; // next available utunX
        let rc = unsafe {
            libc::connect(
                fd,
                (&addr as *const SockAddrCtl) as *const libc::sockaddr,
                mem::size_of::<SockAddrCtl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let error = io::Error::last_os_error();
            return Err(Self::rollback_open_error(&mut fd, false, None, error));
        }

        // Keep the descriptor interruptible by the cooperative reader
        // loop. `poll(2)` supplies the blocking wait and the shutdown
        // flag is checked between bounded waits.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            let error = io::Error::last_os_error();
            return Err(Self::rollback_open_error(&mut fd, true, None, error));
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            let error = io::Error::last_os_error();
            return Err(Self::rollback_open_error(&mut fd, true, None, error));
        }

        // Query interface name
        let mut ifname = [0u8; 64];
        let mut len = ifname.len() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                ifname.as_mut_ptr() as *mut libc::c_void,
                &mut len,
            )
        };
        if rc < 0 {
            let error = io::Error::last_os_error();
            return Err(Self::rollback_open_error(&mut fd, true, None, error));
        }
        let reported_len = match usize::try_from(len) {
            Ok(length) => length,
            Err(_) => {
                let error = io::Error::new(
                    io::ErrorKind::InvalidData,
                    "utun interface name length overflow",
                );
                return Err(Self::rollback_open_error(&mut fd, true, None, error));
            }
        };
        let name_s = match parse_bounded_interface_name(&ifname, reported_len) {
            Ok(name) => name,
            Err(error) => return Err(Self::rollback_open_error(&mut fd, true, None, error)),
        };
        let mtu = match Self::configure(&name_s, cfg) {
            Ok(mtu) => mtu,
            Err(error) => {
                return Err(Self::rollback_open_error(&mut fd, true, Some(&name_s), error));
            }
        };
        let name: Arc<str> = Arc::from(name_s);
        Ok(Self { fd, name, mtu: AtomicU16::new(mtu) })
    }
}

impl TunDevice for MacTun {
    fn name(&self) -> &str {
        self.name.as_ref()
    }
    fn mtu(&self) -> u16 {
        self.mtu.load(Ordering::Acquire)
    }
    fn read_contract(&self) -> TunReadContract {
        TunReadContract::NonBlocking
    }
    fn set_mtu(&self, mtu: u16) -> io::Result<()> {
        Self::set_device_mtu(self.name(), mtu)?;
        self.mtu.store(mtu, Ordering::Release);
        Ok(())
    }
    #[cfg(unix)]
    fn raw_fd(&self) -> Option<std::os::fd::RawFd> {
        Some(self.fd)
    }
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        // utun prepends 4-byte AF header; use readv to avoid extra allocation/copy
        let mut hdr = [0u8; 4];
        let mut iov = [
            libc::iovec { iov_base: hdr.as_mut_ptr() as *mut libc::c_void, iov_len: hdr.len() },
            libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() },
        ];
        loop {
            let n = unsafe { libc::readv(self.fd, iov.as_mut_ptr(), iov.len() as i32) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let total = 4usize.checked_add(buf.len()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "utun read buffer length overflow")
            })?;
            let total_read = validate_raw_read_result(n, total, "macOS utun readv")?;
            if total_read <= 4 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "macOS utun readv returned an incomplete AF header or empty packet",
                ));
            }
            return Ok(total_read - 4);
        }
    }
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        // Prepend AF header based on version (IPv6 0x60 high nibble == 6) using writev
        let af: u32 = if !buf.is_empty() && (buf[0] >> 4) == 6 {
            libc::AF_INET6 as u32
        } else {
            libc::AF_INET as u32
        };
        let mut hdr = af.to_be_bytes();
        let total = 4usize.checked_add(buf.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "utun packet length overflow")
        })?;
        let mut written = 0usize;
        while written < total {
            let iov = Self::writev_iovecs(&mut hdr, buf, written)?;
            let n = unsafe { libc::writev(self.fd, iov.as_ptr(), iov.len() as i32) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let progress = validate_raw_write_progress(n, total - written, "macOS utun writev")?;
            written = written.checked_add(progress).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "utun writev progress overflow")
            })?;
        }
        Ok(buf.len())
    }
}

impl Drop for MacTun {
    fn drop(&mut self) {
        if let Err(error) = close_owned_fd(&mut self.fd) {
            log::error!("close macOS utun descriptor failed: {error}");
        }
    }
}

/// Open the platform-native macOS utun device.
pub fn open_platform_tun(cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
    Ok(Box::new(MacTun::open(cfg)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utun_writev_iovecs_follow_bounded_progress() {
        let mut hdr = [0u8; 4];
        let payload = [1u8, 2, 3];

        let initial = MacTun::writev_iovecs(&mut hdr, &payload, 0).unwrap();
        assert_eq!(initial[0].iov_len, 4);
        assert_eq!(initial[1].iov_len, payload.len());

        let header_partial = MacTun::writev_iovecs(&mut hdr, &payload, 2).unwrap();
        assert_eq!(header_partial[0].iov_len, 2);
        assert_eq!(header_partial[1].iov_len, payload.len());

        let payload_partial = MacTun::writev_iovecs(&mut hdr, &payload, 5).unwrap();
        assert_eq!(payload_partial[0].iov_len, 0);
        assert_eq!(payload_partial[1].iov_len, 2);
        assert_eq!(payload_partial[1].iov_base as usize, payload.as_ptr() as usize + 1);

        assert!(MacTun::writev_iovecs(&mut hdr, &payload, 7).is_err());
    }
}
