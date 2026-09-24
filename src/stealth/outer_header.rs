//! Outer IP/UDP header shaping for the claimed-OS persona (TODO-1057).
//!
//! The censor reads the *outer* IP header of the client link — TTL, the DF
//! flag, and the IPv4 ID field are cheaper tells than the ClientHello. This
//! module maps the frozen persona OS to socket options applied on the client
//! UDP socket at connect time and after every disguise migration (TODO-1056),
//! because a freshly bound socket forgets them.
//!
//! Inner-packet normalization (TCP window/flags, ICMP suppression on the
//! server exit path) is unaffected — that is `fingerprint::PacketNormalizer`'s
//! job, so the destination does not see "Linux VPN" under an "iPhone" persona.
//!
//! ## Table provenance
//!
//! - TTL values follow the long-standing p0f/OS defaults (Windows 128,
//!   macOS/iOS/Linux/Android 64). These are stable, well-documented values.
//! - DF follows QUIC client reality, not the generic OS default: Chromium-
//!   family QUIC stacks enable PMTUD and emit DF=1 on IPv4; Apple's iOS
//!   stack does not set DF on UDP datagrams and iOS browsers do not run a
//!   native QUIC client, so the iOS persona keeps DF=0.
//! - IPv4 ID is not socket-controllable on Linux/macOS; when DF=1 is set the
//!   kernels emit ID=0 anyway, which matches QUIC captures. Recorded gap:
//!   per-packet ID increment policy (Windows emits a global incrementing ID)
//!   cannot be shaped without raw sockets — a documented non-goal.
//! - IPv6 carries no DF flag and no ID; only the hop limit is shaped.

use super::{OsFingerprintProfile, OsProfile};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
/// Windows sockets expose `AsRawSocket`; the alias keeps the generic bound
/// identical on every platform.
#[cfg(windows)]
use std::os::windows::io::AsRawSocket as AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};

/// Raw socket handle type handed to the platform sockopt helpers.
#[cfg(unix)]
type SocketFd = std::os::unix::io::RawFd;
#[cfg(windows)]
type SocketFd = std::os::windows::io::RawSocket;

/// Whether the "unsupported sockopt" warning already fired. The spec asks for
/// a single log line per process — repeated disguise migrations must not spam.
static OUTER_HEADER_WARNED: AtomicBool = AtomicBool::new(false);

/// Socket-level outer header policy for one persona OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsOuterHeader {
    /// IPv4 TTL / IPv6 hop limit to request. `None` leaves the OS default.
    pub ttl: Option<u8>,
    /// IPv4 Don't-Fragment policy. `Some(true)` requests DF on emitted
    /// datagrams (Linux: `IP_MTU_DISCOVER=IP_PMTUDISC_DO`, macOS:
    /// `IP_DONTFRAG`), `Some(false)` leaves DF cleared explicitly. `None`
    /// leaves the OS default untouched.
    pub df: Option<bool>,
}

/// Per-OS outer header table (TODO-1057).
///
/// `Disabled` applies nothing — an operator passthrough must not leak a
/// synthetic header shape either.
pub fn outer_header_for(os: OsProfile) -> OsOuterHeader {
    match os {
        OsProfile::Windows => OsOuterHeader { ttl: Some(128), df: Some(true) },
        OsProfile::MacOS => OsOuterHeader { ttl: Some(64), df: Some(true) },
        OsProfile::Linux => OsOuterHeader { ttl: Some(64), df: Some(true) },
        OsProfile::Android => OsOuterHeader { ttl: Some(64), df: Some(true) },
        OsProfile::IOS => OsOuterHeader { ttl: Some(64), df: Some(false) },
    }
}

/// `OsFingerprintProfile`-flavoured lookup for callers that hold the
/// normalizer profile instead of the persona OS. `Disabled` yields an
/// all-`None` policy.
pub fn outer_header_for_fingerprint(profile: OsFingerprintProfile) -> OsOuterHeader {
    match profile {
        OsFingerprintProfile::Disabled => OsOuterHeader { ttl: None, df: None },
        OsFingerprintProfile::Windows => outer_header_for(OsProfile::Windows),
        OsFingerprintProfile::MacOS => outer_header_for(OsProfile::MacOS),
        OsFingerprintProfile::Linux => outer_header_for(OsProfile::Linux),
        OsFingerprintProfile::Android => outer_header_for(OsProfile::Android),
    }
}

/// Result of applying the outer header policy to one socket.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OuterHeaderOutcome {
    /// TTL/hop-limit sockopt succeeded.
    pub ttl_applied: bool,
    /// DF sockopt succeeded (or was intentionally skipped on IPv6).
    pub df_applied: bool,
}

impl OuterHeaderOutcome {
    /// Every requested option landed on the socket.
    pub fn fully_applied(self) -> bool {
        self.ttl_applied && self.df_applied
    }
}

/// Applies the persona outer-header policy to `socket` (TODO-1057).
///
/// Works on both `std::net::UdpSocket` and `tokio::net::UdpSocket` (both
/// expose `AsRawFd`). `ipv6` selects hop-limit-only shaping — IPv6 has no DF
/// flag and no ID field, per spec. Platforms that reject a sockopt leave the
/// OS default and report `false`; callers log once and keep the connection.
pub fn apply_outer_header<S: AsRawFd>(socket: &S, os: OsProfile, ipv6: bool) -> OuterHeaderOutcome {
    let policy = outer_header_for(os);
    #[cfg(unix)]
    let fd = socket.as_raw_fd();
    #[cfg(windows)]
    let fd = socket.as_raw_socket();
    let ttl_applied = match policy.ttl {
        Some(ttl) => set_hop_limit(fd, ttl, ipv6),
        None => true, // Nothing requested — treat as applied for logging purposes.
    };
    let df_applied = if ipv6 {
        true // IPv6 has no DF; hop limit already covered above.
    } else {
        match policy.df {
            Some(df) => set_ipv4_df(fd, df),
            None => true,
        }
    };
    OuterHeaderOutcome { ttl_applied, df_applied }
}

/// Applies the policy and emits one process-wide `warn!` when a sockopt is
/// unsupported (TODO-1057 non-goal: never fail the connection over header
/// shaping — the OS default is the safe fallback).
pub fn apply_outer_header_logged<S: AsRawFd>(socket: &S, os: OsProfile, ipv6: bool) {
    let outcome = apply_outer_header(socket, os, ipv6);
    if outcome.fully_applied() {
        return;
    }
    let detail = format!(
        "outer IP/UDP header shaping unsupported by this platform (os={:?} ipv6={} ttl_applied={} df_applied={}); keeping OS defaults",
        os, ipv6, outcome.ttl_applied, outcome.df_applied
    );
    if !OUTER_HEADER_WARNED.swap(true, Ordering::Relaxed) {
        log::warn!("{}", detail);
    } else {
        log::debug!("{}", detail);
    }
}

/// Sets the IPv4 TTL (`IP_TTL`) or IPv6 hop limit (`IPV6_UNICAST_HOPS`).
#[cfg(unix)]
fn set_hop_limit(fd: SocketFd, ttl: u8, ipv6: bool) -> bool {
    let value = ttl as libc::c_int;
    let (level, name) = if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS)
    } else {
        (libc::IPPROTO_IP, libc::IP_TTL)
    };
    // SAFETY: `value` outlives the call; fd belongs to a live socket owned by
    // the caller for the duration of this function.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    rc == 0
}

/// Windows carries no `libc` sockopt surface in this build; shaping is a
/// documented non-goal there, so report unsupported like other platforms do.
#[cfg(windows)]
fn set_hop_limit(_fd: SocketFd, _ttl: u8, _ipv6: bool) -> bool {
    false
}

/// Sets or clears the IPv4 Don't-Fragment flag on emitted datagrams.
///
/// - Linux: `IP_MTU_DISCOVER = IP_PMTUDISC_DO` (2) for DF, `IP_PMTUDISC_DONT`
///   (0) to clear.
/// - macOS/BSD: `IP_DONTFRAG = 1` for DF, `0` to clear.
#[cfg(target_os = "linux")]
fn set_ipv4_df(fd: SocketFd, df: bool) -> bool {
    let value: libc::c_int = if df { libc::IP_PMTUDISC_DO as libc::c_int } else { 0 };
    // SAFETY: as above — `value` outlives the call, fd is a live socket.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    rc == 0
}

#[cfg(target_os = "macos")]
fn set_ipv4_df(fd: SocketFd, df: bool) -> bool {
    let value: libc::c_int = df as libc::c_int;
    // SAFETY: as above — `value` outlives the call, fd is a live socket.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_DONTFRAG,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    rc == 0
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn set_ipv4_df(_fd: SocketFd, _df: bool) -> bool {
    // Platforms without a DF sockopt report failure; callers keep the
    // connection on the OS default per the non-goal.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn bound_v4_socket() -> std::net::UdpSocket {
        std::net::UdpSocket::bind("127.0.0.1:0").expect("bind v4")
    }

    #[cfg(unix)]
    fn get_sockopt_int(fd: std::os::unix::io::RawFd, level: libc::c_int, name: libc::c_int) -> i32 {
        let mut value: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `value`/`len` are valid out-params for the duration of the call.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                level,
                name,
                &mut value as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt must succeed on a bound UDP socket");
        value
    }

    #[test]
    fn ios_and_linux_personas_request_different_df() {
        // Spec sub-task: the requested TTL/DF policy must differ between an
        // iOS persona and a Linux persona (DF is the discriminator; iOS keeps
        // the Apple-stack default, Linux emits QUIC PMTUD DF).
        let ios = outer_header_for(OsProfile::IOS);
        let linux = outer_header_for(OsProfile::Linux);
        assert_eq!(ios.ttl, linux.ttl, "both are 64-hop OS families");
        assert_eq!(ios.df, Some(false), "iOS keeps the Apple UDP default");
        assert_eq!(linux.df, Some(true), "Linux persona follows QUIC PMTUD");
    }

    #[test]
    fn windows_persona_requests_128_ttl() {
        let win = outer_header_for(OsProfile::Windows);
        assert_eq!(win.ttl, Some(128));
        assert_eq!(win.df, Some(true));
    }

    #[test]
    #[cfg(unix)]
    fn real_socket_accepts_persona_ttl_and_df() {
        // Real-socket proof (spec risk): apply to a bound UDP socket and read
        // the kernel-visible values back with getsockopt — the mock alone
        // would only prove the call, not the kernel acceptance.
        use std::os::unix::io::AsRawFd;
        let socket = bound_v4_socket();
        let outcome = apply_outer_header(&socket, OsProfile::Windows, false);
        let fd = socket.as_raw_fd();

        let ttl = get_sockopt_int(fd, libc::IPPROTO_IP, libc::IP_TTL);
        assert_eq!(ttl, 128, "kernel must expose the Windows TTL on the socket");

        #[cfg(target_os = "macos")]
        {
            assert!(outcome.df_applied, "macOS IP_DONTFRAG must be accepted");
            let df = get_sockopt_int(fd, libc::IPPROTO_IP, libc::IP_DONTFRAG);
            assert_eq!(df, 1, "kernel must report DF set for the Windows persona");
        }
        #[cfg(target_os = "linux")]
        {
            assert!(outcome.df_applied, "Linux IP_PMTUDISC_DO must be accepted");
            let mode = get_sockopt_int(fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER);
            assert_eq!(mode, libc::IP_PMTUDISC_DO as i32, "kernel must report PMTUD/DF");
        }
        assert!(outcome.fully_applied());
    }

    #[test]
    #[cfg(unix)]
    fn real_socket_ios_df_is_cleared() {
        use std::os::unix::io::AsRawFd;
        let socket = bound_v4_socket();
        let outcome = apply_outer_header(&socket, OsProfile::IOS, false);
        let fd = socket.as_raw_fd();

        #[cfg(target_os = "macos")]
        {
            assert!(outcome.df_applied);
            let df = get_sockopt_int(fd, libc::IPPROTO_IP, libc::IP_DONTFRAG);
            assert_eq!(df, 0, "iOS persona must leave DF cleared");
        }
        #[cfg(target_os = "linux")]
        {
            assert!(outcome.df_applied);
            let mode = get_sockopt_int(fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER);
            assert_eq!(mode, 0, "iOS persona maps to IP_PMTUDISC_DONT");
        }
    }

    #[test]
    fn disabled_fingerprint_policy_requests_nothing() {
        let policy = outer_header_for_fingerprint(OsFingerprintProfile::Disabled);
        assert_eq!(policy.ttl, None);
        assert_eq!(policy.df, None);
    }
}
