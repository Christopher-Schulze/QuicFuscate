//! Privilege dropping after privileged initialization (TODO-441).
//!
//! On Unix, the server starts as root (or with `CAP_NET_ADMIN` /
//! `CAP_NET_RAW` / `CAP_NET_BIND_SERVICE`) to bind privileged ports, set up
//! the TUN interface, and install iptables/nftables rules. After all
//! privileged operations are complete, [`drop_privileges`] switches the
//! process to a dedicated unprivileged user/group so a compromise cannot
//! escalate beyond the VPN service's blast radius.
//!
//! On non-Unix targets this module is a no-op stub.

use std::ffi::CString;

/// Report on the current process's privilege state.
#[derive(Debug, Clone)]
pub struct CapabilityReport {
    /// True when the effective UID is 0 (root).
    pub is_root: bool,
    /// True when `CAP_NET_ADMIN` is in the effective capability set (Linux).
    pub has_net_admin: bool,
    /// True when `CAP_NET_RAW` is in the effective capability set (Linux).
    pub has_net_raw: bool,
    /// True when `CAP_NET_BIND_SERVICE` is in the effective set (Linux).
    pub has_net_bind_service: bool,
    /// True when privilege dropping is possible and advisable.
    pub can_drop: bool,
}

/// Error returned by [`drop_privileges`].
#[derive(Debug)]
pub enum DropError {
    /// The specified user name was not found in the passwd database.
    UserNotFound(String),
    /// The specified group name was not found in the group database.
    GroupNotFound(String),
    /// `setgid(2)` failed.
    SetgidFailed(i32),
    /// `setuid(2)` failed.
    SetuidFailed(i32),
    /// After dropping, the process is still running as root.
    StillRoot,
    /// Platform does not support privilege dropping.
    NotSupported,
}

impl std::fmt::Display for DropError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserNotFound(u) => write!(f, "user not found: {u}"),
            Self::GroupNotFound(g) => write!(f, "group not found: {g}"),
            Self::SetgidFailed(code) => write!(f, "setgid failed (errno {code})"),
            Self::SetuidFailed(code) => write!(f, "setuid failed (errno {code})"),
            Self::StillRoot => write!(f, "still running as root after drop"),
            Self::NotSupported => write!(f, "privilege dropping not supported on this platform"),
        }
    }
}

impl std::error::Error for DropError {}

/// Check the current process's privilege state.
///
/// On Linux, parses `/proc/self/status` for the `CapEff` line (effective
/// capability bitmask). On other Unix, falls back to `geteuid() == 0`.
pub fn check_capabilities() -> CapabilityReport {
    let is_root = geteuid() == 0;

    #[cfg(target_os = "linux")]
    let (has_net_admin, has_net_raw, has_net_bind_service) = {
        let caps = read_linux_cap_eff().unwrap_or(0u64);
        // Capability bit positions (include/uapi/linux/capability.h):
        //   CAP_NET_ADMIN          = 12
        //   CAP_NET_RAW            = 13
        //   CAP_NET_BIND_SERVICE   = 10
        (caps & (1u64 << 12) != 0, caps & (1u64 << 13) != 0, caps & (1u64 << 10) != 0)
    };
    #[cfg(not(target_os = "linux"))]
    let (has_net_admin, has_net_raw, has_net_bind_service) = (is_root, is_root, is_root);

    CapabilityReport {
        is_root,
        has_net_admin,
        has_net_raw,
        has_net_bind_service,
        can_drop: is_root,
    }
}

/// Drop root privileges by switching to the specified user and group.
///
/// The order is critical: `setgid` **must** be called before `setuid` to
/// prevent regaining group privileges after dropping UID (POSIX requirement).
///
/// After the call, file descriptors (socket, TUN fd) remain valid — they
/// were opened during the privileged phase and survive the UID/GID change.
pub fn drop_privileges(user: &str, group: &str) -> Result<(), DropError> {
    #[cfg(unix)]
    {
        let group_cstr =
            CString::new(group).map_err(|_| DropError::GroupNotFound(group.to_string()))?;
        let user_cstr =
            CString::new(user).map_err(|_| DropError::UserNotFound(user.to_string()))?;

        // SAFETY: getgrnam looks up the group database. The pointer is valid
        // until the next group-related call (not thread-safe, but we're
        // single-threaded during startup). We copy the gid immediately.
        let gid = unsafe {
            let grp = libc::getgrnam(group_cstr.as_ptr());
            if grp.is_null() {
                return Err(DropError::GroupNotFound(group.to_string()));
            }
            (*grp).gr_gid
        };

        // SAFETY: getpwnam looks up the user database. Same safety as above.
        let uid = unsafe {
            let pwd = libc::getpwnam(user_cstr.as_ptr());
            if pwd.is_null() {
                return Err(DropError::UserNotFound(user.to_string()));
            }
            (*pwd).pw_uid
        };

        // SAFETY: setgid sets the real, effective, and saved set-group-ID.
        // We call it before setuid per POSIX security requirements.
        if unsafe { libc::setgid(gid) } != 0 {
            return Err(DropError::SetgidFailed(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            ));
        }

        // SAFETY: setuid sets the real, effective, and saved set-user-ID.
        // After this, the process cannot regain root (unless uid==0).
        if unsafe { libc::setuid(uid) } != 0 {
            return Err(DropError::SetuidFailed(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            ));
        }

        // Verify: we must no longer be root.
        if geteuid() == 0 {
            return Err(DropError::StillRoot);
        }

        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (user, group);
        Err(DropError::NotSupported)
    }
}

/// Returns true if the process is running as root and should drop privileges.
pub fn should_drop_privileges() -> bool {
    check_capabilities().is_root
}

// --- Platform helpers ---

#[cfg(unix)]
fn geteuid() -> u32 {
    // SAFETY: geteuid is always safe to call; it has no side effects.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn geteuid() -> u32 {
    0
}

/// Parse the `CapEff:` line from `/proc/self/status` (Linux only).
#[cfg(target_os = "linux")]
fn read_linux_cap_eff() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:\t") {
            return u64::from_str_radix(rest.trim(), 16).ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drop_error_display() {
        assert!(format!("{}", DropError::UserNotFound("foo".into())).contains("foo"));
        assert!(format!("{}", DropError::StillRoot).contains("root"));
        assert!(format!("{}", DropError::NotSupported).contains("not supported"));
    }

    #[test]
    fn test_capability_report_construction() {
        let report = CapabilityReport {
            is_root: false,
            has_net_admin: false,
            has_net_raw: false,
            has_net_bind_service: false,
            can_drop: false,
        };
        assert!(!report.is_root);
        assert!(!report.can_drop);
    }

    #[test]
    fn test_should_drop_privileges_consistent_with_check() {
        let report = check_capabilities();
        assert_eq!(should_drop_privileges(), report.is_root);
    }

    #[cfg(not(unix))]
    #[test]
    fn test_drop_privileges_not_supported_on_non_unix() {
        let result = drop_privileges("nobody", "nogroup");
        assert!(matches!(result, Err(DropError::NotSupported)));
    }
}
