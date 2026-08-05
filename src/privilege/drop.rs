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

use serde::Serialize;
#[cfg(unix)]
use std::ffi::{CStr, CString};

const CAP_CHOWN: u32 = 0;
const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;
const CAP_NET_BIND_SERVICE: u32 = 10;
const CAP_NET_ADMIN: u32 = 12;
const CAP_NET_RAW: u32 = 13;

/// Operations whose kernel privileges must be available during server setup.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct CapabilityRequirements {
    /// Creating/configuring a TUN interface and host routing.
    pub tun: bool,
    /// Binding a UDP port below 1024.
    pub privileged_bind: bool,
    /// Clearing supplementary groups before the final identity transition.
    pub privilege_finalize: bool,
    /// Transferring a root-created audit log to the final runtime identity.
    pub audit_owner: bool,
}

/// A user/group pair resolved through the platform account database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedIdentity {
    pub user_selector: String,
    pub user_name: String,
    pub uid: u32,
    pub group_selector: String,
    pub group_name: String,
    pub gid: u32,
}

/// Non-failing target-account diagnostic used by the capabilities command.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityResolution {
    pub user_exists: bool,
    pub group_exists: bool,
    pub identity: Option<ResolvedIdentity>,
    pub error: Option<String>,
}

/// Report on the current process's privilege state.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityReport {
    pub real_uid: u32,
    pub effective_uid: u32,
    /// Saved UID when the target platform exposes it; `None` means the
    /// platform has no portable saved-ID query and the value must not be
    /// inferred from the effective UID.
    pub saved_uid: Option<u32>,
    pub real_gid: u32,
    pub effective_gid: u32,
    /// Saved GID when the target platform exposes it; `None` means the
    /// platform has no portable saved-ID query and the value must not be
    /// inferred from the effective GID.
    pub saved_gid: Option<u32>,
    pub supplementary_groups: Vec<u32>,
    pub effective_capabilities: u64,
    pub permitted_capabilities: u64,
    pub inheritable_capabilities: u64,
    pub ambient_capabilities: u64,
    pub bounding_capabilities: u64,
    pub no_new_privileges: Option<bool>,
    pub is_root: bool,
    pub has_net_admin: bool,
    pub has_net_raw: bool,
    pub has_net_bind_service: bool,
    pub has_setgid: bool,
    pub has_setuid: bool,
    pub has_chown: bool,
    pub can_drop: bool,
    pub target: Option<ResolvedIdentity>,
    pub target_user_exists: bool,
    pub target_group_exists: bool,
    pub target_matches_current_identity: bool,
    pub ready_for_tun: bool,
    pub ready_for_privileged_bind: bool,
    pub ready_for_requested_operations: bool,
}

/// Error returned by [`drop_privileges`].
#[derive(Debug)]
pub enum DropError {
    /// The specified user name was not found in the passwd database.
    UserNotFound(String),
    /// The specified group name was not found in the group database.
    GroupNotFound(String),
    InvalidIdentity(String),
    UnsafeTarget(String),
    AccountLookupFailed {
        selector: String,
        errno: i32,
    },
    MalformedAccountRecord {
        selector: String,
        field: &'static str,
        reason: &'static str,
    },
    StateInspectionFailed(String),
    MissingCapabilities(String),
    SystemCallFailed {
        operation: &'static str,
        errno: i32,
    },
    VerificationFailed(String),
    /// Platform does not support privilege dropping.
    NotSupported,
}

impl std::fmt::Display for DropError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserNotFound(u) => write!(f, "user not found: {u}"),
            Self::GroupNotFound(g) => write!(f, "group not found: {g}"),
            Self::InvalidIdentity(detail) => write!(f, "invalid identity selector: {detail}"),
            Self::UnsafeTarget(detail) => write!(f, "unsafe privilege-drop target: {detail}"),
            Self::AccountLookupFailed { selector, errno } => {
                write!(f, "account lookup failed for {selector:?} (errno {errno})")
            }
            Self::MalformedAccountRecord { selector, field, reason } => {
                write!(f, "malformed account record for {selector:?}: {field} {reason}")
            }
            Self::StateInspectionFailed(detail) => {
                write!(f, "privilege-state inspection failed: {detail}")
            }
            Self::MissingCapabilities(detail) => {
                write!(f, "required startup capabilities missing: {detail}")
            }
            Self::SystemCallFailed { operation, errno } => {
                write!(f, "{operation} failed (errno {errno})")
            }
            Self::VerificationFailed(detail) => {
                write!(f, "post-drop verification failed: {detail}")
            }
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
    try_check_capabilities(None, CapabilityRequirements::default())
        .unwrap_or_else(|_| CapabilityReport::unavailable())
}

/// Inspect the current identity and kernel capability sets.
pub fn try_check_capabilities(
    target: Option<&ResolvedIdentity>,
    requirements: CapabilityRequirements,
) -> Result<CapabilityReport, DropError> {
    let ids = current_ids()?;
    let supplementary_groups = current_groups()?;
    #[cfg(target_os = "linux")]
    let linux = read_linux_status()?;
    #[cfg(not(target_os = "linux"))]
    let linux = LinuxPrivilegeState::for_non_linux(ids.1 == 0);

    let effective = linux.effective;
    let is_root = ids.1 == 0;
    let has_net_admin = has_capability(effective, CAP_NET_ADMIN);
    let has_net_raw = has_capability(effective, CAP_NET_RAW);
    let has_net_bind_service = has_capability(effective, CAP_NET_BIND_SERVICE);
    let has_setgid = has_capability(effective, CAP_SETGID);
    let has_setuid = has_capability(effective, CAP_SETUID);
    let has_chown = has_capability(effective, CAP_CHOWN);
    let ready_for_tun = has_net_admin && has_net_raw;
    let ready_for_privileged_bind = has_net_bind_service;
    let target_matches_current_identity =
        target.is_some_and(|identity| identity.uid == ids.1 && identity.gid == ids.4);

    Ok(CapabilityReport {
        real_uid: ids.0,
        effective_uid: ids.1,
        saved_uid: ids.2,
        real_gid: ids.3,
        effective_gid: ids.4,
        saved_gid: ids.5,
        supplementary_groups,
        effective_capabilities: linux.effective,
        permitted_capabilities: linux.permitted,
        inheritable_capabilities: linux.inheritable,
        ambient_capabilities: linux.ambient,
        bounding_capabilities: linux.bounding,
        no_new_privileges: linux.no_new_privileges,
        is_root,
        has_net_admin,
        has_net_raw,
        has_net_bind_service,
        has_setgid,
        has_setuid,
        has_chown,
        can_drop: is_root || target_matches_current_identity,
        target: target.cloned(),
        target_user_exists: target.is_some(),
        target_group_exists: target.is_some(),
        target_matches_current_identity,
        ready_for_tun,
        ready_for_privileged_bind,
        ready_for_requested_operations: (!requirements.tun || ready_for_tun)
            && (!requirements.privileged_bind || ready_for_privileged_bind)
            && (!requirements.privilege_finalize || (has_setgid && has_setuid))
            && (!requirements.audit_owner || has_chown),
    })
}

impl CapabilityReport {
    fn unavailable() -> Self {
        Self {
            real_uid: u32::MAX,
            effective_uid: u32::MAX,
            saved_uid: None,
            real_gid: u32::MAX,
            effective_gid: u32::MAX,
            saved_gid: None,
            supplementary_groups: Vec::new(),
            effective_capabilities: 0,
            permitted_capabilities: 0,
            inheritable_capabilities: 0,
            ambient_capabilities: 0,
            bounding_capabilities: 0,
            no_new_privileges: None,
            is_root: false,
            has_net_admin: false,
            has_net_raw: false,
            has_net_bind_service: false,
            has_setgid: false,
            has_setuid: false,
            has_chown: false,
            can_drop: false,
            target: None,
            target_user_exists: false,
            target_group_exists: false,
            target_matches_current_identity: false,
            ready_for_tun: false,
            ready_for_privileged_bind: false,
            ready_for_requested_operations: false,
        }
    }
}

/// Resolve a name or numeric UID/GID without ambiguous fallback.
///
/// An all-decimal selector is always interpreted as a numeric ID. Every
/// other selector is interpreted as an account name.
pub fn resolve_identity(user: &str, group: &str) -> Result<ResolvedIdentity, DropError> {
    #[cfg(unix)]
    {
        let (uid, user_name) = resolve_user(user)?;
        let (gid, group_name) = resolve_group(group)?;
        if uid == 0 {
            return Err(DropError::UnsafeTarget("target UID must not be 0".to_string()));
        }
        if gid == 0 {
            return Err(DropError::UnsafeTarget("target GID must not be 0".to_string()));
        }
        Ok(ResolvedIdentity {
            user_selector: user.to_string(),
            user_name,
            uid,
            group_selector: group.to_string(),
            group_name,
            gid,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (user, group);
        Err(DropError::NotSupported)
    }
}

/// Inspect user and group selectors independently so diagnostics remain useful
/// even when one side does not resolve.
pub fn inspect_identity(user: &str, group: &str) -> IdentityResolution {
    #[cfg(unix)]
    {
        let user_result = resolve_user(user);
        let group_result = resolve_group(group);
        let user_exists = user_result.is_ok();
        let group_exists = group_result.is_ok();
        match (user_result, group_result) {
            (Ok((uid, user_name)), Ok((gid, group_name))) if uid != 0 && gid != 0 => {
                IdentityResolution {
                    user_exists,
                    group_exists,
                    identity: Some(ResolvedIdentity {
                        user_selector: user.to_string(),
                        user_name,
                        uid,
                        group_selector: group.to_string(),
                        group_name,
                        gid,
                    }),
                    error: None,
                }
            }
            (Ok((0, _)), _) => IdentityResolution {
                user_exists,
                group_exists,
                identity: None,
                error: Some("unsafe privilege-drop target: target UID must not be 0".to_string()),
            },
            (_, Ok((0, _))) => IdentityResolution {
                user_exists,
                group_exists,
                identity: None,
                error: Some("unsafe privilege-drop target: target GID must not be 0".to_string()),
            },
            (Err(error), _) | (_, Err(error)) => IdentityResolution {
                user_exists,
                group_exists,
                identity: None,
                error: Some(error.to_string()),
            },
            _ => IdentityResolution {
                user_exists,
                group_exists,
                identity: None,
                error: Some("identity resolution failed".to_string()),
            },
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (user, group);
        IdentityResolution {
            user_exists: false,
            group_exists: false,
            identity: None,
            error: Some(DropError::NotSupported.to_string()),
        }
    }
}

/// Fail closed unless all capabilities required for privileged setup exist.
pub fn validate_startup_capabilities(
    report: &CapabilityReport,
    requirements: CapabilityRequirements,
) -> Result<(), DropError> {
    let mut missing = Vec::new();
    if requirements.tun && !report.has_net_admin {
        missing.push("CAP_NET_ADMIN");
    }
    if requirements.tun && !report.has_net_raw {
        missing.push("CAP_NET_RAW");
    }
    if requirements.privileged_bind && !report.has_net_bind_service {
        missing.push("CAP_NET_BIND_SERVICE");
    }
    if requirements.privilege_finalize && !report.has_setgid {
        missing.push("CAP_SETGID");
    }
    if requirements.privilege_finalize && !report.has_setuid {
        missing.push("CAP_SETUID");
    }
    if requirements.audit_owner && !report.has_chown {
        missing.push("CAP_CHOWN");
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(DropError::MissingCapabilities(missing.join(", ")))
    }
}

/// Drop privileges to a previously resolved identity.
///
/// The order is critical: `setgid` **must** be called before `setuid` to
/// prevent regaining group privileges after dropping UID (POSIX requirement).
///
/// After the call, file descriptors (socket, TUN fd) remain valid — they
/// were opened during the privileged phase and survive the UID/GID change.
pub fn drop_privileges_resolved(
    identity: &ResolvedIdentity,
) -> Result<CapabilityReport, DropError> {
    #[cfg(target_os = "linux")]
    {
        enable_no_new_privileges()?;
        clear_supplementary_groups()?;
        call_zero("setresgid", unsafe {
            libc::setresgid(identity.gid, identity.gid, identity.gid)
        })?;
        call_zero("setresuid", unsafe {
            libc::setresuid(identity.uid, identity.uid, identity.uid)
        })?;
        clear_ambient_capabilities()?;
        clear_process_capabilities()?;

        let report = try_check_capabilities(Some(identity), CapabilityRequirements::default())?;
        verify_linux_post_drop(&report, identity)?;
        Ok(report)
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        call_zero("setgid", unsafe { libc::setgid(identity.gid) })?;
        call_zero("setuid", unsafe { libc::setuid(identity.uid) })?;
        let report = try_check_capabilities(Some(identity), CapabilityRequirements::default())?;
        if report.effective_uid != identity.uid || report.effective_gid != identity.gid {
            return Err(DropError::VerificationFailed(
                "effective identity does not match the resolved target".to_string(),
            ));
        }
        Ok(report)
    }
    #[cfg(not(unix))]
    {
        let _ = identity;
        Err(DropError::NotSupported)
    }
}

/// Resolve and irreversibly drop to the specified user/group.
pub fn drop_privileges(user: &str, group: &str) -> Result<CapabilityReport, DropError> {
    let identity = resolve_identity(user, group)?;
    drop_privileges_resolved(&identity)
}

/// Enable Linux's irreversible exec-time privilege-escalation guard.
pub fn enable_no_new_privileges() -> Result<(), DropError> {
    #[cfg(target_os = "linux")]
    {
        call_zero("prctl(PR_SET_NO_NEW_PRIVS)", unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

/// Harden a Tokio worker before it can poll server work.
pub fn harden_runtime_worker_thread() -> Result<(), DropError> {
    #[cfg(target_os = "linux")]
    {
        enable_no_new_privileges()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

/// Verify every Linux thread, not only the caller, after the final drop.
pub fn verify_process_privilege_state(identity: &ResolvedIdentity) -> Result<usize, DropError> {
    #[cfg(target_os = "linux")]
    {
        let tasks = std::fs::read_dir("/proc/self/task")
            .map_err(|error| DropError::StateInspectionFailed(error.to_string()))?;
        let mut verified = 0usize;
        for task in tasks {
            let task = task.map_err(|error| {
                DropError::StateInspectionFailed(format!("task enumeration failed: {error}"))
            })?;
            let status_path = task.path().join("status");
            let status = std::fs::read_to_string(&status_path).map_err(|error| {
                DropError::StateInspectionFailed(format!(
                    "failed to read {}: {error}",
                    status_path.display()
                ))
            })?;
            verify_linux_thread_status(&status, identity, &status_path)?;
            verified += 1;
        }
        if verified == 0 {
            return Err(DropError::VerificationFailed(
                "no Linux threads were available for verification".to_string(),
            ));
        }
        Ok(verified)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = identity;
        Ok(0)
    }
}

/// Prove that UID 0 cannot be regained after a completed Linux drop.
///
/// This invokes glibc's process-wide `setresuid` path and must therefore run
/// only in an isolated single-threaded subprocess, never in the live server.
pub fn prove_root_cannot_be_regained() -> Result<(), DropError> {
    #[cfg(target_os = "linux")]
    {
        verify_root_cannot_be_regained()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(DropError::NotSupported)
    }
}

/// Returns true if the process is running as root and should drop privileges.
pub fn should_drop_privileges() -> bool {
    check_capabilities().is_root
}

// --- Platform helpers ---

#[cfg(unix)]
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(unix)]
fn call_zero(operation: &'static str, result: libc::c_int) -> Result<(), DropError> {
    if result == 0 {
        Ok(())
    } else {
        Err(DropError::SystemCallFailed { operation, errno: errno() })
    }
}

#[cfg(unix)]
fn parse_numeric_selector(selector: &str, kind: &str) -> Result<Option<u32>, DropError> {
    if selector.is_empty() {
        return Err(DropError::InvalidIdentity(format!("{kind} selector is empty")));
    }
    if selector.as_bytes().contains(&0) {
        return Err(DropError::InvalidIdentity(format!("{kind} selector contains NUL")));
    }
    if selector.bytes().all(|byte| byte.is_ascii_digit()) {
        return selector
            .parse::<u32>()
            .map(Some)
            .map_err(|_| DropError::InvalidIdentity(format!("{kind} ID is outside u32")));
    }
    Ok(None)
}

#[cfg(unix)]
fn lookup_buffer<T>(
    selector: &str,
    mut lookup: impl FnMut(*mut T, *mut libc::c_char, usize, *mut *mut T) -> libc::c_int,
) -> Result<(T, Vec<libc::c_char>), DropError> {
    let mut size = 16 * 1024usize;
    loop {
        let mut value = std::mem::MaybeUninit::<T>::uninit();
        let output = value.as_mut_ptr();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0 as libc::c_char; size];
        let status = lookup(output, buffer.as_mut_ptr(), buffer.len(), &mut result);
        if status == libc::ERANGE && size < 1024 * 1024 {
            size *= 2;
            continue;
        }
        if status != 0 {
            return Err(DropError::AccountLookupFailed {
                selector: selector.to_string(),
                errno: status,
            });
        }
        if result.is_null() {
            return Err(DropError::AccountLookupFailed {
                selector: selector.to_string(),
                errno: 0,
            });
        }
        if result != output {
            return Err(DropError::AccountLookupFailed {
                selector: selector.to_string(),
                errno: libc::EINVAL,
            });
        }
        // SAFETY: the successful lookup contract initializes the caller-owned
        // output object and returns that exact pointer. The status, null, and
        // pointer-identity checks above establish those preconditions.
        return Ok((unsafe { value.assume_init() }, buffer));
    }
}

#[cfg(unix)]
fn copy_bounded_cstr_field(
    selector: &str,
    field: &'static str,
    pointer: *const libc::c_char,
    buffer: &[libc::c_char],
) -> Result<String, DropError> {
    let malformed = |reason| DropError::MalformedAccountRecord {
        selector: selector.to_string(),
        field,
        reason,
    };
    if pointer.is_null() {
        return Err(malformed("pointer is null"));
    }

    let buffer_start = buffer.as_ptr() as usize;
    let buffer_end = buffer_start
        .checked_add(buffer.len())
        .ok_or_else(|| malformed("buffer address range overflow"))?;
    let field_address = pointer as usize;
    if field_address < buffer_start || field_address >= buffer_end {
        return Err(malformed("pointer is outside the lookup buffer"));
    }

    let offset = field_address - buffer_start;
    let nul_offset = buffer[offset..]
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| malformed("field has no NUL terminator in the lookup buffer"))?;
    let end = offset + nul_offset + 1;
    let bytes = buffer[offset..end].iter().copied().collect::<Vec<_>>();
    let value = CStr::from_bytes_with_nul(&bytes)
        .map_err(|_| malformed("field is not a valid NUL-terminated byte string"))?;
    Ok(value.to_string_lossy().into_owned())
}

#[cfg(unix)]
fn resolve_user(selector: &str) -> Result<(u32, String), DropError> {
    let numeric = parse_numeric_selector(selector, "user")?;
    let name = numeric
        .is_none()
        .then(|| CString::new(selector).map_err(|_| DropError::InvalidIdentity(selector.into())))
        .transpose()?;
    let name_ptr = name.as_ref().map_or(std::ptr::null(), |value| value.as_ptr());
    let (pwd, buffer) = lookup_buffer(selector, |output, buffer, len, result| unsafe {
        match numeric {
            Some(uid) => libc::getpwuid_r(uid, output, buffer, len, result),
            None => libc::getpwnam_r(name_ptr, output, buffer, len, result),
        }
    })
    .map_err(|error| match error {
        DropError::AccountLookupFailed { errno: 0, .. } => {
            DropError::UserNotFound(selector.to_string())
        }
        other => other,
    })?;
    let canonical = copy_bounded_cstr_field(selector, "pw_name", pwd.pw_name, &buffer)?;
    drop(buffer);
    Ok((pwd.pw_uid, canonical))
}

#[cfg(unix)]
fn resolve_group(selector: &str) -> Result<(u32, String), DropError> {
    let numeric = parse_numeric_selector(selector, "group")?;
    let name = numeric
        .is_none()
        .then(|| CString::new(selector).map_err(|_| DropError::InvalidIdentity(selector.into())))
        .transpose()?;
    let name_ptr = name.as_ref().map_or(std::ptr::null(), |value| value.as_ptr());
    let (grp, buffer) = lookup_buffer(selector, |output, buffer, len, result| unsafe {
        match numeric {
            Some(gid) => libc::getgrgid_r(gid, output, buffer, len, result),
            None => libc::getgrnam_r(name_ptr, output, buffer, len, result),
        }
    })
    .map_err(|error| match error {
        DropError::AccountLookupFailed { errno: 0, .. } => {
            DropError::GroupNotFound(selector.to_string())
        }
        other => other,
    })?;
    let canonical = copy_bounded_cstr_field(selector, "gr_name", grp.gr_name, &buffer)?;
    drop(buffer);
    Ok((grp.gr_gid, canonical))
}

#[cfg(unix)]
type CurrentIds = (u32, u32, Option<u32>, u32, u32, Option<u32>);

#[cfg(unix)]
fn current_ids() -> Result<CurrentIds, DropError> {
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "emscripten",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "l4re",
        target_os = "linux",
        target_os = "openbsd",
    ))]
    {
        let mut real_uid = 0;
        let mut effective_uid = 0;
        let mut saved_uid = 0;
        call_zero("getresuid", unsafe {
            libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid)
        })?;
        let mut real_gid = 0;
        let mut effective_gid = 0;
        let mut saved_gid = 0;
        call_zero("getresgid", unsafe {
            libc::getresgid(&mut real_gid, &mut effective_gid, &mut saved_gid)
        })?;
        Ok((real_uid, effective_uid, Some(saved_uid), real_gid, effective_gid, Some(saved_gid)))
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "emscripten",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "l4re",
        target_os = "linux",
        target_os = "openbsd",
    )))]
    {
        let real_uid = unsafe { libc::getuid() };
        let effective_uid = unsafe { libc::geteuid() };
        let real_gid = unsafe { libc::getgid() };
        let effective_gid = unsafe { libc::getegid() };
        Ok((real_uid, effective_uid, None, real_gid, effective_gid, None))
    }
}

#[cfg(not(unix))]
fn current_ids() -> Result<CurrentIds, DropError> {
    Err(DropError::NotSupported)
}

#[cfg(unix)]
fn current_groups() -> Result<Vec<u32>, DropError> {
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count < 0 {
        return Err(DropError::SystemCallFailed { operation: "getgroups(size)", errno: errno() });
    }
    let mut groups = vec![0; count as usize];
    if count > 0 {
        let actual = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
        if actual < 0 {
            return Err(DropError::SystemCallFailed { operation: "getgroups", errno: errno() });
        }
        groups.truncate(actual as usize);
    }
    groups.sort_unstable();
    groups.dedup();
    Ok(groups)
}

#[cfg(not(unix))]
fn current_groups() -> Result<Vec<u32>, DropError> {
    Ok(Vec::new())
}

#[derive(Clone, Copy)]
struct LinuxPrivilegeState {
    effective: u64,
    permitted: u64,
    inheritable: u64,
    ambient: u64,
    bounding: u64,
    no_new_privileges: Option<bool>,
}

impl LinuxPrivilegeState {
    #[cfg(not(target_os = "linux"))]
    fn for_non_linux(root: bool) -> Self {
        let all = if root { u64::MAX } else { 0 };
        Self {
            effective: all,
            permitted: all,
            inheritable: 0,
            ambient: 0,
            bounding: all,
            no_new_privileges: None,
        }
    }
}

#[cfg(target_os = "linux")]
fn read_linux_status() -> Result<LinuxPrivilegeState, DropError> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|error| DropError::StateInspectionFailed(error.to_string()))?;
    let parse_hex = |key: &str| -> Result<u64, DropError> {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .ok_or_else(|| DropError::StateInspectionFailed(format!("missing {key}")))?;
        u64::from_str_radix(value.trim(), 16)
            .map_err(|error| DropError::StateInspectionFailed(format!("invalid {key}: {error}")))
    };
    let no_new_privileges = status
        .lines()
        .find_map(|line| line.strip_prefix("NoNewPrivs:"))
        .and_then(|value| value.trim().parse::<u8>().ok())
        .map(|value| value != 0);
    Ok(LinuxPrivilegeState {
        effective: parse_hex("CapEff:")?,
        permitted: parse_hex("CapPrm:")?,
        inheritable: parse_hex("CapInh:")?,
        ambient: parse_hex("CapAmb:")?,
        bounding: parse_hex("CapBnd:")?,
        no_new_privileges,
    })
}

fn has_capability(mask: u64, capability: u32) -> bool {
    mask & (1u64 << capability) != 0
}

#[cfg(target_os = "linux")]
fn clear_supplementary_groups() -> Result<(), DropError> {
    call_zero("setgroups", unsafe { libc::setgroups(0, std::ptr::null()) })
}

#[cfg(target_os = "linux")]
fn clear_ambient_capabilities() -> Result<(), DropError> {
    call_zero("prctl(PR_CAP_AMBIENT_CLEAR_ALL)", unsafe {
        libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
    })
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LinuxCapabilityHeader {
    version: u32,
    pid: i32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct LinuxCapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[cfg(target_os = "linux")]
fn clear_process_capabilities() -> Result<(), DropError> {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let mut header = LinuxCapabilityHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let data = [LinuxCapabilityData::default(); 2];
    let result = unsafe {
        libc::syscall(libc::SYS_capset, &mut header as *mut LinuxCapabilityHeader, data.as_ptr())
    };
    if result == 0 {
        Ok(())
    } else {
        Err(DropError::SystemCallFailed { operation: "capset(clear)", errno: errno() })
    }
}

#[cfg(target_os = "linux")]
fn verify_linux_post_drop(
    report: &CapabilityReport,
    identity: &ResolvedIdentity,
) -> Result<(), DropError> {
    if (report.real_uid, report.effective_uid, report.saved_uid)
        != (identity.uid, identity.uid, Some(identity.uid))
    {
        return Err(DropError::VerificationFailed(format!(
            "UIDs are {}/{}/{:?}, expected {}",
            report.real_uid, report.effective_uid, report.saved_uid, identity.uid
        )));
    }
    if (report.real_gid, report.effective_gid, report.saved_gid)
        != (identity.gid, identity.gid, Some(identity.gid))
    {
        return Err(DropError::VerificationFailed(format!(
            "GIDs are {}/{}/{:?}, expected {}",
            report.real_gid, report.effective_gid, report.saved_gid, identity.gid
        )));
    }
    if !report.supplementary_groups.is_empty() {
        return Err(DropError::VerificationFailed(format!(
            "supplementary groups remain: {:?}",
            report.supplementary_groups
        )));
    }
    if report.effective_capabilities != 0
        || report.permitted_capabilities != 0
        || report.inheritable_capabilities != 0
        || report.ambient_capabilities != 0
    {
        return Err(DropError::VerificationFailed(format!(
            "capability sets remain: effective={:#x}, permitted={:#x}, inheritable={:#x}, ambient={:#x}",
            report.effective_capabilities,
            report.permitted_capabilities,
            report.inheritable_capabilities,
            report.ambient_capabilities
        )));
    }
    if report.no_new_privileges != Some(true) {
        return Err(DropError::VerificationFailed("no_new_privileges is not set".to_string()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_linux_thread_status(
    status: &str,
    identity: &ResolvedIdentity,
    path: &std::path::Path,
) -> Result<(), DropError> {
    let parse_ids = |key: &str| -> Result<[u32; 3], DropError> {
        let values = status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .ok_or_else(|| {
                DropError::StateInspectionFailed(format!("missing {key} in {}", path.display()))
            })?
            .split_whitespace()
            .take(3)
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                DropError::StateInspectionFailed(format!(
                    "invalid {key} in {}: {error}",
                    path.display()
                ))
            })?;
        values.try_into().map_err(|_| {
            DropError::StateInspectionFailed(format!("incomplete {key} in {}", path.display()))
        })
    };
    if parse_ids("Uid:")? != [identity.uid; 3] {
        return Err(DropError::VerificationFailed(format!(
            "thread {} does not have target real/effective/saved UIDs",
            path.display()
        )));
    }
    if parse_ids("Gid:")? != [identity.gid; 3] {
        return Err(DropError::VerificationFailed(format!(
            "thread {} does not have target real/effective/saved GIDs",
            path.display()
        )));
    }
    let groups = status.lines().find_map(|line| line.strip_prefix("Groups:")).ok_or_else(|| {
        DropError::StateInspectionFailed(format!("missing Groups in {}", path.display()))
    })?;
    if !groups.trim().is_empty() {
        return Err(DropError::VerificationFailed(format!(
            "thread {} retains supplementary groups: {}",
            path.display(),
            groups.trim()
        )));
    }
    for key in ["CapEff:", "CapPrm:", "CapInh:", "CapAmb:"] {
        let value = status.lines().find_map(|line| line.strip_prefix(key)).ok_or_else(|| {
            DropError::StateInspectionFailed(format!("missing {key} in {}", path.display()))
        })?;
        let mask = u64::from_str_radix(value.trim(), 16).map_err(|error| {
            DropError::StateInspectionFailed(format!(
                "invalid {key} in {}: {error}",
                path.display()
            ))
        })?;
        if mask != 0 {
            return Err(DropError::VerificationFailed(format!(
                "thread {} retains {key} {mask:#x}",
                path.display()
            )));
        }
    }
    let no_new_privileges = status
        .lines()
        .find_map(|line| line.strip_prefix("NoNewPrivs:"))
        .and_then(|value| value.trim().parse::<u8>().ok());
    if no_new_privileges != Some(1) {
        return Err(DropError::VerificationFailed(format!(
            "thread {} does not have no_new_privileges",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_root_cannot_be_regained() -> Result<(), DropError> {
    let result = unsafe { libc::setresuid(0, 0, 0) };
    if result == 0 {
        return Err(DropError::VerificationFailed(
            "setresuid(0,0,0) unexpectedly regained root".to_string(),
        ));
    }
    if errno() != libc::EPERM {
        return Err(DropError::VerificationFailed(format!(
            "root-regain probe failed with errno {}, expected EPERM",
            errno()
        )));
    }
    let ids = current_ids()?;
    if ids.0 == 0 || ids.1 == 0 || ids.2 == Some(0) {
        return Err(DropError::VerificationFailed("root-regain probe left a root UID".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drop_error_display() {
        assert!(format!("{}", DropError::UserNotFound("foo".into())).contains("foo"));
        assert!(format!("{}", DropError::UnsafeTarget("root".into())).contains("root"));
        assert!(format!("{}", DropError::NotSupported).contains("not supported"));
    }

    #[test]
    fn test_capability_report_construction() {
        let report = CapabilityReport::unavailable();
        assert!(!report.is_root);
        assert!(!report.can_drop);
    }

    #[cfg(unix)]
    #[test]
    fn numeric_identity_selectors_never_fallback_to_names() {
        assert_eq!(parse_numeric_selector("123", "user").unwrap(), Some(123));
        assert_eq!(parse_numeric_selector("alice", "user").unwrap(), None);
        assert!(parse_numeric_selector("", "user").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn lookup_buffer_rejects_nonzero_status_before_extraction() {
        let result =
            lookup_buffer::<u32>("status-failure", |_output, _buffer, _len, _result| libc::EIO);

        assert!(matches!(
            result,
            Err(DropError::AccountLookupFailed { errno, .. }) if errno == libc::EIO
        ));
    }

    #[cfg(unix)]
    #[test]
    fn lookup_buffer_retries_and_grows_after_erange() {
        let mut calls = 0;
        let (value, buffer) =
            lookup_buffer::<u32>("erange-retry", |output, _buffer, len, result| {
                calls += 1;
                match calls {
                    1 => {
                        assert_eq!(len, 16 * 1024);
                        libc::ERANGE
                    }
                    2 => {
                        assert_eq!(len, 32 * 1024);
                        unsafe {
                            output.write(7);
                            *result = output;
                        }
                        0
                    }
                    _ => unreachable!("lookup callback called after successful retry"),
                }
            })
            .expect("ERANGE retry must succeed");

        assert_eq!(calls, 2);
        assert_eq!(value, 7);
        assert_eq!(buffer.len(), 32 * 1024);
    }

    #[cfg(unix)]
    #[test]
    fn lookup_buffer_rejects_null_result_before_extraction() {
        let result = lookup_buffer::<u32>("null-result", |_output, _buffer, _len, _result| 0);

        assert!(matches!(
            result,
            Err(DropError::AccountLookupFailed { errno, .. }) if errno == 0
        ));
    }

    #[cfg(unix)]
    #[test]
    fn lookup_buffer_rejects_result_pointer_not_owned_by_output() {
        let mut foreign = std::mem::MaybeUninit::<u32>::new(11);
        let foreign_pointer = foreign.as_mut_ptr();
        let result = lookup_buffer::<u32>("pointer-mismatch", |_output, _buffer, _len, result| {
            unsafe {
                *result = foreign_pointer;
            }
            0
        });

        assert!(matches!(
            result,
            Err(DropError::AccountLookupFailed { errno, .. }) if errno == libc::EINVAL
        ));
    }

    #[cfg(unix)]
    #[test]
    fn real_unknown_user_and_group_are_reported_as_not_found() {
        let user_selector = "__quicfuscate_missing_user_5f4d8e2a__";
        let group_selector = "__quicfuscate_missing_group_5f4d8e2a__";

        assert!(matches!(resolve_user(user_selector), Err(DropError::UserNotFound(_))));
        assert!(matches!(resolve_group(group_selector), Err(DropError::GroupNotFound(_))));
    }

    #[cfg(unix)]
    fn c_char_buffer(bytes: &[u8]) -> Vec<libc::c_char> {
        bytes.iter().map(|byte| *byte as libc::c_char).collect()
    }

    #[cfg(unix)]
    #[test]
    fn bounded_cstr_field_accepts_nul_terminated_pointer_inside_buffer() {
        let buffer = c_char_buffer(b"prefix\0alice\0");
        let pointer = buffer.as_ptr().wrapping_add("prefix\0".len());

        let value = copy_bounded_cstr_field("normal", "pw_name", pointer, &buffer)
            .expect("bounded account name must be copied");

        assert_eq!(value, "alice");
    }

    #[cfg(unix)]
    #[test]
    fn bounded_cstr_field_rejects_null_pointer() {
        let buffer = c_char_buffer(b"alice\0");
        let result = copy_bounded_cstr_field("null", "pw_name", std::ptr::null(), &buffer);

        assert!(matches!(
            result,
            Err(DropError::MalformedAccountRecord { field, reason, .. })
                if field == "pw_name" && reason == "pointer is null"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_cstr_field_rejects_pointer_outside_buffer() {
        let buffer = c_char_buffer(b"alice\0");
        let pointer = buffer.as_ptr().wrapping_add(buffer.len());
        let result = copy_bounded_cstr_field("outside", "gr_name", pointer, &buffer);

        assert!(matches!(
            result,
            Err(DropError::MalformedAccountRecord { field, reason, .. })
                if field == "gr_name" && reason == "pointer is outside the lookup buffer"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_cstr_field_rejects_missing_nul_terminator() {
        let buffer = c_char_buffer(b"alice");
        let result = copy_bounded_cstr_field("unterminated", "pw_name", buffer.as_ptr(), &buffer);

        assert!(matches!(
            result,
            Err(DropError::MalformedAccountRecord { field, reason, .. })
                if field == "pw_name"
                    && reason == "field has no NUL terminator in the lookup buffer"
        ));
    }

    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "emscripten",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "l4re",
        target_os = "linux",
        target_os = "openbsd",
    ))]
    #[test]
    fn saved_ids_are_reported_when_the_platform_supports_the_query() {
        let ids = current_ids().expect("supported platform identity query must succeed");
        assert!(ids.2.is_some());
        assert!(ids.5.is_some());
    }

    #[cfg(all(
        unix,
        not(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "l4re",
            target_os = "linux",
            target_os = "openbsd",
        ))
    ))]
    #[test]
    fn saved_ids_are_not_inferred_on_platforms_without_a_query() {
        let ids = current_ids().expect("basic Unix identity query must succeed");
        assert_eq!(ids.2, None);
        assert_eq!(ids.5, None);
    }

    #[test]
    fn startup_capability_validation_names_every_missing_capability() {
        let report = CapabilityReport::unavailable();
        let error = validate_startup_capabilities(
            &report,
            CapabilityRequirements {
                tun: true,
                privileged_bind: true,
                privilege_finalize: true,
                audit_owner: true,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("CAP_NET_ADMIN"));
        assert!(error.contains("CAP_NET_RAW"));
        assert!(error.contains("CAP_NET_BIND_SERVICE"));
        assert!(error.contains("CAP_SETGID"));
        assert!(error.contains("CAP_SETUID"));
        assert!(error.contains("CAP_CHOWN"));
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
