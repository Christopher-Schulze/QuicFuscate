//! Resolver-file backup and restore state shared by platform tests and Linux.

use super::traits::PlatformError;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

const RESOLV_CONF_STATE_SCHEMA: u8 = 2;
const OWNER_MARKER_PREFIX: &str = "# quicfuscate-resolver-owner=";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ResolvConfRestoreState {
    Present { backup: PathBuf, owner_marker: String, write_completed: bool },
    Absent { owner_marker: String, write_completed: bool },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ProcessIdentity {
    pub(super) boot_id: String,
    pub(super) pid: u32,
    pub(super) start_time: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PersistedResolvConfOwnership {
    schema: u8,
    pub(super) owner_boot_id: String,
    pub(super) owner_pid: u32,
    pub(super) owner_start_time: u64,
    pub(super) owner_marker: String,
    pub(super) original_present: bool,
}

pub(super) fn owner_marker(identity: &ProcessIdentity) -> String {
    format!("{OWNER_MARKER_PREFIX}{}:{}:{}", identity.boot_id, identity.pid, identity.start_time)
}

impl ResolvConfRestoreState {
    pub(super) fn owner_marker(&self) -> &str {
        match self {
            Self::Present { owner_marker, .. } | Self::Absent { owner_marker, .. } => owner_marker,
        }
    }

    fn mark_write_completed(&mut self) {
        match self {
            Self::Present { write_completed, .. } | Self::Absent { write_completed, .. } => {
                *write_completed = true;
            }
        }
    }
}

pub(super) fn ownership_path(backup: &Path) -> PathBuf {
    backup.with_extension("state")
}

pub(super) fn load_ownership_at(
    state_path: &Path,
) -> Result<Option<PersistedResolvConfOwnership>, PlatformError> {
    let metadata = match std::fs::symlink_metadata(state_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(PlatformError::DnsError(format!(
                "inspect resolver ownership state {}: {error}",
                state_path.display()
            )))
        }
    };
    if !metadata.file_type().is_file() {
        return Err(PlatformError::DnsError(format!(
            "resolver ownership state {} is not a regular file",
            state_path.display()
        )));
    }
    let contents = std::fs::read_to_string(state_path).map_err(|error| {
        PlatformError::DnsError(format!(
            "read resolver ownership state {}: {error}",
            state_path.display()
        ))
    })?;
    let state: PersistedResolvConfOwnership = serde_json::from_str(&contents).map_err(|error| {
        PlatformError::DnsError(format!(
            "parse resolver ownership state {}: {error}",
            state_path.display()
        ))
    })?;
    if state.schema != RESOLV_CONF_STATE_SCHEMA
        || state.owner_boot_id.trim().is_empty()
        || state.owner_boot_id.chars().any(char::is_whitespace)
        || state.owner_pid == 0
        || state.owner_start_time == 0
        || state.owner_marker
            != owner_marker(&ProcessIdentity {
                boot_id: state.owner_boot_id.clone(),
                pid: state.owner_pid,
                start_time: state.owner_start_time,
            })
    {
        return Err(PlatformError::DnsError(format!(
            "resolver ownership state {} has invalid identity",
            state_path.display()
        )));
    }
    Ok(Some(state))
}

pub(super) fn persist_ownership_at(
    state_path: &Path,
    identity: &ProcessIdentity,
    original_present: bool,
) -> Result<(), PlatformError> {
    if identity.boot_id.trim().is_empty()
        || identity.boot_id.chars().any(char::is_whitespace)
        || identity.pid == 0
        || identity.start_time == 0
    {
        return Err(PlatformError::DnsError("resolver ownership identity is invalid".to_string()));
    }
    let state = PersistedResolvConfOwnership {
        schema: RESOLV_CONF_STATE_SCHEMA,
        owner_boot_id: identity.boot_id.clone(),
        owner_pid: identity.pid,
        owner_start_time: identity.start_time,
        owner_marker: owner_marker(identity),
        original_present,
    };
    let bytes = serde_json::to_vec(&state).map_err(|error| {
        PlatformError::DnsError(format!(
            "serialize resolver ownership state {}: {error}",
            state_path.display()
        ))
    })?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(state_path).map_err(|error| {
        PlatformError::DnsError(format!(
            "create resolver ownership state {}: {error}",
            state_path.display()
        ))
    })?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        let cleanup = std::fs::remove_file(state_path);
        return Err(match cleanup {
            Ok(()) => PlatformError::DnsError(format!(
                "write resolver ownership state {}: {error}",
                state_path.display()
            )),
            Err(cleanup_error) => PlatformError::DnsError(format!(
                "write resolver ownership state {}: {error}; cleanup failed: {cleanup_error}",
                state_path.display()
            )),
        });
    }
    Ok(())
}

pub(super) fn remove_ownership_at(state_path: &Path) -> Result<(), PlatformError> {
    match std::fs::remove_file(state_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(PlatformError::DnsError(format!(
            "remove resolver ownership state {}: {error}",
            state_path.display()
        ))),
    }
}

pub(super) fn restore_persisted_resolv_conf_at(
    source: &Path,
    backup: &Path,
    state_path: &Path,
    ownership: &PersistedResolvConfOwnership,
) -> Result<(), PlatformError> {
    let mut restore_state = Some(if ownership.original_present {
        ResolvConfRestoreState::Present {
            backup: backup.to_path_buf(),
            owner_marker: ownership.owner_marker.clone(),
            write_completed: true,
        }
    } else {
        ResolvConfRestoreState::Absent {
            owner_marker: ownership.owner_marker.clone(),
            write_completed: true,
        }
    });
    restore_resolv_conf_at(source, &mut restore_state)?;
    remove_ownership_at(state_path)
}

pub(super) fn backup_resolv_conf_at(
    source: &Path,
    backup: &Path,
    owner_marker: &str,
    state: &mut Option<ResolvConfRestoreState>,
) -> Result<(), PlatformError> {
    if state.is_some() {
        return Ok(());
    }
    if !source.exists() {
        *state = Some(ResolvConfRestoreState::Absent {
            owner_marker: owner_marker.to_string(),
            write_completed: false,
        });
        return Ok(());
    }
    std::fs::copy(source, backup).map_err(|error| {
        PlatformError::DnsError(format!(
            "backup resolver file {} to {}: {error}",
            source.display(),
            backup.display()
        ))
    })?;
    *state = Some(ResolvConfRestoreState::Present {
        backup: backup.to_path_buf(),
        owner_marker: owner_marker.to_string(),
        write_completed: false,
    });
    Ok(())
}

pub(super) fn mark_resolv_conf_written(
    state: &mut Option<ResolvConfRestoreState>,
) -> Result<(), PlatformError> {
    let Some(state) = state else {
        return Err(PlatformError::DnsError(
            "resolver write completed without restore state".to_string(),
        ));
    };
    state.mark_write_completed();
    Ok(())
}

pub(super) fn source_has_owner_marker(
    source: &Path,
    owner_marker: &str,
) -> Result<bool, PlatformError> {
    let contents = std::fs::read(source).map_err(|error| {
        PlatformError::DnsError(format!(
            "read resolver file {} for ownership verification: {error}",
            source.display()
        ))
    })?;
    Ok(contents.split(|byte| *byte == b'\n').any(|line| line == owner_marker.as_bytes()))
}

pub(super) fn restore_resolv_conf_at(
    source: &Path,
    state: &mut Option<ResolvConfRestoreState>,
) -> Result<(), PlatformError> {
    let Some(restore_state) = state.clone() else {
        return Ok(());
    };

    match restore_state {
        ResolvConfRestoreState::Present { backup, owner_marker, write_completed } => {
            if !backup.exists() {
                return Err(PlatformError::DnsError(format!(
                    "resolver backup {} is missing; refusing to claim DNS restore",
                    backup.display()
                )));
            }
            if write_completed && !source_has_owner_marker(source, &owner_marker)? {
                return Err(PlatformError::DnsError(format!(
                    "resolver file {} has no QuicFuscate ownership marker; refusing restore",
                    source.display()
                )));
            }
            std::fs::copy(&backup, source).map_err(|error| {
                PlatformError::DnsError(format!(
                    "restore resolver file {} from {}: {error}",
                    source.display(),
                    backup.display()
                ))
            })?;
            std::fs::remove_file(&backup).map_err(|error| {
                PlatformError::DnsError(format!(
                    "remove resolver backup {} after restore: {error}",
                    backup.display()
                ))
            })?;
        }
        ResolvConfRestoreState::Absent { owner_marker, write_completed } => {
            if write_completed
                && source.exists()
                && !source_has_owner_marker(source, &owner_marker)?
            {
                return Err(PlatformError::DnsError(format!(
                    "resolver file {} has no QuicFuscate ownership marker; refusing removal",
                    source.display()
                )));
            }
            match std::fs::remove_file(source) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(PlatformError::DnsError(format!(
                        "remove resolver file {} after absent-original session: {error}",
                        source.display()
                    )))
                }
            }
        }
    }

    *state = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique_dns_test_dir(label: &str) -> PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "quicfuscate-dns-restore-{label}-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("create unique DNS restore test directory");
        directory
    }

    fn dns_test_paths(label: &str) -> (PathBuf, PathBuf, PathBuf) {
        let directory = unique_dns_test_dir(label);
        let source = directory.join("resolv.conf");
        let backup = directory.join("resolv.conf.quicfuscate.bak");
        (directory, source, backup)
    }

    fn test_identity(pid: u32) -> ProcessIdentity {
        ProcessIdentity { boot_id: "test-boot".to_string(), pid, start_time: 9876 }
    }

    fn managed_resolver_content(identity: &ProcessIdentity, body: &str) -> String {
        format!("{}\n{body}", owner_marker(identity))
    }

    #[test]
    fn absent_resolv_conf_round_trip_removes_written_file() {
        let (directory, source, backup) = dns_test_paths("absent");
        let identity = test_identity(4241);
        let marker = owner_marker(&identity);
        let mut state = None;

        backup_resolv_conf_at(&source, &backup, &marker, &mut state)
            .expect("record absent resolver state");
        assert!(matches!(state, Some(ResolvConfRestoreState::Absent { .. })));
        assert_eq!(state.as_ref().expect("absent restore state").owner_marker(), marker);

        std::fs::write(&source, managed_resolver_content(&identity, "nameserver 10.8.0.53\n"))
            .expect("write VPN resolver state");
        mark_resolv_conf_written(&mut state).expect("mark resolver write complete");
        restore_resolv_conf_at(&source, &mut state).expect("restore absent resolver state");

        assert!(!source.exists(), "resolver file must be removed when originally absent");
        assert!(!backup.exists(), "absent-original restore must not create a backup");
        assert_eq!(state, None);
        std::fs::remove_dir(&directory).expect("remove DNS restore test directory");
    }

    #[test]
    fn present_resolv_conf_round_trip_restores_original_bytes() {
        let (directory, source, backup) = dns_test_paths("present");
        let identity = test_identity(4242);
        let marker = owner_marker(&identity);
        let original = b"# host resolver\nnameserver 192.0.2.53\nsearch example.test\n";
        std::fs::write(&source, original).expect("write original resolver state");
        let mut state = None;

        backup_resolv_conf_at(&source, &backup, &marker, &mut state)
            .expect("backup existing resolver state");
        assert!(matches!(state, Some(ResolvConfRestoreState::Present { .. })));

        std::fs::write(&source, managed_resolver_content(&identity, "nameserver 10.8.0.53\n"))
            .expect("write VPN resolver state");
        mark_resolv_conf_written(&mut state).expect("mark resolver write complete");
        restore_resolv_conf_at(&source, &mut state).expect("restore existing resolver state");

        assert_eq!(std::fs::read(&source).expect("read restored resolver state"), original);
        assert!(!backup.exists(), "successful restore must remove the backup");
        assert_eq!(state, None);
        std::fs::remove_file(&source).expect("remove restored resolver state");
        std::fs::remove_dir(&directory).expect("remove DNS restore test directory");
    }

    #[test]
    fn missing_resolv_conf_backup_keeps_restore_state_and_fails_closed() {
        let (directory, source, backup) = dns_test_paths("missing-backup");
        let identity = test_identity(4243);
        let marker = owner_marker(&identity);
        std::fs::write(&source, b"# host resolver\n").expect("write original resolver state");
        let mut state = None;

        backup_resolv_conf_at(&source, &backup, &marker, &mut state)
            .expect("backup existing resolver state");
        std::fs::remove_file(&backup).expect("remove test backup");
        std::fs::write(&source, managed_resolver_content(&identity, "nameserver 10.8.0.53\n"))
            .expect("write VPN resolver state");
        mark_resolv_conf_written(&mut state).expect("mark resolver write complete");

        let error = restore_resolv_conf_at(&source, &mut state)
            .expect_err("missing backup must not report a successful restore");
        assert!(error.to_string().contains("backup"));
        assert!(matches!(state, Some(ResolvConfRestoreState::Present { .. })));
        std::fs::remove_file(&source).expect("remove test resolver state");
        std::fs::remove_dir(&directory).expect("remove DNS restore test directory");
    }

    #[test]
    fn absent_restore_refuses_unowned_file() {
        let (directory, source, backup) = dns_test_paths("absent-unowned");
        let identity = test_identity(4247);
        let marker = owner_marker(&identity);
        let mut state = None;

        backup_resolv_conf_at(&source, &backup, &marker, &mut state)
            .expect("record absent resolver state");
        std::fs::write(&source, b"nameserver 192.0.2.53\n").expect("write foreign resolver state");
        mark_resolv_conf_written(&mut state).expect("mark resolver write complete");

        let error = restore_resolv_conf_at(&source, &mut state)
            .expect_err("restore must refuse a file without the ownership marker");
        assert!(error.to_string().contains("ownership marker"));
        assert!(source.exists());
        assert!(matches!(state, Some(ResolvConfRestoreState::Absent { .. })));
        std::fs::remove_file(&source).expect("remove foreign resolver state");
        std::fs::remove_dir(&directory).expect("remove DNS restore test directory");
    }

    #[test]
    fn ownership_marker_round_trip_is_create_only_and_removable() {
        let (directory, _source, backup) = dns_test_paths("ownership");
        let state_path = ownership_path(&backup);
        let identity = test_identity(4244);

        persist_ownership_at(&state_path, &identity, false).expect("persist ownership marker");
        let loaded = load_ownership_at(&state_path)
            .expect("load ownership marker")
            .expect("ownership marker must exist");
        assert_eq!(loaded.owner_boot_id, identity.boot_id);
        assert_eq!(loaded.owner_pid, identity.pid);
        assert_eq!(loaded.owner_start_time, identity.start_time);
        assert_eq!(loaded.owner_marker, owner_marker(&identity));
        assert!(!loaded.original_present);

        let duplicate = persist_ownership_at(&state_path, &identity, true)
            .expect_err("ownership marker must not be overwritten");
        assert!(duplicate.to_string().contains("create resolver ownership state"));
        remove_ownership_at(&state_path).expect("remove ownership marker");
        assert!(load_ownership_at(&state_path).expect("reload ownership marker").is_none());
        std::fs::remove_dir(&directory).expect("remove DNS restore test directory");
    }

    #[test]
    fn persisted_absent_state_recovers_written_file_and_marker() {
        let (directory, source, backup) = dns_test_paths("persisted-absent");
        let state_path = ownership_path(&backup);
        let identity =
            ProcessIdentity { boot_id: "stale-boot".to_string(), pid: 4245, start_time: 9877 };
        persist_ownership_at(&state_path, &identity, false).expect("persist stale absent state");
        std::fs::write(&source, managed_resolver_content(&identity, "nameserver 10.8.0.53\n"))
            .expect("write stale VPN state");

        let ownership = load_ownership_at(&state_path)
            .expect("load stale absent state")
            .expect("stale absent state must exist");
        restore_persisted_resolv_conf_at(&source, &backup, &state_path, &ownership)
            .expect("recover stale absent state");

        assert!(!source.exists());
        assert!(!state_path.exists());
        std::fs::remove_dir(&directory).expect("remove DNS restore test directory");
    }

    #[test]
    fn persisted_present_state_recovers_original_bytes_and_marker() {
        let (directory, source, backup) = dns_test_paths("persisted-present");
        let state_path = ownership_path(&backup);
        let identity =
            ProcessIdentity { boot_id: "stale-boot".to_string(), pid: 4246, start_time: 9878 };
        let original = b"nameserver 192.0.2.53\n";
        std::fs::write(&source, original).expect("write original resolver state");
        std::fs::copy(&source, &backup).expect("create resolver backup");
        persist_ownership_at(&state_path, &identity, true).expect("persist stale present state");
        std::fs::write(&source, managed_resolver_content(&identity, "nameserver 10.8.0.53\n"))
            .expect("write stale VPN state");

        let ownership = load_ownership_at(&state_path)
            .expect("load stale present state")
            .expect("stale present state must exist");
        restore_persisted_resolv_conf_at(&source, &backup, &state_path, &ownership)
            .expect("recover stale present state");

        assert_eq!(std::fs::read(&source).expect("read recovered resolver state"), original);
        assert!(!backup.exists());
        assert!(!state_path.exists());
        std::fs::remove_file(&source).expect("remove recovered resolver state");
        std::fs::remove_dir(&directory).expect("remove DNS restore test directory");
    }

    #[test]
    fn persisted_present_state_refuses_unowned_current_file() {
        let (directory, source, backup) = dns_test_paths("persisted-present-unowned");
        let state_path = ownership_path(&backup);
        let identity =
            ProcessIdentity { boot_id: "stale-boot".to_string(), pid: 4248, start_time: 9879 };
        let original = b"nameserver 192.0.2.53\n";
        std::fs::write(&source, original).expect("write original resolver state");
        std::fs::copy(&source, &backup).expect("create resolver backup");
        persist_ownership_at(&state_path, &identity, true).expect("persist stale present state");
        std::fs::write(&source, b"nameserver 198.51.100.53\n")
            .expect("write foreign resolver state");

        let ownership = load_ownership_at(&state_path)
            .expect("load stale present state")
            .expect("stale present state must exist");
        let error = restore_persisted_resolv_conf_at(&source, &backup, &state_path, &ownership)
            .expect_err("stale recovery must refuse an unowned current file");
        assert!(error.to_string().contains("ownership marker"));
        assert_eq!(
            std::fs::read(&source).expect("read foreign resolver state"),
            b"nameserver 198.51.100.53\n"
        );
        assert!(backup.exists());
        assert!(state_path.exists());
        std::fs::remove_file(&source).expect("remove foreign resolver state");
        std::fs::remove_file(&backup).expect("remove resolver backup");
        std::fs::remove_file(&state_path).expect("remove resolver ownership state");
        std::fs::remove_dir(&directory).expect("remove DNS restore test directory");
    }
}
