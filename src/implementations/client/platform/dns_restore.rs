//! Resolver-file backup and restore state shared by platform tests and Linux.

use super::traits::PlatformError;
use serde::{Deserialize, Serialize};
use std::fs::Metadata;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
#[cfg(not(unix))]
use std::time::UNIX_EPOCH;

const RESOLV_CONF_STATE_SCHEMA: u8 = 3;
const OWNER_MARKER_PREFIX: &str = "# quicfuscate-resolver-owner=";

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(super) enum ResolverPathKind {
    Absent,
    RegularFile,
    Symlink,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(super) struct ResolverObjectIdentity {
    #[serde(default)]
    device: Option<u64>,
    #[serde(default)]
    inode: Option<u64>,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    modified_nanos: Option<u128>,
}

impl ResolverObjectIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                device: Some(metadata.dev()),
                inode: Some(metadata.ino()),
                size: 0,
                modified_nanos: None,
            }
        }

        #[cfg(not(unix))]
        Self {
            device: None,
            inode: None,
            size: metadata.len(),
            modified_nanos: metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .map(|value| value.as_nanos()),
        }
    }

    fn matches(&self, other: &Self) -> bool {
        match (self.device, self.inode, other.device, other.inode) {
            (Some(device), Some(inode), Some(other_device), Some(other_inode)) => {
                device == other_device && inode == other_inode
            }
            _ => self.size == other.size && self.modified_nanos == other.modified_nanos,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(super) struct ResolverPathIdentity {
    kind: ResolverPathKind,
    path_object: Option<ResolverObjectIdentity>,
    link_target: Option<PathBuf>,
    canonical_target: Option<PathBuf>,
    target_object: Option<ResolverObjectIdentity>,
}

impl ResolverPathIdentity {
    fn absent() -> Self {
        Self {
            kind: ResolverPathKind::Absent,
            path_object: None,
            link_target: None,
            canonical_target: None,
            target_object: None,
        }
    }

    fn is_valid(&self) -> bool {
        match self.kind {
            ResolverPathKind::Absent => {
                self.path_object.is_none()
                    && self.link_target.is_none()
                    && self.canonical_target.is_none()
                    && self.target_object.is_none()
            }
            ResolverPathKind::RegularFile => {
                self.path_object.is_some()
                    && self.link_target.is_none()
                    && self.canonical_target.is_none()
                    && self.target_object.is_none()
            }
            ResolverPathKind::Symlink => {
                self.path_object.is_some()
                    && self.link_target.is_some()
                    && self.canonical_target.is_some()
                    && self.target_object.is_some()
            }
        }
    }

    pub(super) fn matches(&self, other: &Self) -> bool {
        if self.kind != other.kind || !self.is_valid() || !other.is_valid() {
            return false;
        }
        let path_matches = self
            .path_object
            .as_ref()
            .zip(other.path_object.as_ref())
            .is_some_and(|(expected, current)| expected.matches(current));
        if self.kind == ResolverPathKind::Absent {
            return self.path_object.is_none() && other.path_object.is_none();
        }
        if !path_matches {
            return false;
        }
        if self.kind != ResolverPathKind::Symlink {
            return true;
        }
        self.link_target == other.link_target
            && self.canonical_target == other.canonical_target
            && self
                .target_object
                .as_ref()
                .zip(other.target_object.as_ref())
                .is_some_and(|(expected, current)| expected.matches(current))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ResolvConfRestoreState {
    Present {
        backup: PathBuf,
        backup_identity: ResolverObjectIdentity,
        backup_digest: [u8; 32],
        owner_marker: String,
        original: ResolverPathIdentity,
        managed: Option<ResolverPathIdentity>,
    },
    Absent {
        owner_marker: String,
        original: ResolverPathIdentity,
        managed: Option<ResolverPathIdentity>,
    },
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
    pub(super) original: ResolverPathIdentity,
    pub(super) backup: Option<ResolverObjectIdentity>,
    pub(super) backup_digest: Option<[u8; 32]>,
    pub(super) managed: Option<ResolverPathIdentity>,
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

    pub(super) fn original_identity(&self) -> &ResolverPathIdentity {
        match self {
            Self::Present { original, .. } | Self::Absent { original, .. } => original,
        }
    }

    fn managed_identity(&self) -> Option<&ResolverPathIdentity> {
        match self {
            Self::Present { managed, .. } | Self::Absent { managed, .. } => managed.as_ref(),
        }
    }
}

pub(super) fn ownership_path(backup: &Path) -> PathBuf {
    backup.with_extension("state")
}

pub(super) fn path_entry_exists(path: &Path) -> Result<bool, PlatformError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(PlatformError::DnsError(format!(
            "inspect resolver path {}: {error}",
            path.display()
        ))),
    }
}

pub(super) fn capture_resolver_path_identity(
    source: &Path,
) -> Result<ResolverPathIdentity, PlatformError> {
    let metadata = match std::fs::symlink_metadata(source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(ResolverPathIdentity::absent())
        }
        Err(error) => {
            return Err(PlatformError::DnsError(format!(
                "inspect resolver path {}: {error}",
                source.display()
            )))
        }
    };
    let path_object = ResolverObjectIdentity::from_metadata(&metadata);
    if metadata.file_type().is_file() {
        return Ok(ResolverPathIdentity {
            kind: ResolverPathKind::RegularFile,
            path_object: Some(path_object),
            link_target: None,
            canonical_target: None,
            target_object: None,
        });
    }
    if !metadata.file_type().is_symlink() {
        return Err(PlatformError::DnsError(format!(
            "resolver path {} is neither a regular file nor a symlink",
            source.display()
        )));
    }

    let link_target = std::fs::read_link(source).map_err(|error| {
        PlatformError::DnsError(format!("read resolver symlink {}: {error}", source.display()))
    })?;
    let resolved_target = if link_target.is_absolute() {
        link_target.clone()
    } else {
        source.parent().unwrap_or_else(|| Path::new(".")).join(&link_target)
    };
    let target_metadata = std::fs::metadata(&resolved_target).map_err(|error| {
        if error.kind() == ErrorKind::NotFound {
            PlatformError::DnsError(format!(
                "resolver symlink {} is broken; refusing DNS mutation",
                source.display()
            ))
        } else {
            PlatformError::DnsError(format!(
                "inspect resolver symlink target {}: {error}",
                source.display()
            ))
        }
    })?;
    if !target_metadata.file_type().is_file() {
        return Err(PlatformError::DnsError(format!(
            "resolver symlink {} does not target a regular file",
            source.display()
        )));
    }
    let canonical_target = std::fs::canonicalize(&resolved_target).map_err(|error| {
        PlatformError::DnsError(format!(
            "canonicalize resolver symlink target {}: {error}",
            source.display()
        ))
    })?;
    Ok(ResolverPathIdentity {
        kind: ResolverPathKind::Symlink,
        path_object: Some(path_object),
        link_target: Some(link_target),
        canonical_target: Some(canonical_target),
        target_object: Some(ResolverObjectIdentity::from_metadata(&target_metadata)),
    })
}

fn capture_backup_identity(backup: &Path) -> Result<ResolverObjectIdentity, PlatformError> {
    let identity = capture_resolver_path_identity(backup)?;
    if identity.kind != ResolverPathKind::RegularFile {
        return Err(PlatformError::DnsError(format!(
            "resolver backup {} is not a regular file",
            backup.display()
        )));
    }
    identity.path_object.ok_or_else(|| {
        PlatformError::DnsError(format!(
            "resolver backup {} has no file identity",
            backup.display()
        ))
    })
}

fn write_create_new_file(path: &Path, contents: &[u8], purpose: &str) -> Result<(), PlatformError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        PlatformError::DnsError(format!(
            "create {purpose} {} without overwrite: {error}",
            path.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            let cleanup = std::fs::remove_file(path);
            return Err(match cleanup {
                Ok(()) => {
                    PlatformError::DnsError(format!("secure {purpose} {}: {error}", path.display()))
                }
                Err(cleanup_error) => PlatformError::DnsError(format!(
                    "secure {purpose} {}: {error}; cleanup failed: {cleanup_error}",
                    path.display()
                )),
            });
        }
    }
    if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
        let cleanup = std::fs::remove_file(path);
        return Err(match cleanup {
            Ok(()) => {
                PlatformError::DnsError(format!("write {purpose} {}: {error}", path.display()))
            }
            Err(cleanup_error) => PlatformError::DnsError(format!(
                "write {purpose} {}: {error}; cleanup failed: {cleanup_error}",
                path.display()
            )),
        });
    }
    Ok(())
}

fn create_backup_file(backup: &Path, contents: &[u8]) -> Result<(), PlatformError> {
    write_create_new_file(backup, contents, "resolver backup")
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
    let identity_valid = state.owner_boot_id.trim() == state.owner_boot_id
        && !state.owner_boot_id.is_empty()
        && !state.owner_boot_id.chars().any(char::is_whitespace)
        && state.owner_pid != 0
        && state.owner_start_time != 0
        && state.owner_marker
            == owner_marker(&ProcessIdentity {
                boot_id: state.owner_boot_id.clone(),
                pid: state.owner_pid,
                start_time: state.owner_start_time,
            });
    let original_valid = state.original.is_valid();
    let backup_valid = matches!(
        (&state.original.kind, &state.backup, &state.backup_digest),
        (ResolverPathKind::Absent, None, None)
            | (ResolverPathKind::RegularFile | ResolverPathKind::Symlink, Some(_), Some(_))
    );
    let managed_valid = state
        .managed
        .as_ref()
        .is_none_or(|managed| managed.is_valid() && managed.kind != ResolverPathKind::Absent);
    if state.schema != RESOLV_CONF_STATE_SCHEMA
        || !identity_valid
        || !original_valid
        || !backup_valid
        || !managed_valid
    {
        return Err(PlatformError::DnsError(format!(
            "resolver ownership state {} has invalid schema or ownership identity",
            state_path.display()
        )));
    }
    Ok(Some(state))
}

pub(super) fn persist_ownership_at(
    state_path: &Path,
    identity: &ProcessIdentity,
    original: ResolverPathIdentity,
    backup: Option<ResolverObjectIdentity>,
    backup_digest: Option<[u8; 32]>,
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
        original,
        backup,
        backup_digest,
        managed: None,
    };
    if !state.original.is_valid()
        || !matches!(
            (&state.original.kind, &state.backup, &state.backup_digest),
            (ResolverPathKind::Absent, None, None)
                | (ResolverPathKind::RegularFile | ResolverPathKind::Symlink, Some(_), Some(_))
        )
    {
        return Err(PlatformError::DnsError(
            "resolver ownership state has an invalid source/backup contract".to_string(),
        ));
    }
    let bytes = serialize_ownership(&state, state_path)?;
    write_create_new_file(state_path, &bytes, "resolver ownership state")
}

pub(super) fn mark_ownership_written_at(
    state_path: &Path,
    managed: ResolverPathIdentity,
) -> Result<(), PlatformError> {
    if !managed.is_valid() || managed.kind == ResolverPathKind::Absent {
        return Err(PlatformError::DnsError(
            "managed resolver identity must be a regular file or valid symlink".to_string(),
        ));
    }
    let mut ownership = load_ownership_at(state_path)?.ok_or_else(|| {
        PlatformError::DnsError(format!(
            "resolver ownership state {} disappeared before write publication",
            state_path.display()
        ))
    })?;
    if let Some(existing) = ownership.managed.as_ref() {
        if !existing.matches(&managed) {
            return Err(PlatformError::DnsError(format!(
                "resolver managed path identity changed in {}",
                state_path.display()
            )));
        }
        return Ok(());
    }
    ownership.managed = Some(managed);
    let bytes = serialize_ownership(&ownership, state_path)?;
    replace_ownership_file(state_path, &bytes)
}

fn serialize_ownership(
    ownership: &PersistedResolvConfOwnership,
    state_path: &Path,
) -> Result<Vec<u8>, PlatformError> {
    serde_json::to_vec(ownership).map_err(|error| {
        PlatformError::DnsError(format!(
            "serialize resolver ownership state {}: {error}",
            state_path.display()
        ))
    })
}

fn replace_ownership_file(state_path: &Path, bytes: &[u8]) -> Result<(), PlatformError> {
    let name = state_path.file_name().and_then(|value| value.to_str()).ok_or_else(|| {
        PlatformError::DnsError(format!(
            "resolver ownership state {} has no valid file name",
            state_path.display()
        ))
    })?;
    let temporary_path = state_path.with_file_name(format!(".{name}.tmp-{}", std::process::id()));
    write_create_new_file(&temporary_path, bytes, "temporary resolver ownership state")?;
    if let Err(error) = std::fs::rename(&temporary_path, state_path) {
        let cleanup = std::fs::remove_file(&temporary_path);
        return Err(match cleanup {
            Ok(()) => PlatformError::DnsError(format!(
                "replace resolver ownership state {}: {error}",
                state_path.display()
            )),
            Err(cleanup_error) => PlatformError::DnsError(format!(
                "replace resolver ownership state {}: {error}; cleanup failed: {cleanup_error}",
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
    let mut restore_state = Some(match ownership.original.kind {
        ResolverPathKind::Absent => ResolvConfRestoreState::Absent {
            owner_marker: ownership.owner_marker.clone(),
            original: ownership.original.clone(),
            managed: ownership.managed.clone(),
        },
        ResolverPathKind::RegularFile | ResolverPathKind::Symlink => {
            let backup_identity = ownership.backup.clone().ok_or_else(|| {
                PlatformError::DnsError(format!(
                    "resolver ownership state {} omitted the backup identity",
                    state_path.display()
                ))
            })?;
            let backup_digest = ownership.backup_digest.ok_or_else(|| {
                PlatformError::DnsError(format!(
                    "resolver ownership state {} omitted the backup digest",
                    state_path.display()
                ))
            })?;
            ResolvConfRestoreState::Present {
                backup: backup.to_path_buf(),
                backup_identity,
                backup_digest,
                owner_marker: ownership.owner_marker.clone(),
                original: ownership.original.clone(),
                managed: ownership.managed.clone(),
            }
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
    let original = capture_resolver_path_identity(source)?;
    let backup_entry = capture_resolver_path_identity(backup)?;
    if backup_entry.kind != ResolverPathKind::Absent {
        return Err(PlatformError::DnsError(format!(
            "resolver backup {} already exists; refusing overwrite",
            backup.display()
        )));
    }
    if original.kind == ResolverPathKind::Absent {
        *state = Some(ResolvConfRestoreState::Absent {
            owner_marker: owner_marker.to_string(),
            original,
            managed: None,
        });
        return Ok(());
    }
    let contents = std::fs::read(source).map_err(|error| {
        PlatformError::DnsError(format!(
            "read resolver file {} for backup: {error}",
            source.display()
        ))
    })?;
    let current = capture_resolver_path_identity(source)?;
    if !original.matches(&current) {
        return Err(PlatformError::DnsError(format!(
            "resolver path {} changed during backup; refusing DNS mutation",
            source.display()
        )));
    }
    create_backup_file(backup, &contents)?;
    let backup_identity = capture_backup_identity(backup)?;
    let backup_digest = crate::crypto::hkdf::sha256(&contents);
    *state = Some(ResolvConfRestoreState::Present {
        backup: backup.to_path_buf(),
        backup_identity,
        backup_digest,
        owner_marker: owner_marker.to_string(),
        original,
        managed: None,
    });
    Ok(())
}

pub(super) fn verify_resolv_conf_write_target(
    source: &Path,
    state: &Option<ResolvConfRestoreState>,
) -> Result<(), PlatformError> {
    let Some(state) = state.as_ref() else {
        return Err(PlatformError::DnsError(
            "resolver write target checked without restore state".to_string(),
        ));
    };
    let current = capture_resolver_path_identity(source)?;
    let expected = state.managed_identity().unwrap_or_else(|| state.original_identity());
    if !expected.matches(&current) {
        return Err(PlatformError::DnsError(format!(
            "resolver path {} changed before DNS write; refusing mutation",
            source.display()
        )));
    }
    Ok(())
}

pub(super) fn mark_resolv_conf_written(
    source: &Path,
    state: &mut Option<ResolvConfRestoreState>,
) -> Result<ResolverPathIdentity, PlatformError> {
    let Some(state_ref) = state.as_mut() else {
        return Err(PlatformError::DnsError(
            "resolver write completed without restore state".to_string(),
        ));
    };
    let current = capture_resolver_path_identity(source)?;
    let expected = state_ref.managed_identity().unwrap_or_else(|| state_ref.original_identity());
    let initial_absent = matches!(state_ref, ResolvConfRestoreState::Absent { managed: None, .. });
    if (!initial_absent && !expected.matches(&current))
        || (initial_absent && current.kind != ResolverPathKind::RegularFile)
    {
        return Err(PlatformError::DnsError(format!(
            "resolver path {} changed during DNS write; refusing ownership publication",
            source.display()
        )));
    }
    if current.kind == ResolverPathKind::Absent {
        return Err(PlatformError::DnsError(
            "resolver write completed but the resolver path is absent".to_string(),
        ));
    }
    if matches!(state_ref, ResolvConfRestoreState::Absent { .. })
        && current.kind != ResolverPathKind::RegularFile
    {
        return Err(PlatformError::DnsError(
            "resolver write from an absent source did not create a regular file".to_string(),
        ));
    }
    *match state_ref {
        ResolvConfRestoreState::Present { managed, .. }
        | ResolvConfRestoreState::Absent { managed, .. } => managed,
    } = Some(current.clone());
    Ok(current)
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
        ResolvConfRestoreState::Present {
            backup,
            backup_identity,
            backup_digest,
            owner_marker,
            original,
            managed,
        } => {
            let current = capture_resolver_path_identity(source)?;
            let expected = managed.as_ref().unwrap_or(&original);
            if !expected.matches(&current) {
                return Err(PlatformError::DnsError(format!(
                    "resolver path {} changed; refusing restore",
                    source.display()
                )));
            }
            let current_backup_identity = capture_backup_identity(&backup)?;
            if !backup_identity.matches(&current_backup_identity) {
                return Err(PlatformError::DnsError(format!(
                    "resolver backup {} changed; refusing restore",
                    backup.display()
                )));
            }
            let backup_contents = std::fs::read(&backup).map_err(|error| {
                PlatformError::DnsError(format!(
                    "read resolver backup {} for restore: {error}",
                    backup.display()
                ))
            })?;
            if crate::crypto::hkdf::sha256(&backup_contents) != backup_digest {
                return Err(PlatformError::DnsError(format!(
                    "resolver backup {} content changed; refusing restore",
                    backup.display()
                )));
            }
            let source_is_owned = if managed.is_some() {
                source_has_owner_marker(source, &owner_marker)?
            } else {
                let source_contents = std::fs::read(source).map_err(|error| {
                    PlatformError::DnsError(format!(
                        "read resolver file {} for ownership verification: {error}",
                        source.display()
                    ))
                })?;
                source_contents
                    .split(|byte| *byte == b'\n')
                    .any(|line| line == owner_marker.as_bytes())
                    || source_contents == backup_contents
            };
            if !source_is_owned {
                return Err(PlatformError::DnsError(format!(
                    "resolver file {} has no proven QuicFuscate ownership; refusing restore",
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
            let restored = capture_resolver_path_identity(source)?;
            if !expected.matches(&restored)
                || std::fs::read(source).map_err(|error| {
                    PlatformError::DnsError(format!(
                        "read restored resolver file {}: {error}",
                        source.display()
                    ))
                })? != backup_contents
            {
                return Err(PlatformError::DnsError(format!(
                    "resolver path {} changed during restore; backup retained",
                    source.display()
                )));
            }
            std::fs::remove_file(&backup).map_err(|error| {
                PlatformError::DnsError(format!(
                    "remove resolver backup {} after restore: {error}",
                    backup.display()
                ))
            })?;
        }
        ResolvConfRestoreState::Absent { owner_marker, managed, .. } => {
            let current = capture_resolver_path_identity(source)?;
            let Some(managed) = managed else {
                if current.kind != ResolverPathKind::Absent {
                    return Err(PlatformError::DnsError(format!(
                        "resolver path {} appeared before ownership was published; refusing removal",
                        source.display()
                    )));
                }
                *state = None;
                return Ok(());
            };
            if current.kind == ResolverPathKind::Absent {
                *state = None;
                return Ok(());
            }
            if !managed.matches(&current) || !source_has_owner_marker(source, &owner_marker)? {
                return Err(PlatformError::DnsError(format!(
                    "resolver file {} has no proven QuicFuscate ownership; refusing removal",
                    source.display()
                )));
            }
            std::fs::remove_file(source).map_err(|error| {
                PlatformError::DnsError(format!(
                    "remove resolver file {} after absent-original session: {error}",
                    source.display()
                ))
            })?;
            if capture_resolver_path_identity(source)?.kind != ResolverPathKind::Absent {
                return Err(PlatformError::DnsError(format!(
                    "resolver path {} remains after absent-original restore",
                    source.display()
                )));
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
        verify_resolv_conf_write_target(&source, &state).expect("verify absent write target");

        std::fs::write(&source, managed_resolver_content(&identity, "nameserver 10.8.0.53\n"))
            .expect("write VPN resolver state");
        mark_resolv_conf_written(&source, &mut state).expect("mark resolver write complete");
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
        verify_resolv_conf_write_target(&source, &state).expect("verify present write target");

        std::fs::write(&source, managed_resolver_content(&identity, "nameserver 10.8.0.53\n"))
            .expect("write VPN resolver state");
        mark_resolv_conf_written(&source, &mut state).expect("mark resolver write complete");
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
        mark_resolv_conf_written(&source, &mut state).expect("mark resolver write complete");

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
        verify_resolv_conf_write_target(&source, &state).expect("verify absent write target");
        std::fs::write(&source, b"nameserver 192.0.2.53\n").expect("write foreign resolver state");
        mark_resolv_conf_written(&source, &mut state).expect("mark resolver write complete");

        let error = restore_resolv_conf_at(&source, &mut state)
            .expect_err("restore must refuse a file without the ownership marker");
        assert!(error.to_string().contains("ownership"));
        assert!(source.exists());
        assert!(matches!(state, Some(ResolvConfRestoreState::Absent { .. })));
        std::fs::remove_file(&source).expect("remove foreign resolver state");
        std::fs::remove_dir(&directory).expect("remove DNS restore test directory");
    }

    #[test]
    fn ownership_marker_round_trip_is_create_only_and_removable() {
        let (directory, source, backup) = dns_test_paths("ownership");
        let state_path = ownership_path(&backup);
        let identity = test_identity(4244);
        let original = capture_resolver_path_identity(&source).expect("capture absent source");
        assert!(!path_entry_exists(&source).expect("inspect absent source"));

        persist_ownership_at(&state_path, &identity, original.clone(), None, None)
            .expect("persist ownership marker");
        let loaded = load_ownership_at(&state_path)
            .expect("load ownership marker")
            .expect("ownership marker must exist");
        assert_eq!(loaded.owner_boot_id, identity.boot_id);
        assert_eq!(loaded.owner_pid, identity.pid);
        assert_eq!(loaded.owner_start_time, identity.start_time);
        assert_eq!(loaded.owner_marker, owner_marker(&identity));
        assert_eq!(loaded.original, original);
        assert!(path_entry_exists(&state_path).expect("inspect ownership state"));

        let duplicate = persist_ownership_at(&state_path, &identity, original, None, None)
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
        let original_identity =
            capture_resolver_path_identity(&source).expect("capture absent source");
        persist_ownership_at(&state_path, &identity, original_identity, None, None)
            .expect("persist stale absent state");
        std::fs::write(&source, managed_resolver_content(&identity, "nameserver 10.8.0.53\n"))
            .expect("write stale VPN state");
        let managed = capture_resolver_path_identity(&source).expect("capture managed source");
        mark_ownership_written_at(&state_path, managed).expect("publish managed source");

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
        let original_identity =
            capture_resolver_path_identity(&source).expect("capture original source");
        let backup_identity = capture_backup_identity(&backup).expect("capture backup identity");
        let backup_digest = crate::crypto::hkdf::sha256(original);
        persist_ownership_at(
            &state_path,
            &identity,
            original_identity,
            Some(backup_identity),
            Some(backup_digest),
        )
        .expect("persist stale present state");
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
        let original_identity =
            capture_resolver_path_identity(&source).expect("capture original source");
        let backup_identity = capture_backup_identity(&backup).expect("capture backup identity");
        let backup_digest = crate::crypto::hkdf::sha256(original);
        persist_ownership_at(
            &state_path,
            &identity,
            original_identity,
            Some(backup_identity),
            Some(backup_digest),
        )
        .expect("persist stale present state");
        std::fs::write(&source, b"nameserver 198.51.100.53\n")
            .expect("write foreign resolver state");

        let ownership = load_ownership_at(&state_path)
            .expect("load stale present state")
            .expect("stale present state must exist");
        let error = restore_persisted_resolv_conf_at(&source, &backup, &state_path, &ownership)
            .expect_err("stale recovery must refuse an unowned current file");
        assert!(error.to_string().contains("ownership"));
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

    #[cfg(unix)]
    #[test]
    fn broken_source_symlink_is_rejected_without_mutation() {
        use std::os::unix::fs::symlink;

        let (directory, source, backup) = dns_test_paths("broken-source-symlink");
        let target = directory.join("missing-target");
        symlink(&target, &source).expect("create broken resolver symlink");
        let marker = owner_marker(&test_identity(4249));
        let mut state = None;

        let error = backup_resolv_conf_at(&source, &backup, &marker, &mut state)
            .expect_err("broken resolver symlink must be rejected");
        assert!(error.to_string().contains("broken"));
        restore_resolv_conf_at(&source, &mut state)
            .expect("failed activation cleanup must not touch an unowned symlink");
        assert_eq!(std::fs::read_link(&source).expect("read broken resolver symlink"), target);
        assert!(!path_entry_exists(&backup).expect("inspect resolver backup"));
        assert!(state.is_none());

        std::fs::remove_file(&source).expect("remove broken resolver symlink");
        std::fs::remove_dir(&directory).expect("remove DNS restore test directory");
    }

    #[cfg(unix)]
    #[test]
    fn valid_resolver_symlink_round_trip_preserves_link_and_target() {
        use std::os::unix::fs::symlink;

        let (directory, source, backup) = dns_test_paths("valid-symlink");
        let target = directory.join("target");
        let identity = test_identity(4250);
        let marker = owner_marker(&identity);
        let original = b"nameserver 192.0.2.53\n";
        std::fs::write(&target, original).expect("write resolver symlink target");
        symlink(&target, &source).expect("create resolver symlink");
        let mut state = None;

        backup_resolv_conf_at(&source, &backup, &marker, &mut state)
            .expect("backup resolver symlink target");
        verify_resolv_conf_write_target(&source, &state).expect("verify resolver symlink target");
        std::fs::write(&source, managed_resolver_content(&identity, "nameserver 10.8.0.53\n"))
            .expect("write managed resolver through symlink");
        mark_resolv_conf_written(&source, &mut state).expect("publish managed symlink target");
        restore_resolv_conf_at(&source, &mut state).expect("restore resolver symlink target");

        assert_eq!(std::fs::read_link(&source).expect("read resolver symlink"), target);
        assert_eq!(std::fs::read(&target).expect("read restored resolver target"), original);
        assert!(!path_entry_exists(&backup).expect("inspect removed resolver backup"));
        assert!(state.is_none());

        std::fs::remove_file(&source).expect("remove resolver symlink");
        std::fs::remove_file(&target).expect("remove resolver symlink target");
        std::fs::remove_dir(&directory).expect("remove DNS restore test directory");
    }

    #[cfg(unix)]
    #[test]
    fn replaced_symlink_target_is_refused_without_consuming_backup() {
        use std::os::unix::fs::symlink;

        let (directory, source, backup) = dns_test_paths("replaced-symlink-target");
        let target = directory.join("target");
        let archived_target = directory.join("target.original");
        let replacement_target = directory.join("target.replacement");
        let identity = test_identity(4251);
        let marker = owner_marker(&identity);
        std::fs::write(&target, b"nameserver 192.0.2.53\n")
            .expect("write original resolver symlink target");
        symlink(&target, &source).expect("create resolver symlink");
        let mut state = None;

        backup_resolv_conf_at(&source, &backup, &marker, &mut state)
            .expect("backup resolver symlink target");
        std::fs::write(&source, managed_resolver_content(&identity, "nameserver 10.8.0.53\n"))
            .expect("write managed resolver through symlink");
        mark_resolv_conf_written(&source, &mut state).expect("publish managed symlink target");
        std::fs::write(&replacement_target, b"nameserver 198.51.100.53\n")
            .expect("write replacement resolver target");
        std::fs::rename(&target, &archived_target).expect("archive original resolver target");
        std::fs::rename(&replacement_target, &target).expect("replace resolver target");

        let error = restore_resolv_conf_at(&source, &mut state)
            .expect_err("replacement resolver target must be refused");
        assert!(error.to_string().contains("changed"));
        assert_eq!(std::fs::read_link(&source).expect("read resolver symlink"), target);
        assert_eq!(
            std::fs::read(&target).expect("read replacement resolver target"),
            b"nameserver 198.51.100.53\n"
        );
        assert!(path_entry_exists(&backup).expect("inspect retained resolver backup"));
        assert!(state.is_some());

        std::fs::remove_file(&source).expect("remove resolver symlink");
        std::fs::remove_file(&target).expect("remove replacement resolver target");
        std::fs::remove_file(&archived_target).expect("remove archived resolver target");
        std::fs::remove_file(&backup).expect("remove retained resolver backup");
        std::fs::remove_dir(&directory).expect("remove DNS restore test directory");
    }

    #[cfg(unix)]
    #[test]
    fn absent_original_broken_symlink_is_refused_without_removal() {
        use std::os::unix::fs::symlink;

        let (directory, source, backup) = dns_test_paths("absent-broken-symlink");
        let target = directory.join("missing-target");
        let marker = owner_marker(&test_identity(4252));
        let mut state = None;

        backup_resolv_conf_at(&source, &backup, &marker, &mut state)
            .expect("record absent resolver state");
        symlink(&target, &source).expect("create foreign broken resolver symlink");

        let error = restore_resolv_conf_at(&source, &mut state)
            .expect_err("foreign broken resolver symlink must be refused");
        assert!(error.to_string().contains("broken"));
        assert_eq!(std::fs::read_link(&source).expect("read foreign resolver symlink"), target);
        assert!(state.is_some());

        std::fs::remove_file(&source).expect("remove foreign resolver symlink");
        std::fs::remove_dir(&directory).expect("remove DNS restore test directory");
    }

    #[cfg(unix)]
    #[test]
    fn resolver_backup_symlink_is_not_overwritten() {
        use std::os::unix::fs::symlink;

        let (directory, source, backup) = dns_test_paths("backup-symlink");
        let sentinel = directory.join("backup-sentinel");
        let original = b"nameserver 192.0.2.53\n";
        let marker = owner_marker(&test_identity(4253));
        std::fs::write(&source, original).expect("write original resolver state");
        std::fs::write(&sentinel, b"sentinel\n").expect("write backup sentinel");
        symlink(&sentinel, &backup).expect("create foreign resolver backup symlink");
        let mut state = None;

        let error = backup_resolv_conf_at(&source, &backup, &marker, &mut state)
            .expect_err("foreign resolver backup symlink must be refused");
        assert!(error.to_string().contains("already exists"));
        assert_eq!(std::fs::read(&source).expect("read original resolver state"), original);
        assert_eq!(std::fs::read(&sentinel).expect("read backup sentinel"), b"sentinel\n");
        assert_eq!(std::fs::read_link(&backup).expect("read backup symlink"), sentinel);
        assert!(state.is_none());

        std::fs::remove_file(&source).expect("remove original resolver state");
        std::fs::remove_file(&backup).expect("remove foreign resolver backup symlink");
        std::fs::remove_file(&sentinel).expect("remove backup sentinel");
        std::fs::remove_dir(&directory).expect("remove DNS restore test directory");
    }

    #[cfg(unix)]
    #[test]
    fn read_only_backup_parent_preserves_original_without_partial_state() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (directory, _, _) = dns_test_paths("read-only-backup-parent");
        let read_only_directory = directory.join("resolver");
        let source = read_only_directory.join("resolv.conf");
        let backup = read_only_directory.join("resolv.conf.quicfuscate.bak");
        let original = b"nameserver 192.0.2.53\n";
        let marker = owner_marker(&test_identity(4254));
        std::fs::create_dir(&read_only_directory).expect("create alternate resolver directory");
        std::fs::write(&source, original).expect("write alternate resolver source");
        std::fs::set_permissions(&read_only_directory, std::fs::Permissions::from_mode(0o500))
            .expect("make alternate resolver directory read-only");
        let mut state = None;

        let error = backup_resolv_conf_at(&source, &backup, &marker, &mut state)
            .expect_err("read-only backup parent must reject backup creation");
        assert!(error.to_string().contains("create resolver backup"));
        std::fs::set_permissions(&read_only_directory, std::fs::Permissions::from_mode(0o700))
            .expect("restore alternate resolver directory permissions");
        assert_eq!(std::fs::read(&source).expect("read alternate resolver source"), original);
        assert!(!path_entry_exists(&backup).expect("inspect absent alternate backup"));
        assert!(state.is_none());

        std::fs::remove_file(&source).expect("remove alternate resolver source");
        std::fs::remove_dir(&read_only_directory).expect("remove alternate resolver directory");
        std::fs::remove_dir(&directory).expect("remove DNS restore test directory");
    }
}
