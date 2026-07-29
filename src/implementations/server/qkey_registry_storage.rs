//! Fail-closed encrypted persistence for the QKey registry.

use crate::crypto::aead::{AeadOpen, AeadSeal};
use crate::secret::SecretBytes;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const ENVELOPE_MAGIC: &[u8; 6] = b"QFQREG";
const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_FLAGS: u8 = 0;
const KEY_ID_LEN: usize = 8;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const ENVELOPE_HEADER_LEN: usize = ENVELOPE_MAGIC.len() + 1 + 1 + KEY_ID_LEN + NONCE_LEN;
const LEGACY_MAGIC: &[u8; 6] = b"QFENC1";
const MAX_REGISTRY_FILE_BYTES: u64 = 4 * 1024 * 1024;

const CURRENT_KEY_ENV: &str = "QUICFUSCATE_QKEY_ENC_KEY";
const CURRENT_KEY_FILE_ENV: &str = "QUICFUSCATE_QKEY_ENC_KEY_FILE";
const PREVIOUS_KEY_ENV: &str = "QUICFUSCATE_QKEY_ENC_PREVIOUS_KEY";
const PREVIOUS_KEY_FILE_ENV: &str = "QUICFUSCATE_QKEY_ENC_PREVIOUS_KEY_FILE";

#[derive(Debug)]
pub enum QKeyRegistryError {
    Io { operation: &'static str, path: PathBuf, source: io::Error },
    InvalidKeySource(String),
    InsecurePermissions { path: PathBuf, mode: u32 },
    MissingKey,
    WrongKey { key_id: String },
    Corrupt(&'static str),
    UnsupportedVersion(u8),
    InvalidPlaintext(String),
    InvalidRecord(String),
    Serialization(String),
    Encryption(String),
}

impl QKeyRegistryError {
    fn io(operation: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io { operation, path: path.to_path_buf(), source }
    }
}

impl fmt::Display for QKeyRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, path, source } => write!(
                formatter,
                "QKey registry {operation} failed for {}: {source}",
                path.display()
            ),
            Self::InvalidKeySource(message) => {
                write!(formatter, "invalid QKey registry key source: {message}")
            }
            Self::InsecurePermissions { path, mode } => write!(
                formatter,
                "QKey registry file {} has insecure permissions {mode:#o}",
                path.display()
            ),
            Self::MissingKey => {
                formatter.write_str("encrypted QKey registry requires an encryption key")
            }
            Self::WrongKey { key_id } => {
                write!(formatter, "no configured QKey registry key matches key id {key_id}")
            }
            Self::Corrupt(reason) => write!(formatter, "QKey registry is corrupt: {reason}"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported QKey registry envelope version {version}")
            }
            Self::InvalidPlaintext(message) => {
                write!(formatter, "invalid plaintext QKey registry: {message}")
            }
            Self::InvalidRecord(message) => write!(formatter, "invalid QKey record: {message}"),
            Self::Serialization(message) => {
                write!(formatter, "QKey registry serialization failed: {message}")
            }
            Self::Encryption(message) => {
                write!(formatter, "QKey registry encryption failed: {message}")
            }
        }
    }
}

impl std::error::Error for QKeyRegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

struct RegistryKey {
    bytes: SecretBytes,
    id: [u8; KEY_ID_LEN],
}

impl RegistryKey {
    fn new(bytes: SecretBytes) -> Result<Self, QKeyRegistryError> {
        if bytes.len() != 32 {
            return Err(QKeyRegistryError::InvalidKeySource(
                "keys must contain exactly 32 bytes".to_string(),
            ));
        }
        let digest = Sha256::digest(bytes.as_slice());
        let mut id = [0u8; KEY_ID_LEN];
        id.copy_from_slice(&digest[..KEY_ID_LEN]);
        Ok(Self { bytes, id })
    }
}

struct RegistryKeyring {
    current: Option<RegistryKey>,
    previous: Option<RegistryKey>,
}

impl RegistryKeyring {
    fn from_environment() -> Result<Self, QKeyRegistryError> {
        let current = load_key_role(
            "current",
            CURRENT_KEY_ENV,
            CURRENT_KEY_FILE_ENV,
            "qkey_registry_current_key",
        )?;
        let previous = load_key_role(
            "previous",
            PREVIOUS_KEY_ENV,
            PREVIOUS_KEY_FILE_ENV,
            "qkey_registry_previous_key",
        )?;
        Self::new(current, previous)
    }

    fn new(
        current: Option<RegistryKey>,
        previous: Option<RegistryKey>,
    ) -> Result<Self, QKeyRegistryError> {
        if current.is_none() && previous.is_some() {
            return Err(QKeyRegistryError::InvalidKeySource(
                "a previous key requires a current key".to_string(),
            ));
        }
        if let (Some(current), Some(previous)) = (&current, &previous) {
            if current.id == previous.id {
                return Err(QKeyRegistryError::InvalidKeySource(
                    "current and previous keys are identical".to_string(),
                ));
            }
        }
        Ok(Self { current, previous })
    }

    fn current(&self) -> Option<&RegistryKey> {
        self.current.as_ref()
    }

    fn find(&self, id: &[u8; KEY_ID_LEN]) -> Option<(&RegistryKey, bool)> {
        if let Some(current) = self.current.as_ref() {
            if &current.id == id {
                return Some((current, true));
            }
        }
        self.previous
            .as_ref()
            .filter(|previous| &previous.id == id)
            .map(|previous| (previous, false))
    }

    fn candidates(&self) -> impl Iterator<Item = (&RegistryKey, bool)> {
        self.current
            .iter()
            .map(|key| (key, true))
            .chain(self.previous.iter().map(|key| (key, false)))
    }

    fn is_empty(&self) -> bool {
        self.current.is_none()
    }
}

fn load_key_role(
    role: &'static str,
    value_env: &'static str,
    file_env: &'static str,
    label: &'static str,
) -> Result<Option<RegistryKey>, QKeyRegistryError> {
    let value = std::env::var_os(value_env);
    let file = std::env::var_os(file_env);
    if value.is_some() && file.is_some() {
        return Err(QKeyRegistryError::InvalidKeySource(format!(
            "{role} key must use exactly one of {value_env} or {file_env}"
        )));
    }

    match (value, file) {
        (Some(value), None) => {
            let value = value.into_string().map_err(|_| {
                QKeyRegistryError::InvalidKeySource(format!("{value_env} is not valid Unicode hex"))
            })?;
            let material = SecretBytes::new(value.into_bytes(), label);
            parse_key_material(material, false).map(Some)
        }
        (None, Some(path)) => {
            let path = PathBuf::from(path);
            load_key_file(&path, label).map(Some)
        }
        (None, None) => Ok(None),
        (Some(_), Some(_)) => {
            Err(QKeyRegistryError::InvalidKeySource(format!("{role} key has conflicting sources")))
        }
    }
}

fn load_key_file(path: &Path, label: &'static str) -> Result<RegistryKey, QKeyRegistryError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| QKeyRegistryError::io("key metadata read", path, error))?;
    if !metadata.file_type().is_file() {
        return Err(QKeyRegistryError::InvalidKeySource(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    validate_protected_file_permissions(path, &metadata)?;
    let bytes =
        std::fs::read(path).map_err(|error| QKeyRegistryError::io("key read", path, error))?;
    parse_key_material(SecretBytes::new(bytes, label), true)
}

#[cfg(unix)]
fn validate_protected_file_permissions(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), QKeyRegistryError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o027 != 0 {
        return Err(QKeyRegistryError::InsecurePermissions { path: path.to_path_buf(), mode });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_protected_file_permissions(
    _path: &Path,
    _metadata: &std::fs::Metadata,
) -> Result<(), QKeyRegistryError> {
    Ok(())
}

fn parse_key_material(
    material: SecretBytes,
    allow_raw: bool,
) -> Result<RegistryKey, QKeyRegistryError> {
    if allow_raw && material.len() == 32 {
        return RegistryKey::new(material);
    }

    let bytes = material.as_slice();
    let start = bytes.iter().position(|byte| !byte.is_ascii_whitespace()).unwrap_or(bytes.len());
    let end =
        bytes.iter().rposition(|byte| !byte.is_ascii_whitespace()).map_or(start, |index| index + 1);
    let trimmed = &bytes[start..end];
    if trimmed.len() != 64 || !trimmed.iter().all(u8::is_ascii_hexdigit) {
        return Err(QKeyRegistryError::InvalidKeySource(
            "keys must be 32 raw file bytes or 64 hexadecimal characters".to_string(),
        ));
    }
    let mut decoded = SecretBytes::zeroed(32, "qkey_registry_decoded_key");
    hex::decode_to_slice(trimmed, decoded.as_mut_slice()).map_err(|_| {
        QKeyRegistryError::InvalidKeySource("key contains invalid hexadecimal".to_string())
    })?;
    RegistryKey::new(decoded)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RewriteReason {
    PlaintextMigration,
    LegacyUpgrade,
    KeyRotation,
    BackupRecovery,
    Normal,
}

pub(crate) struct LoadedPayload {
    bytes: SecretBytes,
    plaintext_len: usize,
    pub rewrite: Option<RewriteReason>,
}

impl LoadedPayload {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes.as_slice()[..self.plaintext_len]
    }
}

pub(crate) struct RegistryStorage {
    path: PathBuf,
    backup_path: PathBuf,
    keys: RegistryKeyring,
}

impl RegistryStorage {
    pub fn from_environment(path: PathBuf) -> Result<Self, QKeyRegistryError> {
        Self::new(path, RegistryKeyring::from_environment()?)
    }

    fn new(path: PathBuf, keys: RegistryKeyring) -> Result<Self, QKeyRegistryError> {
        if path.as_os_str().is_empty() {
            return Err(QKeyRegistryError::InvalidKeySource(
                "registry path cannot be empty".to_string(),
            ));
        }
        let backup_path = backup_path_for(&path);
        Ok(Self { path, backup_path, keys })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        path: PathBuf,
        current: Option<[u8; 32]>,
        previous: Option<[u8; 32]>,
    ) -> Result<Self, QKeyRegistryError> {
        let current = current
            .map(|bytes| {
                RegistryKey::new(SecretBytes::new(bytes.to_vec(), "qkey_registry_current_key"))
            })
            .transpose()?;
        let previous = previous
            .map(|bytes| {
                RegistryKey::new(SecretBytes::new(bytes.to_vec(), "qkey_registry_previous_key"))
            })
            .transpose()?;
        Self::new(path, RegistryKeyring::new(current, previous)?)
    }

    pub fn load(&self) -> Result<Option<LoadedPayload>, QKeyRegistryError> {
        match read_registry_file(&self.path)? {
            Some(bytes) => {
                let loaded = self.decode(bytes, None)?;
                if loaded.rewrite == Some(RewriteReason::PlaintextMigration) {
                    self.validate_plaintext_migration_backup(loaded.as_slice())?;
                }
                Ok(Some(loaded))
            }
            None => {
                let Some(bytes) = read_registry_file(&self.backup_path)? else {
                    return Ok(None);
                };
                let mut loaded = self.decode(bytes, Some(RewriteReason::BackupRecovery))?;
                loaded.rewrite = Some(RewriteReason::BackupRecovery);
                Ok(Some(loaded))
            }
        }
    }

    fn validate_plaintext_migration_backup(
        &self,
        plaintext: &[u8],
    ) -> Result<(), QKeyRegistryError> {
        let Some(backup_bytes) = read_registry_file(&self.backup_path)? else {
            return Ok(());
        };
        if !is_encrypted_payload(backup_bytes.as_slice()) {
            return Err(QKeyRegistryError::Corrupt(
                "plaintext primary has an unencrypted recovery backup",
            ));
        }
        let backup = self.decode(backup_bytes, None)?;
        if backup.as_slice() != plaintext {
            return Err(QKeyRegistryError::Corrupt(
                "plaintext primary does not match the encrypted recovery backup",
            ));
        }
        Ok(())
    }

    pub fn persist(
        &self,
        plaintext: &[u8],
        reason: RewriteReason,
    ) -> Result<(), QKeyRegistryError> {
        let Some(current_key) = self.keys.current() else {
            return atomic_replace(&self.path, plaintext);
        };
        let final_payload = encrypt_v1(plaintext, current_key)?;

        match reason {
            RewriteReason::PlaintextMigration => {
                atomic_replace(&self.backup_path, &final_payload)?;
            }
            RewriteReason::BackupRecovery => {
                if let Some(existing) = read_registry_file(&self.backup_path)? {
                    if !is_encrypted_payload(existing.as_slice()) {
                        atomic_replace(&self.backup_path, &final_payload)?;
                    }
                }
            }
            RewriteReason::LegacyUpgrade | RewriteReason::KeyRotation | RewriteReason::Normal => {
                if let Some(existing) = read_registry_file(&self.path)? {
                    if !is_encrypted_payload(existing.as_slice()) {
                        return Err(QKeyRegistryError::Corrupt(
                            "refusing to copy plaintext into the encrypted backup",
                        ));
                    }
                    atomic_replace(&self.backup_path, existing.as_slice())?;
                }
            }
        }

        atomic_replace(&self.path, &final_payload)
    }

    pub fn encryption_enabled(&self) -> bool {
        !self.keys.is_empty()
    }

    fn decode(
        &self,
        bytes: SecretBytes,
        forced_rewrite: Option<RewriteReason>,
    ) -> Result<LoadedPayload, QKeyRegistryError> {
        if bytes.starts_with(ENVELOPE_MAGIC) {
            return self.decode_v1(bytes, forced_rewrite);
        }
        if bytes.starts_with(LEGACY_MAGIC) {
            return self.decode_legacy(bytes, forced_rewrite);
        }
        if bytes.starts_with(b"QFQ") || bytes.starts_with(b"QFE") {
            return Err(QKeyRegistryError::Corrupt("truncated encrypted envelope"));
        }
        let plaintext_len = bytes.len();
        let rewrite = forced_rewrite
            .or_else(|| self.encryption_enabled().then_some(RewriteReason::PlaintextMigration));
        Ok(LoadedPayload { bytes, plaintext_len, rewrite })
    }

    fn decode_v1(
        &self,
        bytes: SecretBytes,
        forced_rewrite: Option<RewriteReason>,
    ) -> Result<LoadedPayload, QKeyRegistryError> {
        if bytes.len() < ENVELOPE_HEADER_LEN + TAG_LEN {
            return Err(QKeyRegistryError::Corrupt("encrypted envelope is truncated"));
        }
        let version = bytes[ENVELOPE_MAGIC.len()];
        if version != ENVELOPE_VERSION {
            return Err(QKeyRegistryError::UnsupportedVersion(version));
        }
        if bytes[ENVELOPE_MAGIC.len() + 1] != ENVELOPE_FLAGS {
            return Err(QKeyRegistryError::Corrupt("encrypted envelope flags are invalid"));
        }

        let key_id_offset = ENVELOPE_MAGIC.len() + 2;
        let mut key_id = [0u8; KEY_ID_LEN];
        key_id.copy_from_slice(&bytes[key_id_offset..key_id_offset + KEY_ID_LEN]);
        let Some((key, is_current)) = self.keys.find(&key_id) else {
            if self.keys.is_empty() {
                return Err(QKeyRegistryError::MissingKey);
            }
            return Err(QKeyRegistryError::WrongKey { key_id: hex::encode(key_id) });
        };

        let nonce_offset = key_id_offset + KEY_ID_LEN;
        let nonce = &bytes[nonce_offset..nonce_offset + NONCE_LEN];
        let header = &bytes[..ENVELOPE_HEADER_LEN];
        let ciphertext = &bytes[ENVELOPE_HEADER_LEN..];
        let (plaintext, plaintext_len) =
            decrypt(ciphertext, key, nonce, header, "qkey_registry_plaintext")?;
        let rewrite =
            forced_rewrite.or_else(|| (!is_current).then_some(RewriteReason::KeyRotation));
        Ok(LoadedPayload { bytes: plaintext, plaintext_len, rewrite })
    }

    fn decode_legacy(
        &self,
        bytes: SecretBytes,
        forced_rewrite: Option<RewriteReason>,
    ) -> Result<LoadedPayload, QKeyRegistryError> {
        if bytes.len() < LEGACY_MAGIC.len() + NONCE_LEN + TAG_LEN {
            return Err(QKeyRegistryError::Corrupt("legacy encrypted envelope is truncated"));
        }
        if self.keys.is_empty() {
            return Err(QKeyRegistryError::MissingKey);
        }
        let nonce = &bytes[LEGACY_MAGIC.len()..LEGACY_MAGIC.len() + NONCE_LEN];
        let ciphertext = &bytes[LEGACY_MAGIC.len() + NONCE_LEN..];
        for (key, is_current) in self.keys.candidates() {
            if let Ok((plaintext, plaintext_len)) =
                decrypt(ciphertext, key, nonce, &[], "qkey_registry_legacy_plaintext")
            {
                let rewrite = forced_rewrite.or(Some(if is_current {
                    RewriteReason::LegacyUpgrade
                } else {
                    RewriteReason::KeyRotation
                }));
                return Ok(LoadedPayload { bytes: plaintext, plaintext_len, rewrite });
            }
        }
        Err(QKeyRegistryError::Corrupt("legacy envelope authentication failed"))
    }
}

fn encrypt_v1(plaintext: &[u8], key: &RegistryKey) -> Result<Vec<u8>, QKeyRegistryError> {
    let mut nonce = [0u8; NONCE_LEN];
    crate::rng::fill_secure(&mut nonce).map_err(|error| {
        QKeyRegistryError::Encryption(format!("secure nonce generation failed: {error}"))
    })?;

    let mut header = [0u8; ENVELOPE_HEADER_LEN];
    header[..ENVELOPE_MAGIC.len()].copy_from_slice(ENVELOPE_MAGIC);
    header[ENVELOPE_MAGIC.len()] = ENVELOPE_VERSION;
    header[ENVELOPE_MAGIC.len() + 1] = ENVELOPE_FLAGS;
    let key_id_offset = ENVELOPE_MAGIC.len() + 2;
    header[key_id_offset..key_id_offset + KEY_ID_LEN].copy_from_slice(&key.id);
    let nonce_offset = key_id_offset + KEY_ID_LEN;
    header[nonce_offset..nonce_offset + NONCE_LEN].copy_from_slice(&nonce);

    let mut sealed =
        SecretBytes::zeroed(plaintext.len().saturating_add(TAG_LEN), "qkey_registry_seal_buffer");
    if sealed.len() != plaintext.len() + TAG_LEN {
        return Err(QKeyRegistryError::Encryption("registry payload length overflow".to_string()));
    }
    sealed.as_mut_slice()[..plaintext.len()].copy_from_slice(plaintext);
    let cipher = crate::crypto::ChaCha20Poly1305::new(key.bytes.as_slice(), &nonce);
    let written = cipher
        .seal_with_u64_counter(0, &header, sealed.as_mut_slice(), plaintext.len(), None)
        .map_err(|error| QKeyRegistryError::Encryption(error.to_string()))?;

    let mut output = Vec::with_capacity(header.len() + written);
    output.extend_from_slice(&header);
    output.extend_from_slice(&sealed.as_slice()[..written]);
    Ok(output)
}

fn decrypt(
    ciphertext: &[u8],
    key: &RegistryKey,
    nonce: &[u8],
    associated_data: &[u8],
    label: &'static str,
) -> Result<(SecretBytes, usize), QKeyRegistryError> {
    if ciphertext.len() < TAG_LEN {
        return Err(QKeyRegistryError::Corrupt("ciphertext is truncated"));
    }
    let mut plaintext = SecretBytes::new(ciphertext.to_vec(), label);
    let cipher = crate::crypto::ChaCha20Poly1305::new(key.bytes.as_slice(), nonce);
    let plaintext_len = cipher
        .open_with_u64_counter(0, associated_data, plaintext.as_mut_slice())
        .map_err(|_| QKeyRegistryError::Corrupt("authentication failed"))?;
    Ok((plaintext, plaintext_len))
}

fn read_registry_file(path: &Path) -> Result<Option<SecretBytes>, QKeyRegistryError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(QKeyRegistryError::io("metadata read", path, error)),
    };
    if !metadata.file_type().is_file() {
        return Err(QKeyRegistryError::Corrupt("registry path is not a regular file"));
    }
    if metadata.len() > MAX_REGISTRY_FILE_BYTES {
        return Err(QKeyRegistryError::Corrupt("registry file exceeds the size limit"));
    }
    validate_protected_file_permissions(path, &metadata)?;
    let bytes = std::fs::read(path).map_err(|error| QKeyRegistryError::io("read", path, error))?;
    Ok(Some(SecretBytes::new(bytes, "qkey_registry_file_bytes")))
}

fn is_encrypted_payload(bytes: &[u8]) -> bool {
    bytes.starts_with(ENVELOPE_MAGIC) || bytes.starts_with(LEGACY_MAGIC)
}

fn backup_path_for(path: &Path) -> PathBuf {
    let mut file_name =
        path.file_name().map(|name| name.to_os_string()).unwrap_or_else(|| "qkeys".into());
    file_name.push(".backup");
    path.with_file_name(file_name)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), QKeyRegistryError> {
    #[cfg(test)]
    test_failpoint::before_atomic_replace(path)?;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|error| QKeyRegistryError::io("parent creation", parent, error))?;

    let mut nonce = [0u8; 8];
    crate::rng::fill_secure(&mut nonce).map_err(|error| {
        QKeyRegistryError::Encryption(format!("temporary-name entropy failed: {error}"))
    })?;
    let mut temporary_name =
        path.file_name().map(|name| name.to_os_string()).unwrap_or_else(|| "qkeys".into());
    temporary_name.push(format!(".tmp-{}", hex::encode(nonce)));
    let temporary_path = path.with_file_name(temporary_name);

    let result = write_and_commit_temporary(&temporary_path, path, bytes);
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    result
}

#[cfg(test)]
pub(crate) mod test_failpoint {
    use super::QKeyRegistryError;
    use std::cell::Cell;
    use std::io;
    use std::path::Path;

    thread_local! {
        static CALL_INDEX: Cell<usize> = const { Cell::new(0) };
        static FAIL_AT: Cell<Option<usize>> = const { Cell::new(None) };
    }

    pub(crate) struct Guard {
        previous_call_index: usize,
        previous_fail_at: Option<usize>,
    }

    pub(crate) fn install(fail_at: usize) -> Guard {
        let previous_call_index = CALL_INDEX.with(|cell| cell.replace(0));
        let previous_fail_at = FAIL_AT.with(|cell| cell.replace(Some(fail_at)));
        Guard { previous_call_index, previous_fail_at }
    }

    pub(super) fn before_atomic_replace(path: &Path) -> Result<(), QKeyRegistryError> {
        let call_index = CALL_INDEX.with(|cell| {
            let next = cell.get().saturating_add(1);
            cell.set(next);
            next
        });
        let fail = FAIL_AT.with(|cell| cell.get() == Some(call_index));
        if fail {
            return Err(QKeyRegistryError::io(
                "injected atomic replace",
                path,
                io::Error::other("injected registry write failure"),
            ));
        }
        Ok(())
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            CALL_INDEX.with(|cell| cell.set(self.previous_call_index));
            FAIL_AT.with(|cell| cell.set(self.previous_fail_at));
        }
    }
}

fn write_and_commit_temporary(
    temporary_path: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), QKeyRegistryError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(temporary_path)
        .map_err(|error| QKeyRegistryError::io("temporary create", temporary_path, error))?;
    file.write_all(bytes)
        .map_err(|error| QKeyRegistryError::io("temporary write", temporary_path, error))?;
    file.sync_all()
        .map_err(|error| QKeyRegistryError::io("temporary sync", temporary_path, error))?;
    drop(file);

    replace_file(temporary_path, destination)
        .map_err(|error| QKeyRegistryError::io("atomic replace", destination, error))?;
    sync_parent(destination)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both paths are stable, NUL-terminated UTF-16 buffers for the duration of the call.
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), QKeyRegistryError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = std::fs::File::open(parent)
        .map_err(|error| QKeyRegistryError::io("parent open", parent, error))?;
    directory.sync_all().map_err(|error| QKeyRegistryError::io("parent sync", parent, error))
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), QKeyRegistryError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    const CURRENT_KEY: [u8; 32] = [0x31; 32];
    const PREVIOUS_KEY: [u8; 32] = [0x52; 32];
    const WRONG_KEY: [u8; 32] = [0x73; 32];
    const PLAINTEXT: &[u8] = br#"[{"id":"a1b2c3d4e5f6","token_sha256":"0123456789abcdef"}]"#;

    fn test_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "quicfuscate-qkey-storage-{name}-{}-{}",
            std::process::id(),
            fastrand::u64(..)
        ));
        std::fs::create_dir_all(&root).expect("create test root");
        root
    }

    fn write_protected(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).expect("write protected test file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("set protected test permissions");
        }
    }

    fn load_error(storage: &RegistryStorage, context: &str) -> QKeyRegistryError {
        match storage.load() {
            Err(error) => error,
            Ok(_) => panic!("{context}"),
        }
    }

    #[test]
    fn versioned_envelope_round_trip_and_typed_rejections_are_fail_closed() {
        let root = test_root("envelope");
        let path = root.join("qkeys.json");
        let storage =
            RegistryStorage::for_test(path.clone(), Some(CURRENT_KEY), None).expect("storage");
        storage.persist(PLAINTEXT, RewriteReason::Normal).expect("persist encrypted registry");

        let encrypted = std::fs::read(&path).expect("read encrypted registry");
        assert!(encrypted.starts_with(ENVELOPE_MAGIC));
        assert!(!encrypted.windows(16).any(|window| PLAINTEXT.windows(16).any(|p| p == window)));

        let loaded = storage.load().expect("load encrypted registry").expect("payload");
        assert_eq!(loaded.as_slice(), PLAINTEXT);
        assert_eq!(loaded.rewrite, None);

        let wrong =
            RegistryStorage::for_test(path.clone(), Some(WRONG_KEY), None).expect("wrong storage");
        assert!(matches!(
            load_error(&wrong, "wrong key must fail"),
            QKeyRegistryError::WrongKey { .. }
        ));

        let missing =
            RegistryStorage::for_test(path.clone(), None, None).expect("missing-key storage");
        assert!(matches!(
            load_error(&missing, "missing key must fail"),
            QKeyRegistryError::MissingKey
        ));

        let mut unsupported = encrypted.clone();
        unsupported[ENVELOPE_MAGIC.len()] = ENVELOPE_VERSION + 1;
        write_protected(&path, &unsupported);
        assert!(matches!(
            load_error(&storage, "unsupported version must fail"),
            QKeyRegistryError::UnsupportedVersion(2)
        ));

        let mut invalid_flags = encrypted.clone();
        invalid_flags[ENVELOPE_MAGIC.len() + 1] = 1;
        write_protected(&path, &invalid_flags);
        assert!(matches!(
            load_error(&storage, "invalid flags must fail"),
            QKeyRegistryError::Corrupt("encrypted envelope flags are invalid")
        ));

        write_protected(&path, &encrypted[..ENVELOPE_HEADER_LEN + TAG_LEN - 1]);
        assert!(matches!(
            load_error(&storage, "truncated envelope must fail"),
            QKeyRegistryError::Corrupt("encrypted envelope is truncated")
        ));

        let mut tampered = encrypted;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x80;
        write_protected(&path, &tampered);
        assert!(matches!(
            load_error(&storage, "tamper must fail"),
            QKeyRegistryError::Corrupt("authentication failed")
        ));

        std::fs::remove_dir_all(root).expect("clean test root");
    }

    #[test]
    fn plaintext_migration_creates_only_encrypted_primary_and_backup() {
        let root = test_root("migration");
        let path = root.join("qkeys.json");
        write_protected(&path, PLAINTEXT);
        let storage =
            RegistryStorage::for_test(path.clone(), Some(CURRENT_KEY), None).expect("storage");

        let loaded = storage.load().expect("load plaintext").expect("payload");
        assert_eq!(loaded.as_slice(), PLAINTEXT);
        assert_eq!(loaded.rewrite, Some(RewriteReason::PlaintextMigration));
        storage
            .persist(loaded.as_slice(), loaded.rewrite.expect("migration reason"))
            .expect("migrate registry");

        for persisted_path in [&path, &backup_path_for(&path)] {
            let bytes = std::fs::read(persisted_path).expect("read migrated artifact");
            assert!(bytes.starts_with(ENVELOPE_MAGIC));
            assert!(!bytes.windows(16).any(|window| {
                PLAINTEXT.windows(16).any(|plaintext_window| plaintext_window == window)
            }));
        }
        let reloaded = storage.load().expect("reload migrated registry").expect("payload");
        assert_eq!(reloaded.as_slice(), PLAINTEXT);
        assert_eq!(reloaded.rewrite, None);

        write_protected(&path, br#"[{"id":"ffffffffffff","token_sha256":"attacker-controlled"}]"#);
        assert!(matches!(
            load_error(&storage, "plaintext downgrade must fail"),
            QKeyRegistryError::Corrupt(
                "plaintext primary does not match the encrypted recovery backup"
            )
        ));

        std::fs::remove_dir_all(root).expect("clean test root");
    }

    #[test]
    fn key_rotation_rewrites_primary_and_keeps_only_encrypted_recovery_data() {
        let root = test_root("rotation");
        let path = root.join("qkeys.json");
        let old_storage =
            RegistryStorage::for_test(path.clone(), Some(PREVIOUS_KEY), None).expect("old storage");
        old_storage.persist(PLAINTEXT, RewriteReason::Normal).expect("persist old envelope");
        let old_envelope = std::fs::read(&path).expect("read old envelope");

        let rotating =
            RegistryStorage::for_test(path.clone(), Some(CURRENT_KEY), Some(PREVIOUS_KEY))
                .expect("rotating storage");
        let loaded = rotating.load().expect("load old key").expect("payload");
        assert_eq!(loaded.rewrite, Some(RewriteReason::KeyRotation));
        rotating
            .persist(loaded.as_slice(), loaded.rewrite.expect("rotation reason"))
            .expect("rotate registry");

        let primary = std::fs::read(&path).expect("read rotated primary");
        let backup = std::fs::read(backup_path_for(&path)).expect("read rotation backup");
        assert_ne!(primary, old_envelope);
        assert_eq!(backup, old_envelope);
        assert!(primary.starts_with(ENVELOPE_MAGIC));
        assert!(backup.starts_with(ENVELOPE_MAGIC));
        assert!(!primary.windows(16).any(|window| {
            PLAINTEXT.windows(16).any(|plaintext_window| plaintext_window == window)
        }));

        let current_only =
            RegistryStorage::for_test(path.clone(), Some(CURRENT_KEY), None).expect("current");
        assert_eq!(
            current_only.load().expect("load current").expect("payload").as_slice(),
            PLAINTEXT
        );

        std::fs::remove_dir_all(root).expect("clean test root");
    }

    #[test]
    fn migration_is_recoverable_at_every_atomic_replace_boundary() {
        for fail_at in 1..=2 {
            let root = test_root(&format!("migration-interruption-{fail_at}"));
            let path = root.join("qkeys.json");
            write_protected(&path, PLAINTEXT);
            let storage =
                RegistryStorage::for_test(path.clone(), Some(CURRENT_KEY), None).expect("storage");
            let loaded = storage.load().expect("load plaintext").expect("payload");

            {
                let _failure = test_failpoint::install(fail_at);
                assert!(storage
                    .persist(loaded.as_slice(), RewriteReason::PlaintextMigration)
                    .is_err());
            }
            assert_eq!(std::fs::read(&path).expect("read retained primary"), PLAINTEXT);
            if fail_at == 1 {
                assert!(!backup_path_for(&path).exists());
            } else {
                assert!(std::fs::read(backup_path_for(&path))
                    .expect("read recovery backup")
                    .starts_with(ENVELOPE_MAGIC));
            }

            let retry = storage.load().expect("reload plaintext").expect("payload");
            storage
                .persist(retry.as_slice(), retry.rewrite.expect("retry migration"))
                .expect("retry migration");
            for persisted_path in [&path, &backup_path_for(&path)] {
                assert!(std::fs::read(persisted_path)
                    .expect("read migrated artifact")
                    .starts_with(ENVELOPE_MAGIC));
            }
            std::fs::remove_dir_all(root).expect("clean test root");
        }
    }

    #[test]
    fn rotation_is_recoverable_at_every_atomic_replace_boundary() {
        for fail_at in 1..=2 {
            let root = test_root(&format!("rotation-interruption-{fail_at}"));
            let path = root.join("qkeys.json");
            let old =
                RegistryStorage::for_test(path.clone(), Some(PREVIOUS_KEY), None).expect("old");
            old.persist(PLAINTEXT, RewriteReason::Normal).expect("persist old envelope");
            let original = std::fs::read(&path).expect("read original");
            let rotating =
                RegistryStorage::for_test(path.clone(), Some(CURRENT_KEY), Some(PREVIOUS_KEY))
                    .expect("rotating");
            let loaded = rotating.load().expect("load old envelope").expect("payload");

            {
                let _failure = test_failpoint::install(fail_at);
                assert!(rotating
                    .persist(loaded.as_slice(), loaded.rewrite.expect("rotation"))
                    .is_err());
            }
            assert_eq!(std::fs::read(&path).expect("read retained primary"), original);

            let retry = rotating.load().expect("reload old envelope").expect("payload");
            rotating
                .persist(retry.as_slice(), retry.rewrite.expect("retry rotation"))
                .expect("retry rotation");
            let current_only =
                RegistryStorage::for_test(path.clone(), Some(CURRENT_KEY), None).expect("current");
            assert_eq!(
                current_only.load().expect("load current").expect("payload").as_slice(),
                PLAINTEXT
            );
            std::fs::remove_dir_all(root).expect("clean test root");
        }
    }

    #[test]
    fn plaintext_backup_recovery_encrypts_backup_before_restoring_primary() {
        let root = test_root("plaintext-backup-recovery");
        let path = root.join("qkeys.json");
        let backup = backup_path_for(&path);
        write_protected(&backup, PLAINTEXT);
        let storage =
            RegistryStorage::for_test(path.clone(), Some(CURRENT_KEY), None).expect("storage");
        let loaded = storage.load().expect("load backup").expect("payload");
        assert_eq!(loaded.rewrite, Some(RewriteReason::BackupRecovery));
        storage.persist(loaded.as_slice(), loaded.rewrite.expect("recovery")).expect("recover");

        for persisted_path in [&path, &backup] {
            let bytes = std::fs::read(persisted_path).expect("read recovered artifact");
            assert!(bytes.starts_with(ENVELOPE_MAGIC));
            assert!(!bytes.windows(16).any(|window| {
                PLAINTEXT.windows(16).any(|plaintext_window| plaintext_window == window)
            }));
        }
        std::fs::remove_dir_all(root).expect("clean test root");
    }

    #[test]
    fn legacy_envelope_is_authenticated_and_upgraded_without_plaintext_leakage() {
        let root = test_root("legacy-upgrade");
        let path = root.join("qkeys.json");
        let key =
            RegistryKey::new(SecretBytes::new(CURRENT_KEY.to_vec(), "qkey_registry_current_key"))
                .expect("legacy key");
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&[0x91; NONCE_LEN]);
        let cipher = crate::crypto::ChaCha20Poly1305::new(key.bytes.as_slice(), &nonce);
        let mut ciphertext = PLAINTEXT.to_vec();
        ciphertext.resize(PLAINTEXT.len() + TAG_LEN, 0);
        let plaintext_len = PLAINTEXT.len();
        let written = cipher
            .seal_with_u64_counter(0, &[], &mut ciphertext, plaintext_len, None)
            .expect("seal legacy envelope");
        let mut legacy = Vec::with_capacity(LEGACY_MAGIC.len() + NONCE_LEN + written);
        legacy.extend_from_slice(LEGACY_MAGIC);
        legacy.extend_from_slice(&nonce);
        legacy.extend_from_slice(&ciphertext[..written]);
        write_protected(&path, &legacy);

        let storage =
            RegistryStorage::for_test(path.clone(), Some(CURRENT_KEY), None).expect("storage");
        let loaded = storage.load().expect("load legacy").expect("payload");
        assert_eq!(loaded.rewrite, Some(RewriteReason::LegacyUpgrade));
        assert_eq!(loaded.as_slice(), PLAINTEXT);
        storage
            .persist(loaded.as_slice(), loaded.rewrite.expect("legacy upgrade"))
            .expect("upgrade legacy");

        let primary = std::fs::read(&path).expect("read upgraded primary");
        let backup = std::fs::read(backup_path_for(&path)).expect("read legacy backup");
        assert!(primary.starts_with(ENVELOPE_MAGIC));
        assert!(backup.starts_with(LEGACY_MAGIC));
        assert!(!primary.windows(16).any(|window| {
            PLAINTEXT.windows(16).any(|plaintext_window| plaintext_window == window)
        }));
        std::fs::remove_dir_all(root).expect("clean test root");
    }

    #[test]
    fn write_io_failure_is_typed_and_leaves_no_temporary_file() {
        let root = test_root("io-failure");
        let blocking_parent = root.join("not-a-directory");
        write_protected(&blocking_parent, b"regular file");
        let path = blocking_parent.join("qkeys.json");
        let storage = RegistryStorage::for_test(path, Some(CURRENT_KEY), None).expect("storage");
        assert!(matches!(
            storage.persist(PLAINTEXT, RewriteReason::Normal).expect_err("write must fail"),
            QKeyRegistryError::Io { .. }
        ));
        let names: Vec<_> = std::fs::read_dir(&root)
            .expect("read test root")
            .map(|entry| entry.expect("directory entry").file_name())
            .collect();
        assert_eq!(names, vec![blocking_parent.file_name().expect("file name")]);
        std::fs::remove_dir_all(root).expect("clean test root");
    }

    #[test]
    fn key_owners_erase_current_and_previous_material_before_deallocation() {
        let events = Arc::new(Mutex::new(Vec::<(&'static str, Vec<u8>)>::new()));
        let observed = Arc::clone(&events);
        let _observer = crate::secret::test_observation::install(Arc::new(move |label, bytes| {
            observed.lock().expect("erasure event lock").push((label, bytes.to_vec()));
        }));

        let root = test_root("key-erasure");
        let storage = RegistryStorage::for_test(
            root.join("qkeys.json"),
            Some(CURRENT_KEY),
            Some(PREVIOUS_KEY),
        )
        .expect("storage");
        drop(storage);

        let events = events.lock().expect("erasure events");
        for label in ["qkey_registry_current_key", "qkey_registry_previous_key"] {
            let bytes = events
                .iter()
                .find_map(|(event_label, bytes)| (*event_label == label).then_some(bytes))
                .unwrap_or_else(|| panic!("missing erasure event for {label}"));
            assert_eq!(bytes.len(), 32);
            assert!(bytes.iter().all(|byte| *byte == 0));
        }

        std::fs::remove_dir_all(root).expect("clean test root");
    }

    #[cfg(unix)]
    #[test]
    fn key_and_registry_files_reject_other_read_or_group_write_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let root = test_root("permissions");
        let key_path = root.join("registry.key");
        std::fs::write(&key_path, CURRENT_KEY).expect("write key");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
            .expect("set insecure key mode");
        let key_error = match load_key_file(&key_path, "qkey_registry_current_key") {
            Err(error) => error,
            Ok(_) => panic!("insecure key permissions must fail"),
        };
        assert!(matches!(key_error, QKeyRegistryError::InsecurePermissions { mode: 0o644, .. }));

        let registry_path = root.join("qkeys.json");
        std::fs::write(&registry_path, PLAINTEXT).expect("write registry");
        std::fs::set_permissions(&registry_path, std::fs::Permissions::from_mode(0o620))
            .expect("set insecure registry mode");
        let storage =
            RegistryStorage::for_test(registry_path, None, None).expect("plaintext storage");
        assert!(matches!(
            load_error(&storage, "insecure registry permissions must fail"),
            QKeyRegistryError::InsecurePermissions { mode: 0o620, .. }
        ));

        std::fs::remove_dir_all(root).expect("clean test root");
    }

    #[cfg(unix)]
    #[test]
    fn protected_key_files_accept_raw_and_hex_material_without_exposing_it_in_errors() {
        use std::os::unix::fs::PermissionsExt;

        let root = test_root("key-file-sources");
        let raw_path = root.join("raw.key");
        write_protected(&raw_path, &CURRENT_KEY);
        let raw = load_key_file(&raw_path, "qkey_registry_current_key").expect("load raw key");

        let hex_path = root.join("hex.key");
        write_protected(&hex_path, hex::encode(CURRENT_KEY).as_bytes());
        let hex_key = load_key_file(&hex_path, "qkey_registry_current_key").expect("load hex key");
        assert_eq!(raw.id, hex_key.id);

        let invalid_path = root.join("invalid.key");
        let secret_marker = "not-a-valid-secret-key";
        write_protected(&invalid_path, secret_marker.as_bytes());
        std::fs::set_permissions(&invalid_path, std::fs::Permissions::from_mode(0o600))
            .expect("set invalid key permissions");
        let error = match load_key_file(&invalid_path, "qkey_registry_current_key") {
            Err(error) => error,
            Ok(_) => panic!("invalid key must fail"),
        };
        assert!(!error.to_string().contains(secret_marker));

        std::fs::remove_dir_all(root).expect("clean test root");
    }
}
