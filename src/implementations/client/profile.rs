//! Profile management for QuicFuscate client.
//!
//! Handles saving, loading, and managing VPN server profiles. `ProfileManager`
//! is a standalone storage API; `ClientRuntime`, the CLI, and desktop/admin
//! surfaces do not own it in the current product.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::time_source::{ProtocolClock, WallClockError};
use qf_engine_types as qkey;

const PROFILE_ID_BYTES: usize = 16;
#[cfg(unix)]
const PROFILE_FILE_MODE: u32 = 0o600;
const TEMPORARY_FILE_NAME_ATTEMPTS: usize = 8;

/// A saved VPN profile.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    /// Unique identifier. New profiles use 32 lowercase hexadecimal characters
    /// generated from 128 bits of operating-system CSPRNG output. Non-empty
    /// legacy IDs are preserved when loaded and are not automatically migrated.
    pub id: String,
    /// Display name
    pub name: String,
    /// Server address (host:port)
    pub server: String,
    /// SNI hostname
    pub sni: String,
    /// Is favorite
    pub favorite: bool,
    /// Last connected timestamp (unix epoch)
    pub last_connected: Option<u64>,
    /// Connection count
    pub connect_count: u32,
    /// Stealth mode preference
    pub stealth_mode: Option<String>,
    /// FEC mode preference
    pub fec_mode: Option<String>,
    /// QKey token (hex). Required when the server enforces QKeys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<qkey::QKeyToken>,
    /// Country code (for display)
    pub country: Option<String>,
    /// City (for display)
    pub city: Option<String>,
}

impl Profile {
    /// Create a new profile from QKey.
    pub fn from_qkey(name: &str, qkey_str: &str) -> Result<Self, ProfileError> {
        let config = qkey::parse(qkey_str).map_err(|e| ProfileError::InvalidQKey(e.to_string()))?;

        let id = generate_id()?;

        Ok(Self {
            id,
            name: name.to_string(),
            server: config.remote,
            sni: config.sni,
            favorite: false,
            last_connected: None,
            connect_count: 0,
            stealth_mode: config.stealth,
            fec_mode: config.fec,
            token: config.token,
            country: None,
            city: None,
        })
    }

    /// Convert profile back to QKey.
    pub fn to_qkey(&self) -> String {
        let mut config = qkey::QKeyConfig::new(&self.server, &self.sni);
        if let Some(ref stealth) = self.stealth_mode {
            config = config.with_stealth(stealth);
        }
        if let Some(ref fec) = self.fec_mode {
            config = config.with_fec(fec);
        }
        if let Some(ref token) = self.token {
            if !token.trim().is_empty() {
                config = config.with_token(token.trim());
            }
        }
        qkey::generate(&config)
    }

    /// Mark as connected now.
    pub fn mark_connected(&mut self) -> Result<(), ProfileError> {
        self.mark_connected_with_clock(&ProtocolClock::default())
    }

    /// Mark as connected using an explicit wall-clock source.
    pub fn mark_connected_with_clock(&mut self, clock: &ProtocolClock) -> Result<(), ProfileError> {
        self.last_connected = Some(
            crate::time_source::unix_epoch_seconds(clock.now_system())
                .map_err(ProfileError::Clock)?,
        );
        self.connect_count += 1;
        Ok(())
    }
}

/// Standalone profile storage manager.
///
/// The production `ClientRuntime`, CLI, and desktop/admin surfaces do not own
/// this manager. Callers must explicitly choose the storage path and invoke
/// `load`, `add`, and `save`.
pub struct ProfileManager {
    /// Profiles by ID
    profiles: HashMap<String, Profile>,
    /// Storage path
    storage_path: PathBuf,
    /// Dirty flag (needs save)
    dirty: bool,
}

impl ProfileManager {
    /// Create a new profile manager.
    pub fn new<P: AsRef<Path>>(storage_path: P) -> Self {
        Self {
            profiles: HashMap::new(),
            storage_path: storage_path.as_ref().to_path_buf(),
            dirty: false,
        }
    }

    /// Load profiles from storage, rejecting empty or duplicate IDs.
    pub fn load(&mut self) -> Result<(), ProfileError> {
        if !self.storage_path.exists() {
            return Ok(());
        }

        let content = std::fs::read_to_string(&self.storage_path)
            .map_err(|e| ProfileError::Io(e.to_string()))?;

        let profiles: Vec<Profile> =
            serde_json::from_str(&content).map_err(|e| ProfileError::Parse(e.to_string()))?;

        let mut loaded_profiles = HashMap::with_capacity(profiles.len());
        for profile in profiles {
            validate_profile_id(&profile.id)?;
            let id = profile.id.clone();
            if loaded_profiles.contains_key(&id) {
                return Err(ProfileError::DuplicateId(id));
            }
            loaded_profiles.insert(id, profile);
        }

        self.profiles = loaded_profiles;

        self.dirty = false;
        Ok(())
    }

    /// Save profiles to storage.
    pub fn save(&mut self) -> Result<(), ProfileError> {
        if !self.dirty {
            return Ok(());
        }

        let mut profiles: Vec<&Profile> = self.profiles.values().collect();
        profiles.sort_unstable_by(|left, right| left.id.cmp(&right.id));
        let content = serde_json::to_string_pretty(&profiles)
            .map_err(|e| ProfileError::Parse(e.to_string()))?;

        atomic_write_profile(&self.storage_path, content.as_bytes())?;

        self.dirty = false;
        Ok(())
    }

    /// Add a new profile, rejecting empty or duplicate IDs.
    pub fn add(&mut self, profile: Profile) -> Result<String, ProfileError> {
        validate_profile_id(&profile.id)?;
        let id = profile.id.clone();
        if self.profiles.contains_key(&id) {
            return Err(ProfileError::DuplicateId(id));
        }
        self.profiles.insert(id.clone(), profile);
        self.dirty = true;
        Ok(id)
    }

    /// Remove a profile.
    pub fn remove(&mut self, id: &str) -> Option<Profile> {
        self.dirty = true;
        self.profiles.remove(id)
    }

    /// Get a profile by ID.
    pub fn get(&self, id: &str) -> Option<&Profile> {
        self.profiles.get(id)
    }

    /// Get a mutable profile by ID.
    pub fn get_mut(&mut self, id: &str) -> Option<&mut Profile> {
        self.dirty = true;
        self.profiles.get_mut(id)
    }

    /// List all profiles.
    pub fn list(&self) -> Vec<&Profile> {
        self.profiles.values().collect()
    }

    /// List favorites.
    pub fn favorites(&self) -> Vec<&Profile> {
        self.profiles.values().filter(|p| p.favorite).collect()
    }

    /// List recently used (last 5).
    pub fn recent(&self) -> Vec<&Profile> {
        let mut profiles: Vec<_> =
            self.profiles.values().filter(|p| p.last_connected.is_some()).collect();

        profiles.sort_by_key(|profile| std::cmp::Reverse(profile.last_connected));

        profiles.into_iter().take(5).collect()
    }

    /// Set favorite status.
    pub fn set_favorite(&mut self, id: &str, favorite: bool) -> bool {
        if let Some(profile) = self.profiles.get_mut(id) {
            profile.favorite = favorite;
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Import from QKey.
    pub fn import_qkey(&mut self, name: &str, qkey_str: &str) -> Result<String, ProfileError> {
        let profile = Profile::from_qkey(name, qkey_str)?;
        self.add(profile)
    }

    /// Count profiles.
    pub fn count(&self) -> usize {
        self.profiles.len()
    }
}

/// Profile error types.
#[derive(Debug)]
pub enum ProfileError {
    InvalidQKey(String),
    Entropy(String),
    Clock(WallClockError),
    InvalidId(String),
    DuplicateId(String),
    Io(String),
    Parse(String),
    NotFound(String),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidQKey(s) => write!(f, "Invalid QKey: {}", s),
            Self::Entropy(s) => write!(f, "Profile ID entropy unavailable: {}", s),
            Self::Clock(error) => write!(f, "Profile wall-clock timestamp unavailable: {error}"),
            Self::InvalidId(s) => write!(f, "Invalid profile ID: {}", s),
            Self::DuplicateId(id) => write!(f, "Duplicate profile ID: {}", id),
            Self::Io(s) => write!(f, "I/O error: {}", s),
            Self::Parse(s) => write!(f, "Parse error: {}", s),
            Self::NotFound(s) => write!(f, "Profile not found: {}", s),
        }
    }
}

impl std::error::Error for ProfileError {}

struct TemporaryFileGuard {
    path: PathBuf,
    committed: bool,
}

impl TemporaryFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, committed: false }
    }

    fn mark_committed(&mut self) {
        self.committed = true;
    }
}

impl Drop for TemporaryFileGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn atomic_write_profile(path: &Path, bytes: &[u8]) -> Result<(), ProfileError> {
    let parent = parent_directory(path);
    fs::create_dir_all(parent).map_err(|error| profile_io("parent creation", parent, error))?;

    let (temporary_path, file) = create_temporary_profile_file(path)?;
    let mut temporary_file_guard = TemporaryFileGuard::new(temporary_path.clone());

    write_temporary_profile(&temporary_path, file, bytes)?;

    #[cfg(test)]
    test_failpoint::before(AtomicWriteStage::Replace)
        .map_err(|error| profile_io("atomic replace", path, error))?;

    replace_profile_file(&temporary_path, path)
        .map_err(|error| profile_io("atomic replace", path, error))?;
    temporary_file_guard.mark_committed();

    sync_profile_parent(path).map_err(|error| profile_io("parent sync", parent, error))
}

fn write_temporary_profile(
    temporary_path: &Path,
    mut file: File,
    bytes: &[u8],
) -> Result<(), ProfileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temporary_path, fs::Permissions::from_mode(PROFILE_FILE_MODE))
            .map_err(|error| profile_io("temporary permission set", temporary_path, error))?;
    }

    #[cfg(test)]
    test_failpoint::before(AtomicWriteStage::TemporaryWrite)
        .map_err(|error| profile_io("temporary write", temporary_path, error))?;

    file.write_all(bytes).map_err(|error| profile_io("temporary write", temporary_path, error))?;
    file.sync_all().map_err(|error| profile_io("temporary sync", temporary_path, error))?;
    Ok(())
}

fn create_temporary_profile_file(path: &Path) -> Result<(PathBuf, File), ProfileError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(PROFILE_FILE_MODE);
    }

    for _ in 0..TEMPORARY_FILE_NAME_ATTEMPTS {
        let temporary_path = temporary_profile_path(path)?;
        match options.open(&temporary_path) {
            Ok(file) => return Ok((temporary_path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(profile_io("temporary create", &temporary_path, error)),
        }
    }

    Err(ProfileError::Io(format!(
        "temporary create: exhausted unique names for {}",
        path.display()
    )))
}

fn temporary_profile_path(path: &Path) -> Result<PathBuf, ProfileError> {
    let mut nonce = [0u8; 8];
    crate::rng::fill_secure(&mut nonce)
        .map_err(|error| profile_io("temporary name entropy", path, error))?;

    let mut suffix = String::with_capacity(nonce.len() * 2);
    for byte in nonce {
        crate::rng::push_hex_byte(&mut suffix, byte);
    }

    let mut file_name = path.file_name().map(OsString::from).unwrap_or_else(|| "profile".into());
    file_name.push(format!(".tmp-{suffix}"));
    Ok(path.with_file_name(file_name))
}

fn profile_io(operation: &str, path: &Path, error: io::Error) -> ProfileError {
    ProfileError::Io(format!("{operation} {}: {error}", path.display()))
}

fn parent_directory(path: &Path) -> &Path {
    path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."))
}

#[cfg(windows)]
fn replace_profile_file(source: &Path, destination: &Path) -> io::Result<()> {
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
fn replace_profile_file(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(unix)]
fn sync_profile_parent(path: &Path) -> io::Result<()> {
    File::open(parent_directory(path))?.sync_all()
}

#[cfg(not(unix))]
fn sync_profile_parent(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum AtomicWriteStage {
    TemporaryWrite,
    Replace,
}

#[cfg(test)]
mod test_failpoint {
    use super::AtomicWriteStage;
    use std::cell::Cell;
    use std::io;

    thread_local! {
        static FAIL_STAGE: Cell<Option<AtomicWriteStage>> = const { Cell::new(None) };
    }

    pub(super) struct Guard {
        previous: Option<AtomicWriteStage>,
    }

    pub(super) fn install(stage: AtomicWriteStage) -> Guard {
        let previous = FAIL_STAGE.with(|state| state.replace(Some(stage)));
        Guard { previous }
    }

    pub(super) fn before(stage: AtomicWriteStage) -> io::Result<()> {
        if FAIL_STAGE.with(|state| state.get() == Some(stage)) {
            return Err(io::Error::other("injected profile persistence failure"));
        }
        Ok(())
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            FAIL_STAGE.with(|state| state.set(self.previous));
        }
    }
}

fn validate_profile_id(id: &str) -> Result<(), ProfileError> {
    if id.trim().is_empty() {
        return Err(ProfileError::InvalidId("profile ID must not be empty".to_string()));
    }
    Ok(())
}

/// Generate a 128-bit profile ID from the operating system CSPRNG.
fn generate_id() -> Result<String, ProfileError> {
    let mut bytes = [0u8; PROFILE_ID_BYTES];
    crate::rng::fill_secure(&mut bytes)
        .map_err(|error| ProfileError::Entropy(error.to_string()))?;

    let mut id = String::with_capacity(PROFILE_ID_BYTES * 2);
    for byte in bytes {
        crate::rng::push_hex_byte(&mut id, byte);
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_qkey() -> String {
        let config =
            qkey::QKeyConfig::new("192.168.1.1:4433", "example.com").with_token(&"b".repeat(64));
        qkey::generate(&config)
    }

    fn test_profile(id: &str, name: &str) -> Profile {
        Profile {
            id: id.to_string(),
            name: name.to_string(),
            server: "1.2.3.4:4433".to_string(),
            sni: "test.com".to_string(),
            favorite: false,
            last_connected: None,
            connect_count: 0,
            stealth_mode: None,
            fec_mode: None,
            token: None,
            country: None,
            city: None,
        }
    }

    fn test_storage_path(name: &str) -> PathBuf {
        static NEXT_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let sequence = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("quicfuscate-profile-{name}-{}-{sequence}.json", std::process::id()))
    }

    fn temporary_paths(path: &Path) -> Vec<PathBuf> {
        let prefix = format!("{}.tmp-", path.file_name().unwrap().to_string_lossy());
        std::fs::read_dir(parent_directory(path))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|candidate| {
                candidate
                    .file_name()
                    .map(|name| name.to_string_lossy().starts_with(&prefix))
                    .unwrap_or(false)
            })
            .collect()
    }

    fn cleanup_storage(path: &Path) {
        let _ = std::fs::remove_file(path);
        for temporary_path in temporary_paths(path) {
            let _ = std::fs::remove_file(temporary_path);
        }
    }

    #[test]
    fn test_profile_from_qkey() {
        let qkey = valid_qkey();

        let profile = Profile::from_qkey("Test Server", &qkey).unwrap();

        assert_eq!(profile.name, "Test Server");
        assert_eq!(profile.server, "192.168.1.1:4433");
        assert_eq!(profile.sni, "example.com");
        assert!(profile.token.is_some());
        assert_eq!(profile.id.len(), PROFILE_ID_BYTES * 2);
        assert!(profile.id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn mark_connected_rejects_pre_epoch_wall_clock_without_mutating_profile() {
        let source = crate::time_source::test_support::ManualTimeSource::new(
            std::time::Instant::now(),
            std::time::SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(1),
        );
        let clock = ProtocolClock::from_source(source);
        let mut profile = test_profile("clock", "Clock");

        assert!(matches!(
            profile.mark_connected_with_clock(&clock),
            Err(ProfileError::Clock(WallClockError::BeforeUnixEpoch))
        ));
        assert_eq!(profile.last_connected, None);
        assert_eq!(profile.connect_count, 0);
    }

    #[test]
    fn test_profile_manager() {
        let mut manager = ProfileManager::new("/tmp/test_profiles.json");

        let profile = Profile {
            id: "test1".to_string(),
            name: "Test".to_string(),
            server: "1.2.3.4:4433".to_string(),
            sni: "test.com".to_string(),
            favorite: false,
            last_connected: None,
            connect_count: 0,
            stealth_mode: None,
            fec_mode: None,
            token: None,
            country: None,
            city: None,
        };

        manager.add(profile).unwrap();
        assert_eq!(manager.count(), 1);
        assert!(manager.get("test1").is_some());
    }

    #[test]
    fn test_favorites() {
        let mut manager = ProfileManager::new("/tmp/test_profiles2.json");

        let p1 = Profile {
            id: "p1".to_string(),
            name: "Server 1".to_string(),
            server: "1.1.1.1:4433".to_string(),
            sni: "s1.com".to_string(),
            favorite: true,
            last_connected: None,
            connect_count: 0,
            stealth_mode: None,
            fec_mode: None,
            token: None,
            country: None,
            city: None,
        };

        let p2 = Profile {
            id: "p2".to_string(),
            name: "Server 2".to_string(),
            server: "2.2.2.2:4433".to_string(),
            sni: "s2.com".to_string(),
            favorite: false,
            last_connected: None,
            connect_count: 0,
            stealth_mode: None,
            fec_mode: None,
            token: None,
            country: None,
            city: None,
        };

        manager.add(p1).unwrap();
        manager.add(p2).unwrap();

        assert_eq!(manager.favorites().len(), 1);
        assert_eq!(manager.favorites()[0].name, "Server 1");
    }

    #[test]
    fn profile_ids_are_random_128_bit_values_without_rapid_collisions() {
        let qkey = valid_qkey();
        let mut ids = std::collections::HashSet::new();

        for _ in 0..128 {
            let profile = Profile::from_qkey("Test Server", &qkey).unwrap();
            assert!(ids.insert(profile.id));
        }
    }

    #[test]
    fn profile_id_generation_propagates_entropy_failure() {
        let qkey = valid_qkey();
        let previous = crate::rng::test_force_secure_entropy_failure(true);
        let result = Profile::from_qkey("Test Server", &qkey);
        crate::rng::test_force_secure_entropy_failure(previous);

        assert!(matches!(result, Err(ProfileError::Entropy(_))));
    }

    #[test]
    fn add_rejects_empty_and_duplicate_ids_without_replacement() {
        let mut manager = ProfileManager::new(test_storage_path("add"));
        assert!(matches!(manager.add(test_profile("", "empty")), Err(ProfileError::InvalidId(_))));

        manager.add(test_profile("same-id", "first")).unwrap();
        let error = manager.add(test_profile("same-id", "second")).unwrap_err();
        assert!(matches!(error, ProfileError::DuplicateId(id) if id == "same-id"));
        assert_eq!(manager.get("same-id").map(|profile| profile.name.as_str()), Some("first"));
    }

    #[test]
    fn load_rejects_duplicate_ids_before_replacing_current_state() {
        let path = test_storage_path("duplicate-load");
        let content = serde_json::to_string(&[
            test_profile("same-id", "first"),
            test_profile("same-id", "second"),
        ])
        .unwrap();
        std::fs::write(&path, content).unwrap();

        let mut manager = ProfileManager::new(&path);
        let error = manager.load().unwrap_err();
        assert!(matches!(error, ProfileError::DuplicateId(id) if id == "same-id"));
        assert_eq!(manager.count(), 0);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn nonempty_legacy_ids_round_trip_without_automatic_migration() {
        let path = test_storage_path("legacy");
        let mut manager = ProfileManager::new(&path);
        manager.add(test_profile("legacy-short-id", "legacy")).unwrap();
        manager.save().unwrap();

        let mut loaded = ProfileManager::new(&path);
        loaded.load().unwrap();
        assert!(loaded.get("legacy-short-id").is_some());
        cleanup_storage(&path);
    }

    #[test]
    fn save_load_round_trip_is_atomic_and_deterministic() {
        let first_path = test_storage_path("round-trip-first");
        let second_path = test_storage_path("round-trip-second");

        let mut first = ProfileManager::new(&first_path);
        first.add(test_profile("profile-b", "B")).unwrap();
        first.add(test_profile("profile-a", "A")).unwrap();
        first.save().unwrap();

        let mut second = ProfileManager::new(&second_path);
        second.add(test_profile("profile-a", "A")).unwrap();
        second.add(test_profile("profile-b", "B")).unwrap();
        second.save().unwrap();

        assert_eq!(std::fs::read(&first_path).unwrap(), std::fs::read(&second_path).unwrap());

        let mut loaded = ProfileManager::new(&first_path);
        loaded.load().unwrap();
        assert_eq!(loaded.count(), 2);
        assert_eq!(loaded.get("profile-a").map(|profile| profile.name.as_str()), Some("A"));
        assert_eq!(loaded.get("profile-b").map(|profile| profile.name.as_str()), Some("B"));

        cleanup_storage(&first_path);
        cleanup_storage(&second_path);
    }

    #[test]
    fn save_serializes_bearer_token_and_applies_sensitive_file_mode() {
        #[cfg(unix)]
        let _umask = crate::test_support::permissive_umask();
        let path = test_storage_path("bearer");
        let token = "b".repeat(64);
        let qkey = qkey::QKeyConfig::new("192.168.1.1:4433", "example.com").with_token(&token);
        let profile = Profile::from_qkey("Bearer", &qkey::generate(&qkey)).unwrap();
        let id = profile.id.clone();

        let mut manager = ProfileManager::new(&path);
        manager.add(profile).unwrap();
        manager.save().unwrap();

        let encoded: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(encoded[0]["token"].as_str(), Some(token.as_str()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, PROFILE_FILE_MODE);
        }

        let mut loaded = ProfileManager::new(&path);
        loaded.load().unwrap();
        assert_eq!(
            loaded.get(&id).and_then(|profile| profile.token.as_ref()).map(|token| token.as_ref()),
            Some(token.as_str())
        );

        cleanup_storage(&path);
    }

    #[test]
    fn failed_write_preserves_previous_file_keeps_dirty_and_cleans_temporary() {
        let path = test_storage_path("failed-write");
        let mut manager = ProfileManager::new(&path);
        manager.add(test_profile("old", "old")).unwrap();
        manager.save().unwrap();
        let previous = std::fs::read(&path).unwrap();

        manager.add(test_profile("new", "new")).unwrap();
        let failure = test_failpoint::install(AtomicWriteStage::TemporaryWrite);
        let error = manager.save().unwrap_err();
        drop(failure);

        assert!(matches!(error, ProfileError::Io(message) if message.contains("temporary write")));
        assert_eq!(std::fs::read(&path).unwrap(), previous);
        assert!(temporary_paths(&path).is_empty());

        manager.save().unwrap();
        let mut loaded = ProfileManager::new(&path);
        loaded.load().unwrap();
        assert_eq!(loaded.count(), 2);

        cleanup_storage(&path);
    }

    #[test]
    fn failed_replace_preserves_previous_file_keeps_dirty_and_cleans_temporary() {
        let path = test_storage_path("failed-replace");
        let mut manager = ProfileManager::new(&path);
        manager.add(test_profile("old", "old")).unwrap();
        manager.save().unwrap();
        let previous = std::fs::read(&path).unwrap();

        manager.add(test_profile("new", "new")).unwrap();
        let failure = test_failpoint::install(AtomicWriteStage::Replace);
        let error = manager.save().unwrap_err();
        drop(failure);

        assert!(matches!(error, ProfileError::Io(message) if message.contains("atomic replace")));
        assert_eq!(std::fs::read(&path).unwrap(), previous);
        assert!(temporary_paths(&path).is_empty());

        manager.save().unwrap();
        let mut loaded = ProfileManager::new(&path);
        loaded.load().unwrap();
        assert_eq!(loaded.count(), 2);

        cleanup_storage(&path);
    }

    #[test]
    fn real_replace_failure_preserves_destination_and_cleans_temporary() {
        let path = test_storage_path("real-replace-failure");
        std::fs::create_dir(&path).unwrap();

        let mut manager = ProfileManager::new(&path);
        manager.add(test_profile("profile", "profile")).unwrap();
        let error = manager.save().unwrap_err();

        assert!(matches!(error, ProfileError::Io(message) if message.contains("atomic replace")));
        assert!(path.is_dir());
        assert!(temporary_paths(&path).is_empty());
        let _ = std::fs::remove_dir(&path);
    }

    #[test]
    fn interrupted_temporary_artifact_is_ignored_by_load() {
        let path = test_storage_path("interrupted");
        let mut manager = ProfileManager::new(&path);
        manager.add(test_profile("stable", "stable")).unwrap();
        manager.save().unwrap();

        let interrupted_path = path.with_file_name(format!(
            "{}.tmp-interrupted",
            path.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&interrupted_path, b"incomplete profile data").unwrap();

        let mut loaded = ProfileManager::new(&path);
        loaded.load().unwrap();
        assert_eq!(loaded.count(), 1);
        assert!(loaded.get("stable").is_some());
        assert!(interrupted_path.exists());

        cleanup_storage(&path);
    }
}
