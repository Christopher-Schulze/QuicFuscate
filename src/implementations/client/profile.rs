//! Profile management for QuicFuscate client.
//!
//! Handles saving, loading, and managing VPN server profiles. `ProfileManager`
//! is a standalone storage API; `ClientRuntime`, the CLI, and desktop/admin
//! surfaces do not own it in the current product.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::engine::qkey;

const PROFILE_ID_BYTES: usize = 16;

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
    pub fn mark_connected(&mut self) {
        self.last_connected = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        self.connect_count += 1;
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

        // Ensure parent directory exists
        if let Some(parent) = self.storage_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ProfileError::Io(e.to_string()))?;
        }

        let profiles: Vec<&Profile> = self.profiles.values().collect();
        let content = serde_json::to_string_pretty(&profiles)
            .map_err(|e| ProfileError::Parse(e.to_string()))?;

        std::fs::write(&self.storage_path, content).map_err(|e| ProfileError::Io(e.to_string()))?;

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
            Self::InvalidId(s) => write!(f, "Invalid profile ID: {}", s),
            Self::DuplicateId(id) => write!(f, "Duplicate profile ID: {}", id),
            Self::Io(s) => write!(f, "I/O error: {}", s),
            Self::Parse(s) => write!(f, "Parse error: {}", s),
            Self::NotFound(s) => write!(f, "Profile not found: {}", s),
        }
    }
}

impl std::error::Error for ProfileError {}

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
        std::fs::remove_file(path).unwrap();
    }
}
