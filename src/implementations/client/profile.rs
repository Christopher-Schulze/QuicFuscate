//! Profile management for QuicFuscate client.
//!
//! Handles saving, loading, and managing VPN server profiles.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::engine::qkey;

/// A saved VPN profile.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    /// Unique identifier
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

        let id = generate_id();

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

/// Profile manager.
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

    /// Load profiles from storage.
    pub fn load(&mut self) -> Result<(), ProfileError> {
        if !self.storage_path.exists() {
            return Ok(());
        }

        let content = std::fs::read_to_string(&self.storage_path)
            .map_err(|e| ProfileError::Io(e.to_string()))?;

        let profiles: Vec<Profile> =
            serde_json::from_str(&content).map_err(|e| ProfileError::Parse(e.to_string()))?;

        self.profiles = profiles.into_iter().map(|p| (p.id.clone(), p)).collect();

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

    /// Add a new profile.
    pub fn add(&mut self, profile: Profile) -> String {
        let id = profile.id.clone();
        self.profiles.insert(id.clone(), profile);
        self.dirty = true;
        id
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
        Ok(self.add(profile))
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
    Io(String),
    Parse(String),
    NotFound(String),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidQKey(s) => write!(f, "Invalid QKey: {}", s),
            Self::Io(s) => write!(f, "I/O error: {}", s),
            Self::Parse(s) => write!(f, "Parse error: {}", s),
            Self::NotFound(s) => write!(f, "Profile not found: {}", s),
        }
    }
}

impl std::error::Error for ProfileError {}

/// Generate a short unique ID.
fn generate_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    format!("{:x}", now & 0xFFFFFFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_from_qkey() {
        // Generate a valid QKey for testing
        let config =
            qkey::QKeyConfig::new("192.168.1.1:4433", "example.com").with_token(&"b".repeat(64));
        let qkey = qkey::generate(&config);

        let profile = Profile::from_qkey("Test Server", &qkey).unwrap();

        assert_eq!(profile.name, "Test Server");
        assert_eq!(profile.server, "192.168.1.1:4433");
        assert_eq!(profile.sni, "example.com");
        assert!(profile.token.is_some());
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

        manager.add(profile);
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

        manager.add(p1);
        manager.add(p2);

        assert_eq!(manager.favorites().len(), 1);
        assert_eq!(manager.favorites()[0].name, "Server 1");
    }
}
