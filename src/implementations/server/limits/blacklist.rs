use super::{
    MAX_BLACKLIST_BODY_BYTES, MAX_BLACKLIST_CA_BUNDLE_BYTES, MAX_BLACKLIST_ENTRIES,
    MAX_BLACKLIST_REQUEST_TIMEOUT_SECS, MAX_BLACKLIST_SYNC_INTERVAL_SECS, MAX_BLACKLIST_TTL_SECS,
};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::time_source::ProtocolClock;

// ---------------------------------------------------------------------------
// Blacklist sync.
//
// Maintains a set of blocked IPs with per-entry TTL. Supports synchronization
// from external threat-intelligence feeds (plain-text IP lists, one per line).
// Lookups are O(1) under an RwLock read.
// ---------------------------------------------------------------------------

/// Error type for blacklist synchronization operations.
#[derive(Debug)]
pub enum BlacklistError {
    /// No sync URL configured.
    NoSyncUrl,
    /// Synchronization was cancelled by the owning runtime.
    Cancelled,
    /// HTTP fetch failed.
    FetchError(String),
    /// Bounded cache read or write failed.
    CacheError(String),
    /// The wall clock could not provide a valid epoch timestamp.
    Clock(crate::time_source::WallClockError),
    /// Configuration or feed content violated the bounded contract.
    InvalidData(String),
}

impl std::fmt::Display for BlacklistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSyncUrl => write!(f, "no blacklist sync URL configured"),
            Self::Cancelled => write!(f, "blacklist synchronization cancelled"),
            Self::FetchError(s) => write!(f, "blacklist fetch error: {s}"),
            Self::CacheError(s) => write!(f, "blacklist cache error: {s}"),
            Self::Clock(error) => write!(f, "blacklist wall-clock error: {error}"),
            Self::InvalidData(s) => write!(f, "invalid blacklist data: {s}"),
        }
    }
}

impl std::error::Error for BlacklistError {}

const BLACKLIST_SYNC_PHASE_FETCHING: u8 = 0;
const BLACKLIST_SYNC_PHASE_PUBLISHING: u8 = 1;
const BLACKLIST_SYNC_PHASE_FINISHED: u8 = 2;
const BLACKLIST_SYNC_PHASE_CANCELLED: u8 = 3;

/// Cancellation and publication-commit ownership shared by the runtime and
/// the blocking blacklist worker.
pub(crate) struct BlacklistSyncControl {
    cancel_requested: AtomicBool,
    phase: AtomicU8,
    cache_commit: parking_lot::Mutex<()>,
}

impl BlacklistSyncControl {
    pub(crate) fn new() -> Self {
        Self {
            cancel_requested: AtomicBool::new(false),
            phase: AtomicU8::new(BLACKLIST_SYNC_PHASE_FETCHING),
            cache_commit: parking_lot::Mutex::new(()),
        }
    }

    pub(crate) fn request_cancel(&self) {
        self.cancel_requested.store(true, Ordering::Release);
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancel_requested.load(Ordering::Acquire)
            || self.phase.load(Ordering::Acquire) == BLACKLIST_SYNC_PHASE_CANCELLED
    }

    pub(crate) fn begin_publication(&self) -> bool {
        if self.is_cancelled() {
            return false;
        }
        if self
            .phase
            .compare_exchange(
                BLACKLIST_SYNC_PHASE_FETCHING,
                BLACKLIST_SYNC_PHASE_PUBLISHING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        if self.cancel_requested.load(Ordering::Acquire) {
            self.phase.store(BLACKLIST_SYNC_PHASE_CANCELLED, Ordering::Release);
            return false;
        }
        true
    }

    pub(crate) fn cancel_before_publication(&self) -> bool {
        self.request_cancel();
        match self.phase.compare_exchange(
            BLACKLIST_SYNC_PHASE_FETCHING,
            BLACKLIST_SYNC_PHASE_CANCELLED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) | Err(BLACKLIST_SYNC_PHASE_CANCELLED) => true,
            Err(BLACKLIST_SYNC_PHASE_PUBLISHING) | Err(BLACKLIST_SYNC_PHASE_FINISHED) => false,
            Err(_) => false,
        }
    }

    pub(crate) fn publication_in_flight(&self) -> bool {
        self.phase.load(Ordering::Acquire) == BLACKLIST_SYNC_PHASE_PUBLISHING
    }

    pub(crate) fn finish(&self) {
        self.phase.store(BLACKLIST_SYNC_PHASE_FINISHED, Ordering::Release);
    }

    pub(crate) fn synchronize_publication_commit(&self) {
        drop(self.cache_commit.lock());
    }

    fn commit_publication<F>(&self, commit: F) -> std::io::Result<bool>
    where
        F: FnOnce() -> std::io::Result<()>,
    {
        let _commit = self.cache_commit.lock();
        if self.is_cancelled() {
            return Ok(false);
        }
        commit()?;
        Ok(true)
    }
}

fn load_blacklist_ca_bundle(
    path: &std::path::Path,
) -> Result<Vec<reqwest::Certificate>, BlacklistError> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        BlacklistError::InvalidData(format!(
            "blacklist CA bundle metadata {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(BlacklistError::InvalidData(format!(
            "blacklist CA bundle must be a non-empty regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > MAX_BLACKLIST_CA_BUNDLE_BYTES {
        return Err(BlacklistError::InvalidData(format!(
            "blacklist CA bundle exceeds {MAX_BLACKLIST_CA_BUNDLE_BYTES} bytes: {}",
            path.display()
        )));
    }
    let pem = std::fs::read(path).map_err(|error| {
        BlacklistError::InvalidData(format!("blacklist CA bundle read {}: {error}", path.display()))
    })?;
    if pem.len() as u64 > MAX_BLACKLIST_CA_BUNDLE_BYTES {
        return Err(BlacklistError::InvalidData(format!(
            "blacklist CA bundle exceeds {MAX_BLACKLIST_CA_BUNDLE_BYTES} bytes after read: {}",
            path.display()
        )));
    }
    let certificates = reqwest::Certificate::from_pem_bundle(&pem).map_err(|error| {
        BlacklistError::InvalidData(format!(
            "blacklist CA bundle parse {}: {error}",
            path.display()
        ))
    })?;
    if certificates.is_empty() {
        return Err(BlacklistError::InvalidData(format!(
            "blacklist CA bundle contains no certificates: {}",
            path.display()
        )));
    }
    Ok(certificates)
}

/// External blacklist synchronizer with TTL-based expiry.
///
/// Tracks blocked IPs in a `HashMap<IpAddr, Instant>` (IP → expiry). Entries
/// auto-expire past their TTL; `prune_expired` reclaims memory. The `sync`
/// method fetches a plain-text IP list (one IP per line, lines starting with
/// `#` are comments) from the configured URL and replaces the blocked set.
pub struct BlacklistSync {
    blocked: Arc<parking_lot::RwLock<HashMap<IpAddr, Instant>>>,
    default_ttl: Duration,
    sync_url: Option<String>,
    sync_interval: Duration,
    request_timeout: Duration,
    max_body_bytes: usize,
    max_entries: usize,
    cache_path: Option<PathBuf>,
    custom_ca_certificates: Vec<reqwest::Certificate>,
    clock: ProtocolClock,
}

impl BlacklistSync {
    /// Create a new blacklist synchronizer.
    pub fn new(default_ttl: Duration, sync_url: Option<String>, sync_interval: Duration) -> Self {
        Self::new_with_clock(default_ttl, sync_url, sync_interval, &ProtocolClock::default())
    }

    /// Create a blacklist synchronizer bound to an explicit protocol clock.
    ///
    /// The legacy constructor supplies fixed validated bounds and keeps the
    /// original infallible API. Call [`Self::new_bounded_with_clock`] when the
    /// caller needs typed validation errors.
    #[allow(clippy::expect_used)]
    pub fn new_with_clock(
        default_ttl: Duration,
        sync_url: Option<String>,
        sync_interval: Duration,
        clock: &ProtocolClock,
    ) -> Self {
        Self::new_bounded_with_clock(
            default_ttl,
            sync_url,
            sync_interval,
            Duration::from_secs(30),
            MAX_BLACKLIST_BODY_BYTES,
            MAX_BLACKLIST_ENTRIES,
            None,
            clock,
        )
        .expect("legacy blacklist defaults must be valid")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_bounded(
        default_ttl: Duration,
        sync_url: Option<String>,
        sync_interval: Duration,
        request_timeout: Duration,
        max_body_bytes: usize,
        max_entries: usize,
        cache_path: Option<PathBuf>,
    ) -> Result<Self, BlacklistError> {
        Self::new_bounded_with_clock(
            default_ttl,
            sync_url,
            sync_interval,
            request_timeout,
            max_body_bytes,
            max_entries,
            cache_path,
            &ProtocolClock::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_bounded_with_clock(
        default_ttl: Duration,
        sync_url: Option<String>,
        sync_interval: Duration,
        request_timeout: Duration,
        max_body_bytes: usize,
        max_entries: usize,
        cache_path: Option<PathBuf>,
        clock: &ProtocolClock,
    ) -> Result<Self, BlacklistError> {
        Self::new_bounded_with_ca_and_clock(
            default_ttl,
            sync_url,
            sync_interval,
            request_timeout,
            max_body_bytes,
            max_entries,
            cache_path,
            None,
            clock,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_bounded_with_ca(
        default_ttl: Duration,
        sync_url: Option<String>,
        sync_interval: Duration,
        request_timeout: Duration,
        max_body_bytes: usize,
        max_entries: usize,
        cache_path: Option<PathBuf>,
        custom_ca_path: Option<PathBuf>,
    ) -> Result<Self, BlacklistError> {
        Self::new_bounded_with_ca_and_clock(
            default_ttl,
            sync_url,
            sync_interval,
            request_timeout,
            max_body_bytes,
            max_entries,
            cache_path,
            custom_ca_path,
            &ProtocolClock::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_bounded_with_ca_and_clock(
        default_ttl: Duration,
        sync_url: Option<String>,
        sync_interval: Duration,
        request_timeout: Duration,
        max_body_bytes: usize,
        max_entries: usize,
        cache_path: Option<PathBuf>,
        custom_ca_path: Option<PathBuf>,
        clock: &ProtocolClock,
    ) -> Result<Self, BlacklistError> {
        if default_ttl.is_zero()
            || sync_interval.is_zero()
            || request_timeout.is_zero()
            || max_body_bytes == 0
            || max_entries == 0
        {
            return Err(BlacklistError::InvalidData(
                "TTL, sync interval, timeout, body cap, and entry cap must be nonzero".to_string(),
            ));
        }
        if default_ttl > Duration::from_secs(MAX_BLACKLIST_TTL_SECS) {
            return Err(BlacklistError::InvalidData(format!(
                "TTL exceeds {MAX_BLACKLIST_TTL_SECS} seconds"
            )));
        }
        if sync_interval > Duration::from_secs(MAX_BLACKLIST_SYNC_INTERVAL_SECS) {
            return Err(BlacklistError::InvalidData(format!(
                "sync interval exceeds {MAX_BLACKLIST_SYNC_INTERVAL_SECS} seconds"
            )));
        }
        if request_timeout > Duration::from_secs(MAX_BLACKLIST_REQUEST_TIMEOUT_SECS) {
            return Err(BlacklistError::InvalidData(format!(
                "request timeout exceeds {MAX_BLACKLIST_REQUEST_TIMEOUT_SECS} seconds"
            )));
        }
        if max_body_bytes > MAX_BLACKLIST_BODY_BYTES {
            return Err(BlacklistError::InvalidData(format!(
                "body cap exceeds {MAX_BLACKLIST_BODY_BYTES} bytes"
            )));
        }
        if max_entries > MAX_BLACKLIST_ENTRIES {
            return Err(BlacklistError::InvalidData(format!(
                "entry cap exceeds {MAX_BLACKLIST_ENTRIES} entries"
            )));
        }
        if sync_url.as_ref().is_some_and(|url| !url.starts_with("https://")) {
            return Err(BlacklistError::InvalidData(
                "blacklist sync URL must use HTTPS".to_string(),
            ));
        }
        let custom_ca_certificates = match custom_ca_path {
            Some(path) => load_blacklist_ca_bundle(&path)?,
            None => Vec::new(),
        };
        let synchronizer = Self {
            blocked: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            default_ttl,
            sync_url,
            sync_interval,
            request_timeout,
            max_body_bytes,
            max_entries,
            cache_path,
            custom_ca_certificates,
            clock: clock.clone(),
        };
        if let Err(error) = synchronizer.load_cache() {
            log::warn!("Blacklist cache ignored: {error}");
        }
        Ok(synchronizer)
    }

    /// Create a synchronizer with no feed configured (manual blocking only).
    pub fn manual_only(default_ttl: Duration) -> Self {
        Self::manual_only_with_clock(default_ttl, &ProtocolClock::default())
    }

    /// Create a manual-only synchronizer with an explicit protocol clock.
    pub fn manual_only_with_clock(default_ttl: Duration, clock: &ProtocolClock) -> Self {
        Self::new_with_clock(default_ttl, None, Duration::from_secs(3600), clock)
    }

    /// Whether an IP is currently blocked (and not expired).
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let now = self.clock.now();
        let guard = self.blocked.read();
        match guard.get(&ip) {
            Some(expiry) => *expiry > now,
            None => false,
        }
    }

    /// Add an IP to the blacklist with the default TTL.
    pub fn add(&self, ip: IpAddr) {
        self.add_with_ttl(ip, self.default_ttl);
    }

    /// Add an IP to the blacklist with a custom TTL.
    pub fn add_with_ttl(&self, ip: IpAddr, ttl: Duration) {
        let ttl = ttl.min(Duration::from_secs(MAX_BLACKLIST_TTL_SECS));
        let now = self.clock.now();
        let expiry = now.checked_add(ttl).unwrap_or(now);
        self.blocked.write().insert(ip, expiry);
    }

    /// Remove an IP from the blacklist.
    pub fn remove(&self, ip: IpAddr) {
        self.blocked.write().remove(&ip);
    }

    /// Replace the entire blocked set from an external feed (bulk sync).
    /// Each entry is seeded with the default TTL.
    pub fn replace_list(&self, ips: &[IpAddr]) {
        replace_blacklist_entries(&self.blocked, self.default_ttl, ips, &self.clock);
    }

    /// Number of currently-blocked (non-expired) IPs.
    pub fn len(&self) -> usize {
        let now = self.clock.now();
        self.blocked.read().values().filter(|e| **e > now).count()
    }

    /// Whether the blacklist is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Prune expired entries to bound memory.
    pub fn prune_expired(&self) {
        let now = self.clock.now();
        self.blocked.write().retain(|_, expiry| *expiry > now);
    }

    /// Configured sync interval.
    pub fn sync_interval(&self) -> Duration {
        self.sync_interval
    }

    /// Whether an external sync URL is configured.
    pub fn has_sync_url(&self) -> bool {
        self.sync_url.is_some()
    }

    /// Synchronize the blacklist from the external feed.
    ///
    /// Fetches a plain-text IP list (one IP per line; lines starting with `#`
    /// or empty lines are ignored) from the configured URL via HTTPS and
    /// replaces the blocked set. Each entry is seeded with the default TTL.
    ///
    /// The response body is capped at the configured bound, which is itself
    /// validated against `MAX_BLACKLIST_BODY_BYTES`. Both the `Content-Length`
    /// header and the actual byte count are checked.
    ///
    /// Async because the server's housekeeping loop runs inside a Tokio
    /// runtime; using the async `reqwest::Client` avoids the
    /// "Cannot start a runtime from within a runtime" panic that
    /// `reqwest::blocking` triggers under Tokio. Callers outside an async
    /// context should wrap this in `tokio::task::spawn_blocking` + a
    /// `Runtime::block_on`, or use a dedicated runtime.
    pub async fn sync(&self) -> Result<usize, BlacklistError> {
        let control = Arc::new(BlacklistSyncControl::new());
        let result = self.sync_with_cancel(Arc::clone(&control)).await;
        control.finish();
        result
    }

    /// Synchronize the feed while honoring the owning worker's cancellation flag.
    pub(crate) async fn sync_with_cancel(
        &self,
        cancellation: Arc<BlacklistSyncControl>,
    ) -> Result<usize, BlacklistError> {
        let url = match &self.sync_url {
            Some(u) => u.clone(),
            None => return Err(BlacklistError::NoSyncUrl),
        };
        if cancellation.is_cancelled() {
            return Err(BlacklistError::Cancelled);
        }

        let mut client_builder = reqwest::Client::builder()
            .timeout(self.request_timeout)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::limited(3))
            .user_agent("quicfuscate-blacklist-sync/1.0");
        for certificate in &self.custom_ca_certificates {
            client_builder = client_builder.add_root_certificate(certificate.clone());
        }
        let client = client_builder
            .build()
            .map_err(|e| BlacklistError::FetchError(format!("client build: {e}")))?;

        let mut response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| BlacklistError::FetchError(format!("request: {e}")))?;

        if !response.status().is_success() {
            return Err(BlacklistError::FetchError(format!(
                "HTTP {} from {}",
                response.status(),
                url
            )));
        }

        // Pre-check Content-Length if the server provided it. A feed larger
        // than the cap is rejected before any body bytes are buffered.
        if let Some(len) = response.content_length() {
            if len > self.max_body_bytes as u64 {
                return Err(BlacklistError::FetchError(format!(
                    "feed body too large: Content-Length {len} > {} bytes",
                    self.max_body_bytes
                )));
            }
        }

        let mut body = Vec::with_capacity(
            response.content_length().unwrap_or(0).min(self.max_body_bytes as u64) as usize,
        );
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| BlacklistError::FetchError(format!("body read: {error}")))?
        {
            if cancellation.is_cancelled() {
                return Err(BlacklistError::Cancelled);
            }
            if body.len().saturating_add(chunk.len()) > self.max_body_bytes {
                return Err(BlacklistError::FetchError(format!(
                    "feed body exceeds {} bytes",
                    self.max_body_bytes
                )));
            }
            body.extend_from_slice(&chunk);
        }

        if !cancellation.begin_publication() {
            return Err(BlacklistError::Cancelled);
        }

        let max_body_bytes = self.max_body_bytes;
        let max_entries = self.max_entries;
        let default_ttl = self.default_ttl;
        let cache_path = self.cache_path.clone();
        let blocked = Arc::clone(&self.blocked);
        let clock = self.clock.clone();
        let cancellation_for_blocking = Arc::clone(&cancellation);
        let ips = tokio::task::spawn_blocking(move || {
            if cancellation_for_blocking.is_cancelled() {
                return Err(BlacklistError::Cancelled);
            }
            let ips = parse_blacklist_feed(&body, max_body_bytes, max_entries)?;
            if cancellation_for_blocking.is_cancelled() {
                return Err(BlacklistError::Cancelled);
            }
            publish_blacklist_feed(
                cache_path.as_deref(),
                default_ttl,
                max_body_bytes,
                &ips,
                &clock,
                &blocked,
                &cancellation_for_blocking,
            )?;
            Ok(ips.len())
        })
        .await
        .map_err(|error| BlacklistError::CacheError(format!("blocking publication: {error}")))??;

        let count = ips;
        log::info!("Blacklist sync: loaded {count} IPs from {url}");
        Ok(count)
    }

    #[cfg(test)]
    pub(super) fn parse_feed(&self, body: &[u8]) -> Result<Vec<IpAddr>, BlacklistError> {
        parse_blacklist_feed(body, self.max_body_bytes, self.max_entries)
    }

    #[cfg(test)]
    pub(super) fn apply_feed(&self, body: &[u8]) -> Result<usize, BlacklistError> {
        let ips = self.parse_feed(body)?;
        let count = ips.len();
        self.persist_cache(&ips)?;
        self.replace_list(&ips);
        Ok(count)
    }

    fn load_cache(&self) -> Result<usize, BlacklistError> {
        let Some(path) = self.cache_path.as_ref() else {
            return Ok(0);
        };
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => {
                return Err(BlacklistError::CacheError(format!(
                    "metadata {}: {error}",
                    path.display()
                )))
            }
        };
        if metadata.len() > self.max_body_bytes as u64 {
            return Err(BlacklistError::CacheError(format!(
                "{} exceeds {} bytes",
                path.display(),
                self.max_body_bytes
            )));
        }
        let bytes = std::fs::read(path)
            .map_err(|error| BlacklistError::CacheError(format!("read: {error}")))?;
        let cache: BlacklistCache = serde_json::from_slice(&bytes)
            .map_err(|error| BlacklistError::CacheError(format!("parse: {error}")))?;
        if cache.version != 1 || cache.ips.len() > self.max_entries {
            return Err(BlacklistError::CacheError(
                "unsupported version or entry bound exceeded".to_string(),
            ));
        }
        let now = crate::time_source::unix_epoch_seconds(self.clock.now_system())
            .map_err(BlacklistError::Clock)?;
        if cache.expires_at_secs <= now {
            return Err(BlacklistError::CacheError("cache is stale".to_string()));
        }
        if cache.expires_at_secs.saturating_sub(now) > MAX_BLACKLIST_TTL_SECS {
            return Err(BlacklistError::CacheError("cache TTL exceeds absolute bound".to_string()));
        }
        let mut unique: HashSet<IpAddr> = cache.ips.into_iter().collect();
        if unique.len() > self.max_entries {
            return Err(BlacklistError::CacheError("cache entry bound exceeded".to_string()));
        }
        let remaining = Duration::from_secs(cache.expires_at_secs - now);
        let now = self.clock.now();
        let expiry = now.checked_add(remaining).unwrap_or(now);
        let count = unique.len();
        self.blocked.write().extend(unique.drain().map(|ip| (ip, expiry)));
        log::info!("Blacklist cache: loaded {count} entries from {}", path.display());
        Ok(count)
    }

    #[cfg(test)]
    pub(super) fn persist_cache(&self, ips: &[IpAddr]) -> Result<(), BlacklistError> {
        persist_blacklist_cache(
            self.cache_path.as_deref(),
            self.default_ttl,
            self.max_body_bytes,
            ips,
            &self.clock,
        )
    }
}

fn parse_blacklist_feed(
    body: &[u8],
    max_body_bytes: usize,
    max_entries: usize,
) -> Result<Vec<IpAddr>, BlacklistError> {
    if body.len() > max_body_bytes {
        return Err(BlacklistError::InvalidData(format!(
            "feed body exceeds {max_body_bytes} bytes"
        )));
    }
    let body_text = std::str::from_utf8(body)
        .map_err(|error| BlacklistError::InvalidData(format!("feed is not UTF-8: {error}")))?;
    let mut unique = HashSet::new();
    for (line_index, line) in body_text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let ip_str = line.split('#').next().unwrap_or(line).trim();
        let ip = ip_str.parse::<IpAddr>().map_err(|error| {
            BlacklistError::InvalidData(format!(
                "line {} is not an IP address: {error}",
                line_index + 1
            ))
        })?;
        unique.insert(ip);
        if unique.len() > max_entries {
            return Err(BlacklistError::InvalidData(format!(
                "feed exceeds {max_entries} unique entries"
            )));
        }
    }

    let mut ips: Vec<IpAddr> = unique.into_iter().collect();
    ips.sort();
    Ok(ips)
}

fn replace_blacklist_entries(
    blocked: &parking_lot::RwLock<HashMap<IpAddr, Instant>>,
    default_ttl: Duration,
    ips: &[IpAddr],
    clock: &ProtocolClock,
) {
    let now = clock.now();
    let expiry = now.checked_add(default_ttl).unwrap_or(now);
    let mut guard = blocked.write();
    guard.clear();
    guard.reserve(ips.len());
    for ip in ips {
        guard.insert(*ip, expiry);
    }
}

#[cfg(test)]
fn persist_blacklist_cache(
    path: Option<&std::path::Path>,
    default_ttl: Duration,
    max_body_bytes: usize,
    ips: &[IpAddr],
    clock: &ProtocolClock,
) -> Result<(), BlacklistError> {
    let Some(path) = path else {
        return Ok(());
    };
    let bytes = serialize_blacklist_cache(default_ttl, max_body_bytes, ips, clock)?;
    crate::implementations::server::fsutil::atomic_write_file(
        path,
        &bytes,
        Some(0o600),
        "server::blacklist_cache_tmp_nonce",
    )
    .map_err(|error| BlacklistError::CacheError(format!("atomic write: {error}")))
}

pub(super) fn publish_blacklist_feed(
    path: Option<&std::path::Path>,
    default_ttl: Duration,
    max_body_bytes: usize,
    ips: &[IpAddr],
    clock: &ProtocolClock,
    blocked: &parking_lot::RwLock<HashMap<IpAddr, Instant>>,
    control: &BlacklistSyncControl,
) -> Result<(), BlacklistError> {
    let committed = if let Some(path) = path {
        let bytes = serialize_blacklist_cache(default_ttl, max_body_bytes, ips, clock)?;
        crate::implementations::server::fsutil::atomic_write_file_with_commit(
            path,
            &bytes,
            Some(0o600),
            "server::blacklist_cache_tmp_nonce",
            |temporary_path, destination_path| {
                control.commit_publication(|| {
                    std::fs::rename(temporary_path, destination_path)?;
                    replace_blacklist_entries(blocked, default_ttl, ips, clock);
                    Ok(())
                })
            },
        )
        .map_err(|error| BlacklistError::CacheError(format!("atomic write: {error}")))?
    } else {
        control
            .commit_publication(|| {
                replace_blacklist_entries(blocked, default_ttl, ips, clock);
                Ok(())
            })
            .map_err(|error| BlacklistError::CacheError(format!("publication: {error}")))?
    };
    if committed {
        Ok(())
    } else {
        Err(BlacklistError::Cancelled)
    }
}

fn serialize_blacklist_cache(
    default_ttl: Duration,
    max_body_bytes: usize,
    ips: &[IpAddr],
    clock: &ProtocolClock,
) -> Result<Vec<u8>, BlacklistError> {
    let now_secs = crate::time_source::unix_epoch_seconds(clock.now_system())
        .map_err(BlacklistError::Clock)?;
    let expires_at_secs = now_secs.checked_add(default_ttl.as_secs()).ok_or_else(|| {
        BlacklistError::CacheError("cache expiry exceeds Unix seconds".to_string())
    })?;
    let cache = BlacklistCache { version: 1, expires_at_secs, ips: ips.to_vec() };
    let bytes = serde_json::to_vec(&cache)
        .map_err(|error| BlacklistError::CacheError(format!("serialize: {error}")))?;
    if bytes.len() > max_body_bytes {
        return Err(BlacklistError::CacheError(format!(
            "serialized cache exceeds {max_body_bytes} bytes"
        )));
    }
    Ok(bytes)
}

#[derive(serde::Deserialize, serde::Serialize)]
pub(super) struct BlacklistCache {
    pub(super) version: u8,
    pub(super) expires_at_secs: u64,
    pub(super) ips: Vec<IpAddr>,
}

#[cfg(test)]
pub(super) fn current_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
