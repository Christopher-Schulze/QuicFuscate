use crate::reality::{CoverHandshakeCache, RealityConfig, RealityProxy};
use std::future::Future;
use std::sync::Weak;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub const STEALTH_RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const REALITY_SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
static NEXT_STEALTH_RUNTIME_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Shared publication gate for standalone runtime policy generations.
///
/// Transport, FEC, optimization, and stealth values remain owned by their
/// existing consumers, but readers and writers hold this gate before touching
/// those values so one generation is observed across all domains.
#[derive(Clone)]
pub(crate) struct RuntimePolicyGeneration {
    value: Arc<std::sync::RwLock<u64>>,
}

impl RuntimePolicyGeneration {
    pub(crate) fn new() -> Self {
        Self { value: Arc::new(std::sync::RwLock::new(1)) }
    }

    pub(crate) fn current(&self) -> u64 {
        *self.read_guard()
    }

    pub(crate) fn read_guard(&self) -> std::sync::RwLockReadGuard<'_, u64> {
        self.value.read().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn write_guard(&self) -> std::sync::RwLockWriteGuard<'_, u64> {
        self.value.write().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn advance(guard: &mut std::sync::RwLockWriteGuard<'_, u64>) {
        **guard = (**guard).saturating_add(1);
    }
}

struct OwnedStealthWorker {
    name: &'static str,
    handle: JoinHandle<()>,
}

struct StealthWorkerState {
    started: bool,
    workers: Vec<OwnedStealthWorker>,
}

struct ActiveWorkerGuard(Arc<AtomicUsize>);

impl Drop for ActiveWorkerGuard {
    fn drop(&mut self) {
        self.0.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            Some(count.saturating_sub(1))
        }).ok();
    }
}

/// Runtime owner for all stealth work that outlives one connection.
///
/// A runtime creates one owner per generation and passes its handle to every
/// connection it constructs. Connection personas remain immutable, while the
/// owner holds shared Reality material and the only refresh/rotation workers.
pub struct StealthRuntimeOwner {
    generation: u64,
    shutdown: Arc<AtomicBool>,
    cancel_tx: watch::Sender<bool>,
    worker_state: parking_lot::Mutex<StealthWorkerState>,
    active_workers: Arc<AtomicUsize>,
    mutation_gate: Arc<parking_lot::Mutex<()>>,
    reality_cache: Option<Arc<CoverHandshakeCache>>,
    reality_proxies: Arc<parking_lot::Mutex<Vec<Weak<RealityProxy>>>>,
    cleanup_worker_started: AtomicBool,
    next_session_stealth_config:
        parking_lot::Mutex<Option<Arc<std::sync::Mutex<StealthConfig>>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StealthShutdownReport {
    pub generation: u64,
    pub workers_joined: usize,
    pub workers_force_stopped: usize,
}

impl StealthRuntimeOwner {
    /// Construct one owner from an already resolved and validated Reality configuration.
    pub fn new(reality_config: RealityConfig) -> Result<Self, String> {
        reality_config.validate()?;
        let (cancel_tx, _) = watch::channel(false);
        let reality_cache = reality_config
            .enabled
            .then(|| Arc::new(CoverHandshakeCache::new(reality_config)));
        Ok(Self {
            generation: NEXT_STEALTH_RUNTIME_GENERATION.fetch_add(1, Ordering::Relaxed),
            shutdown: Arc::new(AtomicBool::new(false)),
            cancel_tx,
            worker_state: parking_lot::Mutex::new(StealthWorkerState {
                started: false,
                workers: Vec::new(),
            }),
            active_workers: Arc::new(AtomicUsize::new(0)),
            mutation_gate: Arc::new(parking_lot::Mutex::new(())),
            reality_cache,
            reality_proxies: Arc::new(parking_lot::Mutex::new(Vec::new())),
            cleanup_worker_started: AtomicBool::new(false),
            next_session_stealth_config: parking_lot::Mutex::new(None),
        })
    }

    /// Construct one owner from the process' effective Reality environment.
    pub fn from_env() -> Result<Self, String> {
        Self::new(RealityConfig::from_env())
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    pub(crate) fn cover_cache(&self) -> Option<Arc<CoverHandshakeCache>> {
        self.reality_cache.clone()
    }

    /// Return the current configuration snapshot for the next connection.
    pub(crate) fn next_session_stealth_config(&self) -> Option<StealthConfig> {
        let shared = self.next_session_stealth_config.lock().clone()?;
        let snapshot = shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        Some(snapshot)
    }

    /// Publish a validated next-connection configuration update.
    pub(crate) fn update_next_session_stealth_config(&self, config: StealthConfig) {
        let Some(shared) = self.next_session_stealth_config.lock().clone() else {
            return;
        };
        *shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = config;
    }

    /// Register a proxy for the owner's periodic, packet-independent session sweep.
    pub(crate) fn register_reality_proxy(self: &Arc<Self>, proxy: &Arc<RealityProxy>) {
        if self.is_shutdown() {
            return;
        }
        self.reality_proxies.lock().push(Arc::downgrade(proxy));
        if self.is_started() {
            if let Err(error) = self.ensure_cleanup_worker() {
                log::warn!(
                    "stealth runtime generation {} could not start Reality cleanup: {}",
                    self.generation,
                    error
                );
            }
        }
    }

    /// Start the shared Reality refresh, proxy cleanup, and profile rotation workers.
    pub fn start(
        self: &Arc<Self>,
        stealth_config: Option<Arc<std::sync::Mutex<StealthConfig>>>,
        profiles: Vec<FingerprintProfile>,
        profile_interval_secs: u64,
    ) -> Result<(), String> {
        self.start_with_policy_generation(stealth_config, profiles, profile_interval_secs, None)
    }

    pub(crate) fn start_with_policy_generation(
        self: &Arc<Self>,
        stealth_config: Option<Arc<std::sync::Mutex<StealthConfig>>>,
        profiles: Vec<FingerprintProfile>,
        profile_interval_secs: u64,
        runtime_policy_generation: Option<RuntimePolicyGeneration>,
    ) -> Result<(), String> {
        let _gate = self.mutation_gate.lock();
        if self.is_shutdown() {
            return Err(format!("stealth runtime generation {} is shut down", self.generation));
        }
        let needs_runtime = self.reality_cache.is_some()
            || !self.reality_proxies.lock().is_empty()
            || (stealth_config.is_some() && profiles.len() > 1 && profile_interval_secs > 0);
        if needs_runtime && tokio::runtime::Handle::try_current().is_err() {
            return Err("stealth background workers require an active Tokio runtime".to_string());
        }
        {
            let mut state = self.worker_state.lock();
            if state.started {
                return Err(format!(
                    "stealth runtime generation {} was already started",
                    self.generation
                ));
            }
            state.started = true;
        }
        *self.next_session_stealth_config.lock() = stealth_config.clone();

        let result = (|| {
            if let Some(cache) = self.reality_cache.clone() {
                let cancel = self.cancel_tx.subscribe();
                self.spawn_owned("reality-cover-refresh", async move {
                    cache.refresh_loop(cancel).await;
                })?;
            }
            if !self.reality_proxies.lock().is_empty() {
                self.ensure_cleanup_worker()?;
            }
            if let Some(stealth_config) = stealth_config {
                if profiles.len() > 1 && profile_interval_secs > 0 {
                    self.spawn_profile_rotation(
                        stealth_config,
                        profiles,
                        profile_interval_secs,
                        runtime_policy_generation,
                    )?;
                }
            }
            Ok::<(), String>(())
        })();
        if let Err(error) = result {
            self.shutdown.store(true, Ordering::Release);
            self.cancel_tx.send_replace(true);
            *self.next_session_stealth_config.lock() = None;
            let mut state = self.worker_state.lock();
            for worker in state.workers.drain(..) {
                worker.handle.abort();
            }
            state.started = false;
            self.active_workers.store(0, Ordering::Release);
            self.cleanup_worker_started.store(false, Ordering::Release);
            return Err(error);
        }
        Ok(())
    }

    fn is_started(&self) -> bool {
        self.worker_state.lock().started
    }

    fn spawn_owned<F>(
        &self,
        name: &'static str,
        future: F,
    ) -> Result<(), String>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(format!("worker {name} requires an active Tokio runtime"));
        }
        let active_workers = self.active_workers.clone();
        active_workers.fetch_add(1, Ordering::AcqRel);
        let handle = tokio::spawn(async move {
            let _guard = ActiveWorkerGuard(active_workers);
            future.await;
        });
        let mut state = self.worker_state.lock();
        if self.is_shutdown() {
            handle.abort();
            return Err(format!("worker {name} was created after shutdown"));
        }
        state.workers.push(OwnedStealthWorker { name, handle });
        Ok(())
    }

    fn spawn_profile_rotation(
        &self,
        stealth_config: Arc<std::sync::Mutex<StealthConfig>>,
        profiles: Vec<FingerprintProfile>,
        profile_interval_secs: u64,
        runtime_policy_generation: Option<RuntimePolicyGeneration>,
    ) -> Result<(), String> {
        let mut cancel = self.cancel_tx.subscribe();
        let shutdown = self.shutdown.clone();
        let mutation_gate = self.mutation_gate.clone();
        let generation = self.generation;
        self.spawn_owned("stealth-profile-rotation", async move {
            let mut index = 0usize;
            let delay = Duration::from_secs(profile_interval_secs);
            loop {
                if !wait_for_delay_or_cancel(&mut cancel, delay).await {
                    return;
                }
                let _gate = mutation_gate.lock();
                if shutdown.load(Ordering::Acquire) {
                    return;
                }
                let mut policy_generation_guard =
                    runtime_policy_generation.as_ref().map(RuntimePolicyGeneration::write_guard);
                index = (index + 1) % profiles.len();
                let profile = &profiles[index];
                let mut guard = match stealth_config.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => {
                        log::warn!(
                            "stealth profile configuration mutex poisoned in generation {}; recovering",
                            generation
                        );
                        poisoned.into_inner()
                    }
                };
                if shutdown.load(Ordering::Acquire) {
                    return;
                }
                guard.initial_browser = profile.browser;
                guard.initial_os = profile.os;
                crate::telemetry!(crate::telemetry::STEALTH_BROWSER_PROFILE
                    .set(guard.initial_browser as i64));
                crate::telemetry!(crate::telemetry::STEALTH_OS_PROFILE.set(guard.initial_os as i64));
                log::debug!(
                    "stealth runtime generation {} rotated next-session profile to {:?}/{:?}",
                    generation,
                    profile.browser,
                    profile.os
                );
                if let Some(ref mut policy_generation_guard) = policy_generation_guard {
                    RuntimePolicyGeneration::advance(policy_generation_guard);
                }
            }
        })
    }

    fn ensure_cleanup_worker(&self) -> Result<(), String> {
        if self.cleanup_worker_started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let mut cancel = self.cancel_tx.subscribe();
        let proxies = self.reality_proxies.clone();
        let result = self.spawn_owned("reality-session-cleanup", async move {
            let mut interval = tokio::time::interval(REALITY_SESSION_CLEANUP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    changed = cancel.changed() => {
                        if changed.is_err() || *cancel.borrow() {
                            return;
                        }
                    }
                    _ = interval.tick() => {
                        let mut registered = proxies.lock();
                        registered.retain(|weak| {
                            let Some(proxy) = weak.upgrade() else {
                                return false;
                            };
                            proxy.cleanup_stale_sessions_now();
                            true
                        });
                    }
                }
            }
        });
        if result.is_err() {
            self.cleanup_worker_started.store(false, Ordering::Release);
        }
        result
    }

    pub fn worker_count(&self) -> usize {
        self.active_workers.load(Ordering::Acquire)
    }

    pub fn request_shutdown(&self) {
        let _gate = self.mutation_gate.lock();
        if !self.shutdown.swap(true, Ordering::AcqRel) {
            self.cancel_tx.send_replace(true);
        }
    }

    /// Signal and join every worker in this generation.
    pub async fn shutdown(&self, timeout: Duration) -> Result<StealthShutdownReport, String> {
        self.request_shutdown();
        let workers = {
            let mut state = self.worker_state.lock();
            std::mem::take(&mut state.workers)
        };
        let mut joined = 0usize;
        let mut force_stopped = 0usize;
        let mut errors = Vec::new();
        // Worker joins are Tokio runtime deadlines, independent of the
        // manually controlled protocol clock used by product state.
        let deadline = tokio::time::Instant::now() + timeout;
        for worker in workers {
            let mut handle = worker.handle;
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                handle.abort();
                let _ = handle.await;
                force_stopped += 1;
                continue;
            }
            match tokio::time::timeout(remaining, &mut handle).await {
                Ok(Ok(())) => joined += 1,
                Ok(Err(error)) => errors.push(format!("{} join failed: {}", worker.name, error)),
                Err(_) => {
                    handle.abort();
                    let _ = handle.await;
                    force_stopped += 1;
                }
            }
        }
        self.active_workers.store(0, Ordering::Release);
        *self.next_session_stealth_config.lock() = None;
        let mut proxies = self.reality_proxies.lock();
        proxies.retain(|weak| {
            let Some(proxy) = weak.upgrade() else {
                return false;
            };
            proxy.shutdown_sessions();
            false
        });
        let report = StealthShutdownReport {
            generation: self.generation,
            workers_joined: joined,
            workers_force_stopped: force_stopped,
        };
        if errors.is_empty() {
            Ok(report)
        } else {
            Err(format!("generation {}: {}", self.generation, errors.join("; ")))
        }
    }
}

impl Drop for StealthRuntimeOwner {
    fn drop(&mut self) {
        self.request_shutdown();
        let mut state = self.worker_state.lock();
        if !state.workers.is_empty() {
            log::warn!(
                "stealth runtime generation {} dropped without async worker join; force-stopping {} workers",
                self.generation,
                state.workers.len()
            );
            for worker in state.workers.drain(..) {
                worker.handle.abort();
            }
        }
    }
}

async fn wait_for_delay_or_cancel(cancel: &mut watch::Receiver<bool>, delay: Duration) -> bool {
    tokio::select! {
        changed = cancel.changed() => changed.is_ok() && !*cancel.borrow(),
        _ = tokio::time::sleep(delay) => !*cancel.borrow(),
    }
}

#[cfg(test)]
mod runtime_owner_tests {
    use super::*;

    #[test]
    fn runtime_generations_are_unique() {
        let first = StealthRuntimeOwner::new(RealityConfig::default()).unwrap();
        let second = StealthRuntimeOwner::new(RealityConfig::default()).unwrap();
        assert!(second.generation() > first.generation());
    }

    #[test]
    fn one_owner_exposes_one_shared_cover_cache() {
        let owner = StealthRuntimeOwner::new(RealityConfig {
            enabled: true,
            ..RealityConfig::default()
        })
        .unwrap();
        let first = owner.cover_cache().unwrap();
        let second = owner.cover_cache().unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn start_without_runtime_returns_error_without_spawning() {
        let owner = Arc::new(
            StealthRuntimeOwner::new(RealityConfig {
                enabled: true,
                ..RealityConfig::default()
            })
            .expect("valid reality configuration"),
        );

        let error = owner.start(None, Vec::new(), 0).expect_err("runtime is required");

        assert!(error.contains("active Tokio runtime"));
        assert_eq!(owner.worker_count(), 0);
    }

    #[tokio::test]
    async fn profile_rotation_is_cancelled_and_joined() {
        let owner = Arc::new(StealthRuntimeOwner::new(RealityConfig::default()).unwrap());
        let config = Arc::new(std::sync::Mutex::new(StealthConfig::default()));
        let profiles = vec![
            FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows),
            FingerprintProfile::new(BrowserProfile::Firefox, OsProfile::Linux),
        ];
        owner.start(Some(config.clone()), profiles, 1).unwrap();
        assert_eq!(owner.worker_count(), 1);
        let before = config.lock().unwrap().initial_browser;
        let report = owner.shutdown(STEALTH_RUNTIME_SHUTDOWN_TIMEOUT).await.unwrap();
        assert_eq!(report.workers_joined, 1);
        assert_eq!(owner.worker_count(), 0);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(config.lock().unwrap().initial_browser, before);
    }

    #[tokio::test]
    async fn reality_refresh_is_bounded_and_cancellable() {
        let owner = Arc::new(
            StealthRuntimeOwner::new(RealityConfig {
                enabled: true,
                cover_host: "192.0.2.1".to_string(),
                cache_ttl: 1,
                ..RealityConfig::default()
            })
            .unwrap(),
        );
        owner.start(None, Vec::new(), 0).unwrap();
        tokio::task::yield_now().await;
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            owner.shutdown(STEALTH_RUNTIME_SHUTDOWN_TIMEOUT),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result.workers_joined, 1);
        assert_eq!(owner.worker_count(), 0);
    }
}
