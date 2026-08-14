use super::*;

/// Orchestrator for cross-module runtime steering (feature-gated by `orchestrator`).
///
/// This type is intentionally lightweight and only exposes stable control signals
/// consumed from core runtime loops.
pub struct DeepIntegrationOrchestrator {
    _cfg: StealthBrainConfig,
    server_push_enabled: AtomicBool,
    server_push_last_trigger: Mutex<Instant>,
    stealth_active: AtomicBool,
    loss_rate: AtomicU32,         // 0..1000 => 0.0%..100.0% in 0.1% units
    cpu_usage_percent: AtomicU32, // 0..100
    memory_pressure: AtomicU32,   // 0..100
    bandwidth_bps: AtomicU64,     // outbound delivery estimate
}

impl DeepIntegrationOrchestrator {
    /// Creates a new orchestrator with the given brain config and pool hints.
    pub fn new(config: StealthBrainConfig, _pool_capacity: usize, _block_size: usize) -> Arc<Self> {
        Arc::new(Self {
            _cfg: config,
            server_push_enabled: AtomicBool::new(false),
            server_push_last_trigger: Mutex::new(crate::time_source::now_instant()),
            stealth_active: AtomicBool::new(false),
            loss_rate: AtomicU32::new(0),
            cpu_usage_percent: AtomicU32::new(0),
            memory_pressure: AtomicU32::new(0),
            bandwidth_bps: AtomicU64::new(0),
        })
    }

    /// Enables or disables server push cover traffic coordination.
    pub fn enable_server_push(&self, enabled: bool) {
        self.server_push_enabled.store(enabled, Ordering::Relaxed);
        if enabled {
            info!("Orchestrator: Server Push coordination enabled");
        }
    }

    /// Returns whether server push coordination is currently enabled.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn server_push_enabled(&self) -> bool {
        self.server_push_enabled.load(Ordering::Relaxed)
    }

    /// Updates runtime telemetry signals used by server push trigger heuristics.
    pub fn update_runtime_signals(
        &self,
        loss_rate_permille: u32,
        cpu_usage_percent: u32,
        memory_pressure: u32,
        bandwidth_bps: u64,
        stealth_active: bool,
    ) {
        self.loss_rate.store(loss_rate_permille.min(1000), Ordering::Relaxed);
        self.cpu_usage_percent.store(cpu_usage_percent.min(100), Ordering::Relaxed);
        self.memory_pressure.store(memory_pressure.min(100), Ordering::Relaxed);
        self.bandwidth_bps.store(bandwidth_bps, Ordering::Relaxed);
        self.stealth_active.store(stealth_active, Ordering::Relaxed);
    }

    /// Returns whether server push cover traffic should fire based on current signals.
    pub fn should_trigger_server_push(&self) -> bool {
        should_trigger_server_push_internal(
            self.server_push_enabled.load(Ordering::Relaxed),
            self.loss_rate.load(Ordering::Relaxed),
            self.stealth_active.load(Ordering::Relaxed),
            self.cpu_usage_percent.load(Ordering::Relaxed),
            self.memory_pressure.load(Ordering::Relaxed),
            self.bandwidth_bps.load(Ordering::Relaxed),
            &self.server_push_last_trigger,
        )
    }

    /// Returns recommended server push intensity (0.0 - 1.0) based on loss and bandwidth.
    pub fn get_server_push_intensity(&self) -> f32 {
        server_push_intensity_internal(
            self.loss_rate.load(Ordering::Relaxed),
            self.bandwidth_bps.load(Ordering::Relaxed),
        )
    }
}
