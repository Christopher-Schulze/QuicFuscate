/// Singleton manager for runtime optimizations.
#[derive(Clone)]
pub struct OptimizationManager {
    memory_pool: Arc<MemoryPool>,
}

impl OptimizationManager {
    /// Creates a new optimization manager with the adaptive packet-pool default.
    ///
    /// This compatibility constructor is intentionally infallible. Use
    /// [`OptimizationManager::try_new`] when allocation failure must be handled.
    #[allow(clippy::panic)]
    pub fn new() -> Self {
        Self::try_new().unwrap_or_else(|error| panic!("OptimizationManager::new failed: {error}"))
    }

    /// Fallible counterpart to [`OptimizationManager::new`].
    pub fn try_new() -> Result<Self, MemoryPoolError> {
        Ok(Self { memory_pool: Arc::new(MemoryPool::try_new_adaptive(1024, 4096)?) })
    }

    /// Creates a new optimization manager with explicit pool capacity and block size.
    ///
    /// This compatibility constructor is intentionally infallible. Use
    /// [`OptimizationManager::try_new_with_config`] when invalid configuration
    /// or allocation failure must be handled.
    #[allow(clippy::panic)]
    pub fn new_with_config(capacity: usize, block_size: usize) -> Self {
        Self::try_new_with_config(capacity, block_size)
            .unwrap_or_else(|error| panic!("OptimizationManager::new_with_config failed: {error}"))
    }

    /// Fallible counterpart to [`OptimizationManager::new_with_config`].
    pub fn try_new_with_config(
        capacity: usize,
        block_size: usize,
    ) -> Result<Self, MemoryPoolError> {
        Ok(Self { memory_pool: Arc::new(MemoryPool::try_new(capacity, block_size)?) })
    }

    /// Creates a new optimization manager from an `OptimizeConfig`.
    pub fn from_cfg(cfg: OptimizeConfig) -> Self {
        Self::new_with_config(cfg.pool_capacity, cfg.block_size)
    }

    /// Fallible counterpart to [`OptimizationManager::from_cfg`].
    pub fn try_from_cfg(cfg: OptimizeConfig) -> Result<Self, MemoryPoolError> {
        Self::try_new_with_config(cfg.pool_capacity, cfg.block_size)
    }

    /// Allocates a 64-byte aligned block from the internal memory pool.
    pub fn alloc_block(&self) -> AlignedBox<[u8]> {
        self.memory_pool.alloc()
    }

    /// Fallible counterpart to [`OptimizationManager::alloc_block`].
    pub fn try_alloc_block(&self) -> Result<AlignedBox<[u8]>, MemoryPoolError> {
        self.memory_pool.try_alloc()
    }

    /// Returns an allocated block to the internal memory pool.
    pub fn free_block(&self, block: AlignedBox<[u8]>) {
        self.memory_pool.free(block);
    }

    /// Returns a shared reference to the underlying memory pool.
    pub fn memory_pool(&self) -> Arc<MemoryPool> {
        Arc::clone(&self.memory_pool)
    }
}

impl Default for OptimizationManager {
    fn default() -> Self {
        Self::new()
    }
}
