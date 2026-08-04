/// Singleton manager for runtime optimizations.
#[derive(Clone)]
pub struct OptimizationManager {
    memory_pool: Arc<MemoryPool>,
}

impl OptimizationManager {
    /// Creates a new optimization manager with the adaptive packet-pool default.
    pub fn new() -> Self {
        Self { memory_pool: Arc::new(MemoryPool::new_adaptive(1024, 4096)) }
    }

    /// Creates a new optimization manager with explicit pool capacity and block size.
    pub fn new_with_config(capacity: usize, block_size: usize) -> Self {
        Self { memory_pool: Arc::new(MemoryPool::new(capacity, block_size)) }
    }

    /// Creates a new optimization manager from an `OptimizeConfig`.
    pub fn from_cfg(cfg: OptimizeConfig) -> Self {
        Self::new_with_config(cfg.pool_capacity, cfg.block_size)
    }

    /// Allocates a 64-byte aligned block from the internal memory pool.
    pub fn alloc_block(&self) -> AlignedBox<[u8]> {
        self.memory_pool.alloc()
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
