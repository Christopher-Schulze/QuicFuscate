pub const DEFAULT_MIN_MTU: u16 = 1200;
pub const DEFAULT_MAX_MTU: u16 = 1500;

pub struct IoContext;

pub struct QuicConfig;

pub struct QuicConnection<'a> {
    _ctx: &'a IoContext,
    _config: QuicConfig,
}

impl<'a> QuicConnection<'a> {
    pub fn new(ctx: &'a IoContext, config: QuicConfig) -> Self {
        Self {
            _ctx: ctx,
            _config: config,
        }
    }
}

pub struct PathMtuManager;

impl PathMtuManager {
    pub fn new() -> Self {
        Self
    }
    pub fn send_probe(&self) {}
    pub fn handle_probe_response(&self) {}
}

pub struct StreamOptimizationConfig;

pub struct QuicStreamOptimizer;

impl QuicStreamOptimizer {
    pub fn new() -> Self {
        Self
    }
    pub fn initialize(&mut self, _cfg: StreamOptimizationConfig) -> bool {
        true
    }
    pub fn set_stream_priority(&mut self, _stream_id: u64, _priority: u8) -> bool {
        true
    }
    pub fn update_flow_control_window(&mut self, _stream_id: u64, _size: u32) -> bool {
        true
    }
    pub fn can_send_data(&self, _stream_id: u64, _size: u32) -> bool {
        true
    }
    pub fn get_optimal_chunk_size(&self, _stream_id: u64) -> u32 {
        1
    }
}
