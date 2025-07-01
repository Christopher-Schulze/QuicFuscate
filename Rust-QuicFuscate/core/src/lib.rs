use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("QUIC error: {0}")]
    Quic(String),
}

pub struct QuicConfig {
    pub server_name: String,
    pub port: u16,
}

pub struct QuicConnection {
    config: QuicConfig,
}

impl QuicConnection {
    pub fn new(config: QuicConfig) -> Result<Self, CoreError> {
        Ok(Self { config })
    }

    pub fn connect(&self, _addr: &str) -> Result<(), CoreError> {
        Ok(())
    }
}

pub struct PathMtuManager;

impl PathMtuManager {
    pub fn new() -> Self {
        Self
    }

    pub fn send_probe(&self, _size: u16, _incoming: bool) -> u32 {
        1
    }

    pub fn handle_probe_response(&self, _id: u32, _success: bool, _incoming: bool) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructible() {
        let cfg = QuicConfig { server_name: "localhost".into(), port: 443 };
        let conn = QuicConnection::new(cfg);
        assert!(conn.is_ok());
    }

    #[test]
    fn has_probe_methods() {
        let mgr = PathMtuManager::new();
        let id = mgr.send_probe(1200, false);
        mgr.handle_probe_response(id, true, false);
    }
}
