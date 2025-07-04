pub struct ZeroRttConfig {
    pub max_early_data: usize,
    pub enabled: bool,
}

impl Default for ZeroRttConfig {
    fn default() -> Self {
        Self { max_early_data: 1024, enabled: false }
    }
}

pub struct ZeroRttEngine {
    cfg: ZeroRttConfig,
    pub attempts: usize,
    pub successes: usize,
}

impl Default for ZeroRttEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ZeroRttEngine {
    pub fn new() -> Self {
        Self { cfg: ZeroRttConfig::default(), attempts: 0, successes: 0 }
    }

    pub fn with_config(cfg: ZeroRttConfig) -> Self {
        Self { cfg, attempts: 0, successes: 0 }
    }

    pub fn set_enabled(&mut self, e: bool) { self.cfg.enabled = e; }
    pub fn set_max_early_data(&mut self, max: usize) { self.cfg.max_early_data = max; }

    pub async fn send_early_data(&mut self, data: &[u8]) -> Result<(), ()> {
        self.attempts += 1;

        // Mirror the checks performed by the C++ implementation. Early data
        // can only be sent when zero-RTT has been enabled and the payload size
        // stays within the configured limit.
        if !self.cfg.enabled || data.len() > self.cfg.max_early_data {
            return Err(());
        }

        // In the C++ version the data would be written to the network. Here we
        // simply simulate a small asynchronous delay so the call truly awaits.
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;

        self.successes += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn send_fails_without_enable() -> Result<(), Box<dyn std::error::Error>> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let mut eng = ZeroRttEngine::new();
            assert!(eng.send_early_data(b"x").await.is_err());
        });
        Ok(())
    }

    #[test]
    fn send_checks_size_and_enabled() -> Result<(), Box<dyn std::error::Error>> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let mut eng = ZeroRttEngine::new();
            eng.set_enabled(true);
            let max = eng.cfg.max_early_data;
            assert!(eng.send_early_data(&vec![0u8; max]).await.is_ok());
            assert!(eng.send_early_data(&vec![0u8; max + 1]).await.is_err());
        });
        Ok(())
    }
}
