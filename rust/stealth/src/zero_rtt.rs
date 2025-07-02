pub struct ZeroRttEngine {
    enabled: bool,
    pub attempts: usize,
    pub successes: usize,
}

const MAX_EARLY_DATA_SIZE: usize = 1024;

impl ZeroRttEngine {
    pub fn new() -> Self { Self { enabled: false, attempts: 0, successes: 0 } }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub async fn send_early_data(&mut self, data: &[u8]) -> Result<(), ()> {
        self.attempts += 1;

        if !self.enabled || data.len() > MAX_EARLY_DATA_SIZE {
            return Err(());
        }

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
            eng.enable();
            assert!(eng.send_early_data(&vec![0u8; MAX_EARLY_DATA_SIZE]).await.is_ok());
            assert!(eng.send_early_data(&vec![0u8; MAX_EARLY_DATA_SIZE + 1]).await.is_err());
        });
        Ok(())
    }
}
