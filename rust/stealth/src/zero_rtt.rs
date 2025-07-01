pub struct ZeroRttEngine {
    enabled: bool,
    pub attempts: usize,
    pub successes: usize,
}

impl ZeroRttEngine {
    pub fn new() -> Self { Self { enabled: false, attempts: 0, successes: 0 } }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub async fn send_early_data(&mut self, _data: &[u8]) -> Result<(), ()> {
        self.attempts += 1;
        if self.enabled {
            self.successes += 1;
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn send_fails_without_enable() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut eng = ZeroRttEngine::new();
            assert!(eng.send_early_data(b"x").await.is_err());
        });
    }
}
