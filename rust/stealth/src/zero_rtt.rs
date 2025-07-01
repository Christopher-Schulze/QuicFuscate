pub struct ZeroRttEngine {
    enabled: bool,
}

impl ZeroRttEngine {
    pub fn new() -> Self { Self { enabled: false } }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub async fn send_early_data(&self, data: &[u8]) -> Result<(), ()> {
        if self.enabled {
            // placeholder: pretend to send data asynchronously
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
            let eng = ZeroRttEngine::new();
            assert!(eng.send_early_data(b"x").await.is_err());
        });
    }
}
