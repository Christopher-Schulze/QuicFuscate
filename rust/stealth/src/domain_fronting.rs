pub struct SniConfig {
    pub front_domain: String,
    pub real_domain: String,
}

impl Default for SniConfig {
    fn default() -> Self {
        Self {
            front_domain: "front.example.com".into(),
            real_domain: "real.example.com".into(),
        }
    }
}

pub struct SniHiding {
    config: SniConfig,
    enabled: bool,
}

impl SniHiding {
    pub fn new(config: SniConfig) -> Self { Self { config, enabled: false } }

    pub fn enable(&mut self, enable: bool) { self.enabled = enable; }

    /// Replace the Host header with the fronting domain.
    pub fn apply_domain_fronting(&self, headers: &str) -> String {
        if !self.enabled {
            headers.to_string()
        } else {
            headers.replace(
                &format!("Host: {}", self.config.real_domain),
                &format!("Host: {}", self.config.front_domain),
            )
        }
    }
}
