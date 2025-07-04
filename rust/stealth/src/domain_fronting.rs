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

    /// Replace the Host/`:authority` header with the fronting domain.
    pub fn apply_domain_fronting(&self, headers: &str) -> String {
        if !self.enabled {
            return headers.to_string();
        }

        headers
            .lines()
            .map(|l| {
                let lower = l.to_ascii_lowercase();
                if lower.starts_with("host:") {
                    format!("Host: {}", self.config.front_domain)
                } else if lower.starts_with(":authority") {
                    format!(":authority {}", self.config.front_domain)
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\r\n")
    }
}
