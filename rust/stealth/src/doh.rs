use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone)]
pub struct DohConfig {
    pub enable_caching: bool,
}

impl Default for DohConfig {
    fn default() -> Self {
        Self { enable_caching: true }
    }
}

pub struct DohClient {
    config: DohConfig,
    cache: HashMap<String, IpAddr>,
    enabled: bool,
}

impl DohClient {
    pub fn new(config: DohConfig) -> Self {
        Self { config, cache: HashMap::new(), enabled: false }
    }

    pub fn enable(&mut self, enable: bool) { self.enabled = enable; }

    /// Simplified asynchronous resolver that returns a fixed IP address.
    pub async fn resolve(&mut self, domain: &str) -> IpAddr {
        if !self.enabled {
            return IpAddr::V4(Ipv4Addr::new(127,0,0,1));
        }
        if self.config.enable_caching {
            if let Some(ip) = self.cache.get(domain) {
                return *ip;
            }
        }
        let ip = if domain == "example.com" {
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        } else {
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
        };
        if self.config.enable_caching {
            self.cache.insert(domain.to_string(), ip);
        }
        ip
    }
}
