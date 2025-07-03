use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone)]
pub struct DohConfig {
    pub enable_caching: bool,
    pub cache_ttl_secs: u64,
}

impl Default for DohConfig {
    fn default() -> Self {
        Self { enable_caching: true, cache_ttl_secs: 300 }
    }
}

pub struct DohClient {
    config: DohConfig,
    cache: HashMap<String, (IpAddr, std::time::Instant)>,
    enabled: bool,
}

impl DohClient {
    pub fn new(config: DohConfig) -> Self {
        Self { config, cache: HashMap::new(), enabled: false }
    }

    pub fn enable(&mut self, enable: bool) { self.enabled = enable; }

    pub fn cache_size(&self) -> usize { self.cache.len() }

    pub fn set_cache_ttl(&mut self, ttl: u64) { self.config.cache_ttl_secs = ttl; }

    /// Simplified asynchronous resolver that returns a fixed IP address.
    pub async fn resolve(&mut self, domain: &str) -> IpAddr {
        if !self.enabled {
            return IpAddr::V4(Ipv4Addr::new(127,0,0,1));
        }
        if self.config.enable_caching {
            if let Some((ip, t)) = self.cache.get(domain) {
                if t.elapsed().as_secs() < self.config.cache_ttl_secs {
                    return *ip;
                }
            }
        }
        let ip = if domain == "example.com" {
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        } else {
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
        };
        if self.config.enable_caching {
            self.cache.insert(domain.to_string(), (ip, std::time::Instant::now()));
        }
        ip
    }

    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}
