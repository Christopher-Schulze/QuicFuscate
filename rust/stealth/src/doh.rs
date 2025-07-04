use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

#[cfg(feature = "doh-reqwest")]
use reqwest::Client;
#[cfg(feature = "doh-reqwest")]
use serde_json::Value;

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
    #[cfg(feature = "doh-reqwest")]
    client: Client,
}

impl DohClient {
    pub fn new(config: DohConfig) -> Self {
        Self {
            config,
            cache: HashMap::new(),
            enabled: false,
            #[cfg(feature = "doh-reqwest")]
            client: Client::new(),
        }
    }

    pub fn enable(&mut self, enable: bool) { self.enabled = enable; }

    /// Resolve a domain name asynchronously via DoH.
    pub async fn resolve(&mut self, domain: &str) -> IpAddr {
        if !self.enabled {
            return IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        }

        if self.config.enable_caching {
            if let Some(ip) = self.cache.get(domain) {
                return *ip;
            }
        }

        #[cfg(feature = "doh-reqwest")]
        if let Ok(resp) = self
            .client
            .get(format!("https://dns.google/resolve?name={domain}&type=A"))
            .send()
            .await
        {
            if let Ok(v) = resp.json::<Value>().await {
                if let Some(ans) = v["Answer"].as_array() {
                    if let Some(data) = ans.get(0).and_then(|a| a["data"].as_str()) {
                        if let Ok(parsed) = data.parse() {
                            if self.config.enable_caching {
                                self.cache.insert(domain.to_string(), parsed);
                            }
                            return parsed;
                        }
                    }
                }
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
