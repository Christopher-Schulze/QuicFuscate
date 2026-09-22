//! Weighted HTTP/3 cover-request scheduling.

use qf_common::time_source::ProtocolClock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Generates realistic browser traffic patterns
pub struct CoverTrafficScheduler {
    /// Monotonic clock owned by the connection's stealth manager.
    clock: ProtocolClock,
    /// Target domain for cover traffic
    target_domain: String,
    /// Request interval (milliseconds)
    interval_ms: Arc<AtomicU64>,
    /// Last request time
    last_request: Arc<Mutex<std::time::Instant>>,
    /// Request types with weights
    request_patterns: Vec<(CoverRequestType, u32)>,
}

#[derive(Clone, Debug)]
enum CoverRequestType {
    GetIndex,
    GetFavicon,
    GetRobots,
    GetManifest,
    HeadResource,
    GetStyle,
    GetScript,
}

impl CoverTrafficScheduler {
    /// Creates a scheduler that emits weighted cover requests at the given interval.
    pub fn new(target_domain: String, interval_ms: u64) -> Self {
        Self::new_with_clock(target_domain, interval_ms, &ProtocolClock::default())
    }

    #[doc(hidden)]
    pub fn new_with_clock(target_domain: String, interval_ms: u64, clock: &ProtocolClock) -> Self {
        Self {
            clock: clock.clone(),
            target_domain,
            interval_ms: Arc::new(AtomicU64::new(interval_ms)),
            last_request: Arc::new(Mutex::new(clock.now())),
            request_patterns: vec![
                (CoverRequestType::GetIndex, 30),
                (CoverRequestType::GetFavicon, 20),
                (CoverRequestType::GetStyle, 15),
                (CoverRequestType::GetScript, 15),
                (CoverRequestType::GetManifest, 10),
                (CoverRequestType::GetRobots, 5),
                (CoverRequestType::HeadResource, 5),
            ],
        }
    }

    /// Return the next cover request target `(authority, path)` once its
    /// weighted interval has elapsed, or `None` while the interval is still
    /// running. The request headers themselves are built by the stealth
    /// manager from the persona fixture (TODO-1055: one header code path).
    pub fn next_cover_target(&self) -> Option<(String, String)> {
        if let Ok(mut last) = self.last_request.lock() {
            let elapsed = self.clock.elapsed_since(*last).as_millis() as u64;
            let interval = self.interval_ms.load(Ordering::Relaxed);
            if elapsed < interval {
                return None;
            }
            *last = self.clock.now();
        }

        // Select request type based on weights
        let total_weight: u32 = self.request_patterns.iter().map(|(_, w)| w).sum();
        let mut rng = rand::rng();
        use rand::Rng;
        let mut random_val = rng.random_range(0..total_weight);

        let mut selected_type = &CoverRequestType::GetIndex;
        for (req_type, weight) in &self.request_patterns {
            if random_val < *weight {
                selected_type = req_type;
                break;
            }
            random_val -= weight;
        }

        let path: &str = match selected_type {
            CoverRequestType::GetIndex => "/",
            CoverRequestType::GetFavicon => "/favicon.ico",
            CoverRequestType::GetRobots => "/robots.txt",
            CoverRequestType::GetManifest => "/manifest.json",
            CoverRequestType::GetStyle => {
                let styles: [&str; 3] = ["/css/main.css", "/css/style.css", "/assets/styles.css"];
                styles[rng.random_range(0..styles.len())]
            }
            CoverRequestType::GetScript => {
                let scripts: [&str; 3] = ["/js/app.js", "/js/main.js", "/assets/bundle.js"];
                scripts[rng.random_range(0..scripts.len())]
            }
            CoverRequestType::HeadResource => "/api/health",
        };

        Some((self.target_domain.clone(), path.to_string()))
    }

    /// Updates the request interval in milliseconds (thread-safe)
    pub fn set_interval_ms(&self, ms: u64) {
        self.interval_ms.store(ms, Ordering::Relaxed);
    }

    /// Return the active request interval.
    #[doc(hidden)]
    pub fn interval_ms(&self) -> u64 {
        self.interval_ms.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::CoverTrafficScheduler;

    #[test]
    fn new_scheduler_waits_for_its_first_interval() {
        let scheduler = CoverTrafficScheduler::new("cdn.example.com".to_owned(), 60_000);
        assert!(scheduler.next_cover_target().is_none());
    }

    #[test]
    fn interval_updates_are_immediately_observable() {
        let scheduler = CoverTrafficScheduler::new("cdn.example.com".to_owned(), 5_000);
        scheduler.set_interval_ms(1_000);
        assert_eq!(scheduler.interval_ms(), 1_000);
    }
}
