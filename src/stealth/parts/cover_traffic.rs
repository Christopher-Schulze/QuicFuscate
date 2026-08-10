// --- 8. Cover Traffic Scheduler

/// Generates realistic browser traffic patterns
struct CoverTrafficScheduler {
    /// Monotonic clock owned by the connection's stealth manager.
    clock: crate::time_source::ProtocolClock,
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
    #[allow(dead_code)]
    pub fn new(target_domain: String, interval_ms: u64) -> Self {
        Self::new_with_clock(
            target_domain,
            interval_ms,
            &crate::time_source::ProtocolClock::default(),
        )
    }

    pub(crate) fn new_with_clock(
        target_domain: String,
        interval_ms: u64,
        clock: &crate::time_source::ProtocolClock,
    ) -> Self {
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

    /// Generate next cover request if due
    pub fn get_next_request(&self) -> Option<Vec<qf_transport_types::h3::Header>> {
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

        Some(self.build_request_headers(selected_type))
    }

    fn build_request_headers(
        &self,
        req_type: &CoverRequestType,
    ) -> Vec<qf_transport_types::h3::Header> {
        use qf_transport_types::h3::Header;
        use rand::Rng;

        let method: &[u8] = match req_type {
            CoverRequestType::HeadResource => b"HEAD",
            _ => b"GET",
        };

        let path: &[u8] = match req_type {
            CoverRequestType::GetIndex => b"/",
            CoverRequestType::GetFavicon => b"/favicon.ico",
            CoverRequestType::GetRobots => b"/robots.txt",
            CoverRequestType::GetManifest => b"/manifest.json",
            CoverRequestType::GetStyle => {
                let styles: [&[u8]; 3] =
                    [b"/css/main.css", b"/css/style.css", b"/assets/styles.css"];
                styles[rand::rng().random_range(0..styles.len())]
            }
            CoverRequestType::GetScript => {
                let scripts: [&[u8]; 3] = [b"/js/app.js", b"/js/main.js", b"/assets/bundle.js"];
                scripts[rand::rng().random_range(0..scripts.len())]
            }
            CoverRequestType::HeadResource => b"/api/health",
        };

        let mut headers = vec![
            Header::new(b":method", method),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", self.target_domain.as_bytes()),
            Header::new(b":path", path),
        ];

        // Add realistic browser headers
        headers.push(Header::new(
            b"accept",
            match req_type {
                CoverRequestType::GetStyle => b"text/css,*/*;q=0.1",
                CoverRequestType::GetScript => b"*/*",
                CoverRequestType::GetFavicon => b"image/webp,image/apng,image/*,*/*;q=0.8",
                _ => b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        ));

        headers.push(Header::new(b"accept-encoding", b"gzip, deflate, br"));
        headers.push(Header::new(b"accept-language", b"en-US,en;q=0.9"));

        // Add cache headers with some variation
        if rand::rng().random_bool(0.7) {
            headers.push(Header::new(b"cache-control", b"no-cache"));
        }

        headers
    }

    /// Updates the request interval in milliseconds (thread-safe)
    pub fn set_interval_ms(&self, ms: u64) {
        self.interval_ms.store(ms, Ordering::Relaxed);
    }
}
