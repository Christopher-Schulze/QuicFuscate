// --- 4. Domain Fronting ---

/// Supported CDN providers for domain fronting with advanced rotation strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CdnProvider {
    Cloudflare,
    Fastly,
    Akamai,
    CloudFront,
    GoogleCloud,
    AzureCDN,
    StackPath,
    KeyCDN,
    BunnyCDN,
    Imperva,
}

impl CdnProvider {
    /// Returns multiple domains for this CDN provider for sophisticated rotation.
    fn get_domains(&self) -> Vec<&'static str> {
        match self {
            Self::Cloudflare => vec![
                "cdn.cloudflare.com",
                "cloudflare-dns.com",
                "one.one.one.one",
                "warp.plus",
                "workers.dev",
            ],
            Self::Fastly => vec!["cdn.fastly.net", "fastly.com", "fastlylb.net", "fsly.net"],
            Self::Akamai => vec![
                "akamaized.net",
                "akamai.net",
                "akamaihd.net",
                "akamaitechnologies.com",
                "edgesuite.net",
            ],
            Self::CloudFront => {
                vec!["cloudfront.net", "amazonaws.com", "aws.amazon.com", "awsstatic.com"]
            }
            Self::GoogleCloud => vec![
                "googleapis.com",
                "googleusercontent.com",
                "googlevideo.com",
                "gstatic.com",
                "google.com",
            ],
            Self::AzureCDN => {
                vec!["azureedge.net", "azure.microsoft.com", "windows.net", "msecnd.net"]
            }
            Self::StackPath => vec!["stackpathdns.com", "stackpathcdn.com", "bootstrapcdn.com"],
            Self::KeyCDN => vec!["kxcdn.com", "keycdn.com"],
            Self::BunnyCDN => vec!["b-cdn.net", "bunnycdn.com"],
            Self::Imperva => vec!["incapdns.net", "imperva.com"],
        }
    }
}

/// Manages domain fronting by rotating through configured domains.
///
/// Provides both round-robin and random selection strategies. Rotation is
/// thread-safe via an `AtomicUsize` index. Callers must ensure that the
/// domain list is non-empty before requesting a domain.
///
/// - Integration: used when `StealthConfig::enable_domain_fronting` is true.
///   Domains may come from `StealthConfig.fronting_domains` or be derived
///   from built-in [`CdnProvider`]s (via [`DomainFrontingManager::from_providers`]).
/// - Concurrency: selection (`&self`) is lock-free using atomics; mutation is
///   via [`DomainFrontingManager::set_domains`] which requires `&mut self`.
/// - Panics: requesting a round-robin domain with an empty list will panic.
pub(crate) struct DomainFrontingManager {
    domains: Arc<[String]>,
    index: AtomicUsize,
}

impl DomainFrontingManager {
    /// Creates a new manager from a list of domains.
    #[inline]
    pub fn new(domains: Vec<String>) -> Self {
        Self { domains: Arc::from(domains), index: AtomicUsize::new(0) }
    }

    /// Creates a manager from built-in CDN providers with all their domains.
    #[inline]
    pub fn from_providers(providers: Vec<CdnProvider>) -> Self {
        let domains = providers
            .into_iter()
            .flat_map(|p| p.get_domains().into_iter().map(|d| d.to_string()))
            .collect();
        Self::new(domains)
    }

    /// Creates an ultra-sophisticated manager with all major CDN providers.
    #[inline]
    pub fn ultra_stealth() -> Self {
        use CdnProvider::*;
        Self::from_providers(vec![
            Cloudflare,
            Fastly,
            Akamai,
            CloudFront,
            GoogleCloud,
            AzureCDN,
            StackPath,
            KeyCDN,
            BunnyCDN,
            Imperva,
        ])
    }

    /// Selects the next domain using sophisticated time-based rotation with jitter.
    /// This prevents predictable patterns that could be detected by DPI.
    ///
    /// Uses a monotonically increasing atomic counter to choose the next index.
    /// The internal list must be non-empty.
    ///
    /// Panics
    /// -----
    /// Panics if `self.domains` is empty (modulo by zero).
    ///
    /// Examples
    /// --------
    ///
    /// ```text
    /// // Constructed elsewhere via explicit domains or from providers.
    /// // let mut df = DomainFrontingManager::new(vec!["a.example".into(), "b.example".into()]);
    /// // assert!(matches!(df.get_fronted_domain().as_str(), "a.example" | "b.example"));
    /// ```
    #[inline]
    pub fn get_fronted_domain(&self) -> String {
        use rand::Rng;
        let mut rng = rand::rng();

        // Add time-based jitter to prevent predictable patterns
        let jitter = rng.random_range(0..3);
        let current = self.index.fetch_add(1 + jitter, Ordering::Relaxed);
        let idx = current % self.domains.len();
        self.domains[idx].clone()
    }

    /// Randomly chooses a domain. Useful when deterministic rotation is undesired.
    ///
    /// Falls back to "cdn.cloudflare.com" if the list is empty.
    /// This does not implicitly enable domain fronting; callers should check
    /// `StealthConfig.enable_domain_fronting` before using the value.
    ///
    /// Examples
    /// --------
    /// ```text
    /// // let df = DomainFrontingManager::new(vec!["a".into(), "b".into()]);
    /// // let d = df.random_domain();
    /// // assert!(!d.is_empty());
    /// ```
    ///
    /// Notes
    /// -----
    /// This method is thread-safe and suitable for concurrent access.
    #[inline]
    #[allow(dead_code)] // retained for explicit/randomized fronting experiments and rust-tests
    pub fn random_domain(&self) -> String {
        use rand::seq::IndexedRandom;
        let mut rng = rand::rng();
        self.domains
            .as_ref()
            .choose(&mut rng)
            .cloned()
            .unwrap_or_else(|| "cdn.cloudflare.com".to_string())
    }
}
