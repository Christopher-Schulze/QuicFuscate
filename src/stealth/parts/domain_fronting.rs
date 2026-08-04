// --- 4. Domain Fronting ---

const DEFAULT_FRONTING_DOMAIN: &str = "cdn.cloudflare.com";

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
/// `get_fronted_domain` provides strict round-robin selection. `random_domain`
/// is a separate explicit random-selection path. Rotation is thread-safe via
/// an `AtomicUsize` index; serial calls have a deterministic sequence, while
/// concurrent completion order follows thread scheduling.
///
/// - Integration: used when `StealthConfig::enable_domain_fronting` is true.
///   Domains may come from `StealthConfig.fronting_domains` or be derived
///   from built-in [`CdnProvider`]s (via [`DomainFrontingManager::from_providers`]).
/// - Concurrency: selection (`&self`) is lock-free using atomics. Concurrent
///   calls reserve unique sequence slots, but their completion order is not
///   deterministic.
/// - Empty input: both selection methods return `cdn.cloudflare.com`.
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

    /// Selects the next domain using strict round-robin rotation.
    ///
    /// Serial calls are deterministic. Concurrent calls reserve unique slots,
    /// but the order in which callers observe their results is scheduling-
    /// dependent. An empty manager returns `cdn.cloudflare.com`.
    ///
    /// Examples
    /// --------
    ///
    /// ```text
    /// // Constructed elsewhere via explicit domains or from providers.
    /// // let df = DomainFrontingManager::new(vec!["a.example".into(), "b.example".into()]);
    /// // assert_eq!(df.get_fronted_domain(), "a.example");
    /// // assert_eq!(df.get_fronted_domain(), "b.example");
    /// ```
    #[inline]
    pub fn get_fronted_domain(&self) -> String {
        if self.domains.is_empty() {
            return DEFAULT_FRONTING_DOMAIN.to_string();
        }
        let current = self.index.fetch_add(1, Ordering::Relaxed);
        let idx = current % self.domains.len();
        self.domains[idx].clone()
    }

    /// Randomly chooses a domain. Useful when deterministic rotation is undesired.
    ///
    /// Falls back to `cdn.cloudflare.com` if the list is empty.
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
            .unwrap_or_else(|| DEFAULT_FRONTING_DOMAIN.to_string())
    }
}
