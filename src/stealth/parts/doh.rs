// --- Global Tokio Runtime for async DoH requests ---
// Returns None when the runtime cannot be created (e.g. resource exhaustion).
// Callers skip async DoH/MASQUE work gracefully when the runtime is unavailable.
#[allow(dead_code)] // retained for explicit DoH/MASQUE compatibility paths outside the default lib build
static DOH_RUNTIME: LazyLock<Option<Runtime>> = LazyLock::new(|| {
    let threads = 2.min(std::thread::available_parallelism().map_or(1, |n| n.get()));
    match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .thread_name("quicfuscate-doh")
        .enable_all()
        .build()
    {
        Ok(rt) => Some(rt),
        Err(e) => {
            error!("Failed to build DoH Tokio runtime: {}. DoH and MASQUE features disabled.", e);
            None
        }
    }
});

// --- 1. DNS over HTTPS (DoH) ---

/// Built-in DoH provider endpoints for multi-provider resolution with fallback.
pub const DOH_PROVIDERS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query", // Cloudflare - fastest, privacy-focused
    "https://dns.quad9.net:5053/dns-query", // Quad9 - security-focused, blocks malware
    "https://dns.google/resolve",           // Google - reliable, high availability
    "https://dns.nextdns.io/dns-query",     // NextDNS - privacy-focused, customizable
];

/// Atomic index for round-robin DoH provider rotation.
static DOH_PROVIDER_INDEX: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Asynchronously resolves a domain name using DNS-over-HTTPS with multi-provider fallback.
///
/// Tries providers in round-robin order, falling back to next provider on failure.
/// Rotation ensures load distribution and resilience against single provider outages.
///
/// # Arguments
/// * `domain` - The domain to resolve.
/// * `preferred_provider` - Optional preferred provider URL. If empty, uses built-in rotation.
///
/// # Returns
/// A `Result` containing the resolved `IpAddr` or an error if all providers fail.
pub async fn resolve_doh_multi(
    client: &Client,
    domain: &str,
    preferred_provider: &str,
) -> Result<IpAddr, Box<dyn std::error::Error>> {
    // If user specified a provider, try it first
    let providers: Vec<&str> = if !preferred_provider.is_empty() {
        std::iter::once(preferred_provider).chain(DOH_PROVIDERS.iter().copied()).collect()
    } else {
        // Round-robin rotation through built-in providers
        let start_idx = DOH_PROVIDER_INDEX.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % DOH_PROVIDERS.len();
        DOH_PROVIDERS.iter().cycle().skip(start_idx).take(DOH_PROVIDERS.len()).copied().collect()
    };

    let mut last_error: Option<Box<dyn std::error::Error>> = None;

    for provider in providers {
        match resolve_doh_single(client, domain, provider).await {
            Ok(ip) => {
                log::debug!("DoH resolved {} via {} -> {}", domain, provider, ip);
                return Ok(ip);
            }
            Err(e) => {
                log::warn!("DoH provider {} failed for {}: {}", provider, domain, e);
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| "All DoH providers failed".into()))
}

/// Single-provider DoH resolution (internal helper).
async fn resolve_doh_single(
    client: &Client,
    domain: &str,
    doh_provider: &str,
) -> Result<IpAddr, Box<dyn std::error::Error>> {
    let mut url = Url::parse(doh_provider).inspect_err(|&e| {
        error!("Invalid DoH provider URL: {}", e);
    })?;
    url.query_pairs_mut().append_pair("name", domain).append_pair("type", "A");

    let resp = client
        .get(url)
        .header("Accept", "application/dns-json")
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    if let Some(answers) = resp.get("Answer") {
        if let Some(arr) = answers.as_array() {
            for answer in arr {
                if answer["type"] == 1 {
                    if let Some(ip_str) = answer["data"].as_str() {
                        if let Ok(ip) = ip_str.parse() {
                            return Ok(ip);
                        }
                    }
                }
            }
        }
    }
    Err("No A record returned".into())
}

/// Resolve a domain using a single DoH provider.
pub async fn resolve_doh(
    client: &Client,
    domain: &str,
    doh_provider: &str,
) -> Result<IpAddr, Box<dyn std::error::Error>> {
    resolve_doh_multi(client, domain, doh_provider).await
}
