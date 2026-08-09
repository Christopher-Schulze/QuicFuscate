// --- 3. HTTP/3 Masquerading ---

const ACCEPT_ENCODING_VALUE: &[u8] = b"gzip, deflate, br";
const SEC_FETCH_DEST_VALUE: &[u8] = b"document";
const SEC_FETCH_MODE_VALUE: &[u8] = b"navigate";
const SEC_FETCH_USER_VALUE: &[u8] = b"?1";
const UPGRADE_INSECURE_REQUESTS_VALUE: &[u8] = b"1";
const CACHE_CONTROL_VALUE: &[u8] = b"max-age=0";
const MOBILE_TRUE_VALUE: &[u8] = b"?1";
const MOBILE_FALSE_VALUE: &[u8] = b"?0";

#[derive(Copy, Clone)]
struct HeaderTemplateEntry {
    name: &'static [u8],
    value: HeaderValueSpec,
}

#[derive(Copy, Clone)]
enum HeaderValueSpec {
    Dynamic(DynamicValueSpec),
}

#[derive(Copy, Clone)]
enum DynamicValueSpec {
    UserAgent,
    Accept,
    AcceptLanguage,
    AcceptEncoding,
    SecChUa,
    SecChUaMobile,
    SecChUaPlatform,
    SecFetchDest,
    SecFetchMode,
    SecFetchSite,
    SecFetchUser,
    UpgradeInsecureRequests,
    CacheControl,
    Cookie,
    Referer,
}

struct PersonaTemplate {
    entries: &'static [HeaderTemplateEntry],
}

struct HeaderDynamic<'a> {
    user_agent: &'a [u8],
    accept: &'a [u8],
    accept_language: &'a [u8],
    accept_encoding: &'a [u8],
    sec_ch_ua: Option<&'a [u8]>,
    sec_ch_ua_mobile: &'a [u8],
    sec_ch_ua_platform: &'a [u8],
    sec_fetch_dest: &'a [u8],
    sec_fetch_mode: &'a [u8],
    sec_fetch_site: &'a [u8],
    sec_fetch_user: &'a [u8],
    upgrade_insecure_requests: &'a [u8],
    cache_control: &'a [u8],
    cookie: Option<&'a [u8]>,
    referer: Option<&'a [u8]>,
}

impl HeaderValueSpec {
    fn resolve<'a>(&self, ctx: &'a HeaderDynamic<'a>) -> Option<&'a [u8]> {
        match self {
            HeaderValueSpec::Dynamic(kind) => kind.resolve(ctx),
        }
    }
}

impl DynamicValueSpec {
    fn resolve<'a>(&self, ctx: &'a HeaderDynamic<'a>) -> Option<&'a [u8]> {
        match self {
            DynamicValueSpec::UserAgent => Some(ctx.user_agent),
            DynamicValueSpec::Accept => Some(ctx.accept),
            DynamicValueSpec::AcceptLanguage => Some(ctx.accept_language),
            DynamicValueSpec::AcceptEncoding => Some(ctx.accept_encoding),
            DynamicValueSpec::SecChUa => ctx.sec_ch_ua,
            DynamicValueSpec::SecChUaMobile => Some(ctx.sec_ch_ua_mobile),
            DynamicValueSpec::SecChUaPlatform => Some(ctx.sec_ch_ua_platform),
            DynamicValueSpec::SecFetchDest => Some(ctx.sec_fetch_dest),
            DynamicValueSpec::SecFetchMode => Some(ctx.sec_fetch_mode),
            DynamicValueSpec::SecFetchSite => Some(ctx.sec_fetch_site),
            DynamicValueSpec::SecFetchUser => Some(ctx.sec_fetch_user),
            DynamicValueSpec::UpgradeInsecureRequests => Some(ctx.upgrade_insecure_requests),
            DynamicValueSpec::CacheControl => Some(ctx.cache_control),
            DynamicValueSpec::Cookie => ctx.cookie,
            DynamicValueSpec::Referer => ctx.referer,
        }
    }
}

impl PersonaTemplate {
    fn for_browser(browser: BrowserProfile) -> &'static Self {
        match browser {
            BrowserProfile::Chrome | BrowserProfile::Edge => &CHROMIUM_TEMPLATE,
            BrowserProfile::Firefox => &TITLECASE_TEMPLATE,
            BrowserProfile::Safari => &SAFARI_TEMPLATE,
        }
    }

    fn apply(
        &self,
        backend: &AsciiSimdBackend,
        ctx: &HeaderDynamic<'_>,
        headers: &mut Vec<crate::transport::h3::Header>,
    ) {
        for entry in self.entries {
            if let Some(value) = entry.value.resolve(ctx) {
                headers.push(make_header(backend, entry.name, value));
            }
        }
    }
}

fn make_header(
    backend: &AsciiSimdBackend,
    name: &[u8],
    value: &[u8],
) -> crate::transport::h3::Header {
    let mut name_vec = Vec::with_capacity(name.len());
    backend.append_bytes(&mut name_vec, name);
    let mut value_vec = Vec::with_capacity(value.len());
    backend.append_bytes(&mut value_vec, value);
    crate::transport::h3::Header::from_parts(name_vec, value_vec)
}

const CHROMIUM_TEMPLATE_ENTRIES: &[HeaderTemplateEntry] = &[
    HeaderTemplateEntry {
        name: b"user-agent",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::UserAgent),
    },
    HeaderTemplateEntry {
        name: b"accept",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Accept),
    },
    HeaderTemplateEntry {
        name: b"accept-language",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::AcceptLanguage),
    },
    HeaderTemplateEntry {
        name: b"accept-encoding",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::AcceptEncoding),
    },
    HeaderTemplateEntry {
        name: b"sec-ch-ua",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecChUa),
    },
    HeaderTemplateEntry {
        name: b"sec-ch-ua-mobile",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecChUaMobile),
    },
    HeaderTemplateEntry {
        name: b"sec-ch-ua-platform",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecChUaPlatform),
    },
    HeaderTemplateEntry {
        name: b"sec-fetch-dest",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchDest),
    },
    HeaderTemplateEntry {
        name: b"sec-fetch-mode",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchMode),
    },
    HeaderTemplateEntry {
        name: b"sec-fetch-site",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchSite),
    },
    HeaderTemplateEntry {
        name: b"sec-fetch-user",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchUser),
    },
    HeaderTemplateEntry {
        name: b"upgrade-insecure-requests",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::UpgradeInsecureRequests),
    },
    HeaderTemplateEntry {
        name: b"cache-control",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::CacheControl),
    },
    HeaderTemplateEntry {
        name: b"cookie",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Cookie),
    },
    HeaderTemplateEntry {
        name: b"referer",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Referer),
    },
];

const TITLECASE_TEMPLATE_ENTRIES: &[HeaderTemplateEntry] = &[
    HeaderTemplateEntry {
        name: b"User-Agent",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::UserAgent),
    },
    HeaderTemplateEntry {
        name: b"Accept",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Accept),
    },
    HeaderTemplateEntry {
        name: b"Accept-Language",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::AcceptLanguage),
    },
    HeaderTemplateEntry {
        name: b"Accept-Encoding",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::AcceptEncoding),
    },
    HeaderTemplateEntry {
        name: b"Sec-Fetch-Dest",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchDest),
    },
    HeaderTemplateEntry {
        name: b"Sec-Fetch-Mode",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchMode),
    },
    HeaderTemplateEntry {
        name: b"Sec-Fetch-Site",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchSite),
    },
    HeaderTemplateEntry {
        name: b"Sec-Fetch-User",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchUser),
    },
    HeaderTemplateEntry {
        name: b"Upgrade-Insecure-Requests",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::UpgradeInsecureRequests),
    },
    HeaderTemplateEntry {
        name: b"Cache-Control",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::CacheControl),
    },
    HeaderTemplateEntry {
        name: b"Referer",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Referer),
    },
];

const SAFARI_TEMPLATE_ENTRIES: &[HeaderTemplateEntry] = &[
    HeaderTemplateEntry {
        name: b"User-Agent",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::UserAgent),
    },
    HeaderTemplateEntry {
        name: b"Accept",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Accept),
    },
    HeaderTemplateEntry {
        name: b"Accept-Language",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::AcceptLanguage),
    },
    HeaderTemplateEntry {
        name: b"Accept-Encoding",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::AcceptEncoding),
    },
    HeaderTemplateEntry {
        name: b"Referer",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Referer),
    },
];

const CHROMIUM_TEMPLATE: PersonaTemplate = PersonaTemplate { entries: CHROMIUM_TEMPLATE_ENTRIES };
const TITLECASE_TEMPLATE: PersonaTemplate = PersonaTemplate { entries: TITLECASE_TEMPLATE_ENTRIES };
const SAFARI_TEMPLATE: PersonaTemplate = PersonaTemplate { entries: SAFARI_TEMPLATE_ENTRIES };

/// Manages the generation of fake HTTP/3 headers to masquerade QUIC traffic.
pub struct Http3Masquerade {
    profile: FingerprintProfile,
}

impl Http3Masquerade {
    /// Creates a new masquerader using the provided fingerprint profile.
    ///
    /// The profile controls pseudo-header fields such as `user-agent` and
    /// `accept-language` that are reflected in generated request headers.
    pub fn new(profile: FingerprintProfile) -> Self {
        Self { profile }
    }

    /// Generates a list of QPACK-style headers for an HTTP/3 request.
    /// The returned list is consumed by the transport's header encoder.
    pub fn generate_headers(&self, host: &str, path: &str) -> Vec<crate::transport::h3::Header> {
        let mut headers = vec![
            crate::transport::h3::Header::new(b":method", b"GET"),
            crate::transport::h3::Header::new(b":scheme", b"https"),
            crate::transport::h3::Header::new(b":authority", host.as_bytes()),
            crate::transport::h3::Header::new(b":path", path.as_bytes()),
        ];

        let backend = AsciiSimdBackend::detect();
        let accept_language_owned = self.get_browser_accept_language();
        let accept_header_bytes = self.get_browser_accept_header().as_bytes();
        let fetch_site_bytes = self.get_sec_fetch_site(host).as_bytes();
        let sec_ch_ua_owned =
            if matches!(self.profile.browser, BrowserProfile::Chrome | BrowserProfile::Edge) {
                Some(self.build_sec_ch_ua())
            } else {
                None
            };
        let cookie_owned = if self.should_include_cookies(host) {
            self.generate_realistic_cookies()
        } else {
            None
        };
        let referer_owned = if self.should_include_referer(host) {
            Some(self.generate_realistic_referer(host))
        } else {
            None
        };

        let sec_ch_ua_mobile =
            if self.is_mobile() { MOBILE_TRUE_VALUE } else { MOBILE_FALSE_VALUE };
        let platform_bytes = self.get_platform_string().as_bytes();

        let dynamic = HeaderDynamic {
            user_agent: self.profile.user_agent.as_bytes(),
            accept: accept_header_bytes,
            accept_language: accept_language_owned.as_bytes(),
            accept_encoding: ACCEPT_ENCODING_VALUE,
            sec_ch_ua: sec_ch_ua_owned.as_deref().map(str::as_bytes),
            sec_ch_ua_mobile,
            sec_ch_ua_platform: platform_bytes,
            sec_fetch_dest: SEC_FETCH_DEST_VALUE,
            sec_fetch_mode: SEC_FETCH_MODE_VALUE,
            sec_fetch_site: fetch_site_bytes,
            sec_fetch_user: SEC_FETCH_USER_VALUE,
            upgrade_insecure_requests: UPGRADE_INSECURE_REQUESTS_VALUE,
            cache_control: CACHE_CONTROL_VALUE,
            cookie: cookie_owned.as_deref().map(str::as_bytes),
            referer: referer_owned.as_deref().map(str::as_bytes),
        };

        let template = PersonaTemplate::for_browser(self.profile.browser);
        template.apply(&backend, &dynamic, &mut headers);

        headers
    }

    /// Returns platform string for `sec-ch-ua-platform`.
    fn get_platform_string(&self) -> &'static str {
        match self.profile.os {
            OsProfile::Windows => "\"Windows\"",
            OsProfile::MacOS => "\"macOS\"",
            OsProfile::Linux => "\"Linux\"",
            OsProfile::Android => "\"Android\"",
            OsProfile::IOS => "\"iOS\"",
        }
    }

    /// Returns whether current profile is mobile (Android/iOS).
    fn is_mobile(&self) -> bool {
        matches!(self.profile.os, OsProfile::Android | OsProfile::IOS)
    }

    /// Build a realistic sec-ch-ua value for the current browser.
    fn build_sec_ch_ua(&self) -> String {
        let ua = self.profile.user_agent.as_str();
        match self.profile.browser {
            BrowserProfile::Chrome => {
                let major = self.extract_major_version(ua, "Chrome").unwrap_or(126);
                format!(
                    "\"Chromium\";v=\"{0}\", \"Not A(Brand\";v=\"24\", \"Google Chrome\";v=\"{0}\"",
                    major
                )
            }
            BrowserProfile::Edge => {
                // Edge user-agent typically contains "Edg/<ver>" and Chrome base
                let major = self
                    .extract_major_version(ua, "Edg")
                    .or_else(|| self.extract_major_version(ua, "Chrome"))
                    .unwrap_or(126);
                format!("\"Chromium\";v=\"{0}\", \"Not A(Brand\";v=\"24\", \"Microsoft Edge\";v=\"{0}\"", major)
            }
            BrowserProfile::Firefox => {
                // Firefox does not widely use brands; still include a consistent value
                let major = self.extract_major_version(ua, "Firefox").unwrap_or(128);
                format!("\"Not A(Brand\";v=\"99\", \"Firefox\";v=\"{0}\"", major)
            }
            BrowserProfile::Safari => {
                // Safari: use Version/<ver> as proxy if present
                let major = self.extract_major_version(ua, "Version").unwrap_or(17);
                format!("\"Not A(Brand\";v=\"99\", \"Safari\";v=\"{0}\"", major)
            }
        }
    }

    /// Extracts major version from UA for tokens like "Token/123.4".
    fn extract_major_version(&self, ua: &str, token: &str) -> Option<u32> {
        let needle = format!("{}/", token);
        if let Some(pos) = ua.find(&needle) {
            let start = pos + needle.len();
            let tail = &ua[start..];
            let mut num = String::new();
            for ch in tail.chars() {
                if ch.is_ascii_digit() {
                    num.push(ch);
                } else {
                    break;
                }
            }
            if !num.is_empty() {
                return num.parse::<u32>().ok();
            }
        }
        None
    }

    /// Returns browser-specific Accept header for maximum realism.
    fn get_browser_accept_header(&self) -> &'static str {
        match self.profile.browser {
            BrowserProfile::Chrome => "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            BrowserProfile::Firefox => "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            BrowserProfile::Safari => "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            BrowserProfile::Edge => "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        }
    }

    /// Returns browser/OS-specific Accept-Language with realistic ordering.
    fn get_browser_accept_language(&self) -> String {
        let base_lang = &self.profile.accept_language;
        match self.profile.os {
            OsProfile::Windows => {
                // Windows tends to have more specific locale variants
                if base_lang.starts_with("en") {
                    "en-US,en;q=0.9".to_string()
                } else {
                    format!("{},en-US;q=0.9,en;q=0.8", base_lang)
                }
            }
            OsProfile::MacOS => {
                // macOS often has cleaner language preferences
                if base_lang.starts_with("en") {
                    "en-US,en;q=0.9".to_string()
                } else {
                    format!("{},en;q=0.9", base_lang)
                }
            }
            OsProfile::Linux => {
                // Linux users often have more diverse language setups
                if base_lang.starts_with("en") {
                    "en-US,en;q=0.9".to_string()
                } else {
                    format!("{},en-US;q=0.8,en;q=0.7", base_lang)
                }
            }
            OsProfile::Android => {
                // Android has specific mobile language patterns
                if base_lang.starts_with("en") {
                    "en-US,en;q=0.9".to_string()
                } else {
                    format!("{},en-US;q=0.9,en;q=0.8", base_lang)
                }
            }
            OsProfile::IOS => {
                // iOS similar to macOS but with mobile specifics
                if base_lang.starts_with("en") {
                    "en-US,en;q=0.9".to_string()
                } else {
                    format!("{},en;q=0.9", base_lang)
                }
            }
        }
    }

    /// Returns sec-fetch-site value based on fronting scenario.
    fn get_sec_fetch_site(&self, host: &str) -> &'static str {
        // Check if this looks like a CDN/fronting domain
        if host_contains(host, "cloudflare") || host_contains(host, "cdn") {
            "cross-site"
        } else {
            "none"
        }
    }

    /// Determines if cookies should be included based on browser and domain
    fn should_include_cookies(&self, host: &str) -> bool {
        // Include cookies for major sites and CDNs (more realistic)
        matches!(self.profile.browser, BrowserProfile::Chrome | BrowserProfile::Edge)
            && (host_contains(host, "google")
                || host_contains(host, "cloudflare")
                || host_contains(host, "amazon")
                || host_contains(host, "microsoft")
                || host_contains(host, "cdn")
                || host_contains(host, ".com"))
    }

    /// Generates realistic cookies from the canonical wall clock.
    ///
    /// A pre-Unix-epoch value cannot produce a valid browser timestamp, so the
    /// optional cookie is omitted instead of emitting a deterministic zero.
    fn generate_realistic_cookies(&self) -> Option<String> {
        let timestamp = crate::time_source::now_system()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        Some(self.generate_realistic_cookies_at(timestamp))
    }

    /// Deterministic cookie rendering helper (exposed for testing/benchmarks).
    pub fn generate_realistic_cookies_at(&self, timestamp: u64) -> String {
        let ga_id = self.profile.user_agent.len() as u64 * 1_234_567 + timestamp % 1_000_000;
        let session_id =
            (self.profile.accept_language.len() as u64 + 1) * 987_654 + timestamp % 100_000;

        let mut raw = Vec::with_capacity(96);
        let simd = crate::optimize::stealth::AsciiSimdBackend::detect();

        match self.profile.browser {
            BrowserProfile::Chrome | BrowserProfile::Edge => {
                simd.append_bytes(&mut raw, b"_ga=GA1.2.");
                simd.append_decimal(&mut raw, ga_id);
                simd.append_bytes(&mut raw, b".");
                simd.append_decimal(&mut raw, timestamp.saturating_sub(86_400));
                simd.append_bytes(&mut raw, b"; _gid=GA1.2.");
                simd.append_decimal(&mut raw, session_id);
                simd.append_bytes(&mut raw, b".");
                simd.append_decimal(&mut raw, timestamp);
                simd.append_bytes(&mut raw, b"; _gat=1");
            }
            BrowserProfile::Firefox => {
                simd.append_bytes(&mut raw, b"sessionid=");
                simd.append_decimal(&mut raw, session_id);
                simd.append_bytes(&mut raw, b"; csrftoken=");
                let token = timestamp % 0xFF_FFFF;
                simd.append_lower_hex(&mut raw, token);
            }
            BrowserProfile::Safari => {
                simd.append_bytes(&mut raw, b"s_sess=");
                simd.append_decimal(&mut raw, timestamp);
                simd.append_bytes(&mut raw, b"%20");
                simd.append_decimal(&mut raw, session_id);
                simd.append_bytes(&mut raw, b"%20End");
            }
        }

        String::from_utf8_lossy(&raw).into_owned()
    }

    /// Determines if referer should be included
    fn should_include_referer(&self, host: &str) -> bool {
        // Include referer for cross-site navigation (domain fronting scenarios)
        self.get_sec_fetch_site(host) == "cross-site"
    }

    /// Generates realistic referer based on fronting scenario
    fn generate_realistic_referer(&self, host: &str) -> String {
        let simd = crate::optimize::stealth::AsciiSimdBackend::detect();

        if host_contains(host, "cloudflare") || host_contains(host, "cdn") {
            let literal: &[u8] = match self.profile.browser {
                BrowserProfile::Chrome | BrowserProfile::Edge => b"https://www.google.com/",
                BrowserProfile::Firefox => b"https://duckduckgo.com/",
                BrowserProfile::Safari => b"https://www.apple.com/",
            };
            let mut raw = Vec::with_capacity(literal.len());
            simd.append_bytes(&mut raw, literal);
            return String::from_utf8_lossy(&raw).into_owned();
        }

        if host.contains("amazon") || host.contains("aws") {
            let literal = b"https://console.aws.amazon.com/";
            let mut raw = Vec::with_capacity(literal.len());
            simd.append_bytes(&mut raw, literal);
            return String::from_utf8_lossy(&raw).into_owned();
        }

        if host.contains("microsoft") || host.contains("azure") {
            let literal = b"https://portal.azure.com/";
            let mut raw = Vec::with_capacity(literal.len());
            simd.append_bytes(&mut raw, literal);
            return String::from_utf8_lossy(&raw).into_owned();
        }

        let mut raw = Vec::with_capacity(host.len() + 9);
        simd.append_bytes(&mut raw, b"https://");
        simd.append_bytes(&mut raw, host.as_bytes());
        simd.append_bytes(&mut raw, b"/");

        String::from_utf8_lossy(&raw).into_owned()
    }

    /// Deterministic referer builder surfaced for tests and tooling.
    pub fn generate_realistic_referer_for(&self, host: &str) -> String {
        self.generate_realistic_referer(host)
    }
}

#[inline(always)]
fn host_contains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    crate::optimize::string::string_contains(haystack, needle)
}

/// Configuration for [`FakeHeaders`].
struct FakeHeadersConfig {
    /// If true, removes TCP-centric headers (for example, `connection`) to better
    /// align with QUIC semantics and reduce protocol mismatches during masquerading.
    pub optimize_for_quic: bool,
}

/// Generates HTTP/3 headers optionally optimized for QUIC.
struct FakeHeaders {
    cfg: FakeHeadersConfig,
    profile: FingerprintProfile,
}

impl FakeHeaders {
    /// Creates a new header generator with the given config and fingerprint profile.
    pub fn new(cfg: FakeHeadersConfig, profile: FingerprintProfile) -> Self {
        Self { cfg, profile }
    }

    /// Returns an HTTP/3 header list for the given `host` and `path`.
    ///
    /// When `optimize_for_quic` is enabled, TCP-specific headers (like
    /// `connection`) are removed.
    pub fn header_list(&self, host: &str, path: &str) -> Vec<crate::transport::h3::Header> {
        let mut headers = Http3Masquerade::new(self.profile.clone()).generate_headers(host, path);
        if self.cfg.optimize_for_quic {
            headers.retain(|h| h.name() != b"connection");
        }
        headers
    }
}
