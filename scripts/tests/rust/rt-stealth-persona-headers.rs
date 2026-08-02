#![cfg(feature = "rust-tests")]
use quicfuscate::stealth::{BrowserProfile, FingerprintProfile, Http3Masquerade, OsProfile};

fn is_title_case(name: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(name) else {
        return false;
    };
    s.split('-').all(|part| {
        if part.is_empty() {
            return true;
        }
        let mut chars = part.chars();
        match chars.next() {
            Some(first) if first.is_ascii_uppercase() || !first.is_ascii_alphabetic() => {
                chars.all(|c| !c.is_ascii_uppercase())
            }
            Some(_) => false,
            None => true,
        }
    })
}

fn is_all_lowercase(name: &[u8]) -> bool {
    name.iter().all(|b| !b.is_ascii_uppercase())
}

fn assert_title_case_headers(headers: &[quicfuscate::transport::h3::Header]) {
    for h in headers.iter().filter(|h| !h.name().starts_with(b":")) {
        assert!(
            is_title_case(h.name()),
            "expected Title-Case header name, found {:?}",
            std::str::from_utf8(h.name()).unwrap_or("<invalid utf8>")
        );
    }
}

fn expected_cookie_string(profile: &FingerprintProfile, timestamp: u64) -> String {
    let ga_id = profile.user_agent.len() as u64 * 1_234_567 + timestamp % 1_000_000;
    let session_id = (profile.accept_language.len() as u64 + 1) * 987_654 + timestamp % 100_000;

    match profile.browser {
        BrowserProfile::Chrome | BrowserProfile::Edge => format!(
            "_ga=GA1.2.{ga}.{prev}; _gid=GA1.2.{session}.{ts}; _gat=1",
            ga = ga_id,
            prev = timestamp.saturating_sub(86_400),
            session = session_id,
            ts = timestamp
        ),
        BrowserProfile::Firefox => {
            format!("sessionid={}; csrftoken={:x}", session_id, timestamp % 0xFF_FFFF)
        }
        BrowserProfile::Safari => format!("s_sess={}%20{}%20End", timestamp, session_id),
    }
}

#[test]
fn safari_headers_use_title_case() {
    let profile = FingerprintProfile::new(BrowserProfile::Safari, OsProfile::MacOS);
    let masquerade = Http3Masquerade::new(profile);
    let headers = masquerade.generate_headers("www.apple.com", "/");
    assert_title_case_headers(&headers);
}

#[test]
fn firefox_headers_use_title_case() {
    let profile = FingerprintProfile::new(BrowserProfile::Firefox, OsProfile::Windows);
    let masquerade = Http3Masquerade::new(profile);
    let headers = masquerade.generate_headers("www.mozilla.org", "/");
    assert_title_case_headers(&headers);
}

#[test]
fn chrome_headers_remain_lowercase() {
    let profile = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
    let masquerade = Http3Masquerade::new(profile);
    let headers = masquerade.generate_headers("www.google.com", "/");
    for h in headers.iter().filter(|h| !h.name().starts_with(b":")) {
        assert!(
            is_all_lowercase(h.name()),
            "expected lowercase header, found {:?}",
            std::str::from_utf8(h.name()).unwrap_or("<invalid utf8>")
        );
    }
}

#[test]
fn chrome_cookie_simd_matches_scalar_formatter() {
    let profile = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
    let masquerade = Http3Masquerade::new(profile.clone());
    let timestamp = 1_700_000_000_u64;
    let expected = expected_cookie_string(&profile, timestamp);
    let actual = masquerade.generate_realistic_cookies_at(timestamp);
    assert_eq!(actual, expected);
}

#[test]
fn firefox_cookie_simd_matches_scalar_formatter() {
    let profile = FingerprintProfile::new(BrowserProfile::Firefox, OsProfile::Windows);
    let masquerade = Http3Masquerade::new(profile.clone());
    let timestamp = 1_700_000_000_u64;
    let expected = expected_cookie_string(&profile, timestamp);
    let actual = masquerade.generate_realistic_cookies_at(timestamp);
    assert_eq!(actual, expected);
}

#[test]
fn safari_cookie_simd_matches_scalar_formatter() {
    let profile = FingerprintProfile::new(BrowserProfile::Safari, OsProfile::MacOS);
    let masquerade = Http3Masquerade::new(profile.clone());
    let timestamp = 1_700_000_000_u64;
    let expected = expected_cookie_string(&profile, timestamp);
    let actual = masquerade.generate_realistic_cookies_at(timestamp);
    assert_eq!(actual, expected);
}

#[test]
fn chrome_fronting_referer_matches_expected_literal() {
    let profile = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
    let masquerade = Http3Masquerade::new(profile);
    let referer = masquerade.generate_realistic_referer_for("cdn.cloudflare.com");
    assert_eq!(referer, "https://www.google.com/");
}

#[test]
fn firefox_fronting_referer_matches_expected_literal() {
    let profile = FingerprintProfile::new(BrowserProfile::Firefox, OsProfile::Windows);
    let masquerade = Http3Masquerade::new(profile);
    let referer = masquerade.generate_realistic_referer_for("cdn.cloudflare.com");
    assert_eq!(referer, "https://duckduckgo.com/");
}

#[test]
fn safari_fronting_referer_matches_expected_literal() {
    let profile = FingerprintProfile::new(BrowserProfile::Safari, OsProfile::MacOS);
    let masquerade = Http3Masquerade::new(profile);
    let referer = masquerade.generate_realistic_referer_for("cdn.cloudflare.com");
    assert_eq!(referer, "https://www.apple.com/");
}

#[test]
fn vendor_specific_referers_use_literals() {
    let chrome =
        Http3Masquerade::new(FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows));
    assert_eq!(
        chrome.generate_realistic_referer_for("console.aws.amazon.com"),
        "https://console.aws.amazon.com/"
    );

    let edge =
        Http3Masquerade::new(FingerprintProfile::new(BrowserProfile::Edge, OsProfile::Windows));
    assert_eq!(
        edge.generate_realistic_referer_for("login.microsoftonline.com"),
        "https://portal.azure.com/"
    );
}

#[test]
fn same_origin_referer_fallback_is_well_formed() {
    let profile = FingerprintProfile::new(BrowserProfile::Safari, OsProfile::MacOS);
    let masquerade = Http3Masquerade::new(profile);
    let referer = masquerade.generate_realistic_referer_for("example.com");
    assert_eq!(referer, "https://example.com/");
}

#[test]
fn chrome_header_order_uses_simd_template() {
    let profile = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
    let masquerade = Http3Masquerade::new(profile);
    let headers = masquerade.generate_headers("cdn.cloudflare.com", "/");

    let names: Vec<&[u8]> = headers.iter().map(|h| h.name()).collect();
    let expected_names = vec![
        &b":method"[..],
        &b":scheme"[..],
        &b":authority"[..],
        &b":path"[..],
        &b"user-agent"[..],
        &b"accept"[..],
        &b"accept-language"[..],
        &b"accept-encoding"[..],
        &b"sec-ch-ua"[..],
        &b"sec-ch-ua-mobile"[..],
        &b"sec-ch-ua-platform"[..],
        &b"sec-fetch-dest"[..],
        &b"sec-fetch-mode"[..],
        &b"sec-fetch-site"[..],
        &b"sec-fetch-user"[..],
        &b"upgrade-insecure-requests"[..],
        &b"cache-control"[..],
        &b"cookie"[..],
        &b"referer"[..],
    ];
    assert_eq!(names, expected_names);

    let fetch_site = headers.iter().find(|h| h.name() == b"sec-fetch-site").unwrap();
    assert_eq!(fetch_site.value(), b"cross-site");

    let referer = headers.iter().find(|h| h.name() == b"referer").unwrap();
    assert_eq!(referer.value(), b"https://www.google.com/");

    assert!(headers.iter().any(|h| h.name() == b"cookie"));
}

#[test]
fn safari_header_order_dedicated_template() {
    let profile = FingerprintProfile::new(BrowserProfile::Safari, OsProfile::MacOS);
    let masquerade = Http3Masquerade::new(profile);
    let headers = masquerade.generate_headers("cdn.cloudflare.com", "/");

    let names: Vec<&[u8]> = headers.iter().map(|h| h.name()).collect();
    let expected_names = vec![
        &b":method"[..],
        &b":scheme"[..],
        &b":authority"[..],
        &b":path"[..],
        &b"User-Agent"[..],
        &b"Accept"[..],
        &b"Accept-Language"[..],
        &b"Accept-Encoding"[..],
        &b"Referer"[..],
    ];
    assert_eq!(names, expected_names);

    let referer = headers.iter().find(|h| h.name() == b"Referer").unwrap();
    assert_eq!(referer.value(), b"https://www.apple.com/");
}
