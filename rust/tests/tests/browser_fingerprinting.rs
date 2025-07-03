use stealth::{
    browser::{default_headers, BrowserProfile},
    BrowserFingerprint, BrowserType, OperatingSystem,
};

#[test]
fn headers_include_user_agent() {
    let fp = BrowserFingerprint::new(BrowserType::Chrome, OperatingSystem::Windows, "UA".into());
    let headers = fp.generate_http_headers();
    assert_eq!(headers.get("User-Agent"), Some(&"UA".to_string()));
}

#[test]
fn default_profiles_provide_user_agent() {
    let headers = default_headers(BrowserProfile::Firefox);
    assert!(headers.get("user-agent").is_some());
}
