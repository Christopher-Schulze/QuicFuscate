use stealth::{BrowserFingerprint, BrowserType, OperatingSystem};

#[test]
fn headers_include_user_agent() {
    let fp = BrowserFingerprint::new(BrowserType::Chrome, OperatingSystem::Windows, "UA".into());
    let headers = fp.generate_http_headers();
    assert_eq!(headers.get("User-Agent"), Some(&"UA".to_string()));
}
