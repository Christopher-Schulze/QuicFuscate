use std::collections::HashMap;

#[derive(Clone, Copy)]
pub enum BrowserProfile {
    Chrome,
    Firefox,
    Safari,
    Edge,
}

pub fn default_headers(profile: BrowserProfile) -> HashMap<String, String> {
    match profile {
        BrowserProfile::Chrome => HashMap::from([
            ("user-agent".into(), "Mozilla/5.0 Chrome".into()),
        ]),
        BrowserProfile::Firefox => HashMap::from([
            ("user-agent".into(), "Mozilla/5.0 Firefox".into()),
        ]),
        BrowserProfile::Safari => HashMap::from([
            ("user-agent".into(), "Mozilla/5.0 Safari".into()),
        ]),
        BrowserProfile::Edge => HashMap::from([
            ("user-agent".into(), "Mozilla/5.0 Edge".into()),
        ]),
    }
}
