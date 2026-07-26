use regex::Regex;
use unicode_normalization::UnicodeNormalization;

pub fn extract_qkey(text: &str) -> Option<String> {
    let re = Regex::new(r"(?:QKey|qkey)-[A-Za-z0-9+/=_-]+").unwrap();
    let m = re.find(text)?;
    let s = m.as_str();
    let normalized = s
        .trim_start_matches("qkey-")
        .trim_start_matches("QKey-")
        .replace("qkey-", "QKey-");
    Some(normalized)
}

pub fn normalize_utf8(value: &str) -> String {
    value
        .replace('\u{feff}', "")
        .replace(&['\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}'][..], "")
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .nfc()
        .collect::<String>()
}
