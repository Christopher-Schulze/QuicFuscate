use std::collections::VecDeque;

use parking_lot::Mutex;

use crate::time_source::ProtocolClock;

#[derive(Clone, Debug)]
pub struct AdminLogLine {
    pub ts: u64,
    pub timestamp_valid: bool,
    pub timestamp_error: Option<String>,
    pub level: String,
    pub msg: String,
}

#[derive(Debug)]
struct Inner {
    next_seq: u64,
    lines: VecDeque<(u64, AdminLogLine)>,
}

/// In-memory log buffer for the Admin UI.
///
/// Notes:
/// - This is intentionally memory-only. No disk writes.
/// - Cursor is a monotonic sequence number ("seq"). Clients ask for lines after a cursor.
#[derive(Debug)]
pub struct AdminLogBuffer {
    capacity: usize,
    inner: Mutex<Inner>,
    clock: ProtocolClock,
}

impl AdminLogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self::new_with_clock(capacity, &ProtocolClock::default())
    }

    pub fn new_with_clock(capacity: usize, clock: &ProtocolClock) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: Mutex::new(Inner { next_seq: 1, lines: VecDeque::new() }),
            clock: clock.clone(),
        }
    }

    pub fn clear(&self) {
        let mut g = self.inner.lock();
        g.lines.clear();
    }

    pub fn push(&self, level: log::Level, msg: &str) {
        let (ts, timestamp_valid, timestamp_error) =
            match crate::time_source::unix_epoch_millis(self.clock.now_system()) {
                Ok(ts) => (ts, true, None),
                Err(error) => (0, false, Some(error.to_string())),
            };
        let mut g = self.inner.lock();
        let seq = g.next_seq;
        g.next_seq = g.next_seq.saturating_add(1);

        let line = AdminLogLine {
            ts,
            timestamp_valid,
            timestamp_error,
            level: level.to_string(),
            // Keep message stable for the UI, avoid CRLF differences.
            msg: msg.replace("\r\n", "\n"),
        };
        g.lines.push_back((seq, line));
        while g.lines.len() > self.capacity {
            g.lines.pop_front();
        }
    }

    /// Returns (lines, new_cursor).
    pub fn since(&self, cursor: u64, mode: &str, max_lines: usize) -> (Vec<AdminLogLine>, u64) {
        let max_lines = max_lines.clamp(1, 2000);
        let g = self.inner.lock();

        let mut out: Vec<AdminLogLine> = Vec::new();
        let mut new_cursor = cursor;

        for (seq, line) in g.lines.iter() {
            if *seq <= cursor {
                continue;
            }
            if out.len() >= max_lines {
                break;
            }

            let msg = match mode {
                "minimal" => redact_minimal(&line.msg),
                "no-log" => String::new(),
                _ => line.msg.clone(),
            };

            out.push(AdminLogLine {
                ts: line.ts,
                timestamp_valid: line.timestamp_valid,
                timestamp_error: line.timestamp_error.clone(),
                level: line.level.clone(),
                msg,
            });
            new_cursor = *seq;
        }

        (out, new_cursor)
    }
}

impl qf_logging::LogSink for AdminLogBuffer {
    fn push(&self, level: log::Level, msg: &str) {
        Self::push(self, level, msg);
    }
}

fn redact_minimal(input: &str) -> String {
    // Minimal mode should avoid leaking client metadata:
    // - redact ipv4 addresses
    // - redact obvious credential-ish fragments
    let s = redact_ipv4_like(input);
    redact_simple_secrets(&s)
}

fn redact_ipv4_like(input: &str) -> String {
    // Fast, dependency-free replacement: detect runs with 3 dots and digits around them.
    // We do not validate octet ranges, this is a privacy feature, not a parser.
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut out = String::with_capacity(input.len());

    while i < bytes.len() {
        let start = i;
        let mut j = i;
        let mut dots = 0usize;
        let mut saw_digit = false;
        while j < bytes.len() {
            let b = bytes[j];
            if b.is_ascii_digit() {
                saw_digit = true;
                j += 1;
                continue;
            }
            if b == b'.' {
                dots += 1;
                j += 1;
                continue;
            }
            break;
        }

        if saw_digit && dots == 3 && j > start {
            // Ensure there is at least one digit between dots by a cheap check:
            // reject leading/trailing dot or ".."
            let seg = &input[start..j];
            if !seg.starts_with('.') && !seg.ends_with('.') && !seg.contains("..") {
                out.push_str("<ip>");
                i = j;
                continue;
            }
        }

        // No match, copy one char.
        let Some(ch) = input[i..].chars().next() else {
            break;
        };
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn redact_simple_secrets(input: &str) -> String {
    // Redact very common patterns without regex:
    // - Bearer tokens (inline or header-like)
    // - password=... / password: ...
    // - token=... / token: ...
    let mut out = input.to_string();
    out = redact_bearer_tokens(&out);
    out = redact_kv_value(&out, "password");
    out = redact_kv_value(&out, "token");
    out
}

fn redact_bearer_tokens(input: &str) -> String {
    // Replace "Bearer <token>" (case-insensitive for Bearer).
    let mut out = String::with_capacity(input.len());
    let lower = input.to_ascii_lowercase();
    let pat = "bearer ";
    let mut i = 0usize;
    while i < input.len() {
        let Some(pos) = lower[i..].find(pat) else {
            out.push_str(&input[i..]);
            break;
        };
        let abs = i + pos;
        out.push_str(&input[i..abs]);
        out.push_str(&input[abs..abs + pat.len()]);
        let mut j = abs + pat.len();
        // Skip token up to whitespace.
        while j < input.len() {
            let b = input.as_bytes()[j];
            if b.is_ascii_whitespace() {
                break;
            }
            j += 1;
        }
        out.push_str("<redacted>");
        i = j;
    }
    out
}

fn redact_kv_value(input: &str, key: &str) -> String {
    // Replace occurrences like "key=VALUE" or "key: VALUE" (case-insensitive) up to whitespace/comma.
    let mut out = String::with_capacity(input.len());
    let lower = input.to_ascii_lowercase();
    let key_lower = key.to_ascii_lowercase();

    let mut i = 0usize;
    while i < input.len() {
        let Some(pos) = lower[i..].find(&key_lower) else {
            out.push_str(&input[i..]);
            break;
        };
        let abs = i + pos;
        out.push_str(&input[i..abs]);

        // Copy the matched key with original casing.
        out.push_str(&input[abs..abs + key.len()]);
        let mut j = abs + key.len();

        // Skip optional spaces.
        while j < input.len() && input.as_bytes()[j].is_ascii_whitespace() {
            out.push(input.as_bytes()[j] as char);
            j += 1;
        }

        if j >= input.len() {
            i = j;
            continue;
        }

        let sep = input.as_bytes()[j];
        if sep != b'=' && sep != b':' {
            // Not a kv pair, continue.
            i = abs + 1;
            continue;
        }
        out.push(sep as char);
        j += 1;

        // Skip one space after separator.
        if j < input.len() && input.as_bytes()[j].is_ascii_whitespace() {
            out.push(input.as_bytes()[j] as char);
            j += 1;
        }

        out.push_str("<redacted>");

        // Skip until delimiter.
        while j < input.len() {
            let b = input.as_bytes()[j];
            if b.is_ascii_whitespace() || b == b',' {
                break;
            }
            j += 1;
        }
        i = j;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_streaming_is_monotonic_and_capped() {
        let buf = AdminLogBuffer::new(3);
        buf.push(log::Level::Info, "a");
        buf.push(log::Level::Info, "b");
        buf.push(log::Level::Info, "c");

        let (l1, c1) = buf.since(0, "normal", 100);
        assert_eq!(l1.len(), 3);
        assert!(c1 > 0);

        buf.push(log::Level::Info, "d");
        let (l2, c2) = buf.since(c1, "normal", 100);
        assert_eq!(l2.len(), 1);
        assert!(c2 > c1);

        // Old cursor should not crash even if entries were evicted.
        let (l3, _c3) = buf.since(0, "normal", 100);
        assert_eq!(l3.len(), 3);
        assert_eq!(l3[0].msg, "b");
        assert_eq!(l3[2].msg, "d");
    }

    #[test]
    fn pre_epoch_wall_clock_is_explicit_in_admin_log_lines() {
        let source = crate::time_source::test_support::ManualTimeSource::new(
            std::time::Instant::now(),
            std::time::SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(1),
        );
        let clock = ProtocolClock::from_source(source);
        let buffer = AdminLogBuffer::new_with_clock(4, &clock);

        buffer.push(log::Level::Warn, "clock test");
        let (lines, _) = buffer.since(0, "normal", 4);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].ts, 0);
        assert!(!lines[0].timestamp_valid);
        assert_eq!(
            lines[0].timestamp_error.as_deref(),
            Some("wall clock is before the Unix epoch")
        );
    }

    #[test]
    fn minimal_redacts_ipv4_and_secrets() {
        let msg = "peer=192.168.1.50 Authorization: Bearer abc password=123 token:deadbeef";
        let r = redact_minimal(msg);
        assert!(!r.contains("192.168.1.50"));
        assert!(r.contains("<ip>"));
        assert!(r.to_ascii_lowercase().contains("bearer <redacted>"));
        assert!(r.contains("password=<redacted>") || r.contains("password: <redacted>"));
        assert!(
            r.contains("token:<redacted>")
                || r.contains("token: <redacted>")
                || r.contains("token=<redacted>")
        );
    }
}
