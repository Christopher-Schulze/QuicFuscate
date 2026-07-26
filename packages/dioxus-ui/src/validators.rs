use regex::Regex;

pub struct Remote {
    pub server: String,
    pub port: u16,
}

pub fn parse_remote(remote: &str) -> Option<Remote> {
    let trimmed = remote.trim();
    if trimmed.is_empty() || trimmed.contains(char::is_whitespace) {
        return None;
    }
    if trimmed.contains(&['/', '?', '#', '@'][..]) {
        return None;
    }

    let parse_port = |port_str: &str| -> Option<u16> {
        if port_str.is_empty() {
            return Some(4433);
        }
        if !Regex::new(r"^\d+$").unwrap().is_match(port_str) {
            return None;
        }
        port_str.parse::<u16>().ok().filter(|&p| p >= 1)
    };

    if trimmed.starts_with('[') {
        let end = trimmed.find(']')?;
        let host = &trimmed[1..end];
        if host.is_empty() || host.contains(char::is_whitespace) {
            return None;
        }
        let port_str = if trimmed[end + 1..].starts_with(':') {
            &trimmed[end + 2..]
        } else {
            ""
        };
        let port = parse_port(port_str)?;
        return Some(Remote {
            server: host.into(),
            port,
        });
    }

    let colon_count = trimmed.matches(':').count();
    if colon_count > 1 {
        return None;
    }

    let (host, port_str) = trimmed.split_once(':').unwrap_or((trimmed, ""));
    if host.is_empty() || !Regex::new(r"^[A-Za-z0-9._-]+$").unwrap().is_match(host) {
        return None;
    }
    let port = parse_port(port_str)?;
    Some(Remote {
        server: host.into(),
        port,
    })
}

pub fn normalize_remote_for_storage(remote: &str) -> Option<String> {
    let parsed = parse_remote(remote)?;
    let host = if parsed.server.contains(':') {
        format!("[{}]", parsed.server)
    } else {
        parsed.server
    };
    Some(format!("{host}:{}", parsed.port))
}

pub fn is_valid_sni_host(value: &str) -> bool {
    let sni = value.trim();
    !sni.is_empty()
        && !sni.contains(char::is_whitespace)
        && !sni.contains(&['/', '?', '#', '@'][..])
        && !sni.contains(':')
}
