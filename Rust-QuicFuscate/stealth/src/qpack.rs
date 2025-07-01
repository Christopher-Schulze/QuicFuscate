use std::collections::HashMap;

#[derive(Default)]
pub struct QpackEngine {
    table: HashMap<String, String>,
}

impl QpackEngine {
    pub fn new() -> Self {
        Self { table: HashMap::new() }
    }

    pub fn encode(&self, headers: &[(String, String)]) -> Vec<u8> {
        // extremely simplified: concatenate key:value pairs
        headers
            .iter()
            .flat_map(|(k, v)| [k.as_bytes(), b":", v.as_bytes(), b"\n"].concat())
            .collect()
    }

    pub fn decode(&self, data: &[u8]) -> Vec<(String, String)> {
        let s = String::from_utf8_lossy(data);
        s.lines()
            .filter_map(|l| {
                let mut parts = l.splitn(2, ':');
                Some((parts.next()?.to_string(), parts.next()?.to_string()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let engine = QpackEngine::new();
        let headers = vec![("a".to_string(), "b".to_string())];
        let enc = engine.encode(&headers);
        let dec = engine.decode(&enc);
        assert_eq!(dec, headers);
    }
}
