use std::collections::HashMap;

#[derive(Default)]
pub struct QpackEngine {
    table: HashMap<String, String>,
    pub encoded: usize,
    pub decoded: usize,
}

impl QpackEngine {
    pub fn new() -> Self {
        Self { table: HashMap::new(), encoded: 0, decoded: 0 }
    }

    pub fn encode(&mut self, headers: &[(String, String)]) -> Vec<u8> {
        for (k, v) in headers {
            self.table.insert(k.clone(), v.clone());
        }
        self.encoded += 1;
        headers
            .iter()
            .flat_map(|(k, v)| [k.as_bytes(), b":", v.as_bytes(), b"\n"].concat())
            .collect()
    }

    pub fn decode(&mut self, data: &[u8]) -> Vec<(String, String)> {
        let s = String::from_utf8_lossy(data);
        self.decoded += 1;
        s.lines()
            .filter_map(|l| {
                let mut parts = l.splitn(2, ':');
                let k = parts.next()?.to_string();
                let v = parts.next()?.to_string();
                self.table.insert(k.clone(), v.clone());
                Some((k, v))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let mut engine = QpackEngine::new();
        let headers = vec![("a".to_string(), "b".to_string())];
        let enc = engine.encode(&headers);
        let dec = engine.decode(&enc);
        assert_eq!(dec, headers);
    }
}
