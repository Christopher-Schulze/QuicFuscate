use once_cell::sync::Lazy;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// Simple in-memory network used by the patched quiche stub.
static NETWORK: Lazy<Mutex<HashMap<String, VecDeque<Vec<u8>>>>> = Lazy::new(|| {
    Mutex::new(HashMap::new())
});

/// Minimal QUIC connection stub used for tests.
pub struct Connection {
    addr: String,
}

impl Connection {
    /// Create a new connection associated with the given address.
    pub fn connect(addr: &str) -> Self {
        NETWORK
            .lock()
            .unwrap()
            .entry(addr.to_string())
            .or_insert_with(VecDeque::new);
        Self {
            addr: addr.to_string(),
        }
    }

    /// Send a packet over this connection.
    pub fn send(&mut self, data: &[u8]) {
        let mut net = NETWORK.lock().unwrap();
        let queue = net.entry(self.addr.clone()).or_insert_with(VecDeque::new);
        queue.push_back(data.to_vec());
    }

    /// Receive a pending packet if available.
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        let mut net = NETWORK.lock().unwrap();
        net.get_mut(&self.addr).and_then(|q| q.pop_front())
    }
}
