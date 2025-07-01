use std::collections::{HashMap, VecDeque};

pub struct StreamEngine {
    next_id: u64,
    priorities: HashMap<u64, u8>,
    queue: VecDeque<(u64, Vec<u8>)>,
}

impl StreamEngine {
    pub fn new() -> Self {
        Self { next_id: 0, priorities: HashMap::new(), queue: VecDeque::new() }
    }

    pub fn create_stream(&mut self, priority: u8) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.priorities.insert(id, priority);
        id
    }

    pub fn send(&mut self, id: u64, data: Vec<u8>) {
        self.queue.push_back((id, data));
    }

    pub async fn recv(&mut self) -> Option<(u64, Vec<u8>)> {
        if self.queue.is_empty() {
            return None;
        }
        let idx = self
            .queue
            .iter()
            .enumerate()
            .max_by_key(|(_, (id, _))| self.priorities.get(id).cloned().unwrap_or(0))
            .map(|(i, _)| i)?;
        Some(self.queue.remove(idx).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn stream_roundtrip() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut eng = StreamEngine::new();
            let id = eng.create_stream(1);
            eng.send(id, vec![4,5,6]);
            let (rid, data) = eng.recv().await.unwrap();
            assert_eq!(rid, id);
            assert_eq!(data, vec![4,5,6]);
        });
    }
}
