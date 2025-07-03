use std::collections::{HashMap, VecDeque};

struct Stream {
    priority: u8,
    buffer: VecDeque<Vec<u8>>,
    closed: bool,
}

pub struct StreamEngine {
    next_id: u64,
    streams: HashMap<u64, Stream>,
}

impl StreamEngine {
    pub fn new() -> Self {
        Self { next_id: 0, streams: HashMap::new() }
    }

    pub fn create_stream(&mut self, priority: u8) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.streams.insert(id, Stream { priority, buffer: VecDeque::new(), closed: false });
        id
    }

    pub fn close_stream(&mut self, id: u64) -> bool {
        self.streams.remove(&id).is_some()
    }

    pub fn send(&mut self, id: u64, data: Vec<u8>) {
        if let Some(stream) = self.streams.get_mut(&id) {
            if !stream.closed {
                stream.buffer.push_back(data);
            }
        }
    }

    pub async fn recv(&mut self) -> Option<(u64, Vec<u8>)> {
        let id = self
            .streams
            .iter()
            .filter(|(_, s)| !s.buffer.is_empty())
            .max_by_key(|(_, s)| s.priority)
            .map(|(id, _)| *id)?;

        let stream = self.streams.get_mut(&id)?;
        if stream.closed {
            return None;
        }
        let data = stream.buffer.pop_front()?;
        Some((id, data))
    }

    pub fn active_streams(&self) -> usize {
        self.streams.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn stream_roundtrip_priority() -> Result<(), Box<dyn std::error::Error>> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let mut eng = StreamEngine::new();
            let id1 = eng.create_stream(1);
            let id2 = eng.create_stream(10);
            eng.send(id1, vec![1]);
            eng.send(id2, vec![2]);
            let (rid, data) = eng.recv().await.unwrap();
            assert_eq!(rid, id2);
            assert_eq!(data, vec![2]);
            let (rid, data) = eng.recv().await.unwrap();
            assert_eq!(rid, id1);
            assert_eq!(data, vec![1]);
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        Ok(())
    }
}
