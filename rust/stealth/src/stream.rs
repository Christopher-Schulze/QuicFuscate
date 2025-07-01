use tokio::sync::mpsc::{unbounded_channel, UnboundedSender, UnboundedReceiver};

pub struct StreamEngine {
    tx: UnboundedSender<(u64, Vec<u8>)>,
    rx: UnboundedReceiver<(u64, Vec<u8>)>,
    next_id: u64,
}

impl StreamEngine {
    pub fn new() -> Self {
        let (tx, rx) = unbounded_channel();
        Self { tx, rx, next_id: 0 }
    }

    pub fn create_stream(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn send(&self, id: u64, data: Vec<u8>) {
        let _ = self.tx.send((id, data));
    }

    pub async fn recv(&mut self) -> Option<(u64, Vec<u8>)> {
        self.rx.recv().await
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
            let id = eng.create_stream();
            eng.send(id, vec![4,5,6]);
            let (rid, data) = eng.recv().await.unwrap();
            assert_eq!(rid, id);
            assert_eq!(data, vec![4,5,6]);
        });
    }
}
