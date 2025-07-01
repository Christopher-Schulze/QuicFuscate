use tokio::sync::mpsc::{unbounded_channel, UnboundedSender, UnboundedReceiver};

pub struct DatagramEngine {
    tx: UnboundedSender<Vec<u8>>,
    rx: UnboundedReceiver<Vec<u8>>,
}

impl DatagramEngine {
    pub fn new() -> Self {
        let (tx, rx) = unbounded_channel();
        Self { tx, rx }
    }

    pub fn send(&self, data: Vec<u8>) {
        let _ = self.tx.send(data);
    }

    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn send_receive() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut eng = DatagramEngine::new();
            eng.send(vec![1,2,3]);
            let data = eng.recv().await.unwrap();
            assert_eq!(data, vec![1,2,3]);
        });
    }
}
