use std::collections::VecDeque;

pub struct DatagramEngine {
    queue: VecDeque<(u8, Vec<u8>)>,
}

impl DatagramEngine {
    pub fn new() -> Self {
        Self { queue: VecDeque::new() }
    }

    pub fn send(&mut self, data: Vec<u8>, priority: u8) {
        self.queue.push_back((priority, data));
    }

    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        if self.queue.is_empty() {
            return None;
        }
        let idx = self
            .queue
            .iter()
            .enumerate()
            .max_by_key(|(_, (p, _))| *p)
            .map(|(i, _)| i)?;
        Some(self.queue.remove(idx).unwrap().1)
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
            eng.send(vec![1,2,3], 1);
            let data = eng.recv().await.unwrap();
            assert_eq!(data, vec![1,2,3]);
        });
    }
}
