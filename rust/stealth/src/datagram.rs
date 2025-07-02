use std::cmp::Ordering;
use std::collections::BinaryHeap;

#[derive(Eq)]
struct Datagram {
    priority: u8,
    sequence: u32,
    data: Vec<u8>,
}

impl Ord for Datagram {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

impl PartialOrd for Datagram {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl PartialEq for Datagram {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.sequence == other.sequence
    }
}

pub struct DatagramEngine {
    queue: BinaryHeap<Datagram>,
    next_seq: u32,
}

impl DatagramEngine {
    pub fn new() -> Self {
        Self { queue: BinaryHeap::new(), next_seq: 0 }
    }

    pub fn send(&mut self, data: Vec<u8>, priority: u8) {
        let dg = Datagram { priority, sequence: self.next_seq, data };
        self.next_seq = self.next_seq.wrapping_add(1);
        self.queue.push(dg);
    }

    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.queue.pop().map(|d| d.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn send_receive_priority() -> Result<(), Box<dyn std::error::Error>> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let mut eng = DatagramEngine::new();
            eng.send(vec![1], 1);
            eng.send(vec![2], 10);
            assert_eq!(eng.recv().await, Some(vec![2]));
            assert_eq!(eng.recv().await, Some(vec![1]));
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        Ok(())
    }
}
