use std::cmp::Ordering;
use std::collections::{BinaryHeap, VecDeque};
use std::time::{Duration, Instant};

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
    inbound: VecDeque<Vec<u8>>,
    next_seq: u32,
    bundling: bool,
    bundle_buffer: Vec<Datagram>,
    last_bundle: Instant,
    max_bundle: usize,
}

impl DatagramEngine {
    pub fn new() -> Self {
        Self {
            queue: BinaryHeap::new(),
            inbound: VecDeque::new(),
            next_seq: 0,
            bundling: false,
            bundle_buffer: Vec::new(),
            last_bundle: Instant::now(),
            max_bundle: 10,
        }
    }

    pub fn send(&mut self, data: Vec<u8>, priority: u8) {
        let dg = Datagram { priority, sequence: self.next_seq, data };
        self.next_seq = self.next_seq.wrapping_add(1);
        self.queue.push(dg);
    }

    pub fn enable_bundling(&mut self, enable: bool) {
        self.bundling = enable;
    }

    fn process_outbound(&mut self) {
        let now = Instant::now();

        while let Some(dg) = self.queue.pop() {
            if self.bundling {
                self.bundle_buffer.push(dg);
                if self.bundle_buffer.len() >= self.max_bundle {
                    self.flush_bundle();
                }
            } else {
                self.inbound.push_back(dg.data);
            }
        }

        if self.bundling && now.duration_since(self.last_bundle) > Duration::from_millis(5) {
            self.flush_bundle();
        }
    }

    fn flush_bundle(&mut self) {
        for dg in self.bundle_buffer.drain(..) {
            self.inbound.push_back(dg.data);
        }
        self.last_bundle = Instant::now();
    }

    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.process_outbound();
        self.inbound.pop_front()
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
