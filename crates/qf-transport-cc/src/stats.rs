//! Connection-level congestion and delivery statistics.

use qf_cpu::transport::{aggregate_congestion, CongestionSample, CONGESTION_WINDOW_SIZE};
use qf_transport_types::Stats;
use std::collections::VecDeque;

/// Connection statistics projected from the transport-owned counters.
#[derive(Debug)]
#[doc(hidden)]
pub struct ConnectionStats {
    /// Smoothed round-trip time in seconds.
    pub rtt: f32,
    /// Packet loss rate in [0.0, 1.0].
    pub loss_rate: f32,
    /// Total packets sent on this connection.
    pub packets_sent: u64,
    /// Total packets lost (detected by transport).
    pub packets_lost: u64,
    /// Current congestion window in bytes.
    pub congestion_cwnd: u64,
    /// Bytes currently in flight (unacknowledged).
    pub congestion_bytes_in_flight: u64,
    /// Estimated delivery rate in bytes per second.
    pub congestion_delivery_rate: u64,
    /// Total packets lost as tracked by congestion controller.
    pub congestion_lost: u64,
    /// Aggregate congestion score (higher = more congested).
    pub congestion_score: u64,
    congestion_samples: VecDeque<CongestionSample>,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            rtt: 0.0,
            loss_rate: 0.0,
            packets_sent: 0,
            packets_lost: 0,
            congestion_cwnd: 0,
            congestion_bytes_in_flight: 0,
            congestion_delivery_rate: 0,
            congestion_lost: 0,
            congestion_score: 0,
            congestion_samples: VecDeque::with_capacity(CONGESTION_WINDOW_SIZE),
        }
    }
}

impl ConnectionStats {
    /// Update the connection projection from one transport statistics snapshot.
    #[doc(hidden)]
    pub fn update_from_transport_stats(&mut self, stats: &Stats, rtt_seconds: f32) {
        self.packets_sent = stats.sent as u64;
        self.rtt = rtt_seconds;
        self.packets_lost = stats.lost as u64;
        self.loss_rate = if stats.sent > 0 { stats.lost as f32 / stats.sent as f32 } else { 0.0 };
        self.update_congestion(CongestionSample::from_transport_stats(stats));
    }

    /// Record one congestion sample while retaining the bounded rolling window.
    #[doc(hidden)]
    pub fn record_congestion_sample(&mut self, sample: CongestionSample) {
        self.update_congestion(sample);
    }

    /// Return the number of samples retained in the bounded rolling window.
    #[doc(hidden)]
    pub fn congestion_sample_count(&self) -> usize {
        self.congestion_samples.len()
    }

    fn update_congestion(&mut self, sample: CongestionSample) {
        if self.congestion_samples.len() == CONGESTION_WINDOW_SIZE {
            self.congestion_samples.pop_front();
        }
        self.congestion_samples.push_back(sample);
        let summary = aggregate_congestion(self.congestion_samples.make_contiguous());
        self.congestion_cwnd = summary.total_cwnd;
        self.congestion_bytes_in_flight = summary.total_bytes_in_flight;
        self.congestion_delivery_rate = summary.total_delivery_rate;
        self.congestion_lost = summary.total_lost_packets;
        self.congestion_score = summary.congestion_score;
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectionStats;
    use qf_transport_types::Stats;
    use std::time::Duration;

    #[test]
    fn defaults_are_empty_and_zeroed() {
        let stats = ConnectionStats::default();
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_lost, 0);
        assert_eq!(stats.congestion_score, 0);
    }

    #[test]
    fn update_projects_transport_and_congestion_fields() {
        let mut projected = ConnectionStats::default();
        let snapshot = Stats {
            sent: 8,
            lost: 2,
            rtt: Duration::from_millis(125),
            cwnd: 32_000,
            bytes_in_flight: 8_000,
            delivery_rate: 64_000,
            ..Stats::default()
        };
        projected.update_from_transport_stats(&snapshot, snapshot.rtt.as_secs_f32());

        assert_eq!(projected.packets_sent, 8);
        assert_eq!(projected.packets_lost, 2);
        assert!((projected.rtt - 0.125).abs() < f32::EPSILON);
        assert!((projected.loss_rate - 0.25).abs() < f32::EPSILON);
        assert_eq!(projected.congestion_cwnd, 32_000);
        assert_eq!(projected.congestion_bytes_in_flight, 8_000);
        assert_eq!(projected.congestion_delivery_rate, 64_000);
        assert_eq!(projected.congestion_lost, 2);
        assert!(projected.congestion_score > 0);
    }
}
