//! Connection quality assessment for QuicFuscate client.

use std::collections::VecDeque;

use crate::time_source::ProtocolClock;

/// Connection quality level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quality {
    /// Excellent (< 50ms RTT, < 1% loss)
    Excellent,
    /// Good (< 100ms RTT, < 3% loss)
    Good,
    /// Fair (< 200ms RTT, < 10% loss)
    Fair,
    /// Poor (> 200ms RTT or > 10% loss)
    Poor,
    /// Unknown (not enough data)
    Unknown,
}

impl Quality {
    /// Get quality from RTT and loss.
    pub fn from_metrics(rtt_ms: f32, loss_percent: f32) -> Self {
        if rtt_ms < 50.0 && loss_percent < 1.0 {
            Self::Excellent
        } else if rtt_ms < 100.0 && loss_percent < 3.0 {
            Self::Good
        } else if rtt_ms < 200.0 && loss_percent < 10.0 {
            Self::Fair
        } else {
            Self::Poor
        }
    }

    /// Get quality bar (5 segments).
    pub fn bar(&self) -> &'static str {
        match self {
            Self::Excellent => "#####",
            Self::Good => "####.",
            Self::Fair => "###..",
            Self::Poor => "##...",
            Self::Unknown => ".....",
        }
    }

    /// Get quality as number (0-4).
    pub fn as_number(&self) -> u8 {
        match self {
            Self::Excellent => 4,
            Self::Good => 3,
            Self::Fair => 2,
            Self::Poor => 1,
            Self::Unknown => 0,
        }
    }

    /// Get color hint.
    pub fn color(&self) -> &'static str {
        match self {
            Self::Excellent => "green",
            Self::Good => "lime",
            Self::Fair => "yellow",
            Self::Poor => "red",
            Self::Unknown => "gray",
        }
    }
}

impl std::fmt::Display for Quality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Excellent => write!(f, "Excellent"),
            Self::Good => write!(f, "Good"),
            Self::Fair => write!(f, "Fair"),
            Self::Poor => write!(f, "Poor"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Quality tracker with smoothing.
pub struct QualityTracker {
    /// RTT samples (last N)
    rtt_samples: VecDeque<f32>,
    /// Loss samples (last N)
    loss_samples: VecDeque<f32>,
    /// Maximum samples to keep
    max_samples: usize,
}

impl QualityTracker {
    /// Create a new quality tracker.
    pub fn new(max_samples: usize) -> Self {
        Self {
            rtt_samples: VecDeque::with_capacity(max_samples),
            loss_samples: VecDeque::with_capacity(max_samples),
            max_samples,
        }
    }

    /// Add a new sample.
    pub fn add_sample(&mut self, rtt_ms: f32, loss_percent: f32) {
        // Add RTT
        if self.rtt_samples.len() >= self.max_samples {
            self.rtt_samples.pop_front();
        }
        self.rtt_samples.push_back(rtt_ms);

        // Add loss
        if self.loss_samples.len() >= self.max_samples {
            self.loss_samples.pop_front();
        }
        self.loss_samples.push_back(loss_percent);
    }

    /// Get current smoothed RTT.
    pub fn rtt(&self) -> f32 {
        if self.rtt_samples.is_empty() {
            return 0.0;
        }
        self.rtt_samples.iter().sum::<f32>() / self.rtt_samples.len() as f32
    }

    /// Get current smoothed loss.
    pub fn loss(&self) -> f32 {
        if self.loss_samples.is_empty() {
            return 0.0;
        }
        self.loss_samples.iter().sum::<f32>() / self.loss_samples.len() as f32
    }

    /// Get current quality.
    pub fn quality(&self) -> Quality {
        if self.rtt_samples.len() < 3 {
            return Quality::Unknown;
        }
        Quality::from_metrics(self.rtt(), self.loss())
    }

    /// Reset tracker.
    pub fn reset(&mut self) {
        self.rtt_samples.clear();
        self.loss_samples.clear();
    }
}

impl Default for QualityTracker {
    fn default() -> Self {
        Self::new(10)
    }
}

/// Bandwidth tracker.
pub struct BandwidthTracker {
    /// Bytes received in current window
    bytes_in: u64,
    /// Bytes sent in current window
    bytes_out: u64,
    /// Last update time
    last_update: std::time::Instant,
    /// Calculated rates
    rate_in: f64,
    rate_out: f64,
    /// Clock owning the measurement window.
    clock: ProtocolClock,
}

impl BandwidthTracker {
    /// Create a new bandwidth tracker.
    pub fn new() -> Self {
        Self::new_with_clock(&ProtocolClock::default())
    }

    /// Create a bandwidth tracker bound to an explicit protocol clock.
    pub fn new_with_clock(clock: &ProtocolClock) -> Self {
        Self {
            bytes_in: 0,
            bytes_out: 0,
            last_update: clock.now(),
            rate_in: 0.0,
            rate_out: 0.0,
            clock: clock.clone(),
        }
    }

    /// Add received bytes.
    pub fn add_received(&mut self, bytes: u64) {
        self.bytes_in += bytes;
        self.maybe_update();
    }

    /// Add sent bytes.
    pub fn add_sent(&mut self, bytes: u64) {
        self.bytes_out += bytes;
        self.maybe_update();
    }

    /// Update rates if enough time has passed.
    fn maybe_update(&mut self) {
        let elapsed = self.clock.elapsed_since(self.last_update);
        if elapsed.as_secs_f64() >= 1.0 {
            let secs = elapsed.as_secs_f64();
            self.rate_in = self.bytes_in as f64 / secs;
            self.rate_out = self.bytes_out as f64 / secs;
            self.bytes_in = 0;
            self.bytes_out = 0;
            self.last_update = self.clock.now();
        }
    }

    /// Get download rate in bytes/sec.
    pub fn download_rate(&self) -> f64 {
        self.rate_in
    }

    /// Get upload rate in bytes/sec.
    pub fn upload_rate(&self) -> f64 {
        self.rate_out
    }

    /// Get download rate formatted.
    pub fn download_rate_formatted(&self) -> String {
        format_bytes_rate(self.rate_in)
    }

    /// Get upload rate formatted.
    pub fn upload_rate_formatted(&self) -> String {
        format_bytes_rate(self.rate_out)
    }
}

impl Default for BandwidthTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Format bytes/sec as human readable.
fn format_bytes_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1024.0 {
        format!("{:.0} B/s", bytes_per_sec)
    } else if bytes_per_sec < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", bytes_per_sec / 1024.0)
    } else if bytes_per_sec < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} MB/s", bytes_per_sec / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB/s", bytes_per_sec / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Format bytes as human readable.
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Format duration as human readable.
pub fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        let secs = secs % 60;
        format!("{}h {}m {}s", hours, mins, secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quality_from_metrics() {
        assert_eq!(Quality::from_metrics(20.0, 0.5), Quality::Excellent);
        assert_eq!(Quality::from_metrics(80.0, 2.0), Quality::Good);
        assert_eq!(Quality::from_metrics(150.0, 5.0), Quality::Fair);
        assert_eq!(Quality::from_metrics(300.0, 15.0), Quality::Poor);
    }

    #[test]
    fn test_quality_bar() {
        assert_eq!(Quality::Excellent.bar(), "#####");
        assert_eq!(Quality::Poor.bar(), "##...");
    }

    #[test]
    fn test_quality_tracker() {
        let mut tracker = QualityTracker::new(5);

        tracker.add_sample(30.0, 0.5);
        tracker.add_sample(35.0, 0.3);
        tracker.add_sample(32.0, 0.4);

        assert_eq!(tracker.quality(), Quality::Excellent);
    }

    #[test]
    fn bandwidth_tracker_uses_explicit_clock_without_sleeping() {
        let source = crate::time_source::test_support::ManualTimeSource::new(
            std::time::Instant::now(),
            std::time::SystemTime::UNIX_EPOCH,
        );
        let clock = crate::time_source::ProtocolClock::from_source(source.clone());
        let mut tracker = BandwidthTracker::new_with_clock(&clock);
        tracker.add_received(1_000);
        source.advance(std::time::Duration::from_secs(2));
        tracker.add_received(1_000);

        assert_eq!(tracker.download_rate(), 1_000.0);
        assert_eq!(tracker.upload_rate(), 0.0);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1500), "1.5 KB");
        assert_eq!(format_bytes(1_500_000), "1.4 MB");
        assert_eq!(format_bytes(1_500_000_000), "1.40 GB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(125), "2m 5s");
        assert_eq!(format_duration(3725), "1h 2m 5s");
    }
}
