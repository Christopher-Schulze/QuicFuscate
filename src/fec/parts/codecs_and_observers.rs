// Transport integration remains a root compatibility adapter because the
// transport observer trait and live Connection type are root-owned.
pub(crate) struct FecTransportObserver {
    inner: qf_fec::FecObserver,
}

impl FecTransportObserver {
    pub(crate) fn new() -> Arc<Self> {
        let environment = crate::env_utils::EnvSnapshot::capture();
        Self::new_with_snapshot(&environment)
    }

    pub(crate) fn new_with_snapshot(environment: &crate::env_utils::EnvSnapshot) -> Arc<Self> {
        Arc::new(Self { inner: qf_fec::FecObserver::new_with_snapshot(environment) })
    }

    /// Attach the Brain hints belonging to this connection.
    pub(crate) fn attach_brain_hints(&self, hints: Arc<BrainFecHints>) {
        self.inner.attach_brain_hints(hints);
    }

    /// FEC streaming interval based on current network conditions.
    pub(crate) fn compute_streaming_interval(&self) -> u32 {
        self.inner.compute_streaming_interval()
    }

    /// Return the immutable base interval captured for this observer.
    #[cfg(test)]
    pub(crate) fn base_stream_interval(&self) -> u32 {
        self.inner.base_stream_interval()
    }

    /// Sync FEC-owned runtime hints into transport control deltas.
    pub(crate) fn sync_runtime_hints(&self, conn: &mut crate::transport::Connection) {
        if let Some(ppm) = self.inner.take_redundancy_hint() {
            conn.set_fec_redundancy_ppm(ppm);
        }
    }
}

impl TransportObserver for FecTransportObserver {
    fn on_ack(&self, ack_delay: u64, _ranges: &[(u64, u64)]) {
        self.inner.on_ack(ack_delay);
    }

    fn on_packet_recv(&self, _pn: u64, _pt_len: usize) {}

    fn on_ecn_update(&self, ect0: u64, ect1: u64, ce: u64) {
        self.inner.on_ecn_update(ect0, ect1, ce);
    }
}

/// Thin public wrapper exposing the GF(2^8) streaming decoder for transport integration.
#[cfg(any(test, feature = "rust-tests", feature = "benches"))]
pub struct FecDecoder8(Decoder8);

#[cfg(any(test, feature = "rust-tests", feature = "benches"))]
impl FecDecoder8 {
    /// Create a new GF(2^8) decoder with the given source block size.
    pub fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
        Self(Decoder8::new(k, pool))
    }

    /// Create a GF(2^8) decoder and reject dimensions outside the wire contract.
    pub fn try_new(
        k: usize,
        pool: Arc<MemoryPool>,
    ) -> Result<Self, FecDecoderConfigError> {
        validate_decoder_dimensions(k, 1, wire::MAX_GF8_BLOCK_SOURCE_COUNT)?;
        Ok(Self(Decoder8::new(k, pool)))
    }
    /// Create a benchmark decoder with an explicit decoder policy snapshot.
    #[cfg(feature = "benches")]
    pub fn new_with_decoder_policy(
        k: usize,
        pool: Arc<MemoryPool>,
        decoder_policy: &str,
    ) -> Self {
        let mut policy = FecRuntimePolicy::detect();
        policy.decoder_policy = decoder_policy.to_string();
        Self(Decoder8::new_with_policy(k, pool, &policy))
    }

    /// Create a benchmark decoder with an explicit policy and checked dimensions.
    #[cfg(feature = "benches")]
    pub fn try_new_with_decoder_policy(
        k: usize,
        pool: Arc<MemoryPool>,
        decoder_policy: &str,
    ) -> Result<Self, FecDecoderConfigError> {
        validate_decoder_dimensions(k, 1, wire::MAX_GF8_BLOCK_SOURCE_COUNT)?;
        let mut policy = FecRuntimePolicy::detect();
        policy.decoder_policy = decoder_policy.to_string();
        Ok(Self(Decoder8::new_with_policy(k, pool, &policy)))
    }
    /// Feed a received FEC packet (source or repair) into the decoder.
    pub fn take_packet(&mut self, p: FecPacket) {
        self.0.take_packet(p)
    }
    /// Drain all recovered packets from the decoder output queue.
    pub fn poll_recovered(&mut self) -> VecDeque<FecPacket> {
        self.0.get_partial_result()
    }
}

// Transport imports removed - not needed for FEC module

#[cfg(test)]
mod estimator_tests {
    use super::{KalmanFilter, LossEstimator};

    #[test]
    fn loss_estimator_ignores_non_finite_smoothed_input() {
        let mut estimator = LossEstimator::new();
        estimator.report_smoothed_rate(f32::NAN, 100);
        assert!(estimator.smoothed_loss().is_finite());
        assert_eq!(estimator.smoothed_loss(), 0.0);
        estimator.report_smoothed_rate(f32::INFINITY, 100);
        assert!(estimator.smoothed_loss().is_finite());
    }

    #[test]
    fn kalman_filter_rejects_non_finite_q_r_and_measurement() {
        let mut kf = KalmanFilter::new(f32::NAN, f32::NEG_INFINITY);
        assert!(kf.process_noise().is_finite() && kf.process_noise() > 0.0);
        assert!(kf.measurement_noise().is_finite() && kf.measurement_noise() > 0.0);
        assert_eq!(kf.update(f32::NAN), 0.0);
        let after = kf.update(0.5);
        assert!(after.is_finite() && after > 0.0 && after < 0.5);
    }
}
