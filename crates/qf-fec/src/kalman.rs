//! Scalar Kalman smoothing used by the adaptive FEC estimator.

/// One-dimensional Kalman filter with bounded process and measurement noise.
#[derive(Debug)]
#[doc(hidden)]
pub struct KalmanFilter {
    q: f32,
    r: f32,
    x: f32,
    p: f32,
}

impl KalmanFilter {
    /// Create a filter with finite, positive noise parameters.
    #[doc(hidden)]
    pub fn new(q: f32, r: f32) -> Self {
        let q = if q.is_finite() && q > 0.0 { q.clamp(1e-8, 1.0) } else { 0.001 };
        let r = if r.is_finite() && r > 0.0 { r.clamp(1e-8, 1.0) } else { 0.01 };
        Self { q, r, x: 0.0, p: 1.0 }
    }

    /// Apply one measurement and return the smoothed estimate.
    #[doc(hidden)]
    pub fn update(&mut self, z: f32) -> f32 {
        if !z.is_finite() {
            return self.x;
        }
        self.p += self.q;
        let k = self.p / (self.p + self.r);
        self.x = self.x + k * (z - self.x);
        self.p *= 1.0 - k;
        self.x
    }

    /// Scale process noise within the caller's bounded policy range.
    #[doc(hidden)]
    pub fn scale_process_noise(&mut self, factor: f32, minimum: f32, maximum: f32) {
        self.q = (self.q * factor).clamp(minimum, maximum);
    }

    /// Return the current process-noise covariance for diagnostics and tests.
    #[doc(hidden)]
    pub fn process_noise(&self) -> f32 {
        self.q
    }

    /// Return the current measurement-noise covariance for diagnostics and tests.
    #[doc(hidden)]
    pub fn measurement_noise(&self) -> f32 {
        self.r
    }
}
