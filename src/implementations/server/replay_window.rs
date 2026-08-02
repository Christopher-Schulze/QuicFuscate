//! Sliding-window anti-replay protection for QKey auth frames.
//!
//! `ReplayWindow` tracks recently-seen `(timestamp, nonce)` pairs inside a
//! fixed-width time window. Each timestamp second owns a small bloom-style bit
//! mask of nonce fingerprints, so a replayed frame (same timestamp + nonce)
//! is detected while fresh frames with new nonces are accepted.
//!
//! The window slides forward monotonically: once a timestamp beyond the
//! current window is observed, the base advances and old slots are discarded.

use crate::crypto::hkdf::sha256;

/// Number of bloom bits per one-second timestamp slot. 512 bits keeps the
/// collision probability for two distinct nonces in the same second around
/// ~0.2%, which is acceptable because a colliding client simply retries with a
/// fresh nonce.
const BITS_PER_SLOT: u64 = 512;
const WORDS_PER_SLOT: usize = (BITS_PER_SLOT / u64::BITS as u64) as usize; // 8
const SLOT_MASK: u64 = BITS_PER_SLOT - 1; // 0x1FF

/// Sliding-window anti-replay protection for auth frames.
pub struct ReplayWindow {
    /// Number of one-second timestamp slots tracked.
    window_size: u64,
    /// Bit array of `window_size * WORDS_PER_SLOT` u64 words. Slot `s` occupies
    /// words `[s * WORDS_PER_SLOT .. (s+1) * WORDS_PER_SLOT)`.
    bitmap: Vec<u64>,
    /// Timestamp of slot 0 (the oldest tracked second).
    base_timestamp: Option<u64>,
}

impl ReplayWindow {
    /// Create a new replay window covering `window_size` seconds.
    pub fn new(window_size: u64) -> Self {
        let window_size = window_size.max(1);
        let words = (window_size as usize) * WORDS_PER_SLOT;
        Self { window_size, bitmap: vec![0u64; words], base_timestamp: None }
    }

    /// Check an auth frame's `(timestamp, nonce)` and mark it as seen.
    ///
    /// Returns `false` if the frame is a replay (already seen) or stale
    /// (timestamp falls below the current window). Returns `true` and records
    /// the frame if it is fresh.
    pub fn check_and_mark(&mut self, timestamp: u64, nonce: &[u8; 16]) -> bool {
        // First-ever frame seeds the window base.
        if self.base_timestamp.is_none() && self.is_empty() {
            self.base_timestamp = Some(timestamp);
        }

        let Some(base_timestamp) = self.base_timestamp else {
            return false;
        };

        // Stale: below the window's lower edge -> replay or too old.
        if timestamp < base_timestamp {
            return false;
        }

        // Future: slide the window forward so the new timestamp lands at the top.
        if timestamp.saturating_sub(base_timestamp) >= self.window_size {
            self.slide_to(timestamp);
        }

        let Some(base_timestamp) = self.base_timestamp else {
            return false;
        };
        let slot = (timestamp - base_timestamp) as usize;
        let bit = self.nonce_bit(timestamp, nonce);
        let word_idx = slot * WORDS_PER_SLOT + (bit / u64::BITS as u64) as usize;
        let bit_mask = 1u64 << (bit % u64::BITS as u64);

        if self.bitmap[word_idx] & bit_mask != 0 {
            return false; // replay within this slot
        }
        self.bitmap[word_idx] |= bit_mask;
        true
    }

    /// Drop slots older than `now - window_size`.
    ///
    /// The timestamp is expressed in the same seconds-based domain as auth
    /// frames. Pruning advances the logical base even when the bitmap is
    /// empty, so a quiet registry cannot later accept a newly-seen frame whose
    /// timestamp is already outside the replay window.
    pub fn prune(&mut self, now: u64) {
        self.advance_base_to(now.saturating_sub(self.window_size));
    }

    /// Returns true if no frames have been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.bitmap.iter().all(|&w| w == 0)
    }

    /// Advance the window so that `timestamp` maps to the final slot, zeroing
    /// the newly exposed region.
    fn slide_to(&mut self, timestamp: u64) {
        // New base places `timestamp` at the top slot.
        let new_base = timestamp.saturating_sub(self.window_size - 1);
        self.advance_base_to(new_base);
    }

    fn advance_base_to(&mut self, new_base: u64) {
        let Some(base_timestamp) = self.base_timestamp else {
            self.base_timestamp = Some(new_base);
            return;
        };
        if new_base <= base_timestamp {
            return;
        }
        let delta = (new_base - base_timestamp) as usize;
        if delta >= self.window_size as usize {
            // Entire window rolled past: clear everything.
            self.bitmap.fill(0);
        } else {
            let shift_words = delta * WORDS_PER_SLOT;
            let total_words = self.bitmap.len();
            // Shift remaining words to the front, zero the tail.
            self.bitmap.copy_within(shift_words..total_words, 0);
            for w in &mut self.bitmap[total_words - shift_words..] {
                *w = 0;
            }
        }
        self.base_timestamp = Some(new_base);
    }

    /// Compute the bloom bit index within a slot for `(timestamp, nonce)`.
    fn nonce_bit(&self, timestamp: u64, nonce: &[u8; 16]) -> u64 {
        let mut msg = [0u8; 24];
        msg[..8].copy_from_slice(&timestamp.to_be_bytes());
        msg[8..].copy_from_slice(nonce);
        let h = sha256(&msg);
        let raw = u64::from_be_bytes(h[0..8].try_into().expect("8 bytes"));
        raw & SLOT_MASK
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce(seed: u8) -> [u8; 16] {
        let mut n = [0u8; 16];
        for (i, b) in n.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        n
    }

    #[test]
    fn first_frame_accepted() {
        let mut rw = ReplayWindow::new(64);
        assert!(rw.check_and_mark(1000, &nonce(1)));
    }

    #[test]
    fn exact_replay_rejected() {
        let mut rw = ReplayWindow::new(64);
        let n = nonce(2);
        assert!(rw.check_and_mark(1000, &n));
        assert!(!rw.check_and_mark(1000, &n));
    }

    #[test]
    fn same_timestamp_different_nonce_accepted() {
        let mut rw = ReplayWindow::new(64);
        assert!(rw.check_and_mark(1000, &nonce(3)));
        assert!(rw.check_and_mark(1000, &nonce(4)));
    }

    #[test]
    fn different_timestamps_accepted() {
        let mut rw = ReplayWindow::new(64);
        assert!(rw.check_and_mark(1000, &nonce(5)));
        assert!(rw.check_and_mark(1001, &nonce(5)));
    }

    #[test]
    fn stale_timestamp_below_window_rejected() {
        let mut rw = ReplayWindow::new(8);
        assert!(rw.check_and_mark(1000, &nonce(6)));
        // Slide forward to 1010.
        assert!(rw.check_and_mark(1010, &nonce(7)));
        // 1000 is now below the window base (1010 - 7 = 1003).
        assert!(!rw.check_and_mark(1000, &nonce(6)));
    }

    #[test]
    fn window_slides_forward_on_future_timestamp() {
        let mut rw = ReplayWindow::new(8);
        assert!(rw.check_and_mark(1000, &nonce(8)));
        // Jump far beyond the window: old slots must be discarded.
        assert!(rw.check_and_mark(2000, &nonce(9)));
        // The original (1000, nonce(8)) is now below the base -> rejected.
        assert!(!rw.check_and_mark(1000, &nonce(8)));
    }

    #[test]
    fn replay_after_slide_within_window_still_detected() {
        let mut rw = ReplayWindow::new(16);
        let n = nonce(10);
        assert!(rw.check_and_mark(1000, &n));
        // Move forward but keep 1000 inside the new window.
        assert!(rw.check_and_mark(1005, &nonce(11)));
        assert!(!rw.check_and_mark(1000, &n));
    }

    #[test]
    fn nonce_uniqueness_via_hash_index() {
        let mut rw = ReplayWindow::new(64);
        // Many distinct nonces in the same second should all be accepted
        // (barring rare bloom collisions).
        let mut accepted = 0;
        for i in 0..64u8 {
            if rw.check_and_mark(1000, &nonce(i)) {
                accepted += 1;
            }
        }
        assert!(accepted >= 60, "expected most nonces accepted, got {accepted}");
    }

    #[test]
    fn zero_window_size_clamped_to_one() {
        let mut rw = ReplayWindow::new(0);
        assert!(rw.check_and_mark(1000, &nonce(12)));
        assert!(!rw.check_and_mark(1000, &nonce(12)));
    }

    #[test]
    fn is_empty_initially_true() {
        let rw = ReplayWindow::new(32);
        assert!(rw.is_empty());
    }

    #[test]
    fn epoch_timestamp_is_not_an_initialization_sentinel() {
        let mut rw = ReplayWindow::new(32);
        assert_eq!(rw.base_timestamp, None);
        let n = nonce(18);
        assert!(rw.check_and_mark(0, &n));
        assert_eq!(rw.base_timestamp, Some(0));
        assert!(!rw.check_and_mark(0, &n));
    }

    #[test]
    fn prune_on_empty_is_noop() {
        let mut rw = ReplayWindow::new(32);
        rw.prune(0); // must not panic
        assert!(rw.is_empty());
    }

    #[test]
    fn prune_discards_slots_older_than_now_minus_window() {
        let mut rw = ReplayWindow::new(8);
        assert!(rw.check_and_mark(991, &nonce(13)));
        assert!(rw.check_and_mark(992, &nonce(14)));

        rw.prune(1000);

        assert!(!rw.check_and_mark(991, &nonce(15)));
        assert!(rw.check_and_mark(992, &nonce(16)));
    }

    #[test]
    fn prune_advances_empty_window_for_stale_rejection() {
        let mut rw = ReplayWindow::new(8);
        rw.prune(1000);

        assert!(!rw.check_and_mark(991, &nonce(17)));
        assert!(rw.check_and_mark(992, &nonce(18)));
    }
}
