use super::CryptoContext;
use crate::crypto::aead::{Algorithm, KeyScheduleHooks, Level};
use std::sync::{Arc, Mutex};

#[test]
fn tls_secret_replacement_drop_and_header_protection_erase_owned_bytes() {
    let events = Arc::new(Mutex::new(Vec::<(&'static str, Vec<u8>)>::new()));
    let observed = Arc::clone(&events);
    let _observer = crate::secret::test_observation::install(Arc::new(move |label, bytes| {
        observed.lock().expect("erasure event lock").push((label, bytes.to_vec()));
    }));

    {
        let mut crypto = CryptoContext::default();
        crypto
            .set_read_secret(Level::OneRTT, Algorithm::AES128_GCM, &[0x11; 32])
            .expect("valid read secret");
        crypto
            .set_read_secret(Level::OneRTT, Algorithm::AES128_GCM, &[0x22; 32])
            .expect("valid read secret");
        crypto
            .set_write_secret(Level::OneRTT, Algorithm::AES128_GCM, &[0x33; 32])
            .expect("valid write secret");
        crypto
            .set_write_secret(Level::OneRTT, Algorithm::AES128_GCM, &[0x44; 32])
            .expect("valid write secret");
        crypto.read_secret_1rtt = None;
        drop(crate::crypto::aead::AesHp::from_key(&[0x55; 16]));
    }

    let events = events.lock().expect("erasure events");
    for (label, minimum_events, expected_len) in
        [("tls_1rtt_read_secret", 2, 32), ("tls_1rtt_write_secret", 2, 32), ("aes_hp_key", 1, 16)]
    {
        let matches: Vec<_> =
            events.iter().filter(|(event_label, _)| *event_label == label).collect();
        assert!(
            matches.len() >= minimum_events,
            "missing normal/replacement erasure events for {label}"
        );
        for (_, bytes) in matches {
            assert_eq!(bytes.len(), expected_len);
            assert!(bytes.iter().all(|byte| *byte == 0));
        }
    }
}
