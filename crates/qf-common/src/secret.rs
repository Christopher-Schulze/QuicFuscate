//! Explicit owners for secret byte and UTF-8 representations.

use std::ops::Deref;
use zeroize::Zeroize;

/// Heap-owned secret bytes that are overwritten before their allocation is released.
pub struct SecretBytes {
    bytes: Vec<u8>,
    label: &'static str,
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>, label: &'static str) -> Self {
        Self { bytes, label }
    }

    pub fn zeroed(len: usize, label: &'static str) -> Self {
        Self::new(vec![0u8; len], label)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    fn erase(&mut self) {
        self.bytes.as_mut_slice().zeroize();
        observe_erasure(self.label, self.bytes.as_slice());
        self.bytes.clear();
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::new(self.bytes.clone(), self.label)
    }
}

impl Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.erase();
    }
}

/// Error returned when raw secret bytes are not valid UTF-8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretStringUtf8Error;

/// UTF-8 secret backed by a private [`String`] owner.
pub struct SecretString {
    value: String,
    label: &'static str,
}

impl SecretString {
    pub fn new(value: String, label: &'static str) -> Self {
        Self { value, label }
    }

    /// Construct a UTF-8 secret from a byte owner without retaining invalid input.
    pub fn try_from_bytes(bytes: SecretBytes) -> Result<Self, SecretStringUtf8Error> {
        let label = bytes.label;
        let value = match std::str::from_utf8(bytes.as_slice()) {
            Ok(value) => value.to_owned(),
            Err(_) => return Err(SecretStringUtf8Error),
        };
        drop(bytes);
        Ok(Self { value, label })
    }

    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self::new(self.value.clone(), self.label)
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        let value = std::mem::take(&mut self.value);
        drop(SecretBytes::new(value.into_bytes(), self.label));
    }
}

impl Deref for SecretString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::{SecretBytes, SecretString, SecretStringUtf8Error};
    use std::sync::{Arc, Mutex};

    #[test]
    fn secret_string_preserves_valid_utf8_and_clone() {
        let secret = SecretString::new("pässwörd".to_owned(), "secret_string_valid");
        let clone = secret.clone();

        assert_eq!(secret.as_str(), "pässwörd");
        assert_eq!(clone.as_str(), "pässwörd");
    }

    #[test]
    fn secret_string_erases_owned_utf8_bytes() {
        let events = Arc::new(Mutex::new(Vec::<(&'static str, Vec<u8>)>::new()));
        let observed = Arc::clone(&events);
        let _observer = super::test_observation::install(Arc::new(move |label, bytes| {
            observed.lock().expect("erasure event lock").push((label, bytes.to_vec()));
        }));

        {
            let secret = SecretString::new("secret".to_owned(), "secret_string_owned");
            assert_eq!(secret.as_str(), "secret");
        }

        let events = events.lock().expect("erasure events");
        assert_eq!(events.as_slice(), &[("secret_string_owned", vec![0; 6])]);
    }

    #[test]
    fn secret_string_rejects_invalid_utf8_and_erases_rejected_bytes() {
        let events = Arc::new(Mutex::new(Vec::<(&'static str, Vec<u8>)>::new()));
        let observed = Arc::clone(&events);
        let _observer = super::test_observation::install(Arc::new(move |label, bytes| {
            observed.lock().expect("erasure event lock").push((label, bytes.to_vec()));
        }));

        let result = SecretString::try_from_bytes(SecretBytes::new(
            vec![0xff, 0xfe],
            "secret_string_invalid",
        ));

        assert!(matches!(result, Err(SecretStringUtf8Error)));
        let events = events.lock().expect("erasure events");
        assert_eq!(events.as_slice(), &[("secret_string_invalid", vec![0; 2])]);
    }

    #[test]
    fn secret_string_checked_boundary_accepts_utf8_and_erases_source_owner() {
        let events = Arc::new(Mutex::new(Vec::<(&'static str, Vec<u8>)>::new()));
        let observed = Arc::clone(&events);
        let _observer = super::test_observation::install(Arc::new(move |label, bytes| {
            observed.lock().expect("erasure event lock").push((label, bytes.to_vec()));
        }));

        let secret = SecretString::try_from_bytes(SecretBytes::new(
            "päss".as_bytes().to_vec(),
            "secret_string_checked",
        ))
        .expect("valid UTF-8 must be accepted");
        assert_eq!(secret.as_str(), "päss");
        drop(secret);

        let events = events.lock().expect("erasure events");
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|(label, bytes)| {
            *label == "secret_string_checked"
                && bytes.len() == "päss".len()
                && bytes.iter().all(|byte| *byte == 0)
        }));
    }
}

#[inline]
pub fn observe_erasure(label: &'static str, bytes: &[u8]) {
    #[cfg(any(test, feature = "rust-tests"))]
    test_observation::notify(label, bytes);

    #[cfg(not(any(test, feature = "rust-tests")))]
    {
        let _ = label;
        let _ = bytes;
    }
}

#[cfg(any(test, feature = "rust-tests"))]
pub mod test_observation {
    use std::cell::RefCell;
    use std::sync::Arc;

    type Observer = Arc<dyn Fn(&'static str, &[u8]) + Send + Sync>;

    thread_local! {
        static OBSERVER: RefCell<Option<Observer>> = const { RefCell::new(None) };
    }

    pub struct ObserverGuard {
        previous: Option<Observer>,
    }

    pub fn install(observer: Observer) -> ObserverGuard {
        let previous = OBSERVER.with(|slot| slot.replace(Some(observer)));
        ObserverGuard { previous }
    }

    pub(super) fn notify(label: &'static str, bytes: &[u8]) {
        OBSERVER.with(|slot| {
            if let Some(observer) = slot.borrow().as_ref() {
                observer(label, bytes);
            }
        });
    }

    impl Drop for ObserverGuard {
        fn drop(&mut self) {
            let previous = self.previous.take();
            OBSERVER.with(|slot| {
                slot.replace(previous);
            });
        }
    }
}
