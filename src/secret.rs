//! Explicit owners for secret byte and UTF-8 representations.

use std::ops::Deref;
use zeroize::Zeroize;

/// Heap-owned secret bytes that are overwritten before their allocation is released.
pub(crate) struct SecretBytes {
    bytes: Vec<u8>,
    label: &'static str,
}

impl SecretBytes {
    pub(crate) fn new(bytes: Vec<u8>, label: &'static str) -> Self {
        Self { bytes, label }
    }

    pub(crate) fn zeroed(len: usize, label: &'static str) -> Self {
        Self::new(vec![0u8; len], label)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
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

/// UTF-8 secret backed by [`SecretBytes`].
pub(crate) struct SecretString(SecretBytes);

impl SecretString {
    pub(crate) fn new(value: String, label: &'static str) -> Self {
        Self(SecretBytes::new(value.into_bytes(), label))
    }

    pub(crate) fn as_str(&self) -> &str {
        // SAFETY: construction consumes a valid String, and the inner bytes are
        // never exposed mutably through SecretString.
        unsafe { std::str::from_utf8_unchecked(self.0.as_slice()) }
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self(self.0.clone())
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

#[inline]
pub(crate) fn observe_erasure(label: &'static str, bytes: &[u8]) {
    #[cfg(test)]
    test_observation::notify(label, bytes);

    #[cfg(not(test))]
    {
        let _ = label;
        let _ = bytes;
    }
}

#[cfg(test)]
pub(crate) mod test_observation {
    use std::cell::RefCell;
    use std::sync::Arc;

    type Observer = Arc<dyn Fn(&'static str, &[u8]) + Send + Sync>;

    thread_local! {
        static OBSERVER: RefCell<Option<Observer>> = const { RefCell::new(None) };
    }

    pub(crate) struct ObserverGuard {
        previous: Option<Observer>,
    }

    pub(crate) fn install(observer: Observer) -> ObserverGuard {
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
