//! Callback contracts for the MASQUE transport surface.

use std::sync::{Arc, Mutex};

/// Callback invoked for a MASQUE capsule carrying a stream identifier.
#[doc(hidden)]
pub type CapsuleHandler = Arc<Mutex<Box<dyn FnMut(u64, &[u8]) + Send>>>;

/// Callback invoked for a MASQUE datagram payload.
#[doc(hidden)]
pub type DatagramHandler = Arc<Mutex<Box<dyn FnMut(&[u8]) + Send>>>;
