//! Compatibility projection for the transport batch workspace leaf.
//!
//! The batch processor is an explicit rust parity/test-only surface. Its implementation and
//! tests live in `qf-transport-batch`; this module preserves the historical root path.

#[cfg(any(test, feature = "rust-tests"))]
pub use qf_transport_batch::BatchProcessor;
