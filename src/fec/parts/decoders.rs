#[cfg(any(test, feature = "rust-tests", feature = "benches"))]
pub(crate) use qf_fec::decoders::{validate_decoder_dimensions, Decoder8};

#[cfg(test)]
pub(crate) use qf_fec::decoders::{Decoder16, Decoder4};

#[cfg(test)]
pub(crate) use qf_fec::decoders::{multiply_gf256_with_scratch, WiedemannScratch};
