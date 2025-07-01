# Rust QuicFuscate Changelog

This changelog summarises the progress of the Rust rewrite and highlights
differences from the original C++ implementation.

## [Unreleased]
### Added
- Initial workspace layout with `core`, `crypto`, `fec` and `stealth` crates.
- Placeholder implementations for cipher selection and FEC logic.

### Changed
- Build system switched from CMake to Cargo for the Rust modules.
- Modules are compiled as part of a Cargo workspace instead of individual C++
  libraries.

### Removed
- Direct dependency on the legacy C++ build for new functionality. Existing C++
  code remains while components are ported gradually.

The original C++ changelog can be found in [`docs/Changelog.md`](../../docs/Changelog.md).
