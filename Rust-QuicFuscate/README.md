# Rust-QuicFuscate

This directory contains a Rust workspace with several crates mirroring the main C++ modules of the project. The workspace is composed of the following members:

- `core`
- `crypto`
- `fec`
- `stealth`
- `cli`

Each crate is currently a minimal placeholder intended for future Rust implementations. The `cli` crate provides a simple binary entry point.

## Building

Ensure you have Rust installed (https://www.rust-lang.org/tools/install). From this directory run:

```bash
cargo build --workspace
```

This will build all crates in the workspace.
