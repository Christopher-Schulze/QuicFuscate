# QuicFuscate Implementation Roadmap

This document outlines the comprehensive, phased implementation plan to build a production-ready version of QuicFuscate. It replaces the previous `todo.md` and is based on `PLAN.txt` and a detailed architectural analysis. The current prototype is a non-functional facade and requires a complete rebuild of core components.

---

## Phase 1: Foundational Fixes & Performance Optimization (`optimize.rs`)

The goal of this phase is to build a high-performance memory management layer to eliminate copies and reduce allocation overhead, which is critical for the entire data path.

-   **Implement Production-Ready `MemoryPool`:**
    -   [ ] Design and implement a `MemoryPool` struct.
    -   [ ] Ensure all allocated memory blocks are 64-byte aligned for optimal CPU cache performance.
    -   [ ] Implement efficient pool growth and shrinkage strategies.
    -   [ ] Add robust thread-safety mechanisms for multi-threaded access.

-   **Integrate `ZeroCopyBuffer`:**
    -   [ ] Define a `ZeroCopyBuffer` type that leverages the `MemoryPool`.
    -   [ ] This buffer should manage its lifecycle by returning memory to the pool on `Drop`.
    -   [ ] Refactor all parts of the codebase that currently use `Vec<u8>` or similar heap-allocated buffers for packet data to use `ZeroCopyBuffer`.

---

## Phase 2: FEC Module Rebuild (`fec.rs`)

This phase involves a from-scratch rebuild of the Forward Error Correction (FEC) module to meet the "ASW-RLNC-X" specification for maximum reliability and performance.

-   **Rebuild FEC Core Logic from Scratch:**
    -   [ ] Remove the existing placeholder FEC implementation entirely.
    -   [ ] Design the core traits and structures for encoding and decoding based on Random Linear Network Coding (RLNC).

-   **Implement Cauchy Matrix Encoder:**
    -   [ ] Implement a highly-efficient encoder using a Cauchy matrix over a Galois Field (e.g., GF(2^8)).
    -   [ ] This encoder will generate repair symbols from source symbols.
    -   [ ] Optimize matrix operations for performance.

-   **Implement High-Performance Decoder:**
    -   [ ] Implement a decoder capable of reconstructing the original data from a set of source and repair symbols.
    -   [ ] The decoder must implement a hybrid approach:
        -   Use **Sparse Gaussian Elimination** for typical loss scenarios.
        -   Integrate the **Wiedemann algorithm** for handling larger, more complex recovery scenarios efficiently.
    -   [ ] Ensure the decoder is robust against various packet loss patterns.

---

## Phase 3: Stealth Module Hardening (`stealth.rs`)

This phase focuses on replacing simulated stealth features with hardened, production-grade implementations to provide true traffic obfuscation.

-   **Implement True uTLS Fingerprint Spoofing:**
    -   [ ] Remove the current simulated fingerprinting logic.
    -   [ ] Integrate a library or implement custom logic to directly manipulate the QUIC and TLS handshake parameters to precisely match real browser fingerprints (e.g., Chrome, Firefox).
    -   [ ] Add missing browser profiles for **Opera** and **Brave**.
    -   [ ] Implement a mechanism to dynamically switch profiles.

-   **Implement SIMD-Accelerated XOR Obfuscation:**
    -   [ ] Replace the basic, placeholder XOR obfuscation with a high-performance version.
    -   [ ] Use SIMD intrinsics (e.g., AVX2, SSE4.1) to accelerate the XOR operations on packet data.
    -   [ ] Implement a rolling key mechanism for the XOR stream to prevent trivial analysis.

---

## Phase 4: Core Logic Integration (`core.rs`)

This is the most critical phase, where the rebuilt, functional modules are integrated into the main data path. The goal is to make the `send` and `recv` functions fully operational and feature-complete.

-   **Integrate `MemoryPool` into Data Path:**
    -   [ ] Modify `send()` and `recv()` functions to exclusively use the `ZeroCopyBuffer` from the `MemoryPool` for all packet operations.
    -   [ ] Ensure zero-copy behavior is maintained throughout the entire data processing pipeline.

-   **Integrate FEC into Packet Processing:**
    -   [ ] In the `send()` path, apply the `fec.rs` encoder to generate repair packets for outgoing data streams.
    -   [ ] In the `recv()` path, buffer incoming packets and use the `fec.rs` decoder to reconstruct missing packets when necessary.

-   **Integrate Custom AEAD Ciphers:**
    -   [ ] This is a high-risk task. Investigate the internals of the `quiche` library to find a way to replace its default TLS ciphers (AES-GCM, ChaCha20-Poly1305).
    -   [ ] Implement hooks or patches to integrate the custom **AEGIS-256** and **MORUS-1280-256** ciphers from `crypto.rs`.
    -   [ ] If direct integration is not feasible, design a "crypto-wrapper" layer that applies the custom cipher encryption *after* `quiche` encrypts and *before* `quiche` decrypts, while managing nonces carefully. This is the fallback strategy.

---

## Phase 5: Binary Finalization & CLI (`main.rs`)

The final phase is to create a usable binary with a proper command-line interface for end-users.

-   **Implement `clap`-based CLI:**
    -   [ ] Add `clap` as a dependency.
    -   [ ] Define the CLI structure with subcommands for `client` and `server` modes.
    -   [ ] **Client Mode Arguments:**
        -   `--remote <address:port>`: Server to connect to.
        -   `--local <address:port>`: Local port to listen on for applications.
        -   `--profile <name>`: uTLS profile to use (e.g., `chrome`, `firefox`, `brave`).
    -   **Server Mode Arguments:**
        -   `--listen <address:port>`: Address to listen on for incoming clients.
        -   `--cert <path>`: Path to the TLS certificate file.
        -   `--key <path>`: Path to the TLS private key file.

-   **Implement Main Application Logic:**
    -   [ ] Write the `main` function logic to parse the CLI arguments.
    -   [ ] Launch the QuicFuscate core in either client or server mode based on the parsed arguments.
    -   [ ] Handle process lifecycle, signals, and graceful shutdown.
