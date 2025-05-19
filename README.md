# QuicSand: QUIC-based VPN with Advanced Stealth & Resilience Features

<div align="center">
  <img src="logo.png" alt="QuicSand Logo" width="300">
</div>

## Overview

QuicSand is a highly optimized QUIC-based VPN system with a focus on strong stealth capabilities and extreme robustness in demanding network environments. The project combines state-of-the-art optimization techniques like zero-copy data paths and SIMD-accelerated cryptography with advanced stealth mechanisms that enable reliable communication even in restrictive network environments.

QuicSand: All Features and Optimizations at a Glance

### Core Technology
- **QUIC Protocol**: Modern UDP-based transport layer
- **C++17 Implementation**: High-performance codebase
- **Cross-Platform**: Runs on Linux, macOS (Intel/ARM), Windows

### Performance Optimizations
- **Zero-Copy**: eBPF/XDP integration for direct packets without kernel copies
- **Lock-Free Queues**: Non-blocking data structures for multi-core
- **CPU Pinning**: Affinity-based core assignment
- **NUMA Optimizations**: Memory access patterns for multi-socket servers
- **Memory Pool**: Pre-allocated memory regions against fragmentation
- **Burst Buffering**: Packet batching for higher throughput

### SIMD Acceleration
- **CPU Feature Detection**: Automatic detection of SSE/SSE2/SSE3/SSSE3/SSE4/AVX/AVX2/AES-NI on x86 and NEON/Crypto on ARM
- **AES-NI/PCLMULQDQ**: Hardware-accelerated AES-GCM encryption (up to 5.7x on x86, 4.75x on ARM)
- **Batch Processing**: 4-block batch processing for parallel cryptography
- **NEON Support**: ARM-optimized crypto operations for Apple M1/M2
- **SIMD FEC**: Vectorized Forward Error Correction with 4x loop unrolling and prefetching
- **Ascon-SIMD**: Accelerated post-quantum cryptography
- **Cross-Platform Optimizations**: Transparent abstraction with automatic feature selection
- **GHASH Acceleration**: Karatsuba-optimized multiplication for GF(2^128) (8x faster)
- **XOR Operations**: Highly optimized bitwise operations with chunk-based processing (2.65-3.06x faster)
- **Galois Field Optimizations**: SIMD-accelerated operations for FEC (5-8x faster)

### Cryptographic Features
- **AES-128-GCM**: Hardware-accelerated symmetric encryption
- **Ascon-128a**: Lightweight cryptography for resource-constrained devices
- **X25519**: Elliptic curves for key exchange
- **TLS 1.3**: State-of-the-art encryption layer

### Forward Error Correction
- **Tetrys-FEC**: Adaptive Forward Error Correction
- **SIMD-optimized Matrix Operations**: For FEC encoding (up to 6x faster) and decoding (up to 2.8x faster)
- **Dynamic Adjustment**: Redundancy level based on network conditions
- **Seamless Fallback**: Automatic support for non-SIMD hardware

### Stealth Features
#### Deep Packet Inspection (DPI) Evasion
- **Packet Fragmentation**: Splitting packets to evade detection
- **Timing Randomization**: Random delays against traffic analysis
- **Payload Randomization**: Obfuscation of payload signatures
- **TLS Imitation**: Mimicking common TLS browser communication
- **Protocol Obfuscation**: Obfuscation of the QUIC protocol

#### SNI Hiding
- **Domain Fronting**: Separation of SNI and Host header
- **Encrypted Client Hello (ECH)**: Full encryption of SNI
- **SNI-Padding**: Extending SNI with random data
- **SNI-Split**: Splitting SNI across multiple packets
- **SNI Omission**: Selective omission of SNI extension
- **ESNI Support**: Legacy support

#### Traffic Masking
- **HTTP-Mimicry**: Disguise as regular web traffic
- **HTTP/3 Masquerading**: VPN traffic disguised as HTTP/3
- **Fake-TLS**: Emulation of various TLS implementations
- **Fake-Headers**: HTTP header manipulation for obfuscation

#### QUIC Spin Bit
- **Spin Bit Randomizer**: Various strategies (Random, Alternating, Constant)
- **Timing-based Manipulation**: Time-controlled spin bit changes
- **Browser Mimicry**: Imitation of known QUIC implementations

#### Browser Fingerprinting
- **uTLS Integration**: Emulation of browser TLS fingerprints
- **Browser Profiles**: Chrome, Firefox, Safari, Edge, Opera, etc.
- **Dynamic Fingerprinting**: Changing fingerprints per session

### Network Robustness
- **BBRv2 Congestion Control**: Modern congestion control
- **Connection Migration**: Seamless switching between networks
- **Path MTU Discovery**: Optimal packet size adjustment
- **0-RTT Session Resumption**: Faster reconnections

### Management & Configuration
- **Stealth Manager**: Central stealth level configuration (0-3)
- **CLI and GUI**: Command line and Flutter-based user interface
- **Profile-based Configuration**: Predefined setting profiles
- **Fallback Mechanisms**: Automatic detection and evasion
- **Platform-specific Optimization**: Automatic adaptation to available hardware

### Dependencies

- **Required**:
  - CMake 3.15+
  - C++17 compatible compiler (GCC 9+, Clang 10+, MSVC 2019+)
  - Boost 1.74+
  - OpenSSL 1.1.1+ or 3.0+ with QUIC support
  - libebpf (Linux only for XDP support)
  - libnuma (for NUMA optimizations)
  
- **Optional**:
  - Flutter SDK (for GUI)
  - Google Test (for tests)
  - Google Benchmark (for benchmarks)

## Project Structure

QuicSand is modularly structured and consists of the following main components:

### Core Components

- **`core/`**: Implementation of the QUIC protocol stack
  - `quic_connection.cpp/.hpp`: Base class for QUIC connections with zero-copy optimizations
  - `quic_stream.cpp/.hpp`: Stream abstraction for QUIC data
  - `zero_copy_buffer.cpp/.hpp`: Zero-copy buffer for high-performance data transfer
  - `zero_copy_receiver.cpp/.hpp`: Receiver implementation for zero-copy data paths
  - `simd_optimizations.hpp`: Central header for SIMD acceleration
  - `simd_optimizations.cpp`: CPU feature detection for x86/x64 and ARM
  
- **`simd/`**: Platform-specific SIMD implementations
  - `simd_dispatcher.cpp`: Intelligent selection of optimal implementations
  - `arm_simd_impl.cpp`: ARM-NEON specific optimizations
  - `x86_simd_impl.cpp`: Intel/AMD (SSE/AVX/AES-NI) specific optimizations

- **`crypto/`**: Cryptographic components
  - `aes_gcm.cpp/.hpp`: Hardware-accelerated AES-128-GCM implementation
  - `ascon.cpp/.hpp`: Ascon-128a as lightweight alternative
  - `key_exchange.cpp/.hpp`: X25519-based key exchange
  - `random.cpp/.hpp`: Cryptographically secure random number generation

- **`fec/`**: Forward Error Correction
  - `tetrys.cpp/.hpp`: Tetrys-FEC implementation
  - `tetrys_encoder.cpp/.hpp`: Optimized Tetrys encoder
  - `tetrys_decoder.cpp/.hpp`: Optimized Tetrys decoder
  - `block_encoder.cpp/.hpp`: Block-based FEC encoding

### Stealth Components

- **`stealth/`**: Comprehensive stealth functionalities
  - `stealth_manager.cpp/.hpp`: Central manager for stealth features
  - `dpi_evasion.cpp/.hpp`: Deep Packet Inspection evasion techniques
  - `sni_hiding.cpp/.hpp`: Server Name Indication hiding (ECH, Domain Fronting, SNI-Split)
  - `spin_bit_randomizer.cpp/.hpp`: QUIC Spin Bit randomization
  - `fake_tls.cpp/.hpp`: TLS camouflage and emulation
  - `fake_headers.cpp/.hpp`: HTTP header manipulation
  - `utls.cpp/.hpp`: Browser fingerprint emulation
  - `http3_masquerading.cpp/.hpp`: HTTP/3 masquerading for VPN traffic

- **`tls/`**: TLS integration
  - `utls_client_configurator.cpp/.hpp`: Browser fingerprint configuration
  - `tls_context.cpp/.hpp`: TLS context management
  - `certificate_verifier.cpp/.hpp`: Certificate verification

### User Interfaces

- **`cli/`**: Command line interface
  - `main.cpp`: Entry point for CLI application
  - `config.cpp/.hpp`: Configuration management
  - `commands.cpp/.hpp`: Command processing

- **`flutter_ui/`**: Graphical user interface
  - `lib/`: Flutter source code
  - `android/`: Android-specific code
  - `ios/`: iOS-specific code
  - `macos/`: macOS-specific code

### Tests and Benchmarks

- **`tests/`**: Comprehensive test suites
  - `unit/`: Unit tests for individual components
  - `integration/`: Integration tests for component interaction
  - `benchmarks/`: Performance tests for critical functions
  - `simd_test_simple.cpp`: Simple tests for SIMD optimizations
  - `simd_comprehensive_benchmark.cpp`: Comprehensive performance tests for SIMD optimizations
  - `simd_end_to_end_test.cpp`: End-to-end test of SIMD optimizations in the QUIC pipeline
  - `platform_simd_test.cpp`: Cross-platform test for ARM and x86 architectures
  - `quic_simd_integration_test.cpp`: Integration test for SIMD functions in the QUIC stack
  - `sni_hiding_test.cpp`: Tests for SNI hiding functionalities

## uTLS Integration

QuicSand integrates uTLS technology to disguise VPN traffic as regular browser traffic. This integration allows emulating various browser fingerprints to evade traffic analysis.

### Supported Browser Fingerprints

- **Chrome Latest**: Emulates the latest Chrome version
- **Firefox Latest**: Emulates the latest Firefox version
- **Safari Latest**: Emulates the latest Safari version
- **Edge Chromium**: Emulates Microsoft Edge (Chromium-based)
- **Safari iOS**: Emulates Safari on iOS devices
- **Chrome Android**: Emulates Chrome on Android devices
- **Brave Latest**: Emulates the Brave browser
- **Opera Latest**: Emulates the Opera browser
- **Legacy Browser**: Older versions of Chrome (v70) and Firefox (v63)

### Usage

#### Configuration in the GUI

1. Start the QuicSand app
2. Navigate to "Connection Settings" > "Stealth Settings"
3. Under "Browser Fingerprint," select the desired browser
4. Save the settings and establish the connection

#### Using the CLI

```bash
# Display available CLI options
./build/bin/quicsand-cli --help

# Establish a connection with Chrome fingerprint
./build/bin/quicsand-cli --server example.com --port 443 --fingerprint chrome

# Establish a connection with Firefox fingerprint
./build/bin/quicsand-cli --server example.com --port 443 --fingerprint firefox

# Establish a connection without uTLS (standard TLS)
./build/bin/quicsand-cli --server example.com --port 443 --no-utls

# Enable peer verification with CA certificate
./build/bin/quicsand-cli --server example.com --verify-peer --ca-file /path/to/ca.crt

# List available browser fingerprints
./build/bin/quicsand-cli --list-fingerprints
```

### Known Limitations

The current uTLS integration has the following known limitations:

1. **Quiche Compatibility**: The integration is sensitive to the used Quiche version. Tested and optimized for Quiche 0.24.2.

2. **Address Issues**: With some Quiche versions, there may be issues with socket address structures. The implementation provides multiple fallback mechanisms to work around these.

3. **SSL_CTX_set_quic_method**: This function must be available in the used OpenSSL library; otherwise, a fallback mechanism with limited uTLS functionality is used.

4. **Error Messages**: Warnings like `SSL_CTX_set_quic_method not available` indicate that the integration is running in a degraded mode.

### Troubleshooting

#### Connection Issues

1. **"SSL_CTX_set_quic_method not available"**:
   - Check if OpenSSL was compiled with QUIC support
   - Ensure the OpenSSL version is compatible with Quiche

2. **"Failed to initialize UTLSClientConfigurator"**:
   - Verify the specified browser fingerprints are correct
   - Test with the standard fingerprint (Chrome_Latest)

3. **"Cannot create SSL connection without context"**:
   - The SSL initialization failed, but the program attempts to establish a connection
   - Use the `--verbose` option for more detailed error information

#### Compilation Issues

1. Ensure all dependencies are installed:
   ```bash
   brew install boost openssl@3 cloudflare-quiche
   ```

2. Check the paths to libraries in the Makefiles

3. For specific uTLS features, a patched version of Quiche might be required:
   ```bash
   git clone https://github.com/yourusername/quiche-patched.git
   cd quiche-patched && make install
   ```

### Development and Extension

To extend or modify the uTLS integration:

1. **New Browser Fingerprints**: Add new fingerprint profiles in `tls/utls_client_configurator.cpp`:
   ```cpp
   FingerprintProfile create_chrome_profile() {
       FingerprintProfile profile;
       profile.name = "Chrome_Latest";
       // Add cipher suites, curves, and extensions here
       return profile;
   }
   ```

2. **Test the Integration**: Use the test binaries:
   ```bash
   make -f Makefile.utls
   ./test_utls_simple
   ```

3. **Improve Robustness**: The current implementation is fault-tolerant but can be further improved, especially in handling various network environments.

### Technical Details

The uTLS integration is based on the `UTLSClientConfigurator` class, which configures SSL_CTX and SSL objects with specific fingerprint properties. The `QuicConnection` class uses these configured objects to generate TLS ClientHello messages that mimic authentic browser connections.

## Performance Tests

The performance tests show no significant performance degradation due to the uTLS integration, while the stealth capability is significantly improved. Detailed performance data can be found in the `benchmarks.md` file.

## Performance Optimizations

QuicSand integrates numerous high-performance components that ensure maximum performance and minimal latency:

### Zero-Copy Data Paths

- **eBPF/XDP Integration**: Direct packet transfer between network interface and application memory without kernel copies
- **Kernel Bypass**: Bypassing the network stack for minimal latency
- **Shared Memory IPC**: Efficient inter-process communication without data copies
- **Zero-Copy Buffer**: Specialized buffer classes optimized for direct memory access

### Multi-Core Optimizations

- **Lock-Free Data Structures**: High-performance concurrent processing without synchronization blocks
- **CPU Core Affinity**: Binding QUIC connections to dedicated CPU cores for better cache behavior
- **NUMA-Awareness**: Optimizations for Non-Uniform Memory Access on multi-socket servers
- **Event-Driven I/O Multiplexing**: Efficient processing of thousands of concurrent connections

### SIMD Acceleration

- **CPU Feature Detection**: Automatic detection and utilization of available SIMD instructions:
  - SSE, SSE2, SSE3, SSSE3, SSE4.1, SSE4.2, AVX, AVX2, and AVX-512 on x86/x64 processors
  - AES-NI and PCLMULQDQ for hardware-accelerated cryptography on Intel/AMD
  - NEON and ARM Crypto Extensions on ARM architectures (Apple Silicon, Snapdragon)
  - Seamless fallback to standard implementations when hardware acceleration is not available

- **SIMD-Optimized Cryptography**:
  - AES-GCM with AES-NI and PCLMULQDQ instructions (up to 5.7x on x86)
  - GHASH acceleration with optimized Karatsuba multiplication (8x faster)
  - 4-block batch processing for higher throughput
  - ARM Crypto Extensions for AES and PMULL on Apple M1/M2 (4.75x faster)
  - AVX2-accelerated Ascon-128a implementation

- **SIMD-Optimized FEC**:
  - Tetrys-FEC with SIMD-accelerated matrix mathematics
  - Parallelized encoding (up to 6x faster) and decoding (up to 2.8x faster)
  - Loop unrolling and prefetching for optimized cache usage
  - Optimized Galois field operations (5-8x faster)

- **Cross-Platform Abstractions**:
  - Unified API for all supported platforms
  - Automatic selection of optimal implementations at runtime
  - SIMD dispatcher class for transparent hardware abstraction
  - XOR operations with 4x loop unrolling (2.65-3.06x faster)

### Network Optimizations

- **UDP Burst Buffering**: Optimized packet batching techniques
- **Congestion Control**: Implementation of BBRv2 with dynamic adjustment
- **Path MTU Discovery**: Optimal packet size adjustment
- **Connection Migration**: Seamless switching between networks without connection breakage
- **Memory Pool**: Pre-allocated memory regions against fragmentation

## Stealth Features

QuicSand implements comprehensive stealth mechanisms that are effective even against advanced surveillance systems and DPI mechanisms:

### Deep Packet Inspection (DPI) Evasion

- **Packet Fragmentation**: Splitting packets to evade detection
- **Timing Randomization**: Random delays against traffic analysis
- **Payload Randomization**: Obfuscation of payload signatures
- **TLS Imitation**: Mimicking common TLS browser communication
- **Protocol Obfuscation**: Obfuscation of the QUIC protocol

### SNI Hiding

- **Domain Fronting**: Separation of SNI and Host header
- **Encrypted Client Hello (ECH)**: Full encryption of SNI
- **SNI-Padding**: Extending SNI with random data
- **SNI-Split**: Splitting SNI across multiple packets
- **SNI Omission**: Selective omission of SNI extension
- **ESNI Support**: Legacy support

### Traffic Masking

- **HTTP-Mimicry**: Disguise as regular web traffic
- **HTTP/3 Masquerading**: VPN traffic disguised as HTTP/3
- **Fake-TLS**: Emulation of various TLS implementations
- **Fake-Headers**: HTTP header manipulation for obfuscation

### QUIC Spin Bit

- **Spin Bit Randomizer**: Various strategies (Random, Alternating, Constant)
- **Timing-based Manipulation**: Time-controlled spin bit changes
- **Browser Mimicry**: Imitation of known QUIC implementations

### Browser Fingerprinting

- **uTLS Integration**: Emulation of browser TLS fingerprints
- **Browser Profiles**: Chrome, Firefox, Safari, Edge, Opera, etc.
- **Dynamic Fingerprinting**: Changing fingerprints per session

### Stealth Configuration

- **Stealth Levels**: Predefined levels (0-3) for quick configuration
  - Level 0: No stealth features
  - Level 1: Basic obfuscation
  - Level 2: Advanced obfuscation
  - Level 3: Maximum stealth features

- **Custom Configuration**: Granular control over individual stealth techniques
- **Profile-based Configuration**: Predefined profiles for different deployment scenarios

### Cryptographic Components

QuicSand implements modern cryptographic primitives with a focus on security and performance:

### AES-128-GCM with Hardware Acceleration

- **AES-NI and PCLMULQDQ**: Utilization of specific CPU instructions for maximum performance
- **SIMD Optimization**: Parallel encryption with AVX2/NEON
- **Ciphertext Authentication**: Integrated authentication through GCM
- **Auto-Detection**: Automatic detection and utilization of available hardware acceleration

### Ascon-128a Integration

- **Post-Quantum Security**: Future-proof, lightweight encryption primitive
- **SIMD Optimization**: Specialized implementation for AVX2 and NEON
- **Fallback Mechanism**: Automatic fallback when AES hardware support is not available
- **Nonce Management**: Robust management of unique nonce values

### Key Exchange and Certificate Management

- **X25519**: Efficient elliptic curves for key exchange
- **TLS 1.3 Integration**: State-of-the-art TLS protocol support
- **Certificate Verification**: Comprehensive verification of server certificates


# --- # --- # --- # --- #