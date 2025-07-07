# Quiche Dependency Management

## Table of Contents
1. [Overview](#overview)
2. [Integration Guidelines](#integration-guidelines)
3. [Optimization Strategy](#optimization-strategy)
4. [Build System](#build-system)
5. [Custom TLS Hooks](#custom-tls-hooks)
6. [Advanced Optimizations](#advanced-optimizations)
7. [Maintenance](#maintenance)

## Overview

This document consolidates all information regarding the integration, optimization, and maintenance of the quiche library within the QuicFuscate project. The quiche library serves as the foundation for QUIC protocol implementation, specifically tailored for QuicFuscate's requirements.

## Quick Start

Clone the repository and run the workflow to download, patch and build quiche:

```bash
./scripts/quiche_workflow.sh --type release
```

The workflow fetches the sources, applies all patches and builds quiche in one go.
If a patch fails to apply check the logs under `libs/logs` for details.

## Schritt-für-Schritt-Anleitung

1. **Vorbedingungen installieren**
   - Rust 1.82+ samt `cargo`
   - `cmake`, `perl` und `go` für den BoringSSL‑Build

2. **Workflow ausführen**
   ```bash
   ./scripts/quiche_workflow.sh --type release
   ```
   Dieser Aufruf lädt quiche, wendet alle Patches an und erstellt die Bibliothek
   im Release‑Modus.

3. **Patches aktualisieren und Build wiederholen**
   - Änderungen an `libs/patches/*.patch` vornehmen
   - Den obigen Workflow erneut starten, um die Patches anzuwenden und die
     kompilierten Artefakte zu aktualisieren

## Integration Guidelines

### Core Principles

1. **Minimalist Approach**
   - Keep the quiche library trimmed to essential functionality only
   - Implement all QuicFuscate-specific features in dedicated modules
   - Maintain clear separation of concerns between quiche and QuicFuscate

2. **Code Organization**
   ```
  QuicFuscate/
  ├── libs/
  │   ├── patched_quiche/      # Customized quiche version
  │   ├── vanilla_quiche/      # Upstream quiche source
  │   └── patches/             # *.patch files
  ├── scripts/                 # Automation scripts
  └── docs/                    # Documentation
  ```

3. **Technical Guidelines**
   - Only make compatibility changes to quiche
   - Keep cryptographic implementations in QuicFuscate modules
   - Document all modifications to quiche

## Optimization Strategy

### Code Reduction

1. **Removed Components**
   - HTTP/3 and WebTransport support
   - Legacy QUIC versions
   - Experimental features
   - Platform-specific code for unsupported systems
   - Debug and test infrastructure

2. **Build Optimization**
   - Selective feature compilation
   - Dead code elimination
   - Removal of debug symbols in release builds

### Performance Optimizations

1. **Build-time Optimizations**
   - LTO (Link Time Optimization)
   - CPU-specific instruction sets (AVX2, AES-NI, etc.)
   - Optimized code generation

2. **Runtime Optimizations**
   - BBR Congestion Control
   - Zero-Copy packet handling
   - Memory pooling
   - SIMD optimizations

## Build System

### Prerequisites

- Rust 1.82+
- Cargo
- CMake (for BoringSSL)
- Perl (for BoringSSL)
- Go (for BoringSSL)

### Building

```bash
# Complete workflow (release build)
./scripts/quiche_workflow.sh --type release

# For a debug build use
./scripts/quiche_workflow.sh --type debug
```

If any step fails the build script aborts. Consult the log files in
`libs/logs` for the exact error messages.

### Custom Build Features

```toml
[dependencies]
quiche = { path = "libs/patched_quiche/quiche" }
```

## Custom TLS Hooks

QuicFuscate relies on a patched version of **quiche** to inject prebuilt TLS
ClientHello messages. This allows the stealth layer to emulate real browsers
without modifying the Rust code of quiche during runtime.

### Required Changes

- `libs/patched_quiche/quiche/include/quiche.h` – declaration of the additional
  `quiche_config_set_custom_tls()` function.
- `libs/patched_quiche/quiche/src/ffi.rs` – implementation of the FFI symbol and
  binding to `Config`.
- `libs/patched_quiche/quiche/src/lib.rs` – store the provided ClientHello in the
  configuration object.
- `libs/patched_quiche/quiche/src/tls/mod.rs` – pass the stored buffer to the TLS
  backend during connection setup.

The patch series under `libs/patched_quiche/patches/` contains these
modifications (see `custom_tls.patch`). Apply them via
`scripts/maintain_quiche.sh patch` after fetching the submodule.

### Provided FFI Symbols

```c
void quiche_config_set_custom_tls(quiche_config *cfg,
                                  const uint8_t *hello, size_t len);
```

When the patched library is absent, a stub implementation lives in
`src/tls_ffi.rs` so unit tests continue to compile.

## Advanced Optimizations

### CPU-Specific Optimizations

- **x86_64**: AES, SSE4.2, AVX2, BMI2
- **ARM64**: AES, SHA2, CRC, LSE

### Memory Management

- Transparent Huge Pages
- Optimized buffer sizes
- NUMA alignment

### Security Hardening

- Stack protection
- PIE (Position Independent Executables)
- RELRO (Relocation Read-Only)
- ASLR (Address Space Layout Randomization)

## Automated Build and CI/CD

### GitHub Actions Workflow

QuicFuscate includes a GitHub Actions workflow for automated building and testing of the patched quiche library. The workflow is defined in `.github/workflows/build-quiche.yml` and provides the following features:

#### Key Features
- **Automated Builds**: Triggered on push/pull requests to main/master branches
- **Manual Triggers**: Supports manual execution with custom build types
- **Artifact Publishing**: Automatically uploads build artifacts
- **Release Management**: Creates GitHub releases for main/master builds

#### Workflow Steps
1. **Setup Environment**
   - Checks out the repository with submodules
   - Configures Rust toolchain with required components
   - Installs build dependencies (cmake, etc.)

2. **Build Process**
   - Executes the quiche workflow script
   - Supports both release and debug builds
   - Applies all patches from `libs/patches/*.patch`

3. **Test Process**
   - Runs `scripts/quiche_workflow.sh --step test`
   - Uploads logs from `libs/logs` as workflow artifacts

4. **Artifact Handling**
   - Packages the built artifacts
   - Uploads them as workflow artifacts
   - Creates GitHub releases for stable builds

### Local Development Workflow

The `scripts/quiche_workflow.sh` script provides a complete local development workflow:

```bash
# Complete workflow (fetch, patch, build, test)
./scripts/quiche_workflow.sh --type release

# Run specific steps only
./scripts/quiche_workflow.sh --step fetch
./scripts/quiche_workflow.sh --step patch
./scripts/quiche_workflow.sh --step build
./scripts/quiche_workflow.sh --step test
```

## Maintenance

### Update Process

1. **Automated Workflow** (recommended):
   ```bash
   # Complete update and build process
   ./scripts/quiche_workflow.sh --type release
   ```

2. **Manual Process** (if needed):
   ```bash
   # Fetch the latest quiche version and initialize the submodule
   ./scripts/quiche_workflow.sh --step fetch

   # Apply custom patches from libs/patches/*.patch
   ./scripts/apply_patches.sh

   # Test the updated version
   cargo test --release
   ```

3. **Patch Management**:
   ```bash
   # Generate new patch
   ./scripts/generate_patch.sh "Description of changes"

   # Alternatively manage the quiche tree and apply patches
   ./scripts/maintain_quiche.sh patch
   ```

4. **Submodule Update**:
   Update the embedded quiche sources to the latest upstream commit and store the
   new state in version control:
   ```bash
   git submodule update --remote libs/patched_quiche
   git add libs/patched_quiche
   git commit -m "Update quiche submodule"
   ```
   Verify afterwards that all patches still apply and the build succeeds.

### Version Control

- All changes to quiche must be tracked in git
- Each update should be a single commit
- Include detailed commit messages referencing related issues

## Troubleshooting

### Common Issues

1. **Build Failures**
   - Verify all prerequisites are installed
   - Check for version conflicts
   - Clean build artifacts and try again

2. **Performance Issues**
   - Verify CPU features are properly detected
   - Check system resource usage
   - Review optimization flags

3. **Patch Application Failures**
   - The workflow aborts automatically when a patch fails to apply.
   - Review the error message and fix the patch before rerunning.
4. **Manual Patch Conflict Resolution**
   - Reapply the failing patch with `git apply --reject <patch>` to create `.rej` files.
   - Edit the affected sources and resolve each hunk manually.
   - After fixing the conflicts run `git add -u` and regenerate the patch with
     `git diff > libs/patches/<patch-name>.patch`.
   - Restart the workflow to verify the updated patch series.

### Getting Help

For issues with the quiche integration:
1. Check the [quiche documentation](https://docs.quic.tech/quiche/)
2. Review the QuicFuscate documentation
3. Open an issue in the project repository

## License

This customized version of quiche is distributed under the same license as the original:
- [BSD-2-Clause](LICENSE)
