# Build-Anleitung für QuicSand

## Voraussetzungen

- CMake 3.15+
- C++17 kompatibler Compiler (GCC 9+, Clang 10+, MSVC 2019+)
- Boost 1.74+
- OpenSSL 1.1.1+ oder 3.0+ mit QUIC-Unterstützung
- Rust (für den Build der quiche-Bibliothek)

## Repository klonen

```bash
git clone --recursive https://github.com/Christopher-Schulze/QuicSandVPN.git
cd QuicSandVPN
```

## Quiche-Bibliothek bauen

Die quiche-Bibliothek ist als Submodul enthalten. Führen Sie die folgenden Schritte aus, um sie zu bauen:

```bash
cd libs/quiche-patched
cargo build --package quiche --release --features ffi,pkg-config-meta,qlog --lib
```

## QuicSand bauen

```bash
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

## Bekannte Probleme

### Quiche-Bibliothek kann nicht gefunden werden

Stellen Sie sicher, dass die Umgebungsvariable `QUICHE_LIB_PATH` auf das Verzeichnis zeigt, in dem die quiche-Bibliothek gebaut wurde:

```bash
export QUICHE_LIB_PATH=$(pwd)/libs/quiche-patched/target/release
```

### Fehlende Abhängigkeiten

Unter Ubuntu/Debian:
```bash
sudo apt-get install -y cmake build-essential libssl-dev pkg-config
```

Unter macOS:
```bash
brew install cmake openssl@3 pkg-config
```
