# Contributing to QuicFuscate

Thank you for considering contributing to the project! The codebase is still experimental and evolving, so contributions are welcome.

## Coding Style
- Use modern C++17 features and prefer `std::unique_ptr` or `std::shared_ptr` for memory management.
- Follow the [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html) where practical.
- Format all C++ code with `clang-format` before submitting a pull request.

## Running Tests
Currently the project does not provide automated unit tests. To verify that your changes build correctly:

1. Ensure the patched QUIC submodule is available:
   ```bash
   git submodule update --init libs/quiche-patched
   ```
2. Compile the CLI tools:
   ```bash
   g++ -std=c++17 cli/*.cpp core/*.cpp crypto/*.cpp stealth/*.cpp fec/*.cpp optimize/*.cpp \
       -I./ -lboost_system -lssl -lcrypto -pthread -o quicfuscate
   ```
3. Run the client or server binaries to verify basic functionality.

Please keep pull requests focused and include a clear description of the changes.
