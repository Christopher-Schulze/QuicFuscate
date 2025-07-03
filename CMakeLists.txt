cmake_minimum_required(VERSION 3.15)
project(QuicFuscate LANGUAGES C)

add_custom_target(quicfuscate ALL
    COMMAND cargo build --workspace --release
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/rust
    COMMENT "Building Rust workspace")

enable_testing()
add_custom_target(check
    COMMAND cargo test --workspace
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/rust
    COMMENT "Running Rust tests")
