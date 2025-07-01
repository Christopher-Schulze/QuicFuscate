cmake_minimum_required(VERSION 3.15)
project(QuicFuscate LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
set(gtest_force_shared_crt OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Build the patched quiche library with Cargo
set(QUICHE_LIB "${PROJECT_SOURCE_DIR}/libs/quiche-patched/target/release/libquiche.a")

if(EXISTS "${PROJECT_SOURCE_DIR}/libs/quiche-patched/Cargo.toml")
add_custom_command(
    OUTPUT ${QUICHE_LIB}
    COMMAND cargo build --release
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/libs/quiche-patched
    COMMENT "Building quiche via cargo"
)

add_custom_target(quiche_build ALL DEPENDS ${QUICHE_LIB})

add_library(quiche STATIC IMPORTED GLOBAL)
set_target_properties(quiche PROPERTIES
    IMPORTED_LOCATION "${QUICHE_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/libs/quiche-patched/include"
)
add_dependencies(quiche quiche_build)
endif()

if(TARGET quiche AND EXISTS "${PROJECT_SOURCE_DIR}/libs/quiche-patched/include/quiche.h")
add_library(quicfuscate_core
    core/quic_connection_impl.cpp
    core/quic_integration_impl.cpp
    core/quic_packet.cpp
    core/quic_stream_impl.cpp
)

target_include_directories(quicfuscate_core
    PUBLIC
        ${PROJECT_SOURCE_DIR}/core
        ${PROJECT_SOURCE_DIR}/optimize
        ${PROJECT_SOURCE_DIR}/crypto
        ${PROJECT_SOURCE_DIR}/fec
        ${PROJECT_SOURCE_DIR}/stealth
)

target_link_libraries(quicfuscate_core
    PUBLIC
        quiche
        OpenSSL::SSL
        OpenSSL::Crypto
)
add_dependencies(quicfuscate_core quiche_build)
endif()

add_library(quicfuscate_crypto
    crypto/cipher_suite_selector.cpp
)

target_include_directories(quicfuscate_crypto PUBLIC ${PROJECT_SOURCE_DIR}/crypto)
target_link_libraries(quicfuscate_crypto PUBLIC OpenSSL::SSL OpenSSL::Crypto)

add_library(quicfuscate_fec
    fec/FEC_Modul.cpp
)

target_include_directories(quicfuscate_fec PUBLIC ${PROJECT_SOURCE_DIR}/fec)

add_library(quicfuscate_stealth
    stealth/DoH.cpp
    stealth/DomainFronting.cpp
    stealth/FakeTLS.cpp
    stealth/QuicFuscate_Stealth.cpp
    stealth/XOR_Obfuscation.cpp
    stealth/http3_masquerading.cpp
    stealth/stealth_gov.cpp
    stealth/utls.cpp
)

target_include_directories(quicfuscate_stealth PUBLIC ${PROJECT_SOURCE_DIR}/stealth)
target_link_libraries(quicfuscate_stealth PUBLIC OpenSSL::SSL OpenSSL::Crypto)

add_library(quicfuscate_optimize
    optimize/quic_stream_optimizer.cpp
)
target_include_directories(quicfuscate_optimize PUBLIC ${PROJECT_SOURCE_DIR}/optimize ${PROJECT_SOURCE_DIR}/core)

if(TARGET quicfuscate_core)
add_executable(quicfuscate_cli cli/quicfuscate_cli.cpp)
target_link_libraries(quicfuscate_cli PRIVATE
    quicfuscate_core
    quicfuscate_crypto
    quicfuscate_fec
    quicfuscate_stealth
    OpenSSL::SSL
    OpenSSL::Crypto
    quiche
)

add_executable(quicfuscate_client cli/quicfuscate_client.cpp)
target_link_libraries(quicfuscate_client PRIVATE
    quicfuscate_core
    quicfuscate_crypto
    quicfuscate_fec
    quicfuscate_stealth
    OpenSSL::SSL
    OpenSSL::Crypto
    quiche
)

add_executable(quicfuscate_server cli/quicfuscate_server.cpp)
target_link_libraries(quicfuscate_server PRIVATE
    quicfuscate_core
    quicfuscate_crypto
    quicfuscate_fec
    quicfuscate_stealth
    OpenSSL::SSL
    OpenSSL::Crypto
    quiche
)

add_executable(quicfuscate_demo cli/main.cpp)
target_link_libraries(quicfuscate_demo PRIVATE
    quicfuscate_core
    quicfuscate_crypto
    quicfuscate_fec
    quicfuscate_stealth
    OpenSSL::SSL
    OpenSSL::Crypto
    quiche
)
endif()

enable_testing()
add_executable(fec_module_test tests/fec_module_test.cpp)
target_link_libraries(fec_module_test PRIVATE quicfuscate_fec gtest_main)
add_test(NAME fec_module_test COMMAND fec_module_test)


add_executable(stream_handling_test tests/stream_handling_test.cpp)
target_link_libraries(stream_handling_test PRIVATE quicfuscate_optimize gtest_main)
add_test(NAME stream_handling_test COMMAND stream_handling_test)

add_executable(path_mtu_manager_test tests/path_mtu_manager_test.cpp)
target_link_libraries(path_mtu_manager_test PRIVATE gtest_main)
add_test(NAME path_mtu_manager_test COMMAND path_mtu_manager_test)

add_executable(quic_connection_test tests/quic_connection_test.cpp)
target_link_libraries(quic_connection_test PRIVATE gtest_main)
add_test(NAME quic_connection_test COMMAND quic_connection_test)

add_executable(xor_obfuscation_test tests/xor_obfuscation_test.cpp)
target_link_libraries(xor_obfuscation_test PRIVATE quicfuscate_stealth gtest_main)
add_test(NAME xor_obfuscation_test COMMAND xor_obfuscation_test)

add_executable(path_mtu_probe_logic_test tests/path_mtu_probe_logic_test.cpp)
target_link_libraries(path_mtu_probe_logic_test PRIVATE gtest_main)
add_test(NAME path_mtu_probe_logic_test COMMAND path_mtu_probe_logic_test)

add_executable(connection_features_test tests/connection_features_test.cpp)
target_link_libraries(connection_features_test PRIVATE gtest_main)
add_test(NAME connection_features_test COMMAND connection_features_test)
