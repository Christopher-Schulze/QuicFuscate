cmake_minimum_required(VERSION 3.15)
project(QuicFuscate LANGUAGES CXX)

include(CTest)
option(BUILD_TESTING "Build tests" ON)

include(FetchContent)
if(BUILD_TESTING)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
    )
    FetchContent_MakeAvailable(googletest)
    enable_testing()
endif()

find_package(OpenMP)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_library(quiche STATIC IMPORTED)
set_target_properties(quiche PROPERTIES
    IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/libs/quiche-patched/target/release/libquiche.a"
    INTERFACE_INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/libs/quiche-patched/include"
)

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

add_library(quicfuscate_crypto
    crypto/aegis128l.cpp
    crypto/aegis128x.cpp
    crypto/morus.cpp
    crypto/morus1280.cpp
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

if(BUILD_TESTING)
    add_executable(quicfuscate_tests
        tests/fec_module_test.cpp
        fec/FEC_Modul.cpp
        stealth/XOR_Obfuscation.cpp
    )
    target_compile_options(quicfuscate_tests PRIVATE -mavx2 -fopenmp)
    target_link_libraries(quicfuscate_tests PRIVATE
        gtest_main
    )
    if(OpenMP_CXX_FOUND)
        target_link_libraries(quicfuscate_tests PRIVATE OpenMP::OpenMP_CXX)
    endif()
    add_test(NAME quicfuscate_tests COMMAND quicfuscate_tests)
endif()

