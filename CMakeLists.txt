cmake_minimum_required(VERSION 3.14)
project(QuicFuscate CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-maes -msse4.1 -mpclmul -mavx2)

add_library(quicfuscate_crypto
    crypto/morus.cpp
    crypto/morus1280.cpp
)

target_include_directories(quicfuscate_crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_library(quicfuscate_fec
    fec/FEC_Modul.cpp
)

target_include_directories(quicfuscate_fec PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

include(FetchContent)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.0
)
FetchContent_MakeAvailable(Catch2)

enable_testing()
add_executable(tests
    tests/aegis_stub.cpp
    tests/test_crypto.cpp
    tests/test_fec.cpp
    tests/test_quic.cpp
)

target_link_libraries(tests PRIVATE quicfuscate_crypto quicfuscate_fec Catch2::Catch2WithMain)

add_test(NAME QuicFuscateTests COMMAND tests)
