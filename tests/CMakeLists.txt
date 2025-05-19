cmake_minimum_required(VERSION 3.14)

# Google Test Framework einbinden
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.11.0
)
FetchContent_MakeAvailable(googletest)

# Testhinweise
enable_testing()

# Test-Executables
add_executable(utls_tests utls_tests.cpp)
add_executable(quic_simd_integration_test quic_simd_integration_test.cpp)
add_executable(simd_comprehensive_benchmark simd_comprehensive_benchmark.cpp)
add_executable(simd_end_to_end_test simd_end_to_end_test.cpp)
add_executable(platform_simd_test platform_simd_test.cpp)

# Verknüpfe Tests mit den Bibliotheken
target_link_libraries(utls_tests 
    gtest 
    gtest_main
    pthread
    quicsand-core
    quicsand-tls
    ssl
    crypto
)

# Füge Tests zur Test-Suite hinzu
add_test(NAME UTLSTests COMMAND utls_tests)

# Library-Verknüpfungen für den SIMD-Integrationstest
target_link_libraries(quic_simd_integration_test
    gtest
    gtest_main
    pthread
    quicsand-core
    quicsand-crypto
    quicsand-fec
    ssl
    crypto
    boost_system
)

# Füge SIMD-Integrationstest zur Test-Suite hinzu
add_test(NAME SIMD_Integration_Test COMMAND quic_simd_integration_test)

# Ausgabeverzeichnis setzen
set_target_properties(utls_tests PROPERTIES 
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Ausgabeverzeichnis für SIMD-Integrationstest setzen
set_target_properties(quic_simd_integration_test PROPERTIES 
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Library-Verknüpfungen für den Comprehensive Benchmark
target_link_libraries(simd_comprehensive_benchmark
    pthread
    quicsand-core
    quicsand-crypto
    quicsand-fec
    ssl
    crypto
    boost_system
)

# Ausgabeverzeichnis für den Comprehensive Benchmark setzen
set_target_properties(simd_comprehensive_benchmark PROPERTIES 
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Library-Verknüpfungen für den End-to-End SIMD-Test
target_link_libraries(simd_end_to_end_test
    pthread
    quicsand-core
    quicsand-crypto
    quicsand-fec
    ssl
    crypto
    boost_system
)

# Ausgabeverzeichnis für den End-to-End SIMD-Test setzen
set_target_properties(simd_end_to_end_test PROPERTIES 
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Library-Verknüpfungen für den plattformübergreifenden SIMD-Test
target_link_libraries(platform_simd_test
    pthread
    quicsand-core
    quicsand-crypto
    quicsand-fec
    ssl
    crypto
    boost_system
)

# Ausgabeverzeichnis für den plattformübergreifenden SIMD-Test setzen
set_target_properties(platform_simd_test PROPERTIES 
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
