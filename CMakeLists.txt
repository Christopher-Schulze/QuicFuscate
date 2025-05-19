cmake_minimum_required(VERSION 3.14)
project(QuicSand VERSION 0.1.0 LANGUAGES CXX)

# C++17 Standard festlegen
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Ausgabeverzeichnisse
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Include-Verzeichnisse
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/quiche-patched/include
)

# Compiler-Flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Finde benötigte Bibliotheken
find_package(Boost REQUIRED COMPONENTS system thread)
find_package(OpenSSL REQUIRED)

# Füge alle Unterverzeichnisse hinzu
add_subdirectory(core)
add_subdirectory(crypto)
add_subdirectory(fec)
add_subdirectory(stealth)
add_subdirectory(tls)
add_subdirectory(cli)
add_subdirectory(tests)

# Erstelle Haupt-Bibliothek
add_library(quicsand-core
    core/quic_connection.cpp
    core/quic_stream.cpp
    core/simd_optimizations.cpp
    simd/simd_dispatcher.cpp
    # Plattform-spezifische SIMD-Implementierungen
    $<$<NOT:$<BOOL:$<C_COMPILER_ID:MSVC>>>:$<$<BOOL:$<TARGET_PROPERTY:COMPILE_DEFINITIONS,__ARM_NEON>>:simd/arm_simd_impl.cpp>>
    $<$<NOT:$<BOOL:$<C_COMPILER_ID:MSVC>>>:$<$<NOT:$<BOOL:$<TARGET_PROPERTY:COMPILE_DEFINITIONS,__ARM_NEON>>>:simd/x86_simd_impl.cpp>>
    # Weitere Core-Quelldateien hier
)

# Erstelle TLS-Bibliothek
add_library(quicsand-tls
    tls/utls_client_configurator.cpp
    tls/quiche_utls_wrapper.cpp
    # Weitere TLS-Quelldateien hier
)

# Füge Link-Bibliotheken hinzu
target_link_libraries(quicsand-core
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    quicsand-tls
    quiche
)

target_link_libraries(quicsand-tls
    ${OPENSSL_LIBRARIES}
    quiche
)

# Füge Linkverzeichnisse hinzu
link_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/quiche-patched/build
)

# Erstelle CLI-Anwendung
add_executable(quicsand-cli cli/main.cpp)
target_link_libraries(quicsand-cli quicsand-core)
