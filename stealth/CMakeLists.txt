cmake_minimum_required(VERSION 3.10)

# Stealth-Bibliothek
add_library(stealth STATIC
    stealth.cpp
    fake_headers.cpp
    fake_tls.cpp
    utls.cpp
    http3_masquerading.cpp
)
