cmake_minimum_required(VERSION 3.18.1)

project("rasp_native" LANGUAGES CXX)

# C++17 for std::chrono, structured bindings, etc.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(rasp_native SHARED
    rasp_native.cpp
)

# Link against Android log library (for __android_log_print)
find_library(log-lib log)

target_link_libraries(rasp_native
    ${log-lib}
)

# Note on OpenSSL: The DEX attestation code uses SHA256 from OpenSSL.
# If the NDK's bundled crypto is not available, we fall back to a
# lightweight standalone SHA256 implementation. For now, we compile
# without -lcrypto and use a built-in SHA256 (see sha256_fallback.h).
# To enable OpenSSL, uncomment the line below and ensure the NDK
# includes the crypto library:
#   target_link_libraries(rasp_native crypto)
