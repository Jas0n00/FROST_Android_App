cmake_minimum_required(VERSION 3.22.1)
project("frost")

# Define paths to BoringSSL headers and libraries within the project
set(BORINGSSL_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/boringssl/include")
set(BORINGSSL_LIB_DIR "${CMAKE_SOURCE_DIR}/boringssl/lib/arm64-v8a")

# Define the source files
set(SOURCES
        src/frost.c        # Native library entry point
        src/main.c         # Engine, which calls the other files
        src/globals.c      # Additional sources
        src/macros.c       # Additional sources
        src/setup.c        # Additional sources
        src/signing.c      # Additional sources
)

# Add project-specific headers
set(HEADERS
        headers/globals.h
        headers/setup.h
        headers/signing.h
)

# Create the shared library (libfrost.so)
add_library(frost SHARED ${SOURCES})

# Add include directories for BoringSSL and project-specific headers
target_include_directories(frost PUBLIC
        ${BORINGSSL_INCLUDE_DIR}    # For BoringSSL headers
        ${CMAKE_SOURCE_DIR}/headers # For project-specific headers
)

# Link against BoringSSL static libraries and Android logging library
target_link_libraries(
        frost
        android
        "${BORINGSSL_LIB_DIR}/libcrypto.a"
        "${BORINGSSL_LIB_DIR}/libssl.a"
        log  # Required for Android logging
)

# Set compilation flags for better warnings and debugging info
target_compile_options(frost PUBLIC -Wall -Wextra -g)

# Ensure the library is properly placed (optional step for Android)
set_target_properties(frost PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/jniLibs/arm64-v8a"
)
