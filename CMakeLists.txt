cmake_minimum_required(VERSION 4.0)

project(rgu-labs-term4-crypto LANGUAGES CXX)

include(FetchContent)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_testing()

FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include_directories(src)

add_subdirectory(src/crypto)
add_subdirectory(src/rc4_client_server)
add_subdirectory(src/des_encoding_demo)
add_subdirectory(src/des_cli)
add_subdirectory(tests)
