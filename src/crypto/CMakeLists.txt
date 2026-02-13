add_library(crypto STATIC
    bits/permute.cpp
    bits/substitute.cpp
    bits/utils.cpp
    rc4/encoder.cpp
)

target_include_directories(crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
