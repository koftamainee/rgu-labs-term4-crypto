add_library(crypto STATIC
    bits/permute.cpp
    bits/substitute.cpp
    bits/utils.cpp
    rc4/encoder.cpp

    core/feistel_network.cpp
    core/feistel_network_wrapper.cpp

    algorithms/des.cpp
    algorithms/triple_des.cpp
    
    io/symmetric_cipher.cpp
)

target_include_directories(crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
