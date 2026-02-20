find_package(GTest REQUIRED)

function(add_crypto_test target source)
    add_executable(${target} ${source})
    target_link_libraries(${target}
        PRIVATE
            crypto
            GTest::gtest
            GTest::gtest_main
    )
    target_include_directories(${target} PRIVATE
        ${CMAKE_SOURCE_DIR}/src
    )
    add_test(NAME ${target} COMMAND ${target})
endfunction()

add_crypto_test(test_crypto_bits_permute    test_crypto_bits_permute.cpp)
add_crypto_test(test_crypto_bits_substitute test_crypto_bits_substitute.cpp)
add_crypto_test(test_crypto_bits_utils      test_crypto_bits_utils.cpp)
add_crypto_test(test_crypto_rc4_encoder     test_crypto_rc4_encoder.cpp)
add_crypto_test(test_crypto_des             test_crypto_des.cpp)
add_crypto_test(test_crypto_triple_des      test_crypto_triple_des.cpp)
