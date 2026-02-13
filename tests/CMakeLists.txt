add_executable(test_crypto_bits_permute
    test_crypto_bits_permute.cpp
)

target_link_libraries(test_crypto_bits_permute
    PRIVATE crypto
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME test_crypto_bits_permute COMMAND test_crypto_bits_permute)


add_executable(test_crypto_bits_substitute
    test_crypto_bits_substitute.cpp
)

target_link_libraries(test_crypto_bits_substitute
    PRIVATE crypto
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME test_crypto_bits_substitute COMMAND test_crypto_bits_substitute)


add_executable(test_crypto_bits_utils
    test_crypto_bits_utils.cpp
)

target_link_libraries(test_crypto_bits_utils
    PRIVATE crypto
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME test_crypto_bits_utils COMMAND test_crypto_bits_utils)



add_executable(test_crypto_rc4_encoder
    test_crypto_rc4_encoder.cpp
)

target_link_libraries(test_crypto_rc4_encoder
    PRIVATE crypto
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME test_crypto_rc4_encoder COMMAND test_crypto_rc4_encoder)
