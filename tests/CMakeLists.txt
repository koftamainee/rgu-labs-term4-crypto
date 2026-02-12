add_executable(test_crypto_bits_permute
    test_crypto_bits_permute.cpp
)

target_link_libraries(test_crypto_bits_permute
    PRIVATE crypto
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME test_crypto_bits_permute COMMAND test_crypto_bits_permute)
