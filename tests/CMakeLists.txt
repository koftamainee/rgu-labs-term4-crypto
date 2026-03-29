cmake_minimum_required(VERSION 3.20)

find_package(GTest REQUIRED)
include(CTest)
include(GoogleTest)

function(add_crypto_test target source)
    add_executable(${target} ${source})

    target_link_libraries(${target}
            PRIVATE
            crypto
            math
            rsa_vulnerabilities
            GTest::gtest
            GTest::gtest_main
    )

    target_include_directories(${target} PRIVATE
            ${CMAKE_SOURCE_DIR}/src
    )

    gtest_discover_tests(${target})
endfunction()

add_crypto_test(test_crypto_bits_permute            test_crypto_bits_permute.cpp)
add_crypto_test(test_crypto_bits_substitute         test_crypto_bits_substitute.cpp)
add_crypto_test(test_crypto_bits_utils              test_crypto_bits_utils.cpp)
add_crypto_test(test_crypto_rc4_encoder             test_crypto_rc4_encoder.cpp)
add_crypto_test(test_crypto_des                     test_crypto_des.cpp)
add_crypto_test(test_crypto_triple_des              test_crypto_triple_des.cpp)
add_crypto_test(test_crypto_cipher_context          test_crypto_cipher_context.cpp)
add_crypto_test(test_math_utils                     test_math_utils.cpp)
add_crypto_test(test_math_fermat_prime              test_math_fermat_prime.cpp)
add_crypto_test(test_math_miller_rabin_prime        test_math_miller_rabin_prime.cpp)
add_crypto_test(test_math_solovay_strassen_prime    test_math_solovay_strassen_prime.cpp)
add_crypto_test(test_crypto_rsa_keygen              test_crypto_rsa_keygen.cpp)
add_crypto_test(test_crypto_rsa                     test_crypto_rsa.cpp)
add_crypto_test(test_crypto_rsa_serializer          test_crypto_rsa_serializer.cpp)
add_crypto_test(test_rsa_vulnerabilities            test_rsa_vulnerabilities.cpp)