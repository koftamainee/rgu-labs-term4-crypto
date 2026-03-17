add_library(math STATIC
        utils.cpp
        fermat_prime_test.cpp
        fermat_prime_test.h
        prime_test.cpp
        prime_test.hpp
)


target_include_directories(math PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(bigint)