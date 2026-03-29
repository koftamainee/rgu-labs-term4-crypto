add_library(rsa_vulnerabilities STATIC
        vulnerable_key_generator.cpp
)


target_include_directories(rsa_vulnerabilities PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(rsa_vulnerabilities PUBLIC crypto)