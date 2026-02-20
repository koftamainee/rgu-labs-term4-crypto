add_executable(des_encoding_demo
    main.cpp
)

target_link_libraries(des_encoding_demo PRIVATE crypto)

target_include_directories(des_encoding_demo PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)


    set_target_properties(des_encoding_demo PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
