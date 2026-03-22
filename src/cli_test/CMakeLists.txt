add_executable(cli_test
    main.cpp
)

target_link_libraries(cli_test PRIVATE crypto)

target_include_directories(cli_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

set_target_properties(cli_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
