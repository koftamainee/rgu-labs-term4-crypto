add_executable(des_cli
    main.cpp
)

target_link_libraries(des_cli PRIVATE crypto)

target_include_directories(des_cli PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

set_target_properties(des_cli PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
