add_executable(rc4_server
    server/server.cpp
)

target_include_directories(rc4_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/server)
target_link_libraries(rc4_server PRIVATE crypto)


add_executable(rc4_client
    client/client.cpp
)

target_include_directories(rc4_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/client)


foreach(target rc4_server rc4_client)
    set_target_properties(${target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/rc4_client_server
    )
endforeach()
