target_sources(math
        PRIVATE
        advanced.cpp
        arithmetics.cpp
        bigint.cpp
        bitwise.cpp
        division.cpp
        helpers.cpp
        io.cpp
        logical.cpp
        multiplication.cpp
        unsafe.cpp
)

target_include_directories(math
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)