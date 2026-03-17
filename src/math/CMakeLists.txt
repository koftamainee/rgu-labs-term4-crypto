add_library(math STATIC
        utils.cpp
)
include(FetchContent)
FetchContent_Declare(
        bigmath
        GIT_REPOSITORY https://github.com/koftamainee/bigmath.git
        GIT_TAG master
)
set(BIGMATH_BUILD_TESTS   OFF CACHE BOOL "" FORCE)
set(BIGMATH_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(bigmath)

target_link_libraries(math PUBLIC bigmath++)

target_include_directories(math PUBLIC .)