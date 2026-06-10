cmake_minimum_required(VERSION 3.14)
project(wep_embedded CXX C)

set(CMAKE_CXX_STANDARD 17)

# ---------- sources ----------
add_library(wep_lib
    ring_buffer.cpp
    web_crypto.cpp
    web_auth.cpp
)
target_include_directories(wep_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# ---------- Google Test ----------
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(run_tests test_all.cpp)
target_link_libraries(run_tests wep_lib GTest::gtest_main)

include(GoogleTestHelpers OPTIONAL)
add_test(NAME all_tests COMMAND run_tests)