cmake_minimum_required(VERSION 3.16)

project(WEP_SECURITY_PC LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT WIN32)
    message(FATAL_ERROR "Ten projekt PC jest aktualnie napisany pod Windows, bo serial_port.cpp używa Windows API.")
endif()

add_library(wep_pc STATIC
    pc_auth.cpp
    pc_frame.cpp
    serial_port.cpp
    wep_crypto.cpp
)

target_include_directories(wep_pc PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(wep_security_pc
    main.cpp
)

target_link_libraries(wep_security_pc PRIVATE
    wep_pc
)