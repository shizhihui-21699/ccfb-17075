cmake_minimum_required(VERSION 3.20)

project(PipeSec
    VERSION 1.0.0
    DESCRIPTION "Windows named pipe enumeration, audit, monitoring and secure wrappers"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(WARNING "PipeSec targets Windows. Configure with cmake/mingw-w64-x86_64.cmake for a MinGW cross-build.")
endif()

add_library(pipesec STATIC
    src/Util.cpp
    src/SecurityInspector.cpp
    src/PipeEnumerator.cpp
    src/ProcessInspector.cpp
    src/HandleScanner.cpp
    src/ServiceHunter.cpp
    src/RiskAnalyzer.cpp
    src/Auditor.cpp
    src/Report.cpp
    src/Monitor.cpp
    src/Harden.cpp
    src/SecurePipe.cpp
)

target_include_directories(pipesec
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(pipesec PUBLIC UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(pipesec PUBLIC advapi32)

if(MSVC)
    target_compile_options(pipesec PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(pipesec PRIVATE -Wall -Wextra -Wpedantic -Wno-unused-parameter)
endif()

add_executable(pipe-audit src/main.cpp)
target_link_libraries(pipe-audit PRIVATE pipesec)

add_executable(secure_server examples/secure_server.cpp)
target_link_libraries(secure_server PRIVATE pipesec)

add_executable(secure_client examples/secure_client.cpp)
target_link_libraries(secure_client PRIVATE pipesec)

foreach(target pipe-audit secure_server secure_client)
    if(MINGW)
        target_compile_options(${target} PRIVATE -municode)
        target_link_options(${target} PRIVATE -municode)
    endif()
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
    endif()
endforeach()
