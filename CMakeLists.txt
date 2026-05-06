cmake_minimum_required(VERSION 3.10)
project(ThyrnAnalyzer VERSION 0.1)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source files
file(GLOB SOURCES "src/*.cpp")

include_directories(src)

add_executable(ThyrnAnalyzer ${SOURCES})

# Compiler flags for security research
if(MSVC)
    target_compile_options(ThyrnAnalyzer PRIVATE /W4)
else()
    target_compile_options(ThyrnAnalyzer PRIVATE -Wall -Wextra -O3)
endif()