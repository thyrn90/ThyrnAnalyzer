cmake_minimum_required(VERSION 3.10)
project(ThyrnAnalyzer VERSION 0.1)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCES 
    src/main.cpp
)

add_executable(ThyrnAnalyzer ${SOURCES})

target_include_directories(ThyrnAnalyzer PRIVATE src)

if(MSVC)
    target_compile_options(ThyrnAnalyzer PRIVATE /W4 /O2 /GS)
    
    target_compile_definitions(ThyrnAnalyzer PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(ThyrnAnalyzer PRIVATE -Wall -Wextra -Wpedantic -O3 -fstack-protector-strong)
    
    target_compile_definitions(ThyrnAnalyzer PRIVATE _FORTIFY_SOURCE=2)
endif()