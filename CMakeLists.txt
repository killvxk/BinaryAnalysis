cmake_minimum_required(VERSION 3.13)
project(BinaryLoader)

set(CMAKE_CXX_STANDARD 17)

add_executable(BinaryLoader loader/loader.cc basic_capstone.cpp basic_capstone_recursive.cc)

target_link_libraries(BinaryLoader
        PRIVATE bfd
        capstone)

add_subdirectory(synthesizer)
