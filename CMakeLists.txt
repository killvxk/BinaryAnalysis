cmake_minimum_required(VERSION 3.13)
project(BinaryLoader)

set(CMAKE_CXX_STANDARD 17)

add_executable(BinaryLoader loader.cc basic_capstone.cpp)

target_link_libraries(BinaryLoader
        PRIVATE bfd
        capstone)

