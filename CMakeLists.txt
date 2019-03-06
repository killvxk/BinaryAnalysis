cmake_minimum_required(VERSION 3.13)
project(BinaryLoader)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(UNICORN_ROOT "${CMAKE_SOURCE_DIR}/3rdParty/unicorn")
set(CAPSTONE_ROOT "${CMAKE_SOURCE_DIR}/3rdParty/capstone")

find_package(UNICORN REQUIRED)
find_package(CAPSTONE REQUIRED)

add_executable(BinaryLoader loader/loader.cc basic_capstone.cpp basic_capstone_recursive.cc)

target_link_libraries(BinaryLoader
        PRIVATE bfd
        CAPSTONE::CAPSTONE)

add_subdirectory(synthesizer)
