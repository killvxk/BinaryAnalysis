cmake_minimum_required(VERSION 3.13)
project(BinaryLoader)

set(CMAKE_CXX_STANDARD 17)

add_executable(BinaryLoader main.cpp loader.cc)


set(CMAKE_CXX_FLAGS "-lbfd")

