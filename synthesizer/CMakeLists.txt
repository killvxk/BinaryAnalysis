cmake_minimum_required(VERSION 3.13)
project(Synthesize)

set(CMAKE_CXX_STANDARD 17)

add_executable(Synthesize main.cpp UnicornEngine.cpp Grammar.cpp MCTS.cpp Game.cpp Game.h)

target_link_libraries(
        Synthesize
        PUBLIC UNICORN::UNICORN
        pthread
)