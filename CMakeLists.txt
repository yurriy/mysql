cmake_minimum_required(VERSION 3.13)
project(mysql)

set(CMAKE_CXX_STANDARD 17)

include_directories(poco)

add_executable(mysql main.cpp)