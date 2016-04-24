cmake_minimum_required(VERSION 3.0)
project(PPdedupe)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14") # Enable C++14 features
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall") # Turn on warnings

add_executable(PPdedupe src/main.cpp)
