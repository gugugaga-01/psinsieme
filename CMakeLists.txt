cmake_minimum_required(VERSION 3.16)
project(mpsi VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Always build the service
add_subdirectory(service)

# Optionally build experiments (requires additional dependencies)
option(BUILD_EXPERIMENTS "Build experiment code under experiments/" OFF)
if(BUILD_EXPERIMENTS)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/experiments/CMakeLists.txt")
        add_subdirectory(experiments)
    else()
        message(WARNING "BUILD_EXPERIMENTS is ON but experiments/CMakeLists.txt not found")
    endif()
endif()
