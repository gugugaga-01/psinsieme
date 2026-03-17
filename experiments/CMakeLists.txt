cmake_minimum_required(VERSION 3.16)
project(psi_experiments VERSION 1.0 LANGUAGES CXX)

# Find NTL and GMP (shared dependency)
find_library(NTL_LIBRARY ntl PATHS /usr/local/lib)
find_library(GMP_LIBRARY gmp)
find_path(NTL_INCLUDE_DIR NTL/ZZ.h PATHS /usr/local/include)

if(NOT NTL_LIBRARY OR NOT GMP_LIBRARY)
    message(FATAL_ERROR "NTL and GMP libraries are required. Install with: sudo apt install libntl-dev libgmp-dev")
endif()

# Common dependencies
find_package(Threads REQUIRED)
find_package(Boost QUIET COMPONENTS system thread regex)

# Protocol dependencies (optional — KS05/BEH21 skip if not found)
# Resolve at top level so transitive deps are visible to all subdirectories.
find_package(volePSI QUIET)
find_package(coproto QUIET)

# Build options
option(BUILD_KS05 "Build KS05 T-MPSI experiment" ON)
option(BUILD_BEH21 "Build BEH21 OT-MPSI experiment" ON)
option(BUILD_YYH26 "Build YYH26 TT-MPSI experiment" OFF)

# Shared crypto library (paillier, defines, logger)
add_subdirectory(shared)

if(BUILD_KS05)
    add_subdirectory(ks05)
endif()

if(BUILD_BEH21)
    add_subdirectory(beh21)
endif()

if(BUILD_YYH26)
    add_subdirectory(yyh26)
endif()
