cmake_minimum_required(VERSION 3.16)
project(mpsi VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Build options ---
# BUILD_EXPERIMENTS: Build standalone experiment binaries under experiments/.
#   Requires additional deps (Boost, coproto, volePSI, libOTe).
#   Per-protocol toggles: BUILD_KS05 (ON), BUILD_BEH21 (ON), BUILD_YYH26 (OFF).
option(BUILD_EXPERIMENTS "Build experiment code under experiments/" OFF)

# MPSI_BUILD_YYH26: Build YYH26 TT-MPSI protocol support in the service.
#   Requires upstream deps installed via service/protocols/yyh26/vendor/setup.sh.
#   Set -DYYH26_DEPS_PREFIX=<path> to point to the install prefix.
# (This option is defined in service/CMakeLists.txt, documented here for reference.)

# Always build the service (gRPC framework, psi_party + psi_dealer binaries)
add_subdirectory(service)

# Optionally build experiments
if(BUILD_EXPERIMENTS)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/experiments/CMakeLists.txt")
        add_subdirectory(experiments)
    else()
        message(WARNING "BUILD_EXPERIMENTS is ON but experiments/CMakeLists.txt not found")
    endif()
endif()

# --- Configure summary ---
message(STATUS "")
message(STATUS "=== MPSI Build Configuration ===")
message(STATUS "  Service:         ON")
message(STATUS "  YYH26 (service): ${MPSI_BUILD_YYH26}")
message(STATUS "  Experiments:     ${BUILD_EXPERIMENTS}")
if(BUILD_EXPERIMENTS)
    message(STATUS "    KS05:          ${BUILD_KS05}")
    message(STATUS "    BEH21:         ${BUILD_BEH21}")
    message(STATUS "    YYH26:         ${BUILD_YYH26}")
endif()
message(STATUS "================================")
message(STATUS "")
