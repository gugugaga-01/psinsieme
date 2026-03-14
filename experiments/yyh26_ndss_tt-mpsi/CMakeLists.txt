cmake_minimum_required (VERSION 2.8)

project("libPSI")


set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/bin)
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)
set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)


#############################################
#            Flag and #defines              #
#############################################
add_definitions(-DSOLUTION_DIR=\"${CMAKE_SOURCE_DIR}\")
set(CMAKE_C_FLAGS "-ffunction-sections -Wall  -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -pthread")
set(CMAKE_CXX_FLAGS  "${CMAKE_C_FLAGS}  -std=c++17")

# Set a default build type for single-configuration
# CMake generators if no build type is set.
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE Release)
endif()

if(NOT ${CMAKE_BUILD_TYPE} STREQUAL "Release")
  message(WARNING "\nConfiguration NOT set to Release. Please call cmake with CMAKE_BUILD_TYPE=Release")
endif()

# Select flags.
SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")
SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g")


#############################################
#       Library/includes locations          #
#############################################

# Upstream submodule provides cryptoTools + libOTe + thirdparty/miracl
# Build upstream first: cd upstream && cmake . && make
set(UPSTREAM_DIR "${CMAKE_SOURCE_DIR}/upstream")

# cryptoTools and libOTe headers (from upstream submodule)
include_directories("${UPSTREAM_DIR}/cryptoTools")
include_directories("${UPSTREAM_DIR}/libOTe")

# Pre-built libraries from upstream
link_directories("${UPSTREAM_DIR}/lib")

# miracl (from upstream submodule)
set(Miracl_Dirs "${UPSTREAM_DIR}/thirdparty/linux/miracl/")
include_directories("${Miracl_Dirs}")
link_directories("${Miracl_Dirs}/miracl/source/")

# default location for NTL
set(NTL_Dirs "/usr/local")
include_directories("${NTL_Dirs}/include/")
link_directories("${NTL_Dirs}/lib/")

# default location for Boost
set(BOOST_ROOT "${UPSTREAM_DIR}/thirdparty/linux/boost/")
find_package(Boost REQUIRED COMPONENTS system thread)


#############################################
#               Build libOPRF              #
#############################################
add_subdirectory(libOPRF)
include_directories(libOPRF)


#############################################
#         libOLE includes/libs             #
#############################################
# libOLE submodule provides gazelle + cryptoTools for OLE
# Build libOLE first: cd libOLE && make
include_directories(libOLE/third_party/cryptoTools)
include_directories(libOLE/src/lib)
include_directories(libOLE/bin/lib)


#############################################
#              Build Frontend               #
#############################################
add_subdirectory(frontend)
