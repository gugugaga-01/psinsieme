cmake_minimum_required (VERSION 2.8)

project("xzh26-EC-MPSI")


set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/bin)
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)
set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)


#############################################
#            Flag and #defines              #
#############################################
add_definitions(-DSOLUTION_DIR=\"${CMAKE_SOURCE_DIR}\")
add_definitions(-DNO_INTEL_ASM_SHA1=1)
set(CMAKE_C_FLAGS "-ffunction-sections -Wall  -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -pthread")
set(CMAKE_CXX_FLAGS  "${CMAKE_C_FLAGS}  -std=c++14")

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

set(CRYPTOTOOLS_DIR "${CMAKE_SOURCE_DIR}/../yyh26/upstream/cryptoTools")

# Miracl (required by cryptoTools)
set(Miracl_Dirs "${CMAKE_SOURCE_DIR}/../yyh26/upstream/thirdparty/linux/miracl/")
include_directories("${Miracl_Dirs}")
link_directories("${Miracl_Dirs}/miracl/source/")

# NTL
set(NTL_Dirs "/usr/local")
include_directories("${NTL_Dirs}/include/")
link_directories("${NTL_Dirs}/lib/")

# libsodium
set(SODIUM_Dirs "/usr/local")
include_directories("${SODIUM_Dirs}/include")
link_directories("${SODIUM_Dirs}/lib")

# Boost
find_package(Boost REQUIRED COMPONENTS system thread)

#############################################
#            Build cryptoTools              #
#############################################
# Build cryptoTools as a library from yyh26 upstream sources.
# We compile it here instead of add_subdirectory() because the
# upstream CMakeLists has CMAKE_SOURCE_DIR-relative asm paths
# that break when used as a subdirectory.
file(GLOB_RECURSE CRYPTOTOOLS_SRCS "${CRYPTOTOOLS_DIR}/*.cpp")
include_directories("${CRYPTOTOOLS_DIR}")

find_library(MIRACL_LIB NAMES miracl HINTS "${Miracl_Dirs}/miracl/source/")

add_library(cryptoTools ${CRYPTOTOOLS_SRCS})
target_include_directories(cryptoTools PUBLIC "${CRYPTOTOOLS_DIR}")
target_link_libraries(cryptoTools ${MIRACL_LIB} ${Boost_LIBRARIES})

#############################################
#              Build Frontend               #
#############################################
add_subdirectory(frontend)
