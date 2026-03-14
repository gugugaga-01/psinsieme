cmake_minimum_required(VERSION 3.10)
project(yyh26_tt_mpsi_v2)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)

add_definitions(-DSOLUTION_DIR=\"${CMAKE_SOURCE_DIR}\")
set(CMAKE_C_FLAGS "-ffunction-sections -Wall -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -pthread")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++17")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g")

# ── Local deps (self-contained, no external dependency) ──
set(DEPS_DIR "${CMAKE_SOURCE_DIR}/deps")

# OPPRF-side headers (osuCrypto namespace): cryptoTools, libOTe
include_directories("${DEPS_DIR}/include/cryptoTools_opprf")
include_directories("${DEPS_DIR}/include/libOTe")

# Miracl headers (referenced as "miracl/include/miracl.h" from Curve.h)
include_directories("${DEPS_DIR}/include/miracl")

# OLE-side headers (osuCryptoNew namespace): cryptoTools for libOLE
include_directories("${DEPS_DIR}/include/cryptoTools_ole")

# Gazelle/OLE headers (pke/ole.h, math/dcrt.h, etc.)
include_directories("${DEPS_DIR}/include/gazelle")

# Pre-built libraries
link_directories("${DEPS_DIR}/lib")

find_library(LIB_GAZELLE NAMES gazelle PATHS "${DEPS_DIR}/lib" NO_DEFAULT_PATH)
find_library(LIB_CRYPTO_OLE NAMES cryptoTools_ole PATHS "${DEPS_DIR}/lib" NO_DEFAULT_PATH)

if(NOT LIB_GAZELLE OR NOT LIB_CRYPTO_OLE)
    message(FATAL_ERROR "Pre-built deps not found in deps/lib/. See README.")
endif()

# ── NTL / GMP / Boost (system) ──
find_library(NTL_LIB ntl PATHS /usr/local/lib)
find_library(GMP_LIB gmp)
include_directories(/usr/local/include)

find_package(Boost REQUIRED COMPONENTS system thread)

# ── Build libOPRF (local copy) ──
include_directories("${CMAKE_SOURCE_DIR}/libOPRF")
file(GLOB_RECURSE OPPRF_SRCS libOPRF/*.cpp)
add_library(libOPRF_v2 ${OPPRF_SRCS})
target_link_libraries(libOPRF_v2 libOTe cryptoTools ${NTL_LIB} ${GMP_LIB})

# ── Build main executable ──
file(GLOB_RECURSE MAIN_SRCS src/*.cpp)
add_executable(yyh26_v2.exe ${MAIN_SRCS})

target_include_directories(yyh26_v2.exe PRIVATE ${CMAKE_SOURCE_DIR}/src)

target_link_libraries(yyh26_v2.exe
    libOPRF_v2
    libOTe
    cryptoTools
    ${LIB_CRYPTO_OLE}
    ${LIB_GAZELLE}
    ${NTL_LIB}
    ${GMP_LIB}
    Boost::system
    Boost::thread
    miracl
    mpfr gmpxx benchmark pthread rt
)
