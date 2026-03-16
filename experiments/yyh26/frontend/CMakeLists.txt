
#project(fronend)

find_library(GMP_LIB gmp)

if(GMP_LIB)
    message(STATUS "Found gmp library: ${GMP_LIB}")
else()
    message(WARNING "gmp library not found")
endif()


#############################################
#               Build fronend.exe           #
#############################################

file(GLOB_RECURSE SRC_FRONTEND ${CMAKE_SOURCE_DIR}/frontend/*.cpp)
include_directories(${CMAKE_SOURCE_DIR}/frontend/)

add_executable(frontend.exe ${SRC_FRONTEND})


#############################################
#            Link our libraries             #
#############################################
target_link_libraries(frontend.exe -lgmp)
target_link_libraries(frontend.exe libOPRF)

# Pre-built libs from upstream submodule (order matters for static linking)
target_link_libraries(frontend.exe libOTe)
target_link_libraries(frontend.exe ${CMAKE_SOURCE_DIR}/upstream/lib/libcryptoTools.a)
target_link_libraries(frontend.exe ${CMAKE_SOURCE_DIR}/upstream/thirdparty/linux/miracl/miracl/source/libmiracl.a)

# cryptoTools for OLE (from libOLE submodule)
find_library(LIB_cryptoOLE NAMES cryptoTools PATHS ${CMAKE_SOURCE_DIR}/libOLE/third_party/cryptoTools/lib NO_DEFAULT_PATH)

if (LIB_cryptoOLE)
    MESSAGE(STATUS "Found cryptoOLE library: ${LIB_cryptoOLE}")
else()
    MESSAGE(FATAL_ERROR "Could not find cryptoOLE library")
endif()
target_link_libraries(frontend.exe ${LIB_cryptoOLE})

# gazelle library (from libOLE submodule)
find_library(LIB_GAZELLE NAMES gazelle PATHS ${CMAKE_SOURCE_DIR}/libOLE/bin/lib NO_DEFAULT_PATH)

if (LIB_GAZELLE)
    MESSAGE(STATUS "Found gazelle library: ${LIB_GAZELLE}")
else()
    MESSAGE(FATAL_ERROR "Could not find gazelle library")
endif()

target_link_libraries(frontend.exe -lgazelle)


target_link_libraries(frontend.exe

    boost_system
    boost_thread
    mpfr
    gmpxx
    gmp
    ntl
    gf2x
    benchmark
    pthread
    rt
    ${LIB_GAZELLE}
)
