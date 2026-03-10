
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
#target_link_libraries(frontend.exe libPSI_Tests)
target_link_libraries(frontend.exe -lgmp)
target_link_libraries(frontend.exe libOPRF)
target_link_libraries(frontend.exe libOTe)

find_library(LIB_cryptoOLE NAMES cryptoTools PATHS ../libOLE/third_party/cryptoTools/lib)

if (LIB_cryptoOLE)
    MESSAGE(STATUS "Found cryptoOLE library: ${LIB_cryptoOLE}")
else()
    MESSAGE(FATAL_ERROR "Could not find cryptoOLE library")
endif()
target_link_libraries(frontend.exe ${LIB_cryptoOLE})

# Find the gazelle library
find_library(LIB_GAZELLE NAMES gazelle PATHS ../libOLE/bin/lib)

if (LIB_GAZELLE)
    MESSAGE(STATUS "Found gazelle library: ${LIB_GAZELLE}")
else()
    MESSAGE(FATAL_ERROR "Could not find gazelle library")
endif()


# Link the gazelle library
# target_link_libraries(frontend.exe ${LIB_GAZELLE} )
target_link_libraries(frontend.exe -lgazelle)


target_link_libraries(frontend.exe
    
    boost_system
    boost_thread
    mpfr
    gmpxx
    gmp
    benchmark
    pthread
    rt
    ${LIB_GAZELLE}
)
