
#project(frontend)

find_library(GMP_LIB gmp)

if(GMP_LIB)
    message(STATUS "Found gmp library: ${GMP_LIB}")
else()
    message(WARNING "gmp library not found")
endif()


#find_library(BOTAN_LIB botan-2)
#if(BOTAN_LIB)
#    message(STATUS "Found Botan library: ${BOTAN_LIB}")
#else()
#    message(FATAL_ERROR "Botan library not found")
#endif()

find_library(SODIUM_LIB sodium)
if(SODIUM_LIB)
    message(STATUS "Found libsodium library: ${SODIUM_LIB}")
else()
    message(FATAL_ERROR "libsodium library not found. Install: sudo apt install libsodium-dev")
endif()


#############################################
#               Build fronend.exe           #
#############################################

file(GLOB_RECURSE SRC_FRONTEND ${CMAKE_SOURCE_DIR}/frontend/*.cpp  
                                ${CMAKE_SOURCE_DIR}/frontend/utils/*.cpp  
                                ${CMAKE_SOURCE_DIR}/frontend/third_party/*.cpp 
                                ${CMAKE_SOURCE_DIR}/frontend/Hashing/*.cpp 
                                ${CMAKE_SOURCE_DIR}/frontend/OPPRF/*.cpp)


include_directories(${CMAKE_SOURCE_DIR}/frontend/
                    ${CMAKE_SOURCE_DIR}/frontend/utils/
                    ${CMAKE_SOURCE_DIR}/frontend/third_party/
                    ${CMAKE_SOURCE_DIR}/frontend/Hashing/
                    ${CMAKE_SOURCE_DIR}/frontend/OPPRF/)

add_executable(frontend.exe ${SRC_FRONTEND})




#############################################
#            Link our libraries             #
#############################################
#target_link_libraries(frontend.exe libPSI_Tests)
target_link_libraries(frontend.exe ntl)
target_link_libraries(frontend.exe miracl)
target_link_libraries(frontend.exe cryptoTools)
target_link_libraries(frontend.exe ${GMP_LIB})
target_link_libraries(frontend.exe ${SODIUM_LIB})

#target_link_libraries(frontend.exe libOPRF)
#target_link_libraries(frontend.exe libOTe)
#target_link_libraries(frontend.exe ${BOTAN_LIB})




