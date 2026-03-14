
#############################################
#                 Link NTL                  #
#############################################
set(NTL_LIB_DIRS "/usr/local/lib/")
set(NTL_INCLUDE_DIRS "/usr/local/include/")

set(NTL_LIB "${NTL_LIB_DIRS}libntl.a")


#############################################
#                 Link libOTe               #
#############################################

find_library(
	libOTe_LIB
	NAMES libOTe
	HINTS "${CMAKE_SOURCE_DIR}/upstream/lib/")


#############################################
#              Build libOPRF                #
#############################################

file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR}/libOPRF)

add_library(libOPRF ${SRCS})

target_link_libraries(libOPRF libOTe cryptoTools ${NTL_LIB} -lgmp)
