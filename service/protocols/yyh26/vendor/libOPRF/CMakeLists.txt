# Build libOPRF as a static library from vendored source.
# Depends on: libOTe, cryptoTools (found externally via find_library)

file(GLOB_RECURSE LIBOPRF_SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/OPPRF/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Hashing/*.cpp
)

add_library(libOPRF STATIC ${LIBOPRF_SRCS})

target_include_directories(libOPRF PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
# Headers for upstream deps (cryptoTools, libOTe) come from the install prefix
target_include_directories(libOPRF PRIVATE
    ${YYH26_DEPS_PREFIX}/include/yyh26/cryptoTools
    ${YYH26_DEPS_PREFIX}/include/yyh26/libOTe
    ${YYH26_DEPS_PREFIX}/include/yyh26/miracl/include
)

# These are found by the parent CMakeLists.txt
target_link_libraries(libOPRF PUBLIC
    ${LIBOTE_LIBRARY}
    ${CRYPTOTOOLS_LIBRARY}
    ${NTL_LIBRARY}
    ${GMP_LIBRARY}
)

target_compile_options(libOPRF PRIVATE -maes -msse2 -msse4.1 -mpclmul)
