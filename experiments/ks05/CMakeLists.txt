find_package(coproto QUIET)
find_package(volePSI QUIET)

if(NOT TARGET coproto::coproto)
    message(WARNING "coproto not found — skipping ks05 build.\n"
                    "Install it as a CMake package or set CMAKE_PREFIX_PATH.")
    return()
endif()

# volePSI target may be volePSI::volePSI or visa::volePSI depending on version
if(TARGET volePSI::volePSI)
    set(VOLEPSI_TARGET volePSI::volePSI)
elseif(TARGET visa::volePSI)
    set(VOLEPSI_TARGET visa::volePSI)
else()
    message(WARNING "volePSI not found — skipping ks05 build.\n"
                    "Install it as a CMake package or set volePSI_DIR.")
    return()
endif()

add_executable(ks05_t_mpsi
    protocol/t_mpsi.cpp
    protocol/polynomial.cpp
    frontend/main.cpp
)

target_include_directories(ks05_t_mpsi PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}            # for "protocol/t_mpsi.h" etc.
    ${CMAKE_CURRENT_SOURCE_DIR}/protocol   # for "polynomial.h" from t_mpsi.cpp
)

target_compile_features(ks05_t_mpsi PRIVATE cxx_std_20)
target_compile_options(ks05_t_mpsi PRIVATE -maes -msse2 -msse4.1 -mpclmul)

target_link_libraries(ks05_t_mpsi PRIVATE
    experiment_shared_crypto
    coproto::coproto
    ${VOLEPSI_TARGET}
)
