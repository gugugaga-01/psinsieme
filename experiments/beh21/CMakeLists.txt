find_package(coproto QUIET)
find_package(volePSI QUIET)

if(NOT TARGET coproto::coproto)
    message(WARNING "coproto not found — skipping beh21 build.\n"
                    "Install it as a CMake package or set CMAKE_PREFIX_PATH.")
    return()
endif()

# volePSI target may be volePSI::volePSI or visa::volePSI depending on version
if(TARGET volePSI::volePSI)
    set(VOLEPSI_TARGET volePSI::volePSI)
elseif(TARGET visa::volePSI)
    set(VOLEPSI_TARGET visa::volePSI)
else()
    message(WARNING "volePSI not found — skipping beh21 build.\n"
                    "Install it as a CMake package or set volePSI_DIR.")
    return()
endif()

add_executable(beh21_ot_mpsi
    protocol/ot_mpsi.cpp
    third_party/smhasher/MurmurHash3.cpp
    frontend/main.cpp
)

target_include_directories(beh21_ot_mpsi PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}              # for "protocol/ot_mpsi.h" etc.
    ${CMAKE_CURRENT_SOURCE_DIR}/protocol     # for "bloom_filter.h" from ot_mpsi.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/smhasher  # for MurmurHash3.h
)

target_compile_features(beh21_ot_mpsi PRIVATE cxx_std_20)
target_compile_options(beh21_ot_mpsi PRIVATE -maes -msse2 -msse4.1 -mpclmul)

target_link_libraries(beh21_ot_mpsi PRIVATE
    experiment_shared_crypto
    coproto::coproto
    ${VOLEPSI_TARGET}
)
