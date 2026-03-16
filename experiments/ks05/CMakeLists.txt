find_package(coproto QUIET)
find_package(volePSI QUIET)

if(NOT coproto_FOUND OR NOT volePSI_FOUND)
    message(WARNING "coproto or volePSI not found — skipping ks05 build.\n"
                    "Install them as CMake packages or set CMAKE_PREFIX_PATH.")
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
    volePSI::volePSI
)
