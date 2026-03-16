add_library(experiment_shared_crypto
    crypto/paillier.cpp
)

target_include_directories(experiment_shared_crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..    # so includes like "shared/crypto/paillier.h" work
)

target_link_libraries(experiment_shared_crypto PUBLIC
    ${NTL_LIBRARY}
    ${GMP_LIBRARY}
)
