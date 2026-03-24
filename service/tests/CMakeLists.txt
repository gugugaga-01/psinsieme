# GoogleTest
find_package(GTest REQUIRED)
include(GoogleTest)

# === Core Tests ===

# Config file parser unit tests
add_executable(test_config_file core/test_config_file.cpp)
target_include_directories(test_config_file PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(test_config_file PRIVATE GTest::gtest_main)
gtest_discover_tests(test_config_file)

# Transport channel unit tests
add_executable(test_transport protocols/ks05/test_transport.cpp)
target_link_libraries(test_transport PRIVATE mpsi_core GTest::gtest_main)
gtest_discover_tests(test_transport)

# Minimal gRPC connectivity test
add_executable(test_grpc_minimal protocols/ks05/test_grpc_minimal.cpp)
target_link_libraries(test_grpc_minimal PRIVATE mpsi_core mpsi_proto)
add_test(NAME grpc_minimal COMMAND test_grpc_minimal)

# === KS05 Protocol Tests ===

# Paillier crypto unit tests
add_executable(test_paillier protocols/ks05/test_paillier.cpp)
target_link_libraries(test_paillier PRIVATE ks05_crypto GTest::gtest_main)
gtest_discover_tests(test_paillier)

# Polynomial unit tests
add_executable(test_polynomial protocols/ks05/test_polynomial.cpp)
target_link_libraries(test_polynomial PRIVATE ks05_crypto GTest::gtest_main)
gtest_discover_tests(test_polynomial)

# Dealer service tests
add_executable(test_ks05_dkg protocols/ks05/test_dkg.cpp)
target_link_libraries(test_ks05_dkg PRIVATE ks05_protocol ks05_crypto mpsi_core GTest::gtest_main)
gtest_discover_tests(test_ks05_dkg)

# Serialization unit tests
add_executable(test_serialization protocols/ks05/test_serialization.cpp)
target_link_libraries(test_serialization PRIVATE ks05_protocol ks05_crypto mpsi_core GTest::gtest_main)
gtest_discover_tests(test_serialization)

# Logger unit tests
add_executable(test_logger protocols/ks05/test_logger.cpp)
target_include_directories(test_logger PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(test_logger PRIVATE GTest::gtest_main)
gtest_discover_tests(test_logger)

# In-process integration test (no gRPC)
add_executable(test_ks05_integration protocols/ks05/test_integration.cpp)
target_link_libraries(test_ks05_integration PRIVATE ks05_protocol ks05_crypto mpsi_core)
add_test(NAME ks05_integration COMMAND test_ks05_integration)

# Threshold MPSI test (t=2, n=3)
add_executable(test_ks05_threshold protocols/ks05/test_threshold.cpp)
target_link_libraries(test_ks05_threshold PRIVATE ks05_protocol ks05_crypto mpsi_core)
add_test(NAME ks05_threshold COMMAND test_ks05_threshold)

# gRPC integration test (3 parties over gRPC with optional mTLS)
add_executable(test_ks05_grpc protocols/ks05/test_grpc_integration.cpp)
target_link_libraries(test_ks05_grpc PRIVATE ks05_protocol ks05_crypto mpsi_core mpsi_proto)
add_test(NAME ks05_grpc COMMAND test_ks05_grpc)
add_test(NAME ks05_grpc_tls COMMAND test_ks05_grpc --tls
    --certs-dir "${CMAKE_CURRENT_SOURCE_DIR}/../certs/test")

# === BEH21 OT-MPSI Tests ===
if(MPSI_BUILD_BEH21)
    # Bloom filter unit tests
    add_executable(test_beh21_bloom_filter protocols/beh21/test_bloom_filter.cpp)
    target_include_directories(test_beh21_bloom_filter PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
    )
    target_link_libraries(test_beh21_bloom_filter PRIVATE
        beh21_crypto GTest::gtest_main)
    gtest_discover_tests(test_beh21_bloom_filter)

    # Signed plaintext helper unit tests
    add_executable(test_beh21_signed_plaintext protocols/beh21/test_signed_plaintext.cpp)
    target_include_directories(test_beh21_signed_plaintext PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${NTL_INCLUDE_DIR}
    )
    target_link_libraries(test_beh21_signed_plaintext PRIVATE
        beh21_protocol ks05_crypto ${NTL_LIBRARY} ${GMP_LIBRARY} GTest::gtest_main)
    gtest_discover_tests(test_beh21_signed_plaintext)

    # In-process integration test (no gRPC)
    add_executable(test_beh21_integration protocols/beh21/test_beh21_integration.cpp)
    target_include_directories(test_beh21_integration PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${NTL_INCLUDE_DIR}
    )
    target_link_libraries(test_beh21_integration PRIVATE
        beh21_protocol beh21_crypto ks05_crypto mpsi_core
        ${NTL_LIBRARY} ${GMP_LIBRARY})
    add_test(NAME beh21_integration COMMAND test_beh21_integration)

    # gRPC integration test (3 parties over gRPC with optional mTLS)
    add_executable(test_beh21_grpc protocols/beh21/test_beh21_grpc_integration.cpp)
    target_include_directories(test_beh21_grpc PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${NTL_INCLUDE_DIR}
    )
    target_link_libraries(test_beh21_grpc PRIVATE
        beh21_protocol beh21_crypto ks05_crypto mpsi_core mpsi_proto
        ${NTL_LIBRARY} ${GMP_LIBRARY})
    add_test(NAME beh21_grpc COMMAND test_beh21_grpc)
    add_test(NAME beh21_grpc_tls COMMAND test_beh21_grpc --tls
        --certs-dir "${CMAKE_CURRENT_SOURCE_DIR}/../certs/test")
endif()

# === XZH26 EC-MPSI Tests ===
if(MPSI_BUILD_XZH26)
    find_library(SODIUM_LIB sodium)

    # In-process integration test
    add_executable(test_xzh26_integration protocols/xzh26/test_xzh26_integration.cpp)
    target_include_directories(test_xzh26_integration PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
    )
    target_link_libraries(test_xzh26_integration PRIVATE
        xzh26_protocol xzh26_crypto xzh26_cryptotools mpsi_core ${SODIUM_LIB})
    add_test(NAME xzh26_integration COMMAND test_xzh26_integration)

    # gRPC integration test (3 parties over gRPC with optional mTLS)
    add_executable(test_xzh26_grpc protocols/xzh26/test_xzh26_grpc_integration.cpp)
    target_include_directories(test_xzh26_grpc PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
    )
    target_link_libraries(test_xzh26_grpc PRIVATE
        xzh26_protocol xzh26_crypto xzh26_cryptotools mpsi_core mpsi_proto ${SODIUM_LIB})
    add_test(NAME xzh26_grpc COMMAND test_xzh26_grpc)
    add_test(NAME xzh26_grpc_tls COMMAND test_xzh26_grpc --tls
        --certs-dir "${CMAKE_CURRENT_SOURCE_DIR}/../certs/test")
endif()

# === YYH26 TT-MPSI Tests ===
if(MPSI_BUILD_YYH26)
    add_executable(test_yyh26_tt_mpsi protocols/yyh26/test_tt_mpsi.cpp)
    target_include_directories(test_yyh26_tt_mpsi PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${NTL_INCLUDE_DIR}
    )
    target_link_libraries(test_yyh26_tt_mpsi PRIVATE
        yyh26_protocol ${NTL_LIBRARY} ${GMP_LIBRARY} GTest::gtest_main)
    gtest_discover_tests(test_yyh26_tt_mpsi)
endif()
