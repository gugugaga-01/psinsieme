# GoogleTest
find_package(GTest REQUIRED)
include(GoogleTest)

# === Unit Tests ===

# Paillier crypto unit tests
add_executable(test_paillier ks05/test_paillier.cpp)
target_link_libraries(test_paillier PRIVATE ks05_crypto GTest::gtest_main)
gtest_discover_tests(test_paillier)

# Polynomial unit tests
add_executable(test_polynomial ks05/test_polynomial.cpp)
target_link_libraries(test_polynomial PRIVATE ks05_crypto GTest::gtest_main)
gtest_discover_tests(test_polynomial)

# Transport channel unit tests
add_executable(test_transport ks05/test_transport.cpp)
target_link_libraries(test_transport PRIVATE mpsi_core GTest::gtest_main)
gtest_discover_tests(test_transport)

# Dealer service tests
add_executable(test_ks05_dkg ks05/test_dkg.cpp)
target_link_libraries(test_ks05_dkg PRIVATE ks05_protocol ks05_crypto mpsi_core GTest::gtest_main)
gtest_discover_tests(test_ks05_dkg)

# === Integration Tests ===

# In-process integration test (no gRPC)
add_executable(test_ks05_integration ks05/test_integration.cpp)
target_link_libraries(test_ks05_integration PRIVATE ks05_protocol ks05_crypto mpsi_core)
add_test(NAME ks05_integration COMMAND test_ks05_integration)

# Threshold MPSI test (t=2, n=3)
add_executable(test_ks05_threshold ks05/test_threshold.cpp)
target_link_libraries(test_ks05_threshold PRIVATE ks05_protocol ks05_crypto mpsi_core)
add_test(NAME ks05_threshold COMMAND test_ks05_threshold)

# gRPC integration test (3 parties over gRPC with optional mTLS)
add_executable(test_ks05_grpc ks05/test_grpc_integration.cpp)
target_link_libraries(test_ks05_grpc PRIVATE ks05_protocol ks05_crypto mpsi_core mpsi_proto)
add_test(NAME ks05_grpc COMMAND test_ks05_grpc)
add_test(NAME ks05_grpc_tls COMMAND test_ks05_grpc --tls
    --certs-dir "${CMAKE_CURRENT_SOURCE_DIR}/../certs/test")

# Minimal gRPC connectivity test
add_executable(test_grpc_minimal ks05/test_grpc_minimal.cpp)
target_link_libraries(test_grpc_minimal PRIVATE mpsi_core mpsi_proto)
add_test(NAME grpc_minimal COMMAND test_grpc_minimal)

# === YYH26 TT-MPSI Tests ===
if(MPSI_BUILD_YYH26)
    add_executable(test_yyh26_tt_mpsi yyh26/test_tt_mpsi.cpp)
    target_include_directories(test_yyh26_tt_mpsi PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${NTL_INCLUDE_DIR}
    )
    target_link_libraries(test_yyh26_tt_mpsi PRIVATE
        yyh26_protocol ${NTL_LIBRARY} ${GMP_LIBRARY} GTest::gtest_main)
    gtest_discover_tests(test_yyh26_tt_mpsi)
endif()
