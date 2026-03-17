cmake_minimum_required(VERSION 3.16)

# Support both standalone and subdirectory builds
if(NOT CMAKE_PROJECT_NAME OR CMAKE_PROJECT_NAME STREQUAL "mpsi_service")
    project(mpsi_service VERSION 1.0 LANGUAGES CXX)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()

# Find NTL and GMP
find_library(NTL_LIBRARY ntl PATHS /usr/local/lib)
find_library(GMP_LIBRARY gmp)
find_path(NTL_INCLUDE_DIR NTL/ZZ.h PATHS /usr/local/include)

if(NOT NTL_LIBRARY OR NOT GMP_LIBRARY)
    message(FATAL_ERROR "NTL and GMP libraries are required. Install with: sudo apt install libntl-dev libgmp-dev")
endif()

# Find gRPC and Protobuf
find_package(PkgConfig REQUIRED)
pkg_check_modules(GRPC REQUIRED grpc++)
pkg_check_modules(PROTOBUF REQUIRED protobuf)

find_program(PROTOC protoc REQUIRED)
find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin REQUIRED)

# Generate protobuf/gRPC sources
set(PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/proto)
set(PROTO_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${PROTO_GEN_DIR})

set(PROTO_FILES
    ${PROTO_DIR}/common.proto
    ${PROTO_DIR}/ks05_party.proto
    ${PROTO_DIR}/psi_service.proto
    ${PROTO_DIR}/dealer.proto
)

set(PROTO_GEN_SRCS)
set(PROTO_GEN_HDRS)

foreach(PROTO_FILE ${PROTO_FILES})
    get_filename_component(PROTO_NAME ${PROTO_FILE} NAME_WE)

    set(PB_CC ${PROTO_GEN_DIR}/${PROTO_NAME}.pb.cc)
    set(PB_H ${PROTO_GEN_DIR}/${PROTO_NAME}.pb.h)
    set(GRPC_CC ${PROTO_GEN_DIR}/${PROTO_NAME}.grpc.pb.cc)
    set(GRPC_H ${PROTO_GEN_DIR}/${PROTO_NAME}.grpc.pb.h)

    add_custom_command(
        OUTPUT ${PB_CC} ${PB_H} ${GRPC_CC} ${GRPC_H}
        COMMAND ${PROTOC}
            --proto_path=${PROTO_DIR}
            --cpp_out=${PROTO_GEN_DIR}
            --grpc_out=${PROTO_GEN_DIR}
            --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN}
            ${PROTO_FILE}
        DEPENDS ${PROTO_FILE}
        COMMENT "Generating protobuf/gRPC sources for ${PROTO_NAME}"
    )

    list(APPEND PROTO_GEN_SRCS ${PB_CC} ${GRPC_CC})
    list(APPEND PROTO_GEN_HDRS ${PB_H} ${GRPC_H})
endforeach()

# Proto library
add_library(mpsi_proto ${PROTO_GEN_SRCS})
target_include_directories(mpsi_proto PUBLIC
    ${PROTO_GEN_DIR}
    ${PROTOBUF_INCLUDE_DIRS}
    ${GRPC_INCLUDE_DIRS}
)
target_link_libraries(mpsi_proto PUBLIC ${PROTOBUF_LIBRARIES} ${GRPC_LIBRARIES})

# Core transport library (header-only, depends on proto for grpc_channel.h)
add_library(mpsi_core INTERFACE)
target_include_directories(mpsi_core INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROTO_GEN_DIR}
)
target_link_libraries(mpsi_core INTERFACE mpsi_proto)

# ks05 crypto library
add_library(ks05_crypto
    protocols/ks05/crypto/paillier.cpp
    protocols/ks05/crypto/polynomial.cpp
)
target_include_directories(ks05_crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${NTL_INCLUDE_DIR}
)
target_link_libraries(ks05_crypto PUBLIC ${NTL_LIBRARY} ${GMP_LIBRARY})

# ks05 protocol library
add_library(ks05_protocol
    protocols/ks05/protocol/t_mpsi.cpp
)
target_include_directories(ks05_protocol PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ks05_protocol PUBLIC ks05_crypto mpsi_core)
target_link_libraries(ks05_protocol PRIVATE pthread)

# yyh26 TT-MPSI protocol (optional, requires experiments libraries)
option(MPSI_BUILD_YYH26 "Build YYH26 TT-MPSI protocol support" OFF)

if(MPSI_BUILD_YYH26)
    set(YYH26_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../experiments/yyh26")

    # Verify experiments libraries exist (upstream submodule must be built)
    if(NOT EXISTS "${YYH26_ROOT}/upstream/lib/liblibOTe.a")
        message(FATAL_ERROR
            "YYH26 experiments libraries not found at ${YYH26_ROOT}/upstream/lib/\n"
            "Build experiments first:\n"
            "  cd experiments/yyh26 && bash setup.sh\n"
            "  mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc)")
    endif()

    add_library(yyh26_protocol
        protocols/yyh26/protocol/tt_mpsi.cpp
    )

    target_include_directories(yyh26_protocol PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_include_directories(yyh26_protocol PRIVATE
        ${YYH26_ROOT}/upstream/cryptoTools
        ${YYH26_ROOT}/upstream/libOTe
        ${YYH26_ROOT}/libOPRF
        ${YYH26_ROOT}/libOLE/src/lib
        ${YYH26_ROOT}/libOLE/third_party/cryptoTools
        ${YYH26_ROOT}/upstream/thirdparty/linux/miracl/miracl/include
        ${YYH26_ROOT}/frontend
        ${NTL_INCLUDE_DIR}
    )

    target_link_libraries(yyh26_protocol PRIVATE
        ${YYH26_ROOT}/lib/liblibOPRF.a
        ${YYH26_ROOT}/upstream/lib/liblibOTe.a
        ${YYH26_ROOT}/upstream/lib/libcryptoTools.a
        ${YYH26_ROOT}/libOLE/bin/lib/libgazelle.so
        ${YYH26_ROOT}/libOLE/third_party/cryptoTools/lib/libcryptoTools.a
        ${YYH26_ROOT}/upstream/thirdparty/linux/miracl/miracl/source/libmiracl.a
        ${NTL_LIBRARY} ${GMP_LIBRARY}
        boost_system boost_thread pthread
    )

    target_compile_definitions(yyh26_protocol PUBLIC MPSI_HAS_YYH26=1)
    target_compile_options(yyh26_protocol PRIVATE -maes -msse2 -msse4.1 -mpclmul)
endif()

# psi_party binary (client-facing PsiService + inter-party protocol)
add_executable(psi_party
    psi_service/main.cpp
)
target_include_directories(psi_party PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(psi_party PRIVATE ks05_protocol ks05_crypto mpsi_core mpsi_proto pthread)

if(MPSI_BUILD_YYH26)
    target_link_libraries(psi_party PRIVATE yyh26_protocol)
    target_compile_definitions(psi_party PRIVATE MPSI_HAS_YYH26=1)
endif()

# psi_dealer binary (trusted key dealer service)
add_executable(psi_dealer
    dealer/main.cpp
)
target_include_directories(psi_dealer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(psi_dealer PRIVATE ks05_crypto mpsi_core mpsi_proto pthread)

# Tests
option(MPSI_BUILD_TESTS "Build tests" ON)
if(MPSI_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
