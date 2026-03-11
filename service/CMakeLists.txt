cmake_minimum_required(VERSION 3.16)
project(mpsi_service VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
    ks05_t_mpsi/crypto/paillier.cpp
    ks05_t_mpsi/crypto/polynomial.cpp
)
target_include_directories(ks05_crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${NTL_INCLUDE_DIR}
)
target_link_libraries(ks05_crypto PUBLIC ${NTL_LIBRARY} ${GMP_LIBRARY})

# ks05 protocol library
add_library(ks05_protocol
    ks05_t_mpsi/protocol/t_mpsi.cpp
)
target_include_directories(ks05_protocol PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ks05_protocol PUBLIC ks05_crypto mpsi_core)
target_link_libraries(ks05_protocol PRIVATE pthread)

# psi_party binary (client-facing PsiService + inter-party protocol)
add_executable(psi_party
    psi_service/main.cpp
)
target_include_directories(psi_party PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(psi_party PRIVATE ks05_protocol ks05_crypto mpsi_core mpsi_proto pthread)

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
