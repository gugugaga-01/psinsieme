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

# ks05 plugin (OBJECT library ensures static initializer is not dead-stripped)
add_library(ks05_plugin OBJECT
    protocols/ks05/ks05_plugin.cpp
)
target_include_directories(ks05_plugin PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ks05_plugin PRIVATE ks05_protocol ks05_crypto mpsi_core mpsi_proto)

# yyh26 TT-MPSI protocol (optional, requires upstream libraries)
option(MPSI_BUILD_YYH26 "Build YYH26 TT-MPSI protocol support" OFF)

if(MPSI_BUILD_YYH26)
    set(YYH26_VENDOR_DIR "${CMAKE_CURRENT_SOURCE_DIR}/protocols/yyh26/vendor")

    # YYH26_DEPS_PREFIX: where upstream deps (headers + libs) are installed.
    # Set via -DYYH26_DEPS_PREFIX=... or defaults to CMAKE_PREFIX_PATH.
    if(NOT YYH26_DEPS_PREFIX)
        set(YYH26_DEPS_PREFIX "${CMAKE_PREFIX_PATH}")
    endif()

    # Find pre-built upstream libraries (installed by vendor/setup.sh)
    find_library(LIBOTE_LIBRARY libOTe HINTS "${YYH26_DEPS_PREFIX}/lib")
    find_library(CRYPTOTOOLS_LIBRARY cryptoTools HINTS "${YYH26_DEPS_PREFIX}/lib")
    find_library(MIRACL_LIBRARY miracl HINTS "${YYH26_DEPS_PREFIX}/lib")
    find_library(GAZELLE_LIBRARY gazelle HINTS "${YYH26_DEPS_PREFIX}/lib")
    find_library(CRYPTOTOOLS_OLE_LIBRARY cryptoTools_ole HINTS "${YYH26_DEPS_PREFIX}/lib")

    if(NOT LIBOTE_LIBRARY OR NOT CRYPTOTOOLS_LIBRARY)
        message(FATAL_ERROR
            "YYH26 upstream libraries not found.\n"
            "Build and install them first:\n"
            "  bash service/protocols/yyh26/vendor/setup.sh [PREFIX]\n"
            "Then configure with: cmake .. -DMPSI_BUILD_YYH26=ON -DYYH26_DEPS_PREFIX=PREFIX")
    endif()

    # Build libOPRF from vendored source
    add_subdirectory(protocols/yyh26/vendor/libOPRF)

    add_library(yyh26_protocol
        protocols/yyh26/protocol/tt_mpsi.cpp
    )

    target_include_directories(yyh26_protocol PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    # Headers are installed to YYH26_DEPS_PREFIX/include/ by vendor/setup.sh
    target_include_directories(yyh26_protocol PRIVATE
        ${YYH26_DEPS_PREFIX}/include/yyh26/cryptoTools
        ${YYH26_DEPS_PREFIX}/include/yyh26/libOTe
        ${YYH26_VENDOR_DIR}/libOPRF
        ${YYH26_DEPS_PREFIX}/include/yyh26/libOLE/src/lib
        ${YYH26_DEPS_PREFIX}/include/yyh26/libOLE/third_party/cryptoTools
        ${YYH26_DEPS_PREFIX}/include/yyh26/miracl/include
        ${NTL_INCLUDE_DIR}
    )

    target_link_libraries(yyh26_protocol PRIVATE
        libOPRF
        ${LIBOTE_LIBRARY}
        ${CRYPTOTOOLS_LIBRARY}
        ${NTL_LIBRARY} ${GMP_LIBRARY}
        boost_system boost_thread pthread
    )
    if(GAZELLE_LIBRARY)
        target_link_libraries(yyh26_protocol PRIVATE ${GAZELLE_LIBRARY})
    endif()
    if(CRYPTOTOOLS_OLE_LIBRARY)
        target_link_libraries(yyh26_protocol PRIVATE ${CRYPTOTOOLS_OLE_LIBRARY})
    endif()
    if(MIRACL_LIBRARY)
        target_link_libraries(yyh26_protocol PRIVATE ${MIRACL_LIBRARY})
    endif()

    target_compile_definitions(yyh26_protocol PUBLIC MPSI_HAS_YYH26=1)
    target_compile_options(yyh26_protocol PRIVATE -maes -msse2 -msse4.1 -mpclmul)

    # yyh26 plugin (OBJECT library ensures static initializer is not dead-stripped)
    add_library(yyh26_plugin OBJECT
        protocols/yyh26/yyh26_plugin.cpp
    )
    target_include_directories(yyh26_plugin PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(yyh26_plugin PRIVATE yyh26_protocol mpsi_core)
endif()

# psi_party binary (client-facing PsiService + inter-party protocol)
add_executable(psi_party
    party/main.cpp
    $<TARGET_OBJECTS:ks05_plugin>
)
target_include_directories(psi_party PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(psi_party PRIVATE ks05_protocol ks05_crypto mpsi_core mpsi_proto pthread)

if(MPSI_BUILD_YYH26)
    target_sources(psi_party PRIVATE $<TARGET_OBJECTS:yyh26_plugin>)
    target_link_libraries(psi_party PRIVATE yyh26_protocol)
endif()

# BEH21 OT-MPSI protocol (optional, uses Paillier from ks05_crypto + Bloom filters)
option(MPSI_BUILD_BEH21 "Build BEH21 OT-MPSI protocol support" OFF)

if(MPSI_BUILD_BEH21)
    add_library(beh21_crypto
        protocols/beh21/third_party/smhasher/MurmurHash3.cpp
    )
    target_include_directories(beh21_crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

    add_library(beh21_protocol
        protocols/beh21/protocol/ot_mpsi.cpp
    )
    target_include_directories(beh21_protocol PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(beh21_protocol PUBLIC ks05_crypto beh21_crypto mpsi_core)
    target_link_libraries(beh21_protocol PRIVATE pthread)

    add_library(beh21_plugin OBJECT
        protocols/beh21/beh21_plugin.cpp
    )
    target_include_directories(beh21_plugin PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(beh21_plugin PRIVATE beh21_protocol ks05_crypto mpsi_core mpsi_proto)

    target_sources(psi_party PRIVATE $<TARGET_OBJECTS:beh21_plugin>)
    target_link_libraries(psi_party PRIVATE beh21_protocol beh21_crypto)
endif()

# XZH26 EC-ElGamal Bloom OPPRF MPSI protocol (optional)
option(MPSI_BUILD_XZH26 "Build XZH26 EC-MPSI protocol support" OFF)

if(MPSI_BUILD_XZH26)
    find_library(SODIUM_LIB sodium)
    if(NOT SODIUM_LIB)
        message(FATAL_ERROR "libsodium not found. Install: sudo apt install libsodium-dev")
    endif()

    # cryptoTools headers and sources from yyh26 upstream
    set(CRYPTOTOOLS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../experiments/yyh26/upstream/cryptoTools")
    set(MIRACL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../experiments/yyh26/upstream/thirdparty/linux/miracl")

    find_library(MIRACL_LIB NAMES miracl HINTS "${MIRACL_DIR}/miracl/source/")
    find_package(Boost REQUIRED COMPONENTS system thread)

    # Build cryptoTools from yyh26 upstream
    file(GLOB_RECURSE CRYPTOTOOLS_SRCS "${CRYPTOTOOLS_DIR}/*.cpp")
    add_library(xzh26_cryptotools ${CRYPTOTOOLS_SRCS})
    target_compile_definitions(xzh26_cryptotools PUBLIC NO_INTEL_ASM_SHA1=1)
    target_include_directories(xzh26_cryptotools PUBLIC "${CRYPTOTOOLS_DIR}" "${MIRACL_DIR}")
    target_compile_options(xzh26_cryptotools PRIVATE -maes -msse2 -msse4.1 -mpclmul -w -std=c++14)
    target_link_libraries(xzh26_cryptotools PUBLIC ${MIRACL_LIB} ${Boost_LIBRARIES})

    # XZH26 crypto primitives
    add_library(xzh26_crypto
        protocols/xzh26/crypto/point.cpp
        protocols/xzh26/crypto/bloom_filter.cpp
        protocols/xzh26/crypto/murmurhash3.cpp
    )
    target_include_directories(xzh26_crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(xzh26_crypto PUBLIC ${SODIUM_LIB})

    # XZH26 protocol (OPPRF, hashing, EC-MPSI)
    add_library(xzh26_protocol
        protocols/xzh26/protocol/ec_mpsi.cpp
        protocols/xzh26/protocol/binSet.cpp
        protocols/xzh26/protocol/OPPRFSender.cpp
        protocols/xzh26/protocol/OPPRFReceiver.cpp
        protocols/xzh26/protocol/CuckooHasher1.cpp
        protocols/xzh26/protocol/SimpleHasher1.cpp
        protocols/xzh26/protocol/BitPosition.cpp
    )
    target_include_directories(xzh26_protocol PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    target_include_directories(xzh26_protocol PRIVATE "${CRYPTOTOOLS_DIR}")
    target_compile_options(xzh26_protocol PRIVATE -maes -msse2 -msse4.1 -mpclmul -Wno-sign-compare)
    target_link_libraries(xzh26_protocol PUBLIC
        xzh26_crypto xzh26_cryptotools mpsi_core ${SODIUM_LIB} pthread)

    add_library(xzh26_plugin OBJECT
        protocols/xzh26/xzh26_plugin.cpp
    )
    target_include_directories(xzh26_plugin PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(xzh26_plugin PRIVATE xzh26_protocol mpsi_core mpsi_proto)

    target_sources(psi_party PRIVATE $<TARGET_OBJECTS:xzh26_plugin>)
    target_link_libraries(psi_party PRIVATE xzh26_protocol xzh26_crypto ${SODIUM_LIB})
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
