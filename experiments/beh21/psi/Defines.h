#pragma once

// Standard library includes
#include <utility> // For std::pair

// External library includes
#include <NTL/ZZ.h>
#include <NTL/ZZX.h>

#include <memory> // For std::unique_ptr

// CryptoTools includes
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"

// Coproto and volePSI includes
#include "coproto/coproto.h"
#include "volePSI/RsOpprf.h"
#include "volePSI/GMW/Circuit.h"
#include "volePSI/GMW/Gmw.h"
#include "volePSI/SimpleIndex.h"

// Numeric type aliases
using u64 = oc::u64;
using u32 = oc::u32;
using u16 = oc::u16;
using u8 = oc::u8;

using i64 = oc::i64;
using i32 = oc::i32;
using i16 = oc::i16;
using i8 = oc::i8;

using block = oc::block;

// Container type aliases
template <typename T>
using span = oc::span<T>;

template <typename T>
using Matrix = oc::Matrix<T>;

template <typename T>
using MatrixView = oc::MatrixView<T>;

// Crypto and networking aliases
using OcPRNG = oc::PRNG;
using Socket = coproto::Socket;
using Proto = coproto::task<void>;

// NTL type alias
using ZZ = NTL::ZZ;

// Operation modes (using enum class for type safety)
enum class Mode : u8
{
    Leader = 1,
    Member = 2
};

// Constants
constexpr double FALSE_POSITIVE_RATE = 0.0009; // < 2^(-10)