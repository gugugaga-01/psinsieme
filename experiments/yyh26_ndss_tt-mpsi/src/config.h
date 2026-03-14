#pragma once
#include "Common/Defines.h"
#include <cstdint>

namespace yyh26 {

// Two NTT-friendly 32-bit primes for CRT.
// Product > 2^63, sufficient for 24-bit elements after Shamir SS.
constexpr int NUM_CRT_MODULI = 2;
constexpr uint64_t CRT_MODULI[NUM_CRT_MODULI] = {4293230593ULL, 4293836801ULL};

// Maximum supported element value. Elements must fit in 24 bits so that
// Shamir shares (which grow by a factor related to the evaluation points)
// stay well within the 32-bit CRT moduli.
constexpr uint64_t MAX_ELEMENT_VALUE = (1ULL << 24);

// BFV scheme parameters for BOLE
constexpr uint32_t BOLE_LOGN = 13;       // polynomial degree = 2^13 = 8192
constexpr uint32_t BOLE_NUM_LIMBS = 4;   // DCRT limbs (crypto ring property)
constexpr double   BOLE_STD_DEV = 3.2;   // noise standard deviation

// OPPRF / hashing
constexpr uint64_t PSI_SEC_PARAM = 40;
constexpr uint64_t BIT_SIZE = 64;  // share size in bits (down from 128)

// OPPRF channel base port
constexpr uint32_t CHANNEL_BASE_PORT = 1100;

// OLE channel base port (separate from OPPRF to avoid teardown/re-setup)
constexpr uint32_t OLE_BASE_PORT = 7000;

} // namespace yyh26
