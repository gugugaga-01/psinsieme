#pragma once
#include "Common/Defines.h"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <cstdint>

// Pull in the osuCrypto types used everywhere
using osuCrypto::u64;
using osuCrypto::u32;
using osuCrypto::u8;
using osuCrypto::block;

// 128-bit unsigned integer (used for block conversions, not shares)
typedef unsigned __int128 ui128;

inline NTL::ZZ u64_to_ZZ(uint64_t val) {
    return NTL::conv<NTL::ZZ>(static_cast<long>(val));
}

inline uint64_t ZZ_to_u64(const NTL::ZZ& val) {
    return NTL::conv<long>(val);
}

inline ui128 block_to_ui128(const block& b) {
    ui128 result;
    memcpy(&result, &b, sizeof(ui128));
    return result;
}

inline block ui128_to_block(ui128 val) {
    block b;
    memcpy(&b, &val, sizeof(block));
    return b;
}
