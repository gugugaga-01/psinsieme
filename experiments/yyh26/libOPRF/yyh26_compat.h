#pragma once
// Compatibility definitions that were present in the original local
// cryptoTools but are absent from the upstream MultipartyPSI repository.

#include "Common/Defines.h"
#include <immintrin.h>
#include <chrono>
#include <random>

namespace osuCrypto
{
    typedef __uint128_t u128;

    inline block u128_to_block(u128 value)
    {
        alignas(16) u128 aligned_value = value;
        return _mm_load_si128(reinterpret_cast<const block *>(&aligned_value));
    }

    inline u128 block_to_u128(block value)
    {
        u128 result;
        _mm_storeu_si128(reinterpret_cast<block *>(&result), value);
        return result;
    }

    inline block generateRandomBlock()
    {
        auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        std::mt19937_64 gen{static_cast<unsigned>(now)};
        uint64_t high = gen();
        uint64_t low = gen();
        return _mm_set_epi64x(high, low);
    }
}
