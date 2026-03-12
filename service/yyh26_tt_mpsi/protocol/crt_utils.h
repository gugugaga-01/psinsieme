#pragma once

#include <array>
#include <cstdint>

namespace mpsi::yyh26 {

// Four CRT moduli used by the YYH26 protocol for Shamir secret sharing.
// Each is a 32-bit prime chosen so that 4 × 32 = 128 bits covers the
// full element space used by OPPRF (osuCrypto::block = 128 bits).
constexpr std::array<uint64_t, 4> CRT_MODULI = {
    4293230593ULL,
    4293836801ULL,
    4293918721ULL,
    4294475777ULL,
};
constexpr size_t NUM_CRT = CRT_MODULI.size();

using ui128 = __uint128_t;

// Pack four 32-bit CRT residues into a single 128-bit value.
// Layout: [mod0 @ bits 96..127] [mod1 @ bits 64..95] [mod2 @ bits 32..63] [mod3 @ bits 0..31]
inline ui128 crtPack(uint32_t r0, uint32_t r1, uint32_t r2, uint32_t r3) {
    ui128 result = 0;
    result |= static_cast<ui128>(r0) << 96;
    result |= static_cast<ui128>(r1) << 64;
    result |= static_cast<ui128>(r2) << 32;
    result |= static_cast<ui128>(r3);
    return result;
}

// Extract the i-th CRT residue (i=0..3) from a packed 128-bit value.
inline uint64_t crtExtract(ui128 packed, size_t i) {
    uint64_t shift = (3 - i) * 32;
    return static_cast<uint64_t>((packed >> shift) & 0xFFFFFFFF);
}

// Add two packed CRT values modulo each CRT prime.
inline ui128 crtAdd(ui128 a, ui128 b) {
    ui128 result = 0;
    for (size_t i = 0; i < NUM_CRT; i++) {
        uint64_t shift = (3 - i) * 32;
        uint64_t va = (a >> shift) & 0xFFFFFFFF;
        uint64_t vb = (b >> shift) & 0xFFFFFFFF;
        uint64_t sum = (va + vb) % CRT_MODULI[i];
        result |= static_cast<ui128>(sum) << shift;
    }
    return result;
}

// Subtract two packed CRT values modulo each CRT prime.
inline ui128 crtSub(ui128 a, ui128 b) {
    ui128 result = 0;
    for (size_t i = 0; i < NUM_CRT; i++) {
        uint64_t shift = (3 - i) * 32;
        uint64_t va = (a >> shift) & 0xFFFFFFFF;
        uint64_t vb = (b >> shift) & 0xFFFFFFFF;
        uint64_t diff = (va + CRT_MODULI[i] - vb) % CRT_MODULI[i];
        result |= static_cast<ui128>(diff) << shift;
    }
    return result;
}

// Multiply two packed CRT values modulo each CRT prime.
inline ui128 crtMul(ui128 a, ui128 b) {
    ui128 result = 0;
    for (size_t i = 0; i < NUM_CRT; i++) {
        uint64_t shift = (3 - i) * 32;
        uint64_t va = (a >> shift) & 0xFFFFFFFF;
        uint64_t vb = (b >> shift) & 0xFFFFFFFF;
        uint64_t prod = (va * vb) % CRT_MODULI[i];
        result |= static_cast<ui128>(prod) << shift;
    }
    return result;
}

// Replicate a single element across all 4 CRT slots (for use as input to BOLE).
inline ui128 crtReplicate(ui128 element) {
    ui128 result = 0;
    for (size_t i = 0; i < NUM_CRT; i++) {
        uint64_t shift = (3 - i) * 32;
        result |= (element & static_cast<ui128>(0xFFFFFFFF)) << shift;
    }
    return result;
}

} // namespace mpsi::yyh26
