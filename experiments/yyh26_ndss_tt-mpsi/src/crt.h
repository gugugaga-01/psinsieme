#pragma once
#include "config.h"
#include <cstdint>
#include <utility>

namespace yyh26 {

// Pack two 32-bit CRT residues into a single u64.
// Low 32 bits = residue mod CRT_MODULI[0], high 32 bits = residue mod CRT_MODULI[1].
inline uint64_t crt_pack(uint32_t r0, uint32_t r1) {
    return static_cast<uint64_t>(r0) | (static_cast<uint64_t>(r1) << 32);
}

// Unpack a u64 into two 32-bit CRT residues.
inline std::pair<uint32_t, uint32_t> crt_unpack(uint64_t packed) {
    uint32_t r0 = static_cast<uint32_t>(packed & 0xFFFFFFFF);
    uint32_t r1 = static_cast<uint32_t>(packed >> 32);
    return {r0, r1};
}

// Reduce an element value to CRT representation.
inline uint64_t crt_encode(uint64_t element) {
    uint32_t r0 = static_cast<uint32_t>(element % CRT_MODULI[0]);
    uint32_t r1 = static_cast<uint32_t>(element % CRT_MODULI[1]);
    return crt_pack(r0, r1);
}

// Component-wise modular addition of two packed CRT values.
inline uint64_t crt_add(uint64_t a, uint64_t b) {
    auto [a0, a1] = crt_unpack(a);
    auto [b0, b1] = crt_unpack(b);
    uint32_t r0 = static_cast<uint32_t>((static_cast<uint64_t>(a0) + b0) % CRT_MODULI[0]);
    uint32_t r1 = static_cast<uint32_t>((static_cast<uint64_t>(a1) + b1) % CRT_MODULI[1]);
    return crt_pack(r0, r1);
}

// Component-wise modular subtraction of two packed CRT values.
inline uint64_t crt_sub(uint64_t a, uint64_t b) {
    auto [a0, a1] = crt_unpack(a);
    auto [b0, b1] = crt_unpack(b);
    uint32_t r0 = static_cast<uint32_t>((CRT_MODULI[0] + a0 - b0) % CRT_MODULI[0]);
    uint32_t r1 = static_cast<uint32_t>((CRT_MODULI[1] + a1 - b1) % CRT_MODULI[1]);
    return crt_pack(r0, r1);
}

} // namespace yyh26
