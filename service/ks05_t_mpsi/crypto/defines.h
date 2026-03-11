#pragma once

#include <cstdint>
#include <NTL/ZZ.h>

namespace mpsi::ks05 {

using u64 = uint64_t;
using u32 = uint32_t;
using u16 = uint16_t;
using u8  = uint8_t;

using i64 = int64_t;
using i32 = int32_t;
using i16 = int16_t;
using i8  = int8_t;

using ZZ = NTL::ZZ;

enum class Mode : u8 {
    Leader = 1,
    Member = 2
};

} // namespace mpsi::ks05
