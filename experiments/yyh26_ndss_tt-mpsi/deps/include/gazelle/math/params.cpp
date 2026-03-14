/*
params.cpp  --  Defines static parameters for fast modular reduction
*/

#include "params.h"

using namespace lbcrypto;

constexpr ui64 fast_two_limb_reduction_params::P[2];
constexpr ui64 fast_two_limb_reduction_params::Pn[2];
constexpr ui64 fast_two_limb_reduction_params::PrimitiveMthRoots[2];

constexpr ui64 fast_three_limb_reduction_params::P[3];
constexpr ui64 fast_three_limb_reduction_params::Pn[3];
constexpr ui64 fast_three_limb_reduction_params::PrimitiveMthRoots[3];

constexpr ui64 params<ui64>::P[params<ui64>::kMaxNbModuli];
constexpr ui64 params<ui64>::Pn[params<ui64>::kMaxNbModuli];
constexpr ui64 params<ui64>::PrimitiveMthRoots[params<ui64>::kMaxNbModuli];

constexpr ui32 params<ui32>::P[params<ui32>::kMaxNbModuli];
constexpr ui32 params<ui32>::Pn[params<ui32>::kMaxNbModuli];
// constexpr ui32 params<ui32>::PrimitiveMthRoots[params<ui32>::kMaxNbModuli];
constexpr ui32 params<ui32>::kModulusBitsize[params<ui32>::kMaxNbModuli];
