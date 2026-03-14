#pragma once
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include "Common/Defines.h"
#include <vector>

namespace yyh26 {

// Create numShares Shamir shares of secret under modulus p,
// requiring threshold shares for reconstruction.
// Evaluates polynomial f(1), f(2), ..., f(numShares) where f(0) = secret.
std::vector<NTL::ZZ_p> ShareSecret(
    NTL::ZZ_p secret, osuCrypto::u64 numShares,
    osuCrypto::u64 threshold, NTL::ZZ p);

// Generate update values: polynomial g with g(0) = 0, evaluated at 1..numShares.
// Used to rerandomize shares without changing the secret.
std::vector<NTL::ZZ_p> GenerateUpdateValues(
    osuCrypto::u64 numShares, osuCrypto::u64 threshold, NTL::ZZ p);

// Lagrange interpolation at x=0: given (x_i, y_i) pairs, recover f(0) mod p.
NTL::ZZ lagrange_interpolation(
    const std::vector<std::pair<NTL::ZZ, NTL::ZZ>>& shares, NTL::ZZ mod);

} // namespace yyh26
