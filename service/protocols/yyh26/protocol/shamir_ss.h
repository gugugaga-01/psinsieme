#pragma once

#include <vector>
#include <cstdint>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>

namespace mpsi::yyh26 {

// Shamir secret sharing over a prime field.
// Splits `secret` into `numShares` shares such that any `threshold` shares
// can reconstruct the secret via Lagrange interpolation.
//
// Shares are evaluated at points 1, 2, ..., numShares (not 0).
inline std::vector<NTL::ZZ_p> shamirShare(
    const NTL::ZZ_p& secret,
    uint64_t numShares,
    uint64_t threshold,
    const NTL::ZZ& modulus)
{
    NTL::ZZ_p::init(modulus);
    std::vector<NTL::ZZ_p> shares(numShares);

    // Build random polynomial with secret as constant term
    NTL::ZZ_pX poly;
    NTL::SetCoeff(poly, 0, secret);
    for (long i = 1; i < static_cast<long>(threshold); i++) {
        NTL::ZZ coef;
        NTL::RandomBnd(coef, modulus);
        NTL::SetCoeff(poly, i, NTL::conv<NTL::ZZ_p>(coef));
    }

    // Evaluate at points 1..numShares
    for (uint64_t i = 0; i < numShares; i++)
        shares[i] = NTL::eval(poly, NTL::to_ZZ_p(i + 1));

    return shares;
}

// Generate update values for the zero-sharing step.
// Returns shares of 0 (i.e., a random polynomial with f(0) = 0).
inline std::vector<NTL::ZZ_p> generateUpdateValues(
    uint64_t numShares,
    uint64_t threshold,
    const NTL::ZZ& modulus)
{
    NTL::ZZ_p::init(modulus);
    std::vector<NTL::ZZ_p> values(numShares);

    NTL::ZZ_pX poly;
    NTL::SetCoeff(poly, 0, NTL::to_ZZ_p(0)); // f(0) = 0
    for (long j = 1; j < static_cast<long>(threshold); j++) {
        NTL::ZZ coef;
        NTL::RandomBnd(coef, modulus);
        NTL::SetCoeff(poly, j, NTL::conv<NTL::ZZ_p>(coef));
    }

    for (uint64_t j = 0; j < numShares; j++)
        values[j] = NTL::eval(poly, NTL::to_ZZ_p(j + 1));

    return values;
}

// Lagrange interpolation at x=0 to reconstruct the secret.
// `shares` is a vector of (evaluation_point, share_value) pairs.
inline NTL::ZZ lagrangeInterpolateAtZero(
    const std::vector<std::pair<NTL::ZZ, NTL::ZZ>>& shares,
    const NTL::ZZ& modulus)
{
    uint64_t t = shares.size();
    NTL::ZZ secret(0);

    // Precompute -x_j mod p
    std::vector<NTL::ZZ> neg_xj(t);
    for (uint64_t j = 0; j < t; j++)
        neg_xj[j] = NTL::SubMod(modulus, shares[j].first, modulus);

    // Compute Lagrange basis polynomials evaluated at x=0
    for (uint64_t i = 0; i < t; i++) {
        // Denominator: product of (x_i - x_j) for j != i
        NTL::ZZ denominator(1);
        for (uint64_t j = 0; j < t; j++) {
            if (i != j) {
                NTL::ZZ diff = NTL::SubMod(shares[i].first, shares[j].first, modulus);
                denominator = NTL::MulMod(denominator, diff, modulus);
            }
        }
        NTL::ZZ inv = NTL::InvMod(denominator, modulus);

        // Numerator at x=0: product of (-x_j) for j != i
        NTL::ZZ li = inv;
        for (uint64_t j = 0; j < t; j++) {
            if (i != j)
                li = NTL::MulMod(li, neg_xj[j], modulus);
        }

        secret = NTL::AddMod(secret, NTL::MulMod(shares[i].second, li, modulus), modulus);
    }

    return secret;
}

// Generate all C(n, k) combinations of indices.
inline std::vector<std::vector<int>> getCombinations(int n, int k) {
    std::vector<std::vector<int>> result;
    std::vector<int> indices(k);
    for (int i = 0; i < k; i++)
        indices[i] = i;

    while (true) {
        result.push_back(indices);

        int i = k - 1;
        while (i >= 0 && indices[i] == n - k + i)
            --i;
        if (i < 0) break;

        ++indices[i];
        for (int j = i + 1; j < k; j++)
            indices[j] = indices[j - 1] + 1;
    }
    return result;
}

// Reconstruct and verify a secret from a subset of shares across 4 CRT moduli.
// Returns true if reconstruction succeeds for ALL 4 moduli.
inline bool reconstructAndVerify(
    const std::vector<int>& selectedIndices,
    const std::vector<std::pair<int, __uint128_t>>& allShares,
    const std::vector<NTL::ZZ>& fourModuli,
    const NTL::ZZ& expectedSecret)
{
    for (size_t m = 0; m < 4; m++) {
        std::vector<std::pair<NTL::ZZ, NTL::ZZ>> sharesForMod;
        for (int idx : selectedIndices) {
            uint64_t shift = (3 - m) * 32;
            uint64_t shareVal = (allShares[idx].second >> shift) & 0xFFFFFFFF;
            sharesForMod.push_back({
                NTL::ZZ(allShares[idx].first),
                NTL::AddMod(NTL::ZZ(shareVal), NTL::ZZ(0), fourModuli[m])
            });
        }

        NTL::ZZ reconstructed = lagrangeInterpolateAtZero(sharesForMod, fourModuli[m]);
        if (reconstructed != (expectedSecret % fourModuli[m]))
            return false;
    }
    return true;
}

} // namespace mpsi::yyh26
