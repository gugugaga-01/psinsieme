#pragma once
#include "config.h"
#include "types.h"
#include "shamir.h"
#include <NTL/ZZ.h>
#include <vector>

namespace yyh26 {

// Try to reconstruct the secret from selected shares.
// all_shares: vector of (party_index, packed_u64_share) pairs.
// Returns 1 if reconstructed value equals expected secret, 0 otherwise.
int reconstruct_secret(
    const std::vector<int>& selected_indices,
    const std::vector<std::pair<int, uint64_t>>& all_shares,
    const NTL::ZZ& secret);

// Generate all C(totalNumShares, threshold) combinations.
void get_combinations_iterative(
    int totalNumShares, int threshold,
    std::vector<std::vector<int>>& all_combinations);

} // namespace yyh26
