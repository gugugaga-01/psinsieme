#include "reconstruction.h"
#include "crt.h"
#include <functional>

namespace yyh26 {

int reconstruct_secret(
    const std::vector<int>& selected_indices,
    const std::vector<std::pair<int, uint64_t>>& all_shares,
    const NTL::ZZ& secret)
{
    std::vector<std::pair<int, uint64_t>> selected;
    selected.reserve(selected_indices.size());
    for (int idx : selected_indices) {
        selected.push_back(all_shares[idx]);
    }

    // Split u64 packed shares into 2 sets of (x, y) pairs for Lagrange interp.
    std::vector<std::vector<std::pair<NTL::ZZ, NTL::ZZ>>> parts(NUM_CRT_MODULI);
    for (int m = 0; m < NUM_CRT_MODULI; m++) {
        parts[m].resize(selected.size());
    }

    for (size_t i = 0; i < selected.size(); i++) {
        auto [r0, r1] = crt_unpack(selected[i].second);
        parts[0][i] = {NTL::ZZ(selected[i].first),
                       NTL::AddMod(NTL::ZZ(r0), NTL::ZZ(0), NTL::ZZ(CRT_MODULI[0]))};
        parts[1][i] = {NTL::ZZ(selected[i].first),
                       NTL::AddMod(NTL::ZZ(r1), NTL::ZZ(0), NTL::ZZ(CRT_MODULI[1]))};
    }

    int flag = 1;
    for (int m = 0; m < NUM_CRT_MODULI; m++) {
        NTL::ZZ reconstructed = lagrange_interpolation(parts[m], NTL::ZZ(CRT_MODULI[m]));
        if (reconstructed != (secret % NTL::ZZ(CRT_MODULI[m]))) {
            flag = 0;
        }
    }
    return flag;
}

void get_combinations_iterative(
    int totalNumShares, int threshold,
    std::vector<std::vector<int>>& all_combinations)
{
    std::vector<int> current;
    // Stack-based iterative combination generation
    struct Frame {
        int start, depth;
    };
    std::vector<Frame> stack;
    stack.push_back({0, 0});

    while (!stack.empty()) {
        Frame f = stack.back();
        stack.pop_back();

        if (f.depth == threshold) {
            all_combinations.push_back(current);
            // Pop elements added for this branch
            continue;
        }

        // We need to generate C(totalNumShares, threshold) combinations
        // Use recursive approach stored on stack
        for (int i = f.start; i <= totalNumShares - threshold + f.depth; i++) {
            current.push_back(i);
            if ((int)current.size() == threshold) {
                all_combinations.push_back(current);
            } else {
                // Recurse: continue choosing next elements
                // Simple recursive implementation
                // (the stack approach above doesn't work cleanly; use recursion)
            }
            current.pop_back();
        }
    }

    // Actually, use a clean recursive lambda:
    all_combinations.clear();
    current.clear();

    std::function<void(int, int)> generate = [&](int start, int depth) {
        if (depth == threshold) {
            all_combinations.push_back(current);
            return;
        }
        for (int i = start; i <= totalNumShares - threshold + depth; i++) {
            current.push_back(i);
            generate(i + 1, depth + 1);
            current.pop_back();
        }
    };
    generate(0, 0);
}

} // namespace yyh26
