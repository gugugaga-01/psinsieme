#include "protocol.h"
#include <iostream>
#include <cstdlib>
#include <cstring>

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " -n <parties> -t <threshold> -m <setSize> -p <partyIdx>\n";
    exit(1);
}

int main(int argc, char** argv) {
    uint64_t nParties = 0, threshold = 0, setSize = 0, partyIdx = 0;
    bool hasN = false, hasT = false, hasM = false, hasP = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            nParties = std::stoull(argv[++i]); hasN = true;
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            threshold = std::stoull(argv[++i]); hasT = true;
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            setSize = std::stoull(argv[++i]); hasM = true;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            partyIdx = std::stoull(argv[++i]); hasP = true;
        } else {
            usage(argv[0]);
        }
    }

    if (!hasN || !hasT || !hasM || !hasP) usage(argv[0]);

    if (partyIdx >= nParties) {
        std::cerr << "Error: partyIdx must be < nParties\n";
        return 1;
    }
    if (threshold < 2 || threshold > nParties) {
        std::cerr << "Error: threshold must be in [2, nParties]\n";
        return 1;
    }

    uint64_t elementRange = (nParties / 2) * setSize;
    if (elementRange >= yyh26::MAX_ELEMENT_VALUE) {
        std::cerr << "Error: element range (" << elementRange
                  << ") exceeds 2^24. Reduce setSize or nParties.\n";
        return 1;
    }

    std::cout << "YYH26 TT-MPSI v2: party=" << partyIdx
              << " n=" << nParties << " t=" << threshold
              << " m=" << setSize << std::endl;

    auto result = yyh26::tparty(partyIdx, nParties, threshold, setSize);

    if (partyIdx == nParties - 1) {
        std::cout << "Intersection indices: ";
        for (auto idx : result)
            std::cout << idx << " ";
        std::cout << std::endl;
    }

    return 0;
}
