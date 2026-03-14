#pragma once
#include "config.h"
#include "types.h"
#include "crt.h"
#include "shamir.h"
#include "channels.h"
#include "bole_wrapper.h"
#include "reconstruction.h"

#include "OPPRF/OPPRFSender.h"
#include "OPPRF/OPPRFReceiver.h"
#include "OPPRF/binSet.h"
#include "NChooseOne/KkrtNcoOtReceiver.h"
#include "NChooseOne/KkrtNcoOtSender.h"

#include <pke/gazelle-network.h>

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>

#include <vector>
#include <unordered_set>

namespace yyh26 {

// Run the single-threaded TT-MPSI protocol for one party.
// myIdx: this party's index (0..nParties-1), leader = nParties-1
// Returns the intersection indices (only meaningful for the leader).
std::unordered_set<u64> tparty(
    u64 myIdx, u64 nParties, u64 threshold, u64 setSize);

} // namespace yyh26
